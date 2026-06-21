import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

logger = logging.getLogger("pyguarddns.blocklist")

RULES_DIR = os.path.join("data", "rules")
RULES_FILE = os.path.join(RULES_DIR, "user_rules.pgrules")
BACKUP_DIR = os.path.join(RULES_DIR, "backups")

PREFIXES = frozenset({"bd::", "bs::", "br::", "ad::", "as::", "ar::", "cm::"})
BLOCK_PREFIXES = frozenset({"bd::", "bs::", "br::"})
ALLOW_PREFIXES = frozenset({"ad::", "as::", "ar::"})

PREFIX_MEANING = {
    "bd::": "block exact domain",
    "bs::": "block suffix domain",
    "br::": "block regex",
    "ad::": "allow exact domain",
    "as::": "allow suffix domain",
    "ar::": "allow regex",
    "cm::": "cosmetic rule",
}

DANGEROUS_REGEX_MESSAGE = "Pattern is too broad or may cause excessive CPU usage."


def is_dangerous_regex(pattern: str) -> bool:
    cleaned = pattern.strip()

    if cleaned in (".*", ".+", "^.*$", "^.+$"):
        return True

    if cleaned.startswith(".*") or cleaned.startswith(".+"):
        return True

    if re.search(r"\([^()]*[+*?]\)[+*?]", cleaned):
        return True

    if cleaned.count("(") != cleaned.count(")") and ("+" in cleaned or "*" in cleaned):
        return True

    return False


# --- Blocklist import primitives (fix_unsupported_rules.md) ----------------

BOM = "﻿"
MAX_LINE_LENGTH = 2000

HEADER_RE = re.compile(r"^\[.*\]$")
MERGE_MARKERS = ("<<<<<<<", "=======", ">>>>>>>")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9-]+$")

COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#@$#")

UMATRIX_RESOURCE_TYPES = frozenset({
    "*", "doc", "css", "image", "media", "script", "xhr", "frame", "other", "cookie", "csp",
})
UMATRIX_ACTIONS = frozenset({"allow", "block", "noop"})

DNS_SUPPORTED_OPTIONS = frozenset({"badfilter", "important"})
DNS_PARAMETER_OPTIONS = frozenset({"dnstype", "client"})
BROWSER_ONLY_OPTIONS = frozenset({
    "script", "image", "stylesheet", "object", "object-subrequest", "xmlhttprequest",
    "subdocument", "ping", "websocket", "webrtc", "document", "elemhide", "generichide",
    "genericblock", "specifichide", "popup", "popunder", "media", "font", "other",
    "third-party", "first-party", "1p", "3p", "match-case", "csp", "redirect",
    "redirect-rule", "removeparam", "queryprune", "replace", "rewrite", "empty",
    "mp4", "doc", "frame", "inline-script", "inline-font", "all", "header",
    "permissions", "to", "uritransform", "cname",
})

DNS_RECORD_TYPES = frozenset({
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR", "CAA",
    "HTTPS", "SVCB", "NAPTR", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3",
    "TLSA", "ANY",
})

BLOCK_HOST_IPS = frozenset({"0.0.0.0", "127.0.0.1", "255.255.255.255", "::", "::1"})
SKIP_HOST_DOMAINS = frozenset({"localhost", "localhost.localdomain", "local", "broadcasthost"})


def normalize_domain(value: str) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower().rstrip(".")
    if not value:
        return None
    try:
        encoded = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not encoded or len(encoded) > 253:
        return None
    labels = encoded.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not (1 <= len(label) <= 63):
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if not DOMAIN_LABEL_RE.fullmatch(label):
            return None
    return encoded


@lru_cache(maxsize=100_000)
def normalize_domain_cached(value: str) -> Optional[str]:
    return normalize_domain(value)


def is_cosmetic_rule(line: str) -> bool:
    return any(marker in line for marker in COSMETIC_MARKERS)


def strip_inline_comment(line: str) -> str:
    idx = line.find(" #")
    if idx == -1:
        return line
    return line[:idx].rstrip()


def preprocess_rule_line(raw_line: str) -> tuple:
    line = raw_line.lstrip(BOM).strip()
    if not line:
        return None, "empty_line"
    if len(line) > MAX_LINE_LENGTH:
        return None, "line_too_long"
    if line.startswith("!"):
        return None, "comment"
    if line.startswith("#") and not is_cosmetic_rule(line):
        return None, "comment"
    if HEADER_RE.match(line):
        return None, "header"
    if line.startswith(MERGE_MARKERS):
        return None, "merge_marker"
    if not is_cosmetic_rule(line):
        line = strip_inline_comment(line)
    return line, None


def parse_hosts_line(line: str) -> Optional[list]:
    parts = line.split()
    if len(parts) < 2:
        return None
    ip = parts[0].strip().lower()
    if ip not in BLOCK_HOST_IPS:
        return None
    domains = []
    for candidate in parts[1:]:
        candidate = candidate.strip().lower()
        if candidate in SKIP_HOST_DOMAINS:
            continue
        normalized = normalize_domain_cached(candidate)
        if normalized:
            domains.append(normalized)
    return domains or None


def is_umatrix_rule(line: str) -> bool:
    parts = line.split()
    if len(parts) != 4:
        return False
    source, destination, resource_type, action = parts
    if resource_type.lower() not in UMATRIX_RESOURCE_TYPES:
        return False
    if action.lower() not in UMATRIX_ACTIONS:
        return False
    for value in (source, destination):
        if value == "*":
            continue
        if normalize_domain_cached(value.lower()) is None:
            return False
    return True


def classify_options(options: list) -> tuple:
    dns_supported = set()
    browser_only = set()
    unknown = set()
    for opt in options:
        name = opt.split("=", 1)[0].lstrip("~").lower()
        if name in DNS_SUPPORTED_OPTIONS or name in DNS_PARAMETER_OPTIONS:
            dns_supported.add(opt)
        elif name in BROWSER_ONLY_OPTIONS:
            browser_only.add(opt)
        else:
            unknown.add(opt)
    return dns_supported, browser_only, unknown


def _find_option_value(options: list, name: str) -> Optional[str]:
    for opt in options:
        key, sep, value = opt.partition("=")
        if key.lstrip("~").lower() == name:
            return value
    return None


def canonicalize_badfilter_target(line: str) -> str:
    is_allow = line.startswith("@@")
    body = line[2:] if is_allow else line
    if "$" in body:
        rule_part, _, options_part = body.partition("$")
        options = [o.strip() for o in options_part.split(",") if o.strip()]
    else:
        rule_part, options = body, []
    remaining = sorted(o for o in options if o.lower() != "badfilter")
    canonical = rule_part
    if remaining:
        canonical += "$" + ",".join(remaining)
    if is_allow:
        canonical = "@@" + canonical
    return canonical


def deduplicate_preserve_order(values: list) -> tuple:
    seen = set()
    unique = []
    duplicates = []
    for value in values:
        if value in seen:
            duplicates.append(value)
        else:
            seen.add(value)
            unique.append(value)
    return unique, duplicates


def parse_adblock_domain_rule(line: str) -> Optional[tuple]:
    is_allow = line.startswith("@@")
    body = line[2:] if is_allow else line
    if not body.startswith("||"):
        return None
    body = body[2:]
    if "$" in body:
        domain_part, _, options_part = body.partition("$")
        options = [o.strip() for o in options_part.split(",") if o.strip()]
    else:
        domain_part, options = body, []
    domain_part = domain_part.rstrip("^")
    if "/" in domain_part or "*" in domain_part:
        return None
    domain = normalize_domain_cached(domain_part)
    if domain is None:
        return None
    return is_allow, domain, options


def parse_partial_domain_rule(line: str) -> Optional[tuple]:
    is_allow = line.startswith("@@")
    body = line[2:] if is_allow else line
    if body.startswith("://"):
        body = body[3:]
    body = body.lstrip(".")
    body = body.rstrip("^|")
    domain = normalize_domain_cached(body)
    if domain is None:
        return None
    return is_allow, domain


def wildcard_domain_to_regex(value: str) -> Optional[str]:
    if value.startswith("://"):
        value = value[3:]
    value = value.rstrip("^|")
    value = value.lower().rstrip(".")
    if "." not in value or "*" not in value:
        return None
    labels = value.split(".")
    pattern_parts = []
    for label in labels:
        if not label:
            return None
        escaped = re.escape(label)
        escaped = escaped.replace(r"\*", "[a-z0-9-]*")
        escaped = escaped.replace(r"\-", "-")
        pattern_parts.append(escaped)
    return "^" + r"\.".join(pattern_parts) + "$"


_write_lock = threading.Lock()


def ensure_dirs():
    os.makedirs(RULES_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)


def parse_rule_line(line: str) -> Optional[dict]:
    if not line or line.startswith("#") or line.startswith("!"):
        return None
    if line.startswith("bd::"):
        domain = line[4:].strip()
        if not domain:
            return {"error": "Missing domain after bd::", "line": line}
        if re.match(r"^https?://", domain, re.IGNORECASE):
            return {"error": "Use only the domain name, not a URL", "line": line}
        if domain.startswith("*."):
            return {"error": "Use bs:: instead of bd:: with wildcard prefix", "line": line}
        return {"action": "block", "type": "exact", "pattern": domain, "raw": line, "prefix": "bd::"}
    if line.startswith("bs::"):
        domain = line[4:].strip()
        if not domain:
            return {"error": "Missing domain after bs::", "line": line}
        if domain.startswith("*."):
            return {"error": "Use bs::example.com instead of bs::*.example.com", "line": line}
        return {"action": "block", "type": "suffix", "pattern": domain, "raw": line, "prefix": "bs::"}
    if line.startswith("br::"):
        pattern = line[4:].strip()
        if not pattern:
            return {"error": "Missing regex pattern after br::", "line": line}
        try:
            re.compile(pattern)
        except re.error:
            return {"error": "Invalid regex pattern", "line": line}
        if is_dangerous_regex(pattern):
            return {"error": DANGEROUS_REGEX_MESSAGE, "line": line}
        return {"action": "block", "type": "regex", "pattern": pattern, "raw": line, "prefix": "br::"}
    if line.startswith("ad::"):
        domain = line[4:].strip()
        if not domain:
            return {"error": "Missing domain after ad::", "line": line}
        return {"action": "allow", "type": "exact", "pattern": domain, "raw": line, "prefix": "ad::"}
    if line.startswith("as::"):
        domain = line[4:].strip()
        if not domain:
            return {"error": "Missing domain after as::", "line": line}
        return {"action": "allow", "type": "suffix", "pattern": domain, "raw": line, "prefix": "as::"}
    if line.startswith("ar::"):
        pattern = line[4:].strip()
        if not pattern:
            return {"error": "Missing regex pattern after ar::", "line": line}
        try:
            re.compile(pattern)
        except re.error:
            return {"error": "Invalid regex pattern", "line": line}
        if is_dangerous_regex(pattern):
            return {"error": DANGEROUS_REGEX_MESSAGE, "line": line}
        return {"action": "allow", "type": "regex", "pattern": pattern, "raw": line, "prefix": "ar::"}
    if line.startswith("cm::"):
        pattern = line[4:].strip()
        if not pattern:
            return {"error": "Missing pattern after cm::", "line": line}
        return {"action": "cosmetic", "type": "cosmetic", "pattern": pattern, "raw": line, "prefix": "cm::"}

    prefix = line.split("::")[0] + "::" if "::" in line else ""
    if prefix and prefix not in PREFIXES:
        return {"error": f'Invalid prefix "{prefix}"\nExpected: bd::  bs::  br::  ad::  as::  ar::  cm::', "line": line}
    return {"error": "Unrecognized rule syntax", "line": line}


def validate_rules(text: str) -> list:
    errors = []
    lines = text.split("\n")
    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        result = parse_rule_line(line)
        if result and "error" in result:
            errors.append({"line": idx, "text": line, "message": result["error"]})
    return errors


def count_rules(text: str) -> dict:
    counts = {"block_exact": 0, "block_suffix": 0, "block_regex": 0, "allow_exact": 0, "allow_suffix": 0, "allow_regex": 0, "cosmetic": 0, "total": 0}
    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if line.startswith("bd::"):
            counts["block_exact"] += 1
            counts["total"] += 1
        elif line.startswith("bs::"):
            counts["block_suffix"] += 1
            counts["total"] += 1
        elif line.startswith("br::"):
            counts["block_regex"] += 1
            counts["total"] += 1
        elif line.startswith("ad::"):
            counts["allow_exact"] += 1
            counts["total"] += 1
        elif line.startswith("as::"):
            counts["allow_suffix"] += 1
            counts["total"] += 1
        elif line.startswith("ar::"):
            counts["allow_regex"] += 1
            counts["total"] += 1
        elif line.startswith("cm::"):
            counts["cosmetic"] += 1
            counts["total"] += 1
    return counts


def read_rules() -> str:
    ensure_dirs()
    if not os.path.isfile(RULES_FILE):
        return ""
    try:
        with open(RULES_FILE, "r", encoding="utf-8", newline="") as f:
            text = f.read()
    except Exception:
        return ""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def write_rules(text: str) -> dict:
    ensure_dirs()
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.strip() + "\n" if text and not text.endswith("\n") else text
    checksum = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with _write_lock:
        if os.path.isfile(RULES_FILE):
            backup_name = f"user_rules_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pgrules"
            backup_path = os.path.join(BACKUP_DIR, backup_name)
            try:
                shutil.copy2(RULES_FILE, backup_path)
            except OSError:
                pass
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=RULES_DIR, prefix=".tmp_", suffix=".pgrules")
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            os.replace(tmp, RULES_FILE)
        finally:
            if tmp is not None and os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    counts = count_rules(text)
    return {
        "ok": True,
        "checksum": checksum,
        "counts": counts,
        "total": counts["total"],
    }


def get_metadata() -> dict:
    text = read_rules()
    checksum = hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""
    counts = count_rules(text) if text else {}
    mtime = ""
    if os.path.isfile(RULES_FILE):
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(RULES_FILE)).strftime("%Y-%m-%d %H:%M:%S")
        except OSError:
            pass
    return {
        "rule_count": counts.get("total", 0),
        "checksum": checksum,
        "last_modified": mtime,
        "counts": counts,
    }


def load_rules_into_engine(engine) -> dict:
    text = read_rules()
    valid = 0
    invalid = 0
    errors = []
    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        result = parse_rule_line(line)
        if result is None:
            continue
        if "error" in result:
            invalid += 1
            errors.append(result["error"])
            continue
        prefix = result["prefix"]
        pattern = result["pattern"]
        engine.add_pg_rule(prefix, pattern, "user_rules")
        valid += 1
    return {"valid": valid, "invalid": invalid, "errors": errors}


NATIVE_PREFIXES = tuple(PREFIXES)


@dataclass
class ParsedImportLine:
    raw: str
    normalized: Optional[str] = None
    category: str = "unsupported"
    reason: Optional[str] = None
    generated_rules: list = field(default_factory=list)
    options: list = field(default_factory=list)
    line_number: Optional[int] = None


@dataclass
class ImportResult:
    converted: list = field(default_factory=list)
    cosmetic: list = field(default_factory=list)
    browser_only: list = field(default_factory=list)
    ignored: list = field(default_factory=list)
    invalid: list = field(default_factory=list)
    unsupported: list = field(default_factory=list)
    disabled: list = field(default_factory=list)
    duplicates: list = field(default_factory=list)
    lines: list = field(default_factory=list)


def parse_line(raw_line: str, line_number: Optional[int] = None) -> ParsedImportLine:
    try:
        line, ignored_reason = preprocess_rule_line(raw_line)
        if line is None:
            category = "invalid" if ignored_reason == "line_too_long" else "ignored"
            return ParsedImportLine(raw=raw_line, category=category, reason=ignored_reason, line_number=line_number)

        if is_cosmetic_rule(line):
            return ParsedImportLine(raw=line, category="cosmetic", reason="cosmetic_rule", line_number=line_number)

        if is_umatrix_rule(line):
            return ParsedImportLine(raw=line, category="browser_only", reason="umatrix_rule", line_number=line_number)

        if line.startswith(NATIVE_PREFIXES):
            result = parse_rule_line(line)
            if result and "error" not in result:
                return ParsedImportLine(raw=line, category="converted", generated_rules=[line], line_number=line_number)
            return ParsedImportLine(raw=line, category="invalid", reason="invalid_native_rule", line_number=line_number)

        if "$badfilter" in line.lower():
            return ParsedImportLine(raw=line, category="disabled", reason="badfilter", line_number=line_number)

        is_allow = line.startswith("@@")
        candidate = line[2:] if is_allow else line

        adblock = parse_adblock_domain_rule(line)
        if adblock is not None:
            allow, domain, options = adblock
            dnstype_value = _find_option_value(options, "dnstype")
            client_value = _find_option_value(options, "client")
            if dnstype_value is not None:
                types = [t.lstrip("~") for t in dnstype_value.upper().split("|") if t.lstrip("~")]
                if not types or not all(t in DNS_RECORD_TYPES for t in types):
                    return ParsedImportLine(raw=line, normalized=domain, category="invalid", reason="invalid_dnstype", options=options, line_number=line_number)
                return ParsedImportLine(raw=line, normalized=domain, category="unsupported", reason="dnstype_unsupported", options=options, line_number=line_number)
            if client_value is not None:
                return ParsedImportLine(raw=line, normalized=domain, category="unsupported", reason="client_unsupported", options=options, line_number=line_number)
            _, browser_only_opts, _ = classify_options(options)
            if browser_only_opts:
                return ParsedImportLine(raw=line, normalized=domain, category="browser_only", reason="resource_type_option", options=options, line_number=line_number)
            prefix = "as::" if allow else "bs::"
            return ParsedImportLine(raw=line, normalized=domain, category="converted", generated_rules=[prefix + domain], options=options, line_number=line_number)

        hosts_domains = parse_hosts_line(line)
        if hosts_domains is not None:
            return ParsedImportLine(raw=line, category="converted", generated_rules=[f"bd::{d}" for d in hosts_domains], line_number=line_number)

        plain_domain = normalize_domain_cached(candidate.rstrip("^|"))
        if plain_domain is not None and "*" not in candidate and "$" not in line:
            prefix = "ad::" if is_allow else "bd::"
            return ParsedImportLine(raw=line, normalized=plain_domain, category="converted", generated_rules=[prefix + plain_domain], line_number=line_number)

        if "*" in candidate:
            pattern = wildcard_domain_to_regex(candidate)
            if pattern is not None and not is_dangerous_regex(pattern):
                prefix = "ar::" if is_allow else "br::"
                return ParsedImportLine(raw=line, category="converted", generated_rules=[prefix + pattern], line_number=line_number)

        partial = parse_partial_domain_rule(line)
        if partial is not None:
            allow, domain = partial
            prefix = "as::" if allow else "bs::"
            return ParsedImportLine(raw=line, normalized=domain, category="converted", generated_rules=[prefix + domain], line_number=line_number)

        if "$dnstype=" in line.lower():
            return ParsedImportLine(raw=line, category="unsupported", reason="dnstype_unsupported", line_number=line_number)
        if "$client=" in line.lower():
            return ParsedImportLine(raw=line, category="unsupported", reason="client_unsupported", line_number=line_number)

        return ParsedImportLine(raw=line, category="unsupported", reason="no_domain_found", line_number=line_number)
    except Exception:
        return ParsedImportLine(raw=raw_line, category="invalid", reason="parse_error", line_number=line_number)


def import_lines(lines: list) -> ImportResult:
    parsed = [parse_line(raw, idx) for idx, raw in enumerate(lines, 1)]

    badfilter_targets = set()
    for item in parsed:
        if item.category == "disabled" and item.reason == "badfilter":
            badfilter_targets.add(canonicalize_badfilter_target(item.raw))

    if badfilter_targets:
        for item in parsed:
            if item.category == "disabled":
                continue
            if canonicalize_badfilter_target(item.raw) in badfilter_targets:
                item.category = "disabled"
                item.reason = "badfilter_target"
                item.generated_rules = []

    seen_rules = set()
    for item in parsed:
        if item.category != "converted":
            continue
        kept = [r for r in item.generated_rules if r not in seen_rules]
        seen_rules.update(kept)
        if not kept:
            item.category = "duplicates"
            item.reason = "duplicate_rule"
            item.generated_rules = []
        else:
            item.generated_rules = kept

    result = ImportResult(lines=parsed)
    bucket_map = {
        "converted": None,
        "cosmetic": result.cosmetic,
        "browser_only": result.browser_only,
        "ignored": result.ignored,
        "invalid": result.invalid,
        "unsupported": result.unsupported,
        "disabled": result.disabled,
        "duplicates": result.duplicates,
    }
    for item in parsed:
        if item.category == "converted":
            result.converted.extend(item.generated_rules)
        else:
            bucket = bucket_map.get(item.category)
            if bucket is not None:
                bucket.append(item.raw)

    logger.info(
        "Imported blocklist: total=%d converted=%d cosmetic=%d browser_only=%d ignored=%d "
        "invalid=%d unsupported=%d disabled=%d duplicates=%d",
        len(lines), len(result.converted), len(result.cosmetic), len(result.browser_only),
        len(result.ignored), len(result.invalid), len(result.unsupported), len(result.disabled),
        len(result.duplicates),
    )
    return result


_BLOCK_TO_ALLOW_PREFIX = {"bd::": "ad::", "bs::": "as::", "br::": "ar::"}


def convert_blocklist_text(text: str, list_id: str, source_url: str = "", list_type: str = "block") -> dict:
    lines = text.splitlines()
    result = import_lines(lines)
    converted = result.converted
    if list_type == "allow":
        converted = [
            _BLOCK_TO_ALLOW_PREFIX.get(r[:4], r[:4]) + r[4:]
            if len(r) > 4 and r[:4] in _BLOCK_TO_ALLOW_PREFIX
            else r
            for r in converted
        ]
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    cache = {
        "version": 1,
        "list_id": list_id,
        "source_url": source_url,
        "source_sha256": sha256,
        "converted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "raw": len(lines),
            "converted": len(converted),
            "cosmetic": len(result.cosmetic),
            "browser_only": len(result.browser_only),
            "ignored": len(result.ignored),
            "invalid": len(result.invalid),
            "unsupported": len(result.unsupported),
            "disabled": len(result.disabled),
            "duplicates": len(result.duplicates),
        },
        "rules": converted,
    }
    return {
        "cache": cache,
        "converted": result.converted,
        "cosmetic": result.cosmetic,
        "browser_only": result.browser_only,
        "ignored": result.ignored,
        "invalid": result.invalid,
        "unsupported": result.unsupported,
        "disabled": result.disabled,
        "duplicates": result.duplicates,
        "sha256": sha256,
        "report": [asdict(item) for item in result.lines],
    }


def save_blocklist_cache(list_id: str, cache: dict):
    cache_dir = os.path.join("data", "blocklists", "cache")
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, f"{list_id}.json")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=cache_dir, prefix=".tmp_", suffix=".json", delete=False) as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
        tmp_path = f.name
    os.replace(tmp_path, path)


def load_blocklist_cache(list_id: str) -> Optional[dict]:
    path = os.path.join("data", "blocklists", "cache", f"{list_id}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_import_report(list_id: str, report: list):
    d = os.path.join("data", "blocklists", "reports")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{list_id}.json")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=d, prefix=".tmp_", suffix=".json", delete=False) as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        tmp_path = f.name
    os.replace(tmp_path, path)


def load_import_report(list_id: str) -> list:
    path = os.path.join("data", "blocklists", "reports", f"{list_id}.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_cosmetic_rules(list_id: str, rules: list):
    d = os.path.join("data", "blocklists", "cosmetic")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{list_id}.txt")
    text = "\n".join(rules) + "\n" if rules else ""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def save_unsupported_rules(list_id: str, rules: list):
    d = os.path.join("data", "blocklists", "unsupported")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{list_id}.txt")
    text = "\n".join(rules) + "\n" if rules else ""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def save_original_text(list_id: str, text: str):
    d = os.path.join("data", "blocklists", "original")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{list_id}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def load_original_text(list_id: str) -> Optional[str]:
    path = os.path.join("data", "blocklists", "original", f"{list_id}.txt")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def read_cosmetic_rules(list_id: str) -> list:
    path = os.path.join("data", "blocklists", "cosmetic", f"{list_id}.txt")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []


def read_unsupported_rules(list_id: str) -> list:
    path = os.path.join("data", "blocklists", "unsupported", f"{list_id}.txt")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []


def build_indexes_from_cache(cache: dict, engine) -> dict:
    counts = {"valid": 0, "invalid": 0}
    source = cache.get("list_name") or cache.get("list_id", "blocklist")
    for raw in cache.get("rules", []):
        result = parse_rule_line(raw)
        if result is None or "error" in result:
            counts["invalid"] += 1
            continue
        prefix = result["prefix"]
        pattern = result["pattern"]
        if prefix == "bd::":
            engine.exact_block.add(pattern)
            engine._track_source(pattern, source)
        elif prefix == "bs::":
            engine.suffix_block.add(pattern)
            engine.suffix_block_trie.add(pattern, pattern)
            engine._track_source(pattern, source)
        elif prefix == "br::":
            compiled = re.compile(pattern, re.IGNORECASE)
            engine.regex_block.add(compiled, f"/{pattern}/")
            engine._track_source(f"/{pattern}/", source)
        elif prefix == "ad::":
            engine.exact_allow.add(pattern)
            engine._track_source(pattern, source)
        elif prefix == "as::":
            engine.suffix_allow.add(pattern)
            engine.suffix_allow_trie.add(pattern, pattern)
            engine._track_source(pattern, source)
        elif prefix == "ar::":
            compiled = re.compile(pattern, re.IGNORECASE)
            engine.regex_allow.add(compiled, f"/{pattern}/")
            engine._track_source(f"/{pattern}/", source)
        elif prefix == "cm::":
            engine.cosmetic_rules.append(pattern)
            engine._track_source(pattern, source)
        counts["valid"] += 1
    return counts


def migration_needed() -> bool:
    if os.path.isfile(RULES_FILE):
        return False
    import sqlite3
    path = os.environ.get("LOCALDNSGUARD_DB", "localdnsguard.sqlite3")
    if not os.path.isfile(path):
        return False
    try:
        conn = sqlite3.connect(path)
        row = conn.execute("SELECT COUNT(*) FROM rules").fetchone()
        conn.close()
        return row and row[0] > 0
    except Exception:
        return False


def run_migration():
    import sqlite3
    path = os.environ.get("LOCALDNSGUARD_DB", "localdnsguard.sqlite3")
    if not os.path.isfile(path):
        return {"migrated": False, "reason": "no database"}
    if os.path.isfile(RULES_FILE):
        return {"migrated": False, "reason": "already migrated"}
    try:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        rules = conn.execute(
            "SELECT action, pattern_type, pattern FROM rules WHERE enabled=1 ORDER BY id ASC"
        ).fetchall()
        conn.close()
    except Exception as exc:
        return {"migrated": False, "reason": str(exc)}
    if not rules:
        return {"migrated": False, "reason": "no rules to migrate"}
    pg_lines = []
    for r in rules:
        action = r["action"]
        pt = r["pattern_type"]
        pattern = r["pattern"]
        if action == "allow" and pt == "domain":
            pg_lines.append(f"as::{pattern}")
        elif action == "allow" and pt == "exact":
            pg_lines.append(f"ad::{pattern}")
        elif action == "allow" and pt == "regex":
            pg_lines.append(f"ar::{pattern}")
        elif action == "allow" and pt == "wildcard":
            clean = pattern.lstrip("*.")
            pg_lines.append(f"as::{clean}")
        elif action == "block" and pt == "domain":
            pg_lines.append(f"bs::{pattern}")
        elif action == "block" and pt == "exact":
            pg_lines.append(f"bd::{pattern}")
        elif action == "block" and pt == "regex":
            pg_lines.append(f"br::{pattern}")
        elif action == "block" and pt == "wildcard":
            clean = pattern.lstrip("*.")
            pg_lines.append(f"bs::{clean}")
    if os.path.isfile(RULES_FILE):
        backup_path = os.path.join(BACKUP_DIR, "user_rules_backup_before_migration.pgrules")
        try:
            shutil.copy2(RULES_FILE, backup_path)
        except OSError:
            pass
    text = "\n".join(pg_lines) + "\n"
    write_rules(text)
    backup_path = os.path.join(BACKUP_DIR, "user_rules_backup_before_migration.pgrules")
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as src:
            with open(backup_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())
    except OSError:
        pass
    return {"migrated": True, "count": len(pg_lines)}
