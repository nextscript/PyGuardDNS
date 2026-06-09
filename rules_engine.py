import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Optional

RULES_DIR = os.path.join("data", "rules")
RULES_FILE = os.path.join(RULES_DIR, "user_rules.pgrules")
BACKUP_DIR = os.path.join(RULES_DIR, "backups")

PREFIXES = frozenset({"bd::", "bs::", "br::", "ad::", "as::", "ar::"})
BLOCK_PREFIXES = frozenset({"bd::", "bs::", "br::"})
ALLOW_PREFIXES = frozenset({"ad::", "as::", "ar::"})

PREFIX_MEANING = {
    "bd::": "block exact domain",
    "bs::": "block suffix domain",
    "br::": "block regex",
    "ad::": "allow exact domain",
    "as::": "allow suffix domain",
    "ar::": "allow regex",
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

    prefix = line.split("::")[0] + "::" if "::" in line else ""
    if prefix and prefix not in PREFIXES:
        return {"error": f'Invalid prefix "{prefix}"\nExpected: bd::  bs::  br::  ad::  as::  ar::', "line": line}
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
    counts = {"block_exact": 0, "block_suffix": 0, "block_regex": 0, "allow_exact": 0, "allow_suffix": 0, "allow_regex": 0, "total": 0}
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
    return counts


def read_rules() -> str:
    ensure_dirs()
    if not os.path.isfile(RULES_FILE):
        return ""
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def write_rules(text: str) -> dict:
    ensure_dirs()
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
            with os.fdopen(fd, "w", encoding="utf-8") as f:
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


def convert_adguard_rule(line: str) -> Optional[str]:
    if not line or line.startswith("!") or line.startswith("#") or line.startswith("["):
        return None
    line = line.strip()
    if not line:
        return None
    is_allow = line.startswith("@@")
    if is_allow:
        line = line[2:].strip()
    if line.startswith("||") and line.endswith("^"):
        domain = line[2:-1]
        prefix = "as::" if is_allow else "bs::"
        return f"{prefix}{domain}"
    if line.startswith("||"):
        domain = line[2:].split("^")[0].split("/")[0]
        prefix = "as::" if is_allow else "bs::"
        return f"{prefix}{domain}"
    if line.startswith("/") and line.endswith("/"):
        pattern = line[1:-1]
        prefix = "ar::" if is_allow else "br::"
        return f"{prefix}{pattern}"
    if line.startswith("|"):
        domain = line[1:].split("^")[0].split("/")[0]
        prefix = "ad::" if is_allow else "bd::"
        return f"{prefix}{domain}"
    if re.match(r"^\d+\.\d+\.\d+\.\d+\s+", line) or line.startswith("0.0.0.0") or line.startswith("127.0.0.1") or line.startswith("::1"):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].strip()
            return f"bd::{domain}"
    if re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", line):
        prefix = "ad::" if is_allow else "bd::"
        return f"{prefix}{line}"
    if line.startswith("@@") and line.endswith("/"):
        domain = line[2:-1]
        return f"as::{domain}"
    return None


def convert_hosts_line(line: str) -> Optional[str]:
    if not line or line.startswith("#") or line.startswith("!"):
        return None
    line = line.strip()
    if not line:
        return None
    parts = line.split()
    if len(parts) < 2:
        return None
    ip = parts[0].strip()
    if ip not in ("0.0.0.0", "127.0.0.1", "::1", "255.255.255.255"):
        return None
    domain = parts[1].strip().lower()
    if domain in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
        return None
    return f"bd::{domain}"


def is_cosmetic_rule(line: str) -> bool:
    return "##" in line or "#@#" in line


def convert_blocklist_text(text: str, list_id: str, source_url: str = "") -> dict:
    converted = []
    cosmetic = []
    unsupported = []
    raw_count = 0
    for raw_line in text.splitlines():
        raw_count += 1
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("!") or line.startswith("#"):
            continue
        if is_cosmetic_rule(line):
            cosmetic.append(line)
            continue
        pg_rule = convert_adguard_rule(line)
        if pg_rule:
            converted.append(pg_rule)
            continue
        pg_hosts = convert_hosts_line(line)
        if pg_hosts:
            converted.append(pg_hosts)
            continue
        unsupported.append(line)
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    cache = {
        "version": 1,
        "list_id": list_id,
        "source_url": source_url,
        "source_sha256": sha256,
        "converted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "raw": raw_count,
            "converted": len(converted),
            "cosmetic": len(cosmetic),
            "unsupported": len(unsupported),
        },
        "rules": converted,
    }
    return {
        "cache": cache,
        "converted": converted,
        "cosmetic": cosmetic,
        "unsupported": unsupported,
        "sha256": sha256,
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
