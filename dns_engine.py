import re
import ipaddress
from dataclasses import dataclass
from typing import Optional, Pattern

try:
    import idna
except ImportError:
    idna = None

from client_manager import SERVICE_DOMAINS, SAFESEARCH_REWRITES, YOUTUBE_SAFESEARCH_REWRITES, SAFESEARCH_PROFILE_COLUMNS


@dataclass(frozen=True)
class FilterResult:
    action: str
    reason: str = ""
    matched_domain: str = ""
    answer_ip: Optional[str] = None
    list_name: Optional[str] = None
    matched_rule: str = ""
    matched_list: str = ""
    profile_name: str = ""


class FilterEngine:
    def __init__(self):
        self.exact_block: set[str] = set()
        self.exact_allow: set[str] = set()
        self.suffix_block: set[str] = set()
        self.suffix_allow: set[str] = set()
        self.regex_block: list[tuple[Pattern, str]] = []
        self.regex_allow: list[tuple[Pattern, str]] = []
        self.rewrite_map: dict[str, str] = {}
        self.rewrite_wildcard: dict[str, str] = {}
        self.rewrite_domain_type: dict[str, str] = {}
        self.invalid_rules: list[str] = []
        self.pattern_sources: dict[str, str] = {}

        self.profiles: dict[int, dict] = {}
        self.profile_safesearch: dict[int, list[str]] = {}
        self.profile_youtube_restricted: dict[int, bool] = {}
        self.profile_blocked_services: dict[int, set[str]] = {}

    def _ensure_profile(self, profile_id: int) -> dict:
        if profile_id not in self.profiles:
            self.profiles[profile_id] = {
                "exact_block": set(),
                "exact_allow": set(),
                "suffix_block": set(),
                "suffix_allow": set(),
                "regex_block": [],
                "regex_allow": [],
                "rewrite_map": {},
                "rewrite_wildcard": {},
                "pattern_sources": {},
            }
        else:
            p = self.profiles[profile_id]
            if "rewrite_wildcard" not in p:
                p["rewrite_wildcard"] = {}
        return self.profiles[profile_id]

    def normalize_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        if domain.endswith("."):
            domain = domain[:-1]
        if not domain:
            return ""
        if idna and any(ord(c) >= 128 for c in domain):
            try:
                domain = idna.encode(domain).decode("ascii")
            except Exception:
                return ""
        if not re.match(r"^[a-z0-9._-]+$", domain):
            return ""
        return domain

    def add_rule(self, raw_rule: str, rule_type: str = "block", list_name: str = "", profile_id: Optional[int] = None) -> None:
        rule = raw_rule.strip()
        if not rule:
            return
        if rule.startswith("#") or rule.startswith("!"):
            return

        is_allow = rule.startswith("@@") or rule_type == "allow"

        if rule.startswith("@@"):
            rule = rule[2:].strip()

        if rule_type == "rewrite" or "->" in rule or " = " in rule:
            self._add_rewrite_rule(rule, list_name, profile_id)
            return

        if rule.startswith("/") and rule.endswith("/"):
            self._add_regex_rule(rule, is_allow, list_name, profile_id)
            return

        hosts_rule = self._parse_hosts_rule(rule)
        if hosts_rule:
            domain, ip = hosts_rule
            if ip in {"0.0.0.0", "127.0.0.1", "::1"}:
                if profile_id:
                    self._ensure_profile(profile_id)["exact_block"].add(domain)
                    self._profile_track_source(profile_id, domain, list_name)
                else:
                    self.exact_block.add(domain)
                    self._track_source(domain, list_name)
            else:
                if profile_id:
                    self._ensure_profile(profile_id)["rewrite_map"][domain] = ip
                    self._profile_track_source(profile_id, domain, list_name)
                else:
                    self.rewrite_map[domain] = ip
                    self._track_source(domain, list_name)
            return

        if rule.startswith("||"):
            domain = rule[2:].replace("^", "")
            domain = self.normalize_domain(domain)
            if domain:
                if profile_id:
                    target = self._ensure_profile(profile_id)["suffix_allow" if is_allow else "suffix_block"]
                    target.add(domain)
                    self._profile_track_source(profile_id, domain, list_name)
                else:
                    self._target_suffix(is_allow).add(domain)
                    self._track_source(domain, list_name)
            return

        if rule.startswith("*."):
            domain = self.normalize_domain(rule[2:])
            if domain:
                if profile_id:
                    target = self._ensure_profile(profile_id)["suffix_allow" if is_allow else "suffix_block"]
                    target.add(domain)
                    self._profile_track_source(profile_id, domain, list_name)
                else:
                    self._target_suffix(is_allow).add(domain)
                    self._track_source(domain, list_name)
            return

        domain = self.normalize_domain(rule.replace("^", ""))
        if domain:
            if profile_id:
                target = self._ensure_profile(profile_id)["exact_allow" if is_allow else "exact_block"]
                target.add(domain)
                self._profile_track_source(profile_id, domain, list_name)
            else:
                self._target_exact(is_allow).add(domain)
                self._track_source(domain, list_name)
        else:
            self.invalid_rules.append(raw_rule)

    def set_profile_safesearch(self, profile_id: int, engines: list[str]) -> None:
        self.profile_safesearch[profile_id] = engines

    def set_profile_youtube_restricted(self, profile_id: int, enabled: bool) -> None:
        self.profile_youtube_restricted[profile_id] = enabled

    def set_profile_blocked_services(self, profile_id: int, services: set[str]) -> None:
        self.profile_blocked_services[profile_id] = services

    def check(self, domain: str, filtering_enabled: bool = True, profile_id: Optional[int] = None) -> FilterResult:
        domain = self.normalize_domain(domain)
        if not domain:
            return FilterResult("REFUSED", "invalid_domain", matched_rule="invalid_domain")

        if not filtering_enabled:
            return FilterResult("ALLOW", "client_filtering_disabled", matched_rule="filtering_disabled")

        if profile_id and profile_id in self.profiles:
            p = self.profiles[profile_id]
            result = self._check_profile_allows(p, domain)
            if result:
                return result

        result = self._check_global_allows(domain)
        if result:
            return result

        if profile_id and profile_id in self.profiles:
            p = self.profiles[profile_id]
            result = self._check_profile_rewrites(p, domain)
            if result:
                return result

        result = self._check_global_rewrites(domain)
        if result:
            return result

        if profile_id and profile_id in self.profiles:
            p = self.profiles[profile_id]
            result = self._check_profile_blocks(p, domain)
            if result:
                return result

        result = self._check_global_blocks(domain)
        if result:
            return result

        if profile_id:
            result = self._check_safesearch(domain, profile_id)
            if result:
                return result

        if profile_id:
            result = self._check_youtube_restricted(domain, profile_id)
            if result:
                return result

        if profile_id:
            result = self._check_service_block(domain, profile_id)
            if result:
                return result

        return FilterResult("ALLOW", "no_match")

    def _check_profile_allows(self, p: dict, domain: str) -> Optional[FilterResult]:
        if domain in p["exact_allow"]:
            return FilterResult("ALLOW", "profile_exact_allow", domain, matched_rule=domain, list_name=p.get("pattern_sources", {}).get(domain))
        matched = self._suffix_match(domain, p["suffix_allow"])
        if matched:
            return FilterResult("ALLOW", "profile_suffix_allow", matched, matched_rule=domain, list_name=p.get("pattern_sources", {}).get(matched))
        for pattern, raw in p["regex_allow"]:
            if pattern.search(domain):
                return FilterResult("ALLOW", "profile_regex_allow", raw, matched_rule=domain, list_name=p.get("pattern_sources", {}).get(raw))
        return None

    def _check_global_allows(self, domain: str) -> Optional[FilterResult]:
        if domain in self.exact_allow:
            return FilterResult("ALLOW", "exact_allow", domain, matched_rule=domain, list_name=self._source(domain))
        matched = self._suffix_match(domain, self.suffix_allow)
        if matched:
            return FilterResult("ALLOW", "suffix_allow", matched, matched_rule=domain, list_name=self._source(matched))
        for pattern, raw in self.regex_allow:
            if pattern.search(domain):
                return FilterResult("ALLOW", "regex_allow", raw, matched_rule=domain, list_name=self._source(raw))
        return None

    def _check_profile_blocks(self, p: dict, domain: str) -> Optional[FilterResult]:
        if domain in p["exact_block"]:
            return FilterResult("BLOCK", "profile_exact_block", domain, matched_rule=domain, list_name=p.get("pattern_sources", {}).get(domain))
        matched = self._suffix_match(domain, p["suffix_block"])
        if matched:
            return FilterResult("BLOCK", "profile_suffix_block", matched, matched_rule=domain, list_name=p.get("pattern_sources", {}).get(matched))
        for pattern, raw in p["regex_block"]:
            if pattern.search(domain):
                return FilterResult("BLOCK", "profile_regex_block", raw, matched_rule=domain, list_name=p.get("pattern_sources", {}).get(raw))
        return None

    def _check_global_blocks(self, domain: str) -> Optional[FilterResult]:
        if domain in self.exact_block:
            return FilterResult("BLOCK", "exact_block", domain, matched_rule=domain, list_name=self._source(domain))
        matched = self._suffix_match(domain, self.suffix_block)
        if matched:
            return FilterResult("BLOCK", "suffix_block", matched, matched_rule=domain, list_name=self._source(matched))
        for pattern, raw in self.regex_block:
            if pattern.search(domain):
                return FilterResult("BLOCK", "regex_block", raw, matched_rule=domain, list_name=self._source(raw))
        return None

    def _check_profile_rewrites(self, p: dict, domain: str) -> Optional[FilterResult]:
        if domain in p["rewrite_map"]:
            return FilterResult("REWRITE", "profile_rewrite", domain, matched_rule=domain, answer_ip=p["rewrite_map"][domain], list_name=p.get("pattern_sources", {}).get(domain))
        matched = self._wildcard_rewrite_match(domain, p.get("rewrite_wildcard", {}))
        if matched:
            return FilterResult("REWRITE", "profile_rwild", domain, matched_rule=matched, answer_ip=p["rewrite_wildcard"][matched], list_name=p.get("pattern_sources", {}).get(matched))
        return None

    def _check_global_rewrites(self, domain: str) -> Optional[FilterResult]:
        if domain in self.rewrite_map:
            return FilterResult("REWRITE", "rewrite", domain, matched_rule=domain, answer_ip=self.rewrite_map[domain], list_name=self._source(domain))
        matched = self._wildcard_rewrite_match(domain, self.rewrite_wildcard)
        if matched:
            return FilterResult("REWRITE", "rwild", domain, matched_rule=matched, answer_ip=self.rewrite_wildcard[matched], list_name=self._source(matched))
        return None

    def _wildcard_rewrite_match(self, domain: str, wc_map: dict) -> Optional[str]:
        parts = domain.split(".")
        for i in range(len(parts)):
            candidate = "*." + ".".join(parts[i:])
            if candidate in wc_map:
                return candidate
        return None

    def _check_safesearch(self, domain: str, profile_id: int) -> Optional[FilterResult]:
        engines = self.profile_safesearch.get(profile_id)
        if not engines:
            return None
        for eng in engines:
            rewrites = SAFESEARCH_REWRITES if eng in ("google", "bing", "ddg") else {}
            if domain in rewrites:
                return FilterResult("REWRITE", "safesearch", domain, matched_rule=domain, answer_ip=rewrites[domain]["force"], list_name=f"safesearch-{eng}")
            for pattern, target in rewrites.items():
                if domain.endswith("." + pattern) or domain == pattern:
                    return FilterResult("REWRITE", "safesearch", domain, matched_rule=pattern, answer_ip=target["force"], list_name=f"safesearch-{eng}")
        return None

    def _check_youtube_restricted(self, domain: str, profile_id: int) -> Optional[FilterResult]:
        enabled = self.profile_youtube_restricted.get(profile_id)
        if not enabled:
            return None
        rewrites = YOUTUBE_SAFESEARCH_REWRITES
        if domain in rewrites:
            return FilterResult("REWRITE", "youtube_restricted", domain, matched_rule=domain, answer_ip=rewrites[domain]["force"], list_name="youtube-restricted")
        for pattern, target in rewrites.items():
            if domain.endswith("." + pattern) or domain == pattern:
                return FilterResult("REWRITE", "youtube_restricted", domain, matched_rule=pattern, answer_ip=target["force"], list_name="youtube-restricted")
        return None

    def _check_service_block(self, domain: str, profile_id: int) -> Optional[FilterResult]:
        services = self.profile_blocked_services.get(profile_id)
        if not services:
            return None
        for service_name in services:
            domains = SERVICE_DOMAINS.get(service_name, [])
            for svc_domain in domains:
                if domain == svc_domain or domain.endswith("." + svc_domain):
                    return FilterResult("BLOCK", "service_block", domain, matched_rule=svc_domain, list_name=f"service-{service_name}")
        return None

    def _target_exact(self, is_allow: bool) -> set[str]:
        return self.exact_allow if is_allow else self.exact_block

    def _target_suffix(self, is_allow: bool) -> set[str]:
        return self.suffix_allow if is_allow else self.suffix_block

    def _add_regex_rule(self, rule: str, is_allow: bool, list_name: str = "", profile_id: Optional[int] = None) -> None:
        pattern = rule[1:-1]
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            self.invalid_rules.append(rule)
            return
        if profile_id:
            p = self._ensure_profile(profile_id)
            target = p["regex_allow"] if is_allow else p["regex_block"]
            target.append((compiled, rule))
            self._profile_track_source(profile_id, rule, list_name)
        else:
            target = self.regex_allow if is_allow else self.regex_block
            target.append((compiled, rule))
            self._track_source(rule, list_name)

    def _add_rewrite_rule(self, rule: str, list_name: str = "", profile_id: Optional[int] = None) -> None:
        if "->" in rule:
            domain, ip = rule.split("->", 1)
        elif "=" in rule:
            domain, ip = rule.split("=", 1)
        else:
            self.invalid_rules.append(rule)
            return
        domain = self.normalize_domain(domain)
        ip = ip.strip()
        is_wildcard = domain.startswith("*.") if domain else False
        clean_domain = domain[2:] if is_wildcard else domain
        if not clean_domain:
            self.invalid_rules.append(rule)
            return
        if profile_id:
            p = self._ensure_profile(profile_id)
            if is_wildcard:
                if "rewrite_wildcard" not in p:
                    p["rewrite_wildcard"] = {}
                p["rewrite_wildcard"][domain] = ip
                p["pattern_sources"][domain] = list_name
            else:
                p["rewrite_map"][clean_domain] = ip
                self._profile_track_source(profile_id, clean_domain, list_name)
        else:
            if is_wildcard:
                self.rewrite_wildcard[domain] = ip
                self._track_source(domain, list_name)
            else:
                self.rewrite_map[clean_domain] = ip
                self._track_source(clean_domain, list_name)

    def _parse_hosts_rule(self, rule: str) -> Optional[tuple[str, str]]:
        parts = rule.split()
        if len(parts) < 2:
            return None
        ip = parts[0].strip()
        domain = self.normalize_domain(parts[1])
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not domain:
            return None
        return domain, ip

    def _suffix_match(self, domain: str, suffix_set: set[str]) -> Optional[str]:
        current = domain
        while True:
            if current in suffix_set:
                return current
            if "." not in current:
                return None
            current = current.split(".", 1)[1]

    def _track_source(self, key: str, list_name: str) -> None:
        if list_name:
            self.pattern_sources[key] = list_name

    def _source(self, key: str) -> Optional[str]:
        return self.pattern_sources.get(key)

    def _profile_track_source(self, profile_id: int, key: str, list_name: str) -> None:
        if list_name:
            p = self._ensure_profile(profile_id)
            p["pattern_sources"][key] = list_name

    def clear_profile(self, profile_id: int) -> None:
        if profile_id in self.profiles:
            del self.profiles[profile_id]

    def list_profiles(self) -> list[int]:
        return list(self.profiles.keys())
