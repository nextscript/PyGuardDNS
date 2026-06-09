import re
import ipaddress
from collections import OrderedDict
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


class DomainSuffixTrie:
    def __init__(self):
        self.children: dict[str, "DomainSuffixTrie"] = {}
        self.value = None
        self.terminal = False

    def add(self, domain: str, value: object | None = None) -> None:
        node = self
        for label in reversed(domain.split(".")):
            if not label:
                continue
            node = node.children.setdefault(label, DomainSuffixTrie())
        node.terminal = True
        node.value = value if value is not None else domain

    def match(self, domain: str):
        node = self
        best = None
        for label in reversed(domain.split(".")):
            node = node.children.get(label)
            if node is None:
                break
            if node.terminal:
                best = node.value
        return best


class RegexIndex:
    def __init__(self):
        self.rules: list[tuple[Pattern, str]] = []
        self.literal_buckets: dict[str, list[int]] = {}
        self.fallback: list[int] = []

    def add(self, pattern: Pattern, raw: str) -> None:
        idx = len(self.rules)
        self.rules.append((pattern, raw))

        literals = self._extract_required_literals(raw)
        if not literals:
            self.fallback.append(idx)
            return

        for lit in literals:
            self.literal_buckets.setdefault(lit, []).append(idx)

    def candidates(self, domain: str):
        labels = set(domain.split("."))
        tokens = labels | self._domain_ngrams(domain)

        seen: set[int] = set()
        for token in tokens:
            for idx in self.literal_buckets.get(token, ()):
                if idx not in seen:
                    seen.add(idx)
                    yield self.rules[idx]

        for idx in self.fallback:
            if idx not in seen:
                yield self.rules[idx]

    def fallback_ratio(self) -> float:
        return len(self.fallback) / max(1, len(self))

    def __len__(self) -> int:
        return len(self.rules)

    @staticmethod
    def _domain_ngrams(domain: str) -> set[str]:
        parts = domain.split(".")
        out = set()
        for i in range(len(parts)):
            joined = ".".join(parts[i:])
            if len(joined) >= 4:
                out.add(joined)
        return out

    @staticmethod
    def _extract_required_literals(raw_rule: str) -> set[str]:
        pattern = raw_rule[1:-1] if raw_rule.startswith("/") and raw_rule.endswith("/") else raw_rule
        pattern = pattern.lower()

        # Alternation and optional pieces make literal extraction unsafe without
        # a full regex parser, so keep those rules on the conservative path.
        if "|" in pattern or "?" in pattern:
            return set()

        # Work with a copy where escaped dots are plain dots (for splitting).
        flattened = pattern.replace(r"\.", ".")
        chunks = re.split(r"[\\\[\]\(\)\{\}\^\$\*\+\|]+", flattened)

        ignored = {"com", "net", "org", "de", "www", "http", "https", "example", "invalid", "local"}
        literals = set()

        for chunk in chunks:
            chunk = chunk.strip(".-_")
            if len(chunk) < 4:
                continue
            if chunk in ignored:
                continue
            if not re.fullmatch(r"[a-z0-9._-]+", chunk):
                continue

            # Reject literals that are adjacent to a dynamic regex construct
            # (character class, group, quantifier, etc.) in the original
            # pattern.  Such a literal may not appear as a standalone token
            # in a matching domain, causing the candidate prefilter to skip
            # the regex even though it would match.
            #
            # Safe neighbors:  ^ $ .  (alphanumeric means the literal is
            # embedded in a longer safe identifier and is handled elsewhere).
            # Unsafe neighbors:  [ ] ( ) { } * + \ etc.
            idx = flattened.find(chunk)
            if idx < 0:
                continue
            if idx > 0:
                prev = flattened[idx - 1]
                if prev not in "^.$_-" and not prev.isalnum():
                    continue
            end = idx + len(chunk)
            if end < len(flattened):
                nxt = flattened[end]
                if nxt not in "$.-_" and not nxt.isalnum():
                    continue

            literals.add(chunk)
            for label in chunk.split("."):
                if len(label) >= 4 and label not in ignored:
                    literals.add(label)

        return set(sorted(literals, key=len, reverse=True)[:3])


class FilterEngine:
    def __init__(self):
        self.exact_block: set[str] = set()
        self.exact_allow: set[str] = set()
        self.suffix_block: set[str] = set()
        self.suffix_allow: set[str] = set()
        self.suffix_block_trie = DomainSuffixTrie()
        self.suffix_allow_trie = DomainSuffixTrie()
        self.regex_block = RegexIndex()
        self.regex_allow = RegexIndex()
        self.rewrite_map: dict[str, str] = {}
        self.rewrite_wildcard: dict[str, str] = {}
        self.rewrite_domain_type: dict[str, str] = {}
        self.invalid_rules: list[str] = []
        self.pattern_sources: dict[str, set[str]] = {}

        self.profiles: dict[int, dict] = {}
        self.profile_safesearch: dict[int, list[str]] = {}
        self.profile_youtube_restricted: dict[int, bool] = {}
        self.profile_blocked_services: dict[int, set[str]] = {}
        self._negative_cache: OrderedDict[tuple[str, Optional[int]], FilterResult] = OrderedDict()
        self._negative_cache_max = 50000
        self._rules_generation = 0

    def _ensure_profile(self, profile_id: int) -> dict:
        if profile_id not in self.profiles:
            self.profiles[profile_id] = {
                "exact_block": set(),
                "exact_allow": set(),
                "suffix_block": set(),
                "suffix_allow": set(),
                "suffix_block_trie": DomainSuffixTrie(),
                "suffix_allow_trie": DomainSuffixTrie(),
                "regex_block": RegexIndex(),
                "regex_allow": RegexIndex(),
                "rewrite_map": {},
                "rewrite_wildcard": {},
                "pattern_sources": {},
            }
        else:
            p = self.profiles[profile_id]
            if "rewrite_wildcard" not in p:
                p["rewrite_wildcard"] = {}
            if "suffix_block_trie" not in p:
                p["suffix_block_trie"] = DomainSuffixTrie()
                for suffix in p.get("suffix_block", set()):
                    p["suffix_block_trie"].add(suffix, suffix)
            if "suffix_allow_trie" not in p:
                p["suffix_allow_trie"] = DomainSuffixTrie()
                for suffix in p.get("suffix_allow", set()):
                    p["suffix_allow_trie"].add(suffix, suffix)
            self._ensure_profile_regex_indexes(p)
        return self.profiles[profile_id]

    @staticmethod
    def _ensure_profile_regex_indexes(p: dict) -> None:
        if isinstance(p.get("regex_block"), list):
            idx = RegexIndex()
            for compiled, raw in p["regex_block"]:
                idx.add(compiled, raw)
            p["regex_block"] = idx
        if isinstance(p.get("regex_allow"), list):
            idx = RegexIndex()
            for compiled, raw in p["regex_allow"]:
                idx.add(compiled, raw)
            p["regex_allow"] = idx

    def _bump_generation(self) -> None:
        self._rules_generation += 1
        self._negative_cache.clear()

    def _negative_cache_get(self, domain: str, profile_id: Optional[int]) -> Optional[FilterResult]:
        key = (domain, profile_id)
        result = self._negative_cache.get(key)
        if result is not None:
            self._negative_cache.move_to_end(key)
        return result

    def _negative_cache_put(self, domain: str, profile_id: Optional[int], result: FilterResult) -> None:
        key = (domain, profile_id)
        self._negative_cache[key] = result
        self._negative_cache.move_to_end(key)
        if len(self._negative_cache) > self._negative_cache_max:
            self._negative_cache.popitem(last=False)

    def regex_index_stats(self) -> dict:
        global_total = len(self.regex_allow) + len(self.regex_block)
        global_fallback = len(self.regex_allow.fallback) + len(self.regex_block.fallback)
        profile_total = 0
        profile_fallback = 0
        for profile in self.profiles.values():
            self._ensure_profile_regex_indexes(profile)
            profile_total += len(profile["regex_allow"]) + len(profile["regex_block"])
            profile_fallback += len(profile["regex_allow"].fallback) + len(profile["regex_block"].fallback)
        total = global_total + profile_total
        fallback = global_fallback + profile_fallback
        ratio = fallback / max(1, total)
        warning = ""
        if ratio > 0.10:
            warning = "High regex fallback ratio: many regex rules cannot be indexed and may slow clean misses."
        return {
            "regex_rules": total,
            "regex_fallback_rules": fallback,
            "regex_fallback_ratio": ratio,
            "warning": warning,
        }

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
        self._bump_generation()

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
                    p = self._ensure_profile(profile_id)
                    target = p["suffix_allow" if is_allow else "suffix_block"]
                    target.add(domain)
                    p["suffix_allow_trie" if is_allow else "suffix_block_trie"].add(domain, domain)
                    self._profile_track_source(profile_id, domain, list_name)
                else:
                    self._target_suffix(is_allow).add(domain)
                    self._target_suffix_trie(is_allow).add(domain, domain)
                    self._track_source(domain, list_name)
            return

        if rule.startswith("*."):
            domain = self.normalize_domain(rule[2:])
            if domain:
                if profile_id:
                    p = self._ensure_profile(profile_id)
                    target = p["suffix_allow" if is_allow else "suffix_block"]
                    target.add(domain)
                    p["suffix_allow_trie" if is_allow else "suffix_block_trie"].add(domain, domain)
                    self._profile_track_source(profile_id, domain, list_name)
                else:
                    self._target_suffix(is_allow).add(domain)
                    self._target_suffix_trie(is_allow).add(domain, domain)
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
        self._bump_generation()

    def set_profile_youtube_restricted(self, profile_id: int, enabled: bool) -> None:
        self.profile_youtube_restricted[profile_id] = enabled
        self._bump_generation()

    def set_profile_blocked_services(self, profile_id: int, services: set[str]) -> None:
        self.profile_blocked_services[profile_id] = services
        self._bump_generation()

    def check(self, domain: str, filtering_enabled: bool = True, profile_id: Optional[int] = None) -> FilterResult:
        domain = self.normalize_domain(domain)
        if not domain:
            return FilterResult("REFUSED", "invalid_domain", matched_rule="invalid_domain")

        if not filtering_enabled:
            return FilterResult("ALLOW", "client_filtering_disabled", matched_rule="filtering_disabled")

        cached_negative = self._negative_cache_get(domain, profile_id)
        if cached_negative is not None:
            return cached_negative

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

        result = FilterResult("ALLOW", "no_match")
        self._negative_cache_put(domain, profile_id, result)
        return result

    def explain(self, domain: str, filtering_enabled: bool = True, profile_id: Optional[int] = None) -> dict:
        original = domain
        normalized = self.normalize_domain(domain)
        steps = [{"step": "normalize", "result": normalized or "invalid"}]
        explanation = {
            "domain": original,
            "normalized_domain": normalized,
            "profile_id": profile_id,
            "profile_name": "",
            "result": "ALLOW",
            "reason": "no_match",
            "matched_rule": "",
            "matched_domain": "",
            "matched_list": "",
            "matched_lists": [],
            "allow_rule_won": False,
            "rewrite_applied": False,
            "safesearch_applied": False,
            "service_block_applied": False,
            "steps": steps,
        }
        if not normalized:
            explanation.update({"result": "REFUSED", "reason": "invalid_domain", "matched_rule": "invalid_domain"})
            return explanation
        if not filtering_enabled:
            steps.append({"step": "filtering_enabled", "result": "disabled"})
            explanation.update({"result": "ALLOW", "reason": "client_filtering_disabled", "matched_rule": "filtering_disabled"})
            return explanation
        steps.append({"step": "filtering_enabled", "result": "enabled"})
        profile = self.profiles.get(profile_id) if profile_id else None
        steps.append({"step": "profile_lookup", "result": "matched" if profile else "none", "profile_id": profile_id})

        checks = [
            ("profile_allow_check", lambda: self._check_profile_allows(profile, normalized) if profile else None),
            ("global_allow_check", lambda: self._check_global_allows(normalized)),
            ("profile_rewrite_check", lambda: self._check_profile_rewrites(profile, normalized) if profile else None),
            ("global_rewrite_check", lambda: self._check_global_rewrites(normalized)),
            ("profile_block_check", lambda: self._check_profile_blocks(profile, normalized) if profile else None),
            ("global_block_check", lambda: self._check_global_blocks(normalized)),
            ("safesearch_check", lambda: self._check_safesearch(normalized, profile_id) if profile_id else None),
            ("youtube_restricted_check", lambda: self._check_youtube_restricted(normalized, profile_id) if profile_id else None),
            ("service_block_check", lambda: self._check_service_block(normalized, profile_id) if profile_id else None),
        ]
        for step_name, fn in checks:
            result = fn()
            if not result:
                steps.append({"step": step_name, "result": "no_match"})
                continue
            step = {
                "step": step_name,
                "result": "matched",
                "action": result.action,
                "reason": result.reason,
                "rule": result.matched_rule or result.matched_domain or result.reason,
                "matched_domain": result.matched_domain,
                "list": result.list_name or result.matched_list or "",
            }
            if result.answer_ip:
                step["target"] = result.answer_ip
            steps.append(step)
            explanation.update({
                "result": result.action,
                "reason": result.reason,
                "matched_rule": result.matched_rule or result.matched_domain or result.reason,
                "matched_domain": result.matched_domain,
                "matched_list": result.list_name or result.matched_list or "",
                "matched_lists": self._sources_for_result(result),
                "allow_rule_won": result.action == "ALLOW" and "allow" in result.reason,
                "rewrite_applied": result.action == "REWRITE",
                "safesearch_applied": result.reason in ("safesearch", "youtube_restricted"),
                "service_block_applied": result.reason == "service_block",
            })
            if result.answer_ip:
                explanation["target"] = result.answer_ip
            return explanation
        steps.append({"step": "final", "result": "ALLOW", "reason": "no_match"})
        return explanation

    def _check_profile_allows(self, p: dict, domain: str) -> Optional[FilterResult]:
        if domain in p["exact_allow"]:
            return FilterResult("ALLOW", "profile_exact_allow", domain, matched_rule=domain, list_name=self._profile_source(p, domain))
        matched = self._suffix_match(domain, p["suffix_allow"], p.get("suffix_allow_trie"))
        if matched:
            return FilterResult("ALLOW", "profile_suffix_allow", matched, matched_rule=matched, list_name=self._profile_source(p, matched))
        for pattern, raw in p["regex_allow"].candidates(domain):
            if pattern.search(domain):
                return FilterResult("ALLOW", "profile_regex_allow", raw, matched_rule=raw, list_name=self._profile_source(p, raw))
        return None

    def _check_global_allows(self, domain: str) -> Optional[FilterResult]:
        if domain in self.exact_allow:
            return FilterResult("ALLOW", "exact_allow", domain, matched_rule=domain, list_name=self._source(domain))
        matched = self._suffix_match(domain, self.suffix_allow, self.suffix_allow_trie)
        if matched:
            return FilterResult("ALLOW", "suffix_allow", matched, matched_rule=matched, list_name=self._source(matched))
        for pattern, raw in self.regex_allow.candidates(domain):
            if pattern.search(domain):
                return FilterResult("ALLOW", "regex_allow", raw, matched_rule=raw, list_name=self._source(raw))
        return None

    def _check_profile_blocks(self, p: dict, domain: str) -> Optional[FilterResult]:
        if domain in p["exact_block"]:
            return FilterResult("BLOCK", "profile_exact_block", domain, matched_rule=domain, list_name=self._profile_source(p, domain))
        matched = self._suffix_match(domain, p["suffix_block"], p.get("suffix_block_trie"))
        if matched:
            return FilterResult("BLOCK", "profile_suffix_block", matched, matched_rule=matched, list_name=self._profile_source(p, matched))
        for pattern, raw in p["regex_block"].candidates(domain):
            if pattern.search(domain):
                return FilterResult("BLOCK", "profile_regex_block", raw, matched_rule=raw, list_name=self._profile_source(p, raw))
        return None

    def _check_global_blocks(self, domain: str) -> Optional[FilterResult]:
        if domain in self.exact_block:
            return FilterResult("BLOCK", "exact_block", domain, matched_rule=domain, list_name=self._source(domain))
        matched = self._suffix_match(domain, self.suffix_block, self.suffix_block_trie)
        if matched:
            return FilterResult("BLOCK", "suffix_block", matched, matched_rule=matched, list_name=self._source(matched))
        for pattern, raw in self.regex_block.candidates(domain):
            if pattern.search(domain):
                return FilterResult("BLOCK", "regex_block", raw, matched_rule=raw, list_name=self._source(raw))
        return None

    def _check_profile_rewrites(self, p: dict, domain: str) -> Optional[FilterResult]:
        if domain in p["rewrite_map"]:
            return FilterResult("REWRITE", "profile_rewrite", domain, matched_rule=domain, answer_ip=p["rewrite_map"][domain], list_name=self._profile_source(p, domain))
        matched = self._wildcard_rewrite_match(domain, p.get("rewrite_wildcard", {}))
        if matched:
            return FilterResult("REWRITE", "profile_rwild", domain, matched_rule=matched, answer_ip=p["rewrite_wildcard"][matched], list_name=self._profile_source(p, matched))
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

    def _target_suffix_trie(self, is_allow: bool) -> DomainSuffixTrie:
        return self.suffix_allow_trie if is_allow else self.suffix_block_trie

    def _add_regex_rule(self, rule: str, is_allow: bool, list_name: str = "", profile_id: Optional[int] = None) -> None:
        if self._try_demote_regex_to_domain_rule(rule, is_allow, list_name, profile_id):
            return
        pattern = rule[1:-1]
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            self.invalid_rules.append(rule)
            return
        if profile_id:
            p = self._ensure_profile(profile_id)
            target = p["regex_allow"] if is_allow else p["regex_block"]
            target.add(compiled, rule)
            self._profile_track_source(profile_id, rule, list_name)
        else:
            target = self.regex_allow if is_allow else self.regex_block
            target.add(compiled, rule)
            self._track_source(rule, list_name)

    def _try_demote_regex_to_domain_rule(self, rule: str, is_allow: bool, list_name: str, profile_id: Optional[int]) -> bool:
        pattern = rule[1:-1]
        p = pattern.lower()

        exact = re.fullmatch(r"\^([a-z0-9_-]+(?:\\\.[a-z0-9_-]+)+)\$", p)
        if exact:
            domain = exact.group(1).replace(r"\.", ".")
            self.add_rule(domain, "allow" if is_allow else "block", list_name, profile_id)
            return True

        suffix = re.fullmatch(r"\(\^\|\\\.\)([a-z0-9_-]+(?:\\\.[a-z0-9_-]+)+)\$", p)
        if suffix:
            domain = suffix.group(1).replace(r"\.", ".")
            self.add_rule("||" + domain + "^", "allow" if is_allow else "block", list_name, profile_id)
            return True

        return False

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

    def _suffix_match(self, domain: str, suffix_set: set[str], trie: Optional[DomainSuffixTrie] = None) -> Optional[str]:
        if trie is not None:
            matched = trie.match(domain)
            if matched:
                return matched
        current = domain
        while True:
            if current in suffix_set:
                return current
            if "." not in current:
                return None
            current = current.split(".", 1)[1]

    def add_pg_rule(self, prefix: str, pattern: str, list_name: str = ""):
        if prefix == "bd::":
            self.exact_block.add(pattern)
            self._track_source(pattern, list_name)
        elif prefix == "bs::":
            self.suffix_block.add(pattern)
            self.suffix_block_trie.add(pattern, pattern)
            self._track_source(pattern, list_name)
        elif prefix == "br::":
            compiled = re.compile(pattern, re.IGNORECASE)
            self.regex_block.add(compiled, f"/{pattern}/")
            self._track_source(f"/{pattern}/", list_name)
        elif prefix == "ad::":
            self.exact_allow.add(pattern)
            self._track_source(pattern, list_name)
        elif prefix == "as::":
            self.suffix_allow.add(pattern)
            self.suffix_allow_trie.add(pattern, pattern)
            self._track_source(pattern, list_name)
        elif prefix == "ar::":
            compiled = re.compile(pattern, re.IGNORECASE)
            self.regex_allow.add(compiled, f"/{pattern}/")
            self._track_source(f"/{pattern}/", list_name)
        self._bump_generation()

    def track_source(self, key: str, list_name: str) -> None:
        self._track_source(key, list_name)

    def bump_generation(self) -> None:
        self._bump_generation()

    def _track_source(self, key: str, list_name: str) -> None:
        if list_name:
            self.pattern_sources.setdefault(key, set()).add(list_name)

    def _source(self, key: str) -> Optional[str]:
        sources = self.pattern_sources.get(key)
        if not sources:
            return None
        return ", ".join(sorted(sources))

    def _profile_track_source(self, profile_id: int, key: str, list_name: str) -> None:
        if list_name:
            p = self._ensure_profile(profile_id)
            current = p["pattern_sources"].get(key)
            if isinstance(current, set):
                current.add(list_name)
            elif current:
                p["pattern_sources"][key] = {current, list_name}
            else:
                p["pattern_sources"][key] = {list_name}

    def _profile_source(self, profile: dict, key: str) -> Optional[str]:
        value = profile.get("pattern_sources", {}).get(key)
        if isinstance(value, set):
            return ", ".join(sorted(value))
        return value

    def _sources_for_result(self, result: FilterResult) -> list[str]:
        source_text = result.list_name or result.matched_list or ""
        if not source_text:
            return []
        return [part.strip() for part in source_text.split(",") if part.strip()]

    def clear_profile(self, profile_id: int) -> None:
        if profile_id in self.profiles:
            del self.profiles[profile_id]
            self._bump_generation()

    def list_profiles(self) -> list[int]:
        return list(self.profiles.keys())
