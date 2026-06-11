import re
import struct
from urllib.parse import urlparse

import app
from dns_engine import RegexIndex


def _query(domain: str, qtype: int) -> bytes:
    return b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + app.encode_qname(domain) + struct.pack("!HH", qtype, 1)


# normalize_domain: ASCII fast path -----------------------------------------

def _idna_reference(raw: str) -> str:
    """Reference implementation: the pre-fast-path normalize_domain (always
    goes through the idna codec)."""
    domain = (raw or "").strip()
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    domain = domain.rstrip(".").lower()
    if not domain:
        return ""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def test_normalize_domain_ascii_fast_path_matches_idna_reference():
    cases = [
        "Example.COM",
        "WWW.Example.com.",
        "  example.com  ",
        "http://Example.COM/path",
        "a" * 60 + ".example.com",
        "",
        "   ",
        ".",
    ]
    for raw in cases:
        assert app.normalize_domain(raw) == _idna_reference(raw), raw


def test_normalize_domain_still_handles_idn_input():
    idn = "müller.example"
    assert app.normalize_domain(idn) == _idna_reference(idn)
    assert app.normalize_domain(idn).isascii()  # result is punycode (ASCII)
    assert app.normalize_domain(idn).startswith("xn--")


# RegexIndex.candidates(): early return on empty index -----------------------

def test_regex_index_candidates_early_return_when_empty():
    index = RegexIndex()

    # Empty index: candidates() must short-circuit before doing any
    # domain.split()/n-gram work, regardless of the domain shape.
    assert list(index.candidates("anything.example.com")) == []
    assert list(index.candidates("")) == []
    assert index.fallback_ratio() == 0

    pattern = re.compile(r"adtrack\.invalid")
    index.add(pattern, r"adtrack\.invalid")

    matches = list(index.candidates("adtrack.invalid"))
    assert matches == [(pattern, r"adtrack\.invalid")]
    assert list(index.candidates("unrelated.example.com")) == []


# build_ip_response / build_block_response: pre-parsed question --------------

def test_build_ip_response_with_preparsed_question_matches_reparsed():
    request = _query("example.com", app.QTYPE_CODE["AAAA"])
    question = app.parse_dns_question(request)

    via_reparse = app.build_ip_response(request, "::", ttl=120)
    via_preparsed = app.build_ip_response(request, "::", ttl=120, question=question)

    assert via_reparse == via_preparsed


def test_build_block_response_with_preparsed_question_matches_reparsed(monkeypatch):
    settings = {
        "block_mode": "zero_ip",
        "block_response_ttl": "60",
        "custom_block_ipv4": "0.0.0.0",
        "custom_block_ipv6": "::",
    }
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))

    request = _query("blocked.example.com", app.QTYPE_CODE["A"])
    question = app.parse_dns_question(request)

    via_reparse = app.build_block_response(request, qtype_name="A")
    via_preparsed = app.build_block_response(request, qtype_name="A", question=question)

    assert via_preparsed is not None
    assert via_reparse == via_preparsed


# Sharded DNS / negative cache -------------------------------------------------

def test_sharded_cache_round_trip_and_stats_clear(monkeypatch):
    settings = {
        "cache_enabled": "1", "cache_ttl": "300", "cache_min_ttl": "0", "cache_max_ttl": "0",
        "cache_size": "4194304",
        "serve_stale_enabled": "0", "cache_optimistic": "0",
        "negative_cache_enabled": "1", "negative_cache_max_ttl": "300", "negative_cache_min_ttl": "30",
        "prefetch_enabled": "0",
    }
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))

    saved_dns = [dict(shard) for shard in app.dns_cache_shards]
    saved_neg = [dict(shard) for shard in app.negative_cache_shards]
    saved_bytes = list(app.cache_bytes_used)
    try:
        domains = [f"shard-test-{i}.example.test" for i in range(64)]

        # Sanity check: these keys really do spread across multiple shards
        # (this is what the sharding change is meant to exercise).
        shards_hit = {app._shard_for(app.cache_key(d, "A")) for d in domains}
        assert len(shards_hit) > 1

        for d in domains:
            app.set_cached(d, "A", b"answer-" + d.encode())
        for d in domains:
            assert app.get_cached(d, "A") == b"answer-" + d.encode()

        nxdomain_response = b"\x00" * 12
        for d in domains:
            app.set_negative_cached(d, "AAAA", nxdomain_response, "nxdomain")
        for d in domains:
            cached = app.get_negative_cached(d, "AAAA")
            assert cached is not None
            assert cached[1] == "nxdomain"

        stats = app.cache_stats()
        assert stats["entries"] >= len(domains)
        assert stats["bytes_used"] >= sum(len(b"answer-" + d.encode()) for d in domains)

        result = app.clear_dns_cache()
        assert result == {"ok": True, "entries": 0, "bytes_used": 0}

        for d in domains:
            assert app.get_cached(d, "A") is None
            assert app.get_negative_cached(d, "AAAA") is None

        stats_after = app.cache_stats()
        assert stats_after["entries"] == 0
        assert stats_after["bytes_used"] == 0
    finally:
        for i in range(app.CACHE_SHARDS):
            app.dns_cache_shards[i].clear()
            app.dns_cache_shards[i].update(saved_dns[i])
            app.negative_cache_shards[i].clear()
            app.negative_cache_shards[i].update(saved_neg[i])
            app.cache_bytes_used[i] = saved_bytes[i]


# get_setting: lock-free read reflects cache invalidation ---------------------

def test_get_setting_lock_free_read_reflects_invalidation():
    key = "__bench_lockfree_test_key__"
    had_key = key in app._settings_cache
    saved_value = app._settings_cache.get(key)
    try:
        with app._settings_cache_lock:
            app._settings_cache[key] = "cached-value"
        # Lock-free hit: returns the cached value without touching the DB.
        assert app.get_setting(key) == "cached-value"

        app._invalidate_settings_cache(key)
        # Cache miss for a key with no row in `settings` -> falls back to default.
        assert app.get_setting(key, "fallback-default") == "fallback-default"
    finally:
        with app._settings_cache_lock:
            if had_key:
                app._settings_cache[key] = saved_value
            else:
                app._settings_cache.pop(key, None)
