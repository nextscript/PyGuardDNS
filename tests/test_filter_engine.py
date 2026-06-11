from dns_engine import FilterEngine


def test_exact_and_suffix_block():
    engine = FilterEngine()
    engine.add_rule("ads.example.com", "block", list_name="Manual")
    engine.add_rule("||trackers.example^", "block", list_name="Trackers")

    exact = engine.check("ads.example.com")
    suffix = engine.check("sub.trackers.example")

    assert exact.action == "BLOCK"
    assert exact.matched_rule == "ads.example.com"
    assert exact.list_name == "Manual"
    assert suffix.action == "BLOCK"
    assert suffix.matched_rule == "trackers.example"


def test_allow_wins_before_block():
    engine = FilterEngine()
    engine.add_rule("||example.com^", "block", list_name="Block")
    engine.add_rule("@@||good.example.com^", "allow", list_name="Allow")

    result = engine.check("sub.good.example.com")
    explanation = engine.explain("sub.good.example.com")

    assert result.action == "ALLOW"
    assert result.reason == "suffix_allow"
    assert explanation["allow_rule_won"] is True
    assert explanation["matched_rule"] == "good.example.com"


def test_rewrite_and_invalid_domain():
    engine = FilterEngine()
    engine.add_rule("rewrite.example.com -> 192.168.1.5", "rewrite")

    rewrite = engine.check("rewrite.example.com")
    invalid = engine.check("invalid_domain_%%%")

    assert rewrite.action == "REWRITE"
    assert rewrite.answer_ip == "192.168.1.5"
    assert invalid.action == "REFUSED"


def test_profile_rules_and_explain_steps():
    engine = FilterEngine()
    engine.add_rule("||kids.example^", "block", list_name="Kids", profile_id=7)
    engine.add_rule("@@||home.kids.example^", "allow", list_name="Profile Allow", profile_id=7)

    result = engine.check("www.home.kids.example", profile_id=7)
    explanation = engine.explain("www.home.kids.example", profile_id=7)

    assert result.action == "ALLOW"
    assert explanation["profile_id"] == 7
    assert any(step["step"] == "profile_allow_check" and step["result"] == "matched" for step in explanation["steps"])


def test_regex_index_keeps_regex_hits_and_clean_misses_fast_path():
    engine = FilterEngine()
    engine.add_rule(r"/ads[0-9]+\.doubleclick\.net/", "block", list_name="Regex")

    hit = engine.check("ads42.doubleclick.net")
    miss = engine.check("example.org")

    assert hit.action == "BLOCK"
    assert hit.reason == "regex_block"
    assert hit.matched_rule == r"/ads[0-9]+\.doubleclick\.net/"
    assert miss.action == "ALLOW"
    assert miss.reason == "no_match"
    assert engine.regex_block.fallback_ratio() == 0


def test_simple_regex_demotes_to_domain_rules():
    engine = FilterEngine()
    engine.add_rule(r"/^ads\.example\.com$/", "block", list_name="Regex")
    engine.add_rule(r"/(^|\.)tracker\.example\.net$/", "block", list_name="Regex")

    exact = engine.check("ads.example.com")
    suffix = engine.check("www.tracker.example.net")

    assert exact.action == "BLOCK"
    assert exact.reason == "exact_block"
    assert suffix.action == "BLOCK"
    assert suffix.reason == "suffix_block"
    assert len(engine.regex_block) == 0


def test_negative_cache_invalidates_when_rules_change():
    engine = FilterEngine()

    clean = engine.check("later-blocked.example")
    engine.add_rule("later-blocked.example", "block", list_name="Manual")
    blocked = engine.check("later-blocked.example")

    assert clean.action == "ALLOW"
    assert clean.reason == "no_match"
    assert blocked.action == "BLOCK"
    assert blocked.reason == "exact_block"


def test_regex_adjacent_character_class_goes_to_fallback():
    engine = FilterEngine()
    engine.add_rule(r"/^beacons[1-9]\.gvt[23]\.com$/", "block", list_name="Beacons")

    # Rules with character classes adjacent to literals must be placed in
    # fallback so they are never skipped by the candidate prefilter.
    assert engine.regex_block.fallback_ratio() > 0

    hits = [
        "beacons1.gvt2.com",
        "beacons5.gvt2.com",
        "beacons9.gvt3.com",
    ]
    for domain in hits:
        result = engine.check(domain)
        assert result.action == "BLOCK", f"expected BLOCK for {domain}, got {result.action}"

    misses = [
        "beacons.gvt2.com",
        "beacons10.gvt2.com",
        "xbeacons5.gvt2.com",
    ]
    for domain in misses:
        result = engine.check(domain)
        assert result.action != "BLOCK", f"expected non-BLOCK for {domain}, got {result.action}"


def test_regex_safe_literal_stays_indexed():
    engine = FilterEngine()
    engine.add_rule(r"/ads[0-9]+\.doubleclick\.net/", "block", list_name="Ads")

    # A literal that is bounded by a dot on both sides (".doubleclick.net")
    # is safe – the dot acts as a label separator, so the literal will
    # appear as a complete suffix n-gram in matching domains.
    assert engine.regex_block.fallback_ratio() == 0

    hit = engine.check("ads42.doubleclick.net")
    assert hit.action == "BLOCK"
    assert hit.reason == "regex_block"

    miss = engine.check("example.org")
    assert miss.action == "ALLOW"
    assert miss.reason == "no_match"
