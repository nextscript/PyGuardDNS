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
