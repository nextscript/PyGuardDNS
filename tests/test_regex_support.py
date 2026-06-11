from rules_engine import parse_rule_line, validate_rules, is_dangerous_regex, DANGEROUS_REGEX_MESSAGE
from dns_engine import FilterEngine


def test_dangerous_regex_is_rejected():
    dangerous_patterns = [
        ".*ads.*",
        "(.+)+",
        "(a+)+",
        "^.*$",
        ".+",
        ".*",
        "^.+$",
        "(.*)*",
        ".+ads.+",
    ]
    for pattern in dangerous_patterns:
        assert is_dangerous_regex(pattern), f"expected {pattern!r} to be dangerous"
        result = parse_rule_line(f"br::{pattern}")
        assert result is not None
        assert "error" in result
        assert result["error"] == DANGEROUS_REGEX_MESSAGE


def test_safe_regex_is_accepted():
    safe_patterns = [
        r"^ad[0-9]+\.example\.com$",
        r"^beacons[1-9]\.gvt[23]\.com$",
        r"^[a-f0-9]{8,32}\.tracker\.example\.com$",
        r"^[a-z0-9-]+\.ads\.example\.com$",
        r"^(?:ads|track|pixel)\.example\.com$",
        r"^(?:[a-z0-9-]+\.)+tracker\.example\.com$",
    ]
    for pattern in safe_patterns:
        assert not is_dangerous_regex(pattern), f"expected {pattern!r} to be safe"
        result = parse_rule_line(f"br::{pattern}")
        assert result is not None
        assert "error" not in result, f"unexpected error for {pattern!r}: {result['error']}"
        assert result["type"] == "regex"
        assert result["action"] == "block"
        assert result["pattern"] == pattern


def test_validates_allow_regex():
    result = parse_rule_line("ar::^[a-z0-9-]+\.safe\.example\.com$")
    assert result is not None
    assert "error" not in result
    assert result["type"] == "regex"
    assert result["action"] == "allow"


def test_dangerous_allow_regex_is_rejected():
    result = parse_rule_line("ar::.*")
    assert result is not None
    assert "error" in result
    assert result["error"] == DANGEROUS_REGEX_MESSAGE


def test_invalid_regex_is_rejected():
    result = parse_rule_line("br::[")
    assert result is not None
    assert "error" in result
    assert "Invalid regex" in result["error"]


def test_validate_rules_reports_dangerous():
    text = "br::.*ads.*\nbr::^beacons[1-9]\.gvt[23]\.com$"
    errors = validate_rules(text)
    assert len(errors) == 1
    assert errors[0]["message"] == DANGEROUS_REGEX_MESSAGE
    assert errors[0]["line"] == 1


def test_validate_rules_reports_invalid_regex():
    text = "br::[\nbr::^valid\.com$"
    errors = validate_rules(text)
    assert len(errors) == 1
    assert "Invalid regex" in errors[0]["message"]


def test_beacons_pattern_matches_correctly():
    engine = FilterEngine()
    engine.add_pg_rule("br::", r"^beacons[1-9]\.gvt[23]\.com$", "test")

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
        "beacons5.gvt2.com.evil.com",
    ]
    for domain in misses:
        result = engine.check(domain)
        assert result.action != "BLOCK", f"expected non-BLOCK for {domain}, got {result.action}"


def test_beacons_pattern_as_allow_overrides_block():
    engine = FilterEngine()
    engine.add_pg_rule("bd::", "beacons1.gvt2.com", "block")
    engine.add_pg_rule("ar::", r"^beacons[1-9]\.gvt[23]\.com$", "allow")

    result = engine.check("beacons1.gvt2.com")
    assert result.action == "ALLOW"
    assert result.reason == "regex_allow"


def test_validate_rules_line_numbers():
    text = "bd::example.com\nbr::[\nbr::.*ads.*\nbr::^valid\.com$"
    errors = validate_rules(text)
    lines_with_errors = {e["line"] for e in errors}
    assert 2 in lines_with_errors
    assert 3 in lines_with_errors
    assert len(lines_with_errors) == 2
