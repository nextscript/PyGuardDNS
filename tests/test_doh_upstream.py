import app


def test_detect_https_doh_resolver_url():
    parsed = app.detect_upstream("https://dns.example.test/dns-query")

    assert parsed["resolver"] == "https://dns.example.test/dns-query"
    assert parsed["address"] == "dns.example.test"
    assert parsed["port"] == 443
    assert parsed["type"] == "doh"
    assert parsed["transport"] == "https"
    assert parsed["supported"] is True


def test_detect_https_doh_resolver_url_with_port_and_query():
    parsed = app.detect_upstream("https://dns.example.test:8443/custom-query?profile=kids")
    host, port, path = app.doh_request_parts(parsed["resolver"])

    assert parsed["address"] == "dns.example.test"
    assert parsed["port"] == 8443
    assert parsed["type"] == "doh"
    assert host == "dns.example.test"
    assert port == 8443
    assert path == "/custom-query?profile=kids"


def test_doh_request_parts_defaults_to_dns_query_path():
    assert app.doh_request_parts("https://dns.example.test") == ("dns.example.test", 443, "/dns-query")


def test_doh_authority_includes_non_default_port_and_ipv6_brackets():
    assert app.doh_authority("dns.example.test", 443) == "dns.example.test"
    assert app.doh_authority("dns.example.test", 8443) == "dns.example.test:8443"
    assert app.doh_authority("2001:db8::53", 8443) == "[2001:db8::53]:8443"


def test_setup_wizard_endpoints_include_public_doh_url(monkeypatch):
    settings = {
        "encrypted_dns_domain": "dns.example.test",
        "dns_over_tls_enabled": "1",
        "dns_over_quic_enabled": "1",
    }
    monkeypatch.setattr(app, "DNS_HOST", "192.0.2.10")
    monkeypatch.setattr(app, "DNS_PORT", 53)
    monkeypatch.setattr(app, "WEB_PORT", 8080)
    monkeypatch.setattr(app, "DNS_TLS_PORT", 853)
    monkeypatch.setattr(app, "DNS_QUIC_PORT", 853)
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(app, "encrypted_dns_readiness", lambda: {"domain": "dns.example.test", "ready": True, "issues": []})

    endpoints = app.dns_connection_endpoints()

    assert "192.0.2.10" in endpoints["plain"]
    assert "https://dns.example.test/dns-query" in endpoints["doh"]
    assert "tls://dns.example.test:853" in endpoints["dot"]
    assert "quic://dns.example.test:853" in endpoints["doq"]


def test_query_one_upstream_uses_configured_timeout(monkeypatch):
    seen = {}
    upstream = {"name": "plain", "resolver_type": "plain_udp", "transport": "udp", "address": "1.1.1.1", "port": 53}

    monkeypatch.setattr(app, "get_setting", lambda key, default="": "7.5" if key == "upstream_timeout" else default)
    monkeypatch.setattr(app, "maybe_update_upstream_status", lambda *args, **kwargs: None)

    def fake_plain(_upstream, _request, timeout):
        seen["timeout"] = timeout
        return b"\x00" * 12

    monkeypatch.setattr(app, "query_plain_upstream", fake_plain)

    app._query_one_upstream(upstream, b"\x00" * 12)

    assert seen["timeout"] == 7.5
