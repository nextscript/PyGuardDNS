import struct

import app


def _query(domain: str, qtype: int) -> bytes:
    return b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + app.encode_qname(domain) + struct.pack("!HH", qtype, 1)


def _first_answer_ttl(response: bytes) -> int:
    question = app.parse_dns_question(response)
    offset = question["question_end"]
    _, offset = app.parse_qname(response, offset)
    return struct.unpack("!I", response[offset + 4 : offset + 8])[0]


def test_block_modes(monkeypatch):
    settings = {
        "block_mode": "zero_ip",
        "custom_block_ipv4": "192.0.2.55",
        "custom_block_ipv6": "2001:db8::55",
    }
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))

    zero = app.build_block_response(_query("ads.example.com", app.QTYPE_CODE["A"]), "A")
    assert app.extract_response_ips(zero) == "0.0.0.0"

    settings["block_mode"] = "custom_ip"
    custom = app.build_block_response(_query("ads.example.com", app.QTYPE_CODE["AAAA"]), "AAAA")
    assert app.extract_response_ips(custom) == "2001:db8::55"

    settings["block_mode"] = "nxdomain"
    assert app.dns_response_rcode(app.build_block_response(_query("ads.example.com", app.QTYPE_CODE["A"]), "A")) == 3

    settings["block_mode"] = "refused"
    assert app.dns_response_rcode(app.build_block_response(_query("ads.example.com", app.QTYPE_CODE["A"]), "A")) == 5

    settings["block_mode"] = "nodata"
    response = app.build_block_response(_query("ads.example.com", app.QTYPE_CODE["A"]), "A")
    assert struct.unpack("!H", response[6:8])[0] == 0

    settings["block_mode"] = "invalid"
    fallback = app.build_block_response(_query("ads.example.com", app.QTYPE_CODE["A"]), "A")
    assert app.extract_response_ips(fallback) == "0.0.0.0"


def test_block_response_ttl(monkeypatch):
    settings = {
        "block_mode": "zero_ip",
        "block_response_ttl": "123",
    }
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))

    response = app.build_block_response(_query("ads.example.com", app.QTYPE_CODE["A"]), "A")

    assert _first_answer_ttl(response) == 123


def test_disable_ipv6_discards_aaaa(monkeypatch):
    settings = {"disable_ipv6": "1", "query_log_enabled": "0", "lan_only": "0", "filtering_enabled": "0"}
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(app, "ensure_client", lambda client_ip: None)

    response = app.handle_dns_request(_query("example.com", app.QTYPE_CODE["AAAA"]), "127.0.0.1")

    assert struct.unpack("!H", response[6:8])[0] == 0


def test_handle_dns_request_logs_connection_type(monkeypatch):
    settings = {"disable_ipv6": "1", "query_log_enabled": "1", "lan_only": "0", "filtering_enabled": "0"}
    seen = {}
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(app, "ensure_client", lambda client_ip: None)

    def fake_log_query(*args, **kwargs):
        seen["connection_type"] = kwargs.get("connection_type")

    monkeypatch.setattr(app, "log_query", fake_log_query)

    app.handle_dns_request(_query("example.com", app.QTYPE_CODE["AAAA"]), "127.0.0.1", "HTTPS")

    assert seen["connection_type"] == "HTTPS"


def test_connection_label_maps_protocols():
    assert app.connection_label("udp") == "UDP"
    assert app.connection_label("tcp") == "TCP"
    assert app.connection_label("doh") == "HTTPS"
    assert app.connection_label("dot") == "TLS"
    assert app.connection_label("doq") == "QUIC"
    assert app.connection_label("") == "UDP"


def test_disable_ipv6_strips_https_ipv6hint(monkeypatch):
    settings = {"disable_ipv6": "1"}
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))
    request = _query("example.com", app.QTYPE_CODE["HTTPS"])
    question = app.parse_dns_question(request)
    rdata = (
        struct.pack("!H", 1)
        + b"\x00"
        + struct.pack("!HH", 4, 4)
        + b"\x01\x02\x03\x04"
        + struct.pack("!HH", 6, 16)
        + bytes.fromhex("20010db8000000000000000000000001")
    )
    response = (
        struct.pack("!HHHHHH", question["id"], 0x8180, 1, 1, 0, 0)
        + request[12 : question["question_end"]]
        + b"\xc0\x0c"
        + struct.pack("!HHIH", app.QTYPE_CODE["HTTPS"], 1, 60, len(rdata))
        + rdata
    )

    filtered = app.apply_ipv6_disabled_policy(response)

    assert struct.pack("!HH", 6, 16) not in filtered
    assert struct.pack("!HH", 4, 4) in filtered
