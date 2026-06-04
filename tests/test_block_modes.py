import struct

import app


def _query(domain: str, qtype: int) -> bytes:
    return b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + app.encode_qname(domain) + struct.pack("!HH", qtype, 1)


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
