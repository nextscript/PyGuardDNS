import struct
import socket
import time

import app


def _dns_response(request, txt_payload=b"", truncated=False):
    question = app.parse_dns_question(request)
    flags = 0x8180 | (0x0200 if truncated else 0)
    ancount = 1 if txt_payload else 0
    header = struct.pack("!HHHHHH", question["id"], flags, 1, ancount, 0, 0)
    response = header + request[12 : question["question_end"]]
    if txt_payload:
        rdata = bytes([len(txt_payload)]) + txt_payload
        response += b"\xc0\x0c" + struct.pack("!HHIH", app.QTYPE_CODE["TXT"], 1, 60, len(rdata)) + rdata
    return response


def test_hchacha20_matches_dnscrypt_draft_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    assert app.hchacha20(key, nonce).hex() == "51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6"


def test_dnscrypt_xchacha20poly1305_round_trip():
    key = bytes(range(32))
    nonce = bytes(range(24))
    plaintext = b"\x12\x34" + b"dns-query" + (b"\x80" + b"\x00" * 31)

    ciphertext = app.dnscrypt_xchacha20poly1305_encrypt(key, nonce, plaintext)

    assert app.dnscrypt_xchacha20poly1305_decrypt(key, nonce, ciphertext) == plaintext


def test_dnscrypt_ipv6_stamp_parses_address_and_uses_ipv6_family():
    stamp = "sdns://AQcAAAAAAAAAF1syMDAxOjRiYTA6ZmZlZDo3Njo6NTNdIDEzcq1ZVjLCQWuHLwmPhRvduWUoTGy-mk8ZCWQw26laHjIuZG5zY3J5cHQtY2VydC5jcnlwdG9zdG9ybS5pcw"

    parsed = app.parse_dnscrypt_stamp(stamp)

    assert parsed["address"] == "2001:4ba0:ffed:76::53"
    assert parsed["port"] == 443
    assert app.socket_family_for_host(parsed["address"]) == socket.AF_INET6


def test_dnscrypt_relay_stamp_parses_and_detects():
    stamp = "sdns://gQ04OS4xMDYuNzguMTA2"

    parsed = app.parse_dnscrypt_relay_stamp(stamp)
    detected = app.detect_upstream(stamp)

    assert parsed == {"address": "89.106.78.106", "port": 443}
    assert detected["type"] == "dnscrypt_relay"
    assert detected["supported"] is False


def test_anonymized_dnscrypt_target_header_maps_ipv4_to_ipv6():
    header = app.anonymized_dnscrypt_target_header({"address": "37.120.217.75", "port": 443})

    assert header[:10] == b"\xff" * 8 + b"\x00\x00"
    assert header[10:22] == b"\x00" * 10 + b"\xff\xff"
    assert header[22:26] == bytes([37, 120, 217, 75])
    assert header[26:28] == struct.pack("!H", 443)


def test_dnscrypt_query_uses_relay_for_cert_and_query(monkeypatch):
    calls = []
    upstream = {
        "resolver": "sdns://AQcAAAAAAAAADTM3LjEyMC4yMTcuNzUgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz",
        "dnscrypt_relay": "sdns://gQ04OS4xMDYuNzguMTA2",
    }
    cert = {
        "es_version": 1,
        "resolver_public_key": b"r" * 32,
        "client_magic": b"12345678",
        "serial": 1,
        "not_before": 1,
        "not_after": int(time.time()) + 3600,
    }

    def fake_fetch(_stamp_info, timeout=4.0, relay_info=None):
        calls.append(("cert", relay_info["address"]))
        return cert

    def fake_send(_stamp_info, _packet, timeout=4.0, transport="udp", relay_info=None):
        calls.append((transport, relay_info["address"]))
        return b"relay-response"

    monkeypatch.setattr(app, "fetch_dnscrypt_certificate", fake_fetch)
    monkeypatch.setattr(app, "dnscrypt_encrypt_query", lambda *_args: (b"packet", b"nonce", lambda *_decrypt_args: b""))
    monkeypatch.setattr(app, "send_dnscrypt_packet", fake_send)
    monkeypatch.setattr(app, "decrypt_dnscrypt_response", lambda response, *_args: response)
    monkeypatch.setattr(app, "dns_response_truncated", lambda _response: False)

    assert app.query_dnscrypt_upstream(upstream, b"\x00" * 12) == b"relay-response"
    assert calls == [("cert", "89.106.78.106"), ("udp", "89.106.78.106")]


def test_dnscrypt_query_uses_active_relay_entry_when_no_relay_on_upstream(monkeypatch):
    calls = []
    upstream = {
        "resolver": "sdns://AQcAAAAAAAAADTM3LjEyMC4yMTcuNzUgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz",
    }
    cert = {
        "es_version": 1,
        "resolver_public_key": b"r" * 32,
        "client_magic": b"12345678",
        "serial": 1,
        "not_before": 1,
        "not_after": int(time.time()) + 3600,
    }

    monkeypatch.setattr(app, "active_dnscrypt_relay", lambda: {"resolver": "sdns://gQ04OS4xMDYuNzguMTA2"})
    monkeypatch.setattr(app, "fetch_dnscrypt_certificate", lambda _stamp_info, timeout=4.0, relay_info=None: calls.append(("cert", relay_info["address"])) or cert)
    monkeypatch.setattr(app, "dnscrypt_encrypt_query", lambda *_args: (b"packet", b"nonce", lambda *_decrypt_args: b""))
    monkeypatch.setattr(app, "send_dnscrypt_packet", lambda _stamp_info, _packet, timeout=4.0, transport="udp", relay_info=None: calls.append((transport, relay_info["address"])) or b"relay-response")
    monkeypatch.setattr(app, "decrypt_dnscrypt_response", lambda response, *_args: response)
    monkeypatch.setattr(app, "dns_response_truncated", lambda _response: False)

    assert app.query_dnscrypt_upstream(upstream, b"\x00" * 12) == b"relay-response"
    assert calls == [("cert", "89.106.78.106"), ("udp", "89.106.78.106")]


def test_dnscrypt_query_retries_over_tcp_when_udp_fails(monkeypatch):
    calls = []
    upstream = {"resolver": "sdns://AQcAAAAAAAAADTM3LjEyMC4yMTcuNzUgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz", "_skip_auto_relay": True}
    cert = {
        "es_version": 1,
        "resolver_public_key": b"r" * 32,
        "client_magic": b"12345678",
        "serial": 1,
        "not_before": 1,
        "not_after": int(time.time()) + 3600,
    }

    monkeypatch.setattr(app, "fetch_dnscrypt_certificate", lambda *_args, **_kwargs: cert)
    monkeypatch.setattr(app, "dnscrypt_encrypt_query", lambda *_args: (b"packet", b"nonce", lambda *_decrypt_args: b""))

    def fake_send(_stamp_info, _packet, timeout=4.0, transport="udp", relay_info=None):
        calls.append(transport)
        if transport == "udp":
            raise OSError("udp failed")
        return b"tcp-response"

    monkeypatch.setattr(app, "send_dnscrypt_packet", fake_send)
    monkeypatch.setattr(app, "decrypt_dnscrypt_response", lambda response, *_args: response)

    assert app.query_dnscrypt_upstream(upstream, b"\x00" * 12) == b"tcp-response"
    assert calls == ["udp", "tcp"]


def test_dnscrypt_certificate_fetch_falls_back_to_tcp_on_truncated_udp(monkeypatch):
    calls = []
    stamp_info = {
        "address": "37.120.217.75",
        "port": 443,
        "provider_name": "2.dnscrypt-cert.cryptostorm.is",
        "provider_public_key": b"x" * 32,
    }
    cert = {"serial": 1, "not_before": 1, "not_after": int(time.time()) + 3600}

    def fake_query(upstream, request, timeout):
        calls.append(upstream["transport"])
        return _dns_response(request, b"DNSC", truncated=upstream["transport"] == "udp")

    monkeypatch.setattr(app, "query_plain_upstream", fake_query)
    monkeypatch.setattr(app, "parse_dnscrypt_certificate", lambda *_args: cert)
    app.dnscrypt_cert_cache.clear()

    assert app.fetch_dnscrypt_certificate(stamp_info) == cert
    assert calls == ["udp", "tcp"]


def test_dnscrypt_certificate_fetch_reports_transport_failure(monkeypatch):
    stamp_info = {
        "address": "2001:db8::53",
        "port": 443,
        "provider_name": "2.dnscrypt-cert.example.test",
        "provider_public_key": b"x" * 32,
    }

    monkeypatch.setattr(app, "query_plain_upstream", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("network unavailable")))
    app.dnscrypt_cert_cache.clear()

    import pytest
    with pytest.raises(OSError, match="DNSCrypt certificate transport failed: network unavailable"):
        app.fetch_dnscrypt_certificate(stamp_info)


def test_dnscrypt_certificate_fetch_uses_udp_when_certificate_is_valid(monkeypatch):
    calls = []
    stamp_info = {
        "address": "127.0.0.1",
        "port": 443,
        "provider_name": "2.dnscrypt-cert.example.test",
        "provider_public_key": b"x" * 32,
    }
    cert = {"serial": 2, "not_before": 1, "not_after": int(time.time()) + 3600}

    def fake_query(upstream, request, timeout):
        calls.append(upstream["transport"])
        return _dns_response(request, b"DNSC")

    monkeypatch.setattr(app, "query_plain_upstream", fake_query)
    monkeypatch.setattr(app, "parse_dnscrypt_certificate", lambda *_args: cert)
    app.dnscrypt_cert_cache.clear()

    assert app.fetch_dnscrypt_certificate(stamp_info) == cert
    assert calls == ["udp"]
