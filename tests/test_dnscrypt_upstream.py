import struct
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
