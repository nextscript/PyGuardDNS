import struct

import app


def _query(domain: str, qtype: int = 1) -> bytes:
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + app.encode_qname(domain) + struct.pack("!HH", qtype, 1)


def _cname_response(name: str, target: str, compressed_target: bool = False) -> bytes:
    request = _query(name)
    question = request[12:]
    header = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    owner = b"\xc0\x0c"
    if compressed_target:
        suffix_offset = 12 + 1 + len(name.split(".")[0])
        rdata = b"\x07tracker" + b"\xc0" + bytes([suffix_offset])
        return header + question + owner + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
    rdata = app.encode_qname(target)
    return header + question + owner + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata


def test_extract_cname_targets_plain():
    response = _cname_response("shop.example.com", "ads.example.com")
    assert app.extract_cname_targets(response) == ["ads.example.com"]


def test_extract_cname_targets_compressed_target():
    response = _cname_response("shop.ads.example.com", "", compressed_target=True)
    assert app.extract_cname_targets(response) == ["tracker.ads.example.com"]


def test_extract_cname_targets_corrupt_safe():
    assert app.extract_cname_targets(b"not dns") == []
