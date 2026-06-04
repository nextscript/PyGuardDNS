import gzip
import io
import zipfile

import pytest

from blocklist_manager import decode_blocklist_content, parse_filter_list


def test_parser_badfilter_hosts_regex_and_wildcard():
    text = """
0.0.0.0 ads.example.com
@@||good.example.com^
||bad.example.com^$badfilter
*.telemetry.example.com
/tracker[0-9]+\\.example/
/(a+)+$/
"""
    entries = parse_filter_list(text)

    assert ("block", "domain", "ads.example.com") in entries
    assert ("allow", "domain", "good.example.com") in entries
    assert ("block", "domain", "bad.example.com") not in entries
    assert ("block", "wildcard", "*.telemetry.example.com") in entries
    assert ("block", "regex", r"tracker[0-9]+\.example") in entries
    assert ("block", "regex", "(a+)+$") not in entries


def test_gzip_blocklist_decodes():
    data = gzip.compress(b"||ads.example.com^\n")
    assert "ads.example.com" in decode_blocklist_content(data, "list.gz")


def test_zip_blocklist_decodes_text_and_rejects_traversal():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("rules.txt", "||ads.example.com^\n")
    assert "ads.example.com" in decode_blocklist_content(buf.getvalue(), "list.zip")

    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("../rules.txt", "||ads.example.com^\n")
    with pytest.raises(ValueError):
        decode_blocklist_content(bad.getvalue(), "list.zip")


def test_empty_and_html_downloads_rejected():
    with pytest.raises(ValueError):
        decode_blocklist_content(b"   \n", "list.txt")
    with pytest.raises(ValueError):
        decode_blocklist_content(b"<!doctype html><html><body>forbidden</body></html>", "list.txt")
