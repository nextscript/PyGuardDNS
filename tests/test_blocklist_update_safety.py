import sqlite3

import blocklist_manager as blm


def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def test_failed_update_keeps_existing_rules(monkeypatch):
    db = _db()
    manager = blm.BlocklistManager(db)
    manager.init_schema()
    manager.add_from_text("Test", "||ads.example.com^\n", "block", source="https://example.test/list.txt")
    item = manager.get_all()[0]

    def fail_fetch(*args, **kwargs):
        raise ValueError("empty")

    monkeypatch.setattr(blm, "fetch_url_text", fail_fetch)
    result = manager.update(item["id"], background=False)
    entries = manager.get_entries(item["id"])
    updated = manager.get_by_id(item["id"])

    assert result["status"] == "error"
    assert entries[0]["pattern"] == "ads.example.com"
    assert updated["last_error"] == "empty"


def test_304_update_keeps_rules_without_reload(monkeypatch):
    db = _db()
    reloaded = {"count": 0}
    manager = blm.BlocklistManager(db, reload_callback=lambda: reloaded.__setitem__("count", reloaded["count"] + 1))
    manager.init_schema()
    manager.add_from_text("Test", "||ads.example.com^\n", "block", source="https://example.test/list.txt", etag='"v1"')
    reloaded["count"] = 0
    item = manager.get_all()[0]

    monkeypatch.setattr(blm, "fetch_url_text", lambda *args, **kwargs: {"status": 304, "text": "", "etag": '"v1"', "last_modified": "", "sha256": ""})
    result = manager.update(item["id"], background=False)

    assert result["status"] == "done"
    assert manager.get_entries(item["id"])[0]["pattern"] == "ads.example.com"
    assert reloaded["count"] == 0
