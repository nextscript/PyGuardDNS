import struct
import threading
import time

import dns.message
import pytest

import app


def _query(domain: str, qtype: int) -> bytes:
    return b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + app.encode_qname(domain) + struct.pack("!HH", qtype, 1)


def _fake_forward_query(request, timeout_override=None):
    response = dns.message.make_response(dns.message.from_wire(request))
    response.set_rcode(0)
    return response.to_wire(), "fake-upstream"


class _FakeClientManager:
    def __init__(self, clients, profiles):
        self._clients = clients
        self._profiles = profiles

    def get_clients_full(self):
        return [dict(c) for c in self._clients]

    def get_profiles(self):
        return [dict(p) for p in self._profiles]


def _base_settings(**overrides):
    settings = {"lan_only": "0", "filtering_enabled": "0", "query_log_enabled": "1",
                "cache_enabled": "0", "disable_ipv6": "0"}
    settings.update(overrides)
    return settings


# Test 1: Query-Logging blockiert DNS nicht ----------------------------------

def test_slow_query_log_persistence_does_not_block_dns_hot_path(monkeypatch):
    settings = _base_settings()
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(app, "ensure_client", lambda client_ip: None)
    monkeypatch.setattr(app, "lookup_client_snapshot", lambda client_ip: None)
    monkeypatch.setattr(app, "forward_query", _fake_forward_query)

    saved_queue = list(app.db_write_queue)
    app.db_write_queue.clear()
    try:
        request = _query("slow-log.example.com", app.QTYPE_CODE["A"])
        durations = []
        for i in range(25):
            t0 = time.perf_counter()
            app.handle_dns_request(request, f"198.51.100.{i}")
            durations.append(time.perf_counter() - t0)

        # log_query() only appends to the in-RAM queue - it must stay fast even
        # though nothing drains db_write_queue (an extreme stand-in for a stalled,
        # arbitrarily slow SQLite batch writer).
        assert max(durations) < 0.05
        # ... and every entry is queued for the (slow) background writer to
        # persist later, instead of being written synchronously.
        assert len(app.db_write_queue) == 25
    finally:
        app.db_write_queue.clear()
        app.db_write_queue.extend(saved_queue)


# Test 2: Settings-Snapshot wird aktualisiert ---------------------------------

def test_settings_snapshot_update_changes_dns_decision_without_db_reads(monkeypatch):
    saved_cache = dict(app._settings_cache)
    app._settings_cache.clear()
    app._settings_cache.update({
        "lan_only": "1", "allowed_networks": "",
        "filtering_enabled": "0", "query_log_enabled": "0",
        "cache_enabled": "0", "disable_ipv6": "0",
        "dnssec_validation_enabled": "0",
    })
    monkeypatch.setattr(app, "ensure_client", lambda client_ip: None)
    monkeypatch.setattr(app, "lookup_client_snapshot", lambda client_ip: None)
    monkeypatch.setattr(app, "forward_query", _fake_forward_query)

    request = _query("example.com", app.QTYPE_CODE["A"])
    try:
        # 1) Setting in its initial state: client IP is outside allowed_networks -> refused
        refused = app.handle_dns_request(request, "203.0.113.5")
        assert app.dns_response_rcode(refused) == 5

        # 2) "Setting ändern" + "Snapshot reload": update the in-RAM settings
        # cache directly - this *is* the snapshot get_setting() reads from, no
        # set_setting()/DB write involved.
        app._settings_cache["lan_only"] = "0"

        # 3) DNS-Anfrage nutzt neuen Wert, and 4) does so without touching SQLite:
        # track every read against app.db and assert none happened.
        read_calls = []
        original_execute = app.db.execute

        def tracking_execute(sql, *args, **kwargs):
            read_calls.append(sql)
            return original_execute(sql, *args, **kwargs)

        monkeypatch.setattr(app.db, "execute", tracking_execute)

        allowed = app.handle_dns_request(request, "203.0.113.5")
        assert app.dns_response_rcode(allowed) == 0
        assert read_calls == []
    finally:
        app._settings_cache.clear()
        app._settings_cache.update(saved_cache)


# Test 3: Client/Profile-Snapshot funktioniert --------------------------------

def test_client_profile_snapshot_used_in_dns_request_and_reflects_profile_change(monkeypatch):
    profile_kids = {"id": 1, "name": "Kids", "is_default": 0, "filtering_enabled": 1}
    profile_adults = {"id": 2, "name": "Adults", "is_default": 0, "filtering_enabled": 0}
    client_row = {
        "id": 10, "name": "test-client", "ip": "198.51.100.7", "cidr": "",
        "filtering_enabled": 1, "profile_id": 1, "profile_name": "Kids", "profile_filtering": 1,
    }
    fake_manager = _FakeClientManager([client_row], [profile_kids, profile_adults])

    settings = _base_settings(query_log_enabled="1")
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(app, "ensure_client", lambda client_ip: None)
    monkeypatch.setattr(app, "forward_query", _fake_forward_query)

    seen = []
    monkeypatch.setattr(app, "log_query", lambda *a, **kw: seen.append((kw.get("client_name"), kw.get("profile_name"))))

    saved_manager = app.client_manager
    saved_snapshot = app.get_client_snapshot()
    monkeypatch.setattr(app, "client_manager", fake_manager)
    try:
        # 1) Client mit Profil "in DB" (faked) + 2) Snapshot laden
        app.reload_client_snapshot()

        # 3) DNS-Anfrage von Client-IP nutzt korrektes Profil
        request = _query("example.com", app.QTYPE_CODE["A"])
        app.handle_dns_request(request, "198.51.100.7")
        assert seen[-1] == ("test-client", "Kids")

        # 4) Profil ändern + 5) Snapshot reload
        client_row["profile_id"] = 2
        client_row["profile_name"] = "Adults"
        client_row["profile_filtering"] = 0
        app.reload_client_snapshot()

        # 6) DNS-Anfrage nutzt neues Profil
        app.handle_dns_request(request, "198.51.100.7")
        assert seen[-1] == ("test-client", "Adults")
    finally:
        monkeypatch.setattr(app, "client_manager", saved_manager)
        with app._client_snapshot_lock:
            app._client_snapshot = saved_snapshot


# Test 4: Blocklist-Reload ist atomar ------------------------------------------

def test_filter_engine_reload_swaps_atomically_and_keeps_old_engine_on_build_failure(monkeypatch):
    old_engine = app.FilterEngine()
    new_engine = app.FilterEngine()

    saved_engine = app.get_filter_engine()
    saved_generation = app._filter_engine_generation
    with app._active_engine_lock:
        app._active_engine = old_engine
    try:
        # 1) Alte Engine aktiv, 3) währenddessen DNS-Anfragen (hier: concurrent
        # readers) - every reader must always observe one complete engine
        # instance, never None or a half-built one.
        stop = threading.Event()
        seen = []
        seen_lock = threading.Lock()

        def reader():
            local = []
            while not stop.is_set():
                local.append(app.get_filter_engine())
            with seen_lock:
                seen.extend(local)

        readers = [threading.Thread(target=reader) for _ in range(4)]
        for t in readers:
            t.start()

        # 2) neue Engine bauen, 4) erst nach Erfolg ersetzen
        monkeypatch.setattr(app, "build_filter_engine", lambda: new_engine)
        app.reload_filter_engine()

        stop.set()
        for t in readers:
            t.join()

        assert app.get_filter_engine() is new_engine
        assert app._filter_engine_generation == saved_generation + 1
        assert all(engine is old_engine or engine is new_engine for engine in seen)

        # 5) Bei Build-Fehler alte (aktuell aktive) Engine behalten
        def failing_build():
            raise RuntimeError("simulated blocklist build failure")

        monkeypatch.setattr(app, "build_filter_engine", failing_build)
        with pytest.raises(RuntimeError):
            app.reload_filter_engine()

        assert app.get_filter_engine() is new_engine
        assert app._filter_engine_generation == saved_generation + 1
    finally:
        with app._active_engine_lock:
            app._active_engine = saved_engine
            app._filter_engine_generation = saved_generation


# Test 5: Queue Full ist sicher -------------------------------------------------

def test_full_query_log_queue_does_not_break_dns_hot_path_and_counts_drops(monkeypatch):
    settings = _base_settings(query_log_enabled="1")
    monkeypatch.setattr(app, "get_setting", lambda key, default="": settings.get(key, default))
    monkeypatch.setattr(app, "ensure_client", lambda client_ip: None)
    monkeypatch.setattr(app, "lookup_client_snapshot", lambda client_ip: None)
    monkeypatch.setattr(app, "forward_query", _fake_forward_query)

    saved_queue = list(app.db_write_queue)
    app.db_write_queue.clear()
    placeholder = ("",) * 17
    # 1) Query-Log-Queue künstlich klein setzen - drive it straight to the
    # hard-coded 20000 cap so log_query() takes the "drop" branch immediately.
    app.db_write_queue.extend([placeholder] * 20000)

    with app.dns_runtime_metrics_lock:
        before_dropped = app.dns_runtime_metrics["query_log_dropped_total"]
    try:
        request = _query("queue-full.example.com", app.QTYPE_CODE["A"])
        # 2) viele DNS-Anfragen senden
        for i in range(10):
            response = app.handle_dns_request(request, f"203.0.113.{i}")
            # 3) keine Exceptions im DNS-Hot-Path - and it still answers normally
            assert app.dns_response_rcode(response) == 0

        assert len(app.db_write_queue) == 20000
        # 4) Drop-Metrik steigt
        with app.dns_runtime_metrics_lock:
            after_dropped = app.dns_runtime_metrics["query_log_dropped_total"]
        assert after_dropped - before_dropped == 10
    finally:
        app.db_write_queue.clear()
        app.db_write_queue.extend(saved_queue)
        with app.dns_runtime_metrics_lock:
            app.dns_runtime_metrics["query_log_dropped_total"] = before_dropped
