import time

import upstream_manager as um


def _use_isolated_upstream_dir(tmp_path, monkeypatch):
    """Point upstream_manager at a throwaway directory + cache for this test only."""
    monkeypatch.setattr(um, "UPSTREAMS_DIR", str(tmp_path))
    monkeypatch.setattr(um, "_cache", {})
    monkeypatch.setattr(um, "_cache_loaded", False)


def _create_dot_upstream():
    return um.create(
        "test-dot", "1.2.3.4", port=853,
        resolver="tls://test-resolver", resolver_type="dot", transport="tls",
    )


def test_update_health_pauses_with_graduated_backoff(tmp_path, monkeypatch):
    _use_isolated_upstream_dir(tmp_path, monkeypatch)
    uid = _create_dot_upstream()

    # 1-3 consecutive failures: below the pause threshold, no backoff yet.
    for _ in range(3):
        assert um.update_health(uid, False, 0, "timeout") is False
    h = um.get(uid)["health"]
    assert h["paused"] is False
    assert h["backoff_until"] == 0

    # 4th consecutive failure crosses the threshold -> newly paused with a
    # real backoff window (this is the transition that should be logged).
    assert um.update_health(uid, False, 0, "timeout") is True
    h = um.get(uid)["health"]
    assert h["paused"] is True
    assert h["backoff_level"] == 2
    assert h["backoff_until"] > time.time()

    # Further failures while already paused are not "newly paused" again.
    assert um.update_health(uid, False, 0, "timeout") is False
    assert um.get(uid)["health"]["paused"] is True

    # A single success fully clears the pause/backoff state.
    assert um.update_health(uid, True, 12.5) is False
    h = um.get(uid)["health"]
    assert h["paused"] is False
    assert h["backoff_level"] == 0
    assert h["backoff_until"] == 0
    assert h["consecutive_failures"] == 0


def test_update_health_backoff_escalates_with_more_failures(tmp_path, monkeypatch):
    _use_isolated_upstream_dir(tmp_path, monkeypatch)
    uid = _create_dot_upstream()

    for _ in range(6):
        um.update_health(uid, False, 0, "timeout")
    h = um.get(uid)["health"]
    assert h["consecutive_failures"] == 6
    assert h["backoff_level"] == 2
    first_backoff_until = h["backoff_until"]

    for _ in range(3):
        um.update_health(uid, False, 0, "timeout")
    h = um.get(uid)["health"]
    assert h["consecutive_failures"] == 9
    assert h["backoff_level"] == 3
    assert h["backoff_until"] > first_backoff_until

    um.update_health(uid, False, 0, "timeout")
    h = um.get(uid)["health"]
    assert h["consecutive_failures"] == 10
    assert h["backoff_level"] == 4
    assert h["paused"] is True


def test_health_state_reflects_pause_and_recovery(tmp_path, monkeypatch):
    _use_isolated_upstream_dir(tmp_path, monkeypatch)
    uid = _create_dot_upstream()

    # Build up a healthy track record first (mirrors a long-running upstream).
    for _ in range(40):
        um.update_health(uid, True, 10.0)
    data = um.get(uid)
    assert um.health_state(data) == "healthy"
    assert any(u["id"] == uid for u in um.active_upstreams())

    # A short failure streak crosses the pause threshold -> "down", and the
    # upstream is taken out of active_upstreams() while paused.
    for _ in range(4):
        um.update_health(uid, False, 0, "timeout")
    data = um.get(uid)
    assert data["health"]["paused"] is True
    assert um.health_state(data) == "down"
    assert all(u["id"] != uid for u in um.active_upstreams())

    # A success recovers it immediately: unpaused and back in active_upstreams().
    um.update_health(uid, True, 10.0)
    data = um.get(uid)
    assert data["health"]["paused"] is False
    assert um.health_state(data) == "healthy"
    assert any(u["id"] == uid for u in um.active_upstreams())
