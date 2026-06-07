import app


def test_client_filtering_enabled_respects_profile_filtering(monkeypatch):
    monkeypatch.setattr(app, "client_manager", object())
    monkeypatch.setattr(app, "lookup_client_snapshot", lambda client_ip: {
        "filtering_enabled": 1,
        "profile_filtering": 0,
    })

    assert app.client_filtering_enabled("192.0.2.10") is False


def test_client_filtering_enabled_requires_client_and_profile_enabled(monkeypatch):
    monkeypatch.setattr(app, "client_manager", object())
    monkeypatch.setattr(app, "lookup_client_snapshot", lambda client_ip: {
        "filtering_enabled": 1,
        "profile_filtering": 1,
    })

    assert app.client_filtering_enabled("192.0.2.10") is True
