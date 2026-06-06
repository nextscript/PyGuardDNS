import app


def test_client_filtering_enabled_respects_profile_filtering(monkeypatch):
    class FakeClientManager:
        def get_client_by_ip(self, client_ip):
            return {
                "filtering_enabled": 1,
                "profile_filtering": 0,
            }

    monkeypatch.setattr(app, "client_manager", FakeClientManager())

    assert app.client_filtering_enabled("192.0.2.10") is False


def test_client_filtering_enabled_requires_client_and_profile_enabled(monkeypatch):
    class FakeClientManager:
        def get_client_by_ip(self, client_ip):
            return {
                "filtering_enabled": 1,
                "profile_filtering": 1,
            }

    monkeypatch.setattr(app, "client_manager", FakeClientManager())

    assert app.client_filtering_enabled("192.0.2.10") is True
