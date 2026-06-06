import sys

import app


def test_console_command_completions_match_full_command_prefixes():
    assert app.console_command_completions("d") == [
        "domain test",
        "dnssec test",
        "dedupe blocklists",
    ]
    assert app.console_command_completions("domain ") == ["domain test"]
    assert app.console_command_completions("cache ") == ["cache clear"]
    assert app.console_command_completions("UPDATE") == ["update blocklist"]


def test_setup_readline_completion_uses_full_line_buffer(monkeypatch):
    class FakeReadline:
        def __init__(self):
            self.line = ""
            self.completer = None
            self.delims = None
            self.bindings = []

        def get_line_buffer(self):
            return self.line

        def set_completer_delims(self, delims):
            self.delims = delims

        def set_completer(self, completer):
            self.completer = completer

        def parse_and_bind(self, binding):
            self.bindings.append(binding)

    fake_readline = FakeReadline()
    monkeypatch.setitem(sys.modules, "readline", fake_readline)
    monkeypatch.setattr(app, "_readline_completion_ready", False)

    assert app.setup_readline_completion() is True
    assert fake_readline.delims == ""
    assert fake_readline.bindings == ["tab: menu-complete"]

    fake_readline.line = "dns"
    assert fake_readline.completer("", 0) == "dnssec test"
    assert fake_readline.completer("", 1) is None

    fake_readline.line = "cache "
    assert fake_readline.completer("", 0) == "cache clear"


def test_run_console_command_domain_test(monkeypatch):
    called = {}

    def fake_print_console_domain_test(domain, client="127.0.0.1", query_type="A"):
        called["domain"] = domain
        called["client"] = client
        called["query_type"] = query_type

    monkeypatch.setattr(app, "print_console_domain_test", fake_print_console_domain_test)

    assert app.run_console_command("domain test example.com 192.168.0.80 AAAA") is True
    assert called == {
        "domain": "example.com",
        "client": "192.168.0.80",
        "query_type": "AAAA",
    }
