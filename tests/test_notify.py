from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from sshguard.config import NotifyConfig
from sshguard.notify import Notifier, describe


class Hook(BaseHTTPRequestHandler):
    received: ClassVar[list[dict]] = []  # type: ignore[type-arg]
    status = 200

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Hook.received.append({"path": self.path, "body": json.loads(body)})
        self.send_response(Hook.status)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args) -> None:  # type: ignore[no-untyped-def]
        pass


@pytest.fixture
def server():  # type: ignore[no-untyped-def]
    Hook.received = []
    Hook.status = 200
    srv = HTTPServer(("127.0.0.1", 0), Hook)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


BAN = {
    "event": "ban",
    "target": "203.0.113.5",
    "reason": "failures",
    "score": 5.0,
    "users": 1,
    "strikes": 2,
    "seconds": 3600,
}


def test_describe():
    assert "banned 203.0.113.5 for 3600s: failures" in describe({**BAN, "host": "h"})
    assert "permanently" in describe({**BAN, "seconds": None, "host": "h"})
    assert "lifted the ban" in describe({"event": "unban", "target": "x", "host": "h"})
    assert "started" in describe({"event": "start", "bans": 3, "host": "h"})


def test_webhook_gets_json(server):  # type: ignore[no-untyped-def]
    n = Notifier(NotifyConfig(webhook_url=server + "/hook"), "web01")
    n.start()
    n.send(BAN)
    n.stop()
    (got,) = Hook.received
    assert got["path"] == "/hook"
    assert got["body"]["target"] == "203.0.113.5" and got["body"]["host"] == "web01"
    assert "banned 203.0.113.5" in got["body"]["text"]
    assert n.sent == 1 and n.failed == 0


def test_events_not_in_the_list_are_not_sent(server):  # type: ignore[no-untyped-def]
    n = Notifier(NotifyConfig(webhook_url=server, on=("ban",)), "h")
    n.start()
    n.send({"event": "unban", "target": "x"})
    n.stop()
    assert Hook.received == []


def test_telegram_message_is_plain_text(server, monkeypatch):  # type: ignore[no-untyped-def]
    import sshguard.notify as mod

    seen: list[str] = []
    real = mod.urllib.request.urlopen

    def fake(request, timeout):  # type: ignore[no-untyped-def]
        seen.append(request.full_url)
        return real(server + "/tg", timeout=timeout) if False else _Ok()

    class _Ok:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *a):  # type: ignore[no-untyped-def]
            return False

        def read(self, n):  # type: ignore[no-untyped-def]
            return b""

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake)
    n = Notifier(NotifyConfig(telegram_token="123:SECRET", telegram_chat_id="42"), "h")
    n.deliver({**BAN, "host": "h"})
    assert seen == ["https://api.telegram.org/bot123:SECRET/sendMessage"]
    assert n.sent == 1


def test_failures_are_counted_never_raised_and_the_token_is_never_logged(caplog):  # type: ignore[no-untyped-def]
    n = Notifier(
        NotifyConfig(
            telegram_token="123:SECRET",
            telegram_chat_id="1",
            webhook_url="http://127.0.0.1:9/h",
            timeout=0.5,
        ),
        "h",
    )
    with caplog.at_level("WARNING", logger="sshguard.notify"):
        n.deliver({**BAN, "host": "h"})
    assert n.failed == 2
    assert "SECRET" not in caplog.text


def test_http_error_is_a_failure(server):  # type: ignore[no-untyped-def]
    Hook.status = 500
    n = Notifier(NotifyConfig(webhook_url=server), "h")
    n.deliver({**BAN, "host": "h"})
    assert n.failed == 1


def test_attacker_text_cannot_inject_into_the_message():
    n = Notifier(NotifyConfig(webhook_url="http://x"), "h")
    sent: list[dict] = []  # type: ignore[type-arg]
    n._queue.put_nowait = sent.append  # type: ignore[method-assign]
    n.send({**BAN, "reason": "bad\nline\x1b[31m" + "x" * 500})
    assert "\n" not in sent[0]["reason"] and "\x1b" not in sent[0]["reason"]
    assert len(sent[0]["reason"]) <= 60


def test_full_queue_drops_instead_of_blocking():
    n = Notifier(NotifyConfig(webhook_url="http://x"), "h")
    for _ in range(300):
        n.send(BAN)
    assert n.failed == 100


def test_disabled_notifier_does_nothing():
    n = Notifier(NotifyConfig(), "h")
    n.start()
    n.send(BAN)
    n.stop()
    assert n.sent == 0 and n._queue.qsize() == 0
