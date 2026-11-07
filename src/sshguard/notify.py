"""Alerts: a generic JSON webhook and Telegram. Sending never blocks or breaks the guard."""

from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.error
import urllib.request
from typing import Any

from .config import NotifyConfig
from .net import printable

log = logging.getLogger("sshguard.notify")


def describe(event: dict[str, Any]) -> str:
    """One plain-text line. Plain text on purpose: no markup for an attacker to inject into."""
    kind = event["event"]
    host = event.get("host", "")
    if kind == "ban":
        until = "permanently" if not event.get("seconds") else f"for {int(event['seconds'])}s"
        users = event.get("users", 0)
        return (
            f"[{host}] sshguard banned {event['target']} {until}: {event['reason']}, "
            f"score {event.get('score', 0):.1f}, {users} user names, "
            f"strike {event.get('strikes', 1)}"
        )
    if kind == "unban":
        return f"[{host}] sshguard lifted the ban on {event['target']}"
    return f"[{host}] sshguard started ({event.get('bans', 0)} bans restored)"


class Notifier:
    def __init__(self, config: NotifyConfig, host: str = "") -> None:
        self.config = config
        self.host = host
        self.sent = 0
        self.failed = 0
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=200)
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.config.enabled and self._thread is None:
            self._thread = threading.Thread(target=self._worker, name="notify", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join(timeout=self.config.timeout * 2 + 1)
            self._thread = None

    def send(self, event: dict[str, Any]) -> None:
        """Queue an event. A full queue drops the event: a flood must not stall detection."""
        if not self.config.enabled or event["event"] not in self.config.on:
            return
        event = {**event, "host": self.host}
        if "reason" in event:
            event["reason"] = printable(str(event["reason"]), 60)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.failed += 1
            log.warning("notification queue full: event dropped")

    def _worker(self) -> None:
        while (event := self._queue.get()) is not None:
            self.deliver(event)

    def deliver(self, event: dict[str, Any]) -> None:
        cfg = self.config
        text = describe(event)
        if cfg.webhook_url:
            self._post(cfg.webhook_url, {**event, "text": text})
        if cfg.telegram_token and cfg.telegram_chat_id:
            url = f"https://api.telegram.org/bot{cfg.telegram_token}/sendMessage"
            self._post(url, {"chat_id": cfg.telegram_chat_id, "text": text}, secret=True)

    def _post(self, url: str, body: dict[str, Any], *, secret: bool = False) -> None:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "sshguard"},
            method="POST",
        )
        shown = "telegram" if secret else url  # the Telegram URL contains the token
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                response.read(1024)
            self.sent += 1
        except urllib.error.HTTPError as error:
            error.close()
            self.failed += 1
            log.warning("notification to %s failed: HTTP %s", shown, error.code)
        except (urllib.error.URLError, OSError, ValueError) as error:
            self.failed += 1
            log.warning("notification to %s failed: %s", shown, type(error).__name__)
