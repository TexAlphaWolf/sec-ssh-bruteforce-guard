"""Run the guard: sources in threads, one loop in the main thread."""

from __future__ import annotations

import json
import logging
import queue
import signal
import threading
import time
from types import FrameType

from . import __version__
from .backends import Backend, CommandBackend, DryRunBackend, NftBackend
from .config import Config
from .follow import start_sources
from .guard import Guard

log = logging.getLogger("sshguard")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
        )


def setup_logging(level: str, fmt: str) -> None:
    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("sshguard")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False


def make_backend(config: Config) -> Backend:
    b = config.backend
    if b.kind == "nftables":
        return NftBackend(table=b.table, ports=b.ports, action=b.action, nft=b.nft_path)
    if b.kind == "command":
        return CommandBackend(b.ban_cmd, b.unban_cmd, b.setup_cmd)
    return DryRunBackend()


def run(
    config: Config,
    *,
    backend: Backend | None = None,
    stop: threading.Event | None = None,
    install_signals: bool = True,
) -> int:
    setup_logging(config.log.level, config.log.format)
    stop = stop or threading.Event()
    backend = backend or make_backend(config)
    guard = Guard(config, backend)
    log.info(
        "sshguard %s starting, backend %s, source %s", __version__, backend.name, config.source.kind
    )
    if backend.name == "dry-run":
        log.warning("backend is dry-run: bans are logged but nothing is blocked")

    if install_signals:

        def on_signal(signum: int, _frame: FrameType | None) -> None:
            log.info("signal %d: stopping", signum)
            stop.set()

        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)

    try:
        guard.start()
    except Exception as error:
        log.error("cannot start: %s", error)
        return 1

    lines: queue.Queue[str] = queue.Queue(maxsize=50_000)
    try:
        start_sources(config.source, lines, stop)
    except RuntimeError as error:
        log.error("%s", error)
        return 1

    next_tick = time.monotonic() + 1
    while not stop.is_set():
        try:
            guard.process_line(lines.get(timeout=0.5))
            for _ in range(2000):  # drain a burst without waiting between lines
                guard.process_line(lines.get_nowait())
        except queue.Empty:
            pass
        if time.monotonic() >= next_tick:
            guard.tick()
            next_tick = time.monotonic() + 1
    # lines still queued when stdin closed (replay through a pipe)
    while True:
        try:
            guard.process_line(lines.get_nowait())
        except queue.Empty:
            break
    guard.stop()
    log.info("stopped")
    return 0
