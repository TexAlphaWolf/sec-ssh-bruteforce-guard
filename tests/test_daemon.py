"""The whole daemon, in-process: a real log file, the real loop, a fake firewall."""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

from conftest import FakeRunner
from sshguard import daemon
from sshguard.backends import DryRunBackend, NftBackend
from sshguard.config import from_dict


def make(tmp_path: Path, **extra):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    data = {
        "source": {"kind": "file", "paths": [str(log)]},
        "state": {
            "path": str(tmp_path / "state.json"),
            "spool": str(tmp_path / "spool"),
            "save_interval": 0,
        },
        "metrics": {"file": str(tmp_path / "m.prom"), "interval": 1},
        **extra,
    }
    return log, from_dict(data)


def run_in_thread(cfg, backend):  # type: ignore[no-untyped-def]
    stop = threading.Event()
    result: list[int] = []
    t = threading.Thread(
        target=lambda: result.append(
            daemon.run(cfg, backend=backend, stop=stop, install_signals=False)
        )
    )
    t.start()
    return t, stop, result


def wait_for(predicate, timeout=15.0):  # type: ignore[no-untyped-def]
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def attack(log: Path, ip: str, n: int = 6) -> None:
    with open(log, "a") as f:
        for i in range(n):
            f.write(
                f"Nov  7 10:00:0{i} web01 sshd[1]: Failed password for root from {ip} port {i} ssh2\n"
            )


def test_daemon_end_to_end(tmp_path):  # type: ignore[no-untyped-def]
    log, cfg = make(tmp_path)
    runner = FakeRunner()
    backend = NftBackend(runner=runner)
    t, stop, result = run_in_thread(cfg, backend)
    try:
        assert wait_for(lambda: any(c[1] and "add chain" in c[1] for c in runner.calls))
        time.sleep(0.8)  # let the tailer open the file at its end
        attack(log, "203.0.113.5")
        assert wait_for(lambda: any(c[0][1:3] == ("add", "element") for c in runner.calls))
        spool = tmp_path / "spool"
        spool.mkdir(exist_ok=True)
        cmd = spool / "1.json"
        cmd.write_text(json.dumps({"op": "ban", "target": "198.51.100.0/24"}))
        cmd.chmod(0o600)
        assert wait_for(lambda: any("198.51.100.0/24" in " ".join(c[0]) for c in runner.calls))
        assert wait_for(
            lambda: (
                (tmp_path / "m.prom").exists()
                and "sshguard_active_bans 2" in (tmp_path / "m.prom").read_text()
            )
        )
    finally:
        stop.set()
        t.join(timeout=15)
    assert result == [0]
    state = json.loads((tmp_path / "state.json").read_text())
    assert {b["target"] for b in state["bans"]} == {"203.0.113.5", "198.51.100.0/24"}
    assert "sshguard_up 0" in (tmp_path / "m.prom").read_text()


def test_daemon_refuses_to_start_on_a_corrupt_state(tmp_path):  # type: ignore[no-untyped-def]
    _, cfg = make(tmp_path)
    (tmp_path / "state.json").write_text("{broken")
    assert (
        daemon.run(cfg, backend=DryRunBackend(), stop=threading.Event(), install_signals=False) == 1
    )


def test_daemon_refuses_to_start_when_the_ruleset_cannot_be_created(tmp_path):  # type: ignore[no-untyped-def]
    _, cfg = make(tmp_path)
    runner = FakeRunner(fail_when="add table")
    assert (
        daemon.run(
            cfg, backend=NftBackend(runner=runner), stop=threading.Event(), install_signals=False
        )
        == 1
    )


def test_daemon_reports_a_missing_journalctl(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    _, cfg = make(tmp_path, source={"kind": "journald"})
    assert (
        daemon.run(cfg, backend=DryRunBackend(), stop=threading.Event(), install_signals=False) == 1
    )


def test_stdin_mode_finishes_when_the_pipe_closes(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    import io
    import sys

    lines = "".join(
        f"Nov  7 10:00:0{i} h sshd[1]: Failed password for root from 203.0.113.5 port {i} ssh2\n"
        for i in range(6)
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(lines))
    _, cfg = make(tmp_path, source={"kind": "stdin"})
    backend = DryRunBackend()
    assert daemon.run(cfg, backend=backend, stop=threading.Event(), install_signals=False) == 0
    assert backend.actions == [("ban", "203.0.113.5")]


def test_make_backend(tmp_path):  # type: ignore[no-untyped-def]
    assert daemon.make_backend(from_dict({})).name == "dry-run"
    nft = daemon.make_backend(
        from_dict({"backend": {"kind": "nftables", "ports": [22, 80], "table": "t"}})
    )
    assert isinstance(nft, NftBackend) and nft.ports == (22, 80) and nft.table == "t"
    cmd = daemon.make_backend(from_dict({"backend": {"kind": "command", "ban_cmd": ["x", "{ip}"]}}))
    assert cmd.name == "command"


def test_json_logging(capsys):  # type: ignore[no-untyped-def]
    daemon.setup_logging("INFO", "json")
    import logging

    logging.getLogger("sshguard.test").info("hello %s", "world")
    err = capsys.readouterr().err
    assert json.loads(err.strip().splitlines()[-1])["msg"] == "hello world"
    daemon.setup_logging("INFO", "text")


@pytest.mark.skipif(sys.platform == "win32", reason="os.kill(SIGTERM) kills the process there")
def test_signal_handlers_are_installed_and_stop_the_loop(tmp_path):  # type: ignore[no-untyped-def]
    import os
    import signal

    _, cfg = make(tmp_path)
    threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
    previous = signal.getsignal(signal.SIGTERM)
    try:
        assert daemon.run(cfg, backend=DryRunBackend()) == 0
    finally:
        signal.signal(signal.SIGTERM, previous)
        signal.signal(signal.SIGINT, signal.default_int_handler)


@pytest.fixture(autouse=True)
def _quiet_logging():  # type: ignore[no-untyped-def]
    yield
    daemon.setup_logging("WARNING", "text")
