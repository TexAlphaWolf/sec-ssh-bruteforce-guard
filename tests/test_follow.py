from __future__ import annotations

import os
import queue
import sys
import threading
import time
from pathlib import Path

import pytest

from sshguard.config import SourceConfig
from sshguard.follow import FileTailer, journal_command, start_sources


@pytest.fixture(autouse=True)
def _close_tailers(monkeypatch):  # type: ignore[no-untyped-def]
    """Close every tailer a test made: an open file is a ResourceWarning, and an error here."""
    made: list[FileTailer] = []
    original = FileTailer.__init__

    def init(self, *a, **k):  # type: ignore[no-untyped-def]
        original(self, *a, **k)
        made.append(self)

    monkeypatch.setattr(FileTailer, "__init__", init)
    yield
    for tailer in made:
        tailer.close()


def append(path: Path, text: str) -> None:
    with open(path, "ab") as f:
        f.write(text.encode())


def test_starts_at_the_end_and_returns_only_new_lines(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("old 1\nold 2\n")
    t = FileTailer(str(log))
    assert t.poll() == []
    append(log, "new 1\nnew 2\n")
    assert t.poll() == ["new 1", "new 2"]
    assert t.poll() == []


def test_from_start_replays_history(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("a\nb\n")
    assert FileTailer(str(log), from_start=True).poll() == ["a", "b"]


def test_half_written_lines_wait_for_their_newline(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    t = FileTailer(str(log))
    t.poll()
    append(log, "partial")
    assert t.poll() == []
    append(log, " line\nnext\n")
    assert t.poll() == ["partial line", "next"]


def test_file_that_appears_later_is_read_from_its_beginning(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    t = FileTailer(str(log))
    assert t.poll() == []
    log.write_text("first\n")
    assert t.poll() == ["first"]


@pytest.mark.skipif(sys.platform == "win32", reason="rename over an open file")
def test_rotation_by_rename_loses_nothing(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    t = FileTailer(str(log))
    t.poll()
    append(log, "before rotation\n")
    os.rename(log, tmp_path / "auth.log.1")
    append(tmp_path / "auth.log.1", "late write to the old file\n")
    log.write_text("after rotation\n")
    assert t.poll() == ["before rotation", "late write to the old file", "after rotation"]
    assert t.rotations == 1
    append(log, "more\n")
    assert t.poll() == ["more"]


@pytest.mark.skipif(sys.platform == "win32", reason="rename over an open file")
def test_rotated_away_and_not_yet_recreated(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    t = FileTailer(str(log))
    t.poll()
    os.rename(log, tmp_path / "auth.log.1")
    assert t.poll() == []
    log.write_text("new file\n")
    assert t.poll() == ["new file"]


def test_truncation_restarts_from_zero(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    t = FileTailer(str(log))
    t.poll()
    append(log, "x" * 100 + "\n")
    t.poll()
    log.write_text("short\n")  # copytruncate style
    assert t.poll() == ["short"]
    assert t.truncations == 1


def test_endless_line_and_invalid_utf8_do_not_hurt(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    t = FileTailer(str(log))
    t.poll()
    append(log, "A" * 200_000)
    assert t.poll() == []
    append(log, "\nok\n")
    out = t.poll()
    assert "ok" in out
    log.write_bytes(log.read_bytes() + b"bad \xff\xfe bytes\n")
    assert any("bad" in line for line in t.poll())
    t.close()


def test_tail_thread_delivers_lines_and_stops(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    q: queue.Queue[str] = queue.Queue()
    stop = threading.Event()
    threads = start_sources(SourceConfig(kind="file", paths=(str(log),)), q, stop)
    time.sleep(0.7)
    append(log, "hello\n")
    assert q.get(timeout=5) == "hello"
    stop.set()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive()


def test_full_queue_applies_back_pressure_and_stop_still_works(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("")
    q: queue.Queue[str] = queue.Queue(maxsize=1)
    stop = threading.Event()
    threads = start_sources(SourceConfig(kind="file", paths=(str(log),)), q, stop)
    time.sleep(0.7)
    append(log, "".join(f"line {i}\n" for i in range(10)))
    time.sleep(1.2)
    assert q.qsize() == 1
    stop.set()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive()


def test_journal_command():
    cmd = journal_command(("sshd", "sshd-session"), replay=False)
    assert cmd[0] == "journalctl" and "--follow" in cmd and "--output=json" in cmd
    assert cmd[cmd.index("--lines") + 1] == "0"
    assert cmd.count("--identifier") == 2
    assert (
        journal_command(("sshd",), replay=True)[
            journal_command(("sshd",), True).index("--lines") + 1
        ]
        == "5000"
    )


def test_journald_without_journalctl_is_a_clear_error(monkeypatch):  # type: ignore[no-untyped-def]
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="journalctl was not found"):
        start_sources(SourceConfig(kind="journald"), queue.Queue(), threading.Event())


@pytest.mark.skipif(sys.platform == "win32", reason="fake journalctl is a shell script")
def test_journald_source_reads_the_command_output(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    fake = tmp_path / "journalctl"
    fake.write_text('#!/bin/sh\necho \'{"MESSAGE":"x"}\'\necho second\nexec sleep 30\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    q: queue.Queue[str] = queue.Queue()
    stop = threading.Event()
    threads = start_sources(SourceConfig(kind="journald"), q, stop)
    assert q.get(timeout=5).strip() == '{"MESSAGE":"x"}'
    assert q.get(timeout=5).strip() == "second"
    stop.set()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()


def test_stdin_source(monkeypatch):  # type: ignore[no-untyped-def]
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("one\ntwo\n"))
    q: queue.Queue[str] = queue.Queue()
    stop = threading.Event()
    (t,) = start_sources(SourceConfig(kind="stdin"), q, stop)
    t.join(timeout=5)
    assert [q.get_nowait(), q.get_nowait()] == ["one\n", "two\n"]
    assert stop.is_set()  # the pipe is closed: the daemon can finish


def test_crlf_logs_do_not_leave_a_carriage_return(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_bytes(b"one\r\ntwo\r\n")
    assert FileTailer(str(log), from_start=True).poll() == ["one", "two"]
