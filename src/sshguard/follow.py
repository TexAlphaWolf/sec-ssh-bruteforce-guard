"""Getting log lines in: follow files (surviving rotation), journald, or stdin."""

from __future__ import annotations

import contextlib
import logging
import os
import queue
import shutil
import subprocess
import sys
import threading
from typing import BinaryIO

from .config import SourceConfig

log = logging.getLogger("sshguard.follow")

MAX_LINE = 64 * 1024  # a "line" longer than this is noise or an attack on memory: drop it


class FileTailer:
    """`tail -F`: follows a file by name, notices rotation and truncation.

    It starts at the end of the file (history is not replayed unless `from_start`). A file that
    does not exist yet is picked up from its beginning when it appears.
    """

    def __init__(self, path: str, from_start: bool = False) -> None:
        self.path = path
        self._from_start = from_start
        self._fh: BinaryIO | None = None
        self._ident: tuple[int, int] | None = None
        self._buf = b""
        self._first = True
        self.truncations = 0
        self.rotations = 0

    def _open(self, seek_end: bool) -> None:
        try:
            fh = open(self.path, "rb")  # noqa: SIM115 - kept open between polls
        except OSError:
            return
        st = os.fstat(fh.fileno())
        self._fh = fh
        self._ident = (st.st_dev, st.st_ino)
        self._buf = b""
        if seek_end:
            fh.seek(0, os.SEEK_END)

    def _read(self) -> list[str]:
        fh = self._fh
        if fh is None:
            return []
        out: list[str] = []
        while chunk := fh.read(1 << 16):
            self._buf += chunk
            *whole, self._buf = self._buf.split(b"\n")
            out.extend(
                p.decode("utf-8", "replace").rstrip("\r") for p in whole if len(p) <= MAX_LINE
            )  # a CRLF log must not leave a \r on every line
            if len(self._buf) > MAX_LINE:
                self._buf = b""  # an endless line without a newline
        return out

    def poll(self) -> list[str]:
        if self._fh is None:
            self._open(seek_end=self._first and not self._from_start)
            self._first = False
            if self._fh is None:
                return []
        lines = self._read()
        try:
            st = os.stat(self.path)
        except OSError:
            return lines  # rotated away and not recreated yet: keep the old handle meanwhile
        if (st.st_dev, st.st_ino) != self._ident:
            lines += self._read()  # whatever was still written to the old file
            self.close()
            self.rotations += 1
            self._open(seek_end=False)
            lines += self._read()
        elif self._fh is not None and st.st_size < self._fh.tell():
            self._fh.seek(0)
            self._buf = b""
            self.truncations += 1
            lines += self._read()
        return lines

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def _put(q: queue.Queue[str], line: str, stop: threading.Event) -> bool:
    """Block while the queue is full (back-pressure), but give up when asked to stop."""
    while not stop.is_set():
        try:
            q.put(line, timeout=0.5)
            return True
        except queue.Full:
            continue
    return False


def _tail_loop(path: str, replay: bool, q: queue.Queue[str], stop: threading.Event) -> None:
    tailer = FileTailer(path, from_start=replay)
    try:
        while not stop.is_set():
            lines = tailer.poll()
            for line in lines:
                if not _put(q, line, stop):
                    return
            if not lines:
                stop.wait(0.5)
    finally:
        tailer.close()


def journal_command(identifiers: tuple[str, ...], replay: bool) -> list[str]:
    cmd = [
        "journalctl",
        "--follow",
        "--output=json",
        "--no-pager",
        "--lines",
        "5000" if replay else "0",
    ]
    for ident in identifiers:
        cmd += ["--identifier", ident]
    return cmd


def _reap(proc: subprocess.Popen[str], stop: threading.Event, finished: threading.Event) -> None:
    """Stop journalctl when asked to: its output may be silent for hours, so the reader is stuck."""
    while not finished.is_set():
        if stop.wait(0.2):
            with contextlib.suppress(OSError):
                proc.terminate()
            return


def _journal_loop(cfg: SourceConfig, q: queue.Queue[str], stop: threading.Event) -> None:
    replay = cfg.replay
    while not stop.is_set():
        proc = subprocess.Popen(
            journal_command(cfg.identifiers, replay),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        replay = False  # after a restart, do not feed the same history twice
        assert proc.stdout is not None
        finished = threading.Event()
        threading.Thread(target=_reap, args=(proc, stop, finished), daemon=True).start()
        try:
            for line in proc.stdout:
                if not _put(q, line, stop):
                    return
        finally:
            finished.set()
            with contextlib.suppress(OSError):
                proc.terminate()
            proc.wait(timeout=5)
            proc.stdout.close()
        if not stop.is_set():
            log.warning("journalctl exited; restarting in 5 s")
            stop.wait(5)


def _stdin_loop(q: queue.Queue[str], stop: threading.Event) -> None:
    for line in sys.stdin:
        if not _put(q, line, stop):
            return
    stop.set()  # the pipe closed: nothing more will ever arrive


def start_sources(
    cfg: SourceConfig, q: queue.Queue[str], stop: threading.Event
) -> list[threading.Thread]:
    targets: list[tuple[str, threading.Thread]] = []
    if cfg.kind == "file":
        for path in cfg.paths:
            thread = threading.Thread(target=_tail_loop, args=(path, cfg.replay, q, stop))
            targets.append((path, thread))
    elif cfg.kind == "journald":
        if shutil.which("journalctl") is None:
            raise RuntimeError("source.kind = 'journald' but journalctl was not found")
        targets.append(("journald", threading.Thread(target=_journal_loop, args=(cfg, q, stop))))
    else:
        targets.append(("stdin", threading.Thread(target=_stdin_loop, args=(q, stop))))
    threads = []
    for name, thread in targets:
        thread.name = f"source:{name}"
        thread.daemon = True
        thread.start()
        threads.append(thread)
    return threads
