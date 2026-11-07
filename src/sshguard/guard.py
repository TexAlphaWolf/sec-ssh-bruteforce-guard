"""The daemon's brain: parse, count, ban, expire, remember. No threads, so easy to test."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__
from .backends import Backend, BackendError
from .bans import Ban, BanBook, load_state, save_state
from .config import Config
from .detector import Detector, Verdict
from .events import Attempt
from .metrics import Sample, render, write_atomic
from .net import group_key, normalize_target, parse_ip
from .notify import Notifier
from .parsers import parse_line

log = logging.getLogger("sshguard")

Clock = Callable[[], float]


class Guard:
    def __init__(
        self,
        config: Config,
        backend: Backend,
        notifier: Notifier | None = None,
        *,
        clock: Clock = time.time,
        host: str | None = None,
    ) -> None:
        self.config = config
        self.backend = backend
        self.host = host or socket.gethostname()
        self.notifier = notifier or Notifier(config.notify, self.host)
        self.clock = clock
        self.detector = Detector(config.detect)
        self.book = BanBook(config.ban)
        self.counters: Counter[str] = Counter()
        self.by_kind: Counter[str] = Counter()
        self.by_reason: Counter[str] = Counter()
        self.ignored: Counter[str] = Counter()
        self.started = clock()
        self.last_ban = 0.0
        self._dirty = False
        self._last_save = 0.0
        self._last_metrics = 0.0

    # --- lifecycle ---------------------------------------------------------------------

    def start(self) -> None:
        state = Path(self.config.state.path)
        try:
            if load_state(self.book, state):
                log.info("restored %d ban(s) from %s", len(self.book), state)
        except ValueError as error:
            raise RuntimeError(str(error)) from error
        now = self.clock()
        self.book.expire(now)
        try:
            Path(self.config.state.spool).mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as error:
            log.warning("cannot create the command spool %s: %s", self.config.state.spool, error)
        self.backend.setup()
        self._sync_backend(now)
        self.notifier.start()
        self.notifier.send({"event": "start", "bans": len(self.book)})
        self.write_outputs(force=True)

    def _sync_backend(self, now: float) -> None:
        bans = self.book.active()
        try:
            self.backend.sync((b.target, b.remaining(now)) for b in bans)
        except BackendError as error:
            self.counters["backend_errors"] += 1
            log.error("could not restore the bans in the firewall: %s", error)
            return
        for ban in bans:
            ban.applied = True

    def stop(self) -> None:
        self.write_outputs(force=True, up=False)
        self.save(force=True)
        self.backend.teardown()
        self.notifier.stop()

    # --- the hot path ------------------------------------------------------------------

    def process_line(self, line: str) -> None:
        self.counters["lines"] += 1
        cfg = self.config.source
        attempt = parse_line(line, tz=cfg.tz)
        if attempt is None:
            return
        self.counters["parsed"] += 1
        ts = attempt.ts if cfg.time_source == "log" else self.clock()
        self.handle(attempt, ts)

    def handle(self, attempt: Attempt, ts: float) -> Verdict | None:
        self.by_kind[attempt.kind] += 1
        ip = parse_ip(attempt.ip)
        if ip is None:
            return None
        if self.detector.is_allowed(ip):
            self.ignored["allowlist"] += 1
            return None

        key = group_key(ip, self.config.detect.ipv6_prefix)
        if self.book.is_banned(key, ts):
            self.ignored["already_banned"] += 1
            return None
        verdict = self.detector.observe(attempt, ts)
        if verdict is not None:
            self._ban(verdict, ts)
        return verdict

    def _ban(self, verdict: Verdict, ts: float) -> None:
        ban, evicted = self.book.ban(verdict.target, ts, verdict.reason, score=verdict.score)
        if evicted is not None:
            self.counters["evicted"] += 1
            self._lift(evicted, "evicted")
        if ban is None:
            return
        self.detector.forget(verdict.target)
        if ban.until is not None and ban.until <= self.clock():
            # Replaying an old log: this ban would already be over. Remember the strike only.
            self.book.unban(ban.target)
            self.ignored["expired_on_arrival"] += 1
            return
        self._dirty = True
        self.by_reason[verdict.reason] += 1
        self.last_ban = ts
        self._apply(ban)
        log.warning(
            "ban %s for %s: %s (score %.1f, %d user names, strike %d)",
            ban.target,
            "ever" if ban.until is None else f"{int(ban.until - ts)}s",
            verdict.reason,
            verdict.score,
            verdict.users,
            ban.strikes,
        )
        self.notifier.send(
            {
                "event": "ban",
                "target": ban.target,
                "reason": ban.reason,
                "score": round(ban.score, 1),
                "users": verdict.users,
                "strikes": ban.strikes,
                "seconds": None if ban.until is None else int(ban.until - ts),
            }
        )

    def _apply(self, ban: Ban) -> None:
        try:
            self.backend.ban(ban.target, ban.remaining(self.clock()))
            ban.applied = True
        except BackendError as error:
            ban.applied = False
            self.counters["backend_errors"] += 1
            log.error("%s", error)

    def _lift(self, ban: Ban, why: str) -> None:
        self.counters["unbans"] += 1
        self._dirty = True
        try:
            self.backend.unban(ban.target)
        except BackendError as error:
            self.counters["backend_errors"] += 1
            log.error("%s", error)
        log.info("unban %s (%s)", ban.target, why)
        self.notifier.send({"event": "unban", "target": ban.target, "reason": why})

    # --- housekeeping ------------------------------------------------------------------

    def tick(self) -> None:
        now = self.clock()
        for ban in self.book.expire(now):
            self._lift(ban, "expired")
        for ban in self.book.active():
            if not ban.applied:
                self._apply(ban)
        self.detector.sweep(now)
        self.process_spool()
        self.save()
        self.write_outputs()

    def save(self, force: bool = False) -> None:
        now = self.clock()
        due = now - self._last_save >= self.config.state.save_interval
        if not (self._dirty and due) and not force:
            return
        try:
            save_state(self.book, Path(self.config.state.path))
            self._dirty = False
            self._last_save = now
        except OSError as error:
            log.error("cannot save the state to %s: %s", self.config.state.path, error)

    # --- commands from `sshguard ban/unban` --------------------------------------------

    def process_spool(self) -> int:
        spool = Path(self.config.state.spool)
        try:
            files = sorted(p for p in spool.iterdir() if p.suffix == ".json")
        except OSError:
            return 0
        done = 0
        for path in files:
            if not _trusted_file(path):
                log.error(
                    "ignoring %s: not owned by root or by this user, or writable by others", path
                )
                _discard(path, ".rejected")
                continue
            try:
                command = json.loads(path.read_text(encoding="utf-8"))
                self.apply_command(command)
                done += 1
            except (OSError, ValueError, KeyError, TypeError) as error:
                log.error("bad command file %s: %s", path.name, error)
            _discard(path, None)
        return done

    def apply_command(self, command: dict[str, Any]) -> None:
        op = command["op"]
        target = normalize_target(str(command["target"]))
        now = self.clock()
        if op == "unban":
            ban = self.book.unban(target, forgive=bool(command.get("forgive", False)))
            if ban is not None:
                self._lift(ban, "by hand")
            else:
                log.info("unban %s: it was not banned", target)
        elif op == "ban":
            if self._is_allowlisted(target):
                log.error("refusing to ban %s: it overlaps the allowlist", target)
                return
            ttl = command.get("ttl")
            ban, evicted = self.book.ban(
                target, now, "manual", ttl=float(ttl) if ttl else None, manual=True
            )
            if evicted is not None:
                self._lift(evicted, "evicted")
            if ban is None:
                log.error("cannot ban %s: ban list full of manual bans", target)
                return
            self._dirty = True
            self._apply(ban)
            log.warning("manual ban %s", target)
            self.notifier.send(
                {
                    "event": "ban",
                    "target": target,
                    "reason": "manual",
                    "strikes": ban.strikes,
                    "seconds": None if ban.until is None else int(ban.until - now),
                }
            )
        else:
            raise ValueError(f"unknown command {op!r}")

    def _is_allowlisted(self, target: str) -> bool:
        net = ipaddress.ip_network(target, strict=False)
        return any(
            n.version == net.version and n.overlaps(net) for n in self.config.detect.allowlist
        )

    # --- outputs -----------------------------------------------------------------------

    def samples(self, up: bool = True) -> list[Sample]:
        out: list[Sample] = [
            ("sshguard_up", {}, 1.0 if up else 0.0),
            ("sshguard_start_time_seconds", {}, self.started),
            ("sshguard_lines_total", {}, float(self.counters["lines"])),
            ("sshguard_lines_parsed_total", {}, float(self.counters["parsed"])),
        ]
        out += [
            ("sshguard_attempts_total", {"kind": k}, float(v))
            for k, v in sorted(self.by_kind.items())
        ]
        out += [
            ("sshguard_ignored_total", {"why": k}, float(v))
            for k, v in sorted(self.ignored.items())
        ]
        out += [
            ("sshguard_bans_total", {"reason": k}, float(v))
            for k, v in sorted(self.by_reason.items())
        ]
        out += [
            ("sshguard_unbans_total", {}, float(self.counters["unbans"])),
            ("sshguard_evicted_bans_total", {}, float(self.counters["evicted"])),
            ("sshguard_backend_errors_total", {}, float(self.counters["backend_errors"])),
            ("sshguard_active_bans", {}, float(len(self.book))),
            (
                "sshguard_unapplied_bans",
                {},
                float(sum(1 for b in self.book.active() if not b.applied)),
            ),
            ("sshguard_tracked_sources", {}, float(len(self.detector))),
            ("sshguard_last_ban_timestamp_seconds", {}, self.last_ban),
            ("sshguard_notifications_failed_total", {}, float(self.notifier.failed)),
        ]
        return out

    def status(self) -> dict[str, Any]:
        now = self.clock()
        return {
            "version": __version__,
            "host": self.host,
            "backend": self.backend.name,
            "started": self.started,
            "updated": now,
            "active_bans": len(self.book),
            "tracked_sources": len(self.detector),
            "counters": dict(self.counters),
            "bans": [
                {
                    "target": b.target,
                    "reason": b.reason,
                    "strikes": b.strikes,
                    "remaining": b.remaining(now),
                    "applied": b.applied,
                    "manual": b.manual,
                }
                for b in self.book.active()
            ],
        }

    def write_outputs(self, force: bool = False, up: bool = True) -> None:
        cfg = self.config.metrics
        now = self.clock()
        if not force and now - self._last_metrics < cfg.interval:
            return
        self._last_metrics = now
        try:
            if cfg.file:
                write_atomic(cfg.file, render(self.samples(up)))
            if cfg.status_file:
                write_atomic(cfg.status_file, json.dumps(self.status(), indent=1))
        except OSError as error:
            log.error("cannot write the metrics: %s", error)


def _trusted_file(path: Path) -> bool:
    """A command file may only come from root or from the user the daemon runs as."""
    try:
        st = path.stat()
    except OSError:
        return False
    if st.st_mode & 0o022:
        return False
    if hasattr(os, "geteuid"):
        return st.st_uid in (0, os.geteuid())
    return True


def _discard(path: Path, rename_to: str | None) -> None:
    try:
        if rename_to:
            path.rename(path.with_suffix(rename_to))
        else:
            path.unlink()
    except OSError:
        pass
