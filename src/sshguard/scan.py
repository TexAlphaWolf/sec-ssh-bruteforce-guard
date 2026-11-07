"""Offline mode: replay log files through the same detector and report what would be banned."""

from __future__ import annotations

import gzip
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from .bans import BanBook
from .config import Config
from .detector import Detector
from .net import group_key, parse_ip
from .parsers import parse_line


@dataclass
class BanRecord:
    ts: float
    target: str
    reason: str
    score: float
    users: int
    strikes: int
    seconds: float | None


@dataclass
class ScanReport:
    lines: int = 0
    parsed: int = 0
    by_kind: Counter[str] = field(default_factory=Counter)
    ignored: Counter[str] = field(default_factory=Counter)
    bans: list[BanRecord] = field(default_factory=list)
    failures_by_source: Counter[str] = field(default_factory=Counter)

    @property
    def banned_sources(self) -> set[str]:
        return {b.target for b in self.bans}


def open_log(path: str) -> TextIO:
    if path == "-":
        import sys

        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def read_lines(paths: list[str]) -> Iterator[str]:
    for path in paths:
        handle = open_log(path)
        try:
            yield from handle
        finally:
            if path != "-":
                handle.close()


def scan_lines(
    lines: Iterator[str] | list[str], config: Config, *, year: int | None = None
) -> ScanReport:
    """Run lines through the detector using the *log's* clock, as the daemon does in 'log' mode."""
    detector = Detector(config.detect)
    book = BanBook(config.ban)
    report = ScanReport()
    for line in lines:
        report.lines += 1
        attempt = parse_line(line, tz=config.source.tz, year=year)
        if attempt is None:
            continue
        report.parsed += 1
        report.by_kind[attempt.kind] += 1
        ip = parse_ip(attempt.ip)
        if ip is None:
            continue
        if detector.is_allowed(ip):
            report.ignored["allowlist"] += 1
            continue
        key = group_key(ip, config.detect.ipv6_prefix)
        if book.is_banned(key, attempt.ts):
            report.ignored["already_banned"] += 1
            continue
        if attempt.kind in ("failed_auth", "preauth_drop"):
            report.failures_by_source[key] += 1
        verdict = detector.observe(attempt, attempt.ts)
        if verdict is None:
            continue
        ban, _ = book.ban(verdict.target, attempt.ts, verdict.reason, score=verdict.score)
        detector.forget(verdict.target)
        if ban is not None:
            seconds = None if ban.until is None else ban.until - attempt.ts
            report.bans.append(
                BanRecord(
                    attempt.ts,
                    ban.target,
                    ban.reason,
                    ban.score,
                    verdict.users,
                    ban.strikes,
                    seconds,
                )
            )
    return report


def scan_files(paths: list[str], config: Config, *, year: int | None = None) -> ScanReport:
    return scan_lines(read_lines(paths), config, year=year)


HEADER = (
    f"{'time (UTC)':<20} {'target':<24} {'reason':<9} {'score':>5} {'users':>5} {'strike':>6}  ttl"
)
ROW = "{:<20} {:<24} {:<9} {:>5.1f} {:>5} {:>6}  {}"


def format_report(report: ScanReport, top: int = 10) -> str:
    from datetime import datetime

    out = [
        f"lines read      {report.lines}",
        f"sshd events     {report.parsed}  "
        + "  ".join(f"{k}={v}" for k, v in sorted(report.by_kind.items())),
        f"would ban       {len(report.banned_sources)} source(s), {len(report.bans)} ban(s)",
    ]
    if report.ignored:
        out.append(
            "not counted     " + "  ".join(f"{k}={v}" for k, v in sorted(report.ignored.items()))
        )
    if report.bans:
        out.append("")
        out.append(HEADER)
        for b in report.bans[:200]:
            when = datetime.fromtimestamp(b.ts, tz=__import__("datetime").UTC).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            ttl = "permanent" if b.seconds is None else f"{int(b.seconds)}s"
            out.append(ROW.format(when, b.target, b.reason, b.score, b.users, b.strikes, ttl))
        if len(report.bans) > 200:
            out.append(f"... and {len(report.bans) - 200} more")
    quiet = [
        (k, n) for k, n in report.failures_by_source.most_common() if k not in report.banned_sources
    ]
    if quiet:
        out.append("")
        out.append("most failures from sources that were NOT banned:")
        out += [f"  {k:<24} {n}" for k, n in quiet[:top]]
    return "\n".join(out)


def path_exists(paths: list[str]) -> list[str]:
    return [p for p in paths if p != "-" and not Path(p).exists()]
