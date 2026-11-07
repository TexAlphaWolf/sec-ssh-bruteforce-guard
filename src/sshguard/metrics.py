"""Prometheus text exposition, written to a file for the node_exporter textfile collector."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

Sample = tuple[str, dict[str, str], float]

HELP = {
    "sshguard_up": ("gauge", "1 while the daemon is running."),
    "sshguard_start_time_seconds": ("gauge", "When the daemon started."),
    "sshguard_lines_total": ("counter", "Log lines read."),
    "sshguard_lines_parsed_total": ("counter", "Log lines that were sshd authentication events."),
    "sshguard_attempts_total": ("counter", "Authentication events seen, by kind."),
    "sshguard_ignored_total": (
        "counter",
        "Events not counted, by why (allowlist, already banned).",
    ),
    "sshguard_bans_total": ("counter", "Bans issued, by reason."),
    "sshguard_unbans_total": ("counter", "Bans lifted (expired or by hand)."),
    "sshguard_evicted_bans_total": (
        "counter",
        "Bans dropped early because ban.max_active was hit.",
    ),
    "sshguard_backend_errors_total": ("counter", "Firewall calls that failed."),
    "sshguard_active_bans": ("gauge", "Bans in force now."),
    "sshguard_unapplied_bans": ("gauge", "Bans waiting for the firewall to accept them."),
    "sshguard_tracked_sources": ("gauge", "Sources with a failure count in memory."),
    "sshguard_last_ban_timestamp_seconds": ("gauge", "When the last ban was issued."),
    "sshguard_notifications_failed_total": ("counter", "Alerts that could not be sent."),
}


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render(samples: list[Sample]) -> str:
    lines: list[str] = []
    seen: set[str] = set()
    for name, labels, value in samples:
        if name not in seen:
            seen.add(name)
            kind, text = HELP.get(name, ("untyped", name))
            lines += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
        label = ""
        if labels:
            label = "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items())) + "}"
        lines.append(f"{name}{label} {value:g}")
    return "\n".join(lines) + "\n"


def write_atomic(path: str | Path, text: str, mode: int = 0o644) -> None:
    """Write a file so a reader never sees half of it (the collector reads at any moment)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=target.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        with contextlib.suppress(OSError):
            os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
