"""Command line: run, scan, list, ban, unban, check-config."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .bans import BanBook, load_state, save_state
from .config import Config, ConfigError, apply_env, load, parse_duration
from .daemon import run
from .net import normalize_target
from .scan import format_report, path_exists, scan_files


def _config(args: argparse.Namespace) -> Config:
    return apply_env(load(args.config))


def cmd_run(args: argparse.Namespace) -> int:
    return run(_config(args))


def cmd_check(args: argparse.Namespace) -> int:
    cfg = _config(args)
    print(f"configuration OK ({args.config or 'defaults'})")
    print(
        f"  source   {cfg.source.kind} "
        f"{list(cfg.source.paths) if cfg.source.kind == 'file' else ''}"
    )
    print(
        f"  backend  {cfg.backend.kind}"
        + (" (nothing is blocked)" if cfg.backend.kind == "dry-run" else "")
    )
    print(
        f"  detect   {cfg.detect.max_failures:g} weighted failures in {cfg.detect.window:g}s, "
        f"ban {cfg.ban.ttl:g}s x{cfg.ban.multiplier:g} per repeat"
    )
    print(f"  allowlist {', '.join(str(n) for n in cfg.detect.allowlist) or '(empty)'}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = _config(args)
    missing = path_exists(args.files)
    if missing:
        print(f"sshguard: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    report = scan_files(args.files, cfg, year=args.year)
    if args.json:
        print(
            json.dumps(
                {
                    "lines": report.lines,
                    "events": report.parsed,
                    "by_kind": dict(report.by_kind),
                    "ignored": dict(report.ignored),
                    "bans": [asdict(b) for b in report.bans],
                },
                indent=1,
            )
        )
    else:
        print(format_report(report))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    cfg = _config(args)
    book = BanBook(cfg.ban)
    try:
        if not load_state(book, Path(cfg.state.path)):
            print("no bans (no state file yet)")
            return 0
    except ValueError as error:
        print(f"sshguard: {error}", file=sys.stderr)
        return 1
    now = time.time()
    bans = [b for b in book.active() if b.until is None or b.until > now]
    if args.json:
        print(json.dumps([asdict(b) for b in bans], indent=1))
        return 0
    if not bans:
        print("no active bans")
        return 0
    print(f"{'target':<26} {'reason':<9} {'strike':>6}  {'left':>9}  by")
    for b in bans:
        left = "permanent" if b.until is None else f"{int(b.until - now)}s"
        print(
            f"{b.target:<26} {b.reason:<9} {b.strikes:>6}  {left:>9}  "
            f"{'hand' if b.manual else 'auto'}"
        )
    return 0


def _queue_command(cfg: Config, command: dict[str, object]) -> Path:
    spool = Path(cfg.state.spool)
    spool.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = spool / f"{time.time_ns()}-{uuid.uuid4().hex[:8]}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(command, handle)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        # Run as root, the daemon (an unprivileged user) must still be able to read the file:
        # hand it to whoever owns the spool directory, which is the daemon's own user.
        owner = spool.stat()
        os.chown(path, owner.st_uid, owner.st_gid)
    return path


def _change(args: argparse.Namespace, op: str) -> int:
    cfg = _config(args)
    try:
        target = normalize_target(args.target)
        ttl = parse_duration(args.ttl, "--ttl") if getattr(args, "ttl", None) else None
    except (ValueError, ConfigError) as error:
        print(f"sshguard: {error}", file=sys.stderr)
        return 2
    command: dict[str, object] = {"op": op, "target": target}
    if ttl:
        command["ttl"] = ttl
    if op == "unban":
        command["forgive"] = bool(args.forgive)
    if args.offline:
        book = BanBook(cfg.ban)
        state = Path(cfg.state.path)
        load_state(book, state)
        if op == "unban":
            gone = book.unban(target, forgive=bool(args.forgive))
            print(f"{target}: unbanned in the state file" if gone else f"{target}: was not banned")
        else:
            book.ban(target, time.time(), "manual", ttl=ttl, manual=True)
            print(f"{target}: added to the state file")
        save_state(book, state)
        print("the firewall is only updated when the daemon starts (it re-syncs from the file)")
        return 0
    try:
        path = _queue_command(cfg, command)
    except OSError as error:
        print(f"sshguard: cannot write to the spool {cfg.state.spool}: {error}", file=sys.stderr)
        return 1
    print(
        f"queued {op} {target} ({path.name}); the running daemon applies it within a second or two"
    )
    return 0


def cmd_ban(args: argparse.Namespace) -> int:
    return _change(args, "ban")


def cmd_unban(args: argparse.Namespace) -> int:
    return _change(args, "unban")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sshguard", description=__doc__)
    parser.add_argument("--version", action="version", version=f"sshguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_config(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("-c", "--config", help="path to config.toml (default: built-in, dry-run)")
        return p

    with_config(sub.add_parser("run", help="run the daemon")).set_defaults(func=cmd_run)
    with_config(sub.add_parser("check-config", help="validate a config file")).set_defaults(
        func=cmd_check
    )

    p = with_config(sub.add_parser("scan", help="replay log files and report what would be banned"))
    p.add_argument("files", nargs="+", help="log files, oldest first; .gz is read; - is stdin")
    p.add_argument("--year", type=int, help="year of syslog timestamps (they carry none)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = with_config(sub.add_parser("list", help="show the active bans"))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = with_config(sub.add_parser("ban", help="ban an address or network by hand"))
    p.add_argument("target")
    p.add_argument("--ttl", help="e.g. 2h, 7d (default: permanent)")
    p.add_argument("--offline", action="store_true", help="edit the state file; daemon not running")
    p.set_defaults(func=cmd_ban)

    p = with_config(sub.add_parser("unban", help="lift a ban"))
    p.add_argument("target")
    p.add_argument("--forgive", action="store_true", help="also clear its strike record")
    p.add_argument("--offline", action="store_true", help="edit the state file; daemon not running")
    p.set_defaults(func=cmd_unban)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as error:
        print(f"sshguard: {error}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
