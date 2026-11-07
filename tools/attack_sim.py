#!/usr/bin/env python3
"""Make an sshd log full of labelled attackers and legitimate users, or replay one live.

    python tools/attack_sim.py generate --out auth.log --labels labels.json
    python tools/attack_sim.py live --file auth.log --rate 4     # keep appending an attack

The log is syslog-formatted UTC and reproducible (--seed). `labels.json` says which source is
what, so tools/evaluate.py can score the guard. Every address is from the documentation ranges
(RFC 5737 / RFC 3849): nothing here points at a real machine.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

USERS = ["root", "admin", "ubuntu", "pi", "test", "oracle", "postgres", "git", "ftpuser", "user"]
START = datetime(2026, 11, 6, 0, 0, 0, tzinfo=UTC)
DAY = 86400


@dataclass
class Line:
    t: float  # seconds from START
    text: str


class Sim:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.lines: list[Line] = []
        self.labels: dict[str, str] = {}
        self._n4 = 0
        self._n6 = 0

    # --- helpers -----------------------------------------------------------------------

    def ip4(self) -> str:
        """A fresh documentation address (three /24 blocks reserved for examples)."""
        block = ["192.0.2", "198.51.100", "203.0.113"][self._n4 // 250 % 3]
        self._n4 += 1
        return f"{block}.{self._n4 % 250 + 1}"

    def net6(self) -> str:
        self._n6 += 1
        return f"2001:db8:{self._n6:x}:{self.rng.randrange(1, 0xFFFF):x}"

    def emit(self, t: float, msg: str, prog: str = "sshd") -> None:
        pid = self.rng.randrange(1000, 40000)
        self.lines.append(Line(t, f"{{ts}} web01 {prog}[{pid}]: {msg}"))

    def fail(self, t: float, ip: str, user: str, invalid: bool = False) -> None:
        port = self.rng.randrange(1024, 65535)
        who = "invalid user " if invalid else ""
        self.emit(t, f"Failed password for {who}{user} from {ip} port {port} ssh2")

    def invalid(self, t: float, ip: str, user: str) -> None:
        self.emit(t, f"Invalid user {user} from {ip} port {self.rng.randrange(1024, 65535)}")

    def closed(self, t: float, ip: str, user: str | None = None, invalid: bool = False) -> None:
        port = self.rng.randrange(1024, 65535)
        if user is None:
            self.emit(t, f"Connection closed by {ip} port {port} [preauth]")
        else:
            kind = "invalid" if invalid else "authenticating"
            self.emit(t, f"Connection closed by {kind} user {user} {ip} port {port} [preauth]")

    def accept(self, t: float, ip: str, user: str) -> None:
        port = self.rng.randrange(1024, 65535)
        self.emit(
            t, f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:abc"
        )
        self.emit(t + 5, f"pam_unix(sshd:session): session opened for user {user}")
        self.emit(t + 600, f"Disconnected from user {user} {ip} port {port}")

    def label(self, ip: str, kind: str) -> None:
        self.labels[ip] = kind

    # --- attackers ---------------------------------------------------------------------

    def brute_force(self, count: int) -> None:
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "brute_force")
            t = self.rng.uniform(0, DAY - 3600)
            for i in range(self.rng.randrange(40, 200)):
                user = self.rng.choice(USERS)
                invalid = user not in ("root", "ubuntu", "pi")
                if invalid:
                    self.invalid(t, ip, user)
                self.fail(t, ip, user, invalid)
                if i % 3 == 2:
                    self.closed(t + 0.2, ip, user, invalid)
                t += self.rng.uniform(0.5, 4)

    def spraying(self, count: int) -> None:
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "spraying")
            t = self.rng.uniform(0, DAY - 3600)
            for n in range(60):
                user = f"user{n}"
                self.invalid(t, ip, user)
                self.fail(t, ip, user, True)
                t += self.rng.uniform(8, 25)

    def low_and_slow(self, count: int) -> None:
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "low_and_slow")
            t = self.rng.uniform(0, 1800)
            while t < DAY:
                self.fail(t, ip, self.rng.choice(USERS))
                t += self.rng.uniform(25 * 60, 40 * 60)

    def ipv6_rotation(self, count: int) -> None:
        for _ in range(count):
            prefix = self.net6()
            self.label(prefix + "::/64", "ipv6_rotation")
            t = self.rng.uniform(0, DAY - 3600)
            for _ in range(80):
                ip = (
                    f"{prefix}::{self.rng.randrange(1, 0xFFFF):x}:{self.rng.randrange(1, 0xFFFF):x}"
                )
                self.fail(t, ip, self.rng.choice(USERS))
                t += self.rng.uniform(1, 5)

    def key_only_invalid_users(self, count: int) -> None:
        """Password login is off on the server: only 'Invalid user' and the dropped connection."""
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "key_only_probe")
            t = self.rng.uniform(0, DAY - 3600)
            for _ in range(30):
                user = self.rng.choice(USERS)
                self.invalid(t, ip, user)
                self.closed(t + 0.3, ip, user, True)
                t += self.rng.uniform(2, 8)

    def bot_probes(self, count: int) -> None:
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "probe_flood")
            t = self.rng.uniform(0, DAY - 3600)
            for _ in range(self.rng.randrange(80, 160)):
                self.emit(
                    t,
                    f"Did not receive identification string from {ip} port {self.rng.randrange(1024, 65535)}",
                )
                t += self.rng.uniform(1, 6)

    def noise(self, count: int) -> None:
        """Internet background: a scanner touches the port once or twice and leaves."""
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "noise")
            t = self.rng.uniform(0, DAY)
            for _ in range(self.rng.randrange(1, 3)):
                self.closed(t, ip)
                t += 2

    # --- legitimate --------------------------------------------------------------------

    def typos(self, count: int) -> None:
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "typo")
            user = f"person{self.rng.randrange(100)}"
            t = self.rng.uniform(0, DAY - 3600)
            for _ in range(self.rng.randrange(1, 4)):
                self.fail(t, ip, user)
                t += self.rng.uniform(3, 10)
            self.accept(t, ip, user)

    def forgetful(self, count: int) -> None:
        """Four wrong passwords inside ten minutes, then the right one."""
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "forgetful")
            t = self.rng.uniform(0, DAY - 3600)
            for _ in range(4):
                self.fail(t, ip, "luca")
                t += self.rng.uniform(20, 90)
            self.accept(t, ip, "luca")

    def automation(self, count: int) -> None:
        for _ in range(count):
            ip = self.ip4()
            self.label(ip, "automation")
            for i in range(96):  # every 15 minutes, all day
                self.accept(i * 900.0, ip, "deploy")
            self.fail(self.rng.uniform(0, DAY), ip, "deploy")

    def office_nat(self) -> None:
        """Thirty colleagues behind one address, a couple of typos each, spread over the day."""
        ip = self.ip4()
        self.label(ip, "office_nat")
        for n in range(30):
            user = f"colleague{n}"
            t = self.rng.uniform(8 * 3600, 18 * 3600)
            for _ in range(self.rng.randrange(0, 3)):
                self.fail(t, ip, user)
                t += 5
            self.accept(t, ip, user)

    def health_check(self) -> None:
        """A load balancer opening a TCP connection to port 22 every minute."""
        ip = self.ip4()
        self.label(ip, "health_check")
        for i in range(DAY // 60):
            self.closed(i * 60.0 + 3, ip)

    def chatter(self, count: int) -> None:
        for i in range(count):
            t = self.rng.uniform(0, DAY)
            self.emit(
                t,
                "Server listening on 0.0.0.0 port 22."
                if i % 50 == 0
                else "Received signal 15; terminating.",
            )
            self.lines.append(
                Line(
                    t,
                    "{ts} web01 CRON["
                    + str(i)
                    + "]: pam_unix(cron:session): session opened for user root",
                )
            )

    # --- output ------------------------------------------------------------------------

    def render(self) -> Iterator[str]:
        for line in sorted(self.lines, key=lambda x: x.t):
            moment = START + timedelta(seconds=line.t)
            stamp = f"{moment:%b} {moment.day:>2} {moment:%H:%M:%S}"
            yield line.text.replace("{ts}", stamp)


def build(seed: int = 7, scale: int = 1) -> Sim:
    sim = Sim(seed)
    sim.brute_force(30 * scale)
    sim.spraying(10 * scale)
    sim.low_and_slow(10 * scale)
    sim.ipv6_rotation(5 * scale)
    sim.key_only_invalid_users(10 * scale)
    sim.bot_probes(10 * scale)
    sim.noise(40 * scale)
    sim.typos(30 * scale)
    sim.forgetful(5 * scale)
    sim.automation(5)
    sim.office_nat()
    sim.health_check()
    sim.chatter(300 * scale)
    return sim


def cmd_generate(args: argparse.Namespace) -> int:
    sim = build(args.seed, args.scale)
    count = 0
    with open(args.out, "w", encoding="utf-8") as handle:
        for text in sim.render():
            handle.write(text + "\n")
            count += 1
    if args.labels:
        Path(args.labels).write_text(json.dumps(sim.labels, indent=1), encoding="utf-8")
    print(f"wrote {count} lines and {len(sim.labels)} labelled sources to {args.out}")
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    """Append failed logins to a file, one burst after another, until Ctrl-C."""
    rng = random.Random(args.seed)
    delay = 1 / args.rate
    print(f"appending to {args.file} at {args.rate} lines/s from {args.ip} (Ctrl-C to stop)")
    n = 0
    try:
        while True:
            now = datetime.now(UTC)
            user = rng.choice(USERS)
            stamp = f"{now:%b} {now.day:>2} {now:%H:%M:%S}"
            line = (
                f"{stamp} {args.host} sshd[{rng.randrange(1000, 40000)}]: Failed password for "
                f"{user} from {args.ip} port {rng.randrange(1024, 65535)} ssh2"
            )
            with open(args.file, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            n += 1
            time.sleep(delay)
            if args.count and n >= args.count:
                break
    except KeyboardInterrupt:
        pass
    print(f"wrote {n} lines")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--out", required=True)
    g.add_argument("--labels")
    g.add_argument("--seed", type=int, default=7)
    g.add_argument("--scale", type=int, default=1, help="multiply the number of sources")
    g.set_defaults(func=cmd_generate)
    v = sub.add_parser("live")
    v.add_argument("--file", required=True)
    v.add_argument("--ip", default="203.0.113.50")
    v.add_argument("--host", default="web01")
    v.add_argument("--rate", type=float, default=2.0, help="lines per second")
    v.add_argument("--count", type=int, default=0, help="stop after N lines (0: until Ctrl-C)")
    v.add_argument("--seed", type=int, default=1)
    v.set_defaults(func=cmd_live)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
