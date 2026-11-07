"""Turn sshd log lines into Attempts.

Three line layouts are understood: classic syslog (`Nov  7 10:00:01 host sshd[1]: ...`), ISO
timestamps (rsyslog, `journalctl -o short-iso`) and journald JSON (`journalctl -o json`).

Everything after the program name is matched against the *end* of the line. sshd copies the
user name the client sent into the message, and a client can send `x from 192.0.2.9 port 1`:
matching from the left would let an attacker make the guard ban someone else. Matching from the
right means the address that counts is always the last one, which sshd wrote itself.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, tzinfo
from zoneinfo import ZoneInfo

from .events import ACCEPTED, FAILED_AUTH, INVALID_USER, PREAUTH_DROP, PROBE, Attempt
from .net import parse_ip

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

_HEAD = r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+" + _HEAD
)
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+" + _HEAD
)

_TAIL = r"(?: ssh\d?(?::.*)?)?(?: \[preauth\])?\s*$"
_FAILED = re.compile(
    r"^Failed (?P<method>[\w/-]+) for (?P<invalid>invalid user )?(?P<user>.+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)" + _TAIL
)
_INVALID = re.compile(
    r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port \d+)?\s*(?:\[preauth\])?$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.+) from (?P<ip>\S+) port (?P<port>\d+)"
)
# "Connection closed by authenticating user root 192.0.2.1 port 5 [preauth]", "... by 192.0.2.1 ..."
_CLOSED = re.compile(
    r"^(?:Connection closed by|Connection reset by|Disconnected from) "
    r"(?:(?P<who>invalid|authenticating) user (?P<user>.+) )?(?P<ip>\S+) port \d+ \[preauth\]$"
)
_DISCONNECTING = re.compile(
    r"^Disconnecting (?:(?P<who>invalid|authenticating) user (?P<user>.+?) )?"
    r"(?P<ip>\S+) port \d+: .*\[preauth\]$"
)
_MAXTRIES = re.compile(
    r"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
    r"(?P<user>.+) from (?P<ip>\S+) port \d+" + _TAIL
)
_PROBES = (
    re.compile(r"^Did not receive identification string from (?P<ip>\S+)(?: port \d+)?\s*$"),
    re.compile(r"^Unable to negotiate with (?P<ip>\S+) port \d+: "),
    re.compile(r"^banner exchange: Connection from (?P<ip>\S+) port \d+: "),
    re.compile(r"^Bad protocol version identification .* from (?P<ip>\S+) port \d+\s*$"),
    re.compile(r"^error: kex_exchange_identification: .*from (?P<ip>\S+) port \d+\s*$"),
)

# OpenSSH 9.8 split the daemon in three programs; the old name is still the common one.
_PROGRAMS = ("sshd", "sshd-session", "sshd-auth")


def _zone(name: str) -> tzinfo | None:
    """None means the machine's local time zone."""
    if name.lower() == "local":
        return None
    return ZoneInfo(name)


def _syslog_ts(
    mon: str, day: str, hms: str, tz: str, year: int | None, now: datetime
) -> float | None:
    month = MONTHS.get(mon)
    if month is None:
        return None
    hour, minute, second = (int(p) for p in hms.split(":"))
    zone = _zone(tz)
    try:
        naive = datetime(year or now.year, month, int(day), hour, minute, second)
        moment = naive.replace(tzinfo=zone) if zone else naive.astimezone()
        # A December line read in January belongs to last year.
        if year is None and moment.timestamp() > now.timestamp() + 86400:
            naive = naive.replace(year=naive.year - 1)
            moment = naive.replace(tzinfo=zone) if zone else naive.astimezone()
    except ValueError:
        return None
    return moment.timestamp()


def _iso_ts(value: str, tz: str) -> float | None:
    text = value.replace("Z", "+00:00")
    if len(text) > 5 and text[-5] in "+-" and text[-3] != ":":  # +0200 -> +02:00
        text = text[:-2] + ":" + text[-2:]
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        zone = _zone(tz)
        moment = moment.replace(tzinfo=zone) if zone else moment.astimezone()
    return moment.timestamp()


def classify(msg: str) -> tuple[str, str | None, str, bool] | None:
    """(kind, user, raw ip, user_was_invalid) for the message of an sshd line, if it matters."""
    if m := _FAILED.match(msg):
        return FAILED_AUTH, m["user"], m["ip"], bool(m["invalid"])
    if m := _INVALID.match(msg):
        return INVALID_USER, m["user"] or None, m["ip"], True
    if m := _ACCEPTED.match(msg):
        return ACCEPTED, m["user"], m["ip"], False
    for pattern in (_CLOSED, _DISCONNECTING):
        if m := pattern.match(msg):
            kind = PREAUTH_DROP if m["user"] else PROBE  # no user named: nobody tried to log in
            return kind, m["user"], m["ip"], m["who"] == "invalid"
    if m := _MAXTRIES.match(msg):
        return PREAUTH_DROP, m["user"], m["ip"], bool(m["invalid"])
    for probe in _PROBES:
        if m := probe.match(msg):
            return PROBE, None, m["ip"], False
    return None


def _build(ts: float | None, msg: str) -> Attempt | None:
    if ts is None:
        return None
    found = classify(msg)
    if found is None:
        return None
    kind, user, raw_ip, invalid = found
    ip = parse_ip(raw_ip)
    if ip is None:
        return None  # an address field that is not an address: do not act on the line
    return Attempt(ts=ts, ip=str(ip), kind=kind, user=user, invalid_user=invalid)


def _from_journal_json(line: str) -> Attempt | None:
    try:
        entry = json.loads(line)
    except ValueError:
        return None
    if not isinstance(entry, dict):
        return None
    message = entry.get("MESSAGE")
    ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
    stamp = entry.get("__REALTIME_TIMESTAMP")
    if not isinstance(message, str) or ident not in _PROGRAMS:
        return None  # a non-UTF-8 message arrives as a list of bytes: not an sshd line we know
    try:
        ts = int(stamp) / 1_000_000 if stamp is not None else None
    except (TypeError, ValueError):
        return None
    return _build(ts, message)


def parse_line(
    line: str, *, tz: str = "local", year: int | None = None, now: datetime | None = None
) -> Attempt | None:
    """Parse one log line. None means: not an sshd line we care about."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        return _from_journal_json(line)
    now = now or datetime.now().astimezone()
    if m := _SYSLOG.match(line):
        ts = _syslog_ts(m["mon"], m["day"], m["hms"], tz, year, now)
    elif m := _ISO.match(line):
        ts = _iso_ts(m["ts"], tz)
    else:
        return None
    if m["prog"] not in _PROGRAMS:
        return None
    return _build(ts, m["msg"])


__all__ = ["classify", "parse_line"]
