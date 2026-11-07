from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sshguard.events import ACCEPTED, FAILED_AUTH, INVALID_USER, PREAUTH_DROP, PROBE
from sshguard.parsers import parse_line

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def p(line: str, **kw):  # type: ignore[no-untyped-def]
    return parse_line(line, tz="UTC", year=2026, now=NOW, **kw)


S = "Nov  7 10:00:01 web01 sshd[111]: "


@pytest.mark.parametrize(
    ("message", "kind", "user", "ip", "invalid"),
    [
        (
            "Failed password for root from 203.0.113.5 port 4242 ssh2",
            FAILED_AUTH,
            "root",
            "203.0.113.5",
            False,
        ),
        (
            "Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2",
            FAILED_AUTH,
            "admin",
            "203.0.113.5",
            True,
        ),
        (
            "Failed publickey for git from 203.0.113.5 port 1 ssh2: RSA SHA256:abc",
            FAILED_AUTH,
            "git",
            "203.0.113.5",
            False,
        ),
        (
            "Failed keyboard-interactive/pam for root from 2001:db8::5 port 22 ssh2",
            FAILED_AUTH,
            "root",
            "2001:db8::5",
            False,
        ),
        (
            "Invalid user oracle from 198.51.100.4 port 5555",
            INVALID_USER,
            "oracle",
            "198.51.100.4",
            True,
        ),
        ("Invalid user oracle from 198.51.100.4", INVALID_USER, "oracle", "198.51.100.4", True),
        (
            "Connection closed by authenticating user root 203.0.113.5 port 4242 [preauth]",
            PREAUTH_DROP,
            "root",
            "203.0.113.5",
            False,
        ),
        (
            "Connection closed by invalid user bob 203.0.113.5 port 4242 [preauth]",
            PREAUTH_DROP,
            "bob",
            "203.0.113.5",
            True,
        ),
        (
            "Connection closed by 203.0.113.5 port 4242 [preauth]",
            PROBE,
            None,
            "203.0.113.5",
            False,
        ),
        (
            "Connection reset by 203.0.113.5 port 4242 [preauth]",
            PROBE,
            None,
            "203.0.113.5",
            False,
        ),
        (
            "Disconnected from invalid user bob 203.0.113.5 port 4242 [preauth]",
            PREAUTH_DROP,
            "bob",
            "203.0.113.5",
            True,
        ),
        (
            "Disconnecting authenticating user root 203.0.113.5 port 4242: Too many authentication failures [preauth]",
            PREAUTH_DROP,
            "root",
            "203.0.113.5",
            False,
        ),
        (
            "error: maximum authentication attempts exceeded for invalid user a from 203.0.113.5 port 22 ssh2 [preauth]",
            PREAUTH_DROP,
            "a",
            "203.0.113.5",
            True,
        ),
        (
            "Did not receive identification string from 203.0.113.5 port 4242",
            PROBE,
            None,
            "203.0.113.5",
            False,
        ),
        (
            "Unable to negotiate with 203.0.113.5 port 4242: no matching key exchange method found.",
            PROBE,
            None,
            "203.0.113.5",
            False,
        ),
        (
            "banner exchange: Connection from 203.0.113.5 port 4242: invalid format",
            PROBE,
            None,
            "203.0.113.5",
            False,
        ),
        (
            "Bad protocol version identification 'GET / HTTP/1.1' from 203.0.113.5 port 4242",
            PROBE,
            None,
            "203.0.113.5",
            False,
        ),
        (
            "Accepted publickey for luca from 192.0.2.10 port 5000 ssh2: ED25519 SHA256:xx",
            ACCEPTED,
            "luca",
            "192.0.2.10",
            False,
        ),
        (
            "Failed password for root from ::ffff:203.0.113.5 port 22 ssh2",
            FAILED_AUTH,
            "root",
            "203.0.113.5",
            False,
        ),
    ],
)
def test_messages(message, kind, user, ip, invalid):  # type: ignore[no-untyped-def]
    a = p(S + message)
    assert a is not None
    assert (a.kind, a.user, a.ip, a.invalid_user) == (kind, user, ip, invalid)


@pytest.mark.parametrize(
    "message",
    [
        "Disconnected from user root 203.0.113.5 port 4242",  # a normal logout, not an attack
        "Connection closed by 203.0.113.5 port 4242",  # no [preauth]: after a login
        "Server listening on 0.0.0.0 port 22.",
        "pam_unix(sshd:auth): authentication failure; rhost=203.0.113.5",
        "Received disconnect from 203.0.113.5 port 4242:11: Bye Bye",
        "Failed password for root from not-an-ip port 22 ssh2",
        "",
    ],
)
def test_lines_that_must_not_count(message):  # type: ignore[no-untyped-def]
    assert p(S + message) is None


def test_other_programs_are_ignored():
    assert (
        p("Nov  7 10:00:01 web01 sudo[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
        is None
    )


def test_user_name_cannot_frame_another_address():
    """sshd copies the name the client sent. 'x from 9.9.9.9 port 1' must not move the blame."""
    line = (
        S
        + "Failed password for invalid user x from 9.9.9.9 port 1 ssh2 from 203.0.113.7 port 22 ssh2"
    )
    a = p(line)
    assert a is not None
    assert a.ip == "203.0.113.7"
    assert a.user is not None
    assert a.user.startswith("x from 9.9.9.9")


def test_fake_line_inside_a_user_name_is_one_event():
    a = p(
        S + "Invalid user a Failed password for root from 9.9.9.9 port 1 from 203.0.113.7 port 22"
    )
    assert a is not None
    assert a.ip == "203.0.113.7"


def test_syslog_timestamp_uses_given_zone_and_year():
    a = parse_line(
        S + "Failed password for root from 203.0.113.5 port 1 ssh2", tz="Europe/Rome", year=2026
    )
    assert a is not None
    assert datetime.fromtimestamp(a.ts, UTC) == datetime(2026, 11, 7, 9, 0, 1, tzinfo=UTC)


def test_syslog_december_line_read_in_january_is_last_year():
    now = datetime(2027, 1, 2, 0, 0, tzinfo=UTC)
    a = parse_line(
        "Dec 31 23:59:59 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        tz="UTC",
        now=now,
    )
    assert a is not None
    assert datetime.fromtimestamp(a.ts, UTC).year == 2026


def test_impossible_date_is_dropped():
    assert (
        p("Feb 31 10:00:01 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
        is None
    )


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-11-07T10:00:01+01:00",
        "2026-11-07T10:00:01+0100",
        "2026-11-07T09:00:01Z",
        "2026-11-07T09:00:01.250000+00:00",
    ],
)
def test_iso_timestamps(stamp):  # type: ignore[no-untyped-def]
    a = p(f"{stamp} web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
    assert a is not None
    assert int(a.ts) == int(datetime(2026, 11, 7, 9, 0, 1, tzinfo=UTC).timestamp())


def test_iso_without_zone_uses_tz_setting():
    a = parse_line(
        "2026-11-07T10:00:01 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        tz="Europe/Rome",
    )
    assert a is not None
    assert datetime.fromtimestamp(a.ts, UTC).hour == 9


def test_local_zone_is_accepted():
    assert p(S + "Failed password for root from 203.0.113.5 port 1 ssh2") is not None
    a = parse_line(
        S + "Failed password for root from 203.0.113.5 port 1 ssh2", tz="local", year=2026
    )
    assert a is not None


def test_new_openssh_program_names():
    a = p(
        "Nov  7 10:00:01 h sshd-session[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    )
    assert a is not None


def test_journald_json():
    line = '{"MESSAGE":"Failed password for invalid user a from 203.0.113.5 port 22 ssh2","__REALTIME_TIMESTAMP":"1794045601000000","SYSLOG_IDENTIFIER":"sshd","_HOSTNAME":"h"}'
    a = p(line)
    assert a is not None
    assert a.ts == 1794045601.0
    assert a.invalid_user


@pytest.mark.parametrize(
    "line",
    [
        '{"MESSAGE":[70,97],"__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sshd"}',  # bytes
        '{"MESSAGE":"Failed password for root from 203.0.113.5 port 22 ssh2","SYSLOG_IDENTIFIER":"sshd"}',
        '{"MESSAGE":"Failed password for root from 203.0.113.5 port 22 ssh2","__REALTIME_TIMESTAMP":"x","SYSLOG_IDENTIFIER":"sshd"}',
        '{"MESSAGE":"Failed password for root from 203.0.113.5 port 22 ssh2","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"cron"}',
        "{not json",
        "[1, 2]",
    ],
)
def test_journald_garbage(line):  # type: ignore[no-untyped-def]
    assert p(line) is None


def test_unknown_layout_and_garbage():
    assert p("hello world") is None
    assert p("\x00\x01\x02 " * 50) is None
