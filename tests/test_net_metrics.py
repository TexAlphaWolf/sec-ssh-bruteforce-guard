from __future__ import annotations

import pytest

from sshguard.metrics import render, write_atomic
from sshguard.net import family, group_key, normalize_target, parse_ip, printable


def test_parse_ip():
    assert str(parse_ip("203.0.113.5")) == "203.0.113.5"
    assert str(parse_ip("[2001:db8::1]")) == "2001:db8::1"
    assert str(parse_ip("fe80::1%eth0")) == "fe80::1"
    assert str(parse_ip("::ffff:203.0.113.5")) == "203.0.113.5"
    for bad in ("", "evil.example", "1.2.3", "1.2.3.4.5", "999.1.1.1", "1.2.3.4; id", "0x7f.1"):
        assert parse_ip(bad) is None


def test_group_key():
    v6 = parse_ip("2001:db8:1:2:3:4:5:6")
    assert v6 is not None
    assert group_key(v6, 64) == "2001:db8:1:2::/64"
    assert group_key(v6, 48) == "2001:db8:1::/48"
    v4 = parse_ip("203.0.113.5")
    assert v4 is not None
    assert group_key(v4, 64) == "203.0.113.5"


def test_normalize_target():
    assert normalize_target(" 203.0.113.5 ") == "203.0.113.5"
    assert normalize_target("2001:DB8::1") == "2001:db8::1"
    assert normalize_target("198.51.100.0/24") == "198.51.100.0/24"
    for bad in ("198.51.100.1/24", "x", "1.2.3.4/40", "1.2.3.4 ; reboot"):
        with pytest.raises(ValueError):
            normalize_target(bad)


def test_family():
    assert family("203.0.113.5") == 4
    assert family("2001:db8::/64") == 6


def test_printable_neutralises_control_characters():
    assert printable(None) == "-"
    assert printable("root") == "root"
    assert printable("a\nb\x1b[31m") == "a\\x0ab\\x1b[31m"
    assert printable("x" * 100, 10) == "x" * 9 + "…"
    assert printable("back\\slash") == "back\\x5cslash"


def test_render_prometheus_text():
    text = render(
        [
            ("sshguard_up", {}, 1),
            ("sshguard_bans_total", {"reason": "failures"}, 3),
            ("sshguard_bans_total", {"reason": 'a"b\n'}, 1),
            ("unknown_metric", {}, 2.5),
        ]
    )
    assert text.count("# TYPE sshguard_bans_total counter") == 1
    assert 'sshguard_bans_total{reason="failures"} 3' in text
    assert 'reason="a\\"b\\n"' in text
    assert "# TYPE unknown_metric untyped" in text
    assert text.endswith("\n")


def test_write_atomic(tmp_path):  # type: ignore[no-untyped-def]
    target = tmp_path / "a" / "m.prom"
    write_atomic(target, "one\n")
    write_atomic(target, "two\n")
    assert target.read_text() == "two\n"
    assert [p.name for p in target.parent.iterdir()] == ["m.prom"]
