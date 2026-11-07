from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from sshguard.bans import BanBook, BanPolicy, load_state, save_state

T0 = 1_000_000.0


def book(**kw):  # type: ignore[no-untyped-def]
    return BanBook(BanPolicy(**kw))


def test_ban_and_expiry():
    b = book(ttl=100)
    ban, evicted = b.ban("203.0.113.5", T0, "failures")
    assert ban is not None
    assert evicted is None
    assert ban.until == T0 + 100
    assert b.is_banned("203.0.113.5", T0 + 99)
    assert not b.is_banned("203.0.113.5", T0 + 100)
    assert [x.target for x in b.expire(T0 + 100)] == ["203.0.113.5"]
    assert len(b) == 0


def test_repeat_offenders_wait_longer_up_to_a_cap():
    b = book(ttl=100, multiplier=4, max_ttl=1000)
    seen = []
    t = T0
    for _ in range(4):
        ban, _ = b.ban("203.0.113.5", t, "failures")
        assert ban is not None and ban.until is not None
        seen.append(ban.until - t)
        t = ban.until + 1
        b.expire(t)
    assert seen == [100, 400, 1000, 1000]


def test_recidive_can_be_switched_off():
    b = book(ttl=100, recidive=False)
    for i in range(3):
        ban, _ = b.ban("203.0.113.5", T0 + i * 1000, "failures")
        assert ban is not None and ban.until is not None
        assert ban.until - ban.since == 100
        b.expire(T0 + i * 1000 + 500)


def test_strikes_are_forgotten_after_a_quiet_period():
    b = book(ttl=100, strike_memory=1000)
    b.ban("203.0.113.5", T0, "failures")
    b.expire(T0 + 200)
    b.expire(T0 + 5000)
    ban, _ = b.ban("203.0.113.5", T0 + 6000, "failures")
    assert ban is not None and ban.strikes == 1


def test_banning_twice_while_banned_does_nothing():
    b = book()
    assert b.ban("203.0.113.5", T0, "x")[0] is not None
    assert b.ban("203.0.113.5", T0 + 1, "x")[0] is None


def test_manual_ban_replaces_an_automatic_one_and_can_be_permanent():
    b = book(ttl=100)
    b.ban("203.0.113.5", T0, "failures")
    ban, _ = b.ban("203.0.113.5", T0 + 1, "manual", manual=True)
    assert ban is not None and ban.until is None and ban.manual
    assert b.expire(T0 + 10**9) == []


def test_manual_ban_with_ttl():
    b = book()
    ban, _ = b.ban("198.51.100.0/24", T0, "manual", ttl=60, manual=True)
    assert ban is not None and ban.until == T0 + 60


def test_unban_and_forgive():
    b = book(ttl=100)
    b.ban("203.0.113.5", T0, "x")
    assert b.unban("203.0.113.5", forgive=True) is not None
    ban, _ = b.ban("203.0.113.5", T0 + 1, "x")
    assert ban is not None and ban.strikes == 1
    assert b.unban("203.0.113.99") is None


def test_full_book_evicts_the_ban_that_ends_soonest_and_keeps_manual_ones():
    b = book(ttl=100, max_active=3)
    b.ban("10.0.0.1", T0, "x", manual=True)
    b.ban("10.0.0.2", T0 + 10, "x")
    b.ban("10.0.0.3", T0 + 20, "x")
    ban, evicted = b.ban("10.0.0.4", T0 + 30, "x")
    assert ban is not None
    assert evicted is not None and evicted.target == "10.0.0.2"
    assert {x.target for x in b.active()} == {"10.0.0.1", "10.0.0.3", "10.0.0.4"}


def test_full_of_manual_bans_refuses():
    b = book(max_active=1)
    b.ban("10.0.0.1", T0, "x", manual=True)
    assert b.ban("10.0.0.2", T0, "x") == (None, None)


def test_state_round_trip_marks_bans_unapplied(tmp_path):  # type: ignore[no-untyped-def]
    b = book(ttl=100)
    ban, _ = b.ban("203.0.113.5", T0, "failures", score=5.0)
    assert ban is not None
    ban.applied = True
    path = tmp_path / "sub" / "state.json"
    save_state(b, path)
    again = book(ttl=100)
    assert load_state(again, path)
    loaded = again.get("203.0.113.5")
    assert loaded is not None
    assert (loaded.until, loaded.score, loaded.applied) == (T0 + 100, 5.0, False)
    again.ban("203.0.113.9", T0 + 1, "x")  # an unrelated ban in the book
    again.expire(T0 + 200)
    ban2, _ = again.ban("203.0.113.5", T0 + 300, "failures")
    assert ban2 is not None and ban2.strikes == 2  # the record of the first ban survived


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_state_file_is_private_and_written_atomically(tmp_path):  # type: ignore[no-untyped-def]
    path = tmp_path / "state.json"
    save_state(book(), path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]  # no temp file left behind


def test_missing_state_is_a_fresh_start(tmp_path):  # type: ignore[no-untyped-def]
    assert load_state(book(), tmp_path / "nope.json") is False


@pytest.mark.parametrize(
    "content", ["{not json", '{"version": 99}', '{"version": 1, "bans": [{"x": 1}]}', "[]"]
)
def test_corrupt_state_is_an_error_not_a_silent_reset(tmp_path, content):  # type: ignore[no-untyped-def]
    path = tmp_path / "state.json"
    path.write_text(content)
    with pytest.raises(ValueError, match="cannot read the state file"):
        load_state(book(), path)


def test_failed_save_leaves_the_old_file(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    path = tmp_path / "state.json"
    b = book()
    b.ban("203.0.113.5", T0, "x")
    save_state(b, path)
    before = path.read_text()
    monkeypatch.setattr(json, "dump", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        save_state(b, path)
    assert path.read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]
