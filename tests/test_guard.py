from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from conftest import Clock, FakeRunner, make_config
from sshguard.backends import BackendError, DryRunBackend, NftBackend
from sshguard.guard import Guard
from sshguard.notify import Notifier

ATTACKER = "203.0.113.5"


def line(ip: str = ATTACKER, user: str = "root", n: int = 1) -> str:
    return f"Nov  7 10:00:01 web01 sshd[111]: Failed password for {user} from {ip} port {n} ssh2"


def build(tmp_path: Path, clock: Clock, backend=None, **sections):  # type: ignore[no-untyped-def]
    sections.setdefault("state", {})
    sections["state"] = {
        "path": str(tmp_path / "state.json"),
        "spool": str(tmp_path / "spool"),
        "save_interval": 0,
        **sections["state"],
    }
    cfg = make_config(**sections)
    return Guard(cfg, backend or DryRunBackend(), clock=clock, host="testhost")


def test_five_failures_ban_the_source(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    for i in range(4):
        g.process_line(line(n=i))
    assert len(g.book) == 0
    g.process_line(line(n=5))
    assert [b.target for b in g.book.active()] == [ATTACKER]
    assert g.backend.actions == [("ban", ATTACKER)]  # type: ignore[attr-defined]


def test_arrival_time_is_used_not_the_log_timestamp(tmp_path, clock):  # type: ignore[no-untyped-def]
    """The log line says 1970-ish nothing: windows follow the wall clock, so a wrong log zone is harmless."""
    g = build(tmp_path, clock)
    for i in range(5):
        g.process_line(
            "Jan  1 00:00:00 h sshd[1]: "
            + f"Failed password for root from {ATTACKER} port {i} ssh2"
        )
        clock.advance(1)
    assert len(g.book) == 1
    ban = g.book.active()[0]
    assert ban.since > 1_700_000_000


def test_attempts_after_the_window_do_not_add_up(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    for _ in range(10):
        g.process_line(line())
        clock.advance(700)  # window is 600 s; slow limit (15 in 24 h) not reached
    assert len(g.book) == 0


def test_banned_sources_stop_being_counted(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    for i in range(20):
        g.process_line(line(n=i))
    assert g.ignored["already_banned"] == 15
    assert g.counters["lines"] == 20


def test_ban_expires_and_is_lifted(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock, ban={"ttl": "10m"})
    for i in range(5):
        g.process_line(line(n=i))
    clock.advance(601)
    g.tick()
    assert len(g.book) == 0
    assert ("unban", ATTACKER) in g.backend.actions  # type: ignore[attr-defined]


def test_second_ban_is_longer(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock, ban={"ttl": "10m", "multiplier": 4})
    for round_ in (1, 2):
        for i in range(5):
            g.process_line(line(n=i))
        ban = g.book.active()[0]
        assert ban.until is not None
        assert ban.until - ban.since == 600 * 4 ** (round_ - 1)
        clock.advance(ban.until - ban.since + 1)
        g.tick()


def test_allowlisted_source_is_never_banned(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock, allowlist={"networks": ["203.0.113.0/24"]})
    for i in range(50):
        g.process_line(line(n=i))
    assert len(g.book) == 0
    assert g.ignored["allowlist"] == 50


def test_ipv6_attacker_is_banned_as_a_prefix(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    for i in range(5):
        g.process_line(line(ip=f"2001:db8:0:1::{i + 1:x}", n=i))
    assert [b.target for b in g.book.active()] == ["2001:db8:0:1::/64"]


def test_junk_lines_are_counted_but_harmless(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    for junk in ["", "garbage", "\x00" * 10, "Nov 7 sshd: Failed password for"]:
        g.process_line(junk)
    assert g.counters["lines"] == 4 and g.counters["parsed"] == 0


def test_restart_keeps_the_bans_and_restores_them_in_the_firewall(tmp_path, clock):  # type: ignore[no-untyped-def]
    first = build(tmp_path, clock)
    first.start()
    for i in range(5):
        first.process_line(line(n=i))
    first.stop()

    runner = FakeRunner()
    clock.advance(60)
    second = build(tmp_path, clock, backend=NftBackend(runner=runner))
    second.start()
    assert [b.target for b in second.book.active()] == [ATTACKER]
    sync = [c for c in runner.calls if c[1] and "flush set" in c[1]]
    assert (
        sync and f"add element inet sshguard blocked4 {{ {ATTACKER} timeout 3540s }}" in sync[0][1]
    )  # type: ignore[operator]
    assert second.book.active()[0].applied


def test_bans_that_ended_while_the_daemon_was_down_are_not_restored(tmp_path, clock):  # type: ignore[no-untyped-def]
    first = build(tmp_path, clock, ban={"ttl": "1m"})
    first.start()
    for i in range(5):
        first.process_line(line(n=i))
    first.stop()
    clock.advance(3600)
    second = build(tmp_path, clock, ban={"ttl": "1m"})
    second.start()
    assert len(second.book) == 0


def test_corrupt_state_stops_the_start(tmp_path, clock):  # type: ignore[no-untyped-def]
    (tmp_path / "state.json").write_text("{broken")
    with pytest.raises(RuntimeError, match="cannot read the state file"):
        build(tmp_path, clock).start()


class FlakyBackend(DryRunBackend):
    def __init__(self) -> None:
        super().__init__()
        self.fail = True

    def ban(self, target: str, seconds: float | None) -> None:
        if self.fail:
            raise BackendError("nft is down")
        super().ban(target, seconds)

    def sync(self, bans):  # type: ignore[no-untyped-def]
        if self.fail:
            raise BackendError("nft is down")


def test_a_failing_firewall_is_retried_and_never_crashes_the_guard(tmp_path, clock):  # type: ignore[no-untyped-def]
    backend = FlakyBackend()
    g = build(tmp_path, clock, backend=backend)
    g.start()
    for i in range(5):
        g.process_line(line(n=i))
    ban = g.book.active()[0]
    assert not ban.applied
    assert g.counters["backend_errors"] >= 1
    unapplied = [v for n, _, v in g.samples() if n == "sshguard_unapplied_bans"]
    assert unapplied == [1.0]
    backend.fail = False
    g.tick()
    assert ban.applied
    assert ("ban", ATTACKER) in backend.actions


def test_unban_failure_is_logged_not_raised(tmp_path, clock, caplog):  # type: ignore[no-untyped-def]
    class Bad(DryRunBackend):
        def unban(self, target: str) -> None:
            raise BackendError("cannot unban")

    g = build(tmp_path, clock, backend=Bad())
    for i in range(5):
        g.process_line(line(n=i))
    clock.advance(4000)
    g.tick()
    assert len(g.book) == 0
    assert g.counters["backend_errors"] == 1


def test_replaying_an_old_log_does_not_ban_for_old_attacks(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock, source={"time_source": "log", "tz": "UTC"})
    old = "Jan  1 00:00:%02d web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    year = 2026
    from sshguard.parsers import parse_line

    for i in range(5):
        a = parse_line(old % i, tz="UTC", year=year)
        assert a is not None
        g.handle(a, a.ts)
    assert len(g.book) == 0
    assert g.ignored["expired_on_arrival"] == 1


def test_log_time_mode_bans_recent_attacks(tmp_path, clock):  # type: ignore[no-untyped-def]
    from sshguard.events import Attempt

    g = build(tmp_path, clock, source={"time_source": "log"})
    for i in range(5):
        g.handle(Attempt(clock.now - 30 + i, ATTACKER, "failed_auth", "root"), clock.now - 30 + i)
    assert len(g.book) == 1


# --- commands from the CLI ------------------------------------------------------------


def write_command(spool: Path, name: str, command: dict) -> Path:  # type: ignore[type-arg]
    spool.mkdir(exist_ok=True)
    path = spool / name
    path.write_text(json.dumps(command))
    os.chmod(path, 0o600)
    return path


def test_manual_ban_and_unban_through_the_spool(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    spool = tmp_path / "spool"
    write_command(spool, "1.json", {"op": "ban", "target": "198.51.100.0/24"})
    write_command(spool, "2.json", {"op": "ban", "target": "198.51.100.77", "ttl": 60})
    assert g.process_spool() == 2
    assert {b.target for b in g.book.active()} == {"198.51.100.0/24", "198.51.100.77"}
    assert list(spool.iterdir()) == []  # consumed
    write_command(spool, "3.json", {"op": "unban", "target": "198.51.100.0/24"})
    write_command(spool, "4.json", {"op": "unban", "target": "192.0.2.1"})
    g.process_spool()
    assert {b.target for b in g.book.active()} == {"198.51.100.77"}


def test_manual_ban_refuses_the_allowlist(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock, allowlist={"networks": ["10.0.0.0/8"]})
    for target in ("10.1.2.3", "10.0.0.0/8", "0.0.0.0/0"):
        g.apply_command({"op": "ban", "target": target})
    assert len(g.book) == 0


def test_bad_command_files_are_dropped_without_harm(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    spool = tmp_path / "spool"
    spool.mkdir()
    for name, text in {
        "a.json": "{nope",
        "b.json": '{"op": "reboot", "target": "1.2.3.4"}',
        "c.json": '{"op": "ban", "target": "1.2.3.4; id"}',
        "d.json": "[]",
    }.items():
        p = spool / name
        p.write_text(text)
        os.chmod(p, 0o600)
    g.process_spool()
    assert len(g.book) == 0
    assert list(spool.iterdir()) == []
    assert g.process_spool() == 0
    assert Guard.process_spool(build(tmp_path / "x", clock)) == 0  # no spool dir at all


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_command_files_writable_by_others_are_rejected(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock)
    p = write_command(tmp_path / "spool", "1.json", {"op": "ban", "target": "198.51.100.9"})
    os.chmod(p, 0o666)
    g.process_spool()
    assert len(g.book) == 0
    assert (tmp_path / "spool" / "1.rejected").exists()


def test_full_book_of_manual_bans_refuses_manual_too(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock, ban={"max_active": 1})
    g.apply_command({"op": "ban", "target": "198.51.100.1"})
    g.apply_command({"op": "ban", "target": "198.51.100.2"})
    assert [b.target for b in g.book.active()] == ["198.51.100.1"]


def test_eviction_when_the_book_is_full(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(tmp_path, clock, ban={"max_active": 2})
    for ip in ["203.0.113.1", "203.0.113.2", "203.0.113.3"]:
        for i in range(5):
            g.process_line(line(ip=ip, n=i))
        clock.advance(1)
    assert len(g.book) == 2
    assert g.counters["evicted"] == 1
    assert ("unban", "203.0.113.1") in g.backend.actions  # type: ignore[attr-defined]


# --- outputs --------------------------------------------------------------------------


def test_metrics_and_status_files(tmp_path, clock):  # type: ignore[no-untyped-def]
    g = build(
        tmp_path,
        clock,
        metrics={
            "file": str(tmp_path / "m.prom"),
            "status_file": str(tmp_path / "s.json"),
            "interval": 0,
        },
    )
    g.start()
    for i in range(5):
        g.process_line(line(n=i))
    g.tick()
    text = (tmp_path / "m.prom").read_text()
    assert "sshguard_up 1" in text
    assert 'sshguard_bans_total{reason="failures"} 1' in text
    assert 'sshguard_attempts_total{kind="failed_auth"} 5' in text
    assert "sshguard_active_bans 1" in text
    status = json.loads((tmp_path / "s.json").read_text())
    assert status["active_bans"] == 1 and status["bans"][0]["target"] == ATTACKER
    g.stop()
    assert "sshguard_up 0" in (tmp_path / "m.prom").read_text()


def test_unwritable_metrics_do_not_stop_the_guard(tmp_path, clock, caplog):  # type: ignore[no-untyped-def]
    blocker = tmp_path / "file"
    blocker.write_text("x")
    g = build(tmp_path, clock, metrics={"file": str(blocker / "m.prom"), "interval": 0})
    g.write_outputs(force=True)  # parent is a file: the write fails, the guard carries on


def test_unwritable_state_is_logged(tmp_path, clock):  # type: ignore[no-untyped-def]
    blocker = tmp_path / "file"
    blocker.write_text("x")
    g = build(tmp_path, clock, state={"path": str(blocker / "state.json")})
    for i in range(5):
        g.process_line(line(n=i))
    g.save(force=True)  # must not raise


def test_notifications_are_sent_on_ban_only_by_default(tmp_path, clock):  # type: ignore[no-untyped-def]
    cfg = make_config(
        notify={"webhook_url": "http://127.0.0.1:9/x", "on": ["ban"]},
        state={"path": str(tmp_path / "s.json"), "spool": str(tmp_path / "sp")},
    )
    notifier = Notifier(cfg.notify, "h")
    sent: list[dict] = []  # type: ignore[type-arg]
    notifier.deliver = sent.append  # type: ignore[method-assign]
    notifier._queue.put = lambda e: sent.append(e)  # type: ignore[method-assign,assignment]
    notifier._queue.put_nowait = lambda e: sent.append(e)  # type: ignore[method-assign,assignment]
    g = Guard(cfg, DryRunBackend(), notifier, clock=clock, host="h")
    for i in range(5):
        g.process_line(line(n=i))
    clock.advance(4000)
    g.tick()  # the unban is not in `on`
    assert [e["event"] for e in sent] == ["ban"]
    assert sent[0]["target"] == ATTACKER and sent[0]["host"] == "h"
