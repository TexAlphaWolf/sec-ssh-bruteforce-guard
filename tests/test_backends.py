from __future__ import annotations

import logging
import sys

import pytest

from conftest import FakeRunner
from sshguard.backends import (
    BackendError,
    CommandBackend,
    DryRunBackend,
    NftBackend,
    RunResult,
    run_process,
)


def nft(runner: FakeRunner, **kw):  # type: ignore[no-untyped-def]
    return NftBackend(runner=runner, **kw)


def test_ruleset_is_one_transaction_with_the_expected_pieces(runner):  # type: ignore[no-untyped-def]
    nft(runner, ports=(22, 2222)).setup()
    ((argv, script),) = runner.calls
    assert argv == ("nft", "-f", "-")
    assert script is not None
    assert "add table inet sshguard" in script
    assert "flags interval,timeout" in script
    assert "hook input priority -10" in script
    assert "tcp dport { 22, 2222 } ip saddr @blocked4 counter drop" in script
    assert "tcp dport { 22, 2222 } ip6 saddr @blocked6 counter drop" in script
    assert script.index("flush chain") < script.index("add rule")  # re-running does not stack rules


def test_all_ports_and_reject(runner):  # type: ignore[no-untyped-def]
    nft(runner, ports=(), action="reject").setup()
    script = runner.calls[0][1]
    assert script is not None
    assert "dport" not in script
    assert "ip saddr @blocked4 counter reject" in script
    runner.calls.clear()
    nft(runner, ports=(22,), action="reject").setup()
    assert "reject with tcp reset" in (runner.calls[0][1] or "")


def test_setup_failure(runner):  # type: ignore[no-untyped-def]
    runner.fail_when = "-f"
    with pytest.raises(BackendError, match="cannot create"):
        nft(runner).setup()


def test_ban_uses_the_right_set_and_timeout(runner):  # type: ignore[no-untyped-def]
    b = nft(runner)
    b.ban("203.0.113.5", 3600)
    b.ban("2001:db8::/64", None)
    b.ban("203.0.113.6", 0.2)
    adds = [c[0] for c in runner.calls if c[0][1] == "add"]
    assert adds[0] == (
        "nft",
        "add",
        "element",
        "inet",
        "sshguard",
        "blocked4",
        "{ 203.0.113.5 timeout 3600s }",
    )
    assert adds[1][5:] == ("blocked6", "{ 2001:db8::/64 }")
    assert adds[2][-1] == "{ 203.0.113.6 timeout 1s }"  # never 0: that would mean "no timeout"


def test_ban_replaces_an_existing_element(runner):  # type: ignore[no-untyped-def]
    nft(runner).ban("203.0.113.5", 60)
    assert [c[0][1] for c in runner.calls] == ["delete", "add"]


def test_ban_refuses_anything_that_is_not_an_address(runner):  # type: ignore[no-untyped-def]
    b = nft(runner)
    for bad in [
        "1.2.3.4; reboot",
        "$(id)",
        "1.2.3.4 } ; flush ruleset ; {",
        "evil.example",
        "1.2.3.4/33",
    ]:
        with pytest.raises(
            ValueError, match=r"not an IP|does not appear|has host bits|Invalid|netmask"
        ):
            b.ban(bad, 10)
    assert runner.calls == []  # nothing reached the firewall


def test_ban_failure(runner):  # type: ignore[no-untyped-def]
    runner.fail_when = "add element"
    with pytest.raises(BackendError, match=r"cannot ban 203\.0\.113\.5: Error: boom"):
        nft(runner).ban("203.0.113.5", 60)


def test_unban_is_idempotent(runner):  # type: ignore[no-untyped-def]
    runner.fail_when = "delete element"
    runner.stderr = "Error: Could not process rule: No such file or directory"
    nft(runner).unban("203.0.113.5")  # already gone: fine
    runner.stderr = "Error: element does not exist\ndelete element inet t blocked4 { 1.2.3.4 }"
    nft(runner).unban("203.0.113.5")  # the wording of an interval set (seen on nft 1.0.9)
    runner.stderr = "Error: Operation not permitted"
    with pytest.raises(BackendError, match="cannot unban"):
        nft(runner).unban("203.0.113.5")


def test_sync_is_atomic_and_replaces_everything(runner):  # type: ignore[no-untyped-def]
    nft(runner).sync([("203.0.113.5", 100), ("2001:db8::/64", None)])
    ((argv, script),) = runner.calls
    assert argv == ("nft", "-f", "-")
    assert script is not None
    lines = script.strip().splitlines()
    assert lines[0].startswith("flush set") and lines[1].startswith("flush set")
    assert "add element inet sshguard blocked4 { 203.0.113.5 timeout 100s }" in lines
    assert "add element inet sshguard blocked6 { 2001:db8::/64 }" in lines
    runner.fail_when = "flush"
    with pytest.raises(BackendError, match="cannot restore"):
        nft(runner).sync([])


def test_listing_and_remove_all(runner):  # type: ignore[no-untyped-def]
    b = nft(runner)
    assert b.listing() == ""
    b.remove_all()
    assert runner.calls[-1][0] == ("nft", "delete", "table", "inet", "sshguard")
    runner.fail_when = "list"
    with pytest.raises(BackendError):
        b.listing()


def test_command_backend_expands_placeholders_without_a_shell(runner):  # type: ignore[no-untyped-def]
    b = CommandBackend(
        ban_cmd=["ipset", "add", "ssh{family}", "{ip}", "timeout", "{ttl}"],
        unban_cmd=["ipset", "del", "ssh{family}", "{ip}"],
        setup_cmd=["ipset", "create", "ssh4", "hash:net", "timeout", "0"],
        runner=runner,
    )
    b.setup()
    b.ban("203.0.113.5", 90)
    b.ban("2001:db8::/64", None)
    b.unban("203.0.113.5")
    assert [c[0] for c in runner.calls] == [
        ("ipset", "create", "ssh4", "hash:net", "timeout", "0"),
        ("ipset", "add", "ssh4", "203.0.113.5", "timeout", "90"),
        ("ipset", "add", "ssh6", "2001:db8::/64", "timeout", "0"),
        ("ipset", "del", "ssh4", "203.0.113.5"),
    ]


def test_command_backend_validates_and_reports_failures(runner):  # type: ignore[no-untyped-def]
    b = CommandBackend(
        ban_cmd=["x", "{ip}"], unban_cmd=["y", "{ip}"], setup_cmd=["z"], runner=runner
    )
    with pytest.raises(ValueError):
        b.ban("1.2.3.4; id", 5)
    runner.fail_when = "x"
    with pytest.raises(BackendError, match="ban command failed"):
        b.ban("203.0.113.5", 5)
    runner.fail_when = "y"
    with pytest.raises(BackendError, match="unban command failed"):
        b.unban("203.0.113.5")
    runner.fail_when = "z"
    with pytest.raises(BackendError, match="setup command failed"):
        b.setup()
    b.sync([])  # nothing to do
    b.teardown()
    CommandBackend(ban_cmd=["x"], runner=runner).unban("203.0.113.5")  # no unban_cmd: a no-op


def test_dry_run_only_logs(caplog):  # type: ignore[no-untyped-def]
    b = DryRunBackend()
    with caplog.at_level(logging.INFO, logger="sshguard.backend"):
        b.setup()
        b.ban("203.0.113.5", 60)
        b.unban("203.0.113.5")
        b.sync([("203.0.113.6", None)])
        b.teardown()
    assert b.actions == [("ban", "203.0.113.5"), ("unban", "203.0.113.5")]
    assert "would ban 203.0.113.5" in caplog.text


def test_run_process_reports_missing_programs_and_timeouts(monkeypatch):  # type: ignore[no-untyped-def]
    with pytest.raises(BackendError, match="not found"):
        run_process(["definitely-not-a-program-sshguard"])
    result = run_process(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"], "hi"
    )
    assert result == RunResult(0, "hi", "")
    import subprocess

    def slow(*a, **k):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired("x", 1)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(BackendError, match="timed out"):
        run_process(["x"])
