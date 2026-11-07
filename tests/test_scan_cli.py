from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path

import pytest

from sshguard.cli import main
from sshguard.config import from_dict
from sshguard.scan import format_report, scan_lines

A = "203.0.113.5"


def syslog(sec: int, ip: str = A, user: str = "root", kind: str = "fail") -> str:
    h, m, s = 10 + sec // 3600, sec // 60 % 60, sec % 60
    body = {
        "fail": f"Failed password for {user} from {ip} port 4000 ssh2",
        "ok": f"Accepted password for {user} from {ip} port 4000 ssh2",
    }[kind]
    return f"Nov  7 {h:02d}:{m:02d}:{s:02d} web01 sshd[1]: {body}"


def cfg(**kw):  # type: ignore[no-untyped-def]
    kw.setdefault("source", {"tz": "UTC"})
    return from_dict(kw)


def test_scan_finds_the_attacker_and_not_the_typo(  # type: ignore[no-untyped-def]
):
    lines = [syslog(i, A) for i in range(0, 10, 2)]
    lines += [syslog(100 + i, "192.0.2.10", "luca") for i in range(3)] + [
        syslog(110, "192.0.2.10", "luca", "ok")
    ]
    report = scan_lines(lines, cfg(), year=2026)
    assert report.banned_sources == {A}
    assert report.bans[0].reason == "failures"
    assert report.lines == 9 and report.parsed == 9
    assert report.failures_by_source["192.0.2.10"] == 3
    text = format_report(report)
    assert A in text and "would ban       1 source(s)" in text
    assert "192.0.2.10" in text  # listed among the sources that were not banned


def test_scan_models_expiry_and_recidive():
    lines = [syslog(i * 2, A) for i in range(5)]  # ban at +8 s for 1 h
    lines += [syslog(i, A) for i in range(4000, 4005)]  # after it expired: a second, longer ban
    report = scan_lines(lines, cfg(), year=2026)
    assert [b.strikes for b in report.bans] == [1, 2]
    assert report.bans[1].seconds == 4 * report.bans[0].seconds  # type: ignore[operator]


def test_scan_counts_what_it_skips():
    report = scan_lines(
        [syslog(i, A) for i in range(20)] + [syslog(0, "127.0.0.1")], cfg(), year=2026
    )
    assert report.ignored["already_banned"] == 15
    assert report.ignored["allowlist"] == 1
    assert "not counted" in format_report(report)


def test_report_without_bans():
    assert "would ban       0" in format_report(scan_lines([], cfg()))


def test_cli_scan(tmp_path, capsys):  # type: ignore[no-untyped-def]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(syslog(i * 2) for i in range(6)) + "\n")
    gz = tmp_path / "old.log.gz"
    with gzip.open(gz, "wt") as f:
        f.write("\n".join(syslog(i * 2, "198.51.100.9") for i in range(6)) + "\n")
    assert main(["scan", str(gz), str(log), "--year", "2026"]) == 0
    out = capsys.readouterr().out
    assert A in out and "198.51.100.9" in out
    assert main(["scan", str(log), "--year", "2026", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["bans"][0]["target"] == A


def test_cli_scan_stdin_and_missing_file(tmp_path, capsys, monkeypatch):  # type: ignore[no-untyped-def]
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(syslog(i) for i in range(6))))
    assert main(["scan", "-", "--year", "2026"]) == 0
    assert A in capsys.readouterr().out
    assert main(["scan", str(tmp_path / "nope.log")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_cli_check_config(tmp_path, capsys):  # type: ignore[no-untyped-def]
    assert main(["check-config"]) == 0
    assert "nothing is blocked" in capsys.readouterr().out
    bad = tmp_path / "c.toml"
    bad.write_text("[detect]\nmax_failurez = 1\n")
    assert main(["check-config", "-c", str(bad)]) == 2
    assert "did you mean" in capsys.readouterr().err


def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "c.toml"
    path.write_text(
        f'[state]\npath = "{(tmp_path / "state.json").as_posix()}"\nspool = "{(tmp_path / "spool").as_posix()}"\n'
    )
    return path


def test_cli_list_empty_and_with_bans(tmp_path, capsys):  # type: ignore[no-untyped-def]
    c = str(config_file(tmp_path))
    assert main(["list", "-c", c]) == 0
    assert "no bans" in capsys.readouterr().out
    assert main(["ban", "-c", c, "198.51.100.0/24", "--offline"]) == 0
    assert main(["ban", "-c", c, "203.0.113.9", "--ttl", "2h", "--offline"]) == 0
    capsys.readouterr()
    assert main(["list", "-c", c]) == 0
    out = capsys.readouterr().out
    assert "198.51.100.0/24" in out and "permanent" in out and "hand" in out
    assert main(["list", "-c", c, "--json"]) == 0
    assert {b["target"] for b in json.loads(capsys.readouterr().out)} == {
        "198.51.100.0/24",
        "203.0.113.9",
    }
    assert main(["unban", "-c", c, "203.0.113.9", "--offline", "--forgive"]) == 0
    assert main(["unban", "-c", c, "203.0.113.9", "--offline"]) == 0
    assert "was not banned" in capsys.readouterr().out
    main(["unban", "-c", c, "198.51.100.0/24", "--offline"])
    capsys.readouterr()
    assert main(["list", "-c", c]) == 0
    assert "no active bans" in capsys.readouterr().out


def test_cli_list_with_a_broken_state_file(tmp_path, capsys):  # type: ignore[no-untyped-def]
    c = str(config_file(tmp_path))
    (tmp_path / "state.json").write_text("{x")
    assert main(["list", "-c", c]) == 1
    assert "cannot read the state file" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_cli_ban_queues_a_private_command_file(tmp_path, capsys):  # type: ignore[no-untyped-def]
    c = str(config_file(tmp_path))
    assert main(["ban", "-c", c, "203.0.113.9", "--ttl", "1h"]) == 0
    assert "queued ban 203.0.113.9" in capsys.readouterr().out
    (f,) = (tmp_path / "spool").iterdir()
    assert oct(os.stat(f).st_mode & 0o777) == "0o600"
    assert oct(os.stat(tmp_path / "spool").st_mode & 0o777) == "0o700"
    assert json.loads(f.read_text()) == {"op": "ban", "target": "203.0.113.9", "ttl": 3600.0}
    assert main(["unban", "-c", c, "203.0.113.9"]) == 0
    assert len(list((tmp_path / "spool").iterdir())) == 2


def test_cli_rejects_bad_targets_and_ttl(tmp_path, capsys):  # type: ignore[no-untyped-def]
    c = str(config_file(tmp_path))
    assert main(["ban", "-c", c, "1.2.3.4; id"]) == 2
    assert main(["ban", "-c", c, "203.0.113.9", "--ttl", "soon"]) == 2
    assert not (tmp_path / "spool").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_cli_ban_with_an_unwritable_spool(tmp_path, capsys):  # type: ignore[no-untyped-def]
    c = tmp_path / "c.toml"
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    c.write_text(f'[state]\nspool = "{blocker.as_posix()}/spool"\n')
    assert main(["ban", "-c", str(c), "203.0.113.9"]) == 1
    assert "cannot write to the spool" in capsys.readouterr().err


def test_version_flag(capsys):  # type: ignore[no-untyped-def]
    from sshguard import __version__

    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership")
def test_cli_ban_as_root_hands_the_file_to_the_spool_owner(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    c = str(config_file(tmp_path))
    calls: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append((str(path), uid, gid)))
    assert main(["ban", "-c", c, "203.0.113.9"]) == 0
    owner = (tmp_path / "spool").stat()
    assert len(calls) == 1 and calls[0][1:] == (owner.st_uid, owner.st_gid)
