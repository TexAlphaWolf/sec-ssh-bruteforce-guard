from __future__ import annotations

import pytest

from sshguard.config import ConfigError, apply_env, from_dict, load, parse_duration


def test_defaults_are_safe():
    cfg = from_dict({})
    assert cfg.backend.kind == "dry-run"  # a fresh install can never lock anyone out
    assert cfg.source.time_source == "arrival"
    assert cfg.source.replay is False
    assert [str(n) for n in cfg.detect.allowlist] == ["127.0.0.0/8", "::1/128"]
    assert cfg.detect.max_failures == 5
    assert cfg.ban.ttl == 3600


def test_full_file(tmp_path):  # type: ignore[no-untyped-def]
    path = tmp_path / "c.toml"
    path.write_text(
        """
[detect]
max_failures = 3
window = "5m"
slow_window = "2d"
weights = { failed_auth = 2.0 }
[ban]
ttl = "30m"
multiplier = 2
max_ttl = "1d"
[allowlist]
networks = ["10.0.0.0/8", "192.168.1.5"]
[source]
kind = "journald"
[backend]
kind = "nftables"
ports = [22, 2222]
action = "reject"
[notify]
webhook_url = "https://example.org/hook"
on = ["ban", "unban"]
[state]
path = "/tmp/s.json"
[metrics]
file = "/tmp/m.prom"
[log]
format = "json"
level = "DEBUG"
"""
    )
    cfg = load(path)
    assert (cfg.detect.max_failures, cfg.detect.window, cfg.detect.slow_window) == (3, 300, 172800)
    assert cfg.detect.weights["failed_auth"] == 2.0
    assert cfg.detect.weights["preauth_drop"] == 0.5  # untouched keys keep their default
    assert (cfg.ban.ttl, cfg.ban.multiplier, cfg.ban.max_ttl) == (1800, 2, 86400)
    assert len(cfg.detect.allowlist) == 2
    assert (cfg.backend.kind, cfg.backend.ports, cfg.backend.action) == (
        "nftables",
        (22, 2222),
        "reject",
    )
    assert cfg.notify.enabled
    assert cfg.log.format == "json"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            {"detect": {"max_failurez": 3}},
            "detect.max_failurez: unknown key \\(did you mean 'max_failures'",
        ),
        ({"detec": {}}, "unknown section \\(did you mean \\[detect\\]"),
        ({"detect": {"max_failures": "five"}}, "expected a number"),
        ({"detect": {"max_failures": True}}, "expected a number"),
        ({"detect": {"max_failures": 0}}, "at least"),
        ({"detect": {"max_users": 1.5}}, "whole number"),
        ({"detect": {"ipv6_prefix": 200}}, "out of range"),
        ({"detect": {"window": "soon"}}, "expected seconds"),
        ({"detect": {"window": 100, "slow_window": 50}}, "must not be shorter"),
        ({"detect": {"window": 0}}, "greater than zero"),
        ({"detect": {"forgive_on_success": "yes"}}, "true or false"),
        ({"detect": {"weights": {"failed_auth": "x"}}}, "number"),
        ({"detect": {"weights": {"bogus": 1}}}, "unknown key"),
        ({"detect": "x"}, "must be a table"),
        ({"ban": {"ttl": 0}}, "greater than zero"),
        ({"allowlist": {"networks": ["nope"]}}, "allowlist.networks"),
        ({"allowlist": {"networks": "10.0.0.0/8"}}, "list of strings"),
        ({"source": {"kind": "kafka"}}, "must be one of"),
        ({"source": {"tz": "Mars/Base"}}, "unknown time zone"),
        ({"source": {"paths": []}}, "at least one file"),
        ({"backend": {"ports": [0]}}, "port numbers"),
        ({"backend": {"ports": "22"}}, "port numbers"),
        ({"backend": {"table": "bad name; x"}}, "backend.table"),
        ({"backend": {"kind": "command"}}, "ban_cmd"),
        ({"notify": {"webhook_url": "ftp://x"}}, "http"),
        ({"notify": {"on": ["explode"]}}, "unknown event"),
    ],
)
def test_mistakes_are_rejected_with_a_useful_message(data, message):  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match=message):
        from_dict(data)


def test_durations():
    assert parse_duration(90, "x") == 90
    assert parse_duration("1.5h", "x") == 5400
    assert parse_duration("2w", "x") == 1209600
    for bad in (-1, True, "1 hour", None):
        with pytest.raises(ConfigError):
            parse_duration(bad, "x")


def test_file_errors(tmp_path):  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError, match="not found"):
        load(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[detect\n")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load(bad)
    assert load(None).backend.kind == "dry-run"


def test_secret_comes_from_the_environment_and_is_not_printed(monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SSHGUARD_TELEGRAM_TOKEN", "123:secret")
    cfg = from_dict({"notify": {"telegram_chat_id": "42"}})
    assert cfg.notify.telegram_token == "123:secret"
    assert cfg.notify.enabled
    assert "secret" not in repr(cfg)


def test_backend_override_from_the_environment(monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SSHGUARD_BACKEND", "nftables")
    assert apply_env(from_dict({})).backend.kind == "nftables"
    monkeypatch.setenv("SSHGUARD_BACKEND", "iptables")
    with pytest.raises(ConfigError, match="unknown backend"):
        apply_env(from_dict({}))
    monkeypatch.delenv("SSHGUARD_BACKEND")
    assert apply_env(from_dict({})).backend.kind == "dry-run"
