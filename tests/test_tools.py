"""The simulator and the scorer are part of the project: the numbers in the docs come from them."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import attack_sim
import evaluate

from sshguard.config import load


@pytest.fixture(scope="module")
def sample(tmp_path_factory):  # type: ignore[no-untyped-def]
    d = tmp_path_factory.mktemp("sim")
    log, labels = d / "auth.log", d / "labels.json"
    assert attack_sim.main(["generate", "--out", str(log), "--labels", str(labels)]) == 0
    return log, labels


def test_generation_is_reproducible(sample, tmp_path):  # type: ignore[no-untyped-def]
    log, _ = sample
    again = tmp_path / "again.log"
    attack_sim.main(["generate", "--out", str(again)])
    assert again.read_text() == log.read_text()
    other = tmp_path / "other.log"
    attack_sim.main(["generate", "--out", str(other), "--seed", "8"])
    assert other.read_text() != log.read_text()


def test_only_documentation_addresses_are_used(sample):  # type: ignore[no-untyped-def]
    _, labels = sample
    for source in json.loads(labels.read_text()):
        assert source.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:"))


def test_every_attack_is_caught_and_no_honest_user_is_banned(sample):  # type: ignore[no-untyped-def]
    log, labels = sample
    data = json.loads(labels.read_text())
    health = [s for s, k in data.items() if k == "health_check"]
    config = load(None)
    result = evaluate.evaluate(str(log), data, config)
    assert result["attacks_banned"] == result["attack_sources"]
    # the one honest false positive: a load balancer hitting port 22 every minute
    assert result["legit_banned"] == health
    assert result["unexpected"] == []


def test_allowlisting_the_health_check_removes_the_false_positive(sample, capsys):  # type: ignore[no-untyped-def]
    log, labels = sample
    health = next(s for s, k in json.loads(labels.read_text()).items() if k == "health_check")
    evaluate.main([str(log), str(labels), "--allow", health])
    assert json.loads(capsys.readouterr().out)["legit_banned"] == []


def test_markdown_table(sample, capsys):  # type: ignore[no-untyped-def]
    log, labels = sample
    evaluate.main([str(log), str(labels), "--markdown"])
    out = capsys.readouterr().out
    assert out.startswith("| Source type") and "| brute_force | 30 | 30 |" in out


def test_live_mode_appends_lines(tmp_path):  # type: ignore[no-untyped-def]
    log = tmp_path / "live.log"
    assert attack_sim.main(["live", "--file", str(log), "--rate", "1000", "--count", "5"]) == 0
    from sshguard.parsers import parse_line

    lines = log.read_text().splitlines()
    assert len(lines) == 5
    assert all(parse_line(line) is not None for line in lines)
