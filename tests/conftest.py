from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from sshguard.backends import RunResult
from sshguard.config import Config, from_dict
from sshguard.events import FAILED_AUTH, Attempt


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@dataclass
class FakeRunner:
    """Stands in for the nft program: records calls, can be told to fail."""

    calls: list[tuple[tuple[str, ...], str | None]] = field(default_factory=list)
    fail_when: str = ""  # fail any call whose arguments contain this text
    stderr: str = "Error: boom"

    def __call__(self, argv: Sequence[str], stdin: str | None = None) -> RunResult:
        self.calls.append((tuple(argv), stdin))
        text = " ".join(argv) + (stdin or "")
        if self.fail_when and self.fail_when in text:
            return RunResult(1, "", self.stderr)
        return RunResult(0, "", "")


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


def make_config(**sections: dict) -> Config:  # type: ignore[type-arg]
    return from_dict(sections)


def fail(ip: str, ts: float, user: str | None = "root") -> Attempt:
    return Attempt(ts=ts, ip=ip, kind=FAILED_AUTH, user=user)
