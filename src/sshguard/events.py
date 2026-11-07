"""The one thing the parsers produce and the detector consumes."""

from __future__ import annotations

from dataclasses import dataclass

FAILED_AUTH = "failed_auth"  # a credential was tried and refused
INVALID_USER = "invalid_user"  # the account does not exist (informative: feeds the user count)
PREAUTH_DROP = "preauth_drop"  # a client that named a user left, or was dropped, before logging in
PROBE = "probe"  # connected and left, or spoke nonsense, without trying to log in
ACCEPTED = "accepted"  # a successful login

KINDS = (FAILED_AUTH, INVALID_USER, PREAUTH_DROP, PROBE, ACCEPTED)


@dataclass(frozen=True, slots=True)
class Attempt:
    ts: float  # seconds since the epoch, UTC
    ip: str  # canonical text form of the source address
    kind: str
    user: str | None = None  # attacker-controlled: never trust it, never log it raw
    invalid_user: bool = False
