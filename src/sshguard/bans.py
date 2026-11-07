"""The ban book: what is banned, until when, and how repeat offenders are treated."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STATE_VERSION = 1


@dataclass(slots=True)
class Ban:
    target: str  # an address, an IPv6 /N network, or a manually added network
    since: float
    until: float | None  # None: permanent
    reason: str
    strikes: int = 1
    score: float = 0.0
    manual: bool = False
    applied: bool = False  # is it in the firewall? False after a backend error: retried later

    def remaining(self, now: float) -> float | None:
        return None if self.until is None else max(0.0, self.until - now)


@dataclass(frozen=True, slots=True)
class BanPolicy:
    ttl: float = 3600.0
    recidive: bool = True
    multiplier: float = 4.0  # each new strike lasts this many times longer
    max_ttl: float = 7 * 86400.0
    strike_memory: float = 30 * 86400.0  # a quiet month clears the record
    max_active: int = 10_000


class BanBook:
    def __init__(self, policy: BanPolicy) -> None:
        self.policy = policy
        self._bans: dict[str, Ban] = {}
        self._strikes: dict[str, tuple[int, float]] = {}  # target -> (count, last ban time)

    def __len__(self) -> int:
        return len(self._bans)

    def get(self, target: str) -> Ban | None:
        return self._bans.get(target)

    def is_banned(self, target: str, now: float) -> bool:
        ban = self._bans.get(target)
        return ban is not None and (ban.until is None or ban.until > now)

    def active(self) -> list[Ban]:
        return sorted(self._bans.values(), key=lambda b: b.since)

    def ttl_for(self, strikes: int) -> float:
        p = self.policy
        if not p.recidive:
            return p.ttl
        return min(p.ttl * p.multiplier ** (strikes - 1), max(p.max_ttl, p.ttl))

    def ban(
        self,
        target: str,
        now: float,
        reason: str,
        *,
        score: float = 0.0,
        ttl: float | None = None,
        manual: bool = False,
    ) -> tuple[Ban | None, Ban | None]:
        """Ban `target`. Returns (new ban, ban evicted to make room).

        The new ban is None when the target is already banned (a manual ban replaces an
        automatic one) or when the book is full of manual bans.
        """
        existing = self._bans.get(target)
        if existing is not None and self.is_banned(target, now) and not manual:
            return None, None
        evicted = None
        if existing is None and len(self._bans) >= self.policy.max_active:
            evicted = self._evict()
            if evicted is None:
                return None, None
        count, _ = self._strikes.get(target, (0, now))
        strikes = count + 1
        if manual:
            seconds: float | None = ttl if ttl and ttl > 0 else None  # no ttl: permanent
        else:
            seconds = ttl if ttl is not None else self.ttl_for(strikes)
        ban = Ban(
            target=target,
            since=now,
            until=None if seconds is None else now + seconds,
            reason=reason,
            strikes=strikes,
            score=score,
            manual=manual,
        )
        self._bans[target] = ban
        self._strikes[target] = (strikes, now)
        return ban, evicted

    def _evict(self) -> Ban | None:
        """Make room: drop the automatic ban that would end soonest. Manual bans stay."""
        candidates = [b for b in self._bans.values() if not b.manual]
        if not candidates:
            return None
        victim = min(candidates, key=lambda b: b.until if b.until is not None else float("inf"))
        del self._bans[victim.target]
        return victim

    def unban(self, target: str, *, forgive: bool = False) -> Ban | None:
        if forgive:
            self._strikes.pop(target, None)
        return self._bans.pop(target, None)

    def expire(self, now: float) -> list[Ban]:
        gone = [b for b in self._bans.values() if b.until is not None and b.until <= now]
        for ban in gone:
            del self._bans[ban.target]
        horizon = now - self.policy.strike_memory
        for target in [t for t, (_, last) in self._strikes.items() if last < horizon]:
            if target not in self._bans:
                del self._strikes[target]
        return gone

    # --- persistence -------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "bans": [asdict(b) for b in self._bans.values()],
            "strikes": {t: [c, last] for t, (c, last) in self._strikes.items()},
        }

    def load_dict(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("the file does not hold a JSON object")
        if data.get("version") != STATE_VERSION:
            raise ValueError(f"unsupported state version: {data.get('version')!r}")
        self._bans.clear()
        self._strikes.clear()
        for raw in data.get("bans", []):
            ban = Ban(**raw)
            ban.applied = False  # whatever the firewall holds now is unknown until we sync
            self._bans[ban.target] = ban
        for target, (count, last) in data.get("strikes", {}).items():
            self._strikes[target] = (int(count), float(last))


def save_state(book: BanBook, path: Path) -> None:
    """Write the state atomically and readable by the owner only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(book.to_dict(), handle, indent=1)
            handle.flush()
            os.fsync(handle.fileno())
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def load_state(book: BanBook, path: Path) -> bool:
    """Load the state file. A missing file is a fresh start; a corrupt one is an error."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    try:
        book.load_dict(json.loads(text))
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise ValueError(f"{path}: cannot read the state file ({error})") from error
    return True
