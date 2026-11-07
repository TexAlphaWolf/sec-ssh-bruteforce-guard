"""Per-source failure counting: a fast window, a slow window and a user-spraying check."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field

from .events import ACCEPTED, FAILED_AUTH, INVALID_USER, PREAUTH_DROP, PROBE, Attempt
from .net import IP, Network, group_key, in_networks, parse_ip

DEFAULT_WEIGHTS: Mapping[str, float] = {
    FAILED_AUTH: 1.0,
    INVALID_USER: 0.0,
    PREAUTH_DROP: 0.5,
    PROBE: 0.2,
}

REASON_FAST = "failures"
REASON_SLOW = "slow"
REASON_SPRAY = "spray"


@dataclass(frozen=True, slots=True)
class DetectConfig:
    max_failures: float = 5.0  # weighted failures inside `window`
    window: float = 600.0
    slow_max_failures: float = 15.0  # the same, over a longer window: catches "low and slow"
    slow_window: float = 86400.0
    max_users: int = 10  # distinct user names inside `window`; 0 turns the check off
    ipv6_prefix: int = 64
    max_tracked: int = 100_000  # memory bound: sources tracked at once
    forgive_on_success: bool = True  # a login clears that user's failures from that source
    weights: Mapping[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    allowlist: tuple[Network, ...] = ()


@dataclass(frozen=True, slots=True)
class Verdict:
    target: str
    reason: str
    score: float
    users: int


class _State:
    __slots__ = ("events", "last")

    def __init__(self) -> None:
        # (timestamp, weight, user, counts toward the user-name check). Bounded in size.
        self.events: deque[tuple[float, float, str | None, bool]] = deque(maxlen=2048)
        self.last = 0.0


class Detector:
    def __init__(self, config: DetectConfig) -> None:
        self.config = config
        self._states: OrderedDict[str, _State] = OrderedDict()
        self.evicted = 0

    def __len__(self) -> int:
        return len(self._states)

    def is_allowed(self, ip: IP) -> bool:
        return in_networks(ip, self.config.allowlist)

    def forget(self, target: str) -> None:
        self._states.pop(target, None)

    def _forgive(self, key: str, user: str) -> None:
        """A successful login proves that user's earlier failures were a typo, not an attack.

        Only that user's failures go. An attacker who owns one account can wipe the failures it
        left for that account and nothing else.
        """
        state = self._states.get(key)
        if state is None:
            return
        kept = [e for e in state.events if e[2] != user]
        if len(kept) != len(state.events):
            state.events = deque(kept, maxlen=state.events.maxlen)

    def sweep(self, now: float) -> int:
        """Drop sources that have been quiet for longer than the slowest window."""
        horizon = now - max(self.config.slow_window, self.config.window)
        stale = [k for k, s in self._states.items() if s.last < horizon]
        for key in stale:
            del self._states[key]
        return len(stale)

    def observe(self, attempt: Attempt, ts: float | None = None) -> Verdict | None:
        """Feed one attempt. Returns a Verdict when its source has crossed a threshold."""
        cfg = self.config
        ip = parse_ip(attempt.ip)
        if ip is None or self.is_allowed(ip):
            return None
        key = group_key(ip, cfg.ipv6_prefix)
        if attempt.kind == ACCEPTED:
            if cfg.forgive_on_success and attempt.user is not None:
                self._forgive(key, attempt.user)
            return None
        weight = cfg.weights.get(attempt.kind, 0.0)
        counts_as_user = attempt.user is not None and attempt.kind in (INVALID_USER, FAILED_AUTH)
        if weight <= 0 and not counts_as_user:
            return None

        now = attempt.ts if ts is None else ts
        state = self._states.get(key)
        if state is None:
            state = self._states[key] = _State()
            while len(self._states) > cfg.max_tracked:
                self._states.popitem(last=False)  # the least recently seen source
                self.evicted += 1
        else:
            self._states.move_to_end(key)
        state.last = max(state.last, now)
        state.events.append((now, weight, attempt.user, counts_as_user))

        slow_cutoff = now - cfg.slow_window
        while state.events and state.events[0][0] < slow_cutoff:
            state.events.popleft()

        fast_cutoff = now - cfg.window
        fast = 0.0
        slow = 0.0
        users: set[str] = set()
        for t, w, user, spray in state.events:
            if t > now:
                continue  # an event from the "future" (files read out of order): ignore it
            slow += w
            if t >= fast_cutoff:
                fast += w
                if spray and user is not None:
                    users.add(user)

        if fast >= cfg.max_failures:
            return Verdict(key, REASON_FAST, fast, len(users))
        if cfg.max_users and len(users) >= cfg.max_users:
            return Verdict(key, REASON_SPRAY, fast, len(users))
        if cfg.slow_max_failures and slow >= cfg.slow_max_failures:
            return Verdict(key, REASON_SLOW, slow, len(users))
        return None


__all__ = [
    "DEFAULT_WEIGHTS",
    "REASON_FAST",
    "REASON_SLOW",
    "REASON_SPRAY",
    "DetectConfig",
    "Detector",
    "Verdict",
]
