"""Where a ban is enforced: nftables, any command, or nowhere (dry run)."""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from .net import family, normalize_target

log = logging.getLogger("sshguard.backend")


class BackendError(Exception):
    """The firewall refused or could not be reached. The message is fit for the log."""


class Backend(Protocol):
    name: str

    def setup(self) -> None: ...
    def ban(self, target: str, seconds: float | None) -> None: ...
    def unban(self, target: str) -> None: ...
    def sync(self, bans: Iterable[tuple[str, float | None]]) -> None: ...
    def teardown(self) -> None: ...


Runner = Callable[[Sequence[str], str | None], "RunResult"]


@dataclass(frozen=True, slots=True)
class RunResult:
    code: int
    out: str = ""
    err: str = ""


def run_process(argv: Sequence[str], stdin: str | None = None) -> RunResult:
    """Run a program without a shell. The only place sshguard starts a process."""
    try:
        done = subprocess.run(
            list(argv),
            input=stdin,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError as error:
        raise BackendError(f"{argv[0]}: not found") from error
    except subprocess.TimeoutExpired as error:
        raise BackendError(f"{argv[0]}: timed out") from error
    return RunResult(done.returncode, done.stdout, done.stderr)


# --- dry run ---------------------------------------------------------------------------


@dataclass
class DryRunBackend:
    """Logs what it would do. The default: a fresh install can never lock anyone out."""

    name: str = "dry-run"
    actions: list[tuple[str, str]] = field(default_factory=list)

    def setup(self) -> None:
        log.info("dry-run backend: nothing will be blocked")

    def ban(self, target: str, seconds: float | None) -> None:
        self.actions.append(("ban", target))
        log.warning("dry-run: would ban %s for %s", target, _fmt(seconds))

    def unban(self, target: str) -> None:
        self.actions.append(("unban", target))
        log.info("dry-run: would unban %s", target)

    def sync(self, bans: Iterable[tuple[str, float | None]]) -> None:
        for target, seconds in bans:
            log.info("dry-run: would restore the ban on %s (%s left)", target, _fmt(seconds))

    def teardown(self) -> None:
        pass


def _fmt(seconds: float | None) -> str:
    return "ever" if seconds is None else f"{int(seconds)}s"


def _already_gone(error: str) -> bool:
    """nft words "that element is not there" differently by version and by set type."""
    return "No such file or directory" in error or "element does not exist" in error


# --- nftables --------------------------------------------------------------------------


@dataclass
class NftBackend:
    """Two interval sets with timeouts (IPv4 and IPv6) and one drop rule in an input chain.

    The kernel removes an element when its timeout ends, so a ban expires even if sshguard is
    stopped. Everything lives in its own table: `nft delete table inet sshguard` removes it all.
    """

    table: str = "sshguard"
    ports: tuple[int, ...] = (22,)
    action: str = "drop"
    nft: str = "nft"
    priority: int = -10
    runner: Runner = run_process
    name: str = "nftables"

    def _ruleset(self) -> str:
        t = self.table
        ports = f"tcp dport {{ {', '.join(str(p) for p in self.ports)} }} " if self.ports else ""
        verdict = "reject with tcp reset" if self.action == "reject" else "drop"
        if self.action == "reject" and not self.ports:
            verdict = "reject"
        return "\n".join(
            [
                f"add table inet {t}",
                f"add set inet {t} blocked4 {{ type ipv4_addr; flags interval,timeout; }}",
                f"add set inet {t} blocked6 {{ type ipv6_addr; flags interval,timeout; }}",
                f"add chain inet {t} input {{ type filter hook input priority {self.priority}; "
                "policy accept; }",
                f"flush chain inet {t} input",
                f"add rule inet {t} input {ports}ip saddr @blocked4 counter {verdict}",
                f"add rule inet {t} input {ports}ip6 saddr @blocked6 counter {verdict}",
                "",
            ]
        )

    def _nft(self, *args: str, stdin: str | None = None) -> RunResult:
        return self.runner([self.nft, *args], stdin)

    def setup(self) -> None:
        result = self._nft("-f", "-", stdin=self._ruleset())
        if result.code != 0:
            raise BackendError(f"cannot create the nftables ruleset: {result.err.strip()}")
        log.info("nftables table inet %s ready (ports %s)", self.table, list(self.ports) or "all")

    def _set(self, target: str) -> str:
        return "blocked6" if family(target) == 6 else "blocked4"

    def ban(self, target: str, seconds: float | None) -> None:
        target = normalize_target(target)
        element = target if seconds is None else f"{target} timeout {max(1, int(seconds))}s"
        # Replace an existing element so a new, longer ban also extends the timeout.
        self._nft("delete", "element", "inet", self.table, self._set(target), f"{{ {target} }}")
        result = self._nft(
            "add", "element", "inet", self.table, self._set(target), f"{{ {element} }}"
        )
        if result.code != 0:
            raise BackendError(f"cannot ban {target}: {result.err.strip()}")

    def unban(self, target: str) -> None:
        target = normalize_target(target)
        result = self._nft(
            "delete", "element", "inet", self.table, self._set(target), f"{{ {target} }}"
        )
        if result.code != 0 and not _already_gone(result.err):
            raise BackendError(f"cannot unban {target}: {result.err.strip()}")

    def sync(self, bans: Iterable[tuple[str, float | None]]) -> None:
        """Make the sets hold exactly `bans`, in one transaction: no gap in the protection."""
        lines = [f"flush set inet {self.table} blocked4", f"flush set inet {self.table} blocked6"]
        for target, seconds in bans:
            target = normalize_target(target)
            element = target if seconds is None else f"{target} timeout {max(1, int(seconds))}s"
            lines.append(f"add element inet {self.table} {self._set(target)} {{ {element} }}")
        result = self._nft("-f", "-", stdin="\n".join(lines) + "\n")
        if result.code != 0:
            raise BackendError(f"cannot restore the bans: {result.err.strip()}")

    def teardown(self) -> None:
        pass  # bans keep protecting the machine while the daemon is stopped; they time out alone

    def remove_all(self) -> None:
        """Delete the whole table (used by `sshguard uninstall`-style cleanups and tests)."""
        self._nft("delete", "table", "inet", self.table)

    def listing(self) -> str:
        result = self._nft("list", "table", "inet", self.table)
        if result.code != 0:
            raise BackendError(result.err.strip())
        return result.out


# --- any command -----------------------------------------------------------------------


@dataclass
class CommandBackend:
    """Run your own argv templates, e.g. ipset or a firewall-cmd call. No shell is involved.

    Placeholders: `{ip}` (the validated address or network), `{ttl}` (seconds, 0 = permanent),
    `{family}` (4 or 6).
    """

    ban_cmd: Sequence[str] = ()
    unban_cmd: Sequence[str] = ()
    setup_cmd: Sequence[str] = ()
    runner: Runner = run_process
    name: str = "command"

    def _expand(self, template: Sequence[str], target: str, seconds: float | None) -> list[str]:
        values = {
            "{ip}": target,
            "{ttl}": str(0 if seconds is None else max(1, int(seconds))),
            "{family}": str(family(target)),
        }
        out = []
        for part in template:
            for key, value in values.items():
                part = part.replace(key, value)
            out.append(part)
        return out

    def setup(self) -> None:
        if self.setup_cmd:
            result = self.runner(list(self.setup_cmd), None)
            if result.code != 0:
                raise BackendError(f"setup command failed: {result.err.strip()}")

    def ban(self, target: str, seconds: float | None) -> None:
        target = normalize_target(target)
        result = self.runner(self._expand(self.ban_cmd, target, seconds), None)
        if result.code != 0:
            raise BackendError(f"ban command failed for {target}: {result.err.strip()}")

    def unban(self, target: str) -> None:
        if not self.unban_cmd:
            return
        target = normalize_target(target)
        result = self.runner(self._expand(self.unban_cmd, target, None), None)
        if result.code != 0:
            raise BackendError(f"unban command failed for {target}: {result.err.strip()}")

    def sync(self, bans: Iterable[tuple[str, float | None]]) -> None:
        for target, seconds in bans:
            self.ban(target, seconds)

    def teardown(self) -> None:
        pass
