"""Configuration: one TOML file, validated strictly. A typo is an error, not a silent default."""

from __future__ import annotations

import difflib
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .bans import BanPolicy
from .detector import DEFAULT_WEIGHTS, DetectConfig
from .net import parse_networks


class ConfigError(Exception):
    pass


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)\s*([smhdw])$")


def parse_duration(value: Any, where: str) -> float:
    """`600`, `"10m"`, `"1h"`, `"7d"` -> seconds."""
    if isinstance(value, bool):
        raise ConfigError(f"{where}: expected a duration, got {value!r}")
    if isinstance(value, int | float):
        if value < 0:
            raise ConfigError(f"{where}: must not be negative")
        return float(value)
    if isinstance(value, str) and (m := _DURATION.match(value.strip())):
        return float(m[1]) * _UNITS[m[2]]
    raise ConfigError(
        f'{where}: expected seconds or a string like "10m", "1h", "7d"; got {value!r}'
    )


class _Section:
    """Reads one table and complains about unknown keys and wrong types."""

    def __init__(self, name: str, data: Any) -> None:
        if not isinstance(data, dict):
            raise ConfigError(f"[{name}] must be a table")
        self.name = name
        self.data: dict[str, Any] = dict(data)
        self.known: set[str] = set()

    def _path(self, key: str) -> str:
        return f"{self.name}.{key}"

    def raw(self, key: str, default: Any) -> Any:
        self.known.add(key)
        return self.data.get(key, default)

    def number(self, key: str, default: float, *, minimum: float = 0) -> float:
        value = self.raw(key, default)
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigError(f"{self._path(key)}: expected a number, got {value!r}")
        if value < minimum:
            raise ConfigError(f"{self._path(key)}: must be at least {minimum}")
        return float(value)

    def integer(
        self, key: str, default: int, *, minimum: int = 0, maximum: int | None = None
    ) -> int:
        value = self.raw(key, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{self._path(key)}: expected a whole number, got {value!r}")
        if value < minimum or (maximum is not None and value > maximum):
            raise ConfigError(f"{self._path(key)}: out of range")
        return value

    def boolean(self, key: str, default: bool) -> bool:
        value = self.raw(key, default)
        if not isinstance(value, bool):
            raise ConfigError(f"{self._path(key)}: expected true or false, got {value!r}")
        return value

    def string(self, key: str, default: str, choices: tuple[str, ...] = ()) -> str:
        value = self.raw(key, default)
        if not isinstance(value, str):
            raise ConfigError(f"{self._path(key)}: expected a string, got {value!r}")
        if choices and value not in choices:
            raise ConfigError(f"{self._path(key)}: must be one of {', '.join(choices)}")
        return value

    def strings(self, key: str, default: list[str]) -> list[str]:
        value = self.raw(key, default)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{self._path(key)}: expected a list of strings, got {value!r}")
        return list(value)

    def duration(self, key: str, default: float) -> float:
        return parse_duration(self.raw(key, default), self._path(key))

    def finish(self) -> None:
        for key in self.data:
            if key not in self.known:
                hint = difflib.get_close_matches(key, sorted(self.known), n=1)
                extra = f" (did you mean {hint[0]!r}?)" if hint else ""
                raise ConfigError(f"{self._path(key)}: unknown key{extra}")


@dataclass(frozen=True)
class SourceConfig:
    kind: str = "file"  # file | journald | stdin
    paths: tuple[str, ...] = ("/var/log/auth.log",)
    replay: bool = False  # read existing content too, not only what arrives from now on
    time_source: str = "arrival"  # arrival | log
    tz: str = "local"
    identifiers: tuple[str, ...] = ("sshd", "sshd-session")  # for journald


@dataclass(frozen=True)
class BackendConfig:
    kind: str = "dry-run"  # dry-run | nftables | command
    table: str = "sshguard"
    ports: tuple[int, ...] = (22,)
    action: str = "drop"
    nft_path: str = "nft"
    ban_cmd: tuple[str, ...] = ()
    unban_cmd: tuple[str, ...] = ()
    setup_cmd: tuple[str, ...] = ()


@dataclass(frozen=True)
class NotifyConfig:
    webhook_url: str = ""
    telegram_token: str = field(default="", repr=False)
    telegram_chat_id: str = ""
    on: tuple[str, ...] = ("ban",)
    timeout: float = 5.0

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url or (self.telegram_token and self.telegram_chat_id))


@dataclass(frozen=True)
class StateConfig:
    path: str = "/var/lib/sshguard/state.json"
    spool: str = "/var/lib/sshguard/spool"
    save_interval: float = 30.0


@dataclass(frozen=True)
class MetricsConfig:
    file: str = ""
    status_file: str = ""
    interval: float = 15.0


@dataclass(frozen=True)
class LogConfig:
    level: str = "INFO"
    format: str = "text"


@dataclass(frozen=True)
class Config:
    detect: DetectConfig = field(default_factory=DetectConfig)
    ban: BanPolicy = field(default_factory=BanPolicy)
    source: SourceConfig = field(default_factory=SourceConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    state: StateConfig = field(default_factory=StateConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    log: LogConfig = field(default_factory=LogConfig)


def _detect(data: Any) -> DetectConfig:
    s = _Section("detect", data)
    weights_in = s.raw("weights", {})
    w = _Section("detect.weights", weights_in)
    weights = {kind: w.number(kind, default) for kind, default in DEFAULT_WEIGHTS.items()}
    w.finish()
    cfg = DetectConfig(
        max_failures=s.number("max_failures", 5.0, minimum=0.1),
        window=s.duration("window", 600.0),
        slow_max_failures=s.number("slow_max_failures", 15.0),
        slow_window=s.duration("slow_window", 86400.0),
        max_users=s.integer("max_users", 10),
        ipv6_prefix=s.integer("ipv6_prefix", 64, minimum=16, maximum=128),
        max_tracked=s.integer("max_tracked", 100_000, minimum=100),
        forgive_on_success=s.boolean("forgive_on_success", True),
        weights=weights,
    )
    s.finish()
    if cfg.window <= 0:
        raise ConfigError("detect.window: must be greater than zero")
    if cfg.slow_max_failures and cfg.slow_window < cfg.window:
        raise ConfigError("detect.slow_window: must not be shorter than detect.window")
    return cfg


def _allowlist(data: Any, detect: DetectConfig) -> DetectConfig:
    from dataclasses import replace

    s = _Section("allowlist", data)
    values = s.strings("networks", ["127.0.0.0/8", "::1/128"])
    s.finish()
    try:
        networks = parse_networks(values)
    except ValueError as error:
        raise ConfigError(f"allowlist.networks: {error}") from error
    return replace(detect, allowlist=networks)


def _ban(data: Any) -> BanPolicy:
    s = _Section("ban", data)
    policy = BanPolicy(
        ttl=s.duration("ttl", 3600.0),
        recidive=s.boolean("recidive", True),
        multiplier=s.number("multiplier", 4.0, minimum=1),
        max_ttl=s.duration("max_ttl", 7 * 86400.0),
        strike_memory=s.duration("strike_memory", 30 * 86400.0),
        max_active=s.integer("max_active", 10_000, minimum=1),
    )
    s.finish()
    if policy.ttl <= 0:
        raise ConfigError("ban.ttl: must be greater than zero")
    return policy


def _source(data: Any) -> SourceConfig:
    s = _Section("source", data)
    d = SourceConfig()
    cfg = SourceConfig(
        kind=s.string("kind", d.kind, ("file", "journald", "stdin")),
        paths=tuple(s.strings("paths", list(d.paths))),
        replay=s.boolean("replay", d.replay),
        time_source=s.string("time_source", d.time_source, ("arrival", "log")),
        tz=s.string("tz", d.tz),
        identifiers=tuple(s.strings("identifiers", list(d.identifiers))),
    )
    s.finish()
    if cfg.tz.lower() != "local":
        try:
            ZoneInfo(cfg.tz)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ConfigError(f"source.tz: unknown time zone {cfg.tz!r}") from error
    if cfg.kind == "file" and not cfg.paths:
        raise ConfigError("source.paths: needs at least one file when kind = 'file'")
    return cfg


def _backend(data: Any) -> BackendConfig:
    s = _Section("backend", data)
    d = BackendConfig()
    ports = s.raw("ports", list(d.ports))
    if not isinstance(ports, list) or not all(
        isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in ports
    ):
        raise ConfigError("backend.ports: expected a list of port numbers (1-65535)")
    cfg = BackendConfig(
        kind=s.string("kind", d.kind, ("dry-run", "nftables", "command")),
        table=s.string("table", d.table),
        ports=tuple(ports),
        action=s.string("action", d.action, ("drop", "reject")),
        nft_path=s.string("nft_path", d.nft_path),
        ban_cmd=tuple(s.strings("ban_cmd", [])),
        unban_cmd=tuple(s.strings("unban_cmd", [])),
        setup_cmd=tuple(s.strings("setup_cmd", [])),
    )
    s.finish()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", cfg.table):
        raise ConfigError("backend.table: use letters, digits and underscores (max 32)")
    if cfg.kind == "command" and not cfg.ban_cmd:
        raise ConfigError("backend.ban_cmd: required when kind = 'command'")
    return cfg


def _notify(data: Any) -> NotifyConfig:
    s = _Section("notify", data)
    cfg = NotifyConfig(
        webhook_url=s.string("webhook_url", ""),
        telegram_token=os.environ.get("SSHGUARD_TELEGRAM_TOKEN") or s.string("telegram_token", ""),
        telegram_chat_id=s.string("telegram_chat_id", ""),
        on=tuple(s.strings("on", ["ban"])),
        timeout=s.number("timeout", 5.0, minimum=0.5),
    )
    s.known.add("telegram_token")
    s.finish()
    if cfg.webhook_url and not cfg.webhook_url.startswith(("http://", "https://")):
        raise ConfigError("notify.webhook_url: must start with http:// or https://")
    for event in cfg.on:
        if event not in ("ban", "unban", "start"):
            raise ConfigError(f"notify.on: unknown event {event!r} (ban, unban, start)")
    return cfg


def _state(data: Any) -> StateConfig:
    s = _Section("state", data)
    d = StateConfig()
    cfg = StateConfig(
        path=s.string("path", d.path),
        spool=s.string("spool", d.spool),
        save_interval=s.duration("save_interval", d.save_interval),
    )
    s.finish()
    return cfg


def _metrics(data: Any) -> MetricsConfig:
    s = _Section("metrics", data)
    d = MetricsConfig()
    cfg = MetricsConfig(
        file=s.string("file", d.file),
        status_file=s.string("status_file", d.status_file),
        interval=s.duration("interval", d.interval),
    )
    s.finish()
    return cfg


def _log(data: Any) -> LogConfig:
    s = _Section("log", data)
    cfg = LogConfig(
        level=s.string("level", "INFO", ("DEBUG", "INFO", "WARNING", "ERROR")),
        format=s.string("format", "text", ("text", "json")),
    )
    s.finish()
    return cfg


def from_dict(data: dict[str, Any]) -> Config:
    top = set(data)
    sections = {
        "detect",
        "ban",
        "allowlist",
        "source",
        "backend",
        "notify",
        "state",
        "metrics",
        "log",
    }
    for key in sorted(top - sections):
        hint = difflib.get_close_matches(key, sorted(sections), n=1)
        extra = f" (did you mean [{hint[0]}]?)" if hint else ""
        raise ConfigError(f"[{key}]: unknown section{extra}")
    detect = _allowlist(data.get("allowlist", {}), _detect(data.get("detect", {})))
    return Config(
        detect=detect,
        ban=_ban(data.get("ban", {})),
        source=_source(data.get("source", {})),
        backend=_backend(data.get("backend", {})),
        notify=_notify(data.get("notify", {})),
        state=_state(data.get("state", {})),
        metrics=_metrics(data.get("metrics", {})),
        log=_log(data.get("log", {})),
    )


def load(path: str | Path | None) -> Config:
    """Load a config file; with no path, the defaults (which are safe: dry-run)."""
    if path is None:
        return from_dict({})
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as error:
        raise ConfigError(f"{path}: file not found") from error
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path}: not valid TOML ({error})") from error
    cfg = from_dict(data)
    return cfg


def apply_env(cfg: Config) -> Config:
    """SSHGUARD_BACKEND switches the backend without editing the file (used by the compose file)."""
    from dataclasses import replace

    kind = os.environ.get("SSHGUARD_BACKEND")
    if kind:
        if kind not in ("dry-run", "nftables", "command"):
            raise ConfigError(f"SSHGUARD_BACKEND: unknown backend {kind!r}")
        return replace(cfg, backend=replace(cfg.backend, kind=kind))
    return cfg
