"""Address handling. Every address that reaches a firewall or a subprocess passes through here."""

from __future__ import annotations

import ipaddress

IP = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ip(value: str) -> IP | None:
    """Parse an address as sshd prints it. Returns None for anything that is not one."""
    text = value.strip().strip("[]")
    text = text.split("%", 1)[0]  # fe80::1%eth0
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped  # ::ffff:192.0.2.1 is the IPv4 host 192.0.2.1
    return ip


def group_key(ip: IP, ipv6_prefix: int) -> str:
    """What gets counted and banned: the address for IPv4, the /N network for IPv6.

    An IPv6 attacker usually owns a whole /64 and can rotate addresses inside it for free, so
    counting single addresses would make the guard useless against them.
    """
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ip)
    return str(ipaddress.ip_network((ip, ipv6_prefix), strict=False))


def normalize_target(value: str) -> str:
    """Canonical form of an address or a network, or ValueError. Host bits must be zero."""
    text = value.strip()
    if "/" in text:
        return str(ipaddress.ip_network(text, strict=True))
    ip = parse_ip(text)
    if ip is None:
        raise ValueError(f"not an IP address or network: {value!r}")
    return str(ip)


def family(target: str) -> int:
    return 6 if ":" in target else 4


def parse_networks(values: list[str]) -> tuple[Network, ...]:
    return tuple(ipaddress.ip_network(v, strict=False) for v in values)


def in_networks(ip: IP, networks: tuple[Network, ...]) -> bool:
    return any(ip.version == n.version and ip in n for n in networks)


def printable(text: str | None, limit: int = 40) -> str:
    """Make attacker-controlled text safe for logs and chat messages."""
    if text is None:
        return "-"
    cleaned = "".join(c if c.isprintable() and c not in "\\" else f"\\x{ord(c):02x}" for c in text)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"
