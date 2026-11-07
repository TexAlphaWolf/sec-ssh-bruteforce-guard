# Security notes

A tool that edits your firewall from text an attacker controls deserves a threat model.

## What the daemon trusts

- **The log.** Everything in a log line after the program name can be chosen by the client: the user name above all. So:
  - patterns are anchored at the **end** of the line (the part sshd writes itself); a name like `x from 9.9.9.9 port 1 ssh2` is stored as a name and the address that is banned is the real one (`test_user_name_cannot_frame_another_address`);
  - an address that does not parse is dropped, not guessed;
  - names never reach a shell, a firewall rule or a log unescaped: control characters become `\xNN`, length is capped.
- **The config file** (root-owned) and the **spool directory** (a command file is acted on only if owned by root or by the daemon's user and not writable by anyone else; otherwise it is renamed `.rejected`).

## What it does not do

- It **never uses a shell.** The only process it starts is `nft` (or your `command` templates, or `journalctl`), with an argv list. Every address passes `ipaddress` validation first; `test_ban_refuses_anything_that_is_not_an_address` throws `1.2.3.4; reboot`, `$(id)` and `1.2.3.4 } ; flush ruleset ; {` at it and checks that nothing reaches the firewall.
- It never touches rules outside its own table.
- It has no network listener.

## Denial of service against the guard itself

- Memory is bounded: `max_tracked` sources (least recently seen evicted), 2,048 events per source, 64 KiB per log line (longer lines are dropped), a 50,000-line queue with back-pressure, at most `max_active` bans.
- A flood of banned sources cannot grow the firewall without limit; see `max_active`.
- A burst of notifications cannot stall detection: the queue is bounded and sending runs in its own thread.

## Locking yourself out

The biggest risk is not an attacker, it is you. Mitigations: dry-run by default; the allowlist (loopback by default, add your own addresses); a manual ban that overlaps the allowlist is refused; bans have timeouts that the kernel enforces, so the worst case is waiting out the TTL or `nft delete table inet sshguard` from the console. **Keep a second way in** (console, VPN, a different port) when you first enable nftables.

## Privileges

- systemd: dedicated `sshguard` user, `CAP_NET_ADMIN` as the only (ambient and bounding) capability, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp/Devices`, kernel and cgroup protections, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, `NoNewPrivileges`, `UMask=0077`. CI starts the real unit on a runner and bans a simulated attacker through it.
- Docker: needs the host network namespace (the rules must land there), `cap_drop: ALL` + `NET_ADMIN`, read-only filesystem, `no-new-privileges`, logs mounted read-only. It runs as root inside the container because talking to netfilter requires it; the capability set is what limits it. Prefer the systemd unit when you can.

## Supply chain

No runtime dependencies (the only one is `tzdata`, on Windows). CI runs CodeQL; Dependabot watches pip, Actions and the Docker base image.

Report a problem: [SECURITY.md](../SECURITY.md).
