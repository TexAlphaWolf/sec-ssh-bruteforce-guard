# Limitations

Said plainly, so you can decide whether this is enough.

- **It is reactive.** It bans after the failures. Strong authentication (keys only, no root login, `MaxAuthTries`) is worth more than any banning tool; this removes the noise and the guessing against the weak accounts you forgot.
- **A distributed attack gets through.** A botnet that tries a few passwords per address, from thousands of addresses, never trips a per-source threshold. Nothing that counts per address can stop it.
- **IPv6 granularity is a guess.** /64 is the usual unit, but a provider may hand out /56 or /48 and an attacker may use several /64s. Tune `ipv6_prefix`; the cost of a coarser prefix is banning neighbours.
- **Shared addresses.** Carrier-grade NAT can put an attacker and honest users behind one address. `forgive_on_success` helps with honest typos but not with a real attacker sharing your NAT.
- **Legitimate probes look like attacks.** A health check that opens port 22 and closes it is a probe flood by definition (measured in the README). Allowlist it.
- **It trusts sshd's wording.** The patterns follow the messages of recent OpenSSH releases (8 to 9, including the 9.8 `sshd-session` split). A different sshd (Dropbear, a patched build) logs different lines and will need new patterns; unmatched lines are ignored, never guessed.
- **No log, no ban.** It only sees what sshd logs at `LogLevel INFO` or above. `LogLevel QUIET` blinds it.
- **Only SSH.** The detector is about sshd lines; it is not a general web or mail guard.
- **The window is per daemon.** State is one JSON file on one machine; there is no sharing of bans between servers.
- **Not tested on real hardware here.** CI exercises the kernel firewall on a GitHub runner and the hardened unit on a runner VM, which is strong evidence but not your server: enable nftables only after reading the dry-run log for a day.
- **The numbers are synthetic.** The 75/75 and 0 false positives are measured on a generated day designed to include the awkward cases; real traffic always has surprises. `sshguard scan` on your own logs is the real test.
