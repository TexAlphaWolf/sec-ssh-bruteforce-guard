# Configuration

One TOML file; every key and its default is in [`deploy/config.example.toml`](../deploy/config.example.toml). `sshguard check-config -c FILE` validates it. Unknown sections and keys are **errors** with a "did you mean" hint, because a silently ignored `max_failurez = 3` would leave you less protected than you think.

## What counts as a failure

sshd writes several lines per attempt, and which ones appear depends on how the server is set up:

| Kind | Lines | Weight |
|---|---|---:|
| `failed_auth` | `Failed password/publickey/keyboard-interactive for [invalid user] X from IP` | 1.0 |
| `preauth_drop` | a client **that named a user** left before logging in: `Connection closed by authenticating/invalid user X`, `Disconnecting ...: Too many authentication failures`, `maximum authentication attempts exceeded` | 0.5 |
| `probe` | connect-and-leave without a user, or garbage: `Connection closed by IP [preauth]`, `Did not receive identification string`, `Unable to negotiate`, `Bad protocol version`, `banner exchange` | 0.2 |
| `invalid_user` | `Invalid user X from IP` | 0 (feeds the user-name count) |
| `accepted` | `Accepted ... for X from IP` | forgives X |

With password login on, one wrong guess is typically a `Failed password` line (1.0) and, if the client then leaves, a close line (0.5): about 1.5 per connection. With password login **off** (key only) bots produce only `Invalid user` plus a dropped connection, which is what the 0.5 is for.

`Disconnected from user root ...` (no `[preauth]`) is a normal logout and is never counted.

## Rules

A source is banned when, whichever comes first:

1. weighted failures inside `window` reach `max_failures` (default 5 in 10 minutes), or
2. `max_users` distinct names were tried inside `window` (default 10). With the default weights a source trying one name per attempt reaches rule 1 first; rule 2 matters if you raise `max_failures`, and for sources that only produce zero-weight `Invalid user` lines, or
3. weighted failures inside `slow_window` reach `slow_max_failures` (default 15 in 24 hours): the "one try every half hour" bot that never trips rule 1.

`forgive_on_success` (default on): when user X logs in from an address, X's earlier failures from that address are erased. Only X's. Someone who owns one account cannot erase the failures they left for `root`. This is what keeps thirty colleagues behind one NAT address from adding up each other's typos (measured: see the README).

IPv6 sources are grouped by `ipv6_prefix` (default /64) and the whole prefix is banned. IPv4-mapped addresses (`::ffff:1.2.3.4`) are treated as the IPv4 address.

## Bans

`ttl` (1 h) for the first ban; with `recidive`, strike *n* lasts `ttl x multiplier^(n-1)` (1 h, 4 h, 16 h, 64 h, ...) up to `max_ttl` (7 d). A quiet `strike_memory` (30 d) clears the record. `max_active` (10,000) is a safety valve: when full, the automatic ban that ends soonest is dropped to make room; manual bans are never dropped.

Bans are saved to `state.path` (atomic write, mode 0600) and **restored into the firewall at start**, in one nftables transaction (`flush set` + `add element`), so there is no gap. A corrupt state file stops the daemon instead of silently forgetting every ban.

## Clock

`time_source = "arrival"` (default) counts with the clock at the moment a line is read, so a wrong time zone in the log cannot break the windows. The daemon starts reading at the **end** of the file: history is not replayed. `time_source = "log"` with `replay = true` uses the log's own timestamps (syslog lines carry no year or zone: set `tz`); a ban that would already be over when it is computed is skipped, so replaying last week's log does not ban last week's attackers.

## Backends

- **dry-run** (default): logs the decision.
- **nftables**: creates `table inet <table>` with two interval sets (`blocked4`, `blocked6`, `flags interval,timeout`) and one input chain at priority -10 with a `counter drop` (or `reject`) rule on `ports` (`[]` = every port). Setup is idempotent: the chain is flushed and rebuilt, rules never stack. The table is sshguard's own; `nft delete table inet sshguard` removes everything.
- **command**: your argv templates (`{ip}`, `{ttl}`, `{family}`), run **without a shell**, for ipset/firewalld/anything else.

## Sources

`file` (several paths; follows by name, so rotation and `copytruncate` are handled, and a file that appears later is read from its start), `journald` (runs `journalctl --follow --output=json`; OpenSSH 9.8's `sshd-session` is recognised), `stdin` (pipe a log in; the daemon exits when the pipe closes).

## Notifications

A JSON webhook and/or Telegram, sent from a thread with a timeout; a failure is logged and counted (`sshguard_notifications_failed_total`) and never stops detection. The Telegram token comes from `SSHGUARD_TELEGRAM_TOKEN` (not the file) and is never logged. Messages are plain text, and attacker-controlled text is escaped.

## Metrics

`metrics.file` is Prometheus text, written atomically, for the node_exporter textfile collector (for example the one in [dc-monitoring-stack](https://github.com/TexAlphaWolf/dc-monitoring-stack)). Main series: `sshguard_active_bans`, `sshguard_bans_total{reason}`, `sshguard_attempts_total{kind}`, `sshguard_ignored_total{why}`, `sshguard_backend_errors_total`, `sshguard_unapplied_bans`, `sshguard_up`. Alert on `sshguard_up == 0` and on `sshguard_backend_errors_total` increasing. `status_file` holds the same as JSON plus the list of bans (the Docker health check reads it).
