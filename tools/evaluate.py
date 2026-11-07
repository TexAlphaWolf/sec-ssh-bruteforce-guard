#!/usr/bin/env python3
"""Score the guard on a labelled log: who was banned, who should not have been, how fast.

python tools/attack_sim.py generate --out /tmp/auth.log --labels /tmp/labels.json
python tools/evaluate.py /tmp/auth.log /tmp/labels.json [-c config.toml] [--markdown]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean

from sshguard.config import Config, load
from sshguard.detector import DetectConfig
from sshguard.net import group_key, parse_ip
from sshguard.parsers import parse_line
from sshguard.scan import BanRecord, ScanReport, scan_files

ATTACKS = {
    "brute_force",
    "spraying",
    "low_and_slow",
    "ipv6_rotation",
    "key_only_probe",
    "probe_flood",
}
LEGIT = {"typo", "forgetful", "automation", "office_nat", "health_check"}


def evaluate(log: str, labels: dict[str, str], config: Config) -> dict[str, object]:
    report: ScanReport = scan_files([log], config, year=2026)
    banned: dict[str, BanRecord] = {}
    for record in report.bans:
        banned.setdefault(record.target, record)  # the first ban of each source
    first_ban_time = {t: b.ts for t, b in banned.items()}

    # How many hostile events from each source were let through before its first ban?
    through: dict[str, int] = defaultdict(int)
    with open(log, encoding="utf-8") as handle:
        for line in handle:
            a = parse_line(line, tz=config.source.tz, year=2026)
            if a is None or a.kind in ("accepted", "invalid_user"):
                continue
            ip = parse_ip(a.ip)
            if ip is None:
                continue
            key = group_key(ip, config.detect.ipv6_prefix)
            if key in first_ban_time and a.ts <= first_ban_time[key]:
                through[key] += 1

    rows: dict[str, dict[str, object]] = {}
    for kind in sorted(set(labels.values())):
        sources = [s for s, k in labels.items() if k == kind]
        hit = [s for s in sources if s in banned]
        row: dict[str, object] = {"sources": len(sources), "banned": len(hit)}
        if kind in ATTACKS and hit:
            row["events_before_ban"] = round(mean(through[s] for s in hit), 1)
        rows[kind] = row
    attacks = [s for s, k in labels.items() if k in ATTACKS]
    legit = [s for s, k in labels.items() if k in LEGIT]
    return {
        "lines": report.lines,
        "events": report.parsed,
        "by_kind": rows,
        "attack_sources": len(attacks),
        "attacks_banned": sum(1 for s in attacks if s in banned),
        "legit_sources": len(legit),
        "legit_banned": sorted(s for s in legit if s in banned),
        "unexpected": sorted(s for s in banned if s not in labels),
    }


def markdown(result: dict[str, object]) -> str:
    rows = result["by_kind"]
    assert isinstance(rows, dict)
    out = [
        "| Source type | Sources | Banned | Events let through before the ban |",
        "|---|---:|---:|---:|",
    ]
    for kind, row in rows.items():
        before = row.get("events_before_ban", "-")
        out.append(f"| {kind} | {row['sources']} | {row['banned']} | {before} |")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log")
    parser.add_argument("labels")
    parser.add_argument("-c", "--config")
    parser.add_argument("--allow", action="append", default=[], help="extra allowlisted address")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args(argv)
    config = load(args.config)
    if args.allow:
        from dataclasses import replace

        from sshguard.net import parse_networks

        detect: DetectConfig = replace(
            config.detect, allowlist=config.detect.allowlist + parse_networks(args.allow)
        )
        config = replace(config, detect=detect)
    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    result = evaluate(args.log, labels, config)
    if args.markdown:
        print(markdown(result))
    else:
        print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
