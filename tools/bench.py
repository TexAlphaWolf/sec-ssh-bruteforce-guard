#!/usr/bin/env python3
"""How many log lines per second does the parser + detector handle? (single thread)"""

import sys
import time

from sshguard.config import load
from sshguard.scan import scan_files

path = sys.argv[1]
config = load(None)
start = time.perf_counter()
report = scan_files([path], config, year=2026)
took = time.perf_counter() - start
print(f"{report.lines} lines, {report.parsed} sshd events, {len(report.bans)} bans in {took:.2f}s")
print(f"{report.lines / took:,.0f} lines/s")
