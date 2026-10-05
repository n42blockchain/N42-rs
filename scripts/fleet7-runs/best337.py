#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""usage: best337.py <prefix> <tag> ... Prints the tag (of those given) whose round total is highest among the legs with every block full in all three windows
(round.txt `full(>=95%)=a/b` with a == b ... a within one block of b is not accepted); prints nothing when none qualifies."""
import re, sys
B = '/data/blockchain/rust-fleet7-bench'
best = None
for t in sys.argv[2:]:
    try:
        r = open(f'{B}/bench-{sys.argv[1]}{t}/round.txt').read()
        rows = re.findall(r'^win[123] .*?txs=([\d,]+).*?full\(>=95%\)=(\d+)/(\d+)', r, re.M)
        if len(rows) != 3 or any(a != b for _, a, b in rows): continue
        tot = sum(int(x.replace(',', '')) for x, _, _ in rows)
        if best is None or tot > best[0]: best = (tot, t)
    except Exception: pass
if best: print(best[1])
