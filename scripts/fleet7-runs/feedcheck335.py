#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""usage: feedcheck335.py <tag>. Exit 0 when the feed did not bind on the leg, 1 when it did (the runner then reruns the leg with the feed raised).
Feed-bound = in any of the three log windows (as analyze334.py: 30 s from the first full canonical block on layer 0) fewer than 97% of the canonical blocks
are full (gas >= 95%), or the median queue at the leader's builds is under 2.5 blocks' worth of transactions. Prints one line either way."""
import importlib.util, os, re, statistics as st, sys
B = '/data/blockchain/rust-fleet7-bench'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m')
tag = sys.argv[1]; log = f'{B}/bench-{tag}/node0-el.log'
canon = measure.log_blocks(log)
full = [c for c in canon if c[2] >= 50000]
if not full: print(f'feedcheck {tag}: no block with transactions'); sys.exit(1)
t0 = full[0][0]; blk = max(c[2] for c in canon)
q = []
for l in open(log, errors='replace'):
    if 'seal-first build phases' in l:
        l = ansi.sub('', l); m = re.search(r' queued=(\d+)', l); n = re.search(r' txs=(\d+)', l)
        if m and n and int(n[1]) >= 0.9 * blk:
            try: q.append((measure.datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=measure.timezone.utc).timestamp(), int(m[1])))
            except ValueError: pass
bad = []
for w in range(3):
    a, b = t0 + 30 * w, t0 + 30 * (w + 1)
    cw = [c for c in canon if a <= c[0] < b]; qw = [x for t, x in q if a <= t < b]
    if not cw: bad.append(f'w{w + 1} no blocks'); continue
    fs = sum(1 for c in cw if c[3] >= 95.0) / len(cw); qm = st.median(qw) if qw else 0
    if fs < 0.97 or qm < 2.5 * blk: bad.append(f'w{w + 1} full {fs:.0%} queue median {qm:,.0f}')
print(f'feedcheck {tag}: ' + ('FEED-BOUND: ' + '; '.join(bad) if bad else f'ok (block {blk:,} tx)'))
sys.exit(1 if bad else 0)
