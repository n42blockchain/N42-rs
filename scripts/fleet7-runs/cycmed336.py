#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""usage: cycmed336.py <tag> cycle|seal. Prints one number for the runner's rules: the median proposal-to-proposal interval (validator 0, ms) or the
median `sealed_at_ms` of the leader's full builds, over the three 30 s windows from the first full canonical block on layer 0 (as analyze334.py).
Tag `loop335S250` also falls back to `loop335S250r` (the feed rerun) when the plain leg is missing. Prints 9999 when the leg has no data."""
import importlib.util, os, re, statistics as st, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
tag, what = sys.argv[1], sys.argv[2]
try:
    root = f'{B}/bench-{tag}'
    if not os.path.exists(f'{root}/node0-el.log') and os.path.exists(f'{root}r/node0-el.log'): root += 'r'
    full = [c for c in measure.log_blocks(f'{root}/node0-el.log') if c[2] >= 100000]
    t0 = full[0][0]; t1 = t0 + 90
    if what == 'cycle':
        pts = sorted(ts(ansi.sub('', l)) for l in open(f'{root}/node0-v.log', errors='replace') if 'proposal sent view=' in ansi.sub('', l))
        d = [(b - a) * 1e3 for a, b in zip(pts, pts[1:]) if t0 <= a < t1 and 0 < (b - a) * 1e3 < 2000]
        print(f'{st.median(d):.1f}')
    else:
        s = []
        for l in open(f'{root}/node0-el.log', errors='replace'):
            if 'seal-first build phases' in l:
                l = ansi.sub('', l); m = re.search(r' sealed_at_ms=(\d+)', l); n = re.search(r' txs=(\d+)', l)
                if m and n and int(n[1]) >= 100000 and t0 <= ts(l) < t1: s.append(int(m[1]))
        print(f'{st.median(s):.1f}')
except Exception:
    print(9999)
