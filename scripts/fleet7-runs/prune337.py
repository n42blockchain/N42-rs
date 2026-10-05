#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop337 (docs 10.84): the canonical pruner per leg, from the layer's `canonical blocks pruned from the queue` lines in the three 30 s windows (as analyze334.py).
usage: prune337.py <tag> ...  Prints prune_ms / remove_us / forget_us / settle_us median and p90, the pruner's busy share of the window (sum of prune_ms), and the
share of the window the lanes lock was held for removal (sum of remove_us + settle_us), which is a lower bound of the lock's duty (the inbox drain is not logged)."""
import importlib.util, os, re, statistics as st, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=(\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
for tag in sys.argv[1:]:
    log = f'{B}/bench-{tag}/node0-el.log'
    full = [c for c in measure.log_blocks(log) if c[2] >= 100000]
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; rows = []
    for l in open(log, errors='replace'):
        if 'canonical blocks pruned from the queue' in l:
            l = ansi.sub('', l); d = {k: v for k, v in KV.findall(l)}; d['_t'] = ts(l); rows.append(d)
    print(f'== {tag}: pruner (per block; busy = sum prune_ms / 30 s, lock = sum (remove_us + settle_us) / 30 s)')
    for w in range(3):
        r = [d for d in rows if t0 + 30 * w <= d['_t'] < t0 + 30 * (w + 1) and int(d.get('mined', 0)) >= 100000]
        if not r: continue
        f = lambda k: [float(d[k]) for d in r if k in d]
        busy = sum(f('prune_ms')) / 30e3; lock = (sum(f('remove_us')) + sum(f('settle_us'))) / 30e6
        print(f'  window {w + 1}: {len(r)} prunes; prune_ms {st.median(f("prune_ms")):.0f}/{pct(f("prune_ms"), .9):.0f}; remove_us {st.median(f("remove_us")) / 1e3:.1f}/{pct(f("remove_us"), .9) / 1e3:.1f} ms; '
              f'forget_us {st.median(f("forget_us")) / 1e3:.1f}/{pct(f("forget_us"), .9) / 1e3:.1f} ms; settle_us {st.median(f("settle_us")) / 1e3:.1f} ms; pruner busy {busy:.0%} of a worker; lanes lock held for removal {lock:.0%}')
