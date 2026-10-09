#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop319: per node, from strip-<tag>/mem.log, the in-memory block count at +60 s, at the handover (first proposal of a
view >= 1024), at +150 s and at the last full block, its maximum, the peak RSS, and the backpressure counters.
usage: memsummary319.py <tag> [<tag> ...]; +t is seconds after the first full seal-first build."""
import re, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet3-bench'; S = '/home/n42/src/n42/n42-rs/target/fleet-runs'
ansi = re.compile(r'\x1b\[[0-9;]*m')
def ts(s): return datetime.strptime(s[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'; T0 = None; tend = 0; hand = None
    for l in open(f'{root}/node0-el.log', errors='replace'):
        l = ansi.sub('', l)
        if 'seal-first build phases' in l and re.search(r'txs=(\d{6})', l):
            T0 = T0 or ts(l)
        if 'Block added to canonical chain' in l and 'txs=0 ' not in l: tend = ts(l)
    for n in range(3):
        for l in open(f'{root}/node{n}-v.log', errors='replace'):
            l = ansi.sub('', l)
            if 'proposal sent view=' in l:
                m = re.search(r'view=(\d+)', l)
                if int(m[1]) >= 1024:
                    t = ts(l); hand = t if hand is None else min(hand, t)
    rows = {n: [] for n in range(3)}
    for l in open(f'{S}/strip-{tag}/mem.log'):
        p = l.split(); d = dict(x.split('=') for x in p[3:] if '=' in x)
        rows[int(p[2][4:])].append((float(p[0]), d))
    ho = hand - T0 if hand else float('nan')
    print(f'== {tag}: T0 +0, handover +{ho:.0f}s, last full block +{tend - T0:.0f}s, samples {len(rows[0])}/{len(rows[1])}/{len(rows[2])}')
    for n in range(3):
        def at(t):
            r = [d for tt, d in rows[n] if tt <= T0 + t and d['num'] != '-']
            return int(r[-1]['num']) if r else -1
        nums = [int(d['num']) for _, d in rows[n] if d['num'] != '-']
        rss = [float(d['rss_g']) for _, d in rows[n] if d['rss_g'] != '-']
        bp = [float(d['bp']) for _, d in rows[n] if d['bp'] != '-']
        sn = [float(d['stall_n']) for _, d in rows[n] if d['stall_n'] != '-']; ss = [float(d['stall_s']) for _, d in rows[n] if d['stall_s'] != '-']
        # when the count first exceeds 40
        first40 = next((tt - T0 for tt, d in rows[n] if d['num'] != '-' and int(d['num']) > 40), None)
        print(f'  node{n}: in-mem blocks +60s {at(60)}  handover {at(ho)}  +150s {at(150)}  end {at(tend - T0)}  max {max(nums, default=-1)}'
              f'  (first >40 at {"-" if first40 is None else f"+{first40:.0f}s"})  peak RSS {max(rss, default=0):.1f} G'
              f'  backpressure_active samples {sum(1 for b in bp if b > 0)}/{len(bp)}  stalls {int(sn[-1]) if sn else 0} totalling {ss[-1] if ss else 0:.1f}s')
