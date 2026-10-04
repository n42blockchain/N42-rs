#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Slow blocks against kernel counter rates (docs 10.65). usage: analyze317.py <tag> [<tag> ...]
Reads the leader's (node0) EL log of bench-<tag> and strip-<tag>/kern.log. Window 1 = 30 s from the first full block;
each block's cycle (gap from the previous full block) is assigned the one-second kern.log interval it ends in."""
import bisect, re, sys, statistics as st
from datetime import datetime, timezone
S = '/home/n42/src/n42/n42-rs/target/fleet-runs'; B = '/data/blockchain/rust-fleet3-bench'
ansi = re.compile(r'\x1b\[[0-9;]*m')
def ts(s): return datetime.strptime(s[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
KEYS = ['CAL', 'TLB', 'pgfault', 'pgmajfault', 'thp_fault_alloc', 'thp_fault_fallback', 'compact_stall', 'pgscan_kswapd', 'pgsteal_kswapd']
def rank(x):
    o = sorted(range(len(x)), key=lambda i: x[i]); r = [0.0] * len(x)
    for k, i in enumerate(o): r[i] = k
    return r
def corr(a, b):
    ra, rb = rank(a), rank(b); ma, mb = st.mean(ra), st.mean(rb)
    num = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    den = (sum((x - ma) ** 2 for x in ra) * sum((y - mb) ** 2 for y in rb)) ** .5
    return num / den if den else float('nan')
for tag in sys.argv[1:]:
    t = []
    for l in open(f'{B}/bench-{tag}/node0-el.log', errors='replace'):
        if 'Block added to canonical chain' in l and 'txs=163000' in l: t.append(ts(ansi.sub('', l)))
    t.sort(); t0 = t[0]; w = [x for x in t if x < t0 + 30]
    cyc = [(w[i], (w[i] - w[i - 1]) * 1000) for i in range(1, len(w))]
    kt, kv = [], []
    for l in open(f'{S}/strip-{tag}/kern.log'):
        p = l.split()
        if len(p) < 3 or 'GUARD' in l: continue
        d = dict(x.split('=') for x in p[1:] if '=' in x)
        kt.append(ts(p[0])); kv.append({k: float(d[k]) if d.get(k, 'NA') != 'NA' else None for k in KEYS})
    print(f'\n== {tag}: window 1 blocks {len(w)}, cycle mean {st.mean(c for _, c in cyc):.1f} median {st.median(c for _, c in cyc):.1f} ms; kern samples {len(kt)}')
    ivl = lambda x: bisect.bisect_left(kt, x)  # interval (kt[j-1], kt[j]] holds x
    rows = []
    for tb, c in cyc:
        j = ivl(tb)
        if 0 < j < len(kt): rows.append((c, j))
    cut = sorted(c for c, _ in rows)[int(len(rows) * 0.9)]
    slow = [r for r in rows if r[0] >= cut]; rest = [r for r in rows if r[0] < cut]
    print(f'slowest 10%: {len(slow)} blocks with cycle >= {cut:.0f} ms (mean {st.mean(c for c, _ in slow):.0f}), rest {len(rest)} (mean {st.mean(c for c, _ in rest):.0f})')
    print(f'{"counter":22s} {"win1 /s":>12s} {"slow /s":>12s} {"rest /s":>12s} {"ratio":>6s} {"spearman":>9s}')
    for k in KEYS:
        if kv[0][k] is None: print(f'{k:22s} not exported'); continue
        rate = lambda j: (kv[j][k] - kv[j - 1][k]) / (kt[j] - kt[j - 1])
        a = [rate(j) for _, j in slow]; b = [rate(j) for _, j in rest]
        js = [j for j in range(ivl(w[0]) + 1, ivl(w[-1]))]
        m = st.mean(rate(j) for j in js) if js else float('nan')
        ma, mb = st.mean(a), st.mean(b)
        print(f'{k:22s} {m:12.0f} {ma:12.0f} {mb:12.0f} {ma / mb if mb else float("nan"):6.2f} {corr([c for c, _ in rows], [rate(j) for _, j in rows]):9.3f}')
