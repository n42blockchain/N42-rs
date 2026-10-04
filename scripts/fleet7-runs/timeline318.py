#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Per-10-s timeline of a three-node leg (loop318 follow-up, docs 10.66 addendum). usage: timeline318.py <tag> [bucket_s]
Per bucket since the first full seal-first build: blocks canonical per node, which node leads, the leader's sealed_at /
par_ms / state_ready_ms median, per follower import total_ms median/max and lag behind the leader's proposals (blocks and ms at the
bucket end), the QMDB read view's lag (`reader_lag`, canonical minus view_head), forest-lock `on_persisted` warnings,
EL RSS max (the runner's 5 s sampler; its local clock is UTC-4) and the queue depth after pruning."""
import re, sys, statistics as st, bisect
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet3-bench'; S = '/home/n42/src/n42/n42-rs/target/fleet-runs'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(s): return datetime.strptime(s[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def kv(l): return {k: v.strip('"') for k, v in KV.findall(l)}
def med(x): return st.median(x) if x else float('nan')
tag = sys.argv[1]; BK = float(sys.argv[2]) if len(sys.argv) > 2 else 10
root = f'{B}/bench-{tag}'
el = {n: [(ts(l), l) for l in map(lambda s: ansi.sub('', s), open(f'{root}/node{n}-el.log', errors='replace')) if l[:2] == '20'] for n in range(3)}
vl = {n: [(ts(l), l) for l in map(lambda s: ansi.sub('', s), open(f'{root}/node{n}-v.log', errors='replace')) if l[:2] == '20'] for n in range(3)}
seal = {n: [] for n in range(3)}; canon = {n: [] for n in range(3)}; imp = {n: [] for n in range(3)}; lag = {n: [] for n in range(3)}
persw = {n: [] for n in range(3)}; que = {n: [] for n in range(3)}; prop = {n: [] for n in range(3)}
for n in range(3):
    for t, l in el[n]:
        if 'seal-first build phases' in l:
            d = kv(l)
            if int(d['txs']) >= 100000: seal[n].append((t, d))
        elif 'Block added to canonical chain' in l and 'txs=0 ' not in l: canon[n].append(t)
        elif 'direct import: executed here' in l:
            d = kv(l)
            if int(d['txs']) >= 100000: imp[n].append((t, d))
        elif 'reader_lag=' in l:
            d = kv(l); lag[n].append((t, int(d['canonical']) - int(d['view_head'])))
        elif 'label="on_persisted"' in l: persw[n].append(t)
        elif 'canonical blocks pruned from the queue' in l: que[n].append((t, int(kv(l)['queued'])))
    for t, l in vl[n]:
        if 'proposal sent view=' in l: prop[n].append((t, int(kv(l)['view'])))
T0 = min(t for n in seal for t, _ in seal[n])
tmax = max(t for n in canon for t in canon[n])
first_prop = {n: (prop[n][0][0] - T0 if prop[n] else None) for n in range(3)}
allprop = sorted(x for n in prop for x in prop[n])
pt = [t for t, _ in allprop]; pv = [v for _, v in allprop]
def proposed_by(t):  # highest view proposed by anyone at time t
    i = bisect.bisect_right(pt, t); return max(pv[:i]) if i else 0
mem = []
for l in open(f'{S}/mem-{tag}.txt'):
    m = re.match(r'(\d\d):(\d\d):(\d\d) el_sum=([\d.]+)G el_max=([\d.]+)G', l)
    if m:
        day = datetime.fromtimestamp(T0, timezone.utc).replace(hour=0, minute=0, second=0).timestamp()
        h, mi, s = int(m[1]) + 4, int(m[2]), int(m[3]); mem.append((day + h * 3600 + mi * 60 + s, float(m[4]), float(m[5])))
print(f'== {tag}: T0 {datetime.fromtimestamp(T0, timezone.utc):%H:%M:%S}Z, first proposal by node: ' + ', '.join(f'node{n} +{first_prop[n]:.0f}s' for n in range(3) if first_prop[n] is not None) + f'; last full block +{tmax - T0:.0f}s')
# the handover: first full-block proposal view >= 1024 by a node other than the first leader
hv = [(t, n, v) for n in prop for t, v in prop[n] if v >= 1024]
if hv: t, n, v = min(hv); print(f'   first proposal at view >= 1024: node{n} view {v} at +{t - T0:.0f}s')
print('  t+s  blk/s(n0 n1 n2)  ldr  sealed_at par   ready | imp med/max ms n0 n1 n2 | lag blocks(n0 n1 n2) ms(n0 n1 n2) | qlag(n0 n1 n2) | persw(n0 n1 n2) | el_max G | queued(n0 n1 n2)')
b = 0
while T0 + b * BK < tmax + BK:
    lo, hi = T0 + b * BK, T0 + (b + 1) * BK
    cnt = [sum(lo <= t < hi for t in canon[n]) for n in range(3)]
    sl = [(n, d) for n in range(3) for t, d in seal[n] if lo <= t < hi]
    ldr = max(set(n for n, _ in sl), key=[n for n, _ in sl].count) if sl else -1
    sd = [d for n, d in sl if n == ldr]
    f = lambda k: med([float(d[k]) for d in sd])
    im = {n: [float(d['total_ms']) for t, d in imp[n] if lo <= t < hi] for n in range(3)}
    # follower lag at bucket end: proposals so far minus follower's last imported view
    lb, lm = [], []
    for n in range(3):
        last = [(t, int(d['number']) + 1) for t, d in imp[n] if t < hi]
        if last:
            t_i, v_i = last[-1]; lb.append(proposed_by(hi) - v_i)
        else: lb.append(float('nan'))
        # ms: for blocks imported in the bucket, finish time minus that view's proposal time
        pm = {v: t for t, v in allprop}
        lm.append(med([(t - pm[int(d['number']) + 1]) * 1000 for t, d in imp[n] if lo <= t < hi and int(d['number']) + 1 in pm]))
    ql = [max([x for t, x in lag[n] if lo <= t < hi], default=float('nan')) for n in range(3)]
    pw = [sum(lo <= t < hi for t in persw[n]) for n in range(3)]
    mm = max([m for t, s_, m in mem if lo <= t < hi], default=float('nan'))
    qq = [med([x for t, x in que[n] if lo <= t < hi]) for n in range(3)]
    fm = lambda x: f'{x:5.0f}' if x == x else '    -'
    print(f' {b * BK:4.0f}  {cnt[0]:3d} {cnt[1]:3d} {cnt[2]:3d}   {ldr}   {fm(f("sealed_at_ms"))} {fm(f("par_ms"))} {fm(f("state_ready_ms"))} | {fm(med(im[0]))}/{fm(max(im[0], default=float("nan")))} {fm(med(im[1]))}/{fm(max(im[1], default=float("nan")))} {fm(med(im[2]))}/{fm(max(im[2], default=float("nan")))} | {fm(lb[0])}{fm(lb[1])}{fm(lb[2])} {fm(lm[0])}{fm(lm[1])}{fm(lm[2])} | {fm(ql[0])}{fm(ql[1])}{fm(ql[2])} | {pw[0]:2d}{pw[1]:3d}{pw[2]:3d} | {fm(mm)} | {fm(qq[0])}{fm(qq[1])}{fm(qq[2])}')
    b += 1
