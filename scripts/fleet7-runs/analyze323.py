#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop323 (docs 10.71). usage: analyze323.py <tag> ...
Per leg: the flood's delivery from flood.log (the per-5 s `sent` rates while the flood is not gated, rejected, the final
accepted / submitted figures, gated seconds), the node-0 queue depth over time (`canonical blocks pruned from the queue ... queued=`
median per 10 s), transactions per block in window 1 (leader builds with txs > 0, first 30 s) and the share at >= 95% of 163,000,
`overlay_filter_builds` / `overlay_filter_cached` per leader block (deltas of the cumulative counters), and the handover's timeout
lines (the first ten "Too deep reorg" / "build on the sealed block refused" / TC lines of the new leader with timestamps)."""
import re, sys, statistics as st
from datetime import datetime
B = '/data/blockchain/rust-fleet3-bench'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').timestamp()
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'
    print(f'== {tag}')
    rates, rej, wait, last = [], 0, 0, None
    for l in open(f'{root}/flood.log', errors='replace'):
        m = re.match(r'flood \+\s*(\d+)s: sent (\d+) \((\d+)/s\), rejected (\d+), sign (\d+)s, send (\d+)s, wait (\d+)s, deepest pool (\d+)', l)
        if m: rates.append(int(m[3])); rej = int(m[4]); wait = int(m[7]); last = m
    fin = None
    for l in open(f'{root}/round.txt', errors='replace'):
        m = re.match(r'flood\s+: (\d+) accepted, (\d+) rejected, ([\d.]+)s, (\d+)/s submitted', l)
        if m: fin = m
    top = sorted(rates)[len(rates) // 2] if rates else 0
    final = f'final {fin[1]} accepted {fin[2]} rejected in {fin[3]}s = {fin[4]}/s' if fin else 'final: -'
    if rates:
        print(f'  flood: per-5s rate median {top}/s, max {max(rates)}/s, rejected {rej}, worker-seconds waiting at the gate {wait}s (64 workers, {len(rates) * 5}s of flood), {final}')
    else:
        print('  flood: no progress lines')
    t0 = None; txs = []; builds = []; q = []
    for l in open(f'{root}/node0-el.log', errors='replace'):
        l = ansi.sub('', l)
        if 'seal-first build phases' in l:
            d = dict(KV.findall(l)); t = ts(l)
            if int(d['txs']) >= 1000:
                t0 = t0 or t
                if t - t0 < 30: txs.append(int(d['txs']))
            if 'overlay_filter_builds' in d: builds.append((int(d['overlay_filter_builds']), int(d['overlay_filter_cached'])))
        elif 'canonical blocks pruned from the queue' in l and t0:
            q.append((ts(l) - t0, int(dict(KV.findall(l))['queued'])))
    if txs: print(f'  window-1 leader builds {len(txs)}: txs mean {st.mean(txs):.0f}, share >= 95% of 163000: {sum(1 for x in txs if x >= 154850) / len(txs) * 100:.0f}%')
    if builds:
        db = [b[0] - a[0] for a, b in zip(builds, builds[1:])]
        print(f'  overlay_filter_builds per leader block: mean {st.mean(db):.2f} (total {builds[-1][0] - builds[0][0]} over {len(db)} blocks), overlay_filter_cached last {builds[-1][1]}')
    if q:
        print('  node-0 queue (queued after canonical prune), median per 10 s: ' + ' '.join(f't+{b}:{st.median(x for t, x in q if b <= t < b + 10):.0f}' for b in range(0, 200, 20) if any(b <= t < b + 10 for t, _ in q)))
    lines = []
    for n in range(3):
        for l in open(f'{root}/node{n}-v.log', errors='replace'):
            l = ansi.sub('', l)
            if ('Too deep reorg' in l or 'build on the sealed block refused' in l or 'TC formed' in l) :
                lines.append((l[:26], n, re.sub(r'^\S+\s+', '', l.strip())[:170]))
    lines.sort()
    tc = [x for x in lines if 'TC formed' in x[2]]
    print(f'  handover/timeout lines (TC formed / Too deep reorg / build refused): {len(lines)}; first ten:' if lines else '  no TC / Too deep reorg / build-refused lines')
    for x in lines[:10]: print(f'    {x[0]} node{x[1]} {x[2]}')
