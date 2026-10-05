#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop333 (docs 10.80). usage: analyze333.py <tag> ...  (run analyze328.py and analyze332.py on the same tags for the rest).
Per leg, per 30 s window (window 1 starts at the first full seal-first build on layer 0): blocks, mean transactions, `sealed_at_ms`, `par_ms` and
`parent_fields_ms` median / p90 / p99, the layer's in-memory block count (memsample `num`) maximum, its RSS at the start and end of the window, the
queue depth at the leader's builds (`queued`, minimum and median), the proposals the build throttle delayed, and whether the window holds the window-1
rate. Then the tail: the blocks of the whole leg whose `sealed_at_ms` is in the top 5% against the rest, the mean of every numeric field of the build
line for both groups (the fields with the largest ratio), the share of slow blocks that follow a slow block, and the slow blocks per block number
modulo 8 and 16 (persistence batches)."""
import re, statistics as st, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
def m3(x): return f'{st.median(x):.0f}/{pct(x, .9):.0f}/{pct(x, .99):.0f}' if x else '-'
def num(v):
    try: return float(v)
    except ValueError: return None
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'; print(f'== {tag}')
    builds = []
    for l in open(f'{root}/node0-el.log', errors='replace'):
        if 'seal-first build phases' in l:
            l = ansi.sub('', l); d = {k: num(v) for k, v in KV.findall(l) if num(v) is not None}; d['t'] = ts(l); builds.append(d)
    full = [d for d in builds if d.get('txs', 0) >= 100000]
    if not full: print('  no full build'); continue
    t0 = full[0]['t']
    canon = []
    for l in open(f'{root}/node0-el.log', errors='replace'):
        if 'Block added to canonical chain' in l:
            l = ansi.sub('', l); m = re.search(r' txs=(\d+)', l)
            if m: canon.append((ts(l), int(m[1])))
    mem = []
    try:
        for l in open(f'{S}/strip-{tag}/mem.log'):
            m = re.match(r'(\d+\.\d+) .* rss_g=([\d.]+) num=(\d+)', l)
            if m: mem.append((float(m[1]), float(m[2]), int(m[3])))
    except OSError: pass
    vl = []
    try:
        for l in open(f'{root}/node0-v.log', errors='replace'):
            if 'proposal sent' in l and 'throttle_delay_ms' in l:
                l = ansi.sub('', l); vl.append((ts(l), dict(KV.findall(l))))
    except OSError: pass
    base = None
    for w in range(3):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        ws = [d for d in builds if a <= d['t'] < b]
        if not ws: print(f'  window {w + 1}: no builds'); continue
        tx = sum(d['txs'] for d in ws); rate = tx / 30
        if base is None: base = rate
        cw = [n for t, n in canon if a <= t < b]
        print(f'  window {w + 1} canonical (the layer\'s `Block added to canonical chain`): {len(cw)} blocks, {sum(cw) / 1e6:.1f}M tx = {sum(cw) / 30:,.0f}/s, full (>= 95% of {max(cw) if cw else 0}) {sum(1 for n in cw if cw and n >= 0.95 * max(cw))}')
        ms = [m for m in mem if a <= m[0] < b]
        q = [d['queued'] for d in ws if 'queued' in d]
        thr = [d for t, d in vl if a <= t < b]
        print(f'  window {w + 1}: {len(ws)} builds, {tx / 1e6:.1f}M tx ({rate:,.0f}/s = {rate / base:.0%} of window 1); sealed_at {m3([d["sealed_at_ms"] for d in ws if "sealed_at_ms" in d])}; par_ms {m3([d["par_ms"] for d in ws if "par_ms" in d])}; parent_fields_ms {m3([d["parent_fields_ms"] for d in ws if "parent_fields_ms" in d])}'
              + (f'; in-memory max {max(m[2] for m in ms)}, RSS {ms[0][1]:.1f} -> {ms[-1][1]:.1f} G' if ms else '')
              + (f'; queue min/median {min(q):,.0f}/{st.median(q):,.0f}' if q else '')
              + f'; throttle delayed {sum(1 for d in thr if float(d.get("throttle_delay_ms", 0)) > 0)} of {len(thr)}')
    ws = [d for d in full if d['t'] < t0 + 90 and 'sealed_at_ms' in d]
    if len(ws) < 40: continue
    thr = pct([d['sealed_at_ms'] for d in ws], .95)
    slow = [d for d in ws if d['sealed_at_ms'] >= thr]; rest = [d for d in ws if d['sealed_at_ms'] < thr]
    print(f'  tail: {len(slow)} slow blocks (sealed_at >= {thr:.0f} ms, top 5% of {len(ws)} full builds in the first 90 s); sealed_at slow mean {st.mean(d["sealed_at_ms"] for d in slow):.0f} against {st.mean(d["sealed_at_ms"] for d in rest):.0f}')
    rows = []
    for k in {k for d in ws for k in d if k not in ('t', 'number', 'txs', 'queued', 'usable') and not k.startswith(('seal_to', 'rename', 'overlay', 'reads_', 'view_'))}:
        a = [d[k] for d in slow if k in d]; b = [d[k] for d in rest if k in d]
        if len(a) < 3 or len(b) < 3: continue
        ma, mb = st.mean(a), st.mean(b)
        if k.endswith('_us'): ma, mb = ma / 1000, mb / 1000
        if max(ma, mb) < 3: continue
        rows.append((abs(ma - mb), k, ma, mb))
    rows.sort(reverse=True)
    print('  largest differences (slow mean vs rest mean): ' + '; '.join(f'{k} {ma:.0f} vs {mb:.0f}' for _, k, ma, mb in rows[:10]))
    idx = {d['number']: d for d in builds if 'number' in d}
    after = sum(1 for d in slow if idx.get(d['number'] - 1, {}).get('sealed_at_ms', 0) >= thr)
    print(f'  slow blocks following a slow block: {after} of {len(slow)}; by number mod 8 {sorted(__import__("collections").Counter(int(d["number"]) % 8 for d in slow).items())}')
