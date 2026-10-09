#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop325 (docs 10.73). usage: analyze325.py <tag> ...   (tag = e.g. loop325F)
Per leg and follower, window 1 (the first 30 s after the first full body, as fleet7-depth-replay.py):
  - the validator's `imported a block` lines: share with vote_before_slot, slot_wait_ms median/p90, held_at_arrival distribution
  - body arrival (`import starting`) to the vote sent (`sending vote to leader`), median/p90
  - body arrival to the engine's landing (`Block added to canonical chain`), median/p90
  - the execution layer's `checked: answered before the execution` lines: share with held=true
  - the unexecuted backlog: blocks voted for and not yet landed, sampled at each arrival (median/p90/max), and per 15 s over the leg
The engine thread's CPU per node: percent of one core over window 1 and over the whole sampled interval, from threadcpu-<tag>.tsv
(the runner's per-thread sampler, cumulative CPU seconds)."""
import importlib.util, os, re, statistics as st, sys, time
from collections import Counter
B = '/data/blockchain/rust-fleet3-bench'
S = '/data/n42-build/target-n42-rs/fleet-runs'
here = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('dr', os.path.join(here, '..', 'fleet7-depth-replay.py'))
dr = importlib.util.module_from_spec(sp); sp.loader.exec_module(dr)
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
def ms3(x): return f'{st.median(x):.1f}/{pct(x, .9):.1f}' if x else '-'
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'
    D = dr.collect(root); t0 = D['t0']; lo, hi = t0, t0 + 30
    print(f'== {tag}: leader node{D["ldr"]}, window 1 = [t0, t0+30 s]')
    for n in D['fol']:
        arr, vote, imp = {}, {}, {}
        for t, l in dr.lines(f'{root}/node{n}-v.log'):
            if 'import starting block_hash' in l: arr[dr.kv(l)['block_hash']] = t
            elif 'sending vote to leader' in l:
                d = dr.kv(l); vote[d['block_hash']] = t
            elif 'imported a block' in l:
                d = dr.kv(l); imp[d.get('block')] = (t, d)
        land, held, answered, di = {}, [], 0, []
        for t, l in dr.lines(f'{root}/node{n}-el.log'):
            if 'Block added to canonical chain' in l: land[dr.kv(l)['hash']] = t
            elif 'direct import: executed here' in l and lo <= t <= hi and dr.kv(l).get('txs', 0) >= 10000: di.append(dr.kv(l))
            elif 'checked: answered before the execution' in l and lo <= t <= hi and dr.kv(l).get('txs', 0) >= 10000:
                answered += 1; held.append(str(dr.kv(l).get('held')))
        W = [h for h, t in arr.items() if lo <= t <= hi and h in vote]
        a2v = [(vote[h] - arr[h]) * 1e3 for h in W]
        a2l = [(land[h] - arr[h]) * 1e3 for h in W if h in land]
        recs = [imp[h][1] for h in W if h in imp]
        vbs = Counter(str(d.get('vote_before_slot')) for d in recs)
        sw = [float(d['slot_wait_ms']) for d in recs if 'slot_wait_ms' in d]
        sw_vbs = [float(d['slot_wait_ms']) for d in recs if str(d.get('vote_before_slot')) == 'true']
        hd = Counter(str(d.get('held_at_arrival')) for d in recs)
        print(f'  node{n}: blocks {len(W)}, imported-a-block lines {len(recs)}; vote_before_slot {dict(vbs)}'
              f' ({vbs.get("true", 0) / len(recs) * 100:.0f}% true)' if recs else f'  node{n}: blocks {len(W)}, no `imported a block` lines')
        if recs:
            print(f'    slot_wait_ms median/p90 {ms3(sw)} (blocks that voted before a slot: {ms3(sw_vbs)}); held_at_arrival {dict(sorted(hd.items()))}')
        print(f'    body arrival -> vote sent median/p90 {ms3(a2v)} ms; body arrival -> engine landing {ms3(a2l)} ms')
        vr = []
        for t, l in dr.lines(f'{root}/node{n}-el.log'):
            if lo <= t <= hi and ' vote road number=' in l and dr.kv(l).get('txs', 0) >= 10000: vr.append(dr.kv(l))
        if vr:
            print('    EL `vote road` (ms) median: ' + ' '.join(f'{k}={st.median(float(r[k]) for r in vr if k in r):.0f}' for k in ('assemble_ms', 'parent_wait_ms', 'parent_fields_wait_ms', 'parent_output_wait_ms', 'fields_ms', 'other_ms', 'total_ms')))
        if di:
            print('    EL `direct import` (ms after body arrival) median/p90: ' + '; '.join(f'{k} {ms3([float(d[k]) for d in di if k in d])}' for k in ('exec_start_ms', 'exec_end_ms', 'fields_ready_ms', 'parent_engine_wait_ms', 'engine_ms')))
        # blocks that arrived and had not landed when this one arrived (the line `imported a block` with held_at_arrival is not printed on the compact path)
        inflight = Counter()
        for h in W:
            inflight[sum(1 for g, tg in arr.items() if tg < arr[h] and (g not in land or land[g] > arr[h]) and arr[h] - tg < 2)] += 1
        print(f'    blocks arrived and not yet landed when a block arrives (stand-in for held_at_arrival): {dict(sorted(inflight.items()))}')
        if answered:
            print(f'    EL `answered before the execution` lines {answered}: held {dict(Counter(held))}')
        # backlog: voted-for blocks not yet landed, at each arrival of the leg
        ev = sorted([(t, 1) for h, t in vote.items()] + [(land[h], -1) for h in vote if h in land])
        back, cur = [], 0; marks = []
        for t, d in ev:
            cur += d; marks.append((t, cur))
        inw = [c for t, c in marks if lo <= t <= hi]
        per15 = []
        for b in range(0, 150, 15):
            x = [c for t, c in marks if t0 + b <= t < t0 + b + 15]
            if x: per15.append(f't+{b}:{st.mean(x):.1f}')
        if inw: print(f'    voted-not-landed backlog in window 1 median/p90/max {st.median(inw):.0f}/{pct(inw, .9):.0f}/{max(inw)}; mean per 15 s: ' + ' '.join(per15))
    # engine thread CPU (the parser's times are the UTC stamps read as local time; the sampler's are epoch seconds)
    gm = time.localtime(lo).tm_gmtoff; elo, ehi = lo + gm, hi + gm
    rows = {}
    try:
        for l in open(f'{S}/threadcpu-{tag}.tsv'):
            f = l.rstrip('\n').split('\t')
            if len(f) == 5 and f[1] == 'el' and f[3] == 'engine': rows.setdefault(int(f[2]), []).append((float(f[0]), float(f[4])))
    except OSError:
        pass
    if rows:
        out = []
        for n in sorted(rows):
            r = rows[n]
            def rate(a, b):
                x = [p for p in r if a <= p[0] <= b]
                return (x[-1][1] - x[0][1]) / (x[-1][0] - x[0][0]) * 100 if len(x) > 1 and x[-1][0] > x[0][0] else float('nan')
            out.append(f'node{n} win1 {rate(elo, ehi):.1f}% whole {rate(r[0][0], r[-1][0]):.1f}%')
        print('  engine thread CPU (percent of one core): ' + '; '.join(out))
