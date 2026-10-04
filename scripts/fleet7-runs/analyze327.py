#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop327 (docs 10.75). usage: analyze327.py <tag> ...  (run analyze325.py / analyze326.py on the same tags for the rest).
Per follower, window 1 (median/p90): `direct import` handoff_wait_us, share of handoff_before_canonical=true, parent_engine_wait_ms and the
share of blocks whose wait is a multiple of 20 ms above 0; the `build path: the root's start after the execution` line's merge_ms,
merge_wait_ms and the halves merge_state_ms / merge_reverts_ms / merge_append_ms, merge_mode, the final merge_verified / merge_mismatches;
the slot hold (vote road start = `vote road` line minus total_ms, to the validator's `imported a block` line, joined by block number
through `Block added to canonical chain`); the answers of every direct import (status=) and the lines the correctness watch names."""
import importlib.util, os, re, statistics as st, sys
from collections import Counter
B = '/data/blockchain/rust-fleet3-bench'
here = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('dr', os.path.join(here, '..', 'fleet7-depth-replay.py'))
dr = importlib.util.module_from_spec(sp); sp.loader.exec_module(dr)
ansi = re.compile(r'\x1b\[[0-9;]*m')
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
def m3(x): return f'{st.median(x):.1f}/{pct(x, .9):.1f}' if x else '-'
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'
    D = dr.collect(root); lo, hi = D['t0'], D['t0'] + 30
    print(f'== {tag}')
    for n in D['fol']:
        di, mg, vr, land, rel = [], [], {}, {}, {}
        status = Counter(); last = {}
        for t, l in dr.lines(f'{root}/node{n}-el.log'):
            if 'direct import: executed here' in l:
                d = dr.kv(l); status[str(d.get('status'))] += 1
                if lo <= t <= hi and d.get('txs', 0) >= 10000: di.append(d)
            elif "build path: the root's start after the execution" in l:
                d = dr.kv(l); last = d
                if lo <= t <= hi: mg.append(d)
            elif ' vote road number=' in l:
                d = dr.kv(l); vr[int(d['number'])] = (t - d['total_ms'] / 1e3, d)
            elif 'Block added to canonical chain' in l:
                d = dr.kv(l); land[d['hash']] = int(d['number'])
        for t, l in dr.lines(f'{root}/node{n}-v.log'):
            if 'imported a block' in l:
                d = dr.kv(l)
                if d.get('block'): rel[d['block']] = t
        hold = [(rel[h] - vr[num][0]) * 1e3 for h, num in land.items() if h in rel and num in vr and lo <= vr[num][0] <= hi and vr[num][1].get('txs', 0) >= 10000]
        print(f'  node{n}: window-1 direct imports {len(di)}; status {dict(status)}')
        if di:
            hw = [float(d.get('handoff_wait_us', 0)) for d in di]; hb = Counter(str(d.get('handoff_before_canonical')) for d in di)
            pe = [float(d.get('parent_engine_wait_ms', 0)) for d in di]
            steps = sum(1 for x in pe if x > 0 and x % 20 == 0)
            print(f'    handoff_wait_us median/p90 {m3(hw)}; handoff_before_canonical {dict(hb)}; parent_engine_wait_ms median/p90 {m3(pe)}, nonzero {sum(1 for x in pe if x > 0)}, exact multiples of 20 {steps}, distribution {dict(sorted(Counter(int(x // 20 * 20) for x in pe).items()))}')
        if mg:
            f = lambda k: [float(d[k]) for d in mg if k in d and float(d.get('txs', 0) or 0) >= 0]
            print('    merge (ms, median/p90): ' + '; '.join(f'{k} {m3(f(k))}' for k in ('merge_ms', 'merge_wait_ms', 'merge_state_ms', 'merge_reverts_ms', 'merge_append_ms')) + f'; mode {Counter(str(d.get("merge_mode")) for d in mg)}; at the end of the leg merge_verified {last.get("merge_verified")} merge_mismatches {last.get("merge_mismatches")}')
        if hold: print(f'    slot hold (vote-road start to slot release) median/p90 {m3(hold)} ms (n={len(hold)})')
    # correctness watch
    el = [ansi.sub('', x) for n in range(3) for x in open(f'{root}/node{n}-el.log', errors='replace')]
    vl = [ansi.sub('', x) for n in range(3) for x in open(f'{root}/node{n}-v.log', errors='replace')]
    print(f'  watch: Sidechain block not found {sum("Sidechain block not found" in x for x in el + vl)}; invalid block {sum("Encountered invalid block" in x for x in el)}; TC formed {sum("TC formed" in x for x in vl)}; Too deep reorg {sum("Too deep reorg" in x for x in vl)}')
