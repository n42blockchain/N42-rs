#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop326 (docs 10.74). usage: analyze326.py <tag> ...  (run analyze325.py on the same tags for the vote road and the engine CPU).
Per node per leg: reth_sync_caching_account_cache_size / storage_cache_size (metrics file at the end of the leg), the median `elapsed` of the
`Block added to canonical chain` lines of blocks with >= 10,000 transactions in window 1 (the executed insert on the tree thread), the median
`engine_new_payload_ms` of the `direct import` lines, and the "Too deep reorg" and settlement lines (persisted block first reading, safe= /
finalized= on `commit forkchoice answered`, -38002 / -38006, forkchoice refused)."""
import importlib.util, os, re, statistics as st, sys
B = '/data/blockchain/rust-fleet3-bench'
here = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('dr', os.path.join(here, '..', 'fleet7-depth-replay.py'))
dr = importlib.util.module_from_spec(sp); sp.loader.exec_module(dr)
ansi = re.compile(r'\x1b\[[0-9;]*m')
def dur(s):
    m = re.match(r'([\d.]+)(ns|µs|us|ms|s)$', s)
    return float(m[1]) * {'ns': 1e-6, 'µs': 1e-3, 'us': 1e-3, 'ms': 1.0, 's': 1e3}[m[2]] if m else None
def med(x): return st.median(x) if x else float('nan')
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'
    D = dr.collect(root); lo, hi = D['t0'], D['t0'] + 30
    print(f'== {tag}')
    for n in range(3):
        met = {}
        try:
            for l in open(f'{root}/metrics-node{n}.txt', errors='ignore'):
                m = re.match(r'(reth_sync_caching_(?:account|storage)_cache_size)\S*\s+([0-9.eE+-]+)', l)
                if m: met[m[1].replace('reth_sync_caching_', '')] = int(float(m[2]))
        except OSError: pass
        el, npm, deep, settle = [], [], 0, []
        for t, l in dr.lines(f'{root}/node{n}-el.log'):
            if 'Block added to canonical chain' in l and lo <= t <= hi:
                d = dr.kv(l)
                if d.get('txs', 0) >= 10000 and 'elapsed' in d:
                    v = dur(str(d['elapsed']))
                    if v is not None: el.append(v)
            elif 'direct import: executed here' in l and lo <= t <= hi and dr.kv(l).get('txs', 0) >= 10000:
                npm.append(float(dr.kv(l).get('engine_new_payload_ms', 0)))
            if 'Too deep reorg' in l: deep += 1
        vl = [ansi.sub('', x) for x in open(f'{root}/node{n}-v.log', errors='replace')]
        elines = [ansi.sub('', x) for x in open(f'{root}/node{n}-el.log', errors='replace')]
        sett = {'persisted_first_reading': sum('persisted block: first reading' in x for x in vl + elines),
                'refused': sum(('forkchoice' in x and 'refused' in x) for x in vl + elines),
                '38002_in_forkchoice_lines': sum(('-38002' in x and 'forkchoice' in x) for x in vl + elines), '38006_in_forkchoice_lines': sum(('-38006' in x and 'forkchoice' in x) for x in vl + elines)}
        ans = [x for x in vl if 'commit forkchoice answered' in x]
        sf = re.findall(r'safe=(\S+) finalized=(\S+)', ' '.join(ans[:3])) if ans else []
        print(f'  node{n}: account_cache_size {met.get("account_cache_size")} storage_cache_size {met.get("storage_cache_size")}; Block added elapsed median/p90 {med(el):.2f}/{pct(el, .9):.2f} ms (n={len(el)}); engine_new_payload_ms median/p90 {med(npm):.0f}/{pct(npm, .9):.0f}; Too deep reorg lines {deep}; settlement {sett}; answered lines {len(ans)}')
        if sf: print(f'    first answered lines safe/finalized: {sf}')
