#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop320: the leader's window-1 build-chain medians/p90 per leg (docs 10.68). usage: analyze320.py <tag> [<tag> ...]
Window 1 = the first 30 s of full (txs >= 100000) seal-first builds on node 0. Prints parent_fields_ms, sealed_ms, par_ms,
par_exec_ms, roots_ms, seal_to_{finish,bundle,view,rename,root_start,root_end,fields}_us, rename_wait_us, the share of blocks
with rename_early=true, the fields_at_seal mode, and the process totals of fields_verified / unchecked / mismatches."""
import re, sys, statistics as st
from datetime import datetime
B = '/data/blockchain/rust-fleet3-bench'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').timestamp()
KEYS = ['parent_fields_ms', 'sealed_ms', 'sealed_at_ms', 'par_ms', 'par_exec_ms', 'roots_ms', 'state_ready_ms', 'seal_to_finish_us', 'seal_to_bundle_us',
        'seal_to_view_us', 'seal_to_rename_us', 'rename_wait_us', 'seal_to_root_start_us', 'seal_to_root_end_us', 'seal_to_fields_us']
for tag in sys.argv[1:]:
    rows = []; t0 = None; modes = set(); tot = [0, 0, 0]
    for n in range(3):
        mx = [0, 0, 0]
        for l in open(f'{B}/bench-{tag}/node{n}-el.log', errors='replace'):
            if 'seal-first build phases' not in l: continue
            l = ansi.sub('', l); d = dict(KV.findall(l))
            for i, k in enumerate(('fields_verified', 'fields_unchecked', 'fields_mismatches')):
                if k in d: mx[i] = max(mx[i], int(d[k]))
            if 'fields_at_seal' in d: modes.add(d['fields_at_seal'])
            if n == 0 and int(d['txs']) >= 100000:
                t = ts(l); t0 = t0 or t
                if t - t0 < 30: rows.append(d)
        tot = [a + b for a, b in zip(tot, mx)]
    def pm(k):
        x = sorted(float(d[k]) for d in rows if k in d and d[k].lstrip('-').isdigit())
        return f'{st.median(x):.0f}/{x[int(len(x) * .9)]:.0f}' if x else '-'
    early = sum(1 for d in rows if d.get('rename_early') == 'true')
    print(f'== {tag}: window-1 leader builds {len(rows)}, fields_at_seal={sorted(modes)}, rename_early {early}/{len(rows)} ({early / max(len(rows), 1) * 100:.0f}%)')
    print('  ' + '  '.join(f'{k}={pm(k)}' for k in KEYS))
    print(f'  process totals: fields_verified={tot[0]} fields_unchecked={tot[1]} fields_mismatches={tot[2]}')
