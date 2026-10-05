#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop336 (docs 10.83): the batch, frame-walk and seal-to-child road fields of the leader's `seal-first build phases` lines, per leg, over the three 30 s
windows from the first full canonical block (as analyze334.py). usage: fields336.py <tag> ...  Prints median / p90 for every numeric field in KEYS, the
`one_wave` values, how often batches == batch_threads, and the last-minus-first batch start (`batch_last_start_us` - `batch_first_start_us`) share under 2 ms."""
import importlib.util, os, re, statistics as st, sys
from collections import Counter
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
KEYS = ['par_exec_ms', 'par_run_ms', 'batch_start_skew_ms', 'batch_median_ms', 'batch_max_ms', 'batch_first_start_us', 'batch_last_start_us', 'batch_dispatch_us', 'batch_last_end_us',
        'batches', 'batch_threads', 'batch_txs_max', 'batch_txs_min', 'start_walk_ms', 'start_walk_check_ms', 'par_start_ms', 'sealed_at_ms']
for tag in sys.argv[1:]:
    log = f'{B}/bench-{tag}/node0-el.log'
    full = [c for c in measure.log_blocks(log) if c[2] >= 100000]
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; rows = []
    for l in open(log, errors='replace'):
        if 'seal-first build phases' in l:
            l = ansi.sub('', l)
            if t0 <= ts(l) < t0 + 90: d = dict(KV.findall(l)); d['_t'] = ts(l); rows.append(d)
    rows = [d for d in rows if int(d.get('txs', 0)) >= 100000]
    print(f'== {tag}: {len(rows)} full builds in the 3 windows')
    keys = KEYS + sorted({k for d in rows for k in d if k.startswith(('start_walk_', 'prev_seal_to_')) and k not in KEYS})
    out = []
    for k in keys:
        v = [float(d[k]) for d in rows if k in d and re.fullmatch(r'-?[\d.]+', d[k])]
        if v: out.append(f'{k} {st.median(v):.0f}/{pct(v, .9):.0f}')
    print('  ' + '; '.join(out))
    ow = Counter(d.get('one_wave') for d in rows); print(f'  one_wave {dict(ow)}')
    eq = sum(1 for d in rows if d.get('batches') and d.get('batches') == d.get('batch_threads')); print(f'  batches == batch_threads on {eq} of {len(rows)} builds')
    sp = [float(d['batch_last_start_us']) - float(d['batch_first_start_us']) for d in rows if 'batch_last_start_us' in d and 'batch_first_start_us' in d]
    if sp: print(f'  last - first batch start (ms) median/p90 {st.median(sp) / 1e3:.2f}/{pct(sp, .9) / 1e3:.2f}; under 2 ms on {sum(1 for x in sp if x < 2000)} of {len(sp)} builds')
