#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop339 (docs 10.86): the leader's start / pull phases, the prepared plan, the answer and the chunked drain per leg, in the three 30 s windows from the first
full canonical block (as analyze334.py). usage: plan339.py <tag> ...
`seal-first build phases` (txs >= 100000): median / p90 of start_best_ms, start_walk_us, start_pull_ms, par_pull_ms, par_start_ms, par_ms, sealed_at_ms, pull_bulk_us,
plan_age_us, plan_prep_us, plan_topup_txs; the share of builds by `plan_ahead` (0 fresh, 1 prepared, 2 prepared and topped up); the values of `plan_discard`;
`built ahead on the sealed own block` answer_bytes and `answer_layout_only`; the validator's `proposal sent` answer_bytes / answer_layout_only; the ingest line's
drain_chunks, drain_chunk_max_txs, drain_finished and the last plan_discards."""
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
KEYS = ['start_best_ms', 'start_walk_us', 'start_pull_ms', 'par_pull_ms', 'par_start_ms', 'par_ms', 'sealed_at_ms', 'pull_bulk_us', 'pull_bulk_txs', 'plan_age_us', 'plan_prep_us', 'plan_topup_txs']
for tag in sys.argv[1:]:
    log = f'{B}/bench-{tag}/node0-el.log'
    full = [c for c in measure.log_blocks(log) if c[2] >= 100000]
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; bl, ah, ing = [], [], []
    for l in open(log, errors='replace'):
        if 'seal-first build phases' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l)
            if int(d.get('txs', 0)) >= 100000: bl.append(d)
        elif 'built ahead on the sealed own block' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l); ah.append(d)
        elif ' ingest frames=' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l); ing.append(d)
    ps = []
    try:
        for l in open(f'/data/n42-build/target-n42-rs/fleet-runs/strip-{tag}/v.log', errors='replace'):
            if 'proposal sent view=' in l:
                l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l); ps.append(d)
    except OSError: pass
    print(f'== {tag}: seal start / pull, prepared plan, answer, chunked drain')
    for w in range(int(os.environ.get('W339', '3'))):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        r = [d for d in bl if a <= d['_t'] < b]
        if not r: continue
        out = []
        for k in KEYS:
            v = [float(d[k]) for d in r if k in d and re.fullmatch(r'-?[\d.]+', d[k])]
            if v: out.append(f'{k} {st.median(v):.0f}/{pct(v, .9):.0f}')
        pa = Counter(d.get('plan_ahead', '-') for d in r); pd = Counter(d.get('plan_discard', '-').strip('"') for d in r)
        print(f'  window {w + 1}: {len(r)} builds; ' + '; '.join(out))
        print(f'           plan_ahead {dict(pa)}; plan_discard {dict(pd)}')
        ab = [float(d['answer_bytes']) for d in ah if a <= d['_t'] < b and 'answer_bytes' in d]
        lo = Counter(d.get('answer_layout_only') for d in ah if a <= d['_t'] < b); lp = Counter(d.get('answer_layout_only') for d in ps if a <= d['_t'] < b)
        pb = [float(d['answer_bytes']) for d in ps if a <= d['_t'] < b and 'answer_bytes' in d]
        print(f'           answer: built-ahead bytes median/max {st.median(ab) if ab else 0:,.0f}/{max(ab or [0]):,.0f}, layout_only {dict(lo)}; proposal sent bytes median/max {st.median(pb) if pb else 0:,.0f}/{max(pb or [0]):,.0f}, layout_only {dict(lp)}')
        iw = [d for d in ing if a <= d['_t'] < b]
        g = lambda k: [float(d[k]) for d in iw if k in d and re.fullmatch(r'-?[\d.]+', d[k])]
        print(f'           drain: chunks/5s {st.median(g("drain_chunks") or [0]):,.0f}, chunk max {max(g("drain_chunk_max_txs") or [0]):,.0f} tx, finished by others/5s {st.median(g("drain_finished") or [0]):,.0f}; plan_discards (last ingest line) {iw[-1].get("plan_discards", "-") if iw else "-"}')
