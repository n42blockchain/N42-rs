#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop346 (docs 10.88): the leader's execution and QMDB-root fields per leg, from `seal-first build phases` (txs >= 100000) in the three 30 s windows from the first full canonical
block (as analyze334.py). usage: fields346.py <tag> ...
Per window, median / p90: par_exec_ms, the on-CPU share batch_cpu_sum_us / batch_wall_sum_us, per-transfer CPU (batch_cpu_sum_us / txs, us), batch_minflt / majflt, batch_vcsw, batch_ivcsw and the live-index / view / open counters (per block),
view_journal_reads / searches / skips (per block), root_writes_us, root_delta_us, root_apply_total_us, the other root_*_us pieces, roots_ms, seal_to_fields_us, sealed_at_ms,
batch_max_ms / batch_median_ms. Also the share of builds in which the slowest batch's off-CPU part is ... (not derivable from the sums: the off-CPU share of the sums is 1 - cpu/wall)."""
import importlib.util, os, re, statistics as st, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
NUM = re.compile(r'-?[\d.]+')
KEYS = ['sealed_at_ms', 'par_exec_ms', 'par_fold_ms', 'index_ms', 'par_start_ms', 'gap_before_exec_ms', 'state_wait_us', 'parent_fields_ms', 'roots_ms', 'seal_to_fields_us', 'seal_to_complete_us',
        'rename_fallbacks', 'rename_record_waits', 'carried_depth', 'plan_body_us', 'batch_max_ms', 'tx_root_ms', 'sealed_ms']
BOOLS = ['seal_on_counters', 'freeze_pool_own', 'plan_body', 'prep_from_plan', 'plan_ahead']
for tag in sys.argv[1:]:
    log = f'{B}/bench-{tag}/node0-el.log'
    full = [c for c in measure.log_blocks(log) if c[2] >= 100000]
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; rows = []
    for l in open(log, errors='replace'):
        if 'seal-first build phases' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l)
            if int(d.get('txs', 0)) >= 100000: rows.append(d)
    folded = []
    for l in open(log, errors='replace'):
        if 'output shards folded' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l); folded.append(d)
    allr = [d for d in rows]
    tot = {k: sum(int(d[k]) for d in allr if k in d and d[k].isdigit()) for k in ('rename_fallbacks', 'rename_record_waits')}
    cd = sorted({d.get('carried_depth') for d in allr if 'carried_depth' in d})
    print(f'== {tag}: execution and root fields (median / p90 per block); over {len(allr)} full builds: rename_fallbacks total {tot["rename_fallbacks"]}, rename_record_waits total {tot["rename_record_waits"]}, carried_depth values {cd}')
    for w in range(int(os.environ.get('W339', '3'))):
        r = [d for d in rows if t0 + 30 * w <= d['_t'] < t0 + 30 * (w + 1)]
        if not r: continue
        out = []
        for k in KEYS:
            v = [float(d[k]) for d in r if k in d and NUM.fullmatch(d[k])]
            if v: out.append(f'{k} {st.median(v):,.0f}/{pct(v, .9):,.0f}')
        sh = [float(d['batch_cpu_sum_us']) / float(d['batch_wall_sum_us']) for d in r if float(d.get('batch_wall_sum_us', 0) or 0) > 0 and 'batch_cpu_sum_us' in d]
        pt = [float(d['batch_cpu_sum_us']) / float(d['txs']) for d in r if 'batch_cpu_sum_us' in d]
        fw = [d for d in folded if t0 + 30 * w <= d['_t'] < t0 + 30 * (w + 1)]
        pm = [float(d[k]) for d in fw for k in ('pending_max',) if k in d]; pu = [float(d['pending_us_max']) for d in fw if 'pending_us_max' in d]; dm = [float(d['drops_max']) for d in fw if 'drops_max' in d]
        if fw: print(f'    folded lines {len(fw)}: pending_max max {max(pm or [0]):.0f} (median {st.median(pm or [0]):.0f}); pending_us_max max {max(pu or [0]):,.0f}; drops_max max {max(dm or [0]):.0f}')
        bl = []
        for k in BOOLS:
            vs = [d.get(k) for d in r if k in d]
            if vs: bl.append(f'{k} ' + '/'.join(f'{v}:{vs.count(v)}' for v in sorted(set(vs))))
        sk = [float(d['sealed_at_ms']) / (float(d['txs']) / 1000) for d in r if 'sealed_at_ms' in d]
        print('    flags: ' + '; '.join(bl) + f'; seal per 1,000 transfers {st.median(sk) if sk else float("nan"):.3f} ms')
        print(f'  window {w + 1} ({len(r)} builds): on-CPU share {st.median(sh) if sh else float("nan"):.2f}/{pct(sh, .9):.2f}; CPU per transfer {st.median(pt) if pt else float("nan"):.2f}/{pct(pt, .9):.2f} us; ' + '; '.join(out))
