#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop338 (docs 10.85): the lanes lock, the drain and the pruner per leg, from the new fields (scope section 11.4) in the three 30 s windows from the first
full canonical block on layer 0 (as analyze334.py). usage: feed338.py <tag> ...
`ingest` line (5 s): lock_duty_pct, lock_hold_max_us with its holder lock_hold_max_at, lock_wait_us / lock_wait_max_us, drains, drain_txs, drain_us_mean / max,
plus the rate and the semaphore wait. `canonical blocks pruned` line (per block): prune_ms, fold_us, lock_us, remove_us (now the hold alone), free_us,
frames_swept, coalesced, prune_wait_ms."""
import importlib.util, os, re, statistics as st, sys
from collections import Counter
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=(\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
def med(x): return st.median(x) if x else float('nan')
for tag in sys.argv[1:]:
    log = f'{B}/bench-{tag}/node0-el.log'
    try: full = [c for c in measure.log_blocks(log) if c[2] >= 100000]
    except Exception as e: print(f'== {tag}: {e}'); continue
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; ing, pr = [], []
    for l in open(log, errors='replace'):
        if ' ingest frames=' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l); ing.append(d)
        elif 'canonical blocks pruned from the queue' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['_t'] = ts(l)
            if int(d.get('mined', 0)) >= 100000: pr.append(d)
    print(f'== {tag}: lanes lock, drain and pruner (new fields)')
    for w in range(3):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        iw = [d for d in ing if a <= d['_t'] < b]; pw = [d for d in pr if a <= d['_t'] < b]
        g = lambda rows, k: [float(d[k]) for d in rows if k in d and re.fullmatch(r'-?[\d.]+', d[k])]
        who = Counter(d.get('lock_hold_max_at') for d in iw if 'lock_hold_max_at' in d).most_common(2)
        mx = max(iw, key=lambda d: float(d.get('lock_hold_max_us', 0)), default={})
        print(f'  window {w + 1}: lock duty {med(g(iw, "lock_duty_pct")):.1f}% (max {max(g(iw, "lock_duty_pct") or [0]):.1f}); holds/5s {med(g(iw, "lock_holds")):,.0f}; '
              f'longest hold {med(g(iw, "lock_hold_max_us")) / 1e3:.2f} ms median, {max(g(iw, "lock_hold_max_us") or [0]) / 1e3:.2f} ms max by {mx.get("lock_hold_max_at", "-")} (most frequent holders {who}); '
              f'lock wait {med(g(iw, "lock_wait_us")) / 1e3:.1f} ms/5s, longest {max(g(iw, "lock_wait_max_us") or [0]) / 1e3:.2f} ms; '
              f'drains/5s {med(g(iw, "drains")):,.0f} of {med(g(iw, "drain_txs")) / max(1, med(g(iw, "drains"))):.0f} tx, mean {med(g(iw, "drain_us_mean")):.0f} us, max {max(g(iw, "drain_us_max") or [0]) / 1e3:.2f} ms')
        if pw:
            print(f'           prune ({len(pw)} blocks): prune_ms {med(g(pw, "prune_ms")):.0f}/{pct(g(pw, "prune_ms"), .9):.0f}; fold {med(g(pw, "fold_us")) / 1e3:.1f} ms, lock {med(g(pw, "lock_us")) / 1e3:.1f} ms, '
                  f'remove(hold) {med(g(pw, "remove_us")) / 1e3:.1f} ms, free {med(g(pw, "free_us")) / 1e3:.1f} ms; frames_swept {med(g(pw, "frames_swept")):.0f}; '
                  f'coalesced on {sum(1 for x in g(pw, "coalesced") if x > 0)} of {len(pw)}; prune_wait_ms {med(g(pw, "prune_wait_ms")):.0f}/{pct(g(pw, "prune_wait_ms"), .9):.0f}; '
                  f'pruner busy {sum(g(pw, "prune_ms")) / 30e3:.0%} of a thread, lock held by it {sum(g(pw, "lock_us")) / 30e6:.1%}')
