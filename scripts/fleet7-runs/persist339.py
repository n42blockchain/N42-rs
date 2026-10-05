#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop339 (docs 10.86): persistence lag per window from memsample.py's 2 s lines (node0 of the leg's mem.log). usage: persist339.py <tag> ...
Windows as analyze334.py (30 s from the first full canonical block on layer 0). Per window: blocks persisted (sum of save_blocks batch sizes), mean persistence ms
per block (save_blocks_total) and its sf_transactions / qmdb_persisted parts, in-memory blocks at the window's start and end (median of the 3 samples around the
edge) and the maximum, the persisted height gap (latest - persisted, persisted = earliest - 1) at both edges and its growth in blocks per minute, and the
canonical blocks of the window (so persisted / canonical says whether it keeps up)."""
import importlib.util, os, re, statistics as st, sys
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
for tag in sys.argv[1:]:
    canon = [c for c in measure.log_blocks(f'{B}/bench-{tag}/node0-el.log')]
    full = [c for c in canon if c[2] >= 100000]
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; rows = []
    path = f'{S}/strip-{tag}/mem.log'
    for l in open(path, errors='replace'):
        if ' node0 ' not in l: continue
        d = dict(re.findall(r'(\w+)=(\S+)', l)); t = float(l.split()[0])
        try: rows.append((t, {k: float(v) for k, v in d.items() if k not in ('pid',) and re.fullmatch(r'-?[\d.e+-]+', v)}))
        except ValueError: pass
    def at(t):
        r = min(rows, key=lambda x: abs(x[0] - t)); return r[1]
    print(f'== {tag}: persistence per window (memsample node0, 2 s)')
    prev = None
    for w in range(int(os.environ.get('W339', '3'))):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        A, Bq = at(a), at(b)
        if 'bs_sum' not in A or 'bs_sum' not in Bq: print('  no persistence columns'); break
        n = Bq['bs_sum'] - A['bs_sum']; ms = (Bq['sb_sum'] - A['sb_sum']) * 1e3 / n if n else float('nan')
        sft = (Bq.get('sft_sum', 0) - A.get('sft_sum', 0)) * 1e3 / n if n else float('nan'); qp = (Bq.get('qp_sum', 0) - A.get('qp_sum', 0)) * 1e3 / n if n else float('nan')
        win = [r for t, r in rows if a <= t < b]
        gap = lambda r: r['latest'] - (r['earliest'] - 1)
        g0 = st.median([gap(r) for t, r in rows if a - 3 <= t <= a + 3] or [gap(A)]); g1 = st.median([gap(r) for t, r in rows if b - 3 <= t <= b + 3] or [gap(Bq)])
        nb = sum(1 for c in canon if a <= c[0] < b)
        print(f'  window {w + 1}: persisted {n:.0f} blocks of {nb} canonical ({100 * n / max(1, nb):.0f}%); {ms:.1f} ms/block persistence (sf_transactions {sft:.1f}, qmdb_persisted {qp:.1f}); '
              f'in-memory blocks {A["num"]:.0f} -> {Bq["num"]:.0f} (max {max(r["num"] for r in win):.0f}); lag latest-persisted {g0:.0f} -> {g1:.0f} blocks = {(g1 - g0) * 2:+.1f} blocks/min; bp max {max(r.get("bp", 0) for r in win):.0f}')
    tail = rows[-1][1]; first = at(t0 + 90)
    print(f'  leg end: in-memory {tail["num"]:.0f}, gap {tail["latest"] - (tail["earliest"] - 1):.0f}, max in-memory over the sampler {max(r["num"] for _, r in rows):.0f}, backpressure stalls {tail.get("stall_n", 0):.0f}')
