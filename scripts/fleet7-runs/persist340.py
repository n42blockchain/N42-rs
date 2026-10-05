#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop340 (docs 10.87): the persistence batch taken apart per window, from memsample.py's 2 s lines of the layer (node0 of the leg's mem.log).
usage: persist340.py <tag> ...   (W339 = number of windows, default 3; windows as analyze334.py: 30 s from the first full canonical block on layer 0)
Per window: blocks persisted of blocks produced; ms per block of save_blocks_total and of each part (sf_transactions, sf_receipts, sf_account_changesets, sf_senders,
scope, qmdb_persisted, post_scope, plain_reverts / pre_scope, the commits); the longest task of the scope; in-memory blocks and RSS at both edges and the maximum;
the persisted-height lag at both edges and its growth in blocks per minute (flat = within +/-6 blocks a minute and the in-memory blocks at the end not above the start + 6)."""
import importlib.util, os, re, statistics as st, sys
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
PARTS = [('sb_sum', 'total'), ('sft_sum', 'sf_tx'), ('sfr_sum', 'sf_rcpt'), ('sfa_sum', 'sf_acct'), ('sfs_sum', 'sf_send'), ('scope_sum', 'scope'), ('qp_sum', 'qmdb'),
         ('post_sum', 'post'), ('pre_sum', 'pre'), ('pr_sum', 'plain_rev'), ('csf_sum', 'commit_sf'), ('cmd_sum', 'commit_mdbx'), ('crk_sum', 'commit_rocks')]
for tag in sys.argv[1:]:
    canon = measure.log_blocks(f'{B}/bench-{tag}/node0-el.log')
    full = [c for c in canon if c[2] >= 100000]
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; rows = []
    for l in open(f'{S}/strip-{tag}/mem.log', errors='replace'):
        if ' node0 ' not in l: continue
        d = dict(re.findall(r'(\w+)=(\S+)', l)); t = float(l.split()[0])
        r = {k: float(v) for k, v in d.items() if k != 'pid' and re.fullmatch(r'-?[\d.e+-]+', v)}
        rows.append((t, r))
    def at(t): return min(rows, key=lambda x: abs(x[0] - t))[1]
    print(f'== {tag}: persistence per window (ms per block = part sum / blocks persisted)')
    for w in range(int(os.environ.get('W339', '3'))):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        A, Bq = at(a), at(b)
        if 'bs_sum' not in A or 'sfr_sum' not in A: print('  no persistence columns'); break
        n = Bq['bs_sum'] - A['bs_sum']; nb = sum(1 for c in canon if a <= c[0] < b)
        ms = {nm: (Bq[k] - A[k]) * 1e3 / n for k, nm in PARTS if k in A and k in Bq and n}
        tasks = {nm: ms.get(nm, 0) for nm in ('sf_tx', 'sf_rcpt', 'sf_acct', 'sf_send')}
        longest = max(tasks, key=tasks.get)
        win = [r for t, r in rows if a <= t < b]; gap = lambda r: r['latest'] - (r['earliest'] - 1)
        g0 = st.median([gap(r) for t, r in rows if a - 3 <= t <= a + 3] or [gap(A)]); g1 = st.median([gap(r) for t, r in rows if b - 3 <= t <= b + 3] or [gap(Bq)])
        print(f'  window {w + 1}: persisted {n:.0f} of {nb} produced ({100 * n / max(1, nb):.0f}%); ' + ', '.join(f'{nm} {v:.1f}' for nm, v in ms.items()) + f'; longest task {longest} {tasks[longest]:.1f}; '
              f'in-memory {A["num"]:.0f} -> {Bq["num"]:.0f} (max {max(r["num"] for r in win):.0f}); RSS {A["rss_g"]:.1f} -> {Bq["rss_g"]:.1f} G; lag {g0:.0f} -> {g1:.0f} = {(g1 - g0) * 2:+.1f} blocks/min; bp max {max(r.get("bp", 0) for r in win):.0f}')
    tail = rows[-1][1]
    print(f'  leg end: in-memory {tail["num"]:.0f}, max over the sampler {max(r["num"] for _, r in rows):.0f}, backpressure stalls {tail.get("stall_n", 0):.0f}')
