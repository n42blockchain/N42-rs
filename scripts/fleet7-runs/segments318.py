# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Leader build-chain medians over window 1 per leg (loop318 follow-up). usage: segments318.py BASE COMPACT ..."""
import re,sys,statistics as st
from datetime import datetime,timezone
ansi=re.compile(r'\x1b\[[0-9;]*m');KV=re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26],'%Y-%m-%dT%H:%M:%S.%f').timestamp()
keys='par_ms par_pull_ms par_prep_ms par_exec_ms par_collect_ms par_commit_ms par_fold_ms par_graft_ms parent_fields_ms sealed_ms sealed_at_ms state_ready_ms roots_ms total_ms shard_append_ms shard_merge_ms batch_max_ms batch_wait_ms par_start_ms next_start_gap_ms start_pull_ms'.split()
print('tag     '+' '.join(f'{k[:9]:>9}' for k in keys)+'  | own import by header: total handoff payload (n)')
for tag in sys.argv[1:]:
    rows=[];imps=[];t0=None
    for l in open(f'/data/blockchain/rust-fleet3-bench/bench-loop318{tag}/node0-el.log',errors='replace'):
        l=ansi.sub('',l)
        if 'seal-first build phases' in l:
            d=dict(KV.findall(l))
            if int(d['txs'])>=100000:
                t=ts(l); t0=t0 or t
                if t-t0<30: rows.append(d)
        elif 'imported by header' in l and t0 and ts(l)-t0<30:
            imps.append(dict(KV.findall(l)))
    f=lambda k:st.median(float(d[k]) for d in rows)
    g=lambda k:st.median(float(d[k]) for d in imps if k in d) if imps else float('nan')
    print(f'{tag:8}'+' '.join(f'{f(k):9.0f}' for k in keys)+f'  | {g("total_ms"):.0f} {g("handoff_ms"):.0f} {g("payload_ms"):.0f} ({len(imps)}) n={len(rows)}')
