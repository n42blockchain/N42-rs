#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop321/322: the leader build throttle (docs 10.69) and the persistence phases (10.70). usage:
  analyze321.py throttle <tag> ...   per leader from the validators' "proposal sent" lines: share of proposals delayed, delay
                                     median/p90 when applied, total delay, hard holds, max-hold WARN lines, throttle_in_mem distribution
  analyze321.py persist <tag> ...    every save_blocks_* histogram of each node's metrics file: ms per batch and per FULL block
                                     (full = a persisted block that carried transactions: the node's "Block added to canonical
                                     chain" lines with txs > 0, unique numbers, below the metrics' in_mem earliest block, i.e.
                                     those already written; ms per persisted block of any kind is shown for the totals line)"""
import re, sys, statistics as st
B = '/data/blockchain/rust-fleet3-bench'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def pc(x, p): x = sorted(x); return x[min(len(x) - 1, int(len(x) * p))] if x else float('nan')
mode, tags = sys.argv[1], sys.argv[2:]
for tag in tags:
    root = f'{B}/bench-{tag}'
    if mode == 'throttle':
        print(f'== {tag}')
        for n in range(3):
            rows, warns = [], 0
            for l in open(f'{root}/node{n}-v.log', errors='replace'):
                l = ansi.sub('', l)
                if 'proposal sent view=' in l:
                    d = dict(KV.findall(l))
                    if 'throttle_in_mem' in d: rows.append((int(d['view']), int(d['throttle_in_mem']), int(d['throttle_delay_ms']), int(d['throttle_hard_holds'])))
                elif 'build throttle:' in l: warns += 1
            if not rows: continue
            known = [r for r in rows if r[1] < 10 ** 9]
            delayed = [r[2] for r in rows if r[2] > 0]
            print(f'  node{n}: proposals {len(rows)}, delayed {len(delayed)} ({len(delayed) / len(rows) * 100:.0f}%), delay when applied median/p90 {st.median(delayed) if delayed else 0:.0f}/{pc(delayed, .9) if delayed else 0:.0f} ms, '
                  f'total delay {sum(r[2] for r in rows) / 1000:.1f} s, hard_holds (last) {rows[-1][3]}, max-hold WARN lines {warns}, '
                  f'in_mem median/p90/max {st.median(r[1] for r in known):.0f}/{pc([r[1] for r in known], .9):.0f}/{max(r[1] for r in known)} (unknown {len(rows) - len(known)})')
    else:
        print(f'== {tag}')
        for n in range(3):
            d = {}
            for l in open(f'{root}/metrics-node{n}.txt', errors='replace'):
                m = re.match(r'(\S*save_blocks\S*?)_(sum|count) ([0-9.eE+-]+)$', l)
                if m: d.setdefault(m[1], {})[m[2]] = float(m[3])
            bs = d.get('reth_storage_providers_database_save_blocks_batch_size', {}).get('sum', 0)
            bc = d.get('reth_storage_providers_database_save_blocks_batch_size', {}).get('count', 0)
            earliest = None
            for l in open(f'{root}/metrics-node{n}.txt', errors='replace'):
                if l.startswith('reth_blockchain_tree_in_mem_state_earliest_block '): earliest = int(float(l.split()[1]))
            full = set()
            for l in open(f'{root}/node{n}-el.log', errors='replace'):
                if 'Block added to canonical chain' in l:
                    l = ansi.sub('', l); m = re.search(r'number=(\d+).* txs=(\d+)', l)
                    if m and int(m[2]) > 0 and (earliest is None or int(m[1]) < earliest): full.add(int(m[1]))
            nf = len(full)
            print(f'  node{n}: batches {bc:.0f}, blocks persisted {bs:.0f}, of them full {nf} ({bs / max(bc, 1):.1f} blocks/batch, {nf / max(bc, 1):.1f} full/batch)')
            for k, v in sorted(d.items(), key=lambda kv: -kv[1].get('sum', 0)):
                if k.endswith('batch_size'): continue
                s, c = v.get('sum', 0), v.get('count', 0)
                print(f'    {k.replace("reth_storage_providers_database_", "db.").replace("reth_consensus_engine_persistence_", "eng.")[:52]:52} sum {s:8.2f}s count {c:5.0f}  {s / max(c, 1) * 1000:8.1f} ms/call  {s / max(bc, 1) * 1000:8.1f} ms/batch  {s / max(nf, 1) * 1000:7.2f} ms/full block')
