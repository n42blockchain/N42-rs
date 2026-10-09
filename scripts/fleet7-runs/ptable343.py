#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop343 (docs 10.87): the persistence table from the runners' outputs (persist340.py lines). usage: ptable343.py <out file>... (prefix loop343)."""
import re, sys
cur, rows, order = None, {}, []
for f in sys.argv[1:]:
    for l in open(f, errors='replace'):
        m = re.match(r'== loop343(\w+): persistence per window', l)
        if m: cur = m[1]; rows[cur] = []; order.append(cur) if cur not in order else None; continue
        m = re.match(r'  window (\d): persisted (\d+) of (\d+) produced \((\d+)%\); (.*?); longest task (\w+) ([\d.]+); in-memory (\d+) -> (\d+) \(max (\d+)\); RSS ([\d.]+) -> ([\d.]+) G; lag \d+ -> \d+ = ([+-][\d.]+) blocks/min', l)
        if m and cur:
            parts = dict(re.findall(r'(\w+) ([\d.]+)', m[5])); rows[cur].append((m[4], parts, m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13]))
print('| leg | persisted % | total ms/block | sf_tx | sf_rcpt | sf_acct | sf_send | scope | qmdb | post | plain_rev | longest task | in-memory start->end (max) | RSS start -> end G (w1 / w3) | lag blocks/min |'); print('|' + ' --- |' * 15)
for t in order:
    r = rows[t]
    if len(r) < 3: continue
    g = lambda k: '/'.join(x[1].get(k, '-') for x in r)
    print(f"| {t} | {'/'.join(x[0] for x in r)} | {g('total')} | {g('sf_tx')} | {g('sf_rcpt')} | {g('sf_acct')} | {g('sf_send')} | {g('scope')} | {g('qmdb')} | {g('post')} | {g('plain_rev')} | {'/'.join(x[2] + ' ' + x[3] for x in r)} | {' / '.join(x[4] + '->' + x[5] + ' (' + x[6] + ')' for x in r)} | {r[0][7]}->{r[0][8]} / {r[2][7]}->{r[2][8]} | {'/'.join(x[9] for x in r)} |")
