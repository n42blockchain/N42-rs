#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop346 (docs 10.92): a compact table of fields345.py's output for the report. usage: fieldsum345.py <out file>... -- prints per leg and window (1, 2) median / p90 of the seal-path fields and the flag shares."""
import re, sys
L = []
for f in sys.argv[1:]: L += open(f, errors='replace').read().split('\n')
keys = ['sealed_at_ms', 'par_exec_ms', 'par_fold_ms', 'index_ms', 'par_start_ms', 'gap_before_exec_ms', 'state_wait_us', 'parent_fields_ms', 'roots_ms', 'seal_to_fields_us', 'seal_to_complete_us', 'rename_fallbacks', 'rename_record_waits', 'carried_depth']
cur = None; res = {}; flags = {}
for l in L:
    m = re.match(r'== loop346(\w+): execution and root fields', l)
    if m: cur = m[1]; res[cur] = {}; flags[cur] = []; continue
    if cur and l.startswith('    flags:'): flags[cur].append(l.strip())
    m = re.match(r'  window (\d) \(\d+ builds\): on-CPU share ([\d.]+)/([\d.]+); CPU per transfer ([\d.]+)/([\d.]+) us; (.*)', l)
    if m and cur: res[cur][int(m[1])] = {k: (a, b) for k, a, b in re.findall(r'(\w+) ([\d,]+)/([\d,]+)', m[6])}
print('leg | window | ' + ' | '.join(keys))
for t, w in res.items():
    for n in (1, 2):
        r = w.get(n)
        if r: print(t, n, ' | '.join('/'.join(r.get(k, ('-', '-'))) for k in keys))
    if flags[t]: print('   ', t, flags[t][0][:260], '||', flags[t][1][:260] if len(flags[t]) > 1 else '')
