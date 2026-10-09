#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Top leaf symbols per thread family from a perf record (kernel-leaf samples are one `[kernel]` row). usage: famtop314.py <perf.data>"""
import subprocess, sys, re, collections
p = subprocess.Popen(['perf', 'script', '--no-inline', '-i', sys.argv[1], '-F', 'comm,ip,sym'], stdout=subprocess.PIPE, text=True, errors='replace')
fam = lambda c: re.sub(r'[-_:]?\d+$', '', c.strip()) or '?'
tot = collections.Counter(); sym = collections.defaultdict(collections.Counter); n = 0
comm = None; first = None
def flush():
    global n
    if comm is None or first is None: return
    f = fam(comm); n += 1; tot[f] += 1
    s = '[kernel]' if re.match(r'^\s+ffffffff[0-9a-f]{8}\b', first) else (first.strip().split(None, 1) + ['?'])[1][:100]
    sym[f][s] += 1
for line in p.stdout:
    if not line.strip(): flush(); comm = None; first = None; continue
    if not line.startswith(('\t', ' ')): flush(); first = None; comm = line.strip(); continue
    if first is None: first = line.rstrip()
flush()
print(f'{sys.argv[1]}: {n} samples')
for f, c in tot.most_common(7):
    print(f'-- {f}: {100*c/n:.1f}% of samples')
    for s, k in sym[f].most_common(6): print(f'   {100*k/c:5.1f}% of family  {s}')
