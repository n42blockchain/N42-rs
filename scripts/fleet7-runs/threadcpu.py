#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Per-thread-name CPU of the fleet's processes, sampled every 5 s: where a node's cores go.
usage: threadcpu.py <seconds> > out.tsv   (rows: t, role, node, comm-group, cpu_seconds_cumulative)"""
import os, re, sys, time, glob
HZ = os.sysconf('SC_CLK_TCK')
def procs():
    out = []
    for p in glob.glob('/proc/[0-9]*'):
        try:
            cmd = open(p + '/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace')
        except OSError:
            continue
        m = re.search(r'rust-fleet7-bench/node(\d)', cmd)
        if not m: continue
        role = 'el' if '/n42 node' in cmd or ' node ' in cmd else ('val' if 'h2_validator' in cmd else None)
        if role: out.append((p, role, int(m.group(1))))
    fl = [p for p in glob.glob('/proc/[0-9]*') if b'tx_flood' in (open(p + '/cmdline', 'rb').read() if os.path.exists(p + '/cmdline') else b'')]
    return out, fl
def group(comm):
    return re.sub(r'[-_#:]?\d+$', '', comm.strip()) or comm
def snap(p):
    acc = {}
    for t in glob.glob(p + '/task/*/stat'):
        try:
            s = open(t).read()
        except OSError:
            continue
        comm = s[s.index('(') + 1:s.rindex(')')]
        f = s[s.rindex(')') + 2:].split()
        acc[group(comm)] = acc.get(group(comm), 0) + (int(f[11]) + int(f[12])) / HZ
    return acc
end = time.time() + float(sys.argv[1])
while time.time() < end:
    ps, fl = procs()
    now = time.time()
    for p, role, node in ps:
        for g, v in snap(p).items():
            print(f'{now:.1f}\t{role}\t{node}\t{g}\t{v:.2f}')
    for p in fl:
        for g, v in snap(p).items():
            print(f'{now:.1f}\tflood\t-\t{g}\t{v:.2f}')
    sys.stdout.flush()
    time.sleep(5)
