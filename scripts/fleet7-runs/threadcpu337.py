#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop337 (docs 10.84): CPU of every `tokio-rt*` (and, from loop338, `n42-ingest*` / `n42-queue*`) thread of the execution layer, per thread id, every 5 s. The group view of threadcpu4.py adds the 8 main
runtime workers and the blocking pool into one number; this one tells whether any single worker is saturated.
usage: threadcpu337.py sample <seconds> [node index, default 0] > out.tsv     (rows: t, tid, comm, cumulative cpu seconds)
       threadcpu337.py report out.tsv                                         (threads alive for the whole flood: cores busy, median per 5 s)"""
import glob, os, statistics as st, sys, time
HZ = os.sysconf('SC_CLK_TCK')
def find(node):
    for p in glob.glob('/proc/[0-9]*'):
        try: c = open(p + '/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace')
        except OSError: continue
        if '/n42 node' in c and f'rust-fleet7-bench/node{node}/' in c: return p
if sys.argv[1] == 'sample':
    p = find(int(sys.argv[3]) if len(sys.argv) > 3 else 0)
    if not p: sys.exit(0)
    end = time.time() + float(sys.argv[2])
    while time.time() < end:
        now = time.time()
        for t in glob.glob(p + '/task/*/stat'):
            try: s = open(t).read()
            except OSError: continue
            comm = s[s.index('(') + 1:s.rindex(')')]
            if comm.startswith(('tokio-rt', 'n42-ingest', 'n42-queue')):
                f = s[s.rindex(')') + 2:].split()
                print(f'{now:.1f}\t{os.path.basename(os.path.dirname(t))}\t{comm}\t{(int(f[11]) + int(f[12])) / HZ:.2f}', flush=True)
        time.sleep(5)
else:
    rows = {}
    for l in open(sys.argv[2]):
        t, tid, comm, c = l.rstrip('\n').split('\t'); rows.setdefault(tid, {})[float(t)] = float(c)
    ts = sorted({t for r in rows.values() for t in r})
    # the flood: the samples where the whole group together burned over 3 cores
    tot = {b: sum(r.get(b, 0) - r.get(a, 0) for r in rows.values() if a in r and b in r) / (b - a) for a, b in zip(ts, ts[1:])}
    busy = [b for b, v in tot.items() if v > 3]
    if not busy: print('no busy samples'); sys.exit(0)
    a0, b0 = ts[ts.index(min(busy)) - 1], max(busy)
    full = {tid: r for tid, r in rows.items() if a0 in r and b0 in r}
    per = {tid: (r[b0] - r[a0]) / (b0 - a0) for tid, r in full.items()}
    top = sorted(per.values(), reverse=True)
    print(f'flood span {b0 - a0:.0f} s; tokio-rt threads alive throughout {len(full)} of {len(rows)}; group {sum(per.values()):.1f} cores busy over them (all threads incl. short-lived {sum(tot[b] for b in busy) / len(busy):.1f})')
    print('  per-thread cores busy, top 12: ' + ' '.join(f'{v:.2f}' for v in top[:12]) + f'; threads over 0.9 core: {sum(1 for v in top if v > 0.9)}, over 0.7: {sum(1 for v in top if v > 0.7)}')
