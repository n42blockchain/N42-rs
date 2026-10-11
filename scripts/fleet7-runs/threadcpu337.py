#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop337 (docs 10.84): CPU of every `tokio-rt*` (and, from loop338, `n42-ingest*` / `n42-queue*`) thread of the execution layer, per thread id, every 5 s. The group view of threadcpu4.py adds the 8 main
runtime workers and the blocking pool into one number; this one tells whether any single worker is saturated.
From loop351 stage at the sampler records every thread of the process, enumerating /proc/<pid>/task afresh on each sample (rayon pools and
other threads born after the first sample used to be missed by the name filter); `report` still looks at the old groups only, `families`
sums every thread by name family.
usage: threadcpu337.py sample <seconds> [node index, default 0] > out.tsv     (rows: t, tid, comm, cumulative cpu seconds)
       threadcpu337.py report out.tsv                                         (threads alive for the whole flood: cores busy, median per 5 s)
       threadcpu337.py families out.tsv [t0 t1]                               (cores busy per thread-name family between t0 and t1, default the whole file)"""
import glob, os, re, statistics as st, sys, time
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
        try: tids = os.listdir(p + '/task')   # afresh every sample: pools born later are included
        except OSError: break
        for tid in tids:
            try: s = open(f'{p}/task/{tid}/stat').read()
            except OSError: continue
            comm = s[s.index('(') + 1:s.rindex(')')]
            f = s[s.rindex(')') + 2:].split()
            print(f'{now:.1f}\t{tid}\t{comm}\t{(int(f[11]) + int(f[12])) / HZ:.2f}', flush=True)
        time.sleep(5)
elif sys.argv[1] == 'families':
    # family = the name without a separated trailing number (n42-build-12 -> n42-build; n42 and tokio-rt-worker stay)
    fam = lambda c: re.sub(r'[-_ .#]+[0-9]+$', '', c) or c
    rows, names = {}, {}
    for l in open(sys.argv[2]):
        t, tid, comm, c = l.rstrip('\n').split('\t'); rows.setdefault(tid, {})[float(t)] = float(c); names[tid] = comm
    ts = sorted({t for r in rows.values() for t in r})
    t0 = float(sys.argv[3]) if len(sys.argv) > 3 else ts[0]; t1 = float(sys.argv[4]) if len(sys.argv) > 4 else ts[-1]
    a = min(ts, key=lambda t: abs(t - t0)); b = min(ts, key=lambda t: abs(t - t1))
    out = {}
    for tid, r in rows.items():
        # a thread born inside the span counts from its first sample, one that ended counts to its last
        ins = [t for t in r if a <= t <= b]
        if len(ins) < 2: continue
        k = fam(names[tid]); o = out.setdefault(k, [0.0, 0])
        o[0] += r[max(ins)] - r[min(ins)]; o[1] += 1
    print(f'span {b - a:.0f} s ({a:.1f}..{b:.1f}); family, threads, cores busy')
    for k, (c, n) in sorted(out.items(), key=lambda kv: -kv[1][0]):
        print(f'{k}\t{n}\t{c / (b - a):.2f}')
else:
    rows = {}
    for l in open(sys.argv[2]):
        t, tid, comm, c = l.rstrip('\n').split('\t')
        if not comm.startswith(('tokio-rt', 'n42-ingest', 'n42-queue')): continue
        rows.setdefault(tid, {})[float(t)] = float(c)
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
