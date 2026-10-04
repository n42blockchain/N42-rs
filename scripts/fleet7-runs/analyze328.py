#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop328 (docs 10.76; shared execution, F7_EL_MAP). usage: analyze328.py <tag> ...   (tag = e.g. loop328E1)
The runner copies one `node<e>-el.log` per execution LAYER (e = 0..layers-1) and one `node<i>-v.log` per validator, so nothing here pairs
them. Window 1 = the first 30 s after the first full (txs >= 100,000) seal-first build on layer 0. Per leg: the leader's build-phase medians/p90
(sealed_at_ms, par_ms, par_exec_ms, roots_ms, parent_fields_ms, sealed_ms) and transactions per block; the proposal cycle mean/median/p90
(validator 0's `proposal sent` lines); the execution layer's and the validators' CPU in cores busy in window 1 (threadcpu: cumulative CPU
seconds, summed over thread groups); the layer's peak RSS and in-memory block maximum (memsample); the import-once counters (`once_*` on the
`direct import` lines, cumulative) and the start-up `import_once` line; the queue depth through window 1; the flood's delivery; the
persistence batches (node0 metrics) in ms per full block; and any timeout certificate / handover line with its time against the leg's start."""
import os, re, statistics as st, sys, time
from datetime import datetime
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
def m3(x): return f'{st.median(x):.1f}/{pct(x, .9):.1f}' if x else '-'
def num(v):
    try: return float(v)
    except ValueError: return None
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'
    print(f'== {tag}')
    el = [ansi.sub('', l) for l in open(f'{root}/node0-el.log', errors='replace')]
    t0 = None; builds = []; q = []; once = {}; locks = 0
    for l in el:
        if 'seal-first build phases' in l:
            d = dict(KV.findall(l)); t = ts(l)
            if int(d['txs']) >= 100000:
                t0 = t0 or t
                if t - t0 < 30: builds.append(d)
        elif 'canonical blocks pruned from the queue' in l and t0:
            q.append((ts(l) - t0, int(dict(KV.findall(l))['queued'])))
        elif 'direct import: executed here' in l:
            d = dict(KV.findall(l))
            if 'once_imports' in d: once = d
        if "queue's lock was held or waited for a second" in l: locks += 1
    if not builds: print('  no full build'); continue
    g = lambda k: [num(d[k]) for d in builds if k in d and num(d[k]) is not None]
    print(f'  layer-0 leader window-1 builds {len(builds)}: txs mean {st.mean(g("txs")):.0f}, share >= 95% of the tier {sum(1 for x in g("txs") if x >= 0.95 * max(g("txs"))) / len(builds) * 100:.0f}% (max {max(g("txs")):.0f}); ' + '; '.join(f'{k} {m3(g(k))}' for k in ('sealed_at_ms', 'par_ms', 'par_exec_ms', 'roots_ms', 'parent_fields_ms', 'sealed_ms')))
    pts = [ts(ansi.sub('', l)) for l in open(f'{root}/node0-v.log', errors='replace') if 'proposal sent' in l]
    cyc = [(b - a) * 1e3 for a, b in zip(pts, pts[1:]) if t0 - 1 <= a <= t0 + 30 and 0 < (b - a) * 1e3 < 2000]
    if cyc: print(f'  proposal cycle window 1 (n={len(cyc)}): mean {st.mean(cyc):.1f} median {st.median(cyc):.1f} p90 {pct(cyc, .9):.1f} ms; blocks in the 30 s: {len(cyc)}')
    gm = time.localtime(t0).tm_gmtoff; a, b = t0 + gm, t0 + 30 + gm
    rows = {}
    try:
        for l in open(f'{S}/threadcpu-{tag}.tsv'):
            f = l.rstrip('\n').split('\t')
            if len(f) == 5 and f[1] in ('el', 'val'):
                rows.setdefault((f[1], f[2]), {}).setdefault(float(f[0]), 0.0)
                rows[(f[1], f[2])][float(f[0])] += float(f[4])
    except OSError: pass
    def busy(role):
        tot = 0.0; n = 0
        for (r, nd), series in rows.items():
            if r != role: continue
            x = [(t, v) for t, v in sorted(series.items()) if a <= t <= b]
            if len(x) > 1 and x[-1][0] > x[0][0]: tot += (x[-1][1] - x[0][1]) / (x[-1][0] - x[0][0]); n += 1
        return tot, n
    e, ne = busy('el'); v, nv = busy('val')
    print(f'  CPU in window 1 (cores busy): execution layers {e:.1f} over {ne} process(es); validators {v:.1f} over {nv} process(es)')
    try:
        mem = [l.split() for l in open(f'{S}/strip-{tag}/mem.log')]
        rss = [float(x[4].split('=')[1]) for x in mem if len(x) > 6 and x[4].startswith('rss_g=') and x[4][6:] != '-']
        nb = [int(x[6].split('=')[1]) for x in mem if len(x) > 6 and x[6].startswith('num=') and x[6][4:].isdigit()]
        print(f'  execution layer peak RSS {max(rss):.1f} G; in-memory blocks max {max(nb)} (node0 and others, all layers)')
    except Exception as ex: print(f'  memsample: {ex}')
    print(f'  import-once counters at the last direct import: ' + ' '.join(f'{k}={once[k]}' for k in ('once_reqs', 'once_served', 'once_imports', 'once_blocks', 'once_takeovers') if k in once) + f'; start-up lines with import_once=true: {sum("import_once=true" in l for l in el)}; queue-lock lines {locks}')
    if once and num(once.get('once_blocks', 0)):
        nb_ = num(once['once_blocks']); print(f'    per block: imports {num(once["once_imports"]) / nb_:.2f}, reqs {num(once["once_reqs"]) / nb_:.2f}, served {num(once["once_served"]) / nb_:.2f}')
    if q: print('  layer-0 queue (queued after canonical prune), median per 10 s: ' + ' '.join(f't+{x}:{st.median(y for t, y in q if x <= t < x + 10):.0f}' for x in range(0, 120, 20) if any(x <= t < x + 10 for t, _ in q)))
    try:
        fl = [l for l in open(f'{root}/flood.log', errors='replace')]
        rates = [int(m[1]) for l in fl for m in [re.match(r'flood \+\s*\d+s: sent \d+ \((\d+)/s\)', l)] if m]
        fin = [re.match(r'flood\s+: (\d+) accepted, (\d+) rejected, ([\d.]+)s, (\d+)/s', l) for l in open(f'{root}/round.txt')]; fin = [m for m in fin if m]
        print(f'  flood: median per 5 s {st.median(rates) if rates else 0:.0f}/s, final ' + (f'{fin[-1][1]} accepted {fin[-1][2]} rejected {fin[-1][3]}s' if fin else '-'))
    except OSError: pass
    tcs = []
    for i in range(7):
        for l in open(f'{root}/node{i}-v.log', errors='replace'):
            l = ansi.sub('', l)
            if 'TC formed' in l or 'was not the one committed' in l or 'could not build a block to propose' in l: tcs.append((l[:26], i, re.sub(r'^\S+\s+', '', l.strip())[:110]))
    tcs.sort(); print(f'  timeout / given-up lines: {len(tcs)}; ' + '; '.join(f'{x[0][11:19]} v{x[1]} {x[2][:70]}' for x in tcs[:4]))
