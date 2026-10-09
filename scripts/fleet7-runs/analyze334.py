#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop334 (docs 10.81; E=1, windows from the execution layer's canonical-block log). usage: analyze334.py <tag> ...   (tag = e.g. loop334G80)
Run analyze328.py on the same tags for persistence, import-once counters, timeouts and the flood's final line.
Windows are the bench's own: contiguous 30 s from the first canonical block with >= 100,000 transactions on layer 0 (`node0-el.log`).
Per leg and per window: canonical blocks, transactions, rate, full share (gas >= 95%); proposal cycle mean/median/p90 (validator 0's `proposal sent`
lines); the leader's `sealed_at_ms` median/p90/p99 and the phase medians (gap_before_exec, state_wait with the `state_wait_on` cause counts, par, par_exec,
roots, parent_fields, sealed); the binding wait (tick / quorum / seal / feed) shares; queue depth at the builds (minimum / median) and the flood's delivered
rate; execution-layer cores busy (threadcpu); layer RSS at both ends of the window and its in-memory block maximum (memsample); the engine's own-import
time per block (`handed to the engine as executed`, total_ms) and the slowest key's vote delay. For the whole leg: peak RSS, the fields-at-seal counters,
`own_executed_again` (blocks built here that were also directly imported), and every field of the build line that loop333's lines did not have
(the leader-layers / opener fields of the loop334 binary): numeric ones as median / p90 / max per window, text ones as counts."""
import glob, importlib.util, os, re, statistics as st, sys
from collections import Counter
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
def m3(x): return f'{st.median(x):.0f}/{pct(x, .9):.0f}/{pct(x, .99):.0f}' if x else '-'
def m2(x): return f'{st.median(x):.0f}/{pct(x, .9):.0f}' if x else '-'
def num(v):
    try: return float(v)
    except ValueError: return None
PHASES = ('gap_before_exec_ms', 'state_wait_ms', 'par_ms', 'par_exec_ms', 'roots_ms', 'parent_fields_ms', 'sealed_ms')
def known_keys():
    for f in sorted(glob.glob(f'{B}/bench-loop333G80/node0-el.log')):
        for l in open(f, errors='replace'):
            if 'seal-first build phases' in l: return set(dict(KV.findall(ansi.sub('', l))))
    return set()
KNOWN = known_keys()
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'; print(f'== {tag}  (E=1: seven validator keys on one execution layer)')
    log = f'{root}/node0-el.log'
    canon = measure.log_blocks(log)
    full = [c for c in canon if c[2] >= 100000]
    if not full: print('  no full canonical block'); continue
    t0 = full[0][0]
    builds, own_imp, built, directed = [], [], {}, {}
    for l in open(log, errors='replace'):
        if 'seal-first build phases' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l)); d['t'] = ts(l); builds.append(d)
            if 'number' in d: built[int(d['number']) + 1] = d
        elif 'handed to the engine as executed' in l:
            l = ansi.sub('', l); d = dict(KV.findall(l))
            if 'total_ms' in d: own_imp.append((ts(l), float(d['total_ms'])))
        if 'direct import: executed here' in l:  # also carries 'handed to the engine as executed', so not an elif
            m = re.search(r'number=(\d+)', ansi.sub('', l))
            if m: directed[int(m[1])] = 1
    num_builds = [{k: (num(v) if num(v) is not None else v.strip('"')) for k, v in d.items()} for d in builds]
    P, Pd, Tp, Qc, votes = {}, {}, {}, {}, {}
    for i in range(7):
        try: f = open(f'{root}/node{i}-v.log', errors='replace')
        except OSError: continue
        for l in f:
            l = ansi.sub('', l)
            if i == 0 and 'proposal sent view=' in l:
                d = dict(KV.findall(l)); P[int(d['view'])] = ts(l); Pd[int(d['view'])] = d
            elif i == 0 and 'proposal preamble view=' in l: Tp[int(dict(KV.findall(l))['view'])] = ts(l)
            elif i == 0 and 'block committed!' in l: Qc[int(dict(KV.findall(l))['view'])] = ts(l)
            elif 'sending vote to leader' in l:
                d = dict(KV.findall(l)); votes.setdefault(int(d['view']), {})[i] = ts(l)
    mem = []
    try:
        for l in open(f'{S}/strip-{tag}/mem.log'):
            if ' node0 ' not in l: continue
            m = re.match(r'(\d+\.\d+) .* rss_g=([\d.]+) num=(\d+)', l)
            if m: mem.append((float(m[1]), float(m[2]), int(m[3])))
    except OSError: pass
    cpu = {}
    try:
        for l in open(f'{S}/threadcpu-{tag}.tsv'):
            f = l.rstrip('\n').split('\t')
            if len(f) == 5 and f[1] in ('el', 'val'): cpu.setdefault(f[1], {}).setdefault(float(f[0]), 0.0); cpu[f[1]][float(f[0])] += float(f[4])
    except OSError: pass
    rates = []
    try:
        rates = [int(m[1]) for l in open(f'{root}/flood.log', errors='replace') for m in [re.match(r'flood \+\s*\d+s: sent \d+ \((\d+)/s\)', l)] if m]
    except OSError: pass
    base = None; tot = 0
    newkeys = sorted(k for k in {k for d in num_builds for k in d} - KNOWN - {'t'}) if KNOWN else []
    for w in range(3):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        cw = [c for c in canon if a <= c[0] < b]
        if not cw: print(f'  window {w + 1}: no canonical blocks'); continue
        txs = sum(c[2] for c in cw); rate = txs / 30; tot += txs
        if base is None: base = rate
        nfull = sum(1 for c in cw if c[3] >= 95.0)
        pts = sorted(t for t in P.values() if a - 1 <= t <= b)
        cyc = [(y - x) * 1e3 for x, y in zip(pts, pts[1:]) if 0 < (y - x) * 1e3 < 2000]
        print(f'  window {w + 1}: canonical {len(cw)} blocks, {txs / 1e6:.1f}M tx = {rate:,.0f}/s ({rate / base:.1%} of window 1), full {nfull}/{len(cw)} ({nfull / len(cw):.0%}); '
              + (f'cycle mean/median/p90 {st.mean(cyc):.1f}/{st.median(cyc):.1f}/{pct(cyc, .9):.1f} ms' if cyc else 'cycle -'))
        bw = [d for d in num_builds if a <= d['t'] < b and d.get('txs', 0) >= 100000]
        if bw:
            g = lambda k: [d[k] for d in bw if isinstance(d.get(k), float)]
            print(f'    leader builds {len(bw)}: sealed_at median/p90/p99 {m3(g("sealed_at_ms"))}; phases median/p90 ms: ' + ', '.join(f'{k[:-3]} {m2(g(k))}' for k in PHASES))
            ons = Counter(d.get('state_wait_on', '-') for d in bw); slow = [d for d in bw if (d.get('state_wait_ms') or 0) > 20]
            print(f'    state_wait_on {dict(ons)}; builds with state_wait > 20 ms: {len(slow)} ({Counter(d.get("state_wait_on") for d in slow).most_common(3)}); gp_layer {dict(Counter(d.get("gp_layer") for d in bw))}, ggp_missing {dict(Counter(d.get("ggp_missing") for d in bw))}')
            q = g('queued')
            if q: print(f'    queue at the builds min/median {min(q):,.0f}/{st.median(q):,.0f}')
            for k in newkeys:
                vals = [d[k] for d in bw if k in d]
                if not vals: continue
                if all(isinstance(v, float) for v in vals): print(f'    new field {k}: median/p90/max {st.median(vals):.1f}/{pct(vals, .9):.1f}/{max(vals):.0f}, nonzero {sum(1 for v in vals if v)}')
                else: print(f'    new field {k}: {dict(Counter(vals).most_common(5))}')
        W = [v for v in sorted(P) if a <= P[v] < b and v - 1 in P and v in Tp and v - 1 in Qc]
        if W:
            cls = {'tick': [], 'quorum': [], 'seal': [], 'feed': []}
            for v in W:
                take = float(Pd[v].get('take_sealed_us', 0)) / 1e3
                q_at = num(Pd[v].get('queued', '1e9')) if 'queued' in Pd[v] else None
                c = 'seal' if take > 3 else ('quorum' if (Tp[v] - Qc[v - 1]) * 1e3 < 10 and Tp[v] > P[v - 1] + 0.103 else 'tick')
                cls[c].append((P[v] - P[v - 1]) * 1e3)
            print('    binding wait (tick / quorum / seal share, mean cycle): ' + '; '.join(f'{c} {len(x) / len(W) * 100:.0f}% ({st.mean(x):.0f})' if x else f'{c} 0%' for c, x in cls.items() if c != 'feed') + f'; feed-bound (blocks under 95% of the tier): {len(cw) - nfull} of {len(cw)}')
            worst = []
            for v in W:
                vv = votes.get(v, {})
                if len(vv) >= 5: worst.append(max((t - P[v]) * 1e3 for t in vv.values()))
            if worst: print(f'    slowest key vote delay median/p90 {st.median(worst):.1f}/{pct(worst, .9):.1f} ms')
        oi = [x for t, x in own_imp if a <= t < b]
        if oi: print(f'    engine own-import total_ms per block median/p90/max {st.median(oi):.0f}/{pct(oi, .9):.0f}/{max(oi):.0f} (n={len(oi)})')
        ms = [m for m in mem if a - 2 <= m[0] <= b + 2]
        if ms: print(f'    layer RSS {ms[0][1]:.1f} -> {ms[-1][1]:.1f} G (max {max(m[1] for m in ms):.1f}), in-memory blocks max {max(m[2] for m in ms)}')
        for role, name in (('el', 'execution layer'), ('val', 'validators')):
            x = [(t, v) for t, v in sorted(cpu.get(role, {}).items()) if a <= t <= b]
            if len(x) > 1 and x[-1][0] > x[0][0]: print(f'    {name} cores busy {(x[-1][1] - x[0][1]) / (x[-1][0] - x[0][0]):.1f}', end='')
        print()
        if rates: print(f'    flood delivered (median per 5 s over the leg) {st.median(rates):,.0f}/s') if w == 0 else None
    print(f'  round total (3 windows, canonical): {tot / 1e6:.1f}M tx')
    if mem: print(f'  layer peak RSS {max(m[1] for m in mem):.1f} G; in-memory blocks max {max(m[2] for m in mem)}')
    if builds:
        last = builds[-1]
        print(f'  fields at seal: mode {last.get("fields_at_seal")}, verified {last.get("fields_verified")}, unchecked {last.get("fields_unchecked")}, mismatches {last.get("fields_mismatches")} (last build line, cumulative)')
    both = sorted(set(built) & set(directed))
    print(f'  own_executed_again (built here and also directly imported): {len(both)} of {len(built)} built blocks')
