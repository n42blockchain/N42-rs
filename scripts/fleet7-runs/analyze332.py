#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop332 (docs 10.79). usage: analyze332.py <tag> ...   (run analyze328.py on the same tags for the rest).
Feed figures per leg: the flood's offered rate (header) and delivered rate per 5 s (median, p10 over the samples before the first worker ran out), the
ingest lines' stage figures on layer 0 (rate, slots_busy_pct, reply_us_per_frame, gate_us_per_frame, busy_us_per_tx, recover_us_per_tx) in window 1,
seconds of full blocks sustained (from the first full build to the first build under 95% of the tier, and whether that was the end of the replay
set), the flood's cores busy in window 1 (threadcpu), and the throttle / given-up / timeout lines per validator."""
import re, statistics as st, sys
from datetime import datetime
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').timestamp()
def pct(x, q): x = sorted(x); return x[min(len(x) - 1, int(len(x) * q))] if x else float('nan')
for tag in sys.argv[1:]:
    root = f'{B}/bench-{tag}'; print(f'== {tag}')
    fl = open(f'{root}/flood.log', errors='replace').read()
    off = re.search(r'rate\s+: rate=(\d+)/s', fl)
    rates = []; ran_out_at = None
    for l in fl.split('\n'):
        m = re.match(r'flood \+\s*(\d+)s: sent \d+ \((\d+)/s\)', l)
        if m: rates.append((int(m[1]), int(m[2])))
        if 'ran out' in l and ran_out_at is None and rates: ran_out_at = rates[-1][0]
    use = [r for t, r in rates if ran_out_at is None or t <= ran_out_at]
    use = use[1:] if len(use) > 1 else use      # the first 5 s carries the limiter's burst
    print(f'  feed: offered {off[1] if off else "?"}/s; delivered per 5 s median {st.median(use):,.0f} p10 {pct(use, .1):,.0f} (n={len(use)}; first sample {rates[0][1] if rates else 0:,} not counted); first worker out of frames at +{ran_out_at}s; final line: {(re.findall(r'flood +: .*accepted.*', fl) or ['?'])[-1][:90]}')
    el = [ansi.sub('', l) for l in open(f'{root}/node0-el.log', errors='replace')]
    builds = []; ing = []
    for l in el:
        if 'seal-first build phases' in l:
            d = dict(KV.findall(l)); builds.append((ts(l), int(d['txs'])))
        elif ' INFO ingest frames=' in l: ing.append((ts(l), dict(KV.findall(l))))
    if not builds: print('  no builds'); continue
    tier = max(t for _, t in builds)
    full = [(t, n) for t, n in builds if n >= 100000]
    t0 = full[0][0]; end = None; nfull = 0
    for t, n in builds:
        if t < t0: continue
        if n >= 0.95 * tier: nfull += 1
        elif end is None and t - t0 > 5: end = t
    tail = builds[-1][0]
    sus = (end if end else tail) - t0
    print(f'  full blocks (>= 95% of {tier}): sustained {sus:.0f} s from the first full build to {"the first short block" if end else "the last build"}; {nfull} full builds in all; builds in window 1 {sum(1 for t, _ in builds if t0 <= t < t0 + 30)}')
    w = [d for t, d in ing if t0 <= t <= t0 + 30]
    g = lambda k: [float(d[k]) for _, d in [(0, x) for x in w] if k in d]
    if w: print('  ingest on layer 0 in window 1 (median): ' + ', '.join(f'{k} {st.median(g(k)):.0f}' for k in ('rate', 'slots_busy_pct', 'reply_us_per_frame', 'gate_us_per_frame', 'busy_us_per_tx', 'recover_us_per_tx')))
    # flood cores busy in window 1: slope of the summed cumulative cpu seconds of the flood threads
    byt = {}
    try:
        for l in open(f'{S}/threadcpu-{tag}.tsv'):
            r = l.rstrip('\n').split('\t')
            if len(r) >= 5 and r[1] == 'flood': byt[float(r[0])] = byt.get(float(r[0]), 0) + float(r[4])
        k = sorted(byt); a = [x for x in k if x >= t0]; b = [x for x in k if x >= t0 + 30]
        if a and b: print(f'  flood cores busy in window 1: {(byt[b[0]] - byt[a[0]]) / (b[0] - a[0]):.2f}')
    except OSError: pass
    vl = [ansi.sub('', l) for n in range(7) for l in open(f'{root}/node{n}-v.log', errors='replace')]
    pr = [dict(KV.findall(x)) for x in vl if 'proposal sent' in x and 'throttle_delay_ms' in x]
    late = [float(d['tick_late_us']) / 1e3 for d in pr if 'tick_late_us' in d]
    print(f'  proposals {len(pr)}: throttle delayed {sum(1 for d in pr if float(d["throttle_delay_ms"]) > 0)} (max delay {max([float(d["throttle_delay_ms"]) for d in pr] or [0]):.0f} ms, hard holds {sum(int(d["throttle_hard_holds"]) for d in pr)} max unpersisted {max([int(d["throttle_in_mem"]) for d in pr] or [0])}); tick_late median/p90 {st.median(late):.1f}/{pct(late, .9):.1f} ms; given up (proposals) {sum("given up" in x and "proposal" in x for x in vl)}; TC formed {sum("TC formed" in x for x in vl)}')
