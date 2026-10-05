#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop337 (docs 10.84): the feed check per leg. usage: feed337.py <tag> ...
For each of the three 30 s windows from the first full canonical block on layer 0 (as analyze334.py), from the layer's 5 s `ingest` lines and the
`seal-first build phases` lines: the recovery-semaphore acquire wait (acq_us_per_frame), the gate wait (gate_us_per_frame), the reply time, the delivered
rate per `ingest` line (median / max), the queue at the builds (median / min), the slots busy share, and the full-block share. The flood's own per-5 s
rate and reply latency come from flood.log over the same 90 s (the flood's clock starts at its funding line, so it is read as a whole)."""
import importlib.util, os, re, statistics as st, sys
from datetime import datetime, timezone
B = '/data/blockchain/rust-fleet7-bench'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
ansi = re.compile(r'\x1b\[[0-9;]*m'); KV = re.compile(r'(\w+)=(\S+)')
def ts(l): return datetime.strptime(l[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def med(x): return st.median(x) if x else float('nan')
for tag in sys.argv[1:]:
    log = f'{B}/bench-{tag}/node0-el.log'
    try: canon = measure.log_blocks(log)
    except Exception as e: print(f'== {tag}: {e}'); continue
    full = [c for c in canon if c[2] >= 100000]
    if not full: print(f'== {tag}: no full block'); continue
    t0 = full[0][0]; blk = max(c[2] for c in canon)
    ing, q = [], []
    for l in open(log, errors='replace'):
        if ' ingest frames=' in l:
            l = ansi.sub('', l); d = {k: v for k, v in KV.findall(l)}; d['_t'] = ts(l); ing.append(d)
        elif 'seal-first build phases' in l:
            l = ansi.sub('', l); d = {k: v for k, v in KV.findall(l)}
            if 'queued' in d and int(d.get('txs', 0)) >= 0.9 * blk: q.append((ts(l), int(d['queued'])))
    print(f'== {tag}: feed check (acq_us / gate_us / reply_us are per frame of 500; rate per 5 s `ingest` line)')
    for w in range(int(os.environ.get('W339', '3'))):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        iw = [d for d in ing if a <= d['_t'] < b]; qw = [x for t, x in q if a <= t < b]
        cw = [c for c in canon if a <= c[0] < b]
        fs = sum(1 for c in cw if c[3] >= 95.0) / max(1, len(cw))
        g = lambda k: [float(d[k]) for d in iw if k in d]
        rate = g('rate')
        print(f'  window {w + 1}: ingest lines {len(iw)}; acq_us {med(g("acq_us_per_frame")):.0f} (max {max(g("acq_us_per_frame") or [0]):.0f}); gate_us {med(g("gate_us_per_frame")):.0f}; '
              f'reply_us {med(g("reply_us_per_frame")):.0f}; slots_busy {med(g("slots_busy_pct")):.0f}%; delivered median {med(rate):,.0f}/s max {max(rate or [0]):,.0f}/s; '
              f'queue at builds median {med(qw):,.0f} min {min(qw or [0]):,.0f}; full {fs:.0%} of {len(cw)} blocks')
    fl = [l for l in open(f'{B}/bench-{tag}/flood.log', errors='replace') if l.startswith('flood +')]
    r, lat = [], []
    for l in fl:
        m = re.match(r'flood \+\s*(\d+)s: sent \d+ \((\d+)/s\).*reply ms/node \[([\d.]+)', l)
        if m: r.append((int(m[1]), int(m[2]), float(m[3])))
    rr = [x[1] for x in r if 15 <= x[0] <= 100]; ll = [x[2] for x in r if 15 <= x[0] <= 100]
    if rr: print(f'  flood.log (+15..+100 s): rate per 5 s median {med(rr):,.0f}/s max {max(rr):,.0f}/s; reply latency median {med(ll):.1f} ms max {max(ll):.1f} ms')
