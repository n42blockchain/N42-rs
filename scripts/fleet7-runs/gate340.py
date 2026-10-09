#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""loop340 (docs 10.87): the pacing steps' rule. usage: gate340.py <pacing ms of the previous step> <tag> [<tag> ...]  (tags with the loop prefix, e.g. loop340P3 loop340P3b).
Passes (prints `ok ...`, exit 0) when, for the best of the given legs, (1) the cycle median is within 3 ms of the pacing (cycmed336.py cycle <= pacing + 3) AND (2) the backlog is
not growing: the in-memory block count at the end of window 3 is at most 10 above its value at the end of window 1 and its maximum in window 3 is under 40. Otherwise prints
`FAIL cycle ...` or `FAIL backlog ...` (naming the test) and exits 1. A missing leg fails with `FAIL no data`."""
import importlib.util, os, re, subprocess, sys
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('measure', os.path.join(HERE, '..', 'fleet7-measure.py'))
measure = importlib.util.module_from_spec(spec); spec.loader.exec_module(measure)
pacing = float(sys.argv[1]); tags = sys.argv[2:]
res = []
for tag in tags:
    try:
        cyc = float(subprocess.run(['python3', os.path.join(HERE, 'cycmed336.py'), tag, 'cycle'], capture_output=True, text=True).stdout.strip())
        full = [c for c in measure.log_blocks(f'{B}/bench-{tag}/node0-el.log') if c[2] >= 100000]; t0 = full[0][0]
        rows = []
        for l in open(f'{S}/strip-{tag}/mem.log', errors='replace'):
            if ' node0 ' in l:
                d = dict(re.findall(r'(\w+)=(\S+)', l))
                try: rows.append((float(l.split()[0]), float(d['num'])))
                except (KeyError, ValueError): pass
        e1 = min(rows, key=lambda r: abs(r[0] - (t0 + 30)))[1]; e3 = min(rows, key=lambda r: abs(r[0] - (t0 + 90)))[1]
        mx3 = max(n for t, n in rows if t0 + 60 <= t <= t0 + 90)
        res.append((tag, cyc, e1, e3, mx3))
    except Exception as e:
        res.append((tag, None, None, None, str(e)[:60]))
good = [r for r in res if r[1] is not None]
if not good: print('FAIL no data', res); sys.exit(1)
best = min(good, key=lambda r: r[1])
cyc_ok = best[1] <= pacing + 3; back_ok = (best[3] - best[2] <= 10) and best[4] < 40
msg = f'cycle median {best[1]:.1f} ms against {pacing:.0f} (limit {pacing + 3:.0f}); in-memory blocks end of w1 {best[2]:.0f}, end of w3 {best[3]:.0f}, max in w3 {best[4]:.0f} ({best[0]})'
if cyc_ok and back_ok: print('ok', msg); sys.exit(0)
print(('FAIL cycle ' if not cyc_ok else 'FAIL backlog ') + msg); sys.exit(1)
