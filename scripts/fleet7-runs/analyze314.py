#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Tables B and C of docs 10.62: perf stat per second and vmstat deltas against slow blocks.
usage: analyze314.py <tag> [<fleet-bench-dir>]   (reads target/fleet-runs/*-<tag>*)"""
import re, sys, glob, statistics as st
from datetime import datetime, timezone
S = '/home/n42/src/n42/n42-rs/target/fleet-runs'
tag = sys.argv[1]
B = (sys.argv[2] if len(sys.argv) > 2 else '/data/blockchain/rust-fleet3-bench') + '/bench-' + tag
ansi = re.compile(r'\x1b\[[0-9;]*m')
def ts(l): return datetime.strptime(ansi.sub('', l)[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc).timestamp()
def kv(l): return {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', ansi.sub('', l))}
t0 = int(re.search(r'T0_ms=(\d+)', open(f'{S}/prof-{tag}.t0').read()).group(1))
t0 = t0 / 1e9 if t0 > 1e15 else t0 / 1000  # the first loop314 sampler wrote nanoseconds
# slow events as (start, end) in epoch seconds
slow = []; vslow = []; allseal = []; allimp = []
for i in range(3):
    for l in open(f'{B}/node{i}-el.log', errors='replace'):
        if 'seal-first build phases' in l and 'txs=163000' in l:
            d = kv(l); e = ts(l); allseal.append(d['sealed_at_ms'])
            a = e - d['total_ms'] / 1000
            if d['sealed_at_ms'] > 120: slow.append((a, a + d['sealed_at_ms'] / 1000, f'seal{i}'))
            if d['sealed_at_ms'] > 160: vslow.append((a, a + d['sealed_at_ms'] / 1000, f'seal{i}'))
        elif 'direct import: executed here' in l and 'txs=163000' in l:
            d = kv(l); e = ts(l); allimp.append(d['fields_ready_ms'])
            a = e - d['total_ms'] / 1000
            if d['fields_ready_ms'] > 130: slow.append((a, a + d['fields_ready_ms'] / 1000, f'imp{i}'))
            if d['fields_ready_ms'] > 170: vslow.append((a, a + d['fields_ready_ms'] / 1000, f'imp{i}'))
slow = [s for s in slow if t0 - 1 <= s[1] <= t0 + 101]
vslow = [s for s in vslow if t0 - 1 <= s[1] <= t0 + 101]
print(f'{tag}: slow events in the 100 s after T0: {len(slow)} (seal {sum(1 for s in slow if s[2].startswith("seal"))}, imp {sum(1 for s in slow if s[2].startswith("imp"))}); '
      f'sealed_at median {st.median(allseal):.0f}, fields_ready median {st.median(allimp):.0f}')
# ---- B: perf stat
print('\n== B: perf stat per node (60 s, 1 s rows)')
for i in range(3):
    f = f'{S}/perfstat-{tag}-node{i}.csv'
    rows = {}
    for l in open(f):
        p = l.strip().split(',')
        if len(p) < 4 or l.startswith('#'): continue
        try: t = float(p[0]); v = float(p[1])
        except ValueError: continue
        rows.setdefault(round(t), {})[p[3]] = v
    secs = sorted(rows)
    if not secs or 'instructions' not in rows[secs[0]]:
        print(f'node{i}: no perf stat rows'); continue
    def ipc(r): return r['instructions'] / r['cycles'] if r.get('cycles') else 0
    tot = {k: sum(rows[s].get(k, 0) for s in secs) for k in rows[secs[0]]}
    n = len(secs)
    print(f'node{i}: IPC {tot["instructions"]/tot["cycles"]:.2f}  cache-miss/1k-instr {1000*tot["cache-misses"]/tot["instructions"]:.2f}  dTLB-miss/1k-instr {1000*tot["dTLB-load-misses"]/tot["instructions"]:.2f}  '
          f'cpus {tot["task-clock"]/1000/n:.1f}  ctx-sw/s {tot["context-switches"]/n:.0f}  migr/s {tot["cpu-migrations"]/n:.0f}  faults/s {tot["page-faults"]/n:.0f}')
    ipcs = [ipc(rows[s]) for s in secs]
    slowsec = [s for s in secs if any(a <= t0 + s and t0 + s - 1 <= b for a, b, _ in slow)]
    oth = [s for s in secs if s not in slowsec]
    mean = lambda xs: sum(xs) / len(xs) if xs else float('nan')
    print(f'   IPC by second: ' + ' '.join(f'{x:.2f}' for x in ipcs[::2]) + '   (every 2nd s)')
    print(f'   seconds with a slow block {len(slowsec)}: IPC {mean([ipc(rows[s]) for s in slowsec]):.3f} vs {mean([ipc(rows[s]) for s in oth]):.3f} others; '
          f'cache-miss/1k {mean([1000*rows[s]["cache-misses"]/rows[s]["instructions"] for s in slowsec]):.2f} vs {mean([1000*rows[s]["cache-misses"]/rows[s]["instructions"] for s in oth]):.2f}')
    worst = sorted(secs, key=lambda s: ipc(rows[s]))[:6]
    print(f'   6 worst-IPC seconds {[(s, round(ipc(rows[s]),2), s in slowsec) for s in worst]} (second, IPC, has slow block)')
def mean(x): return sum(x) / len(x)
# ---- C: vmstat
def table(slow, name):
  print(f'\n== C: vmstat deltas per 0.5 s, intervals overlapping [{name}] against the rest')
  rows = [l.rstrip('\n').split('\t') for l in open(f'{S}/vmstat-{tag}.tsv')]
  hdr = rows[0]; data = rows[1:]
  T = [int(r[0]) / 1000 for r in data]
  level = {'nr_dirty', 'nr_writeback'}
  mark = []
  for k in range(len(data) - 1):
      a, b = T[k], T[k + 1]
      mark.append(any(x <= b and a <= y for x, y, _ in slow))
  ns = sum(mark); print(f'intervals {len(mark)}, slow-marked {ns}')
  out = []
  for j, c in enumerate(hdr[1:], 1):
      try: vals = [float(r[j]) for r in data]
      except ValueError: continue
      if c.endswith('_kb') or c.startswith('psi_') and 'avg10' in c: d = vals[:-1]
      elif c in level: d = vals[:-1]
      else: d = [vals[k + 1] - vals[k] for k in range(len(vals) - 1)]
      sm = [x for x, m in zip(d, mark) if m]; ot = [x for x, m in zip(d, mark) if not m]
      ms, mo = mean(sm) if sm else 0, mean(ot) if ot else 0
      out.append((c, ms, mo))
  print(f'{"counter":28s} {"slow mean":>14s} {"other mean":>14s} {"ratio":>7s}')
  for c, ms, mo in out:
      r = ms / mo if mo else (float('inf') if ms else 1.0)
      flag = '  <-- >2x' if (r > 2 and not c.endswith('_kb') and 'total' not in c) else ''
      print(f'{c:28s} {ms:14.1f} {mo:14.1f} {r:7.2f}{flag}')

table(slow, 'slow: sealed_at>120 or fields_ready>130 ms, span road start to seal/fields')
table(vslow, 'very slow: sealed_at>160 or fields_ready>170 ms')
