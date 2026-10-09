#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop330.sh / launch-loop330.sh (E=1 tuning, docs 10.77) from the loop328 pair. Base = loop328's E1 line (seven validator keys on
one execution layer, N42_IMPORT_ONCE=1, loop326's N knob set). Legs: WARM (E=1), A (E1 pinned to 74 CPUs laid out like the three-node node 0:
F7_EL_CPUS=74 gives 0-36,128-164), Ab, A208 (the same knobs on all 208 CPUs), T64 (build pool 64, rayon 32), T64R64 (64 / 64), T96 (96 / 48),
then BP90 and BP80 (the best of A..T96 by window 1, at 90 and 80 ms pacing, only when that leg's median sealed_at is under 100 ms), BG (the best at
200,000 transfers a block), BR (the best again). The best leg's tokens are kept per leg in a bash array (LA_<tag>), so the later legs repeat them
exactly. Gates of loop328 stay (free-space gate, stale-binary check, test gate with n42 --lib, claim, 75-minute cap, headers, memsample)."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop328.sh').read().replace('loop328', 'loop330')
lines = run.split('\n')

def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else:
        toks.append(f'{key}={val}')
    new = ' '.join(toks)
    a = [t for t in line.split(' ') if not t.startswith(key + '=')]
    b = [t for t in new.split(' ') if not t.startswith(key + '=')]
    assert a == b, key
    return new

def leg_line(name):
    i = [k for k, l in enumerate(lines) if l.startswith(f'leg {name} ')]
    assert len(i) == 1, name
    return i[0]
warm, base = lines[leg_line('WARM')], lines[leg_line('E1')]
assert 'F7_EL_MAP=0,0,0,0,0,0,0' in base and '$ONCE' in base and 'N42_PARALLEL_BUILD_THREADS=32' in base and 'RAYON_NUM_THREADS' not in base
for k in ('F7_EL_CPUS', 'F7_GASCEIL_ARG'): assert k not in base, k
def mk(name, *edits):
    l = base.replace('leg E1 ', f'leg {name} ', 1)
    assert l.startswith(f'leg {name} ')
    for k, v in edits: l = set_tok(l, k, v)
    return l
# RAYON_NUM_THREADS lives in $R (RAYON_NUM_THREADS=16); a later token overrides it in `env`
static = [warm, mk('A', ('F7_EL_CPUS', '74')), mk('Ab', ('F7_EL_CPUS', '74')), mk('A208'),
          mk('T64', ('N42_PARALLEL_BUILD_THREADS', '64'), ('RAYON_NUM_THREADS', '32')),
          mk('T64R64', ('N42_PARALLEL_BUILD_THREADS', '64'), ('RAYON_NUM_THREADS', '64')),
          mk('T96', ('N42_PARALLEL_BUILD_THREADS', '96'), ('RAYON_NUM_THREADS', '48'))]
dyn = r'''
# --- the best of the static legs by window 1, and whether its seal is under 100 ms
BEST=$(python3 - <<'PYEOF'
import re, statistics as st, glob
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
ansi = re.compile(r'\x1b\[[0-9;]*m'); best = None
for t in ('A', 'Ab', 'A208', 'T64', 'T64R64', 'T96'):
    try:
        m = re.search(r'win1 +tps= *([\d,]+)', open(f'{B}/bench-loop330{t}/round.txt').read())
        v = int(m[1].replace(',', ''))
    except Exception: continue
    if best is None or v > best[0]: best = (v, t)
if best:
    sa = []
    try:
        for l in open(f'{S}/strip-loop330{best[1]}/el.log', errors='replace'):
            if 'seal-first build phases' in l and 'txs=163000' in l:
                m = re.search(r' sealed_at_ms=(\d+)', l)
                if m: sa.append(int(m[1]))
    except Exception: pass
    print(best[1], best[0], int(st.median(sa)) if sa else 9999)
PYEOF
)
echo "best of the static legs (tag, window 1, median sealed_at ms): $BEST"
set -- $BEST; BT=$1; BS=${3:-9999}
if [ -n "$BT" ]; then
  eval "bargs=(\"\${LA_${BT}[@]}\")"
  if [ "$BS" -lt 100 ]; then leg BP90 "${bargs[@]}" F7_BLOCK_INTERVAL_MS=90; leg BP80 "${bargs[@]}" F7_BLOCK_INTERVAL_MS=80
  else echo "BP90 and BP80 skipped: the best leg's median sealed_at is ${BS} ms, not under 100"; fi
  leg BG "${bargs[@]}" F7_GASCEIL_ARG=4200000000
  leg BR "${bargs[@]}"
fi
'''
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
guard_i = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop330WARM')]
assert len(guard_i) == 1
lines[legs[0]:legs[-1] + 1] = [static[0], lines[guard_i[0]]] + static[1:] + dyn.split('\n')
run = '\n'.join(lines)
old = "  local tag=$1; shift\n  local need=120"
assert run.count(old) == 1
run = run.replace(old, '  local tag=$1; shift\n  eval "LA_${tag}=(\\"\\$@\\")"\n  local need=120')
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop330 = E=1 tuning (docs 10.77): base = loop328 E1. Legs WARM, A (74 CPUs laid out like the three-node node 0), Ab, A208, T64 (build 64 / rayon 32), T64R64, T96 (96 / 48), then the best by window 1 at 90 and 80 ms pacing (only when its sealed_at median is under 100 ms), at 200,000 transfers a block, and a repeat. Free-space gate 120G a leg.\n', 1)
open(D + 'run-loop330.sh', 'w').write(run)
open(D + 'launch-loop330.sh', 'w').write(open(D + 'launch-loop328.sh').read().replace('loop328', 'loop330'))
