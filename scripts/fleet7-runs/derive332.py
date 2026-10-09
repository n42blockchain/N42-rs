#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop332.sh / launch-loop332.sh (the E=1 peak, docs 10.79) from the loop331 pair. Base B = loop331 B32 (build pool 32, rayon 16, all 208
CPUs, E=1, N42_IMPORT_ONCE=1) with the feed raised: F7_FLOOD_RATE=4000000 (loop331's 2,000,000 was the whole of its delivery ceiling: every flood
line read 2.000M/s while the ingest was 15% busy) and F7_BENCH_POOL_SLOTS=2000000 (the ingest gate follows it: 5/6, 1.667M). Legs: WARM, B80, B80b, then
B70 / B60 / B50 (a step is skipped once the leg before it shows the seal or the feed binding on more than a third of blocks), G80 and G100 (200,000
transfers a block), X (the best leg by window 1 among those with at least 95% full blocks and the seal binding under a third) and Xb. Gates of loop331
stay (free space 120G a leg, stale-binary check, test gate, claim, 75-minute cap, headers, memsample, datadir wipe)."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop331.sh').read().replace('loop331', 'loop332')
lines = run.split('\n')
def leg_line(name):
    i = [k for k, l in enumerate(lines) if l.startswith(f'leg {name} ')]
    assert len(i) == 1, name
    return i[0]
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
warm, b32 = lines[leg_line('WARM')], lines[leg_line('B32')]
assert 'F7_FLOOD_RATE=2000000' in b32 and 'F7_BENCH_POOL_SLOTS=1000000' in b32 and 'F7_BLOCK_INTERVAL_MS=100' in b32 and 'F7_EL_MAP=0,0,0,0,0,0,0' in b32
assert 'F7_GASCEIL_ARG' not in b32 and 'N42_PARALLEL_BUILD_THREADS=32' in b32
def base_line(name, *edits):
    l = b32.replace('leg B32 ', f'leg {name} ', 1)
    assert l.startswith(f'leg {name} ')
    for k, v in (('F7_FLOOD_RATE', '4000000'), ('F7_BENCH_POOL_SLOTS', '2000000')) + edits: l = set_tok(l, k, v)
    return l
wl = base_line('WARM', ('F7_BLOCK_INTERVAL_MS', '80'))
guard_i = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop332WARM')]
assert len(guard_i) == 1
# the base legs are generated as shell: B80 / B80b literal lines, then the dynamic part reuses their tokens
B80 = base_line('B80', ('F7_BLOCK_INTERVAL_MS', '80'))
B80b = base_line('B80b', ('F7_BLOCK_INTERVAL_MS', '80'))
dyn = r'''
# one leg's verdict: window 1, the full share, the seal's share of the binding waits ("tag win1 fullshare sealshare")
jud() { python3 - $1 <<'PYEOF'
import re, subprocess, sys
t = sys.argv[1]; B = '/data/blockchain/rust-fleet7-bench'
try:
    r = open(f'{B}/bench-loop332{t}/round.txt').read()
    w = int(re.search(r'win1 +tps= *([\d,]+)', r)[1].replace(',', ''))
    m = re.search(r'win1 .*full\(>=95%\)=(\d+)/(\d+)', r); full = int(m[1]) / max(1, int(m[2]))
    out = subprocess.run(['python3', 'scripts/fleet7-runs/analyze328.py', f'loop332{t}'], capture_output=True, text=True).stdout
    m = re.search(r'seal ([\d.]+)%', out); seal = float(m[1]) / 100 if m else 0.0
    print(t, w, round(full, 3), round(seal, 3))
except Exception as e:
    print(t, 0, 0, 1, file=sys.stdout)
PYEOF
}
STOP=0
for P in 70 60 50; do
  if [ $STOP = 1 ]; then echo "B$P skipped: the step before it showed the seal or the feed binding on more than a third of blocks"; continue; fi
  leg B$P "${LA_B80[@]}" F7_BLOCK_INTERVAL_MS=$P
  V=$(jud B$P); echo "verdict B$P (tag, window 1, full share, seal share): $V"
  set -- $V
  if python3 -c "import sys; sys.exit(0 if float('$3') < 0.667 else 1)"; then echo "B$P: the feed or the selection was short on more than a third of blocks (full share $3)"; STOP=1; fi
  if python3 -c "import sys; sys.exit(0 if float('$4') > 0.333 else 1)"; then echo "B$P: the seal binds more than a third of blocks (seal share $4)"; STOP=1; fi
done
leg G80 "${LA_B80[@]}" F7_BLOCK_INTERVAL_MS=80 F7_GASCEIL_ARG=4200000000
leg G100 "${LA_B80[@]}" F7_BLOCK_INTERVAL_MS=100 F7_GASCEIL_ARG=4200000000
BESTX=$(python3 - <<'PYEOF'
import subprocess
tags = [t for t in 'B80 B80b B70 B60 B50 G80 G100'.split()]
best = None
for t in tags:
    out = subprocess.run(['bash', '-c', f'cd /home/n42/src/n42/n42-rs; true'], capture_output=True)
print('')
PYEOF
)
BEST=""; BW=0
for T in B80 B80b B70 B60 B50 G80 G100; do
  [ -f $B/bench-loop332$T/round.txt ] || continue
  V=$(jud $T); set -- $V
  if python3 -c "import sys; sys.exit(0 if float('$3') >= 0.95 and float('$4') <= 0.333 else 1)"; then
    if [ "$2" -gt "$BW" ]; then BW=$2; BEST=$T; fi
  fi
done
echo "X is the best leg by window 1 with full blocks and the seal not binding: ${BEST:-none} ($BW)"
if [ -n "$BEST" ]; then eval "xargs_=(\"\${LA_$BEST[@]}\")"; leg X "${xargs_[@]}"; leg Xb "${xargs_[@]}"; fi
'''
dyn = re.sub(r"BESTX=\$\(python3 - <<'PYEOF'.*?PYEOF\n\)\n", '', dyn, flags=re.S)
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
lines[legs[0]:legs[-1] + 1] = [wl, lines[guard_i[0]], B80, B80b] + dyn.split('\n')
run = '\n'.join(lines)
# headers also name the feed knobs
pat = 'F7_EL_MAP|'
assert run.count(pat) >= 1
run = run.replace(pat, 'F7_FLOOD_RATE|F7_BENCH_POOL_SLOTS|N42_TX_INGEST_HIGH_WATER|F7_EL_MAP|')
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop332 = the E=1 peak (docs 10.79): base B = loop331 B32 with the feed raised (rate 4.0M, pool 2.0M, gate 5/6). Legs WARM, B80, B80b, B70, B60, B50 (a step is skipped once the leg before shows the seal or the feed binding on a third of blocks), G80, G100 (200,000 a block), X (best leg by window 1 with full blocks) and Xb. Free-space gate 120G a leg.\n', 1)
open(D + 'run-loop332.sh', 'w').write(run)
open(D + 'launch-loop332.sh', 'w').write(open(D + 'launch-loop331.sh').read().replace('loop331', 'loop332'))
