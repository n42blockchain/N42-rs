#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop331.sh / launch-loop331.sh (E=1 with the re-execution fix, docs 10.78) from the loop330 pair. Legs: WARM (E=1), R (loop330's T96
line exactly: build pool 96, rayon 48, all 208 CPUs), Rb, B32 (build pool 32, rayon from $R, i.e. loop330's A208), then RP90, RP80, RP70 (R at that
pacing, each only when the best leg so far has a median sealed_at under the pacing plus 10 ms), RFS (R + N42_FIELDS_AT_SEAL=1), RG (R at 200,000
transfers a block), BESTb (a repeat of the single leg with the highest window 1). Gates of loop330 stay (free space 120G a leg, stale-binary check,
test gate with n42 --lib, claim, 75-minute cap, headers, memsample, datadir wipe at the end)."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop330.sh').read().replace('loop330', 'loop331')
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
warm, t96, a208 = lines[leg_line('WARM')], lines[leg_line('T96')], lines[leg_line('A208')]
assert 'N42_PARALLEL_BUILD_THREADS=96' in t96 and 'RAYON_NUM_THREADS=48' in t96 and 'F7_EL_CPUS' not in t96 and 'F7_GASCEIL_ARG' not in t96
assert 'F7_EL_MAP=0,0,0,0,0,0,0' in t96 and '$ONCE' in t96
def mk(src, old, name, *edits):
    l = src.replace(f'leg {old} ', f'leg {name} ', 1)
    assert l.startswith(f'leg {name} ')
    for k, v in edits: l = set_tok(l, k, v)
    return l
static = [warm, None, mk(t96, 'T96', 'R'), mk(t96, 'T96', 'Rb'), mk(a208, 'A208', 'B32')]
dyn = r'''
# best leg so far by window 1 among the given tags: prints "tag win1 median-sealed_at"
bestof() { python3 - "$@" <<'PYEOF'
import re, statistics as st, sys
B = '/data/blockchain/rust-fleet7-bench'; S = '/data/n42-build/target-n42-rs/fleet-runs'
best = None
for t in sys.argv[1:]:
    try:
        v = int(re.search(r'win1 +tps= *([\d,]+)', open(f'{B}/bench-loop331{t}/round.txt').read())[1].replace(',', ''))
    except Exception: continue
    if best is None or v > best[0]: best = (v, t)
if best:
    sa = []
    try:
        for l in open(f'{S}/strip-loop331{best[1]}/el.log', errors='replace'):
            if 'seal-first build phases' in l and 'txs=163000' in l:
                m = re.search(r' sealed_at_ms=(\d+)', l)
                if m: sa.append(int(m[1]))
    except Exception: pass
    print(best[1], best[0], int(st.median(sa)) if sa else 9999)
PYEOF
}
TRIED="R Rb B32"
for P in 90 80 70; do
  BEST=$(bestof $TRIED); set -- $BEST; BS=${3:-9999}
  echo "pacing $P: best so far (tag, window 1, median sealed_at ms): $BEST"
  if [ "$BS" -lt $((P + 10)) ]; then leg RP$P "${LA_R[@]}" F7_BLOCK_INTERVAL_MS=$P; TRIED="$TRIED RP$P"
  else echo "RP$P skipped: the best leg's median sealed_at is ${BS} ms, not under $((P + 10))"; fi
done
leg RFS "${LA_R[@]}" N42_FIELDS_AT_SEAL=1
leg RG "${LA_R[@]}" F7_GASCEIL_ARG=4200000000
TRIED="$TRIED RFS"
BEST=$(bestof $TRIED); set -- $BEST
echo "best single leg (tag, window 1, median sealed_at ms): $BEST"
if [ -n "$1" ]; then eval "bargs=(\"\${LA_$1[@]}\")"; leg BESTb "${bargs[@]}"; fi
'''
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
guard_i = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop331WARM')]
assert len(guard_i) == 1
static[1] = lines[guard_i[0]]
lines[legs[0]:legs[-1] + 1] = [x for x in static] + dyn.split('\n')
run = '\n'.join(lines)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop331 = E=1 with the re-execution fix (docs 10.78): R = loop330 T96 knobs on the fixed binary (625bceb1a, 1fa8abd0b). Legs WARM, R, Rb, B32 (build 32 / rayon 16), RP90/RP80/RP70 (only when the best leg so far seals under the pacing + 10 ms), RFS (fields at seal), RG (200,000 transfers a block), BESTb (repeat of the best single leg). Free-space gate 120G a leg.\n', 1)
open(D + 'run-loop331.sh', 'w').write(run)
open(D + 'launch-loop331.sh', 'w').write(open(D + 'launch-loop330.sh').read().replace('loop330', 'loop331'))
