#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop336.sh / launch-loop336.sh (claim 1: WARM, P60, P60b, W, Wb, WR) and run-loop336b.sh / launch-loop336b.sh (claim 2: WARM2, R, Rb, WRb,
WR50 when WR's cycle median is under 66 ms, WRT64, WR250 at loop335 S250's sealed_at median + 12 ms) for loop336 (docs 10.83) from loop335's runner.
Base P60 = loop334 L3FS60 (N42_LEADER_LAYERS=3, N42_FIELDS_AT_SEAL=1, 200,000 a block, 60 ms, 400M set). W = + N42_BUILD_ONE_WAVE=1, R = + N42_ROAD_RUNTIME=1.
The sources are built in the git worktree /data/n42-build/wt335 (the main tree carries another agent's uncommitted work); the scripts there use its paths."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop335.sh').read()
def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else: toks.append(f'{key}={val}')
    return ' '.join(toks)
def derive(suffix):
    run = base_run.replace('loop335', 'loop336')
    lines = run.split('\n')
    g = [l for l in lines if l.startswith('legf P70 ')]
    assert len(g) == 1; p = g[0]
    assert 'N42_LEADER_LAYERS=3' in p and 'N42_FIELDS_AT_SEAL=1' in p and 'F7_GASCEIL_ARG=4200000000' in p and 'F7_BLOCK_INTERVAL_MS=70' in p
    def mk(name, *edits, fn='legf'):
        l = p.replace('legf P70 ', f'{fn} {name} ', 1)
        l = set_tok(l, 'F7_BLOCK_INTERVAL_MS', '60')
        for k, v in edits: l = set_tok(l, k, v)
        return l
    W = ('N42_BUILD_ONE_WAVE', '1'); R = ('N42_ROAD_RUNTIME', '1'); iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    warm = 'WARM' if suffix == '' else 'WARM2'
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop336WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop336WARM2?', f'bench-loop336{warm}', lines[gi[0]])
    if suffix == '':
        body = [mk(warm, fn='leg'), guard, mk('P60'), mk('P60b'), mk('W', W), mk('Wb', W), mk('WR', W, R)]
        title = 'Claim 1: WARM (P60 shape), P60, P60b, W, Wb, WR.'
    else:
        # claim 1 showed the plain feed capping at ~2.5-2.6M/s (the ingest's twelve recovery slots; P60r, WR, WRr bound even at 8.0M / 4.0M): claim 2 runs every
        # leg with N42_TX_INGEST_RECOVER_PARALLEL=24 ("F") and no feed reruns, with its own control pair
        F = ('N42_TX_INGEST_RECOVER_PARALLEL', '24')
        wr50 = mk('WR50F', W, R, iv(50), F)
        wr250 = mk('WR250F', W, R, ('F7_GASCEIL_ARG', '5250000000'), iv('$PACE250'), F)
        body = [mk(warm, F, fn='leg'), guard, mk('P60F', F), mk('P60Fb', F), mk('RF', R, F), mk('RFb', R, F), mk('WRF', W, R, F), mk('WRFb', W, R, F),
                'CM=$(python3 scripts/fleet7-runs/cycmed336.py loop336WRF cycle); echo "WRF cycle median $CM ms"',
                'if python3 -c "import sys; sys.exit(0 if float(\'$CM\') < 66 else 1)"; then', wr50,
                'else echo "WR50F skipped: WRF\'s cycle median $CM ms is not under 66"; fi',
                mk('WRT64F', W, R, ('N42_PARALLEL_BUILD_THREADS', '64'), ('RAYON_NUM_THREADS', '32'), F),
                'SS=$(python3 scripts/fleet7-runs/cycmed336.py loop335S250 seal); PACE250=$(python3 -c "import math; s=float(\'$SS\'); print(int(math.ceil(s+12)) if s < 900 else 100)"); echo "WR250 pacing $PACE250 ms (loop335 S250 sealed_at median $SS + 12)"',
                wr250]
        title = 'Claim 2 (ingest recovery slots 24 on every leg, no feed reruns): WARM2, P60F, P60Fb, RF, RFb, WRF, WRFb, WR50F (when WRF\'s cycle median is under 66 ms), WRT64F, WR250F (pacing = loop335 S250 sealed_at median + 12 ms).'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ') or l.startswith('leg WARM2 ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop336 = '); i1 = run.index('cd /data/n42-build/wt335')
    hdr = ('# loop336 = one wave and the road runtime (docs 10.83): base P60 = loop334 L3FS60. ' + title + ' A feed-bound leg is rerun once with the feed raised. '
           'Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    assert run.count('LEADER_LAYERS|') == 2
    run = run.replace('LEADER_LAYERS|', 'LEADER_LAYERS|BUILD_ONE_WAVE|ROAD_RUNTIME|')
    if suffix == 'b':
        i = run.index('  if ! python3 scripts/fleet7-runs/feedcheck335.py loop336$tag; then'); j = run.index('  fi\n}', i)
        run = run[:i] + '  python3 scripts/fleet7-runs/feedcheck335.py loop336$tag\n' + run[j + 5:]
    open(D + f'run-loop336{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop335a.sh').read().replace('run-loop335.sh', 'run-loop336' + suffix + '.sh').replace('loop335', 'loop336' + suffix)
    open(D + f'launch-loop336{suffix}.sh', 'w').write(la)
import sys
for sfx in (sys.argv[1:] or ['', 'b']): derive(sfx)
