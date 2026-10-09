#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop337.sh / launch-loop337.sh (claim 1: WARM, RF64, RF64b, RF24) and run-loop337b.sh / launch-loop337b.sh (claim 2: WARM2, RF64P55, RF64P50,
RF64S250, RF64S300, RF64T64, BEST, BESTb) for loop337 (docs 10.84) from loop336's claim-2 runner. Base RF = loop336 RF (N42_LEADER_LAYERS=3, N42_FIELDS_AT_SEAL=1,
N42_ROAD_RUNTIME=1, 200,000 a block, 60 ms, the F legs' feed settings) with N42_TX_INGEST_RECOVER_PARALLEL=64 ("RF64"); RF24 is RF as it was.
Gates: RF64P55 runs when the lower cycle median of RF64 / RF64b is within 3 ms of 60; RF64P50 when RF64P55's is within 3 ms of 55 (cycmed336.py).
BEST / BESTb repeat the single leg of P55, P50, S250, S300, T64 with the highest round total and every block full in all three windows (best337.py).
Built and run from the git worktree /data/n42-build/wt335 (the main tree carries another agent's uncommitted work)."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop336b.sh').read().replace('loop336', 'loop337')
def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else: toks.append(f'{key}={val}')
    return ' '.join(toks)
def derive(suffix):
    lines = base_run.split('\n')
    g = [l for l in lines if l.startswith('legf RF ')]
    assert len(g) == 1; p = g[0]
    for need in ('N42_LEADER_LAYERS=3', 'N42_FIELDS_AT_SEAL=1', 'F7_GASCEIL_ARG=4200000000', 'F7_BLOCK_INTERVAL_MS=60', 'N42_ROAD_RUNTIME=1', 'N42_TX_INGEST_RECOVER_PARALLEL=24', 'F7_EL_MAP=0,0,0,0,0,0,0'):
        assert need in p, need
    def mk(name, *edits, fn='legf'):
        l = p.replace('legf RF ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        return l
    S64 = ('N42_TX_INGEST_RECOVER_PARALLEL', '64'); iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    warm = {'': 'WARM', 'b': 'WARM2', 'c': 'WARM3', 'd': 'WARM4'}[suffix]
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop337WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop337WARM2?', f'bench-loop337{warm}', lines[gi[0]])
    cyc = lambda tag: f"$(python3 scripts/fleet7-runs/cycmed336.py loop337{tag} cycle)"
    if suffix == '':
        body = [mk(warm, S64, fn='leg'), guard, mk('RF64', S64), mk('RF64b', S64), mk('RF24', ('N42_TX_INGEST_RECOVER_PARALLEL', '24'))]
        title = 'Claim 1: WARM (RF64), RF64, RF64b, RF24.'
    elif suffix in ('c', 'd'):
        # claim 3: claim 2's runner was killed with the session's background shell during RF64T64's post-processing (salvaged by hand), so BEST / BESTb never ran
        body = [mk(warm, S64, fn='leg'), guard,
                'BT=$(python3 scripts/fleet7-runs/best337.py loop337 RF64P55 RF64P50 RF64S250 RF64S300 RF64T64); echo "BEST single leg: ${BT:-none}"',
                'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 3 / 4 (4: claim 3 ran a stale best337.py from the worktree and found no BEST leg): WARM3 / WARM4, BEST, BESTb (the highest fully-full single leg of claim 2).'
    else:
        body = [mk(warm, S64, fn='leg'), guard,
                'C1=' + cyc('RF64') + '; C2=' + cyc('RF64b') + '; CM=$(python3 -c "print(min(float(\'$C1\'), float(\'$C2\')))"); echo "RF64 / RF64b cycle medians $C1 / $C2 ms"',
                'RAN55=0; if python3 -c "import sys; sys.exit(0 if float(\'$CM\') <= 63 else 1)"; then RAN55=1', mk('RF64P55', S64, iv(55)),
                'else echo "RF64P55 skipped: the lower RF64 cycle median $CM ms is not within 3 ms of 60"; fi',
                'if [ $RAN55 = 1 ] && python3 -c "import sys; sys.exit(0 if float(\'' + cyc('RF64P55') + '\') <= 58 else 1)"; then', mk('RF64P50', S64, iv(50)),
                'else echo "RF64P50 skipped: RF64P55 was skipped or its cycle median is not within 3 ms of 55"; fi',
                mk('RF64S250', S64, ('F7_GASCEIL_ARG', '5250000000'), iv(80)),
                mk('RF64S300', S64, ('F7_GASCEIL_ARG', '6300000000'), iv(93)),
                mk('RF64T64', S64, ('N42_PARALLEL_BUILD_THREADS', '64'), ('RAYON_NUM_THREADS', '32')),
                'BT=$(python3 scripts/fleet7-runs/best337.py loop337 RF64P55 RF64P50 RF64S250 RF64S300 RF64T64); echo "BEST single leg: ${BT:-none}"',
                'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 2: WARM2, RF64P55, RF64P50 (both gated on the cycle median), RF64S250, RF64S300, RF64T64, BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ') or l.startswith('leg WARM2 ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop337 = '); i1 = run.index('cd /data/n42-build/wt335')
    hdr = ('# loop337 = the feed with 64 recovery permits (docs 10.84): base RF = loop336 RF. ' + title + ' Feed check per leg (feed337.py). '
           'Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    # the per-leg report: the feed check next to feedcheck335.py's verdict
    run = run.replace('  python3 scripts/fleet7-runs/feedcheck335.py loop337$tag\n', '  python3 scripts/fleet7-runs/feedcheck335.py loop337$tag; python3 scripts/fleet7-runs/feed337.py loop337$tag 2>&1 | cut -c1-420; python3 scripts/fleet7-runs/fields336.py loop337$tag 2>&1 | cut -c1-900\n')
    assert 'feed337.py' in run
    # per-thread CPU of the layer's tokio-rt threads (threadcpu337.py): is one main-runtime worker saturated?
    key = "F7_ROOT=/data/blockchain/rust-fleet7-bench python3 $S/threadcpu4.py 200 ) > $S/threadcpu-$tag.tsv 2>/dev/null &\n"
    assert key in run
    run = run.replace(key, key + "  ( n=0; until grep -q 'funding' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done; python3 scripts/fleet7-runs/threadcpu337.py sample 150 0 ) > $S/tidcpu-$tag.tsv 2>/dev/null &\n")
    run = run.replace('python3 scripts/fleet7-runs/feed337.py loop337$tag 2>&1 | cut -c1-420;', 'python3 scripts/fleet7-runs/feed337.py loop337$tag 2>&1 | cut -c1-420; python3 scripts/fleet7-runs/threadcpu337.py report $S/tidcpu-loop337$tag.tsv 2>&1 | cut -c1-300;')
    open(D + f'run-loop337{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop336b.sh').read().replace('run-loop336b.sh', 'run-loop337' + suffix + '.sh').replace('loop336b', 'loop337' + suffix)
    open(D + f'launch-loop337{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ['', 'b', 'c', 'd']): derive(sfx)
