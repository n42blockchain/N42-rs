#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop338.sh / launch-loop338.sh (claim 1: WARM, WARMb, B, IQ, Bb, IQb, Q, Qb, I, Ib, IQ12) and run-loop338b.sh / launch-loop338b.sh (claim 2: WARM, WARMb,
IQP55, IQP50 (each gated on the previous step's cycle median being within 3 ms of its pacing), IQS250, IQS300, BEST, BESTb) for loop338 (docs 10.85) from loop337's claim-2
runner. Base B = loop336 RF with N42_TX_INGEST_RECOVER_PARALLEL=24 (loop337's best: 200,000 a block, 60 ms, three layers, fields at seal, N42_ROAD_RUNTIME=1) on the
binary that carries the gate mirror and the one-pass prune. I = + N42_INGEST_RUNTIME=1, Q = + N42_QUEUE_PRUNE_THREAD=1, IQ = both, IQ12 = IQ with 12 permits.
Built and run from the worktree /data/n42-build/wt338 (a fresh checkout of the pushed tip)."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop337b.sh').read().replace('wt335', 'wt338').replace('loop337', 'loop338')
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
    g = [l for l in lines if l.startswith('leg WARM2 ')]
    assert len(g) == 1; p = g[0]
    for need in ('N42_LEADER_LAYERS=3', 'N42_FIELDS_AT_SEAL=1', 'F7_GASCEIL_ARG=4200000000', 'F7_BLOCK_INTERVAL_MS=60', 'N42_ROAD_RUNTIME=1', 'N42_TX_INGEST_RECOVER_PARALLEL=64', 'F7_EL_MAP=0,0,0,0,0,0,0'):
        assert need in p, need
    def mk(name, *edits, fn='legf'):
        l = p.replace('leg WARM2 ', f'{fn} {name} ', 1)
        l = set_tok(l, 'N42_TX_INGEST_RECOVER_PARALLEL', '24')
        for k, v in edits: l = set_tok(l, k, v)
        return l
    I = ('N42_INGEST_RUNTIME', '1'); Q = ('N42_QUEUE_PRUNE_THREAD', '1'); iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop338WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop338WARM2?', 'bench-loop338WARM', lines[gi[0]])
    cyc = lambda tag: f"$(python3 scripts/fleet7-runs/cycmed336.py loop338{tag} cycle)"
    # two warm-ups at the start of every claim: the test gate before the claim leaves the box cold (loop337 WARM4 read 12% low after 16 idle minutes)
    warm = [mk('WARM', fn='leg'), guard, mk('WARMb', fn='leg')]
    if suffix == '':
        body = warm + [mk('B'), mk('IQ', I, Q), mk('Bb'), mk('IQb', I, Q), mk('Q', Q), mk('Qb', Q), mk('I', I), mk('Ib', I), mk('IQ12', I, Q, ('N42_TX_INGEST_RECOVER_PARALLEL', '12'))]
        title = 'Claim 1: WARM, WARMb, B, IQ, Bb, IQb, Q, Qb, I, Ib, IQ12.'
    else:
        body = warm + [
            'C1=' + cyc('IQ') + '; C2=' + cyc('IQb') + '; CM=$(python3 -c "print(min(float(\'$C1\'), float(\'$C2\')))"); echo "IQ / IQb cycle medians $C1 / $C2 ms"',
            'RAN55=0; if python3 -c "import sys; sys.exit(0 if float(\'$CM\') <= 63 else 1)"; then RAN55=1', mk('IQP55', I, Q, iv(55)),
            'else echo "IQP55 skipped: the lower IQ cycle median $CM ms is not within 3 ms of 60"; fi',
            'if [ $RAN55 = 1 ] && python3 -c "import sys; sys.exit(0 if float(\'' + cyc('IQP55') + '\') <= 58 else 1)"; then', mk('IQP50', I, Q, iv(50)),
            'else echo "IQP50 skipped: IQP55 was skipped or its cycle median is not within 3 ms of 55"; fi',
            mk('IQS250', I, Q, ('F7_GASCEIL_ARG', '5250000000'), iv(82)),
            mk('IQS300', I, Q, ('F7_GASCEIL_ARG', '6300000000'), iv(97)),
            'BT=$(python3 scripts/fleet7-runs/best337.py loop338 IQP55 IQP50 IQS250 IQS300 IQ); echo "BEST single leg: ${BT:-none}"',
            'if [ -n "$BT" ] && [ "$BT" != IQ ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 2: WARM, WARMb, IQP55, IQP50 (gated on the cycle median), IQS250, IQS300, BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM2 ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop338 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop338 = the feed path built (docs 10.85, scope section 11): base B = RF at 24 recovery permits on the binary with the gate mirror and the one-pass prune. ' + title +
           ' Feed check per leg (feed337.py, feed338.py, prune337.py). Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    key = 'python3 scripts/fleet7-runs/feed337.py loop338$tag 2>&1 | cut -c1-420;'
    assert key in run
    run = run.replace(key, key + ' python3 scripts/fleet7-runs/feed338.py loop338$tag 2>&1 | cut -c1-900; python3 scripts/fleet7-runs/prune337.py loop338$tag 2>&1 | cut -c1-400;')
    n = run.count('ROAD_RUNTIME|'); assert n >= 2, n
    run = run.replace('ROAD_RUNTIME|', 'ROAD_RUNTIME|INGEST_RUNTIME|QUEUE_PRUNE_THREAD|RECOVER_PARALLEL|')
    open(D + f'run-loop338{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop337b.sh').read().replace('wt335', 'wt338').replace('run-loop337b.sh', 'run-loop338' + suffix + '.sh').replace('loop337b', 'loop338' + suffix)
    open(D + f'launch-loop338{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ["", "b"]): derive(sfx)
