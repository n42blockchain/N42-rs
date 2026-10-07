#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop343{,b}.sh / launch-loop343{,b}.sh for loop343 (docs 10.90) from loop342's claim-1 runner. Base D = loop342 D (loop341's P line + N42_LIVE_INDEX_DEFER=1; the line
already carries N42_SEAL_AT_EXEC=1). F2 = D + N42_FREEZE_AFTER_SEAL=1 N42_ROOT_OPS_AHEAD=1 (both read by the execution layer: engine-types/output_shards.rs, payload.rs, qmdb-reth/changes.rs);
FZ / RO = one of them; F2V = F2 + N42_FIELDS_AT_SEAL=verify (fvgate: fields_mismatches must be 0 with checks made, else the round stops after that leg); F2T48 = F2 with 48 build
threads; F2P55 / F2P55b = F2 at 55 ms; F2P50 = F2 at 50 ms only if the lower F2P55 cycle median is at most 56 ms. Claim 1: WARM, WARMb, D, F2, Db, F2b (read-back check on F2, layer started with
--rpc.max-response-size 1000). Claim 2: WARM, WARMb, FZ, RO, F2V, F2T48, F2P55, F2P55b, F2P50, BEST, BESTb. Built and run from /data/n42-build/wt338 at 09a1284e4 (scripts copied in)."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop342.sh').read().replace('loop342', 'loop343')
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
    g = [l for l in lines if l.startswith('legf D ')]
    assert len(g) == 1; p = g[0].replace(' --rpc.max-response-size 1000"', '"')   # loop342's D carried the read-back flag; the base here is the plain line
    for need in ('N42_LIVE_INDEX_DEFER=1', 'N42_SEAL_AT_EXEC=1', 'N42_FIELDS_AT_SEAL=1', 'N42_SF_PARALLEL_ENCODE=1', 'F7_BLOCK_INTERVAL_MS=60', '--prune.transaction-lookup.full"'):
        assert need in p, need
    def mk(name, *edits, fn='legf', rpc=False):
        l = p.replace('legf D ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        if rpc: l = l.replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --rpc.max-response-size 1000"')
        return l
    FZ = ('N42_FREEZE_AFTER_SEAL', '1'); RO = ('N42_ROOT_OPS_AHEAD', '1'); iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n)); T48 = ('N42_PARALLEL_BUILD_THREADS', '48')
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop343WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop343WARM2?', 'bench-loop343WARM', lines[gi[0]])
    warm = [mk('WARM', fn='leg'), guard, mk('WARMb', fn='leg')]
    if suffix == '':
        body = warm + [mk('D'), mk('F2', FZ, RO, rpc=True), mk('Db'), mk('F2b', FZ, RO)]
        title = 'Claim 1: WARM, WARMb, D, F2, Db, F2b (read-back check after F2).'
    else:
        body = warm + [mk('FZ', FZ), mk('RO', RO), mk('F2V', FZ, RO, ('N42_FIELDS_AT_SEAL', 'verify')), 'fvgate', mk('F2T48', FZ, RO, T48),
                       mk('F2P55', FZ, RO, iv(55)), mk('F2P55b', FZ, RO, iv(55)),
                       'C1=$(python3 scripts/fleet7-runs/cycmed336.py loop343F2P55 cycle); C2=$(python3 scripts/fleet7-runs/cycmed336.py loop343F2P55b cycle); CM=$(python3 -c "print(min(float(\'$C1\'), float(\'$C2\')))"); echo "F2P55 / F2P55b cycle medians $C1 / $C2 ms"',
                       'if python3 -c "import sys; sys.exit(0 if float(\'$CM\') <= 56 else 1)"; then ' + mk('F2P50', FZ, RO, iv(50)) + '; else echo "F2P50 skipped: the lower F2P55 cycle median $CM ms is over 56"; fi',
                       'BT=$(python3 scripts/fleet7-runs/best337.py loop343 FZ RO F2V F2T48 F2P55 F2P50); echo "BEST single leg: ${BT:-none}"',
                       'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 2: WARM, WARMb, FZ, RO, F2V (fvgate), F2T48, F2P55, F2P55b, F2P50 (gated), BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop343 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop343 = the freeze and the root ops off the seal chain (docs 10.90, scope section 15): base D = loop342 D. ' + title +
           ' Feed, lock, plan, persistence and execution-field report per leg. Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    k = 'python3 scripts/fleet7-runs/fields342.py loop343$tag 2>&1 | cut -c1-2200;'
    assert k in run; run = run.replace(k, 'python3 scripts/fleet7-runs/fields343.py loop343$tag 2>&1 | cut -c1-3200;')
    assert 'local f=$B/bench-loop343FV/node0-el.log' in run
    run = run.replace('local f=$B/bench-loop343FV/node0-el.log', 'local f=$B/bench-loop343F2V/node0-el.log')
    n = run.count('LIVE_INDEX_DEFER|'); assert n >= 2, n
    run = run.replace('LIVE_INDEX_DEFER|', 'FREEZE_AFTER_SEAL|ROOT_OPS_AHEAD|SEAL_AT_EXEC|LIVE_INDEX_DEFER|')
    assert 'if [ "$tag" = loop343D ]' in run
    run = run.replace('if [ "$tag" = loop343D ]', 'if [ "$tag" = loop343F2 ]')
    open(D + f'run-loop343{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop342.sh').read().replace('run-loop342.sh', 'run-loop343' + suffix + '.sh').replace('loop342', 'loop343' + suffix)
    open(D + f'launch-loop343{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ["", "b"]): derive(sfx)
