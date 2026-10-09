#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop345{a,b,c,d}.sh / launch-loop345{a,b,c,d}.sh for loop345 (docs 10.92) from loop344's claim-1 runner. Base F2 = loop344 F2new (200k, 60 ms; N42_LIVE_INDEX_DEFER=1 N42_FREEZE_AFTER_SEAL=1
N42_ROOT_OPS_AHEAD=1 on loop341's P line, which already has N42_PLAN_AHEAD=1 N42_PULL_BY_FRAMES=1). C = F2 + N42_SEAL_ON_COUNTERS=1; FP = F2 + N42_FREEZE_POOL=own; CB = C + N42_PLAN_AHEAD_BODY=1; CB96 / CB128 = CB +
N42_BUILD_BATCHES; ALL = CB128 + N42_FREEZE_POOL=own; ALLV = ALL + N42_FIELDS_AT_SEAL=verify (fvgate); ALLP50/45/40 = ALL at 50/45/40 ms, gated by gate340.py. All switches are read by the execution layer
(engine-types: payload.rs, parallel_transfer.rs, output_shards.rs; tx-queue for the plan-ahead hook). Any leg with N42_PLAN_AHEAD_BODY=1 passes through bodygate: a refused / invalid block, a gas mismatch, a field
mismatch, a block that was not the one committed or a proposal given up stops the round after that leg.
Claims: a (200k): WARM, WARMb, F2, C, F2b, Cb, FP, CB (read-back check), CB96, CB128. b (200k): WARM, WARMb, ALL, ALLb, ALLV, ALLP50, ALLP45, ALLP40. c (400k, gas 8.4e9): WARM, WARMb, S400, S400ALL, S400b,
S400ALLb (all 120 ms). d (400k): WARM, WARMb, S400ALLP* (first at the S400ALL seal + 5 ms, then 10 ms steps while the gate passes), BEST, BESTb.
Built and run from /data/n42-build/wt338 at the pushed tip (which includes 1401aa6f2)."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop344a.sh').read().replace('loop344', 'loop345')
def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else: toks.append(f'{key}={val}')
    return ' '.join(toks)
BODYGATE = r'''
# a prepared-body leg that produces a refused / invalid block (or a mismatch, an uncommitted own block, a given-up proposal) stops the round after that leg
bodygate() {
  local tag=$1 f=$B/bench-$1/node0-el.log inv gas fm nc gu
  inv=$(grep -ac 'Encountered invalid block' $f 2>/dev/null); gas=$(grep -ac 'gas used mismatch' $f 2>/dev/null)
  fm=$(grep -a 'seal-first build phases' $f 2>/dev/null | grep -oE 'fields_mismatches=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
  nc=$(grep -ac 'was not the one committed' $f 2>/dev/null); gu=$(cat $B/bench-$1/node*-v.log 2>/dev/null | grep -ac 'could not build a block to propose')
  echo "bodygate $tag: invalid_blocks=${inv:-0} gas_mismatch=${gas:-0} fields_mismatches=${fm:-none} own_not_committed=${nc:-0} proposals_given_up=${gu:-0}"
  if [ "${inv:-0}" != 0 ] || [ "${gas:-0}" != 0 ] || [ "${fm:-0}" != 0 ] || [ "${nc:-0}" != 0 ] || [ "${gu:-0}" != 0 ]; then
    echo "BODYGATE FAILED on $tag: stopping the round (datadirs kept as evidence)"; cleanup; echo "released at $(date +%H:%M)"; echo ALLDONE; exit 1
  fi
}
'''
def derive(suffix):
    lines = base_run.split('\n')
    g = [l for l in lines if l.startswith('legf F2new ')]
    assert len(g) == 1; p = g[0].replace(' --rpc.max-response-size 1000"', '"')
    for need in ('N42_LIVE_INDEX_DEFER=1', 'N42_FREEZE_AFTER_SEAL=1', 'N42_ROOT_OPS_AHEAD=1', 'N42_PLAN_AHEAD=1', 'N42_PULL_BY_FRAMES=1', 'F7_BLOCK_INTERVAL_MS=60', 'F7_BIN=$NAT', 'F7_GASCEIL_ARG=4200000000', '--prune.transaction-lookup.full"'):
        assert need in p, need
    def mk(name, *edits, fn='legf', rpc=False):
        l = p.replace('legf F2new ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        if rpc: l = l.replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --rpc.max-response-size 1000"')
        return l
    CO = ('N42_SEAL_ON_COUNTERS', '1'); FPO = ('N42_FREEZE_POOL', 'own'); PB = ('N42_PLAN_AHEAD_BODY', '1'); BB = lambda n: ('N42_BUILD_BATCHES', str(n))
    iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n)); gas = lambda n: ('F7_GASCEIL_ARG', str(n * 21000))
    ALL = [CO, PB, BB(128), FPO]
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop345WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop345WARM2?', 'bench-loop345WARM', lines[gi[0]])
    big = [gas(400000), iv(120)] if suffix in 'cd' else []
    warm = [mk('WARM', *big, fn='leg'), guard, mk('WARMb', *big, fn='leg')]
    if suffix == 'a':
        body = warm + [mk('F2'), mk('C', CO), mk('F2b'), mk('Cb', CO), mk('FP', FPO), mk('CB', CO, PB, rpc=True), mk('CB96', CO, PB, BB(96)), mk('CB128', CO, PB, BB(128))]
        title = 'Claim a (200k): WARM, WARMb, F2, C, F2b, Cb, FP, CB (read-back), CB96, CB128.'
    elif suffix == 'b':
        steps = ['PREV="loop345ALL loop345ALLb"; CUR=60', 'for STEP in 50 45 40; do',
                 '  if G=$(python3 scripts/fleet7-runs/gate340.py $CUR $PREV); then echo "ALLP gate at $CUR ms: $G"; else echo "ALLP steps stop before $STEP ms: $G"; break; fi',
                 '  ' + mk('ALLP$STEP', *ALL, iv('$STEP')), '  PREV=loop345ALLP$STEP; CUR=$STEP', 'done',
                 'if G=$(python3 scripts/fleet7-runs/gate340.py $CUR $PREV); then echo "ALLP final gate at $CUR ms: $G"; else echo "ALLP final gate at $CUR ms failed: $G"; fi']
        body = warm + [mk('ALL', *ALL), mk('ALLb', *ALL), mk('ALLV', *ALL, ('N42_FIELDS_AT_SEAL', 'verify')), 'fvgate'] + steps
        title = 'Claim b (200k): WARM, WARMb, ALL, ALLb, ALLV (fvgate), ALLP50/45/40 (gated).'
    elif suffix == 'c':
        body = warm + [mk('S400', *big), mk('S400ALL', *big, *ALL), mk('S400b', *big), mk('S400ALLb', *big, *ALL)]
        title = 'Claim c (400k, 120 ms): WARM, WARMb, S400, S400ALL, S400b, S400ALLb.'
    else:
        body = warm + ['SA=$(python3 scripts/fleet7-runs/cycmed336.py loop345S400ALL seal); P0=$(python3 -c "import math; print(int(math.ceil(float(\'$SA\') + 5)))"); echo "S400ALL sealed_at median $SA ms: first pacing $P0 ms"',
                       'CUR=$P0; PLEGS=""; for K in 1 2 3 4; do', '  ' + mk('S400ALLP$CUR', gas(400000), *ALL, iv('$CUR')), '  PLEGS="$PLEGS S400ALLP$CUR"; PREV=loop345S400ALLP$CUR',
                       '  if G=$(python3 scripts/fleet7-runs/gate340.py $CUR $PREV); then echo "S400ALLP gate at $CUR ms: $G"; else echo "S400ALLP steps stop after $CUR ms: $G"; break; fi; CUR=$((CUR - 10)); done',
                       'BT=$(python3 scripts/fleet7-runs/best337.py loop345 $PLEGS); echo "BEST single leg: ${BT:-none}"',
                       'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim d (400k): WARM, WARMb, S400ALLP* (first at the S400ALL seal + 5 ms, then 10 ms steps), BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop345 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop345 = the seal path shortened (docs 10.92, scope section 17): base F2 = loop344 F2new. ' + title +
           ' Full build and test gate (n42 and engine-types libs single-threaded), free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    k = 'python3 scripts/fleet7-runs/fields343.py loop345$tag 2>&1 | cut -c1-3200;'
    assert k in run; run = run.replace(k, 'python3 scripts/fleet7-runs/fields345.py loop345$tag 2>&1 | cut -c1-4200;')
    # the bench's and the validators' environment headers
    n = run.count('FREEZE_AFTER_SEAL|ROOT_OPS_AHEAD|'); assert n >= 2, n
    run = run.replace('FREEZE_AFTER_SEAL|ROOT_OPS_AHEAD|', 'SEAL_ON_COUNTERS|PLAN_AHEAD_BODY|BUILD_BATCHES|FREEZE_POOL|FREEZE_AFTER_SEAL|ROOT_OPS_AHEAD|')
    # fvgate follows the verify leg, bodygate every prepared-body leg
    assert 'local f=$B/bench-loop345F2V/node0-el.log' in run
    run = run.replace('local f=$B/bench-loop345F2V/node0-el.log', 'local f=$B/bench-loop345ALLV/node0-el.log')
    run = run.replace('\nlegf() {', BODYGATE + '\nlegf() {', 1)
    ka = '  [ -f $B/bench-loop345$tag/round.txt ] || return\n'
    assert ka in run
    run = run.replace(ka, ka + '', 1)
    kz = 'fields345.py loop345$tag 2>&1 | cut -c1-4200;'
    i = run.index(kz); j = run.index('\n}', i)
    run = run[:j] + '\n  case "$*" in *PLAN_AHEAD_BODY=1*) bodygate loop345$tag ;; esac' + run[j:]
    assert 'if [ "$tag" = loop345F2new ]' in run
    run = run.replace('if [ "$tag" = loop345F2new ]', 'if [ "$tag" = loop345CB ]')
    run = run.replace('if [ "$tag" = loop345Gnew ]', 'if [ "$tag" = loop345NEVER ]')
    if '"-p n42 --lib"; do' in run: run = run.replace('"-p n42 --lib"; do', '"-p n42 --lib -- --test-threads=1"; do')
    assert 'n42 --lib -- --test-threads=1' in run
    open(D + f'run-loop345{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop344a.sh').read().replace('run-loop344a.sh', 'run-loop345' + suffix + '.sh').replace('loop344a', 'loop345' + suffix)
    open(D + f'launch-loop345{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ['a', 'b', 'c', 'd']): derive(sfx)
