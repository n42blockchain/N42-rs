#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop342{,b}.sh / launch-loop342{,b}.sh for loop342 (docs 10.89) from loop341's claim-1 runner. Base P = loop341 P (= loop340 P3: the four seal switches + N42_SF_PARALLEL_ENCODE,
N42_SF_EARLY_WRITEBACK, N42_PERSIST_QMDB_IN_SCOPE; 200k, 60 ms; no journal filter, no parallel writes). D = P + N42_LIVE_INDEX_DEFER=1 (read by the execution layer, engine-types/parallel_transfer.rs).
D48 = D + N42_PARALLEL_BUILD_THREADS=48. DP55 / DP50 = D at 55 / 50 ms (D48P55 / D48P50 when D48's sealed_at median is lower than D's), each only while the previous step passes gate340.py
(cycle median within 3 ms of its pacing and a flat backlog). DPROF = D on the profiling build (F7_BIN=/data/n42-build/wt338/target/prof/profiling) with scripts/fleet7-offcpu.sh --node 0 --secs 10
started 30 s after the flood's funding line; its rate is not judged and the report is read after the claim. Claim 1: WARM, WARMb, P, D, Pb, Db (read-back check on D, layer with
--rpc.max-response-size 1000). Claim 2: WARM, WARMb, D48, DP55, DP50, DPROF, BEST, BESTb. Built and run from /data/n42-build/wt338 at the pushed tip."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop341.sh').read().replace('loop341', 'loop342')
PROF = '/data/n42-build/wt338/target/prof/profiling'
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
    g = [l for l in lines if l.startswith('legf P ')]
    assert len(g) == 1; p = g[0]
    for need in ('N42_SF_PARALLEL_ENCODE=1', 'N42_PERSIST_QMDB_IN_SCOPE=1', 'N42_PLAN_AHEAD=1', 'F7_BLOCK_INTERVAL_MS=60', 'F7_BIN=$NAT', '--prune.transaction-lookup.full"'):
        assert need in p, need
    assert 'VIEW_JOURNAL_FILTER' not in p
    def mk(name, *edits, fn='legf', rpc=False):
        l = p.replace('legf P ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        if rpc: l = l.replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --rpc.max-response-size 1000"')
        return l
    DF = ('N42_LIVE_INDEX_DEFER', '1'); T48 = ('N42_PARALLEL_BUILD_THREADS', '48'); iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop342WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop342WARM2?', 'bench-loop342WARM', lines[gi[0]])
    warm = [mk('WARM', fn='leg'), guard, mk('WARMb', fn='leg')]
    if suffix == '':
        body = warm + [mk('P'), mk('D', DF, rpc=True), mk('Pb'), mk('Db', DF)]
        title = 'Claim 1: WARM, WARMb, P, D, Pb, Db (read-back check after D).'
    else:
        steps = ['SD=$(python3 scripts/fleet7-runs/cycmed336.py loop342D seal); SDb=$(python3 scripts/fleet7-runs/cycmed336.py loop342Db seal); S48=$(python3 scripts/fleet7-runs/cycmed336.py loop342D48 seal)',
                 'echo "sealed_at medians: D $SD, Db $SDb, D48 $S48"',
                 'if python3 -c "import sys; sys.exit(0 if float(\'$S48\') < min(float(\'$SD\'), float(\'$SDb\')) else 1)"; then PC=D48; PREV=loop342D48; else PC=D; PREV="loop342D loop342Db"; fi; echo "pacing legs on $PC"',
                 'for STEP in 55 50 45; do',
                 '  if G=$(python3 scripts/fleet7-runs/gate340.py $((STEP + 5)) $PREV); then echo "pacing gate for $STEP ms: $G"; else echo "pacing steps stop before $STEP ms: $G"; break; fi',
                 '  [ $STEP = 45 ] && break',
                 '  if [ $PC = D48 ]; then ' + mk('D48P$STEP', DF, T48, iv('$STEP')) + '; else ' + mk('DP$STEP', DF, iv('$STEP')) + '; fi',
                 '  PREV=loop342${PC}P$STEP',
                 'done']
        body = warm + [mk('D48', DF, T48)] + steps + [
            mk('DPROF', DF, ('F7_BIN', PROF)),
            'BT=$(python3 scripts/fleet7-runs/best337.py loop342 D48 DP55 DP50 D48P55 D48P50); echo "BEST single leg: ${BT:-none}"',
            'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 2: WARM, WARMb, D48, DP55, DP50 (gated), DPROF (profiling build + off-CPU profile), BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop342 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop342 = the live index hand-over (docs 10.89, scope section 14): base P = loop341 P. ' + title +
           ' Feed, lock, plan, persistence and execution-field report per leg. Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    k = 'python3 scripts/fleet7-runs/fields341.py loop342$tag 2>&1 | cut -c1-1600;'
    assert k in run; run = run.replace(k, 'python3 scripts/fleet7-runs/fields342.py loop342$tag 2>&1 | cut -c1-2200;')
    n = run.count('QMDB_PARALLEL_WRITES|VIEW_JOURNAL_FILTER|'); assert n >= 2, n
    run = run.replace('QMDB_PARALLEL_WRITES|VIEW_JOURNAL_FILTER|', 'LIVE_INDEX_DEFER|QMDB_PARALLEL_WRITES|VIEW_JOURNAL_FILTER|')
    assert 'if [ "$tag" = loop342J ]' in run
    run = run.replace('if [ "$tag" = loop342J ]', 'if [ "$tag" = loop342D ]')
    k = '  echo "leg $tag start $(date +%H:%M:%S)'
    assert run.count(k) == 1
    run = run.replace(k, '  case $tag in *DPROF) ( n=0; until grep -q \'funding\' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done; sleep 30; bash scripts/fleet7-offcpu.sh --node 0 --secs 10 $S/offcpu-$tag > $S/offcpu-$tag.run.out 2>&1 ) & ;; esac\n' + k)
    open(D + f'run-loop342{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop341.sh').read().replace('run-loop341.sh', 'run-loop342' + suffix + '.sh').replace('loop341', 'loop342' + suffix)
    open(D + f'launch-loop342{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ["", "b"]): derive(sfx)
