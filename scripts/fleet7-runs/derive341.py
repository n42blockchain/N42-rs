#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop341{,b}.sh / launch-loop341{,b}.sh for loop341 (docs 10.88) from loop340's claim-1 runner. Base P = loop340 P3 (N + N42_SF_PARALLEL_ENCODE=1 N42_SF_EARLY_WRITEBACK=1
N42_PERSIST_QMDB_IN_SCOPE=1). J = P + N42_VIEW_JOURNAL_FILTER=1 N42_QMDB_PARALLEL_WRITES=1 (both read by the execution layer: engine-types/qmdb-reth, twig-core); JF / JW = one of them; T48 = J +
N42_PARALLEL_BUILD_THREADS=48; T48P55 = T48 at 55 ms when T48's sealed_at median is under 55, else JP55 = J at 55 ms; P55 = P at 55 ms.
Claim 1: WARM, WARMb, P, J, Pb, Jb, with the static-file read-back check (check340.py, fixed) on the layer after J (the layer started with --rpc.max-response-size 1000). Claim 2: WARM, WARMb,
JF, JW, T48, T48P55|JP55, P55, BEST, BESTb. Built and run from /data/n42-build/wt338 at the pushed tip."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop340.sh').read().replace('loop340', 'loop341')
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
    g = [l for l in lines if l.startswith('legf P3 ')]
    assert len(g) == 1; p = g[0]
    for need in ('N42_SF_PARALLEL_ENCODE=1', 'N42_SF_EARLY_WRITEBACK=1', 'N42_PERSIST_QMDB_IN_SCOPE=1', 'N42_PLAN_AHEAD=1', 'F7_BLOCK_INTERVAL_MS=60', 'F7_GASCEIL_ARG=4200000000', '--prune.transaction-lookup.full"'):
        assert need in p, need
    def mk(name, *edits, fn='legf', rpc=False):
        l = p.replace('legf P3 ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        if rpc: l = l.replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --rpc.max-response-size 1000"')
        return l
    JF = ('N42_VIEW_JOURNAL_FILTER', '1'); JW = ('N42_QMDB_PARALLEL_WRITES', '1'); iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n)); T48 = ('N42_PARALLEL_BUILD_THREADS', '48')
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop341WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop341WARM2?', 'bench-loop341WARM', lines[gi[0]])
    warm = [mk('WARM', fn='leg'), guard, mk('WARMb', fn='leg')]
    if suffix == '':
        body = warm + [mk('P'), mk('J', JF, JW, rpc=True), mk('Pb'), mk('Jb', JF, JW)]
        title = 'Claim 1: WARM, WARMb, P, J, Pb, Jb (read-back check after J).'
    else:
        body = warm + [mk('JF', JF), mk('JW', JW), mk('T48', JF, JW, T48),
                       'SS=$(python3 scripts/fleet7-runs/cycmed336.py loop341T48 seal); echo "T48 sealed_at median $SS ms"',
                       'if python3 -c "import sys; sys.exit(0 if float(\'$SS\') < 55 else 1)"; then ' + mk('T48P55', JF, JW, T48, iv(55)) + '; else echo "T48 sealed_at median $SS ms is not under 55: running JP55"; ' + mk('JP55', JF, JW, iv(55)) + '; fi',
                       mk('P55', iv(55)),
                       'BT=$(python3 scripts/fleet7-runs/best337.py loop341 JF JW T48 T48P55 JP55 P55); echo "BEST single leg: ${BT:-none}"',
                       'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 2: WARM, WARMb, JF, JW, T48, T48P55|JP55, P55, BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop341 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop341 = what bounds the execution and the root (docs 10.88, scope section 13): base P = loop340 P3. ' + title +
           ' Feed, lock, plan, persistence and execution-field report per leg. Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    k = 'python3 scripts/fleet7-runs/persist340.py loop341$tag 2>&1 | cut -c1-900;'
    assert k in run; run = run.replace(k, k + ' python3 scripts/fleet7-runs/fields341.py loop341$tag 2>&1 | cut -c1-1600;')
    n = run.count('SF_PARALLEL_ENCODE|SF_EARLY_WRITEBACK|'); assert n >= 2, n
    run = run.replace('SF_PARALLEL_ENCODE|SF_EARLY_WRITEBACK|', 'QMDB_PARALLEL_WRITES|VIEW_JOURNAL_FILTER|PARALLEL_BUILD_THREADS|SF_PARALLEL_ENCODE|SF_EARLY_WRITEBACK|')
    assert 'if [ "$tag" = loop341P3 ]' in run
    run = run.replace('if [ "$tag" = loop341P3 ]', 'if [ "$tag" = loop341J ]')
    assert '"-p n42-engine-types --lib -- --test-threads=1" "-p n42 --lib"' in run
    run = run.replace('"-p n42-engine-types --lib -- --test-threads=1" "-p n42 --lib"', '"-p n42-twig-core --lib" "-p n42-engine-types --lib -- --test-threads=1" "-p n42 --lib"')
    open(D + f'run-loop341{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop340.sh').read().replace('run-loop340.sh', 'run-loop341' + suffix + '.sh').replace('loop340', 'loop341' + suffix)
    open(D + f'launch-loop341{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ["", "b"]): derive(sfx)
