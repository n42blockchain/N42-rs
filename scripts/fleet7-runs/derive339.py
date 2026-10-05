#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop339.sh / launch-loop339.sh (claim 1: WARM, WARMb, B, N4, Bb, N4b) and run-loop339b.sh / launch-loop339b.sh (claim 2: WARM, WARMb, D, A, L, N4P55, N4P50,
N4P45 (each gated on the previous step's cycle median being within 3 ms of its pacing), N4S163, N4X (5 windows), BEST, BESTb) for loop339 (docs 10.86) from loop338's runner.
Base B = loop338 B (200,000 a block, 60 ms, 24 recovery permits, three leader layers, fields at seal, N42_ROAD_RUNTIME=1). N4 = B + N42_TX_QUEUE_DRAIN_CHUNK=8192 N42_PLAN_AHEAD=1
N42_PULL_BY_FRAMES=1 N42_ANSWER_LAYOUT_ONLY=1 (the first three are read by the execution layer, the last by the validator's driver (h2-execution), which tells the layer in
its build request; the runner exports every variable to both processes and prints all four in both environment headers). D = drain chunk only, A = plan ahead + pull by
frames, L = layout-only answer. Built and run from the worktree /data/n42-build/wt338 at the pushed tip."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop338.sh').read().replace('loop338', 'loop339')
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
    g = [l for l in lines if l.startswith('legf B ')]
    assert len(g) == 1; p = g[0]
    for need in ('N42_LEADER_LAYERS=3', 'N42_FIELDS_AT_SEAL=1', 'F7_GASCEIL_ARG=4200000000', 'F7_BLOCK_INTERVAL_MS=60', 'N42_ROAD_RUNTIME=1', 'N42_TX_INGEST_RECOVER_PARALLEL=24', 'F7_EL_MAP=0,0,0,0,0,0,0', 'N42_FRAME_BLOCKS=1', 'N42_TAKE_COMPACT=1'):
        assert need in p, need
    def mk(name, *edits, fn='legf'):
        l = p.replace('legf B ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        return l
    DC = ('N42_TX_QUEUE_DRAIN_CHUNK', '8192'); PA = ('N42_PLAN_AHEAD', '1'); PF = ('N42_PULL_BY_FRAMES', '1'); AL = ('N42_ANSWER_LAYOUT_ONLY', '1')
    N4 = [DC, PA, PF, AL]; iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop339WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop339WARM2?', 'bench-loop339WARM', lines[gi[0]])
    cyc = lambda tag: f"$(python3 scripts/fleet7-runs/cycmed336.py loop339{tag} cycle)"
    warm = [mk('WARM', fn='leg'), guard, mk('WARMb', fn='leg')]
    if suffix == '':
        body = warm + [mk('B'), mk('N4', *N4), mk('Bb'), mk('N4b', *N4)]
        title = 'Claim 1: WARM, WARMb, B, N4, Bb, N4b.'
    else:
        step = lambda tag, n, prev, gate: [
            f'if python3 -c "import sys; sys.exit(0 if float(\'{gate}\') <= {n + 3} else 1)"; then', mk(tag, *N4, iv(n)),
            f'else echo "{tag} skipped: the previous step\'s cycle median {gate} ms is not within 3 ms of {n + 5}"; fi']
        body = warm + [mk('D', DC), mk('A', PA, PF), mk('L', AL),
            'C1=' + cyc('N4') + '; C2=' + cyc('N4b') + '; CM=$(python3 -c "print(min(float(\'$C1\'), float(\'$C2\')))"); echo "N4 / N4b cycle medians $C1 / $C2 ms"',
            'if python3 -c "import sys; sys.exit(0 if float(\'$CM\') <= 63 else 1)"; then', mk('N4P55', *N4, iv(55)),
            'else echo "N4P55 skipped: the lower N4 cycle median $CM ms is not within 3 ms of 60"; fi',
            'if [ -f $B/bench-loop339N4P55/round.txt ] && python3 -c "import sys; sys.exit(0 if float(\'' + cyc('N4P55') + '\') <= 58 else 1)"; then', mk('N4P50', *N4, iv(50)),
            'else echo "N4P50 skipped: N4P55 was skipped or its cycle median is not within 3 ms of 55"; fi',
            'if [ -f $B/bench-loop339N4P50/round.txt ] && python3 -c "import sys; sys.exit(0 if float(\'' + cyc('N4P50') + '\') <= 53 else 1)"; then', mk('N4P45', *N4, iv(45)),
            'else echo "N4P45 skipped: N4P50 was skipped or its cycle median is not within 3 ms of 50"; fi',
            mk('N4S163', *N4, ('F7_GASCEIL_ARG', '3423000000'), iv(52)),
            mk('N4X', *N4, ('F7_WINDOWS_ARG', '5')),
            'W339=5 python3 scripts/fleet7-runs/persist339.py loop339N4X 2>&1 | cut -c1-420; W339=5 python3 scripts/fleet7-runs/feed337.py loop339N4X 2>&1 | cut -c1-420; W339=5 python3 scripts/fleet7-runs/plan339.py loop339N4X 2>&1 | cut -c1-420; grep -E "^win[1-5] " $B/bench-loop339N4X/round.txt | cut -c1-170',
            'BT=$(python3 scripts/fleet7-runs/best337.py loop339 D A L N4P55 N4P50 N4P45 N4S163); echo "BEST single leg: ${BT:-none}"',
            'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 2: WARM, WARMb, D, A, L, N4P55, N4P50, N4P45 (gated on the cycle median), N4S163, N4X (5 windows), BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop339 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop339 = the seal chain\'s four switches (docs 10.86, scope section 12): base B = loop338 B. ' + title +
           ' Feed, lock, plan and persistence report per leg (feed337.py, feed338.py, prune337.py, plan339.py, persist339.py). Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    key = 'python3 scripts/fleet7-runs/prune337.py loop339$tag 2>&1 | cut -c1-400;'
    assert key in run
    run = run.replace(key, key + ' python3 scripts/fleet7-runs/plan339.py loop339$tag 2>&1 | cut -c1-420; python3 scripts/fleet7-runs/persist339.py loop339$tag 2>&1 | cut -c1-420;')
    n = run.count('INGEST_RUNTIME|QUEUE_PRUNE_THREAD|'); assert n >= 2, n
    run = run.replace('INGEST_RUNTIME|QUEUE_PRUNE_THREAD|', 'INGEST_RUNTIME|QUEUE_PRUNE_THREAD|PLAN_AHEAD|PULL_BY_FRAMES|ANSWER_LAYOUT_ONLY|DRAIN_CHUNK|TAKE_COMPACT|FRAME_BLOCKS|')
    # a windows argument for the longer leg: the bench runs N windows (default 3)
    k2 = '  env "$@" timeout -k 30 600 scripts/fleet7-bench.sh --tag "$tag"'
    assert k2 in run
    run = run.replace(k2, '  local WARG=3; for kv in "$@"; do case "$kv" in F7_WINDOWS_ARG=*) WARG=${kv#*=};; esac; done\n' + k2.replace('--tag "$tag"', '--tag "$tag" --windows $WARG'))
    run = run.replace("grep -E '^win[123] '", "grep -E '^win[1-5] '")
    assert '"-p n42 --lib"; do' in run
    run = run.replace('"-p n42 --lib"; do', '"-p n42-engine-types --lib" "-p n42 --lib"; do', 1)
    open(D + f'run-loop339{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop338.sh').read().replace('run-loop338.sh', 'run-loop339' + suffix + '.sh').replace('loop338', 'loop339' + suffix)
    open(D + f'launch-loop339{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ["", "b"]): derive(sfx)
