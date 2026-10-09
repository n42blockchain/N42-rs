#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop340{,b,c}.sh / launch-loop340{,b,c}.sh for loop340 (docs 10.87) from loop339's claim-1 runner.
Base N = loop339 N4 (200,000 a block, 60 ms, 24 permits, three leader layers, fields at seal, road runtime, N42_TX_QUEUE_DRAIN_CHUNK=8192 N42_PLAN_AHEAD=1 N42_PULL_BY_FRAMES=1
N42_ANSWER_LAYOUT_ONLY=1). P3 = N + N42_SF_PARALLEL_ENCODE=1 N42_SF_EARLY_WRITEBACK=1 N42_PERSIST_QMDB_IN_SCOPE=1 (all three are read by the execution layer, in
crates/storage/provider; the runner exports them to both processes and prints them in both environment headers). PE = N + parallel encode; PEW = PE + early writeback;
P3S = P3 + `--prune.sender-recovery.full` appended to F7_EL_EXTRA (the bench's other prune flag stays).
Claim 1 (a): WARM, WARMb, N, P3, Nb, P3b, with the static-file read-back check (check340.py) on the layer after P3, before its datadirs are wiped (a failure stops the round).
Claim 2 (b): WARM, WARMb, PE, PEW, P3S, P3S163, the pacing steps P3P55..P3P40 (gate340.py: each only while the previous step's cycle median is within 3 ms of its pacing AND its
backlog is flat; the first failing test stops the steps and is printed), P3X (the fastest pacing that held, five windows). Claim 3 (c): WARM, WARMb, BEST, BESTb.
Built and run from /data/n42-build/wt338 at the pushed tip."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop339.sh').read().replace('loop339', 'loop340')
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
    g = [l for l in lines if l.startswith('legf N4 ')]
    assert len(g) == 1; p = g[0]
    for need in ('N42_LEADER_LAYERS=3', 'N42_FIELDS_AT_SEAL=1', 'F7_GASCEIL_ARG=4200000000', 'F7_BLOCK_INTERVAL_MS=60', 'N42_ROAD_RUNTIME=1', 'N42_TX_INGEST_RECOVER_PARALLEL=24',
                 'N42_TX_QUEUE_DRAIN_CHUNK=8192', 'N42_PLAN_AHEAD=1', 'N42_PULL_BY_FRAMES=1', 'N42_ANSWER_LAYOUT_ONLY=1', '--prune.transaction-lookup.full"'):
        assert need in p, need
    def mk(name, *edits, fn='legf', sender=False):
        l = p.replace('legf N4 ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        if sender: l = l.replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --prune.sender-recovery.full"')
        return l
    PE = ('N42_SF_PARALLEL_ENCODE', '1'); EW = ('N42_SF_EARLY_WRITEBACK', '1'); QS = ('N42_PERSIST_QMDB_IN_SCOPE', '1'); P3 = [PE, EW, QS]; iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop340WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop340WARM2?', 'bench-loop340WARM', lines[gi[0]])
    warm = [mk('WARM', fn='leg'), guard, mk('WARMb', fn='leg')]
    if suffix == '':
        body = warm + [mk('N'), mk('P3', *P3), mk('Nb'), mk('P3b', *P3)]
        title = 'Claim 1: WARM, WARMb, N, P3, Nb, P3b (read-back check after P3).'
    elif suffix == 'b':
        steps = ['HELD=60; PREV="loop340P3 loop340P3b"',
                 'for STEP in 55 50 45 40 35; do',
                 '  if G=$(python3 scripts/fleet7-runs/gate340.py $((STEP + 5)) $PREV); then echo "pacing gate for $STEP ms: $G"; HELD=$((STEP + 5)); else echo "pacing steps stop before $STEP ms: $G"; break; fi',
                 '  [ $STEP = 35 ] && break',
                 '  ' + mk('P3P$STEP', *P3, iv('$STEP')),
                 '  PREV=loop340P3P$STEP',
                 'done', 'echo "fastest pacing that held: $HELD ms"']
        body = warm + [mk('PE', PE), mk('PEW', PE, EW), mk('P3S', *P3, sender=True), mk('P3S163', *P3, ('F7_GASCEIL_ARG', '3423000000'), iv(52))] + steps + [
            mk('P3X', *P3, iv('$HELD'), ('F7_WINDOWS_ARG', '5')),
            'W339=5 python3 scripts/fleet7-runs/persist340.py loop340P3X 2>&1 | cut -c1-900; W339=5 python3 scripts/fleet7-runs/feed337.py loop340P3X 2>&1 | cut -c1-420; W339=5 python3 scripts/fleet7-runs/plan339.py loop340P3X 2>&1 | cut -c1-420; grep -E "^win[1-5] " $B/bench-loop340P3X/round.txt | cut -c1-170']
        title = 'Claim 2: WARM, WARMb, PE, PEW, P3S, P3S163, P3P55..P3P40 (gated: cycle within 3 ms and flat backlog), P3X (five windows).'
    elif suffix == 'r':
        # claim 1 stopped after P3: the read-back check flagged reth's normal start-up line and a deferred header's gasUsed, and a 200k block does not fit the default 160 MB RPC response: the check's own faults.
        # The rest of claim 1 runs again here with the fixed check on P3b (its layer started with --rpc.max-response-size 1000, an RPC-only limit).
        body = warm + [mk('Nb'), mk('P3b', *P3).replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --rpc.max-response-size 1000"')]
        title = 'Claim 1 repeat: WARM, WARMb, Nb, P3b (read-back check after P3b).'
    else:
        body = warm + ['BT=$(python3 scripts/fleet7-runs/best337.py loop340 PE PEW P3S P3S163 P3P55 P3P50 P3P45 P3P40); echo "BEST single leg: ${BT:-none}"',
                       'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = 'Claim 3: WARM, WARMb, BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop340 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop340 = persistence (docs 10.87, persistence study section 11): base N = loop339 N4. ' + title +
           ' Feed, lock, plan and persistence-part report per leg (feed337.py, feed338.py, prune337.py, plan339.py, persist340.py). Full build and test gate, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    k = 'python3 scripts/fleet7-runs/persist339.py loop340$tag 2>&1 | cut -c1-420;'
    assert k in run; run = run.replace(k, 'python3 scripts/fleet7-runs/persist340.py loop340$tag 2>&1 | cut -c1-900;')
    n = run.count('PLAN_AHEAD|PULL_BY_FRAMES|'); assert n >= 2, n
    run = run.replace('PLAN_AHEAD|PULL_BY_FRAMES|', 'SF_PARALLEL_ENCODE|SF_EARLY_WRITEBACK|PERSIST_QMDB_IN_SCOPE|PLAN_AHEAD|PULL_BY_FRAMES|')
    # a neighbour's load: wait up to two minutes below 8, then go and say so on the leg line (the leg line prints the load)
    k = '  run loop340$tag F7_MEASURE_FROM_LOG=1'
    assert run.count(k) == 1
    run = run.replace(k, '  n=0; while [ "$(awk \'{printf "%d", $1}\' /proc/loadavg)" -ge 8 ] && [ $n -lt 4 ]; do echo "load $(awk \'{print $1}\' /proc/loadavg) at $(date +%H:%M:%S), waiting"; sleep 30; n=$((n+1)); done\n' + k)
    # the static-file read-back check on P3, with the layer still up
    k = "  for p in $(pgrep -f '/n4[2] node --chain'; pgrep -f 'h2_validato[r]'; pgrep -f 'tx_floo[d]'); do kill -9 $p 2>/dev/null; done; sleep 2\n}"
    assert run.count(k) == 1
    hook = ('  STOPNOW=0\n  if [ "$tag" = loop340P3' + ('b' if suffix == 'r' else '') + ' ]; then echo "== read-back check of $tag (layer still up) from $(date +%H:%M:%S)"; timeout 1500 python3 scripts/fleet7-runs/check340.py $tag 2>&1 | cut -c1-420 | tee $S/check340-$tag.out; '
            '[ "${PIPESTATUS[0]}" = 1 ] && STOPNOW=1; echo "== read-back check done $(date +%H:%M:%S)"; fi\n')
    tail = ('  for p in $(pgrep -f \'/n4[2] node --chain\'; pgrep -f \'h2_validato[r]\'; pgrep -f \'tx_floo[d]\'); do kill -9 $p 2>/dev/null; done; sleep 2\n'
            '  if [ "$STOPNOW" = 1 ]; then echo "READ-BACK CHECK FAILED on $tag: stopping the round (datadirs kept as evidence)"; cleanup; echo "released at $(date +%H:%M)"; echo ALLDONE; exit 1; fi\n}')
    run = run.replace(k, hook + tail)
    run = run.replace("grep -E '^win[123] '", "grep -E '^win[1-5] '")
    run = run.replace('"-p n42-engine-types --lib" "-p n42 --lib"', '"-p n42-engine-types --lib -- --test-threads=1" "-p n42 --lib"')
    assert 'test-threads=1' in run
    open(D + f'run-loop340{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop339.sh').read().replace('run-loop339.sh', 'run-loop340' + suffix + '.sh').replace('loop339', 'loop340' + suffix)
    open(D + f'launch-loop340{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ['', 'b', 'c', 'r']): derive(sfx)
