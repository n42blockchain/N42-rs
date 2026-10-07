#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop346{a,b,c}.sh / launch-loop346{a,b,c}.sh for loop346 (docs 10.93) from loop345's claim-b runner. Base A = loop345 ALL (200k, 60 ms; all seal switches: counters, body ahead, 128 batches, own freeze pool,
freeze after seal, root ops ahead, live-index defer, plan ahead, pull by frames, layout answer). A1 = depth 1 (the usual bench genesis); A2 = depth 2 (F7_GENESIS=.../n42_fleet7_bench_d2.json, nothing else; the
chain rule: header N carries the execution result of N-2). Every leg passes through bodygate; every depth-2 leg through d2gate (fields_mismatches 0, invalid_blocks 0, no ParentUnknown, tc 1, fleet7-verify clean:
a failure stops the round after that leg and keeps the datadirs); the fleet7-verify call of a depth-2 leg gets that leg's genesis.
Claim a (200k): WARM, WARMb, A1, A2 (read-back + settlement tags), A1b, A2b, A2P50, A2P45, A2P40 (each only while the previous step's cycle median is within 3 ms of its pacing and the backlog is flat; the first
failure is printed), A1P50. Claim b (400k, gas 8.4e9): WARM, WARMb, S400A1 (104 ms, loop345's floor), S400A2 (104 ms), S400A2P* (10 ms steps down while gate340 passes), S400A2b (the fastest passing pacing).
Claim c: WARM, WARMb, A2X (the best depth-2 configuration, picked by round total among the fully-full depth-2 legs, with the four-window flood), BEST, BESTb (a pair of the same configuration).
Built and run from /data/n42-build/wt338 at the pushed tip (which includes 075786ea3)."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
D2 = '/data/n42-build/wt338/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json'
base_run = open(D + 'run-loop345b.sh').read().replace('loop345', 'loop346')
def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else: toks.append(f'{key}={val}')
    return ' '.join(toks)
D2GATE = r'''
# every depth-2 leg: fields_mismatches 0, invalid_blocks 0, no ParentUnknown, tc 1, fleet7-verify clean; rename_fallbacks and rename_record_waits are printed (a nonzero fallback count is reported, not a stop)
d2gate() {
  local tag=$1 f=$B/bench-$1/node0-el.log inv fm pu tc rf rw vp
  inv=$(grep -ac 'Encountered invalid block' $f 2>/dev/null); fm=$(grep -a 'seal-first build phases' $f 2>/dev/null | grep -oE 'fields_mismatches=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
  pu=$(cat $B/bench-$1/node*-v.log $f 2>/dev/null | grep -ac 'ParentUnknown'); tc=$(cat $B/bench-$1/node*-v.log 2>/dev/null | grep -ac 'TC formed')
  rf=$(grep -a 'seal-first build phases' $f 2>/dev/null | grep -oE 'rename_fallbacks=[0-9]+' | cut -d= -f2 | paste -sd+ | bc); rw=$(grep -a 'seal-first build phases' $f 2>/dev/null | grep -oE 'rename_record_waits=[0-9]+' | cut -d= -f2 | paste -sd+ | bc)
  vp=$(python3 -c "import json; d=json.load(open('$B/bench-$1/verify.json')); print('pass' if d.get('pass') and not d.get('disagreements') else 'FAIL')" 2>/dev/null)
  echo "d2gate $tag: invalid_blocks=${inv:-0} fields_mismatches=${fm:-none} ParentUnknown=${pu:-0} TC_formed_lines=${tc:-0} verify=${vp:-none} rename_fallbacks_total=${rf:-0} rename_record_waits_total=${rw:-0}"
  if [ "${inv:-0}" != 0 ] || [ "${fm:-0}" != 0 ] || [ "${pu:-0}" != 0 ] || [ "${vp:-none}" != pass ] || [ "${tc:-0}" -gt 1 ]; then
    echo "D2GATE FAILED on $tag: stopping the round (datadirs kept as evidence)"; cleanup; echo "released at $(date +%H:%M)"; echo ALLDONE; exit 1
  fi
}
'''
def derive(suffix):
    lines = base_run.split('\n')
    g = [l for l in lines if l.startswith('legf ALL ')]
    assert len(g) == 1; p = g[0]
    for need in ('N42_SEAL_ON_COUNTERS=1', 'N42_PLAN_AHEAD_BODY=1', 'N42_BUILD_BATCHES=128', 'N42_FREEZE_POOL=own', 'N42_LIVE_INDEX_DEFER=1', 'F7_BLOCK_INTERVAL_MS=60', 'F7_GASCEIL_ARG=4200000000', '--prune.transaction-lookup.full"'):
        assert need in p, need
    def mk(name, *edits, fn='legf', d2=False, rpc=False):
        l = p.replace('legf ALL ', f'{fn} {name} ', 1)
        if d2: l = set_tok(l, 'F7_GENESIS', D2)
        for k, v in edits: l = set_tok(l, k, v)
        if rpc: l = l.replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --rpc.max-response-size 1000"')
        return l
    iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n)); gas = lambda n: ('F7_GASCEIL_ARG', str(n * 21000)); big = [gas(400000), iv(104)]
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop346WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop346WARM2?', 'bench-loop346WARM', lines[gi[0]])
    sz = big if suffix == 'b' else []
    warm = [mk('WARM', *sz, fn='leg'), guard, mk('WARMb', *sz, fn='leg')]
    if suffix == 'a':
        steps = ['PREV="loop346A2 loop346A2b"; CUR=60', 'for STEP in 50 45 40; do',
                 '  if G=$(python3 scripts/fleet7-runs/gate340.py $CUR $PREV); then echo "A2P gate at $CUR ms: $G"; else echo "A2P steps stop before $STEP ms: $G"; break; fi',
                 '  ' + mk('A2P$STEP', iv('$STEP'), d2=True), '  PREV=loop346A2P$STEP; CUR=$STEP', 'done',
                 'if G=$(python3 scripts/fleet7-runs/gate340.py $CUR $PREV); then echo "A2P final gate at $CUR ms: $G"; else echo "A2P final gate at $CUR ms failed: $G"; fi']
        body = warm + [mk('A1'), mk('A2', d2=True, rpc=True), mk('A1b'), mk('A2b', d2=True)] + steps + [mk('A1P50', iv(50))]
        title = 'Claim a (200k): WARM, WARMb, A1, A2 (read-back + settlement tags), A1b, A2b, A2P50, A2P45, A2P40 (gated), A1P50.'
    elif suffix == 'b':
        steps = ['PREV=loop346S400A2; CUR=104; FLOOR=104; for K in 1 2 3 4; do',
                 '  if G=$(python3 scripts/fleet7-runs/gate340.py $CUR $PREV); then echo "S400A2 gate at $CUR ms: $G"; FLOOR=$CUR; else echo "S400A2 steps stop at $CUR ms: $G"; break; fi; NEXT=$((CUR - 10));',
                 '  ' + mk('S400A2P$NEXT', gas(400000), iv('$NEXT'), d2=True), '  PREV=loop346S400A2P$NEXT; CUR=$NEXT; done', 'echo "S400A2 floor pacing: $FLOOR ms"']
        body = warm + [mk('S400A1', *big), mk('S400A2', *big, d2=True)] + steps + [mk('S400A2b', gas(400000), iv('$FLOOR'), d2=True)]
        title = 'Claim b (400k): WARM, WARMb, S400A1 (104 ms), S400A2 (104 ms), S400A2P* (10 ms steps down while gate340 passes), S400A2b (at the floor).'
    else:
        body = warm + ['BT=$(python3 scripts/fleet7-runs/best337.py loop346 A2P50 A2P45 A2P40 S400A2 S400A2P94 S400A2P84 S400A2P74 S400A2P64); echo "best depth-2 single leg: ${BT:-none}"',
                       'if [ -z "$BT" ]; then BT=A2; fi; argsof $BT XARGS', 'legf A2X "${XARGS[@]}" F7_WINDOWS_ARG=4',
                       'W339=4 python3 scripts/fleet7-runs/persist340.py loop346A2X 2>&1 | cut -c1-900; W339=4 python3 scripts/fleet7-runs/fields346.py loop346A2X 2>&1 | cut -c1-3600; grep -E "^win[1-5] " $B/bench-loop346A2X/round.txt | cut -c1-170',
                       'legf BEST "${XARGS[@]}"; legf BESTb "${XARGS[@]}"']
        title = 'Claim c: WARM, WARMb, A2X (the best depth-2 configuration, four windows), BEST, BESTb (a pair of it).'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop346 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop346 = deferred execution depth 2 (docs 10.93, DEFERRED_DEPTH_2_DESIGN.md 5.1): base A = loop345 ALL. ' + title +
           ' Full build and test gate (h2-consensus, h2-execution, h2-node, h2-el-rpc, qmdb-reth, engine-types, n42 libs, n42-testing), free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    k = 'python3 scripts/fleet7-runs/fields345.py loop346$tag 2>&1 | cut -c1-4200;'
    assert k in run; run = run.replace(k, 'python3 scripts/fleet7-runs/fields346.py loop346$tag 2>&1 | cut -c1-4200; python3 scripts/fleet7-runs/voteroad346.py loop346$tag 2>&1 | cut -c1-420;')
    n = run.count('SEAL_ON_COUNTERS|'); assert n >= 2, n
    # the verify call of a depth-2 leg gets that leg's genesis; the header says the depth
    k = '  local NEL FIRSTS ELIDX; NEL='
    assert run.count(k) == 1
    run = run.replace(k, '  local GLEG=""; for kv in "$@"; do case "$kv" in F7_GENESIS=*) GLEG=${kv#*=};; esac; done\n' + k)
    k = '$(F7_VALIDATORS=7 F7_ELS=$NEL F7_HTTP_BASE=8700 timeout 60 python3 scripts/fleet7-verify.py'
    assert run.count(k) == 1
    run = run.replace(k, '$(F7_GENESIS=${GLEG:-$F7_GENESIS} F7_VALIDATORS=7 F7_ELS=$NEL F7_HTTP_BASE=8700 timeout 60 python3 scripts/fleet7-verify.py')
    run = run.replace('\nlegf() {', D2GATE + '\nlegf() {', 1)
    k = '\n  case "$*" in *PLAN_AHEAD_BODY=1*) bodygate loop346$tag ;; esac'
    assert k in run
    run = run.replace(k, k + '\n  case "$*" in *n42_fleet7_bench_d2*) d2gate loop346$tag ;; esac')
    # read-back + settlement tags on A2 (the first depth-2 leg)
    k = "if [ \"$tag\" = loop346CB ]"
    assert k in run
    run = run.replace(k, "if [ \"$tag\" = loop346A2 ]")
    k = '[ "${PIPESTATUS[0]}" = 1 ] && STOPNOW=1; echo "== read-back check done $(date +%H:%M:%S)"; fi'
    assert k in run
    run = run.replace(k, '[ "${PIPESTATUS[0]}" = 1 ] && STOPNOW=1; echo "== settlement tags of $tag"; python3 scripts/fleet7-runs/settle346.py $tag 2>&1 | cut -c1-300 | tee $S/settle346-$tag.out; [ "${PIPESTATUS[0]}" = 1 ] && STOPNOW=1; echo "== read-back check done $(date +%H:%M:%S)"; fi')
    # gate: the h2 / qmdb crates and the testing suite
    k = '"-p n42-engine-types --lib -- --test-threads=1" "-p n42 --lib -- --test-threads=1"'
    assert k in run
    run = run.replace(k, '"-p n42-h2-consensus" "-p n42-h2-execution" "-p n42-h2-node" "-p n42-h2-el-rpc" "-p n42-qmdb-reth" "-p n42-testing" ' + k)
    open(D + f'run-loop346{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop345b.sh').read().replace('run-loop345b.sh', 'run-loop346' + suffix + '.sh').replace('loop345b', 'loop346' + suffix)
    open(D + f'launch-loop346{suffix}.sh', 'w').write(la)
for sfx in (sys.argv[1:] or ['a', 'b', 'c']): derive(sfx)
