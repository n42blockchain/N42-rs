#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop344{,b}.sh / launch-loop344{,b}.sh for loop344 (docs 10.91) from loop343's claim-1 runner. usage: derive344.py [a|b] [new|old] (b: the binary the block-size claim runs on).
Base F2 = loop343 F2 (N42_LIVE_INDEX_DEFER=1 N42_FREEZE_AFTER_SEAL=1 N42_ROOT_OPS_AHEAD=1 on loop341's P line; 200k, 60 ms). OLD = 09a1284e4's binaries (copied to /data/n42-build/bins-old before the
checkout moved), NEW = the pushed tip a97a14646 (the other contributor's dependency / hardening commits), built by the launcher's gate in /data/n42-build/wt338 (F7_BIN=$NAT).
Claim 1 (a): WARM (new), WARMo (old), F2old, F2new, F2oldb, F2newb, Gold, Gnew (F7_DIRECT_PUSH=0: bodies over gossip; gossip344.py), the kill-and-restart check (restart344.py) on the layer after Gnew,
and the read-back check on F2new (layer with --rpc.max-response-size 1000). Claim 2 (b): WARM, WARMb, S300 (300k, 90 ms), S400 (400k, 120 ms), S300b / S400b at the pacing the first leg's seal
suggests (seal median + 5 ms, once), S400P* = S400 stepped down 5 ms while gate340.py passes (cycle within 3 ms of the pacing and a flat backlog), BEST / BESTb."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
OLD = '/data/n42-build/bins-old'
base_run = open(D + 'run-loop343.sh').read().replace('loop343', 'loop344')
def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else: toks.append(f'{key}={val}')
    return ' '.join(toks)
def derive(suffix, binary):
    lines = base_run.split('\n')
    g = [l for l in lines if l.startswith('legf F2 ')]
    assert len(g) == 1; p = g[0].replace(' --rpc.max-response-size 1000"', '"')
    for need in ('N42_LIVE_INDEX_DEFER=1', 'N42_FREEZE_AFTER_SEAL=1', 'N42_ROOT_OPS_AHEAD=1', 'F7_BLOCK_INTERVAL_MS=60', 'F7_BIN=$NAT', 'F7_GASCEIL_ARG=4200000000', '--prune.transaction-lookup.full"'):
        assert need in p, need
    def mk(name, *edits, fn='legf', rpc=False, old=False):
        l = p.replace('legf F2 ', f'{fn} {name} ', 1)
        if old: l = set_tok(l, 'F7_BIN', OLD)
        for k, v in edits: l = set_tok(l, k, v)
        if rpc: l = l.replace('--prune.transaction-lookup.full"', '--prune.transaction-lookup.full --rpc.max-response-size 1000"')
        return l
    iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n)); gas = lambda n: ('F7_GASCEIL_ARG', str(n * 21000))
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop344WARM')]; assert len(gi) == 1
    guard = re.sub(r'bench-loop344WARM2?', 'bench-loop344WARM', lines[gi[0]])
    if suffix == 'a':
        body = [mk('WARM', fn='leg'), guard, mk('WARMo', fn='leg', old=True),
                mk('F2old', old=True), mk('F2new', rpc=True), mk('F2oldb', old=True), mk('F2newb'),
                mk('Gold', ('F7_DIRECT_PUSH', '0'), old=True), mk('Gnew', ('F7_DIRECT_PUSH', '0'))]
        title = 'Claim 1: WARM (new), WARMo (old), F2old, F2new, F2oldb, F2newb, Gold, Gnew (gossip bodies; then the kill-and-restart check), read-back on F2new.'
    else:
        o = binary == 'old'
        body = [mk('WARM', fn='leg', old=o), guard, mk('WARMb', fn='leg', old=o),
                mk('S300', gas(300000), iv(90), old=o), mk('S400', gas(400000), iv(120), old=o),
                'for K in 300 400; do SSK=$(python3 scripts/fleet7-runs/cycmed336.py loop344S$K seal); PK=$(python3 -c "import math; print(int(math.ceil(float(\'$SSK\') + 5)))"); echo "S$K sealed_at median $SSK ms: pacing $PK ms for the b leg"; eval "P$K=$PK"; done',
                mk('S300b', gas(300000), iv('$P300'), old=o), mk('S400b', gas(400000), iv('$P400'), old=o),
                'PREV=loop344S400b; CUR=$P400; PLEGS=""; for K in 1 2 3; do if G=$(python3 scripts/fleet7-runs/gate340.py $CUR $PREV); then echo "S400 gate at $CUR ms: $G"; else echo "S400P steps stop at $CUR ms: $G"; break; fi; NEXT=$((CUR - 5));',
                '  ' + mk('S400P$NEXT', gas(400000), iv('$NEXT'), old=o),
                '  PREV=loop344S400P$NEXT; CUR=$NEXT; PLEGS="$PLEGS S400P$NEXT"; done',
                'BT=$(python3 scripts/fleet7-runs/best337.py loop344 $PLEGS); echo "BEST single leg: ${BT:-none}"',
                'if [ -n "$BT" ]; then argsof $BT BARGS; legf BEST "${BARGS[@]}"; legf BESTb "${BARGS[@]}"; fi']
        title = f'Claim 2 (block size, on the {binary.upper()} binary): WARM, WARMb, S300 (90 ms), S400 (120 ms), S300b / S400b (seal + 5 ms), S400P* (stepped down while the gate passes), BEST, BESTb.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    run = '\n'.join(lines)
    i0 = run.index('# loop344 = '); i1 = run.index('cd /data/n42-build/wt338')
    hdr = ('# loop344 = the other contributor\'s commits against the loop343 binary, and block size at the new seal floors (docs 10.91): base F2 = loop343 F2. ' + title +
           ' Full build and test gate on NEW, free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    assert 'if [ "$tag" = loop344F2 ]' in run
    run = run.replace('if [ "$tag" = loop344F2 ]', 'if [ "$tag" = loop344F2new ]')
    k = "  for p in $(pgrep -f '/n4[2] node --chain'; pgrep -f 'h2_validato[r]'; pgrep -f 'tx_floo[d]'); do kill -9 $p 2>/dev/null; done; sleep 2\n  if [ \"$STOPNOW\" = 1 ]"
    assert run.count(k) == 1
    extra = ('  case $tag in G*) python3 scripts/fleet7-runs/gossip344.py $tag 2>&1 | cut -c1-420 ;; esac\n'
             '  if [ "$tag" = loop344Gnew ]; then echo "== kill-and-restart check of $tag from $(date +%H:%M:%S)"; timeout 900 python3 scripts/fleet7-runs/restart344.py $tag 2>&1 | cut -c1-420 | tee $S/restart344-$tag.out; echo "== restart check done $(date +%H:%M:%S)"; fi\n')
    run = run.replace(k, extra + k)
    open(D + f'run-loop344{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop343.sh').read().replace('run-loop343.sh', 'run-loop344' + suffix + '.sh').replace('loop343', 'loop344' + suffix)
    open(D + f'launch-loop344{suffix}.sh', 'w').write(la)
a = sys.argv[1:] or ['a']
if a[0] == 'a': derive('a', 'new')
else: derive('b', a[1] if len(a) > 1 else 'new')
