#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop323.sh / launch-loop323.sh from the loop322 pair. Base line A = loop322's AHOFF (COMPACT + throttle 48/80 +
N42_ACCOUNT_HISTORY=off). Every leg replays the pre-generated attested set /data/n42-pregen/g900000 (offset 900000; the live
generator signs at ~1.2M/s on its 17 cores and cannot offer more): F7_FLOOD_REPLAY + F7_OFFSET_ARG on the leg line, the offer
by F7_FLOOD_RATE. WARM is the baseline line with the same replay at 1.25M and a guard that stops the round if the replay did
not run. The test gate gains `-p n42 --lib`. Env tokens by key regex; every other token asserted unchanged."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop322.sh').read().replace('loop322', 'loop323')
lines = run.split('\n')

def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else:
        toks.append(f'{key}={val}')
    new = ' '.join(toks)
    a = [t for t in line.split(' ') if not t.startswith(key + '=')]
    b = [t for t in new.split(' ') if not t.startswith(key + '=')]
    assert a == b, key
    return new

def leg_line(name):
    i = [k for k, l in enumerate(lines) if l.startswith(f'leg {name} ')]
    assert len(i) == 1, name
    return i[0]
warm, ahoff = lines[leg_line('WARM')], lines[leg_line('AHOFF')]
assert 'N42_ACCOUNT_HISTORY=off' in ahoff and 'N42_BUILD_THROTTLE_HARD=80' in ahoff and 'N42_PERSIST_QMDB_IN_SCOPE' not in ahoff
assert 'F7_FLOOD_REPLAY' not in warm + ahoff and 'F7_FLOOD_RATE=1250000' in ahoff and 'F7_FLOOD_RATE=1250000' in warm
REPLAY = (('F7_FLOOD_REPLAY', '/data/n42-pregen/g900000'), ('F7_OFFSET_ARG', '900000'))
def mk(src, old, name, *edits):
    l = src.replace(f'leg {old} ', f'leg {name} ', 1)
    for k, v in (*REPLAY, *edits): l = set_tok(l, k, v)
    return l
guard = '''W=$B/bench-loop323WARM; if grep -q 'REFUSING' $W/flood.log 2>/dev/null || ! grep -q 'replay *:' $W/flood.log 2>/dev/null || [ "$(grep -oE 'win1 +tps= *[0-9,]+' $W/round.txt | grep -oE '[0-9,]+$' | tr -d , | head -1)" -lt 500000 ]; then echo "REPLAY DID NOT RUN on WARM: stopping"; grep -E 'REFUSING|replay' $W/flood.log | head -5 | cut -c1-300; echo ALLDONE; exit 1; fi'''
new_legs = [mk(warm, 'WARM', 'WARM'), guard,
            mk(ahoff, 'AHOFF', 'A'),
            mk(ahoff, 'AHOFF', 'A16', ('F7_FLOOD_RATE', 1600000)),
            mk(ahoff, 'AHOFF', 'A20', ('F7_FLOOD_RATE', 2000000)),
            mk(ahoff, 'AHOFF', 'A20P90', ('F7_FLOOD_RATE', 2000000), ('F7_BLOCK_INTERVAL_MS', 90)),
            mk(ahoff, 'AHOFF', 'A20P80', ('F7_FLOOD_RATE', 2000000), ('F7_BLOCK_INTERVAL_MS', 80)),
            mk(ahoff, 'AHOFF', 'Ab')]
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
lines[legs[0]:legs[-1] + 1] = new_legs
run = '\n'.join(lines)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop323 = the offer above the tick (docs 10.71): base A = loop322 AHOFF (COMPACT + throttle 48/80 + N42_ACCOUNT_HISTORY=off), every leg replaying /data/n42-pregen/g900000 at the offer. Legs WARM (baseline, replay at 1.25M, stops the round if the replay did not run), A (1.25M), A16 (1.6M), A20 (2.0M), A20P90, A20P80 (2.0M at 90 and 80 ms pacing), Ab. memsample.py and the env headers on every leg; tests include n42 --lib.\n', 1)
m = re.search(r'^for spec in (.*); do$', run, re.M)
assert m and '"-p n42 --lib"' not in m.group(1)
run = run[:m.end(1)] + ' "-p n42 --lib"' + run[m.end(1):]
open(D + 'run-loop323.sh', 'w').write(run)
open(D + 'launch-loop323.sh', 'w').write(open(D + 'launch-loop322.sh').read().replace('loop322', 'loop323'))
