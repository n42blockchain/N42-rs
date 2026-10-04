#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop324.sh / launch-loop324.sh from the loop323 pair. Base F = loop323's A20 line exactly (AHOFF + COMPACT +
throttle 48/80, replayed attested set, offer 2.0M, pacing 100). FV/FS add N42_FIELDS_AT_SEAL=verify/1 (read by the execution
layers); FSG is FS with F7_GASCEIL_ARG=4200000000 (200,000 transfers a block; the runner derives the genesis and the gossip cap
from it, as loop300 did with the same replay set). After FV the runner stops (FS not run) on any fields_mismatches above 0 or a
"fields published at the seal differ" line. The n42 --lib test gate and the WARM replay guard of loop323 stay."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop323.sh').read().replace('loop323', 'loop324')
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
warm, a20 = lines[leg_line('WARM')], lines[leg_line('A20')]
assert 'F7_FLOOD_RATE=2000000' in a20 and 'N42_ACCOUNT_HISTORY=off' in a20 and 'F7_FLOOD_REPLAY=/data/n42-pregen/g900000' in a20
for k in ('N42_FIELDS_AT_SEAL', 'F7_GASCEIL_ARG', 'F7_PERSIST_BACKPRESSURE', 'N42_PERSIST_QMDB_IN_SCOPE'): assert k not in a20
def mk(old, name, *edits):
    l = a20.replace(f'leg {old} ', f'leg {name} ', 1)
    for k, v in edits: l = set_tok(l, k, v)
    return l
FS = ('N42_FIELDS_AT_SEAL', '1')
guard = '''if [ -n "$(sed -n 's/.*fields_mismatches=\\([0-9]*\\).*/\\1/p' $S/strip-loop324FV/el.log | awk '$1>0' | head -1)" ] || grep -q 'the fields published at the seal differ' $S/strip-loop324FV/el.log 2>/dev/null; then echo "FV MISMATCH: stopping, FS not run"; grep -m5 -E 'the fields published at the seal differ' $S/strip-loop324FV/el.log | cut -c1-600; echo ALLDONE; exit 1; fi'''
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
guard_i = [k for k, l in enumerate(lines) if l.startswith("W=$B/bench-loop324WARM")]
assert len(guard_i) == 1
new = [warm, lines[guard_i[0]], mk('A20', 'F'), mk('A20', 'FV', ('N42_FIELDS_AT_SEAL', 'verify')), guard,
       mk('A20', 'FS', FS), mk('A20', 'Fb'), mk('A20', 'FSb', FS), mk('A20', 'FSG', FS, ('F7_GASCEIL_ARG', 4200000000))]
lines[legs[0]:legs[-1] + 1] = new
run = '\n'.join(lines)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop324 = fields at the seal on the full-block base (docs 10.72): base F = loop323 A20 (AHOFF + COMPACT + throttle 48/80, replay set, offer 2.0M). Legs WARM, F (control), FV (N42_FIELDS_AT_SEAL=verify, stops the round on a mismatch), FS (=1), Fb, FSb, FSG (FS at 200,000 transfers a block via F7_GASCEIL_ARG=4200000000). memsample.py and the env headers on every leg; tests include n42 --lib.\n', 1)
open(D + 'run-loop324.sh', 'w').write(run)
open(D + 'launch-loop324.sh', 'w').write(open(D + 'launch-loop323.sh').read().replace('loop323', 'loop324'))
