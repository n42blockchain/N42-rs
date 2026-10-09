#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop322.sh / launch-loop322.sh from the loop321 pair: the persistence switches (N42_PERSIST_QMDB_IN_SCOPE,
N42_ACCOUNT_HISTORY, both read by the execution layer, inherited from the leg line). CTRL is loop321's T4880 line (COMPACT +
throttle SOFT 48 HARD 80). Env tokens are set by key regex and every other token of the base leg lines is asserted unchanged."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop321.sh').read().replace('loop321', 'loop322')
lines = run.split('\n')

def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S+$')
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
warm, ctrl = lines[leg_line('WARM')], lines[leg_line('T4880')]
assert 'N42_BUILD_THROTTLE_SOFT=48' in ctrl and 'N42_BUILD_THROTTLE_HARD=80' in ctrl and 'N42_TAKE_COMPACT=1' in ctrl
for k in ('N42_FIELDS_AT_SEAL', 'F7_PERSIST_BACKPRESSURE', 'N42_ACCOUNT_HISTORY', 'N42_PERSIST_QMDB_IN_SCOPE'): assert k not in ctrl
def mk(src, old, name, *edits):
    l = src.replace(f'leg {old} ', f'leg {name} ', 1)
    for k, v in edits: l = set_tok(l, k, v)
    return l
Q, A = ('N42_PERSIST_QMDB_IN_SCOPE', 1), ('N42_ACCOUNT_HISTORY', 'off')
new_legs = [warm, mk(ctrl, 'T4880', 'CTRL'), mk(ctrl, 'T4880', 'QSCOPE', Q), mk(ctrl, 'T4880', 'AHOFF', A),
            mk(ctrl, 'T4880', 'BOTH', Q, A), mk(ctrl, 'T4880', 'CTRLb'), mk(ctrl, 'T4880', 'BOTHb', Q, A)]
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
lines[legs[0]:legs[-1] + 1] = new_legs
run = '\n'.join(lines)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop322 = the persistence switches (docs 10.70; PERSISTENCE_COST_STUDY 9): legs WARM (baseline, throwaway), CTRL (loop321 T4880: COMPACT + throttle 48/80), QSCOPE (+ N42_PERSIST_QMDB_IN_SCOPE=1), AHOFF (+ N42_ACCOUNT_HISTORY=off), BOTH, CTRLb, BOTHb. memsample.py and the validator env header on every leg.\n', 1)
old = "grep -E 'FIELDS_AT_SEAL|TAKE_COMPACT"
assert run.count(old) == 1
run = run.replace(old, "grep -E 'ACCOUNT_HISTORY|PERSIST_QMDB|FIELDS_AT_SEAL|TAKE_COMPACT", 1)
open(D + 'run-loop322.sh', 'w').write(run)
open(D + 'launch-loop322.sh', 'w').write(open(D + 'launch-loop321.sh').read().replace('loop321', 'loop322'))
