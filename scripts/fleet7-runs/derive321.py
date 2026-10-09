#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop321.sh / launch-loop321.sh from the loop320 pair: the leader build throttle (N42_BUILD_THROTTLE_SOFT /
_HARD, read by the validator process, which inherits the leg's environment like N42_TAKE_COMPACT). Env tokens are set by
key regex and every other token of the base leg lines is asserted unchanged. memsample.py stays on every leg; the leg header
gains the validator process's environment."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop320.sh').read().replace('loop320', 'loop321')
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
warm, comp = lines[leg_line('WARM')], lines[leg_line('COMPACT')]
assert 'N42_TAKE_COMPACT=1' in comp and 'N42_FIELDS_AT_SEAL' not in comp and 'N42_BUILD_THROTTLE' not in comp
assert 'F7_PERSIST_BACKPRESSURE' not in comp and 'N42_ACCOUNT_HISTORY' not in comp and 'N42_PERSIST_QMDB_IN_SCOPE' not in comp
def mk(src, old, name, *edits):
    l = src.replace(f'leg {old} ', f'leg {name} ', 1)
    for k, v in edits: l = set_tok(l, k, v)
    return l
T4880 = (('N42_BUILD_THROTTLE_SOFT', 48), ('N42_BUILD_THROTTLE_HARD', 80))
new_legs = [warm, mk(comp, 'COMPACT', 'T4880', *T4880), mk(comp, 'COMPACT', 'COMPACT'),
            mk(comp, 'COMPACT', 'T4880b', *T4880),
            mk(comp, 'COMPACT', 'T3264', ('N42_BUILD_THROTTLE_SOFT', 32), ('N42_BUILD_THROTTLE_HARD', 64)),
            mk(comp, 'COMPACT', 'COMPACTb')]
first = leg_line('WARM'); last = [k for k, l in enumerate(lines) if l.startswith('leg ')][-1]
guard = [k for k, l in enumerate(lines) if l.startswith('if [ -n "$(sed -n') ]
assert len(guard) == 1 and first < guard[0] < last
lines[first:last + 1] = new_legs
run = '\n'.join(lines)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop321 = the leader build throttle (docs 10.69; N42_BUILD_THROTTLE_SOFT/HARD in the validator): legs WARM (baseline, throwaway), T4880 (COMPACT + SOFT 48 HARD 80), COMPACT (control), T4880b, T3264 (SOFT 32 HARD 64), COMPACTb. memsample.py on every leg. No fields-at-seal, no persistence backpressure or persistence switches.\n', 1)
a = '  e=$(pgrep -f \'/n4[2] node --chain\' | head -1); [ -n "$e" ] && echo "el binary:'
assert run.count(a) == 1
i = run.index(a); j = run.index('\n', i)
run = run[:j + 1] + '''  v=$(pgrep -f 'h2_validato[r]' | head -1); [ -n "$v" ] && echo "validator env: $(tr '\\0' '\\n' < /proc/$v/environ | grep -E 'N42_BUILD_THROTTLE|TAKE_COMPACT|COMPACT_BODY|FIELDS_AT_SEAL|BACKPRESSURE|ACCOUNT_HISTORY|PERSIST_QMDB' | paste -sd' ')"
''' + run[j + 1:]
open(D + 'run-loop321.sh', 'w').write(run)
open(D + 'launch-loop321.sh', 'w').write(open(D + 'launch-loop320.sh').read().replace('loop320', 'loop321'))
