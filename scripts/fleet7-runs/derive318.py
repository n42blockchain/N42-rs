#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop318.sh / launch-loop318.sh from the loop317 pair. The kernel sampler and the TRACE hook are
dropped; env tokens are set by key regex and every other token of the base leg line is asserted unchanged."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop317.sh').read().replace('loop317', 'loop318')
lines = run.split('\n')

def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\d+$')
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
base_i = leg_line('BASE'); base = lines[base_i]
assert 'leg BASE F7_BIN=$NAT' in base
# What the compact legs need: BODY_ONCE and direct push (F7_DIRECT_PUSH=1, exported) are already on the base line.
assert ' N42_BODY_ONCE=1 ' in base and 'N42_TAKE_COMPACT' not in base and 'N42_COMPACT_BODY' not in base
def mk(name, *edits):
    l = base.replace('leg BASE ', f'leg {name} ', 1)
    for k, v in edits: l = set_tok(l, k, v)
    return l
COMPACT = (('N42_TAKE_COMPACT', 1), ('N42_COMPACT_BODY', 1))
new_legs = [mk('WARM'), mk('BASE'), mk('COMPACT', *COMPACT), mk('BASEb'), mk('COMPACTb', *COMPACT),
            mk('COMPACTP90', *COMPACT, ('F7_BLOCK_INTERVAL_MS', 90))]
for n in ('WARM', 'BASEb'):
    assert [l for l in new_legs if l.startswith(f'leg {n} ')][0].split(' ')[2:] == base.split(' ')[2:]
first = leg_line('WARM'); last = leg_line('BASEb')
assert first < base_i < last
lines[first:last + 1] = new_legs
run = '\n'.join(lines)

run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop318 = measurement only (docs 10.66): N42_TAKE_COMPACT=1 N42_COMPACT_BODY=1 (206cc817e: the leader\'s answer carries no transaction bytes) against the loop317 baseline. Legs WARM (throwaway), BASE, COMPACT, BASEb, COMPACTb, COMPACTP90 (COMPACT at 90 ms pacing).\n', 1)

# drop the kernel sampler and the TRACE hook (the derive317 insertions)
i0 = run.index('  STRIP=$S/strip-$tag; mkdir -p $STRIP; python3 scripts/fleet7-runs/kernsample.py')
i1 = run.index('  echo "leg $tag start')
run = run[:i0] + run[i1:]
b = '; kill $KS 2>/dev/null; wait $KS 2>/dev/null'
assert run.count(b) == 1
run = run.replace(b, '', 1)
code = '\n'.join(l for l in run.split('\n') if not l.startswith('#'))
assert 'kernsample' not in code and 'wchansample' not in code and '$KS' not in code
open(D + 'run-loop318.sh', 'w').write(run)

l = open(D + 'launch-loop317.sh').read().replace('loop317', 'loop318')
open(D + 'launch-loop318.sh', 'w').write(l)
