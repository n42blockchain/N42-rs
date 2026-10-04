#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop319.sh / launch-loop319.sh from the loop318 pair. Env tokens are set by key regex and every other
token of the base leg lines is asserted unchanged. Adds memsample.py (2 s RSS and in-memory block samples) beside each leg."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop318.sh').read().replace('loop318', 'loop319')
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
base_i = leg_line('BASE'); comp_i = leg_line('COMPACT')
base, comp = lines[base_i], lines[comp_i]
assert 'N42_TAKE_COMPACT=1' in comp and 'N42_TAKE_COMPACT' not in base and 'F7_PERSIST_BACKPRESSURE' not in comp
def mk(src, old, name, *edits):
    l = src.replace(f'leg {old} ', f'leg {name} ', 1)
    for k, v in edits: l = set_tok(l, k, v)
    return l
new_legs = [mk(base, 'BASE', 'WARM'),
            mk(comp, 'COMPACT', 'CBP32', ('F7_PERSIST_BACKPRESSURE', 32)),
            mk(comp, 'COMPACT', 'COMPACT'),
            mk(comp, 'COMPACT', 'CBP32b', ('F7_PERSIST_BACKPRESSURE', 32)),
            mk(comp, 'COMPACT', 'CBP16', ('F7_PERSIST_BACKPRESSURE', 16)),
            mk(comp, 'COMPACT', 'COMPACTb')]
assert new_legs[2].split(' ')[2:] == comp.split(' ')[2:] and new_legs[5].split(' ')[2:] == comp.split(' ')[2:]
first = leg_line('WARM'); last = leg_line('COMPACTP90')
assert first < base_i < comp_i < last
lines[first:last + 1] = new_legs
run = '\n'.join(lines)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop319 = test of docs 10.66 addendum: COMPACT with a bound on unpersisted blocks (--engine.persistence-backpressure-threshold via F7_PERSIST_BACKPRESSURE, default 1024) and a per-node 2 s sampler of RSS and in-memory blocks (memsample.py -> strip-<tag>/mem.log). Legs WARM (baseline, throwaway), CBP32, COMPACT (unbounded control), CBP32b, CBP16, COMPACTb.\n', 1)

a = '  echo "leg $tag start $(date +%H:%M:%S) load'
assert run.count(a) == 1
run = run.replace(a, '''  STRIP=$S/strip-$tag; mkdir -p $STRIP; rm -f $STRIP/mem.log
  ( n=0; until grep -q 'funding' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done; exec python3 scripts/fleet7-runs/memsample.py $STRIP/mem.log 3 ) > /dev/null 2>&1 & MS=$!
''' + a, 1)
b = '; echo "round $tag exit $? at $(date +%H:%M:%S)"'
assert run.count(b) == 1
run = run.replace(b, b + '; kill $MS 2>/dev/null; wait $MS 2>/dev/null', 1)
open(D + 'run-loop319.sh', 'w').write(run)
open(D + 'launch-loop319.sh', 'w').write(open(D + 'launch-loop318.sh').read().replace('loop318', 'loop319'))
