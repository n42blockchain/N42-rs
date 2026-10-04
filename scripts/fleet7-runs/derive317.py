#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop317.sh / launch-loop317.sh from the loop316 pair. Env tokens are set by key regex and every other
token of the base leg line is asserted unchanged."""
import re, sys
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop316.sh').read().replace('loop316', 'loop317')
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
    # every other token unchanged
    a = [t for t in line.split(' ') if not t.startswith(key + '=')]
    b = [t for t in new.split(' ') if not t.startswith(key + '=')]
    assert a == b, key
    return new

def leg_line(name):
    i = [k for k, l in enumerate(lines) if l.startswith(f'leg {name} ')]
    assert len(i) == 1, name
    return i[0]
base_i = leg_line('NEW'); base = lines[base_i]
assert 'leg NEW F7_BIN=$NAT' in base
def mk(name, *edits):
    l = base.replace('leg NEW ', f'leg {name} ', 1)
    for k, v in edits: l = set_tok(l, k, v)
    return l
new_legs = [mk('WARM'), mk('BASE'),
            mk('P32', ('F7_PERSIST_THRESHOLD', 32), ('F7_BLOCK_BUFFER_TARGET', 24)),
            mk('NOSYNC', ('N42_ROCKSDB_NOSYNC', 1)),
            mk('TRACE'), mk('BASEb')]
# BASE-like legs are identical to NEW but for the name
for n in ('WARM', 'BASE', 'TRACE', 'BASEb'):
    assert [l for l in new_legs if l.startswith(f'leg {n} ')][0].split(' ')[2:] == base.split(' ')[2:]
first = leg_line('WARM'); last = leg_line('NEWP90')
assert first < base_i < last
lines[first:last + 1] = new_legs
run = '\n'.join(lines)

# 1. header comment
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop317 = measurement only (docs 10.65): kernel counters once a second beside every leg (kernsample.py), legs WARM, BASE, P32 (persistence threshold 32, buffer 24), NOSYNC (N42_ROCKSDB_NOSYNC=1), TRACE (leader thread-wait sampling in window 1), BASEb.\n', 1)
# 2. start/stop the sampler around the leg
a = '  echo "leg $tag start $(date +%H:%M:%S) load'
assert run.count(a) == 1
run = run.replace(a, '''  STRIP=$S/strip-$tag; mkdir -p $STRIP; python3 scripts/fleet7-runs/kernsample.py $STRIP/kern.log & KS=$!
  ( case "$tag" in *TRACE*) n=0; until grep -aq 'mined through nonce' $B/bench-$tag/flood.log 2>/dev/null; do sleep 0.5; n=$((n+1)); [ $n -gt 700 ] && exit 0; done; sleep 2
      for p in $(pgrep -f '/n4[2] node --chain'); do tr '\\0' ' ' < /proc/$p/cmdline | grep -q "bench/node0" && { python3 scripts/fleet7-runs/wchansample.py $p 20 $S/wchan-$tag-node0.tsv; break; }; done;; esac ) > $S/trace317-$tag.out 2>&1 &
''' + a, 1)
b = '; echo "round $tag exit $? at $(date +%H:%M:%S)"'
assert run.count(b) == 1
run = run.replace(b, b + '; kill $KS 2>/dev/null; wait $KS 2>/dev/null', 1)
open(D + 'run-loop317.sh', 'w').write(run)

la = open(D + 'launch-loop316.sh').read().replace('loop316', 'loop317')
open(D + 'launch-loop317.sh', 'w').write(la)
