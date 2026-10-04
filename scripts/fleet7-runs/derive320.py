#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop320.sh / launch-loop320.sh from the loop319 pair. Env tokens are set by key regex and every other
token of the base leg lines is asserted unchanged. The memsample.py sampler stays on every leg. After FVERIFY the runner
stops (released, FAS not run) if any fields_mismatches above 0 or a "fields published at the seal differ" line appears."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop319.sh').read().replace('loop319', 'loop320')
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
warm_i = leg_line('WARM'); comp_i = leg_line('COMPACT')
warm, comp = lines[warm_i], lines[comp_i]
assert 'N42_TAKE_COMPACT=1' in comp and 'F7_PERSIST_BACKPRESSURE' not in comp and 'N42_TAKE_COMPACT' not in warm
assert 'N42_FIELDS_AT_SEAL' not in comp and 'N42_BUILD_THROTTLE' not in comp
def mk(src, old, name, *edits):
    l = src.replace(f'leg {old} ', f'leg {name} ', 1)
    for k, v in edits: l = set_tok(l, k, v)
    return l
new_legs = [mk(warm, 'WARM', 'WARM'), mk(comp, 'COMPACT', 'COMPACT'),
            mk(comp, 'COMPACT', 'FVERIFY', ('N42_FIELDS_AT_SEAL', 'verify')),
            'GUARD_FVERIFY',
            mk(comp, 'COMPACT', 'FAS', ('N42_FIELDS_AT_SEAL', '1')),
            mk(comp, 'COMPACT', 'COMPACTb'), mk(comp, 'COMPACT', 'FASb', ('N42_FIELDS_AT_SEAL', '1'))]
assert new_legs[0] == warm and new_legs[1].split(' ')[2:] == comp.split(' ')[2:]
first = leg_line('WARM'); last = leg_line('COMPACTb')
lines[first:last + 1] = new_legs
run = '\n'.join(lines)
guard = '''if [ -n "$(sed -n 's/.*fields_mismatches=\\([0-9]*\\).*/\\1/p' $S/strip-loop320FVERIFY/el.log | awk '$1>0' | head -1)" ] || grep -q 'the fields published at the seal differ' $S/strip-loop320FVERIFY/el.log 2>/dev/null; then echo "FVERIFY MISMATCH: stopping, FAS not run"; grep -m5 -E 'the fields published at the seal differ' $S/strip-loop320FVERIFY/el.log | cut -c1-600; echo ALLDONE; exit 1; fi'''
run = run.replace('GUARD_FVERIFY', guard)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop320 = fields published at the seal (docs 11.8, 10.68; N42_FIELDS_AT_SEAL, 889ebfa80): legs WARM (baseline, throwaway), COMPACT (loop318 COMPACT, unbounded), FVERIFY (COMPACT + N42_FIELDS_AT_SEAL=verify, stops the round on any mismatch), FAS (=1), COMPACTb, FASb. memsample.py on every leg. No N42_BUILD_THROTTLE_* is set.\n', 1)
old = "grep -E 'QMDB_READS|HASHED_TABLES"
assert run.count(old) == 1
run = run.replace(old, "grep -E 'FIELDS_AT_SEAL|TAKE_COMPACT|COMPACT_BODY|BACKPRESSURE|BUILD_THROTTLE|QMDB_READS|HASHED_TABLES", 1)
open(D + 'run-loop320.sh', 'w').write(run)
open(D + 'launch-loop320.sh', 'w').write(open(D + 'launch-loop319.sh').read().replace('loop319', 'loop320'))
