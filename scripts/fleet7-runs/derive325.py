#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop325.sh / launch-loop325.sh from the loop324 pair (docs 10.73). Base F = loop324's F line exactly (history index
off, compact take, throttle 48/80, replayed attested set, offer 2.0M, pacing 100, no fields-at-seal). Legs WARM (throwaway), F,
D3 (+N42_DEFERRED_IN_FLIGHT=3), VBS (+N42_VOTE_BEFORE_SLOT=1), Fb, VBSb, SWAP (F with F7_PIN_SWAP=1:2: nodes 1 and 2 exchange
CPU lists), VBSFS (VBS + N42_FIELDS_AT_SEAL=1). Every launcher gate of loop324 stays (box free, swap empty, native build, test gate
with n42 --lib, claim, per-leg timeout, 75-minute claim cap, release on exit, memsample.py and the environment headers); the
runner also refuses to start the legs when a source file is newer than the native binary, and prints the commit and the build
time against the last source change."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
run = open(D + 'run-loop324.sh').read().replace('loop324', 'loop325')
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
warm, base = lines[leg_line('WARM')], lines[leg_line('F')]
assert 'F7_FLOOD_RATE=2000000' in base and 'N42_ACCOUNT_HISTORY=off' in base and 'F7_FLOOD_REPLAY=/data/n42-pregen/g900000' in base
assert 'F7_BLOCK_INTERVAL_MS=100' in base and 'N42_BUILD_THROTTLE_SOFT=48' in base and 'N42_BUILD_THROTTLE_HARD=80' in base
for k in ('N42_FIELDS_AT_SEAL', 'F7_GASCEIL_ARG', 'F7_PERSIST_BACKPRESSURE', 'N42_PERSIST_QMDB_IN_SCOPE', 'N42_DEFERRED_IN_FLIGHT',
          'N42_VOTE_BEFORE_SLOT', 'F7_PIN_SWAP'):
    assert k not in base, k
def mk(name, *edits, src=base):
    l = src.replace('leg F ', f'leg {name} ', 1)
    assert l.startswith(f'leg {name} ')
    for k, v in edits: l = set_tok(l, k, v)
    return l
D3 = ('N42_DEFERRED_IN_FLIGHT', '3'); VBS = ('N42_VOTE_BEFORE_SLOT', '1'); FS = ('N42_FIELDS_AT_SEAL', '1')
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
guard_i = [k for k, l in enumerate(lines) if l.startswith("W=$B/bench-loop325WARM")]
assert len(guard_i) == 1
new = [warm, lines[guard_i[0]], mk('F'), mk('D3', D3), mk('VBS', VBS), mk('Fb'), mk('VBSb', VBS),
       mk('SWAP', ('F7_PIN_SWAP', '1:2')), mk('VBSFS', VBS, FS)]
# drop the old FV guard line (between legs) and every old leg line
lines[legs[0]:legs[-1] + 1] = new
run = '\n'.join(lines)
assert 'FV MISMATCH' not in run
# the instrumentation guard: the new knobs and the pin variable must be in the tree
old = "if ! grep -q 'fn push_reverted' crates/n42/tx-queue/src/lib.rs"
assert run.count(old) == 1
run = run.replace(old, "if ! grep -q 'fn vote_before_slot' crates/n42/h2-execution/src/driver.rs || ! grep -q 'F7_PIN_SWAP' scripts/fleet7-env.sh || ! grep -q 'fn parse_in_flight' crates/n42/h2-execution/src/driver.rs || ! grep -q 'held_at_arrival' bin/n42/src/follower_import.rs crates/n42/h2-execution/src/driver.rs || ! grep -q 'fn push_reverted' crates/n42/tx-queue/src/lib.rs")
# the test gate: the new knobs' tests
old = '"-p n42 --lib"; do'
assert run.count(old) == 1
run = run.replace(old, '"-p n42-h2-execution --lib" "-p n42-h2-execution --test vote_before_slot" "-p n42-h2-el-rpc --test compact_channel" "-p n42 --lib"; do')
# environment headers carry the new variables
for pat in ("grep -E 'ACCOUNT_HISTORY|PERSIST_QMDB|FIELDS_AT_SEAL|", "grep -E 'N42_BUILD_THROTTLE|TAKE_COMPACT|COMPACT_BODY|FIELDS_AT_SEAL|"):
    assert run.count(pat) == 1, pat
    run = run.replace(pat, pat + "DEFERRED_IN_FLIGHT|VOTE_BEFORE_SLOT|F7_PIN_SWAP|")
# the native binary the legs run must be newer than every source file; record commit and times
old = 'if [ -n "$(find crates bin -name \'*.rs\' -newer $NEW/n42 | head -1)" ]'
assert run.count(old) == 1
rec = '''echo "tip $(git rev-parse --short HEAD) tree: $(git status --short | wc -l) changed files; native n42 built $(date -r $NAT/n42 +%H:%M:%S), h2_validator $(date -r $NAT/examples/h2_validator +%H:%M:%S), deferred n42 $(date -r $NEW/n42 +%H:%M:%S); last source change $(date -r "$(find crates bin scripts -name '*.rs' -o -name '*.sh' | xargs ls -t | head -1)" +%H:%M:%S) ($(find crates bin -name '*.rs' | xargs ls -t | head -1))"
if [ -n "$(find crates bin -name '*.rs' -newer $NAT/n42 | head -1)" ]; then echo "a source file is newer than the native binary the legs run; released without a leg"; echo ALLDONE; exit 1; fi
'''
run = run.replace(old, rec + old)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop325 = the follower import slot (docs 10.73; 11.10): base F = loop324 F (AHOFF + COMPACT + throttle 48/80, replay set, offer 2.0M, pacing 100). Legs WARM (throwaway), F (control), D3 (N42_DEFERRED_IN_FLIGHT=3), VBS (N42_VOTE_BEFORE_SLOT=1), Fb, VBSb, SWAP (F7_PIN_SWAP=1:2: nodes 1 and 2 exchange CPU lists), VBSFS (VBS + N42_FIELDS_AT_SEAL=1). memsample.py, threadcpu and the env headers on every leg; tests include n42 --lib.\n', 1)
open(D + 'run-loop325.sh', 'w').write(run)
open(D + 'launch-loop325.sh', 'w').write(open(D + 'launch-loop324.sh').read().replace('loop324', 'loop325'))
