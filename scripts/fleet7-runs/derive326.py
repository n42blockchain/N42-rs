#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop326.sh / launch-loop326.sh from the loop325 pair (docs 10.74). Base N = loop325's F line exactly, now on the new
default (reth's cross-block execution cache is not written on a QMDB chain, 7a0c7b551). Legs WARM (throwaway), N, O (N +
N42_ENGINE_EXEC_CACHE=on, the old behaviour), Nb, Ob, NFS (N + N42_FIELDS_AT_SEAL=1), NP90 (N at 90 ms pacing), HT (N +
N42_HASHED_TABLES=on: the hashed tables are written, reads stay on), QR (N + N42_QMDB_READS=verify + N42_HASHED_TABLES=on: verify
needs the tables, since N42_HASHED_TABLES=off is refused unless reads are on). SPLIT (settlement tags) is added only when the tree has
N42_SETTLEMENT_TAGS; in that case every other leg passes N42_SETTLEMENT_TAGS=legacy. STRACE is not run when ptrace_scope is not 0.
All gates of loop325 stay (stale-binary check, test gate with n42 --lib, claim, 75-minute cap, memsample.py, env headers)."""
import re, subprocess
D = '/data/n42-build/target-n42-rs/fleet-runs/'
REPO = '/home/n42/src/n42/n42-rs'
run = open(D + 'run-loop325.sh').read().replace('loop325', 'loop326')
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
assert 'F7_FLOOD_RATE=2000000' in base and 'N42_ACCOUNT_HISTORY=off' in base and 'F7_BLOCK_INTERVAL_MS=100' in base
for k in ('N42_FIELDS_AT_SEAL', 'N42_DEFERRED_IN_FLIGHT', 'N42_VOTE_BEFORE_SLOT', 'F7_PIN_SWAP', 'N42_ENGINE_EXEC_CACHE', 'N42_SETTLEMENT_TAGS'):
    assert k not in base, k
D_ = "N42_QMDB_READS=on N42_HASHED_TABLES=off"
assert D_.split()[0] in run and 'N42_HASHED_TABLES=off' in run   # the D bundle: HT / QR override it after it
tags = subprocess.run(['grep', '-rl', 'N42_SETTLEMENT_TAGS', REPO + '/crates/n42/h2-execution/src'], capture_output=True, text=True).stdout.strip()
legacy = [('N42_SETTLEMENT_TAGS', 'legacy')] if tags else []
def mk(name, *edits, src=base):
    l = src.replace('leg F ', f'leg {name} ', 1)
    assert l.startswith(f'leg {name} ')
    for k, v in legacy + list(edits): l = set_tok(l, k, v)
    return l
# the D bundle is a shell variable ($D) expanded before the base line's own tokens, so the override has to come after it: appended tokens
# land last on the command line and `env` takes the last assignment.
O = ('N42_ENGINE_EXEC_CACHE', 'on')
warm = set_tok(warm, 'N42_SETTLEMENT_TAGS', 'legacy')
new = [warm, mk('N'), mk('O', O), mk('Nb'), mk('Ob', O), mk('NFS', ('N42_FIELDS_AT_SEAL', '1')), mk('NP90', ('F7_BLOCK_INTERVAL_MS', '90')),
       mk('HT', ('N42_HASHED_TABLES', 'on')), mk('QR', ('N42_QMDB_READS', 'verify'), ('N42_HASHED_TABLES', 'on')), mk('STRACE')]
assert tags, 'settlement tags are in the tree: SPLIT runs'
new.insert(6, mk('SPLIT', ('N42_SETTLEMENT_TAGS', 'split')))
guard_i = [k for k, l in enumerate(lines) if l.startswith("W=$B/bench-loop326WARM")]
assert len(guard_i) == 1
legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
lines[legs[0]:legs[-1] + 1] = [new[0], lines[guard_i[0]]] + new[1:]
run = '\n'.join(lines)
# the test gate: the settlement tags' tests
old = '"-p n42 --lib"; do'
assert run.count(old) == 1
run = run.replace(old, '"-p n42-h2-execution --test settlement_tags" "-p n42-qmdb-reth --lib exec_cache" "-p n42 --lib"; do')
# STRACE: strace -c -f on the leader's execution layer for 20 s inside window 1 (SIGINT detaches it); the leg is not judged
old = "  STRIP=$S/strip-$tag; mkdir -p $STRIP; rm -f $STRIP/mem.log\n"
assert run.count(old) == 1
run = run.replace(old, old + '''  case $tag in *STRACE) ( n=0; until grep -q 'funding' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done; sleep 12; p=$(ps -eo pid,args | grep '/n4[2] node' | grep 'rust-fleet3-bench/node0' | grep -v grep | awk '{print $1}' | head -1); [ -n "$p" ] && echo "$tag strace -c -f -p $p from $(date +%H:%M:%S) for 20 s" && timeout -s INT 20 strace -c -f -p $p -o $S/strace-$tag.txt; echo "strace exit $? at $(date +%H:%M:%S)" ) > $S/strace-$tag.log 2>&1 & ;; esac
''')
# SPLIT: one eth_getBlockByNumber each for latest / safe / finalized on node 1, once, 50 s after the funding (inside window 1)
old = "  STRIP=$S/strip-$tag; mkdir -p $STRIP; rm -f $STRIP/mem.log\n"
assert run.count(old) == 1
run = run.replace(old, old + '''  case $tag in *SPLIT) ( n=0; until grep -q 'funding' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done; sleep 50; for t in latest safe finalized; do echo "$tag $t: $(curl -s --max-time 5 -X POST -H 'content-type: application/json' --data "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"method\\":\\"eth_getBlockByNumber\\",\\"params\\":[\\"$t\\",false]}" 127.0.0.1:8701 | grep -oE '"(number|hash)":"[^"]*"' | paste -sd' ')"; done ) > $S/tags-$tag.txt 2>&1 & ;; esac
''')
old = "if ! grep -q 'fn vote_before_slot' crates/n42/h2-execution/src/driver.rs"
assert run.count(old) == 1
run = run.replace(old, "if ! grep -q 'N42_ENGINE_EXEC_CACHE' crates/n42/qmdb-reth/src/exec_cache.rs || ! grep -q 'N42_SETTLEMENT_TAGS' crates/n42/h2-execution/src/settlement.rs || ! grep -q 'fn vote_before_slot' crates/n42/h2-execution/src/driver.rs")
for pat in ("grep -E 'ACCOUNT_HISTORY|PERSIST_QMDB|FIELDS_AT_SEAL|", "grep -E 'N42_BUILD_THROTTLE|TAKE_COMPACT|COMPACT_BODY|FIELDS_AT_SEAL|"):
    assert run.count(pat) == 1, pat
    run = run.replace(pat, pat + "ENGINE_EXEC_CACHE|SETTLEMENT_TAGS|")
# the validator header also shows the read-mode switches
pat = "grep -E 'N42_BUILD_THROTTLE|TAKE_COMPACT|"
run = run.replace(pat, "grep -E 'N42_QMDB_READS|N42_HASHED_TABLES|N42_BUILD_THROTTLE|TAKE_COMPACT|", 1)
run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop326 = the execution-cache write skipped on QMDB chains (docs 10.74; 11.11): base N = loop325 F on the new default. Legs WARM, N, O (N42_ENGINE_EXEC_CACHE=on), Nb, Ob, NFS (fields at seal), NP90 (90 ms pacing), HT (hashed tables written), QR (reads=verify + hashed tables written)' + (', SPLIT (settlement tags; the others pass legacy)' if tags else '') + '. One claim. memsample.py, threadcpu and the env headers on every leg; tests include n42 --lib.\n', 1)
open(D + 'run-loop326.sh', 'w').write(run)
open(D + 'launch-loop326.sh', 'w').write(open(D + 'launch-loop325.sh').read().replace('loop325', 'loop326'))
