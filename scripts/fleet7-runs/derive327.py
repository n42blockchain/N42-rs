#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop327.sh / launch-loop327.sh (claim 1) and run-loop327b.sh / launch-loop327b.sh (claim 2) from the loop326 pair (docs 10.75).
Base N = loop326's N line exactly (settlement tags legacy). Claim 1: WARM, N, H (+N42_HANDOFF_ON_LANDED=1), HMV (H +
N42_SHARDS_MERGE_OFF_PATH=verify; the runner stops after it when any execution layer reports merge_mismatches above 0), HM (H +
N42_SHARDS_MERGE_OFF_PATH=1), Nb, HMb. Claim 2: WARM2, Hb, HMS (HM with N42_SETTLEMENT_TAGS=split), HMP90 (HM at 90 ms pacing), HMFS (HM +
N42_FIELDS_AT_SEAL=1). Both switches are read in bin/n42/src/follower_import.rs, i.e. by the execution layer; the headers print them for both
processes. All gates of loop326 stay."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop326.sh').read()

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

def derive(suffix, tag_prefix, legs_spec, warm_name):
    run = base_run.replace('loop326', 'loop327' + suffix)
    lines = run.split('\n')
    def leg_line(name):
        i = [k for k, l in enumerate(lines) if l.startswith(f'leg {name} ')]
        assert len(i) == 1, name
        return i[0]
    warm, base = lines[leg_line('WARM')], lines[leg_line('N')]
    assert 'N42_SETTLEMENT_TAGS=legacy' in base and 'F7_BLOCK_INTERVAL_MS=100' in base and 'N42_ENGINE_EXEC_CACHE' not in base
    for k in ('N42_HANDOFF_ON_LANDED', 'N42_SHARDS_MERGE_OFF_PATH', 'N42_FIELDS_AT_SEAL', 'N42_QMDB_READS', 'F7_PIN_SWAP'):
        assert k not in base, k
    H = ('N42_HANDOFF_ON_LANDED', '1'); M1 = ('N42_SHARDS_MERGE_OFF_PATH', '1'); MV = ('N42_SHARDS_MERGE_OFF_PATH', 'verify')
    table = {'N': [], 'Nb': [], 'H': [H], 'Hb': [H], 'HMV': [H, MV], 'HM': [H, M1], 'HMb': [H, M1],
             'HMS': [H, M1, ('N42_SETTLEMENT_TAGS', 'split')], 'HMP90': [H, M1, ('F7_BLOCK_INTERVAL_MS', '90')], 'HMFS': [H, M1, ('N42_FIELDS_AT_SEAL', '1')]}
    def mk(name):
        l = base.replace('leg N ', f'leg {name} ', 1)
        assert l.startswith(f'leg {name} ')
        for k, v in table[name]: l = set_tok(l, k, v)
        return l
    wl = warm.replace('leg WARM ', f'leg {warm_name} ', 1)
    guard_i = [k for k, l in enumerate(lines) if l.startswith(f"W=$B/bench-loop327{suffix}WARM")]
    assert len(guard_i) == 1
    guard = lines[guard_i[0]].replace(f'bench-loop327{suffix}WARM', f'bench-loop327{suffix}{warm_name}')
    new = [wl, guard]
    for n in legs_spec:
        new.append(mk(n))
        if n == 'HMV':
            new.append('''if [ -n "$(cat $S/strip-loop327HMV/el.log | grep 'build path: the root.s start after the execution' | grep -oE 'merge_mismatches=[0-9]+' | cut -d= -f2 | awk '$1>0' | head -1)" ]; then echo "HMV MISMATCH: merge_mismatches above 0, stopping after this leg"; cat $S/strip-loop327HMV/el.log | grep 'build path: the root.s start after the execution' | grep -oE 'merge_verified=[0-9]+|merge_mismatches=[0-9]+' | sort | uniq -c | sort -rn | head -8; cleanup; echo "released at $(date +%H:%M)"; echo ALLDONE; exit 1; fi''')
    legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
    lines[legs[0]:legs[-1] + 1] = new
    run = '\n'.join(lines)
    old = "if ! grep -q 'N42_ENGINE_EXEC_CACHE'"
    assert run.count(old) == 1
    run = run.replace(old, "if ! grep -q 'N42_HANDOFF_ON_LANDED' bin/n42/src/follower_import.rs || ! grep -q 'merge_mismatches' bin/n42/src/follower_import.rs || ! grep -q 'handoff_before_canonical' bin/n42/src/follower_import.rs || " + old[3:])
    pat = "grep -E 'ACCOUNT_HISTORY|PERSIST_QMDB|FIELDS_AT_SEAL|"
    assert run.count(pat) == 1
    run = run.replace(pat, pat + "HANDOFF_ON_LANDED|SHARDS_MERGE_OFF_PATH|")
    pat = "grep -E 'N42_QMDB_READS|N42_HASHED_TABLES|N42_BUILD_THROTTLE|"
    assert run.count(pat) == 1
    run = run.replace(pat, pat + "HANDOFF_ON_LANDED|SHARDS_MERGE_OFF_PATH|")
    run = run.replace('#!/usr/bin/env bash\n', f'#!/usr/bin/env bash\n# loop327{suffix} = the follower hand-off and shards merge (docs 10.75; 11.12): base N = loop326 N (settlement tags legacy). Legs {warm_name}, ' + ', '.join(legs_spec) + '. memsample.py, threadcpu and the env headers on every leg; tests include n42 --lib.\n', 1)
    # free-space gate (a leg needs 250G free on /data; its figure is printed in the leg header)
    old = '  local tag=$1; shift\n  run loop327' + suffix + '$tag'
    assert run.count(old) == 1
    run = run.replace(old, '  local tag=$1; shift\n'
        '  local avail; avail=$(df -BG /data | awk \'NR==2{gsub("G","",$4); print $4}\')\n'
        '  if [ "${avail:-0}" -lt 250 ]; then echo "leg loop327' + suffix + '$tag skipped: /data has ${avail}G free, a leg needs 250G"; return; fi\n'
        '  echo "leg loop327' + suffix + '$tag: /data free ${avail}G (needs 250G)"\n'
        '  run loop327' + suffix + '$tag')
    open(D + f'run-loop327{suffix}.sh', 'w').write(run)
    launch = open(D + 'launch-loop326.sh').read().replace('loop326', 'loop327' + suffix)
    old = 'echo "box free at'
    assert launch.count(old) == 1
    launch = launch.replace(old, 'avail=$(df -BG /data | awk \'NR==2{gsub("G","",$4); print $4}\'); [ "${avail:-0}" -ge 250 ] || { echo "/data has only ${avail}G free (a leg needs 250G); nothing built"; echo ALLDONE; exit 1; }\necho "/data free ${avail}G at launch"\n' + old)
    open(D + f'launch-loop327{suffix}.sh', 'w').write(launch)
derive('', 'loop327', ['N', 'H', 'HMV', 'HM', 'Nb', 'HMb'], 'WARM')
derive('b', 'loop327b', ['Hb', 'HMS', 'HMP90', 'HMFS'], 'WARM2')
