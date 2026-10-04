#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop328.sh / launch-loop328.sh (seven validator keys on ONE execution layer, the peak search) and
run-loop329.sh / launch-loop329.sh (the E=4 maps) from the loop326 pair (docs/SHARED_EXECUTION_SCOPE.md).

Base N = loop326's N line exactly (history index off, compact take, throttle 48/80, execution-cache skip by default,
settlement tags legacy, the replayed set g900000 at an offer of 2.0M per layer, pacing 100 ms), moved from the
three-node chain to the seven-validator bench genesis `n42_fleet7_bench.json` (same chain id 1143, same alloc and gas
limit as `n42_fleet3_bench.json`: the replay set is bound to the chain id and the flood's arguments, not to the validator
count) with F7_NODES=F7_VALIDATORS=7, 32 CPUs a node (224 in all, the fleet's budget), root rust-fleet7-bench.

loop328: WARM (the plain one-to-one fleet, no switch: the throwaway that also proves the replay runs), E7 (the control,
`F7_EL_MAP=0,1,2,3,4,5,6`), E1 (`0,0,0,0,0,0,0`, every CPU the fleet has less 16 for the validators), E1b, then single
legs for E=1's peak: E1P80 / E1P70 (pacing 80 / 70 ms), E1T (build pool and rayon doubled: N42_PARALLEL_BUILD_THREADS 32 ->
64, RAYON_NUM_THREADS 16 -> 32; tokio stays at 16), E1C74 (the layer capped at 74 CPUs, one node of the three-node fleet),
E1FS (N42_FIELDS_AT_SEAL=1). loop329: WARM, E7, E4 (`0,0,1,1,2,2,3`), E4I (`0,1,2,3,0,1,2`), E4b, E4Ib.

The import-once switch is the variable ONCE at the top of the runner (`N42_IMPORT_ONCE=1`, the name the registry's author
was asked for). Every leg but WARM passes it; the runner refuses to start, and so does the launcher after its build, when the
tree or the binary does not know it. All gates of loop326 stay (stale-binary check, test gate, claim, 75-minute cap)."""
import re

D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop326.sh').read()
base_launch = open(D + 'launch-loop326.sh').read()


def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit:
            toks[i] = f'{key}={val}'
    else:
        toks.append(f'{key}={val}')
    new = ' '.join(toks)
    a = [t for t in line.split(' ') if not t.startswith(key + '=')]
    b = [t for t in new.split(' ') if not t.startswith(key + '=')]
    assert a == b, key
    return new


def sub1(text, old, new, count=1):
    assert text.count(old) == count, (text.count(old), old[:90])
    return text.replace(old, new)


def derive(num, legs_spec, title):
    tag = f'loop{num}'
    run = base_run.replace('loop326', tag)
    lines = run.split('\n')

    def leg_line(name):
        i = [k for k, l in enumerate(lines) if l.startswith(f'leg {name} ')]
        assert len(i) == 1, name
        return i[0]

    warm, base = lines[leg_line('WARM')], lines[leg_line('N')]
    for k in ('F7_EL_MAP', 'F7_EL_CPUS', 'N42_IMPORT_ONCE', 'N42_FIELDS_AT_SEAL', 'F7_PIN_SWAP', 'N42_ENGINE_EXEC_CACHE'):
        assert k not in base, k
    assert 'F7_FLOOD_RATE=2000000' in base and 'N42_ACCOUNT_HISTORY=off' in base and 'N42_SETTLEMENT_TAGS=legacy' in base
    assert 'N42_TAKE_COMPACT=1' in base and 'N42_BUILD_THROTTLE_SOFT=48' in base and 'F7_FLOOD_REPLAY=/data/n42-pregen/g900000' in base
    assert 'N42_PARALLEL_BUILD_THREADS=32' in base and 'TOKIO_WORKER_THREADS=16' in base

    def mk(name, *edits):
        l = base.replace('leg N ', f'leg {name} ', 1)
        assert l.startswith(f'leg {name} ')
        for k, v in edits:
            l = set_tok(l, k, v)
        return l

    ONCE = ('N42_IMPORT_ONCE', '1')
    new = [warm]
    for name, edits in legs_spec:
        new.append(mk(name, *edits))
    # `$ONCE` is a shell variable expanded on the leg line; the edits above add it as a token, so write it as the variable.
    new = [l.replace(' N42_IMPORT_ONCE=1', ' $ONCE') for l in new]
    guard_i = [k for k, l in enumerate(lines) if l.startswith(f'W=$B/bench-{tag}WARM')]
    assert len(guard_i) == 1
    legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
    guard = lines[guard_i[0]]
    # the replay must have run on WARM; the throughput floor of the three-node fleet (500k) does not apply to seven nodes
    guard = sub1(guard, '-lt 500000', '-lt 100000')
    lines[legs[0]:legs[-1] + 1] = [new[0], guard] + new[1:]
    run = '\n'.join(lines)

    # --- the chain, the fleet's size and the root: seven validators on the seven-validator bench genesis
    run = sub1(run, 'B=/data/blockchain/rust-fleet3-bench\n',
               'B=/data/blockchain/rust-fleet7-bench\n'
               '# THE IMPORT-ONCE SWITCH. The registry (bin/n42, `ImportOnce`) is being added by another agent; N42_IMPORT_ONCE=1 is the expected\n'
               '# name. Every leg but WARM passes it as $ONCE. Change it here, and only here, if the switch is named differently.\n'
               'ONCE=N42_IMPORT_ONCE=1\n')
    run = sub1(run, 'export F7_NODES=3 F7_CORES_PER_NODE=74 F7_PROFILE=bench F7_ROOT=/data/blockchain/rust-fleet3-bench F7_GENESIS=/home/n42/src/n42/n42-rs/crates/chainspec/res/genesis/n42_fleet3_bench.json',
               'export F7_NODES=7 F7_VALIDATORS=7 F7_CORES_PER_NODE=32 F7_PROFILE=bench F7_ROOT=/data/blockchain/rust-fleet7-bench F7_GENESIS=/home/n42/src/n42/n42-rs/crates/chainspec/res/genesis/n42_fleet7_bench.json')
    run = run.replace('rust-fleet3-bench', 'rust-fleet7-bench')
    assert 'fleet3' not in re.sub(r'#.*', '', run).replace('n42_fleet3_bench.json', '')

    # --- instrumentation gate: the scripts' mapping and the switch must be in the tree
    run = sub1(run, "|| [ ! -r crates/chainspec/res/genesis/n42_fleet3_bench.json ]",
               "|| [ ! -r crates/chainspec/res/genesis/n42_fleet7_bench.json ] || ! grep -q 'F7_EL_MAP' scripts/fleet7-env.sh || ! grep -q 'F7_VAL_CPUS' scripts/fleet7-env.sh "
               "|| ! grep -rq 'N42_IMPORT_ONCE' bin/n42/src crates/n42")

    # --- per-leg layout of the layers: the layer count, the first validator of each layer, and the plan on record
    run = sub1(run, 'run() { local tag=$1; shift\n',
               'run() { local tag=$1; shift\n'
               '  local EL_MAP=0,1,2,3,4,5,6; for kv in "$@"; do case "$kv" in F7_EL_MAP=*) EL_MAP=${kv#*=};; esac; done\n'
               '  local NEL FIRSTS ELIDX; NEL=$(python3 -c "print(max(int(x) for x in \'$EL_MAP\'.split(\',\'))+1)")\n'
               '  FIRSTS=$(python3 -c "m=[int(x) for x in \'$EL_MAP\'.split(\',\')]; print(*[m.index(e) for e in range(max(m)+1)])"); ELIDX=$(seq 0 $((NEL-1)))\n'
               '  env "$@" F7_BIN=$NAT bash scripts/fleet7.sh plan > $S/plan-$tag.txt 2>&1\n')
    # --- everything that looped over three nodes loops over the layers (execution layer logs, metrics, pids) or the validators
    run = sub1(run, 'for i in 0 1 2; do p=$(ps -eo pid,args | grep \'/n4[2] node\' | grep "rust-fleet7-bench/node$i"',
               'for i in $FIRSTS; do p=$(ps -eo pid,args | grep \'/n4[2] node\' | grep "rust-fleet7-bench/node$i/"')
    run = sub1(run, 'for i in 0 1 2 3; do curl -s --max-time 5 127.0.0.1:$((19300 + i))/metrics',
               'for i in $ELIDX; do curl -s --max-time 5 127.0.0.1:$((19300 + i))/metrics')
    run = sub1(run, 'for i in 0 1 2 3; do cp $B/node$i/el.log $B/bench-$tag/node$i-el.log; cp $B/node$i/v.log $B/bench-$tag/node$i-v.log; done',
               'n=0; for f in $FIRSTS; do cp $B/node$f/el.log $B/bench-$tag/node$n-el.log; n=$((n+1)); done; for i in 0 1 2 3 4 5 6; do cp $B/node$i/v.log $B/bench-$tag/node$i-v.log; done')
    run = sub1(run, 'F7_NODES=3 F7_HTTP_BASE=8700 timeout 60 python3 scripts/fleet7-verify.py',
               'F7_VALIDATORS=7 F7_ELS=$NEL F7_HTTP_BASE=8700 timeout 60 python3 scripts/fleet7-verify.py')
    run = sub1(run, 'for i in 0 1 2; do echo -n "node$i=$(awk', 'for i in $FIRSTS; do echo -n "node$i=$(awk')
    run = sub1(run, 'exec python3 scripts/fleet7-runs/memsample.py $STRIP/mem.log 3 )',
               'exec env F7_EL_MAP=$EL_MAP python3 scripts/fleet7-runs/memsample.py $STRIP/mem.log $NEL )')
    # per-layer observations: imports per block per layer (the import-once check reads 1), and the registry's own lines
    old = '  echo "$tag no_variant=$(cat $STRIP/el.log | grep -c \'no gov5 header variant\')'
    run = sub1(run, old, '  echo "$tag imports: layers=$NEL direct_imports=$(cat $STRIP/el.log | grep -c \'direct import: executed here\') canonical_blocks=$(cat $STRIP/el.log | grep -c \'Block added to canonical chain\') import_once_lines=$(cat $STRIP/el.log | grep -ci \'import.once\') (per layer: direct imports should equal canonical blocks for one execution per block)"\n' + old)
    # headers of both processes name the layout and the pool sizes
    run = sub1(run, 'ENGINE_EXEC_CACHE|SETTLEMENT_TAGS|',
               'F7_EL_MAP|F7_EL_CPUS|F7_VAL_CPUS|IMPORT_ONCE|RAYON_NUM_THREADS|PARALLEL_BUILD_THREADS|TOKIO_WORKER_THREADS|ENGINE_EXEC_CACHE|SETTLEMENT_TAGS|', count=2)
    run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# ' + tag + ' = ' + title + '\n', 1)
    open(D + f'run-{tag}.sh', 'w').write(run)

    launch = base_launch.replace('loop326', tag)
    # refuse to build and run when the tree does not know the switch; and once built, when the binary does not
    launch = sub1(launch, 'echo "box free at',
                  'grep -rq N42_IMPORT_ONCE bin/n42/src crates/n42 || { echo "N42_IMPORT_ONCE is not in the tree: the shared-execution legs need the import-once registry; nothing built"; echo ALLDONE; exit 1; }\n'
                  'echo "box free at')
    launch = sub1(launch, 'echo "built at $(date +%H:%M); ingest/tx-types tests:"',
                  'grep -aq N42_IMPORT_ONCE target/native/release/n42 || { echo "the built n42 does not know N42_IMPORT_ONCE; no mapped leg can run"; echo ALLDONE; exit 1; }\n'
                  'echo "built at $(date +%H:%M); ingest/tx-types tests:"')
    open(D + f'launch-{tag}.sh', 'w').write(launch)


ONCE = ('N42_IMPORT_ONCE', '1')
E7 = ('F7_EL_MAP', '0,1,2,3,4,5,6')
E1 = ('F7_EL_MAP', '0,0,0,0,0,0,0')
derive(328, [
    ('E7', [E7, ONCE]),
    ('E1', [E1, ONCE]),
    ('E1b', [E1, ONCE]),
    ('E1P80', [E1, ONCE, ('F7_BLOCK_INTERVAL_MS', '80')]),
    ('E1P70', [E1, ONCE, ('F7_BLOCK_INTERVAL_MS', '70')]),
    ('E1T', [E1, ONCE, ('N42_PARALLEL_BUILD_THREADS', '64'), ('RAYON_NUM_THREADS', '32')]),
    ('E1C74', [E1, ONCE, ('F7_EL_CPUS', '74')]),
    ('E1FS', [E1, ONCE, ('N42_FIELDS_AT_SEAL', '1')]),
], 'seven validator keys on one execution layer (docs/SHARED_EXECUTION_SCOPE.md), the peak search: WARM (one-to-one, no switch), E7 (control), E1, E1b, E1P80, E1P70 (pacing), E1T (build pool and rayon doubled), E1C74 (layer capped at 74 CPUs), E1FS (fields at seal). Validators pinned on 16 CPUs of their own. One claim; legs after 75 minutes are skipped, so the order is the priority.')
derive(329, [
    ('E7', [E7, ONCE]),
    ('E4', [('F7_EL_MAP', '0,0,1,1,2,2,3'), ONCE]),
    ('E4I', [('F7_EL_MAP', '0,1,2,3,0,1,2'), ONCE]),
    ('E4b', [('F7_EL_MAP', '0,0,1,1,2,2,3'), ONCE]),
    ('E4Ib', [('F7_EL_MAP', '0,1,2,3,0,1,2'), ONCE]),
], 'seven validator keys on four execution layers: WARM, E7 (control), E4 (contiguous 0,0,1,1,2,2,3), E4I (interleaved 0,1,2,3,0,1,2), E4b, E4Ib. 52 CPUs a layer and 16 for the validators. One claim.')
