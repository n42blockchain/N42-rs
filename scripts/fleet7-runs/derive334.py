#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop334.sh / launch-loop334.sh (claim 1: the control and fields-at-seal legs on the tree without the leader-layers change) and
run-loop334b.sh / launch-loop334b.sh (claim 2: the legs that need N42_LEADER_LAYERS, plus a fresh control on that binary) for loop334 (docs 10.81)
from the loop333 pair. Every leg is E=1 (F7_EL_MAP=0,0,0,0,0,0,0, N42_IMPORT_ONCE=1), 200,000 transfers a block, the 400M replay set, windows
taken from the execution layer's canonical-block log (F7_MEASURE_FROM_LOG=1), no block read over RPC while a flood runs. Base G80 = loop333 G80.
The selection logic of loop333 (best leg -> X / Xb) is gone: the legs are fixed. Run: python3 derive334.py"""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop333.sh').read()
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
FV_GATE = r'''
# FV must report fields_mismatches 0 with checks made; otherwise nothing after it is run and the lines are the hand-back.
fvgate() {
  local f=$B/bench-loop334FV/node0-el.log m v
  m=$(grep -a 'seal-first build phases' $f 2>/dev/null | grep -oE 'fields_mismatches=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
  v=$(grep -a 'seal-first build phases' $f 2>/dev/null | grep -oE 'fields_verified=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
  echo "FV gate: fields_verified=${v:-none} fields_mismatches=${m:-none}"
  if [ "${m:-x}" != 0 ] || [ "${v:-0}" -le 0 ]; then
    echo "FV FAILED (a mismatch, or no check was made): stopping the round"
    grep -a -E 'fields.*(mismatch|differ)' $f | head -8 | cut -c1-400
    for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el $B/node$i/consensus; done
    cleanup; echo "released at $(date +%H:%M)"; echo ALLDONE; exit 1
  fi
}
'''
JUD = r'''
# the seal share of a leg (analyze328's binding-wait line) and its full-block share, for the rules below
jud() { python3 - $1 <<'PYEOF'
import re, subprocess, sys
t = sys.argv[1]; B = '/data/blockchain/rust-fleet7-bench'
try:
    r = open(f'{B}/bench-loop334{t}/round.txt').read()
    w = int(re.search(r'win1 +tps= *([\d,]+)', r)[1].replace(',', ''))
    m = re.search(r'win1 .*full\(>=95%\)=(\d+)/(\d+)', r); full = int(m[1]) / max(1, int(m[2]))
    out = subprocess.run(['python3', 'scripts/fleet7-runs/analyze328.py', f'loop334{t}'], capture_output=True, text=True).stdout
    m = re.search(r'seal ([\d.]+)%', out); seal = float(m[1]) / 100 if m else 0.0
    print(t, w, round(full, 3), round(seal, 3))
except Exception as e:
    print(t, 0, 0, 1)
PYEOF
}
'''
def derive(suffix):
    run = base_run.replace('loop333', 'loop334')
    lines = run.split('\n')
    # --- the G80 line is the base of every leg
    g = [l for l in lines if l.startswith('leg G80 ')]
    assert len(g) == 1
    g80 = g[0]
    assert 'F7_FLOOD_RATE=4000000' in g80 and 'F7_BENCH_POOL_SLOTS=2000000' in g80 and 'F7_GASCEIL_ARG=4200000000' in g80
    assert 'F7_FLOOD_REPLAY=$REPLAY' in g80 and 'F7_EL_MAP=0,0,0,0,0,0,0' in g80 and '$ONCE' in g80
    assert 'F7_BLOCK_INTERVAL_MS=80' in g80 and 'N42_FIELDS_AT_SEAL' not in g80 and 'LEADER_LAYERS' not in g80
    def mk(name, *edits):
        l = g80.replace('leg G80 ', f'leg {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        return l
    FS1 = ('N42_FIELDS_AT_SEAL', '1'); L3 = ('N42_LEADER_LAYERS', '3'); iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    Q = [('N42_QMDB_APPEND_AHEAD_MB', '256'), ('N42_QMDB_APPEND_REWALK', '1'), ('N42_QMDB_UNDO_POOL', '128'), ('N42_TWIG_POOL_FLOOR', '1024')]
    guard_i = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop334WARM')]
    assert len(guard_i) == 1
    warm_name = 'WARM' if suffix == '' else 'WARM2'
    guard = lines[guard_i[0]].replace('bench-loop334WARM', f'bench-loop334{warm_name}')
    if suffix == '':
        body = [mk('WARM'), guard, mk('G80'), mk('G80b'), mk('FV', ('N42_FIELDS_AT_SEAL', 'verify')), 'fvgate', mk('FS', FS1), mk('FSb', FS1)]
        title = 'Claim 1 (the tree without the leader-layers change, so the controls carry the script fix only): WARM, G80, G80b, FV (stops the round on a mismatch), FS, FSb.'
    else:
        l3fs70 = mk('L3FS70', L3, FS1, iv(70))
        l3fs60 = mk('L3FS60', L3, FS1, iv(60))
        body = [mk('WARM2'), guard, mk('G80n'), mk('L3', L3), mk('L3b', L3), mk('L3FS', L3, FS1), l3fs70,
                'V=$(jud L3FS70); echo "verdict L3FS70 (tag, window 1, full share, seal share): $V"; set -- $V',
                'if python3 -c "import sys; sys.exit(0 if float(\'$4\') < 0.333 else 1)"; then',
                l3fs60,
                'else echo "L3FS60 skipped: L3FS70 had the seal binding on $4 of its blocks (a third or more)"; fi',
                mk('Q', *Q)]
        title = 'Claim 2 (the binary with N42_LEADER_LAYERS and the opener fallback fix): WARM2, G80n (a control on the new binary), L3, L3b, L3FS, L3FS70, L3FS60 (when L3FS70 seals under a third of its blocks), Q.'
    # --- splice: everything from the first `leg ` line up to the datadir wipe is replaced
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = ('\n'.join(body)).split('\n') + ['']
    # the helper jud / argsof of loop333 sat inside the replaced region (between the last C=/R=/D= definitions and the legs): re-added via JUD above
    run = '\n'.join(lines)
    # --- header: the loop333 comment pile is replaced
    i0 = run.index('# loop334 = E=1 around the peak'); i1 = run.index('cd /home/n42/src/n42/n42-rs')
    hdr = ('# loop334 = E=1 (seven validator keys on one execution layer): windows from the execution layer\'s canonical-block log, no block read over RPC while the flood runs (docs 10.81; '
           'SHARED_EXECUTION_SCOPE 8). ' + title + ' 200,000 transfers a block, 400M replay set (12,500 senders), feed 4.0M, pool 2.0M, 80 ms pacing unless the leg says so. '
           'Free-space gate 120G a leg, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs of the round wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    # --- the replay set: the 400M set must exist (generated by loop333), no generation here
    p0 = run.index('# --- the larger replay set'); p1 = run.index('echo $REPLAY > $S/replay-loop334.txt')
    run = run[:p0] + ('# --- the 400M replay set, generated by loop333 (docs 10.80)\nREPLAY=/data/n42-pregen/g900000-400m; export F7_SENDERS_ARG=12500\n'
                      '[ -f $REPLAY/.complete ] || { echo "the 400M replay set is missing ($REPLAY/.complete); released without a leg"; echo ALLDONE; exit 1; }\n'
                      'echo "replay set for every leg: $REPLAY (senders $F7_SENDERS_ARG)"\n') + run[p1:]
    # --- every leg takes its windows from the log
    old = "run loop334$tag F7_EL_EXTRA="
    assert run.count(old) == 1
    run = run.replace(old, "run loop334$tag F7_MEASURE_FROM_LOG=1 F7_EL_EXTRA=")
    # --- environment headers: the new switches
    assert run.count('FIELDS_AT_SEAL|') == 2
    run = run.replace('FIELDS_AT_SEAL|', 'FIELDS_AT_SEAL|LEADER_LAYERS|QMDB_APPEND_AHEAD_MB|QMDB_APPEND_REWALK|QMDB_UNDO_POOL|TWIG_POOL_FLOOR|F7_MEASURE_FROM_LOG|')
    # --- the analysis after every leg
    marker = '  echo "$tag page_faults_per_s_median:'
    assert run.count(marker) == 1
    run = run.replace(marker, '  python3 scripts/fleet7-runs/analyze334.py $tag 2>&1 | cut -c1-420; python3 scripts/fleet7-runs/analyze328.py $tag 2>&1 | cut -c1-320\n' + marker)
    # --- tests: the opener's own tests first
    sp = 'for spec in "'
    assert run.count(sp) == 1
    run = run.replace(sp, 'for spec in "-p n42-engine-types --lib direct_build" "', 1)
    # --- the FV gate and the helper must be defined before the legs
    run = run.replace('\nleg() {', FV_GATE + '\nleg() {', 1)
    # --- the stale wait for another round
    run = run.replace('until grep -q ALLDONE $S/loop198.out 2>/dev/null; do sleep 60; done\n', '')
    assert 'bestof' not in run and 'BEST=' not in run and 'LA_' in run
    run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n', 1)
    if suffix == '':
        # claim 1 runs the binaries frozen from loop333's build (tip 79f20617a; crates/ and bin/ are unchanged through 17fb31cfe): the working tree
        # now carries another agent's uncommitted leader-layers change, so nothing is rebuilt or retested from it. The loop333 test gate (964 tests,
        # n42 --lib among them) ran on these sources.
        FZ = '/data/n42-build/target-n42-rs/loop334-base/release'
        assert run.count('NAT=/home/n42/src/n42/n42-rs/target/native/release') == 1
        run = run.replace('NAT=/home/n42/src/n42/n42-rs/target/native/release', 'NAT=' + FZ)
        t0 = run.index('T=$S/tests-loop334.log; : > $T'); t1 = run.index('echo "built $(git rev-parse --short HEAD)+tree at $(date +%H:%M)"')
        t1 = run.index('\n', t1) + 1
        run = run[:t0] + (
            '# frozen binaries: no build and no test run from the working tree\n'
            'git diff --quiet 79f20617a 17fb31cfe -- crates bin Cargo.toml Cargo.lock || { echo "crates/bin differ between the loop333 build tip and the script-fix commit; released without a leg"; echo ALLDONE; exit 1; }\n'
            'echo "frozen binaries (built from the loop333 tip 79f20617a, crates/bin identical at 17fb31cfe): $(sha256sum $NAT/n42 | cut -c1-16) n42, $(sha256sum $NAT/examples/h2_validator | cut -c1-16) h2_validator, $(sha256sum $NAT/examples/tx_flood | cut -c1-16) tx_flood"\n'
            '[ "$(sha256sum $NAT/n42 | cut -c1-16)" = bfd51f11f2c92ab1 ] && [ "$(sha256sum $NAT/examples/h2_validator | cut -c1-16)" = 414f7c7cd1ae6bf5 ] || { echo "the frozen binaries changed; released without a leg"; echo ALLDONE; exit 1; }\n'
            'echo "loop333 test gate on these sources: $(grep -E \'^test result:\' $S/tests-loop333.log | sed -E \'s/test result: ok. ([0-9]+) passed.*/\\1/\' | paste -sd+ | bc) tests, failures: $(grep -cE \'^test .* FAILED\' $S/tests-loop333.log)"\n'
            'WAITED_FROM=$(date -u +%s)\n') + run[t1:]
        for pat in ("if [ -n \"$(find crates bin -name '*.rs' -newer $NAT/n42 | head -1)\" ]", "if [ -n \"$(find crates bin -name '*.rs' -newer $NEW/n42 | head -1)\" ]"):
            i = run.index(pat); j = run.index('\n', i) + 1; run = run[:i] + run[j:]
    open(D + f'run-loop334{suffix}.sh', 'w').write(run)
    # --- the launcher
    la = open(D + 'launch-loop333.sh').read().replace('loop333', 'loop334' + suffix)
    la = la.replace('# Waits for the box, builds the native binaries, runs the flood\'s own tests, generates the replay set once, then\n# runs loop334' + suffix + '.',
                    '# Waits for the box, checks the tree, builds the native binaries, runs the flood\'s own tests, then runs loop334' + suffix + '.')
    gate_old = 'avail=$(df -BG /data'
    assert la.count(gate_old) == 1
    if suffix == '':
        gate = ('# claim 1 runs binaries frozen from loop333 (the tree is being edited by another agent): committed crates/bin must equal the loop333 build tip\n'
                'if ! git diff --quiet 79f20617a 17fb31cfe -- crates bin Cargo.toml Cargo.lock; then echo "crates/bin differ between 79f20617a and 17fb31cfe; nothing run"; echo ALLDONE; exit 1; fi\n'
                '[ -x /data/n42-build/target-n42-rs/loop334-base/release/n42 ] || { echo "the frozen binaries are missing; nothing run"; echo ALLDONE; exit 1; }\n')
    else:
        gate = ('# claim 2 runs the binary with N42_LEADER_LAYERS: the commit must be in and nothing in crates/ bin/ uncommitted\n'
                'grep -rq N42_LEADER_LAYERS crates/n42/engine-types/src || { echo "N42_LEADER_LAYERS is not in the tree; nothing built"; echo ALLDONE; exit 1; }\n'
                'if [ -n "$(git status --porcelain crates bin | grep -v pycache)" ]; then echo "uncommitted changes in crates/ or bin/; nothing built"; echo ALLDONE; exit 1; fi\n')
    if suffix == '':
        a = la.index('echo "box free at'); b = la.index('swap_used=')
        la = la[:a] + 'echo "frozen binaries (loop333 build, no cargo): box free at $(date +%H:%M)"\n' + la[b:]
    la = la.replace(gate_old, gate + gate_old, 1)
    la = la.replace('echo "box free at $(date +%H:%M); builds:"', 'echo "tree at $(git rev-parse --short HEAD) ($(git log -1 --format=%s | cut -c1-80)); box free at $(date +%H:%M); builds:"')
    open(D + f'launch-loop334{suffix}.sh', 'w').write(la)
derive('')
derive('b')
