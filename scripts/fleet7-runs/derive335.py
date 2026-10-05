#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop335.sh / launch-loop335.sh (claim 1: WARM, P70, P70b, P75, P75b, S163, S163b) and run-loop335b.sh / launch-loop335b.sh (claim 2: WARM2,
S250, S300, L4, T64) for loop335 (docs 10.82) from loop334's claim-2 pair (which carries the full build and test gates). Base P = loop334 L3FS
(N42_LEADER_LAYERS=3, N42_FIELDS_AT_SEAL=1, 200,000 transfers a block, 400M set). Every leg is E=1, windows from the layer's canonical log. A leg whose
feed bound (feedcheck335.py: under 97% full blocks or a median queue under 2.5 blocks in any window) is rerun once as <tag>r with F7_FLOOD_RATE=6.0M and pool 3.0M."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop334b.sh').read()
def set_tok(line, key, val):
    toks = line.split(' ')
    pat = re.compile(r'^' + re.escape(key) + r'=\S*$')
    hit = [i for i, t in enumerate(toks) if pat.match(t)]
    if hit:
        for i in hit: toks[i] = f'{key}={val}'
    else: toks.append(f'{key}={val}')
    return ' '.join(toks)
LEGF = r'''
# a leg whose feed bound is rerun once with the feed raised (docs 10.82); the rerun's numbers are reported as such
legf() {
  local tag=$1; shift
  leg $tag "$@"
  [ -f $B/bench-loop335$tag/round.txt ] || return
  if ! python3 scripts/fleet7-runs/feedcheck335.py loop335$tag; then
    echo "FEED BOUND on $tag: rerun as ${tag}r with F7_FLOOD_RATE=6000000 and pool 3000000"
    leg ${tag}r "$@" F7_FLOOD_RATE=${RR:-6000000} F7_BENCH_POOL_SLOTS=${RP:-3000000}
    [ -f $B/bench-loop335${tag}r/round.txt ] && python3 scripts/fleet7-runs/feedcheck335.py loop335${tag}r
  fi
}
'''
def derive(suffix):
    run = base_run.replace('loop334', 'loop335')
    lines = run.split('\n')
    g = [l for l in lines if l.startswith('leg L3FS ')]
    assert len(g) == 1; p = g[0]
    assert 'N42_LEADER_LAYERS=3' in p and 'N42_FIELDS_AT_SEAL=1' in p and 'F7_GASCEIL_ARG=4200000000' in p and 'F7_BLOCK_INTERVAL_MS=80' in p
    def mk(name, *edits, fn='legf'):
        l = p.replace('leg L3FS ', f'{fn} {name} ', 1)
        for k, v in edits: l = set_tok(l, k, v)
        return l
    iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n)); gas = lambda g: ('F7_GASCEIL_ARG', str(g))
    warm = 'WARM' if suffix == '' else 'WARM2'
    gi = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop335WARM2')]; assert len(gi) == 1
    guard = lines[gi[0]].replace('bench-loop335WARM2', f'bench-loop335{warm}')
    if suffix == '':
        body = [mk(warm, iv(70), fn='leg'), guard, mk('P70', iv(70)), mk('P70b', iv(70)), mk('P75', iv(75)), mk('P75b', iv(75)),
                mk('S163', gas(3423000000), iv(60)), mk('S163b', gas(3423000000), iv(60))]
        title = 'Claim 1: WARM (P70 shape), P70, P70b, P75, P75b, S163, S163b.'
    else:
        body = [mk(warm, iv(70), fn='leg'), guard, mk('S250', gas(5250000000), iv(90)), mk('S300', gas(6300000000), iv(105)),
                mk('L4', iv(70), ('N42_LEADER_LAYERS', '4')), mk('T64', iv(70), ('N42_PARALLEL_BUILD_THREADS', '64'), ('RAYON_NUM_THREADS', '32'))]
        title = 'Claim 2: WARM2 (P70 shape), S250, S300, L4, T64.'
    first = [k for k, l in enumerate(lines) if l.startswith('leg WARM2 ')][0]
    wipe = [k for k, l in enumerate(lines) if l.startswith('for i in 0 1 2 3 4 5 6; do rm -rf $B/node$i/el')][0]
    lines[first:wipe] = body + ['']
    if suffix == '':  # claim 1 runs the raised feed on every leg (rate 6.0M, pool 3.0M), a rerun at 8.0M / 4.0M: loop335 claim 2 showed 2.7M+/s consumption binds the plain feed
        lines = [l + ' F7_FLOOD_RATE=6000000 F7_BENCH_POOL_SLOTS=3000000' if (l.startswith('legf ') or l.startswith('leg WARM ')) else l for l in lines]
    run = '\n'.join(lines)
    i0 = run.index('# loop335 = '); i1 = run.index('cd /home/n42/src/n42/n42-rs')
    hdr = ('# loop335 = the E=1 cycle floor (docs 10.82): base P = loop334 L3FS (N42_LEADER_LAYERS=3, N42_FIELDS_AT_SEAL=1, 200,000 a block, 400M set, windows from the layer\'s canonical log). '
           + title + ' Pairs at 70 and 75 ms, 163k at 60 ms, 250k at 90 ms, 300k at 105 ms, layers 4, build pool 64. A feed-bound leg is rerun once with the feed raised. '
           'Free-space gate 120G a leg, full build and test gate, 75-minute claim cap, per-leg timeout 600 s, claim released on exit, datadirs of the round wiped at the end.\n')
    run = run[:i0] + hdr + run[i1:]
    run = run.replace('\nleg() {', LEGF.replace('legf() {', 'legf_def_marker() {', 0) + '\nleg() {', 1) if False else run
    # legf must be defined after leg(): insert before the first use (the WARM line)
    k = run.index('\nleg ' + warm + ' ') if ('\nleg ' + warm + ' ') in run else run.index('\nleg WARM')
    run = run[:k] + LEGF + run[k:]
    assert 'loop334' not in run.split(chr(10),3)[2].replace('loop334 L3FS','') and run.count('loop334') == 1
    open(D + f'run-loop335{suffix}.sh', 'w').write(run)
    la = open(D + 'launch-loop334b.sh').read().replace('run-loop334b.sh', 'run-loop335' + suffix + '.sh').replace('loop334', 'loop335' + suffix)
    open(D + f'launch-loop335{suffix}.sh', 'w').write(la)
derive(''); derive('b')
