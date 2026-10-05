#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop333.sh / launch-loop333.sh (claim 1) and run-loop333b.sh / launch-loop333b.sh (claim 2: the legs the first claim's 75-minute cap
left out) for loop333 (E=1 around the peak on a 400M replay set, docs 10.80) from the loop332 pair. Claim 1 first generates the set under the claim
(free space >= 200G on /data, `tx_flood --pregen-out ... --pregen-txs 400000000 --senders 12500 --pertx 32000`, wall time and size printed) and falls
back to /data/n42-pregen/g900000 (6,000 senders, 192M) when generation fails or space is short. Base G = loop332 G80 (200,000 transfers a block,
80 ms, feed 4.0M, pool 2.0M, build pool 32). Legs: WARM, G80, G80b, G70, G60 (skipped when G70's seal binds over a third of blocks or its blocks are
under two thirds full), H100 and H80 (250,000 a block: gas ceiling 250,000 x 21,000 = 5,250,000,000), B70b (163k at 70 ms, the pair of loop332 B70),
X and Xb (the best single leg by window 1 among those with >= 95% full blocks and the seal under a third, twice). Every leg's argument list is kept in
$S/args-<tag>.txt so claim 2 repeats claim 1's configurations exactly."""
import re
D = '/data/n42-build/target-n42-rs/fleet-runs/'
base_run = open(D + 'run-loop332.sh').read()
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
PREGEN = r'''
# --- the larger replay set, generated under this claim (docs 10.80); the old one stays untouched
OLDSET=/data/n42-pregen/g900000; NEWSET=/data/n42-pregen/g900000-400m
REPLAY=$OLDSET; export F7_SENDERS_ARG=6000
avail=$(df -BG /data | awk 'NR==2{gsub("G","",$4); print $4}')
if [ -f $NEWSET/.complete ]; then REPLAY=$NEWSET; export F7_SENDERS_ARG=12500; echo "the 400M set is already complete in $NEWSET"
elif [ "${avail:-0}" -lt 200 ]; then echo "PREGEN SKIPPED: /data has only ${avail}G free (needs 200G); the old 192M set is used"
else
  rm -rf $NEWSET; mkdir -p $NEWSET
  PG_CMD="$NAT/examples/tx_flood --pregen-out $NEWSET --pregen-txs 400000000 --alg ed25519 --chain-id 1143 --senders 12500 --pertx 32000 --offset 900000 --gasprice 1000000000000000000000000 --gas 21000 --recipients 2000000 --rpcbatch 500 --conc 64 --gateway-key seed:n42-bench-gateway"
  echo "pregen command: $PG_CMD"; PG_T0=$(date +%s)
  if nice -n 5 $PG_CMD > $S/pregen-loop333.log 2>&1; then
    echo "pregen: done in $(( $(date +%s) - PG_T0 )) s, $(du -sh $NEWSET | cut -f1), $(ls $NEWSET | wc -l) files; $(grep -E '^pregen +:' $S/pregen-loop333.log | head -2 | cut -c1-200 | paste -sd'|')"
    touch $NEWSET/.complete; REPLAY=$NEWSET; export F7_SENDERS_ARG=12500
  else echo "PREGEN FAILED after $(( $(date +%s) - PG_T0 )) s (the old set is used):"; tail -4 $S/pregen-loop333.log | cut -c1-240; rm -rf $NEWSET; fi
  echo "/data free after pregen: $(df -BG /data | awk 'NR==2{print $4}')"
fi
echo "replay set for every leg: $REPLAY (senders $F7_SENDERS_ARG)"
'''
DYN_JUD = r'''
jud() { python3 - $1 <<'PYEOF'
import re, subprocess, sys
t = sys.argv[1]; B = '/data/blockchain/rust-fleet7-bench'
try:
    r = open(f'{B}/bench-loop333{t}/round.txt').read()
    w = int(re.search(r'win1 +tps= *([\d,]+)', r)[1].replace(',', ''))
    m = re.search(r'win1 .*full\(>=95%\)=(\d+)/(\d+)', r); full = int(m[1]) / max(1, int(m[2]))
    out = subprocess.run(['python3', 'scripts/fleet7-runs/analyze328.py', f'loop333{t}'], capture_output=True, text=True).stdout
    m = re.search(r'seal ([\d.]+)%', out); seal = float(m[1]) / 100 if m else 0.0
    print(t, w, round(full, 3), round(seal, 3))
except Exception as e:
    print(t, 0, 0, 1)
PYEOF
}
argsof() { eval "$2=($(cat $S/args-loop333$1.txt))"; }
'''
DYN_X = r'''
BEST=""; BW=0
for T in G80 G80b G70 G60 H100 H80 B70b; do
  [ -f $B/bench-loop333$T/round.txt ] || continue
  V=$(jud $T); set -- $V
  if python3 -c "import sys; sys.exit(0 if float('$3') >= 0.95 and float('$4') <= 0.333 else 1)"; then
    if [ "$2" -gt "$BW" ]; then BW=$2; BEST=$T; fi
  fi
done
echo "X is the best single leg by window 1 with full blocks and the seal not binding: ${BEST:-none} ($BW)"
if [ -n "$BEST" ]; then argsof $BEST xargs_; leg X "${xargs_[@]}"; leg Xb "${xargs_[@]}"; fi
'''
def derive(suffix, tail_only):
    run = base_run.replace('loop332', 'loop333')
    lines = run.split('\n')
    def ll(name):
        i = [k for k, l in enumerate(lines) if l.startswith(f'leg {name} ')]
        assert len(i) == 1, name
        return i[0]
    b80 = lines[ll('B80')]
    assert 'F7_FLOOD_RATE=4000000' in b80 and 'F7_BENCH_POOL_SLOTS=2000000' in b80 and 'F7_BLOCK_INTERVAL_MS=80' in b80 and 'F7_GASCEIL_ARG' not in b80
    assert 'F7_FLOOD_REPLAY=/data/n42-pregen/g900000' in b80
    def mk(name, src=b80, *edits):
        l = src.replace('leg B80 ', f'leg {name} ', 1)
        assert l.startswith(f'leg {name} ')
        l = l.replace('F7_FLOOD_REPLAY=/data/n42-pregen/g900000', 'F7_FLOOD_REPLAY=$REPLAY')
        for k, v in edits: l = set_tok(l, k, v)
        return l
    G = ('F7_GASCEIL_ARG', '4200000000'); H = ('F7_GASCEIL_ARG', '5250000000')
    iv = lambda n: ('F7_BLOCK_INTERVAL_MS', str(n))
    guard_i = [k for k, l in enumerate(lines) if l.startswith('W=$B/bench-loop333WARM')]
    assert len(guard_i) == 1
    guard = lines[guard_i[0]]
    warm_name = 'WARM2' if tail_only else 'WARM'
    guard = guard.replace('bench-loop333WARM', f'bench-loop333{warm_name}')
    if tail_only:
        static = [mk('WARM2', b80, G), guard]
        tailb = mk('B70b', b80, iv(70))
    else:
        static = [mk('WARM', b80, G), guard, mk('G80', b80, G), mk('G80b', b80, G), mk('G70', b80, G, iv(70)),
                  None, mk('H100', b80, H, iv(100)), mk('H80', b80, H), mk('B70b', b80, iv(70))]
        g60 = r'''
V=$(jud G70); echo "verdict G70 (tag, window 1, full share, seal share): $V"; set -- $V
if python3 -c "import sys; sys.exit(0 if float('$3') >= 0.667 and float('$4') <= 0.333 else 1)"; then argsof G80 gargs; leg G60 "${gargs[@]}" F7_BLOCK_INTERVAL_MS=60
else echo "G60 skipped: G70 showed the seal (share $4) or the feed (full share $3) binding on more than a third of blocks"; fi'''
        dyn = DYN_JUD + DYN_X
    legs = [k for k, l in enumerate(lines) if l.startswith('leg ')]
    # the legs, in the order the claim runs them; G60's check sits right after G70
    body = []
    for s in static:
        if s is None:
            continue
        body.append(s)
        if s.startswith('leg G70 '): body.append('__G60__')
    new = [x for x in body]
    out = []
    for x in new:
        if x == '__G60__': out += g60.split('\n')
        else: out.append(x)
    # jud and argsof must be defined before first use: place the dyn helpers (without the X tail) before the first leg
    helpers, xtail = DYN_JUD, DYN_X
    tb = ['[ -f $B/bench-loop333B70b/round.txt ] || ' + tailb] if tail_only else []
    lines[legs[0]:legs[-1] + 1] = helpers.split('\n') + out + tb + xtail.split('\n')
    run = '\n'.join(lines)
    # the loop332 runner's own X selection sits after its last `leg` line and survives the splice above: loop333 ran it a second time (a
    # second X / Xb with G80's configuration after the intended H100 pair); cut that second copy
    first = run.index('BEST=""; BW=0'); second = run.find('BEST=""; BW=0', first + 1)
    if second > 0:
        end = run.index('leg Xb "${xargs_[@]}"; fi\n', second) + len('leg Xb "${xargs_[@]}"; fi\n')
        run = run[:second] + run[end:]
    # remember every leg's arguments
    old = "  local tag=$1; shift\n"
    assert run.count(old) == 1
    run = run.replace(old, old + '  printf \'%q \' "$@" > $S/args-loop333$tag.txt\n')
    # senders follow the set
    assert run.count('--senders 6000') == 1
    run = run.replace('--senders 6000', '--senders ${F7_SENDERS_ARG:-6000}')
    if tail_only:
        run = run.replace('export F7_LEADER_TENURE=16 F7_INGEST=1', 'REPLAY=$(cat $S/replay-loop333.txt); export F7_SENDERS_ARG=$(cat $S/senders-loop333.txt)\necho "replay set for every leg: $REPLAY (senders $F7_SENDERS_ARG)"\nexport F7_LEADER_TENURE=16 F7_INGEST=1', 1)
    else:
        run = run.replace('export F7_LEADER_TENURE=16 F7_INGEST=1', PREGEN + 'echo $REPLAY > $S/replay-loop333.txt; echo $F7_SENDERS_ARG > $S/senders-loop333.txt\nexport F7_LEADER_TENURE=16 F7_INGEST=1', 1)
    run = run.replace('#!/usr/bin/env bash\n', '#!/usr/bin/env bash\n# loop333' + suffix + ' = E=1 around the peak on a 400M replay set (docs 10.80): base G = loop332 G80 (200,000 a block, 80 ms, feed 4.0M, pool 2.0M, build pool 32). ' + ('Claim 2: WARM2, B70b, X, Xb.' if tail_only else 'Claim 1: pregen (400M, 12,500 senders; falls back to the 192M set), WARM, G80, G80b, G70, G60 (rule), H100 / H80 (250,000 a block), B70b, X, Xb.') + ' Free-space gate 120G a leg.\n', 1)
    open(D + f'run-loop333{suffix}.sh', 'w').write(run)
    open(D + f'launch-loop333{suffix}.sh', 'w').write(open(D + 'launch-loop332.sh').read().replace('loop332', 'loop333' + suffix))
derive('', False)
derive('b', True)
