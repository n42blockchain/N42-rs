#!/usr/bin/env bash
# Run one bench configuration several times and report the distribution.
#
#   scripts/fleet7-repeat.sh <runs> --tag <name> [any fleet7-bench.sh argument]
#
# Fifteen single rounds established that this rig's spread can swallow a 20%
# difference: the same configuration produced 1,024,853 and 894,094 transactions
# on consecutive runs, and a window that had reproduced to the transaction three
# times running stopped doing so when one timeout changed. Every comparison made
# from one round each side is therefore a direction and not a magnitude, which
# after a while is most of them.
#
# So a configuration is a distribution, not a number. This runs the same one
# repeatedly with a fresh sender offset each time — reusing an offset is its own
# failure mode, see tx_flood — and prints every round plus the spread, which is
# the only honest way to say whether two configurations differ.

set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

RUNS=${1:?how many runs}
shift
TAG=repeat
ARGS=()
while (( $# )); do
  case $1 in
    --tag) TAG=$2; shift 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

: "${F7_ROOT:=/data/blockchain/rust-fleet7-bench}"
OUT=$F7_ROOT/repeat-$TAG
mkdir -p "$OUT"
echo "$RUNS runs of '$TAG', results in $OUT" | tee "$OUT/summary.txt"

for ((run = 1; run <= RUNS; run++)); do
  # A fresh offset every round, derived so two runs of this script never collide.
  offset=$(( ($(date +%s) + run * 7919) % 1000000 ))
  echo "--- run $run/$RUNS (offset $offset) ---" | tee -a "$OUT/summary.txt"
  "$HERE/fleet7-bench.sh" --tag "$TAG-r$run" --offset "$offset" "${ARGS[@]}" \
    > "$OUT/run$run.log" 2>&1 || true
  grep -E "^win" "$OUT/run$run.log" | tee -a "$OUT/summary.txt" || true
done

echo | tee -a "$OUT/summary.txt"
python3 - "$OUT" "$RUNS" <<'PY' | tee -a "$OUT/summary.txt"
import re, sys, statistics
out, runs = sys.argv[1], int(sys.argv[2])
totals, per_window = [], {}
for run in range(1, runs + 1):
    try:
        lines = [l for l in open(f'{out}/run{run}.log') if l.startswith('win')]
    except OSError:
        continue
    total = 0
    for line in lines:
        w = line.split()[0]
        m = re.search(r'txs=\s*([\d,]+)', line)
        t = re.search(r'tps=\s*([\d,]+)', line)
        if not m:
            continue
        total += int(m.group(1).replace(',', ''))
        per_window.setdefault(w, []).append(int(t.group(1).replace(',', '')))
    if total:
        totals.append(total)
if not totals:
    print('no completed runs')
    raise SystemExit
def spread(v):
    if len(v) < 2:
        return f'{v[0]:,} (one run)'
    return (f'median {statistics.median(v):,.0f}  min {min(v):,}  max {max(v):,}  '
            f'spread {100 * (max(v) - min(v)) / statistics.median(v):.0f}%')
for w in sorted(per_window):
    print(f'{w} tps : {spread(per_window[w])}')
print(f'total txs: {spread(totals)}')
print(f'runs     : {len(totals)} of {runs}')
PY
