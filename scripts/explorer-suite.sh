#!/usr/bin/env bash
# Every Blockscout fetcher, one at a time, on a sparse and a dense range of the
# node scripts/explorer-node.sh runs; results appended to EX_JSON with a label.
# docs/EXPLORER_RPC_PERF.md.
#
#   scripts/explorer-suite.sh <label> [extra explorer-load.py run args, e.g. --rtt-ms 10]
#
#   EX_SPARSE="200 399"  EX_DENSE="1150 1249"  (ranges prepared with explorer-load.py prepare)
#   EX_FETCHERS="blocks receipts block-receipts trace-tx trace-block balances tokens code"
#   EX_SECS=60           cap per fetcher and range
#   EX_MAX_FOREIGN=12    wait until other processes use fewer cores than this
#                        before each run (other lanes' legs share the box)
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
label=${1:?label}; shift
EX_HTTP=${EX_HTTP:-20910}
EX_JSON=${EX_JSON:-/data/n42-build/explorer-rpc/results.jsonl}
EX_SECS=${EX_SECS:-60}
EX_FETCHERS=${EX_FETCHERS:-blocks receipts block-receipts trace-tx trace-block balances tokens code}
pid=$("$REPO/scripts/explorer-node.sh" pid)
# Cores busy on the host over one second, less this node's.
foreign_cores() {
  python3 -I - "$pid" <<'EOF'
import os, sys, time
pid = sys.argv[1]
def host():
    v = [int(x) for x in open('/proc/stat').readline().split()[1:]]
    return sum(v) - v[3] - v[4], sum(v)
def node():
    p = open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()
    return int(p[11]) + int(p[12])
(b0, t0), n0 = host(), node()
time.sleep(1)
(b1, t1), n1 = host(), node()
cores = os.cpu_count() * (b1 - b0) / (t1 - t0)
print(f'{max(0.0, cores - (n1 - n0) / os.sysconf("SC_CLK_TCK")):.1f}')
EOF
}
for range in "${EX_SPARSE:-200 399}" "${EX_DENSE:-1150 1249}"; do
  read -r a b <<< "$range"
  for f in $EX_FETCHERS; do
    for _ in $(seq 1 120); do
      busy=$(foreign_cores)
      awk -v b="$busy" -v m="${EX_MAX_FOREIGN:-12}" 'BEGIN{exit !(b < m)}' && break
      sleep 5
    done
    echo "foreign load $busy cores"
    python3 -I "$REPO/scripts/explorer-load.py" --rpc "http://127.0.0.1:$EX_HTTP" run --from "$a" --to "$b" \
      --fetchers "$f" --duration "$EX_SECS" --pid "$pid" --json "$EX_JSON" --label "$label" "$@" \
      | /usr/bin/grep -vE '^fetcher'
  done
done
