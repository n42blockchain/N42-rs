#!/usr/bin/env bash
# The catch-up benchmark (docs/P1_CATCHUP_PERF.md): a fresh member pulls a
# realistic profile-1 chain by range from serving members and executes it --
# h2_validator range pull -> Engine API -> EL execution -> QMDB -> persistence.
#
#   scripts/catchup-bench.sh genesis            bench genesis in CB_DIR (profile-1 V1 genesis,
#                                               CB_INTERVAL_MS pacing, CB_PHASES x CB_SENDERS funded
#                                               senders, CB_RECIPIENTS pre-created recipients)
#   scripts/catchup-bench.sh produce            init + up four members, flood the phases
#                                               (CB_SCHEDULE), drain, record the chain's shape
#                                               (CB_DIR/blocks.tsv), stop every member
#   scripts/catchup-bench.sh leg <name>         one catch-up: member 3 wiped and re-initialised,
#                                               members 0 and 1 serve (two of four: no quorum, so
#                                               the chain does not move), member 3 pulls from 0;
#                                               heights sampled every CB_SAMPLE_S, CPU per process,
#                                               the EL's metrics before/after; then all down.
#                                               CB_ENV="K=V,K=V" (comma or space) goes to member 3 only,
#                                               CB_EL_ARGS="--flag,value" (comma or space) to its EL.
#   scripts/catchup-bench.sh report <name>      blocks/s, txs/s, bytes/s overall and per segment
#
# Everything lives under CB_DIR (default /data/n42-build/p1-catchup); the
# members are scripts/profile1-round.sh members with P1_PORT_OFFSET (default
# 60: libp2p 30762-30773, body 31762-31773, EL HTTP 20200-20215), off every
# port gov5 reserves. Runs need the agents' devnet round lock:
#   flock /data/n42-build/audit-notes/devnet/.round-agents.lock scripts/catchup-bench.sh leg base
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
CB_DIR=${CB_DIR:-/data/n42-build/p1-catchup}
CB_BIN=${CB_BIN:-/data/n42-build/target-p1-catchup/profiling}
CB_INTERVAL_MS=${CB_INTERVAL_MS:-500}
CB_SENDERS=${CB_SENDERS:-4000}
CB_RECIPIENTS=${CB_RECIPIENTS:-100000}
CB_GASPRICE=${CB_GASPRICE:-1000000000000000}
# Phases "<tx/s>:<seconds>", 0 tx/s = idle. Each loaded phase floods with its
# own funded sender set (offset k*CB_SENDERS), so nonces never collide.
CB_SCHEDULE=${CB_SCHEDULE:-0:60 2000:240 10000:240 40000:90 0:60 20000:240 40000:90 0:30}
CB_SAMPLE_S=${CB_SAMPLE_S:-0.5}
CB_METRICS_PORT=${CB_METRICS_PORT:-20290}
# CPUs: every member on the whole box less the faulty core 99/227 unless
# CB_CPUS (member 3) / CB_SERVER_CPUS (members 0 and 1) pin them.
DEF_CPUS=0-98,100-226,228-255
export P1_DIR=$CB_DIR/members P1_BIN=$CB_BIN P1_PORT_OFFSET=${P1_PORT_OFFSET:-60}
export P1_GENESIS=$CB_DIR/genesis.json P1_GENESIS_NOW=0 P1_MIN_FREE_GB=${P1_MIN_FREE_GB:-50}
# Pool sizing for the flood (reth's defaults hold 10k pending, 16 per sender)
# and no 1-ETH fee cap: the price leaves room for ~100 consecutive full blocks.
EL_POOL="--txpool.pending-max-count 400000 --txpool.pending-max-size 2048 --txpool.basefee-max-count 400000 \
--txpool.basefee-max-size 2048 --txpool.queued-max-count 400000 --txpool.queued-max-size 2048 \
--txpool.max-account-slots 4096 --rpc.txfeecap 0 --rpc.max-connections 512 --rpc-cache.max-blocks 4"
P1=$REPO/scripts/profile1-round.sh
V1=$REPO/crates/n42/qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json
http_port() { local s=0; [ "$1" -lt 2 ] && s=12; echo $((20140 + P1_PORT_OFFSET + $1 + s)); }
rpc() { curl -s -m 10 -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "http://127.0.0.1:$1"; }
height() { rpc "$(http_port "$1")" eth_blockNumber '[]' | python3 -I -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null; }
# A coordinator round holds this lock: no timing run while it does.
COORD_LOCK=${CB_COORD_LOCK:-/data/n42-build/audit-notes/devnet/.round.lock}
coord_free() {
  [ -e "$COORD_LOCK" ] || return 0
  flock -n "$COORD_LOCK" true || { echo "coordinator round lock $COORD_LOCK is held; not starting" >&2; exit 3; }
}
nphases() { local n=0 p; for p in $CB_SCHEDULE; do [ "${p%%:*}" != 0 ] && n=$((n + 1)); done; echo $n; }

cmd_genesis() {
  mkdir -p "$CB_DIR"
  local total=$(( $(nphases) * CB_SENDERS ))
  "$CB_BIN/examples/send_tx" --senders "$total" --print-addresses > "$CB_DIR/senders.txt" || exit 1
  python3 -I - "$V1" "$CB_DIR/genesis.json" "$CB_DIR/senders.txt" "$CB_RECIPIENTS" "$CB_INTERVAL_MS" <<'PY' || exit 1
import json, sys, time
src, out, senders, nrec, interval = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
g = json.load(open(src))
g["timestamp"] = hex(int(time.time()))
g["config"]["hotstuff"]["blockIntervalMs"] = interval
have = {k.lower() for k in g["alloc"]}
for a in open(senders).read().split():
    assert a.lower() not in have, a
    g["alloc"][a] = {"balance": hex(10**24)}
# tx_flood's recipient(spread, i): be32(slot) || 0x42 || 15 zero bytes. Pre-created
# (1 wei), so a transfer to one is 21,000 gas under Amsterdam's EIP-8037 too.
for slot in range(nrec):
    a = "0x" + slot.to_bytes(4, "big").hex() + "42" + "00" * 15
    g["alloc"][a] = {"balance": "0x1"}
json.dump(g, open(out, "w"), indent=1)
print(f"genesis: {out} interval {interval} ms, {len(g['alloc'])} alloc entries")
PY
}

cmd_produce() {
  coord_free
  [ -f "$CB_DIR/genesis.json" ] || cmd_genesis
  P1_MEMBERS="0 1 2 3" "$P1" init || exit 1
  P1_MEMBERS="0 1 2 3" P1_EL_ARGS="$EL_POOL" P1_RUST_LOG=info "$P1" up || exit 1
  sleep 20
  local chain k=0 p rate secs urls
  chain=$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['config']['chainId'])" "$CB_DIR/genesis.json")
  urls=$(for i in 0 1 2 3; do printf 'http://127.0.0.1:%s,' "$(http_port $i)"; done); urls=${urls%,}
  for p in $CB_SCHEDULE; do
    rate=${p%%:*}; secs=${p##*:}
    echo "$(date -u +%T) phase $p at height $(height 0)" | tee -a "$CB_DIR/produce.log"
    if [ "$rate" = 0 ]; then sleep "$secs"; continue; fi
    local pertx=$(( (rate * secs + CB_SENDERS - 1) / CB_SENDERS ))
    timeout $((secs * 3 + 120)) "$CB_BIN/examples/tx_flood" --rpc "$urls" --chain-id "$chain" --senders "$CB_SENDERS" \
      --offset $((k * CB_SENDERS)) --pertx "$pertx" --skip-funding --gasprice "$CB_GASPRICE" \
      --recipients "$CB_RECIPIENTS" --rate "$rate" --conc 64 --rpcbatch 200 \
      >> "$CB_DIR/flood-$k.log" 2>&1
    k=$((k + 1))
  done
  # Let the pools drain into blocks.
  sleep 30
  echo "$(date -u +%T) produced, height $(height 0)" | tee -a "$CB_DIR/produce.log"
  P1_MEMBERS="0 1 2 3" "$P1" status
  P1_MEMBERS="0 1 2 3" "$P1" down
  # The servers' EL is stopped; read the shape back from member 0 once more.
  P1_MEMBERS=0 P1_EL_ARGS="$EL_POOL" "$P1" up > /dev/null || exit 1
  sleep 5
  shape "$(height 0)"
  P1_MEMBERS=0 "$P1" down > /dev/null
}

# blocks.tsv: number, txs, gasUsed, size (bytes, the block's RLP), timestamp.
shape() {
  python3 -I - "$(http_port 0)" "$1" > "$CB_DIR/blocks.tsv" <<'PY'
import json, sys, urllib.request
port, top = int(sys.argv[1]), int(sys.argv[2])
for lo in range(1, top + 1, 100):
    reqs = [{"jsonrpc": "2.0", "id": n, "method": "eth_getBlockByNumber", "params": [hex(n), False]}
            for n in range(lo, min(lo + 100, top + 1))]
    r = urllib.request.Request(f"http://127.0.0.1:{port}", json.dumps(reqs).encode(), {"content-type": "application/json"})
    for x in sorted(json.load(urllib.request.urlopen(r, timeout=60)), key=lambda x: x["id"]):
        b = x.get("result")
        if b:
            print(int(b["number"], 16), len(b["transactions"]), int(b["gasUsed"], 16), int(b["size"], 16),
                  int(b["timestamp"], 16), sep="\t")
PY
  python3 -I - "$CB_DIR/blocks.tsv" <<'PY'
import sys
rows = [list(map(int, l.split())) for l in open(sys.argv[1])]
n = len(rows); tx = sum(r[1] for r in rows); by = sum(r[3] for r in rows)
full = sum(1 for r in rows if r[2] >= 0.95 * 480_000_000)
print(f"chain: {n} blocks, {tx} txs, {by/1e6:.1f} MB, full(>=95%) {full}, empty {sum(1 for r in rows if r[1]==0)}, max txs {max(r[1] for r in rows)}")
PY
}

cmd_leg() {
  local name=${1:?leg name} out
  coord_free
  out=$CB_DIR/legs/$name; rm -rf "$out"; mkdir -p "$out"
  [ -f "$CB_DIR/blocks.tsv" ] || { echo "no chain: produce first" >&2; exit 1; }
  local target; target=$(tail -1 "$CB_DIR/blocks.tsv" | cut -f1)
  pgrep -af "^[${CB_BIN:0:1}]${CB_BIN:1}/(n42 node|examples/h2_validator) --datadir $P1_DIR/" && { echo "members running; down first" >&2; exit 1; }
  # Member 3 from nothing: a fresh EL (n42 init) and no consensus store.
  rm -rf "$P1_DIR/m3/el" "$P1_DIR/m3/consensus"
  taskset -c 0-98,100-226,228-255 "$CB_BIN/n42" init --datadir "$P1_DIR/m3/el" --chain "$P1_DIR/genesis.json" > "$out/init.log" 2>&1 || exit 1
  P1_CPUS="${CB_SERVER_CPUS:-$DEF_CPUS}" P1_MEMBERS="0 1" P1_MEMBERS_ALL="0 1 3" P1_EL_ARGS="$EL_POOL ${CB_SERVER_EL_ARGS:-}" P1_MEMBER_ENV="${CB_SERVER_ENV:-}" \
    P1_RUST_LOG=info "$P1" up > "$out/up-servers.log" 2>&1 || exit 1
  sleep 5
  echo "load before: $(cut -d' ' -f1-3 /proc/loadavg); top: $(ps -eo pcpu,comm --sort=-pcpu | sed -n 2,6p | tr -s ' ' | tr '\n' ';')" | tee "$out/box.txt"
  echo "target $target; CB_ENV=${CB_ENV:-} CB_EL_ARGS=${CB_EL_ARGS:-}" > "$out/leg.txt"
  # The sampler starts before member 3 does: a short pull ends inside `up`.
  python3 -I "$REPO/scripts/catchup-sampler.py" "$(http_port 3)" "$target" "$CB_SAMPLE_S" "${CB_STALL_S:-60}" \
    "$CB_BIN" "$P1_DIR" "$out" &
  local sampler=$!
  P1_CPUS="${CB_CPUS:-$DEF_CPUS}" P1_MEMBERS=3 P1_MEMBERS_ALL="0 1 3" P1_EL_ARGS="$EL_POOL --metrics 127.0.0.1:$CB_METRICS_PORT $(echo "${CB_EL_ARGS:-}" | tr , " ")" \
    P1_MEMBER_ENV="$(echo "${CB_ENV:-}" | tr , " ")" P1_RUST_LOG=info,n42=debug "$P1" up > "$out/up-m3.log" 2>&1 || { kill $sampler; exit 1; }
  wait $sampler
  sleep 2
  curl -s "http://127.0.0.1:$CB_METRICS_PORT" > "$out/metrics-after.txt"
  echo "load after: $(cut -d' ' -f1-3 /proc/loadavg)" >> "$out/box.txt"
  # Member 3's peak RSS (VmHWM) per process, read before it is stopped.
  local pid
  for pid in $(pgrep -f "^[${CB_BIN:0:1}]${CB_BIN:1}/(n42 node|examples/h2_validator) --datadir $P1_DIR/m3"); do
    echo "peak rss: $(tr '\0' ' ' < /proc/$pid/cmdline | cut -c1-60 | sed 's|.*/||') $(awk '/VmHWM/ {print $2, $3}' /proc/$pid/status)"
  done | tee -a "$out/box.txt"
  echo "disk: el $(du -sm "$P1_DIR/m3/el" | cut -f1) MiB, consensus $(du -sm "$P1_DIR/m3/consensus" 2>/dev/null | cut -f1) MiB" | tee -a "$out/box.txt"
  cp "$P1_DIR/m3/v.log" "$out/v3.log"; cp "$P1_DIR/m3/el.log" "$out/el3.log"
  # Every block executed here had its root checked against the header the
  # producers computed; a mismatch is refused and shows up here.
  echo "root mismatches / invalid in el3: $(/usr/bin/grep -ciE 'root mismatch|mismatched.*root|invalid (block|payload)' "$out/el3.log")" | tee -a "$out/box.txt"
  P1_MEMBERS="0 1 3" "$P1" down > "$out/down.log" 2>&1
  cmd_report "$name" | tee "$out/report.txt"
}

cmd_report() {
  python3 -I "$REPO/scripts/catchup-report.py" "$CB_DIR/blocks.tsv" "$CB_DIR/legs/${1:?leg name}"
}


case ${1:-} in
  genesis) cmd_genesis ;;
  produce) cmd_produce ;;
  leg) shift; cmd_leg "$@" ;;
  report) shift; cmd_report "$@" ;;
  shape) shift; shape "$@" ;;
  *) sed -n '2,26p' "$0"; exit 2 ;;
esac
