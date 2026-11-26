#!/usr/bin/env bash
# Memory rounds of profile-1 members (docs/P1_MEMORY.md): RSS, VmHWM and
# jemalloc's counters of each member's `n42` execution layer and
# `h2_validator`, idle, under steady load and during a catch-up.
#
#   scripts/p1-memory-round.sh genesis               8 s and 500 ms genesis files in PM_DIR
#                                                    (the V1 genesis + PM_SENDERS funded senders)
#   scripts/p1-memory-round.sh steady <name>         four members on the 8 s genesis: PM_IDLE_S
#                                                    idle, PM_LOAD_S at PM_RATE tx/s, PM_POST_S
#                                                    idle again; heap profiles at the end of each
#                                                    phase (PM_PPROF=1); then down
#   scripts/p1-memory-round.sh produce               four members on the 500 ms genesis loaded at
#                                                    PM_RATE for PM_PRODUCE_S: the chain catch-up
#                                                    legs pull; stopped, datadirs kept
#   scripts/p1-memory-round.sh catchup <name>        member 3 wiped and re-initialised; members 0
#                                                    and 1 serve (no quorum, the chain stands);
#                                                    member 3 pulls the produced chain; sampled
#                                                    until it reaches the head + PM_TAIL_S; down
#   scripts/p1-memory-round.sh summary <name>        the phases' median/max per member and role
#
# PM_ENV="K=V ..." goes to every member a phase starts (both processes), PM_EL_ARGS to
# every `n42 node`; PM_ENV_<i> / PM_EL_ARGS_<i> to member i only (one variant per member
# in one round: same chain, same load, same box). Members are scripts/profile1-round.sh members with
# P1_PORT_OFFSET (default 120: libp2p 30822-30833, body 31822-31833, EL HTTP
# 20262-20273, authrpc 20462-20473, devp2p 20562-20573, metrics PM_METRICS+i).
# Take the agents' round lock around a phase:
#   flock /data/n42-build/audit-notes/devnet/.round-agents.lock scripts/p1-memory-round.sh steady base
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
PM_DIR=${PM_DIR:-/data/n42-build/p1-memory}
PM_BIN=${PM_BIN:-/data/n42-build/target-p1-memory/profiling}
PM_SENDERS=${PM_SENDERS:-64}
PM_RATE=${PM_RATE:-150}
PM_IDLE_S=${PM_IDLE_S:-600}
PM_LOAD_S=${PM_LOAD_S:-900}
PM_POST_S=${PM_POST_S:-300}
PM_PRODUCE_S=${PM_PRODUCE_S:-1500}
PM_TAIL_S=${PM_TAIL_S:-60}
PM_INTERVAL=${PM_INTERVAL:-5}
PM_METRICS=${PM_METRICS:-29170}
PM_PPROF=${PM_PPROF:-1}
PM_ENV=${PM_ENV:-}
PM_EL_ARGS=${PM_EL_ARGS:-}
export P1_BIN=$PM_BIN P1_PORT_OFFSET=${P1_PORT_OFFSET:-120} P1_LOAD_TOOL=send_tx P1_LOAD_SENDERS=$PM_SENDERS
export P1_MIN_FREE_GB=${P1_MIN_FREE_GB:-50}
P1=$REPO/scripts/profile1-round.sh
SAMPLER=$REPO/scripts/p1-memory-sample.py
V1=$REPO/crates/n42/qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json
CPUS=0-98,100-226,228-255

metrics_map() { local m out=; for m in 0 1 2 3; do out="$out$m:$((PM_METRICS + m)),"; done; echo "${out%,}"; }
box() { echo "load $(cut -d' ' -f1-3 /proc/loadavg); mem $(free -g | awk '/Mem:/{print "used " $3 " G, avail " $7 " G"}'); n42-like procs $(pgrep -c -f '(n42 node|h2_validator|n42-p1|n42-node)')"; }

# up_members <members> <all>: each member started on its own so its EL gets its own metrics port.
up_members() {
  local members=$1 all=$2 i
  for i in $members; do
    local env_i="PM_ENV_$i" args_i="PM_EL_ARGS_$i"
    echo "member $i env: $PM_ENV ${!env_i:-}; el args: $PM_EL_ARGS ${!args_i:-}" >> "$OUT/config.txt"
    P1_MEMBERS=$i P1_MEMBERS_ALL="$all" P1_MEMBER_ENV="$PM_ENV ${!env_i:-}" P1_RUST_LOG=${PM_RUST_LOG:-info} \
      P1_EL_ARGS="--metrics 127.0.0.1:$((PM_METRICS + i)) $PM_EL_ARGS ${!args_i:-}" "$P1" up >> "$OUT/up.log" 2>&1 || return 1
  done
}

pprof_all() { # pprof_all <tag>: a jemalloc heap profile of every running EL (needs MALLOC_CONF=prof:true)
  [ "$PM_PPROF" = 1 ] || return 0
  local m
  for m in 0 1 2 3; do
    curl -s -m 60 "http://127.0.0.1:$((PM_METRICS + m))/debug/pprof/heap" -o "$OUT/heap-$1-m$m.pb.gz" || rm -f "$OUT/heap-$1-m$m.pb.gz"
    [ -s "$OUT/heap-$1-m$m.pb.gz" ] || rm -f "$OUT/heap-$1-m$m.pb.gz"
  done
}

smaps_all() { # smaps_all <tag>: the largest mappings of every member process
  local p
  for p in $(pgrep -f "^[${PM_BIN:0:1}]${PM_BIN:1}/(n42 node|examples/h2_validator) --datadir $P1_DIR/"); do
    {
      tr '\0' ' ' < "/proc/$p/cmdline" | cut -c1-140; echo
      cat "/proc/$p/smaps_rollup" 2>/dev/null
      awk '/^[0-9a-f]+-[0-9a-f]+ /{name=$6; if (name=="") name="[anon]"} /^Rss:/{rss[name]+=$2} END{for (n in rss) printf "%10d kB %s\n", rss[n], n}' "/proc/$p/smaps" 2>/dev/null | sort -rn | head -25
    } > "$OUT/smaps-$1-$p.txt"
  done
}

phase() { # phase <tag> <seconds>
  echo "phase $1 ${2}s start $(date -u +%H:%M:%S); $(box)" | tee -a "$OUT/phases.txt"
  python3 -I "$SAMPLER" sample "$PM_BIN" "$P1_DIR" "$OUT/$1.tsv" "$2" "$PM_INTERVAL" "$(metrics_map)"
  echo "phase $1 end $(date -u +%H:%M:%S); $(box)" | tee -a "$OUT/phases.txt"
  pprof_all "$1"; smaps_all "$1"
}

cmd_genesis() {
  mkdir -p "$PM_DIR"
  P1_GENESIS=$V1 "$P1" load-genesis "$PM_DIR/genesis-8s.json" || exit 1
  python3 -I - "$PM_DIR/genesis-8s.json" "$PM_DIR/genesis-500ms.json" <<'PY' || exit 1
import json, sys
g = json.load(open(sys.argv[1]))
g["config"]["hotstuff"]["blockIntervalMs"] = 500
open(sys.argv[2], "w").write(json.dumps(g, indent=2) + "\n")
PY
  echo "genesis: $PM_DIR/genesis-8s.json $PM_DIR/genesis-500ms.json"
}

cmd_steady() {
  local name=${1:?name}
  OUT=$PM_DIR/runs/$name; rm -rf "$OUT"; mkdir -p "$OUT"
  export P1_DIR=$PM_DIR/steady-members P1_GENESIS=$PM_DIR/genesis-8s.json
  echo "PM_ENV=$PM_ENV PM_EL_ARGS=$PM_EL_ARGS rate=$PM_RATE bin=$PM_BIN" > "$OUT/config.txt"
  P1_MEMBERS="0 1 2 3" "$P1" init > "$OUT/init.log" 2>&1 || { tail -5 "$OUT/init.log"; exit 1; }
  up_members "0 1 2 3" "0 1 2 3" || { tail -5 "$OUT/up.log"; P1_MEMBERS="0 1 2 3" "$P1" down; exit 1; }
  phase idle "$PM_IDLE_S"
  P1_MEMBERS="0 1 2 3" "$P1" load "$PM_RATE" "$PM_LOAD_S" >> "$OUT/up.log" 2>&1
  phase load "$PM_LOAD_S"
  phase post "$PM_POST_S"
  P1_MEMBERS="0 1 2 3" "$P1" status > "$OUT/status.txt" 2>&1
  cat "$P1_DIR"/load-m*.log 2>/dev/null | tail -8 > "$OUT/load-tail.txt"
  P1_MEMBERS="0 1 2 3" "$P1" down > "$OUT/down.log" 2>&1
  cmd_summary "$name"
}

cmd_produce() {
  OUT=$PM_DIR/runs/produce; rm -rf "$OUT"; mkdir -p "$OUT"
  export P1_DIR=$PM_DIR/chain-members P1_GENESIS=$PM_DIR/genesis-500ms.json
  P1_MEMBERS="0 1 2 3" "$P1" init > "$OUT/init.log" 2>&1 || { tail -5 "$OUT/init.log"; exit 1; }
  up_members "0 1 2 3" "0 1 2 3" || { tail -5 "$OUT/up.log"; P1_MEMBERS="0 1 2 3" "$P1" down; exit 1; }
  sleep 20
  P1_MEMBERS="0 1 2 3" "$P1" load "$PM_RATE" "$PM_PRODUCE_S" >> "$OUT/up.log" 2>&1
  PM_PPROF=0 phase produce "$PM_PRODUCE_S"
  P1_MEMBERS="0 1 2 3" "$P1" status | tee "$OUT/status.txt"
  P1_MEMBERS="0 1 2 3" "$P1" down > "$OUT/down.log" 2>&1
  # The chain a leg pulls: member 0's head, read back when it serves.
  tail -1 "$OUT/status.txt" >/dev/null
}

cmd_catchup() {
  local name=${1:?name} target h
  OUT=$PM_DIR/runs/$name; rm -rf "$OUT"; mkdir -p "$OUT"
  export P1_DIR=$PM_DIR/chain-members P1_GENESIS=$PM_DIR/genesis-500ms.json
  echo "PM_ENV=$PM_ENV PM_EL_ARGS=$PM_EL_ARGS bin=$PM_BIN" > "$OUT/config.txt"
  rm -rf "$P1_DIR/m3/el" "$P1_DIR/m3/consensus" "$P1_DIR/m3/v.log"* "$P1_DIR/m3/el.log"*
  taskset -c $CPUS "$PM_BIN/n42" init --datadir "$P1_DIR/m3/el" --chain "$P1_DIR/genesis.json" > "$OUT/init.log" 2>&1 || exit 1
  # Servers 0 and 1: two of four, no quorum, the chain stands still.
  PM_ENV_SAVE=$PM_ENV; PM_ENV=${PM_SERVER_ENV:-}
  up_members "0 1" "0 1 3" || { tail -5 "$OUT/up.log"; exit 1; }
  PM_ENV=$PM_ENV_SAVE
  sleep 5
  target=$(curl -s -m 5 -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "http://127.0.0.1:$((20140 + P1_PORT_OFFSET + 12))" \
    | python3 -I -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))")
  echo "target $target" | tee -a "$OUT/config.txt"
  up_members "3" "0 1 3" || { tail -5 "$OUT/up.log"; exit 1; }
  echo "phase catchup start $(date -u +%H:%M:%S); $(box)" | tee -a "$OUT/phases.txt"
  python3 -I "$SAMPLER" sample "$PM_BIN" "$P1_DIR" "$OUT/catchup.tsv" 100000 "${PM_CU_INTERVAL:-1}" "$(metrics_map)" &
  local sampler=$! t0=$SECONDS
  while :; do
    h=$(curl -s -m 5 -X POST -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "http://127.0.0.1:$((20140 + P1_PORT_OFFSET + 3))" \
      | python3 -I -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null)
    [ -n "$h" ] && [ "$h" -ge "$target" ] && break
    [ $((SECONDS - t0)) -gt "${PM_CU_MAX_S:-3600}" ] && { echo "catch-up did not finish (height ${h:-?})" | tee -a "$OUT/phases.txt"; break; }
    sleep 2
  done
  echo "phase catchup reached ${h:-?} after $((SECONDS - t0)) s at $(date -u +%H:%M:%S); $(box)" | tee -a "$OUT/phases.txt"
  pprof_all catchup-head; smaps_all catchup-head
  sleep "$PM_TAIL_S"
  kill "$sampler"; wait "$sampler" 2>/dev/null
  pprof_all catchup-tail
  cp "$P1_DIR/m3/v.log" "$OUT/v3.log"; cp "$P1_DIR/m3/el.log" "$OUT/el3.log"
  P1_MEMBERS="0 1 3" "$P1" down > "$OUT/down.log" 2>&1
  cmd_summary "$name"
}

cmd_summary() {
  local name=${1:?name} f
  for f in "$PM_DIR/runs/$name"/*.tsv; do
    echo "== $(basename "$f" .tsv) (first 60 s skipped)"
    python3 -I "$SAMPLER" summary "$f" 60
  done
  cat "$PM_DIR/runs/$name/phases.txt" 2>/dev/null
}

case ${1:-} in
  genesis) cmd_genesis ;;
  steady) shift; cmd_steady "$@" ;;
  produce) cmd_produce ;;
  catchup) shift; cmd_catchup "$@" ;;
  summary) shift; cmd_summary "$@" ;;
  *) sed -n '2,28p' "$0"; exit 2 ;;
esac
