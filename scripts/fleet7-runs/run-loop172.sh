#!/usr/bin/env bash
# loop172: the leader's profile on the new footing. loop167's profile was taken before the allocator change and 24%
# of the build thread's samples were jemalloc's madvise; with oversize_threshold:0 and the direct receipts the build
# is 383 -> 298 ms, so what is left has to be measured again before anything is redesigned. Two legs on the fleet's
# adopted settings, each recording one node with perf for 60 s inside the flood (one process at a time: 256 CPUs of
# ring buffers do not fit the 8 MB memlock, loop166). The binaries carry symbols (`--profile profiling`), which a
# release build does not. Tests and the build are already done; the runner waits for the profiling build, then for a
# quiet box; every leg under a hard timeout; released on any exit.
cd /home/n42/src/n42/n42-rs
S=/home/n42/src/n42/n42-rs/target/fleet-runs
B=/data/blockchain/rust-fleet7-bench
NEW=/home/n42/src/n42/n42-rs/target/profiling-build/profiling
CLAIM=/data/blockchain/.box-claim-rust; CLAIM2=/data/blockchain/wr-logs/.box-claim-rust
cleanup() {
  rm -f $CLAIM $CLAIM2
  # The fleet this runner started goes with it. Killing the runner alone left
  # seven nodes and seven validators running for four and a half hours on
  # 2026-09-19: they held the box against this runner's own quiet check and
  # against whoever claimed it next.
  for p in $(pgrep -f '/n4[2] node'; pgrep -f 'h2_validato[r]'; pgrep -f 'tx_floo[d]'); do kill $p 2>/dev/null; done
}
trap cleanup EXIT
while pgrep -f 'carg[o] build.*profiling-build' > /dev/null; do sleep 60; done
if [ ! -x $NEW/n42 ] || [ ! -x $NEW/examples/h2_validator ]; then echo "NO PROFILING BINARY at $NEW"; echo ALLDONE; exit 1; fi
echo "profiling binaries ready at $(date +%H:%M): $(stat -c %y $NEW/n42 | cut -c1-16)"
BUILD_FROM=0
WAITED_FROM=$(date -u +%s)
good() { [ "$(awk '{printf "%d", $1}' /proc/loadavg)" -lt 8 ] && d=$(ps -eo rss,comm | awk '/n42-datc/{s+=$1} END{printf "%d", s/1e6}'); [ "$(pgrep -fc 'bin/n42-[a-z]+ --chai[n]')" = "0" ] && [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" = "0" ] && [ "$(pgrep -fc 'n4[2] node')" = "0" ] && [ "$(pgrep -fc 'n42-dat[c]')" = "0" ] && [ "$(pgrep -fc 'eth-el-frame[d]')" = "0" ] && { [ "$(pgrep -fc 'txfloo[d]')" = "0" ] || [ $(( $(date -u +%s) - ${WAITED_FROM:-0} )) -gt 600 ]; } && [ "${d:-0}" -lt 45 ] && [ "$(free -g | awk '/Mem:/{print $7}')" -ge 80 ]; }
theirs_claim() { local f n=""; for f in /data/blockchain/.box-claim-* /data/blockchain/wr-logs/.box-claim-*; do [ -e "$f" ] || continue; case "$f" in *box-claim-rust) continue;; esac; v=$(tr -c '0-9\n' ' ' < "$f" | tr -s ' ' '\n' | grep -E '^[0-9]+$' | sort -n | tail -1); [ -z "$v" ] && v=9999999999; n="$n $v"; done; echo $n | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -n | tail -1; }
quiet() { local n=0; while [ $n -lt 3 ]; do [ -z "$(theirs_claim)" ] || return 1; good || return 1; n=$((n+1)); [ $n -lt 3 ] && sleep 30; done; return 0; }
mkdir -p /data/blockchain/wr-logs
echo "waiting for a quiet box from $(date +%H:%M)"
while true; do
  until quiet; do sleep 30; done
  mine=$(date -u +%s); echo "$mine" | tee $CLAIM > $CLAIM2
  sleep $((20 + RANDOM % 31))
  theirs=$(theirs_claim)
  [ -n "$theirs" ] && [ "$theirs" -lt "$mine" ] && [ $(( mine - theirs )) -gt 5400 ] && theirs=""
  if good && { [ -z "$theirs" ] || [ "$theirs" -gt "$mine" ]; }; then break; fi
  rm -f $CLAIM $CLAIM2; echo "stood down at $(date +%H:%M): another claim or the box got busy"; sleep 60
done
echo "claimed at $(date +%H:%M) ($mine): avail $(free -g | awk '/Mem:/{print $7}')G load $(awk '{print $1}' /proc/loadavg)"
CLAIMED_AT=$(date -u +%s)
if [ "$(stat -c %Y $NEW/n42)" -lt "$BUILD_FROM" ]; then echo "the binary predates this runner's build; released without a leg"; echo ALLDONE; exit 1; fi
export F7_LEADER_TENURE=16 F7_INGEST=1 F7_INGEST_ALL=1 F7_NO_TX_GOSSIP=1 N42_TX_INGEST_ASYNC=1
export F7_DIRECT_PUSH=1 F7_BLOCK_INTERVAL_MS=250 F7_SKIP_STALE_CHECK=1 F7_METRICS_BASE=19300 N42_TX_QUEUE=1
export N42_TX_INGEST_RECOVER_NICE=10 N42_TX_INGEST_RECOVER_PARALLEL=8 N42_TX_INGEST_DIRECT=1
elpid() { ps -eo pid,args | grep -E '/n4[2] node' | grep -E 'rust-fleet7-bench/node3' | awk '{print $1}' | head -1; }
sample() { local p v; p=$(elpid); v=$(pgrep -f 'h2_validato[r]' | head -1)
  for i in $(seq 1 40); do echo "$(date +%H:%M:%S) el_rss=$(awk '/VmRSS/{printf "%.2f", $2/1e6}' /proc/$p/status 2>/dev/null)G val_rss=$(awk '/VmRSS/{printf "%.2f", $2/1e6}' /proc/$v/status 2>/dev/null)G $(awk '/^MemAvailable|^MemFree|^Cached:|^Dirty:|^Writeback:|^AnonPages|^Shmem:/{printf "%s%.1fG ", $1, $2/1e6}' /proc/meminfo) pgpgin=$(awk '/^pgpgin /{print $2}' /proc/vmstat) fleet_majflt=$(for q in $(pgrep -f "/n4[2] node"; pgrep -f "h2_validato[r]"); do awk '{print $12}' /proc/$q/stat 2>/dev/null; done | paste -sd+ | bc) compact_stall=$(awk '/^compact_stall/{print $2}' /proc/vmstat) flood=$(tail -1 $B/bench-$tag/flood.log 2>/dev/null | grep -oE '\+ *[0-9]+s' | tr -d ' ')"; sleep 5; done
}
median() { sort -n | awk '{a[NR]=$1} END{print (NR ? a[int(NR/2)+1] : "-")}'; }
run() { local tag=$1; shift
  ( n=0; until grep -q 'funding' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done; sample $tag ) > $S/mem-$tag.txt &
  ( n=0; until grep -q 'funding' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done
    sleep 25; p=$(ps -eo pid,args | grep -E '/n4[2] node' | grep -E "rust-fleet7-bench/node$PERF_NODE( |$)" | awk '{print $1}' | head -1)
    [ -n "$p" ] && nice -n 5 perf record -F 499 -g -p $p -o $B/bench-$tag/perf-node$PERF_NODE.data -- sleep 60 ) > $S/perf-$tag.log 2>&1 &
  echo "leg $tag start $(date +%H:%M:%S) load $(awk '{print $1}' /proc/loadavg)"
  env "$@" timeout -k 30 600 scripts/fleet7-bench.sh --tag "$tag" --gasceil 3423000000 --senders 6000 --pertx 10000 --conc 64 --rpcbatch 500 > $S/bench-$tag.out 2>&1; echo "round $tag exit $? at $(date +%H:%M:%S)"
  e=$(pgrep -f '/n4[2] node' | head -1); [ -n "$e" ] && echo "el binary: $(readlink /proc/$e/exe) env: $(tr '\0' '\n' < /proc/$e/environ | grep -E 'QMDB_READS|HASHED_TABLES|ED25519_MERGE|DIRECT_RECEIPTS|MALLOC_CONF' | paste -sd' ')"
  wait
  echo "$tag tc=$(cat $B/node*/v.log | grep -c 'TC formed') invalid_blocks=$(cat $B/node*/el.log | grep -c 'Encountered invalid block') incomplete=$(cat $B/node*/el.log | grep -c 'an incomplete execution result') gas_mismatch=$(cat $B/node*/el.log | grep -c 'gas used mismatch') direct_imports_failed=$(cat $B/node*/el.log | grep -c 'direct import failed') stuck_at_hashed_state=$(cat $B/node*/el.log | grep -c 'import_stage="hashed-state"') engine_idles_over_5s=$(cat $B/node*/el.log | grep -cE 'branch="orchestrator".*idle_before_ms=([5-9][0-9]{3}|[0-9]{5})') proposals_given_up=$(cat $B/node*/v.log | grep -c 'could not build a block to propose') tables_off_nodes=$(cat $B/node*/el.log | grep -c 'hashed state tables are not written') unanswered_reads=$(cat $B/node*/el.log | grep -c 'N42_HASHED_TABLES=off leaves no table') seal_first_total=$(cat $B/node*/el.log | grep -c 'seal-first build phases') seal_first_direct=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -c 'direct_receipts=true') direct_guard_errors=$(cat $B/node*/el.log | grep -c 'early seal that did not happen') commit_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'par_commit_ms=[0-9]+' | cut -d= -f2 | median) fold_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'par_fold_ms=[0-9]+' | cut -d= -f2 | median) sealed_at_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'sealed_at_ms=[0-9]+' | cut -d= -f2 | median) state_ready_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'state_ready_ms=[0-9]+' | cut -d= -f2 | median) build_total_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'total_ms=[0-9]+' | cut -d= -f2 | median) recover_us_median=$(cat $B/node*/el.log | grep -oE 'recover_us_per_tx=[0-9]+' | cut -d= -f2 | median) min_avail_g=$(grep -oE 'MemAvailable:[0-9.]+' $S/mem-$tag.txt | cut -d: -f2 | sort -n | head -1)"
  for i in 0 1 2 3 4 5 6; do cp $B/node$i/el.log $B/bench-$tag/node$i-el.log; cp $B/node$i/v.log $B/bench-$tag/node$i-v.log; done
  python3 scripts/fleet7-phases.py $B > $B/bench-$tag/phases.txt 2>&1; python3 scripts/fleet7-windows.py $B/bench-$tag $S/mem-$tag.txt > $B/bench-$tag/windows.txt 2>&1; python3 scripts/fleet7-cycles.py $B/bench-$tag > $B/bench-$tag/cycles.txt 2>&1
  echo "$tag $(grep -E '^win1 ' $B/bench-$tag/round.txt | grep -oE 'tps= *[0-9,]+' | tr -d ' ') round_txs=$(grep -E '^win[123] ' $B/bench-$tag/round.txt | grep -oE 'txs=[0-9,]+' | cut -d= -f2 | tr -d , | paste -sd+ | bc) cycles_w1=$(awk '/^w1 /{print $4}' $B/bench-$tag/cycles.txt)"
  for p in $(pgrep -f '/n4[2] node'; pgrep -f 'h2_validato[r]'; pgrep -f 'tx_floo[d]'); do kill -9 $p 2>/dev/null; done; sleep 2
}
leg() {
  if [ $(( $(date -u +%s) - CLAIMED_AT )) -gt 4500 ]; then echo "leg loop172$1 skipped: 75 minutes of the claim used"; return; fi
  local tag=$1; shift
  run loop172$tag F7_EL_EXTRA="--builder.interval 60 --builder.deadline 3" N42_FAST_TRANSFER=1 N42_FOLLOWER_DIRECT_IMPORT=1 F7_SENDER_CACHE_MULT=4 N42_TX_QUEUE_BATCH=1024 N42_TX_QUEUE_DRAINER=1 F7_FLOOD_WINDOW=6 N42_TX_INGEST_RECOVER_PARALLEL=20 F7_BLOCK_INTERVAL_MS=350 "$@"
}
C='N42_BUILDER_PULLER=1024 N42_TX_QUEUE_RUN=64 MALLOC_CONF=thp:always N42_FOLLOWER_PARALLEL=1 TOKIO_WORKER_THREADS=8 F7_FLOOD_ALG=ed25519 N42_ALTSIG_SENDER_CACHE=4194304 N42_ED25519_BATCH=128'
R='N42_PARALLEL_BUILD=1 N42_FOLLOWER_GRAFT=1 F7_STRAGGLER_GRACE_MS=600 RAYON_NUM_THREADS=16 N42_BUILD_ON_SEAL=1 F7_LEADER_TENURE=64 N42_QMDB_RETAIN_DEPTH=16 N42_QMDB_ENTRY_FILE=1'
A2='MALLOC_CONF=thp:always,oversize_threshold:0,dirty_decay_ms:2000,background_thread:true'
D='N42_QMDB_READS=on N42_HASHED_TABLES=off'
PERF_NODE=0
leg P0 F7_BIN=$NEW $C $R $D $A2
PERF_NODE=3
leg P3 F7_BIN=$NEW $C $R $D $A2
cleanup
echo "released at $(date +%H:%M)"
echo ALLDONE
