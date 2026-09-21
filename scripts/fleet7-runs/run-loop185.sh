#!/usr/bin/env bash
# loop185: a heap profile of a leg. loop184 put the box's memory on the seven execution layers -- 1 GB to 15-20 GB
# each inside a 90 s round, 95-117 GB together -- and that growth is what takes the page cache, stalls persistence
# and sets the round. One leg of the adopted configuration on a `--features jemalloc-prof` build
# (target/profiling-build), every node dumping its heap each 16 GiB it allocates (lg_prof_interval:34; at 30 the
# dumps themselves would be the load) into $HP on the data disk, never the tmpfs. The leg's throughput is not a
# measurement. Read afterwards: one node's last dump inside the load against its first, by allocation site.
cd /home/n42/src/n42/n42-rs
S=/home/n42/src/n42/n42-rs/target/fleet-runs
B=/data/blockchain/rust-fleet7-bench
NEW=/home/n42/src/n42/n42-rs/target/profiling-build/profiling
HP=/data/blockchain/rust-fleet7-bench/heapprof-loop185
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
if [ ! -x $NEW/n42 ] || [ ! -x $NEW/examples/h2_validator ]; then echo "NO PROFILING BINARY at $NEW"; echo ALLDONE; exit 1; fi
newer=$(find crates bin -name '*.rs' -newer $NEW/n42 2>/dev/null | head -3)
if [ -n "$newer" ]; then echo "SOURCE NEWER THAN THE BINARY ($newer)"; echo ALLDONE; exit 1; fi
rm -rf $HP; mkdir -p $HP
echo "heap-profile binary of $(stat -c %y $NEW/n42 | cut -c1-16), dumps to $HP"
BUILD_FROM=0
WAITED_FROM=$(date -u +%s)
good() { local cpus; cpus=$(nproc)
  [ "$(pgrep -fc 'bin/n42-[a-z]+ --chai[n]')" = "0" ] && [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" = "0" ] \
    && [ "$(pgrep -fc 'n4[2] node')" = "0" ] && [ "$(pgrep -fc 'n42-dat[c]')" = "0" ] && [ "$(pgrep -fc 'eth-el-frame[d]')" = "0" ] \
    && { [ "$(pgrep -fc 'txfloo[d]')" = "0" ] || [ $(( $(date -u +%s) - ${WAITED_FROM:-0} )) -gt 600 ]; } \
    && [ "$(free -g | awk '/Mem:/{print $7}')" -ge 80 ] \
    && [ "$(awk '{printf "%d", $1}' /proc/loadavg)" -lt $(( cpus / 4 )) ]; }
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
sample() { local tag=$1
  for i in $(seq 1 44); do
    echo "$(date +%H:%M:%S) $(ps -eo rss,args | awk '/\/n4[2] node/{n++; s+=$1; if($1>mx)mx=$1; if(mn==0||$1<mn)mn=$1} /h2_validato[r]/{v+=$1} /tx_floo[d]/{f+=$1} END{printf "el_sum=%.1fG el_max=%.1fG el_min=%.1fG el_n=%d val_sum=%.1fG flood=%.1fG", s/1e6, mx/1e6, mn/1e6, n, v/1e6, f/1e6}') $(awk '/^MemAvailable|^MemFree|^AnonPages|^AnonHugePages|^Cached:|^Shmem:|^Slab:|^SUnreclaim|^PageTables|^Dirty:/{printf "%s%.1fG ", $1, $2/1e6}' /proc/meminfo) tmpfs=$(df --output=used -BG /tmp | tail -1 | tr -d ' ') compact_stall=$(awk '/^compact_stall/{print $2}' /proc/vmstat) flood_t=$(tail -1 $B/bench-$tag/flood.log 2>/dev/null | grep -oE '\+ *[0-9]+s' | tr -d ' ')"
    sleep 5
  done
}
median() { sort -n | awk '{a[NR]=$1} END{print (NR ? a[int(NR/2)+1] : "-")}'; }
run() { local tag=$1; shift
  ( n=0; until grep -q 'funding' $B/bench-$tag/flood.log 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 300 ] && exit 0; done; sample $tag ) > $S/mem-$tag.txt &
  echo "leg $tag start $(date +%H:%M:%S) load $(awk '{print $1}' /proc/loadavg)"
  env "$@" timeout -k 30 600 scripts/fleet7-bench.sh --tag "$tag" --gasceil 3423000000 --senders 6000 --pertx 10000 --conc 64 --rpcbatch 500 > $S/bench-$tag.out 2>&1; echo "round $tag exit $? at $(date +%H:%M:%S)"
  for n in 0 3; do echo "heap pid node$n: $(ps -eo pid,args | grep -E '/n4[2] node' | grep -F "rust-fleet7-bench/node$n/el" | awk '{print $1}' | head -1)"; done
  e=$(pgrep -f '/n4[2] node' | head -1); [ -n "$e" ] && echo "el binary: $(readlink /proc/$e/exe) env: $(tr '\0' '\n' < /proc/$e/environ | grep -E 'QMDB_READS|HASHED_TABLES|CHECK_ON_PARENT_OUTPUT|EXEC_ON_PARENT_OUTPUT|BLOCK_INTERVAL|RAYON_NUM_THREADS|PARALLEL_BUILD_THREADS|INGEST_RECOVER_PARALLEL|DIRECT_RECEIPTS|MALLOC_CONF' | paste -sd' ')"
  wait
  echo "$tag tc=$(cat $B/node*/v.log | grep -c 'TC formed') invalid_blocks=$(cat $B/node*/el.log | grep -c 'Encountered invalid block') incomplete=$(cat $B/node*/el.log | grep -c 'an incomplete execution result') gas_mismatch=$(cat $B/node*/el.log | grep -c 'gas used mismatch') direct_imports_failed=$(cat $B/node*/el.log | grep -c 'direct import failed') stuck_at_hashed_state=$(cat $B/node*/el.log | grep -c 'import_stage="hashed-state"') engine_idles_over_5s=$(cat $B/node*/el.log | grep -cE 'branch="orchestrator".*idle_before_ms=([5-9][0-9]{3}|[0-9]{5})') proposals_given_up=$(cat $B/node*/v.log | grep -c 'could not build a block to propose') tables_off_nodes=$(cat $B/node*/el.log | grep -c 'hashed state tables are not written') unanswered_reads=$(cat $B/node*/el.log | grep -c 'N42_HASHED_TABLES=off leaves no table') seal_first_total=$(cat $B/node*/el.log | grep -c 'seal-first build phases') seal_first_direct=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -c 'direct_receipts=true') direct_guard_errors=$(cat $B/node*/el.log | grep -c 'early seal that did not happen') commit_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'par_commit_ms=[0-9]+' | cut -d= -f2 | median) fold_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'par_fold_ms=[0-9]+' | cut -d= -f2 | median) sealed_at_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'sealed_at_ms=[0-9]+' | cut -d= -f2 | median) state_ready_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'state_ready_ms=[0-9]+' | cut -d= -f2 | median) build_total_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'total_ms=[0-9]+' | cut -d= -f2 | median) recover_us_median=$(cat $B/node*/el.log | grep -oE 'recover_us_per_tx=[0-9]+' | cut -d= -f2 | median) par_exec_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'par_exec_ms=[0-9]+' | cut -d= -f2 | median) par_exec_ms_median=$(cat $B/node*/el.log | grep 'seal-first build phases' | grep -oE 'par_exec_ms=[0-9]+' | cut -d= -f2 | median) reader_lag_max=$(cat $B/node*/el.log | grep -oE 'reader_lag=[0-9]+' | cut -d= -f2 | sort -n | tail -1) reader_lag_warns=$(cat $B/node*/el.log | grep -c 'read view is falling behind\|falls behind\|reader lag') view_invalidated=$(cat $B/node*/el.log | grep -c 'read view is invalidated') el_sum_peak_g=$(grep -oE 'el_sum=[0-9.]+' $S/mem-$tag.txt | cut -d= -f2 | sort -n | tail -1) el_max_peak_g=$(grep -oE 'el_max=[0-9.]+' $S/mem-$tag.txt | cut -d= -f2 | sort -n | tail -1) val_sum_peak_g=$(grep -oE 'val_sum=[0-9.]+' $S/mem-$tag.txt | cut -d= -f2 | sort -n | tail -1) flood_peak_g=$(grep -oE 'flood=[0-9.]+' $S/mem-$tag.txt | cut -d= -f2 | sort -n | tail -1) two_roads_blocks=$(cat $B/node*/el.log | grep -c 'two roads: the execution ran beside the vote') two_roads_overlap_ms_median=$(cat $B/node*/el.log | grep 'two roads: the execution ran beside the vote' | grep -oE 'overlap_ms=[0-9]+' | cut -d= -f2 | median) exec_on_output_declined=$(cat $B/node*/el.log | grep -c "not executing on the parent's output") r1_collect_ms_median=$(cat $B/node*/v.log | sed -r 's/\x1b\[[0-9;]*m//g' | grep 'consensus_timing=leader' | grep -oE 'R1_collect=[0-9]+' | cut -d= -f2 | median) proposal_at_ms_median=$(cat $B/node*/v.log | sed -r 's/\x1b\[[0-9;]*m//g' | grep 'consensus_timing=leader' | grep -oE 'proposal=@[0-9]+' | tr -dc '0-9\n' | median) view_total_ms_median=$(cat $B/node*/v.log | sed -r 's/\x1b\[[0-9;]*m//g' | grep 'consensus_timing=leader' | grep -oE 'total=[0-9]+ms' | tr -dc '0-9\n' | median) import_exec_ms_median=$(cat $B/node*/el.log | grep 'handed to the engine as executed' | grep 'txs=1[0-9]\{5\}' | grep -oE 'exec_ms=[0-9]+' | cut -d= -f2 | median) import_total_ms_median=$(cat $B/node*/el.log | grep 'handed to the engine as executed' | grep 'txs=1[0-9]\{5\}' | grep -oE 'total_ms=[0-9]+' | cut -d= -f2 | median) import_senders_ms_median=$(cat $B/node*/el.log | grep 'handed to the engine as executed' | grep 'txs=1[0-9]\{5\}' | grep -oE 'senders_ms=[0-9]+' | cut -d= -f2 | median) import_convert_ms_median=$(cat $B/node*/el.log | grep 'handed to the engine as executed' | grep 'txs=1[0-9]\{5\}' | grep -oE 'convert_ms=[0-9]+' | cut -d= -f2 | median) import_groups_median=$(cat $B/node*/el.log | grep 'parallel import phases' | grep -oE 'groups=[0-9]+' | cut -d= -f2 | sort -rn | head -200 | median) imports_over_600ms=$(cat $B/node*/el.log | grep 'handed to the engine as executed' | grep 'txs=1[0-9]\{5\}' | grep -oE 'total_ms=[0-9]+' | cut -d= -f2 | awk '$1>600' | wc -l) min_avail_g=$(grep -oE 'MemAvailable:[0-9.]+' $S/mem-$tag.txt | cut -d: -f2 | sort -n | head -1)"
  low=$(grep -oE 'MemAvailable:[0-9.]+' $S/mem-$tag.txt 2>/dev/null | cut -d: -f2 | sort -n | head -1)
  awk -v l="${low:-999}" -v t="$tag" 'BEGIN { if (l+0 < 10) printf "MEMORY FLOOR %s: %.1f G free at its lowest\n", t, l }'
  for i in 0 1 2 3 4 5 6; do cp $B/node$i/el.log $B/bench-$tag/node$i-el.log; cp $B/node$i/v.log $B/bench-$tag/node$i-v.log; done
  python3 scripts/fleet7-phases.py $B > $B/bench-$tag/phases.txt 2>&1; python3 scripts/fleet7-windows.py $B/bench-$tag $S/mem-$tag.txt > $B/bench-$tag/windows.txt 2>&1; python3 scripts/fleet7-cycles.py $B/bench-$tag > $B/bench-$tag/cycles.txt 2>&1
  echo "$tag $(grep -E '^win1 ' $B/bench-$tag/round.txt | grep -oE 'tps= *[0-9,]+' | tr -d ' ') round_txs=$(grep -E '^win[123] ' $B/bench-$tag/round.txt | grep -oE 'txs=[0-9,]+' | cut -d= -f2 | tr -d , | paste -sd+ | bc) cycles_w1=$(awk '/^w1 /{print $4}' $B/bench-$tag/cycles.txt)"
  echo "$tag verify: $(F7_NODES=7 F7_HTTP_BASE=8700 timeout 60 python3 scripts/fleet7-verify.py --window 32 --settle 2 --json $B/bench-$tag/verify.json 2>&1 | tail -1)"
  for p in $(pgrep -f '/n4[2] node'; pgrep -f 'h2_validato[r]'; pgrep -f 'tx_floo[d]'); do kill -9 $p 2>/dev/null; done; sleep 2
}
leg() {
  if [ $(( $(date -u +%s) - CLAIMED_AT )) -gt 4500 ]; then echo "leg loop185$1 skipped: 75 minutes of the claim used"; return; fi
  local tag=$1; shift
  run loop185$tag F7_EL_EXTRA="--builder.interval 60 --builder.deadline 3" N42_FAST_TRANSFER=1 N42_FOLLOWER_DIRECT_IMPORT=1 F7_SENDER_CACHE_MULT=4 N42_TX_QUEUE_BATCH=1024 N42_TX_QUEUE_DRAINER=1 F7_FLOOD_WINDOW=6 N42_TX_INGEST_RECOVER_PARALLEL=12 F7_BLOCK_INTERVAL_MS=350 "$@"
}
C='N42_BUILDER_PULLER=1024 N42_TX_QUEUE_RUN=64 MALLOC_CONF=thp:always N42_FOLLOWER_PARALLEL=1 TOKIO_WORKER_THREADS=8 F7_FLOOD_ALG=ed25519 N42_ALTSIG_SENDER_CACHE=4194304 N42_ED25519_BATCH=128'
R='N42_PARALLEL_BUILD=1 N42_FOLLOWER_GRAFT=1 F7_STRAGGLER_GRACE_MS=600 RAYON_NUM_THREADS=16 N42_BUILD_ON_SEAL=1 F7_LEADER_TENURE=64 N42_QMDB_RETAIN_DEPTH=16 N42_QMDB_ENTRY_FILE=1'
A2="MALLOC_CONF=thp:always,oversize_threshold:0,dirty_decay_ms:2000,background_thread:true,prof:true,prof_active:true,lg_prof_interval:34,prof_prefix:$HP/heap"
D='N42_QMDB_READS=on N42_HASHED_TABLES=off F7_BLOCK_INTERVAL_MS=275'
leg H0a F7_BIN=$NEW $C $R $D $A2
echo "heap dumps: $(ls $HP 2>/dev/null | wc -l) files, $(du -sh $HP 2>/dev/null | cut -f1)"
cleanup
echo "released at $(date +%H:%M)"
echo ALLDONE
