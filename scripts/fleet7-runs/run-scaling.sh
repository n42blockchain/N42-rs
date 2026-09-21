#!/usr/bin/env bash
# The per-node core scaling of the parallel phases, which plan v3 section 5 names as the rest of the way to 1M
# ("the parallel phases scale with cores, which a node on its own 64-core machine has and a node on this shared box
# does not"). Same block through the two benches at 8, 16, 32 and 64 threads: the leader's execution and graft
# (bench_build_run) and a follower's import (bench_follower_import). One process, so it needs the box to itself but
# only for a few minutes; it waits for loop179 first, claims, runs, releases.
cd /home/n42/src/n42/n42-rs
S=/home/n42/src/n42/n42-rs/target/fleet-runs
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
until grep -q ALLDONE $S/run-loop179.out 2>/dev/null; do sleep 60; done
echo "loop179 done; waiting for a quiet box from $(date +%H:%M)"
WAITED_FROM=$(date -u +%s)
good() { local cpus; cpus=$(nproc)
  [ "$(pgrep -fc 'bin/n42-[a-z]+ --chai[n]')" = "0" ] && [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" = "0" ] \
    && [ "$(pgrep -fc 'n4[2] node')" = "0" ] && [ "$(pgrep -fc 'n42-dat[c]')" = "0" ] && [ "$(pgrep -fc 'eth-el-frame[d]')" = "0" ] \
    && [ "$(pgrep -fc 'txfloo[d]')" = "0" ] && [ "$(free -g | awk '/Mem:/{print $7}')" -ge 60 ] \
    && [ "$(awk '{printf "%d", $1}' /proc/loadavg)" -lt $(( cpus / 4 )) ]; }
theirs_claim() { local f n=""; for f in /data/blockchain/.box-claim-* /data/blockchain/wr-logs/.box-claim-*; do [ -e "$f" ] || continue; case "$f" in *box-claim-rust) continue;; esac; v=$(tr -c '0-9\n' ' ' < "$f" | tr -s ' ' '\n' | grep -E '^[0-9]+$' | sort -n | tail -1); [ -z "$v" ] && v=9999999999; n="$n $v"; done; echo $n | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -n | tail -1; }
quiet() { local n=0; while [ $n -lt 3 ]; do [ -z "$(theirs_claim)" ] || return 1; good || return 1; n=$((n+1)); [ $n -lt 3 ] && sleep 20; done; return 0; }
while true; do
  until quiet; do sleep 30; done
  mine=$(date -u +%s); echo "$mine" | tee $CLAIM > $CLAIM2
  sleep $((15 + RANDOM % 20))
  theirs=$(theirs_claim)
  if good && { [ -z "$theirs" ] || [ "$theirs" -gt "$mine" ]; }; then break; fi
  rm -f $CLAIM $CLAIM2; echo "stood down at $(date +%H:%M)"; sleep 60
done
echo "claimed at $(date +%H:%M): $(nproc) CPUs, $(free -g | awk '/Mem:/{print $7}')G free"
for t in 8 16 32 64; do
  echo "== $t threads"
  RAYON_NUM_THREADS=$t N42_PARALLEL_BUILD_THREADS=$t timeout -k 30 900 nice -n 5 systemd-run --user --scope -q -p MemoryMax=40G -p MemorySwapMax=0 \
    cargo test -j8 --target-dir target/deferred --release -p n42-engine-types --lib bench_build_run -- --ignored --nocapture 2>&1 |
    grep -E '^round [0-9]: streamed|^round [0-9]: serial' | sed "s/^/  [$t] /"
  RAYON_NUM_THREADS=$t N42_PARALLEL_BUILD_THREADS=$t timeout -k 30 900 nice -n 5 systemd-run --user --scope -q -p MemoryMax=40G -p MemorySwapMax=0 \
    cargo test -j8 --target-dir target/deferred --release -p n42-engine-types --lib bench_follower_import -- --ignored --nocapture 2>&1 |
    grep -E 'components\+graft|senders\+graft' | sed "s/^/  [$t] /"
done
cleanup
echo "released at $(date +%H:%M)"
echo ALLDONE
