#!/bin/bash
# loop348 (E=1 with 7, 21 and 99 keys, docs/E1_MANY_KEYS.md). usage: launch-loop348.sh <a|b|c>. Launch: setsid nohup bash scripts/fleet7-runs/launch-loop348.sh a > target/fleet-runs/loop348a.out 2>&1 &
# Waits for the box, checks the tree, builds the native binaries, runs the flood's own tests, then runs the stage.
cd /data/n42-build/wt338
STAGE=${1:-a}; case $STAGE in a|b|c|p) ;; *) echo "usage: launch-loop348.sh <a|b|c|p>"; exit 2;; esac
n=0
while ls /data/blockchain/.box-claim-* >/dev/null 2>&1 || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 240 ] && { echo "gave up waiting after 4 h"; exit 1; }; done
# claim 2 runs the binary with N42_LEADER_LAYERS: the commit must be in and nothing in crates/ bin/ uncommitted
grep -rq N42_LEADER_LAYERS crates/n42/engine-types/src || { echo "N42_LEADER_LAYERS is not in the tree; nothing built"; echo ALLDONE; exit 1; }
if [ -n "$(git status --porcelain crates bin | grep -v pycache)" ]; then echo "uncommitted changes in crates/ or bin/; nothing built"; echo ALLDONE; exit 1; fi
for f in crates/chainspec/res/genesis/n42_fleet7_bench_v21.json crates/chainspec/res/genesis/n42_fleet7_bench_v99.json scripts/fleet7-runs/run-loop348.sh scripts/fleet7-runs/manykeys348.py scripts/fleet7-runs/valsample348.py; do [ -r $f ] || { echo "$f is not in the tree (git pull in this worktree); nothing built"; echo ALLDONE; exit 1; }; done
grep -q f7_fleet_cpus scripts/fleet7-env.sh || { echo "scripts/fleet7-env.sh lacks f7_fleet_cpus; nothing built"; echo ALLDONE; exit 1; }
avail=$(df -BG /data | awk 'NR==2{gsub("G","",$4); print $4}'); [ "${avail:-0}" -ge 120 ] || { echo "/data has only ${avail}G free (the smallest leg needs 120G); nothing built"; echo ALLDONE; exit 1; }
echo "/data free ${avail}G at launch"
grep -rq N42_IMPORT_ONCE bin/n42/src crates/n42 || { echo "N42_IMPORT_ONCE is not in the tree: the shared-execution legs need the import-once registry; nothing built"; echo ALLDONE; exit 1; }
echo "tree at $(git rev-parse --short HEAD) ($(git log -1 --format=%s | cut -c1-80)); box free at $(date +%H:%M); builds:"
PKGS="-p n42 --bin n42 -p n42-h2-node --example h2_validator --example tx_flood --example h2_keygen --example send_tx"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo build -j16 --release --target-dir target/native $PKGS > target/fleet-runs/build-native-loop348.log 2>&1; then echo "NATIVE BUILD FAILED"; grep -E '^error' -A6 target/fleet-runs/build-native-loop348.log | head -40; echo ALLDONE; exit 1; fi
grep -aq N42_IMPORT_ONCE target/native/release/n42 || { echo "the built n42 does not know N42_IMPORT_ONCE; no mapped leg can run"; echo ALLDONE; exit 1; }
echo "built at $(date +%H:%M); ingest/tx-types tests:"
if ! nice -n 19 cargo test -j16 --target-dir /data/n42-build/agents -p n42-tx-ingest -p n42-tx-types --lib > target/fleet-runs/test-shard-loop348.log 2>&1; then echo "SHARD TESTS FAILED"; grep -E '^error|^test .*FAILED|panicked' -A4 target/fleet-runs/test-shard-loop348.log | head -40; echo ALLDONE; exit 1; fi
grep -E '^test result' target/fleet-runs/test-shard-loop348.log
echo "flood tests:"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo test -j16 --release --target-dir target/native -p n42-h2-node --example tx_flood > target/fleet-runs/test-flood-loop348.log 2>&1; then echo "FLOOD TESTS FAILED"; grep -E '^test |panicked|error' target/fleet-runs/test-flood-loop348.log | head -20; echo ALLDONE; exit 1; fi
grep -E '^test result' target/fleet-runs/test-flood-loop348.log
swap_used=$(free -m | awk '/Swap:/{print $3}'); if [ "${swap_used:-0}" -gt 1024 ]; then echo "SWAP IN USE: ${swap_used} MiB -- the host rule is an empty swap (sudo swapoff -a); legs would be void (docs 10.50). Waiting up to 4 h for it to be emptied."; n=0; while [ "$(free -m | awk '/Swap:/{print $3}')" -gt 1024 ]; do sleep 120; n=$((n+1)); [ $n -gt 120 ] && { echo "swap still in use after 4 h; giving up"; echo ALLDONE; exit 1; }; done; fi
bash scripts/fleet7-runs/run-loop348.sh $STAGE
