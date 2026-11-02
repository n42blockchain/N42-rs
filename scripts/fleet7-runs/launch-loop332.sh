#!/bin/bash
# Waits for the box, builds the native binaries, runs the flood's own tests, generates the replay set once, then
# runs loop332.
cd /home/n42/src/n42/n42-rs
n=0
while ls /data/blockchain/.box-claim-* >/dev/null 2>&1 || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 240 ] && { echo "gave up waiting after 4 h"; exit 1; }; done
avail=$(df -BG /data | awk 'NR==2{gsub("G","",$4); print $4}'); [ "${avail:-0}" -ge 120 ] || { echo "/data has only ${avail}G free (the smallest leg needs 120G); nothing built"; echo ALLDONE; exit 1; }
echo "/data free ${avail}G at launch"
grep -rq N42_IMPORT_ONCE bin/n42/src crates/n42 || { echo "N42_IMPORT_ONCE is not in the tree: the shared-execution legs need the import-once registry; nothing built"; echo ALLDONE; exit 1; }
echo "box free at $(date +%H:%M); builds:"
PKGS="-p n42 --bin n42 -p n42-h2-node --example h2_validator --example tx_flood --example h2_keygen --example send_tx"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo build -j16 --release --target-dir target/native $PKGS > target/fleet-runs/build-native-loop332.log 2>&1; then echo "NATIVE BUILD FAILED"; grep -E '^error' -A6 target/fleet-runs/build-native-loop332.log | head -40; echo ALLDONE; exit 1; fi
grep -aq N42_IMPORT_ONCE target/native/release/n42 || { echo "the built n42 does not know N42_IMPORT_ONCE; no mapped leg can run"; echo ALLDONE; exit 1; }
echo "built at $(date +%H:%M); ingest/tx-types tests:"
if ! nice -n 19 cargo test -j16 --target-dir /data/n42-build/agents -p n42-tx-ingest -p n42-tx-types --lib > target/fleet-runs/test-shard-loop332.log 2>&1; then echo "SHARD TESTS FAILED"; grep -E '^error|^test .*FAILED|panicked' -A4 target/fleet-runs/test-shard-loop332.log | head -40; echo ALLDONE; exit 1; fi
grep -E '^test result' target/fleet-runs/test-shard-loop332.log
echo "flood tests:"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo test -j16 --release --target-dir target/native -p n42-h2-node --example tx_flood > target/fleet-runs/test-flood-loop332.log 2>&1; then echo "FLOOD TESTS FAILED"; grep -E '^test |panicked|error' target/fleet-runs/test-flood-loop332.log | head -20; echo ALLDONE; exit 1; fi
grep -E '^test result' target/fleet-runs/test-flood-loop332.log
swap_used=$(free -m | awk '/Swap:/{print $3}'); if [ "${swap_used:-0}" -gt 1024 ]; then echo "SWAP IN USE: ${swap_used} MiB -- the host rule is an empty swap (sudo swapoff -a); legs would be void (docs 10.50). Waiting up to 4 h for it to be emptied."; n=0; while [ "$(free -m | awk '/Swap:/{print $3}')" -gt 1024 ]; do sleep 120; n=$((n+1)); [ $n -gt 120 ] && { echo "swap still in use after 4 h; giving up"; echo ALLDONE; exit 1; }; done; fi
bash target/fleet-runs/run-loop332.sh
