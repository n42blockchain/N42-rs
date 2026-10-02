#!/bin/bash
# Waits for the box, builds the native binaries, runs the flood's own tests, generates the replay set once, then
# runs loop306.
cd /home/n42/src/n42/n42-rs
n=0
while ls /data/blockchain/.box-claim-* >/dev/null 2>&1 || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 240 ] && { echo "gave up waiting after 4 h"; exit 1; }; done
echo "box free at $(date +%H:%M); builds:"
PKGS="-p n42 --bin n42 -p n42-h2-node --example h2_validator --example tx_flood --example h2_keygen --example send_tx"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo build -j16 --release --target-dir target/native $PKGS > target/fleet-runs/build-native-loop306.log 2>&1; then echo "NATIVE BUILD FAILED"; grep -E '^error' -A6 target/fleet-runs/build-native-loop306.log | head -40; echo ALLDONE; exit 1; fi
echo "built at $(date +%H:%M); ingest/tx-types tests:"
if ! nice -n 19 cargo test -j16 --target-dir /data/n42-build/agents -p n42-tx-ingest -p n42-tx-types --lib > target/fleet-runs/test-shard-loop306.log 2>&1; then echo "SHARD TESTS FAILED"; grep -E '^error|^test .*FAILED|panicked' -A4 target/fleet-runs/test-shard-loop306.log | head -40; echo ALLDONE; exit 1; fi
grep -E '^test result' target/fleet-runs/test-shard-loop306.log
echo "flood tests:"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo test -j16 --release --target-dir target/native -p n42-h2-node --example tx_flood > target/fleet-runs/test-flood-loop306.log 2>&1; then echo "FLOOD TESTS FAILED"; grep -E '^test |panicked|error' target/fleet-runs/test-flood-loop306.log | head -20; echo ALLDONE; exit 1; fi
grep -E '^test result' target/fleet-runs/test-flood-loop306.log
swap_used=$(free -m | awk '/Swap:/{print $3}'); if [ "${swap_used:-0}" -gt 1024 ]; then echo "SWAP IN USE: ${swap_used} MiB -- the host rule is an empty swap (sudo swapoff -a); legs would be void (docs 10.50). Waiting up to 4 h for it to be emptied."; n=0; while [ "$(free -m | awk '/Swap:/{print $3}')" -gt 1024 ]; do sleep 120; n=$((n+1)); [ $n -gt 120 ] && { echo "swap still in use after 4 h; giving up"; echo ALLDONE; exit 1; }; done; fi
bash target/fleet-runs/run-loop306.sh
