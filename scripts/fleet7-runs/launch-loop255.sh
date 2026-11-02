#!/bin/bash
# Waits for the box, builds the node for this CPU into target/native, then runs loop255.
cd /home/n42/src/n42/n42-rs
n=0
while ls /data/blockchain/.box-claim-* >/dev/null 2>&1 || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 180 ] && { echo "gave up waiting after 3 h"; exit 1; }; done
echo "box free at $(date +%H:%M); native build:"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo build -j16 --release --target-dir target/native -p n42 --bin n42 -p n42-h2-node --example h2_validator --example tx_flood --example h2_keygen --example send_tx > target/fleet-runs/build-native-loop255.log 2>&1; then echo "NATIVE BUILD FAILED"; tail -5 target/fleet-runs/build-native-loop255.log; echo ALLDONE; exit 1; fi
echo "native built at $(date +%H:%M)"
bash target/fleet-runs/run-loop255.sh
