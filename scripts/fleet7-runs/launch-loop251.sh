#!/bin/bash
# Waits for gov5 (or anyone) to release the box, then runs the tx-ingest tests and loop251.
cd /home/n42/src/n42/n42-rs
n=0
while ls /data/blockchain/.box-claim-* >/dev/null 2>&1 || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 180 ] && { echo "gave up waiting after 3 h"; exit 1; }; done
echo "box free at $(date +%H:%M); tx-ingest tests:"
nice -n 19 cargo build -p n42-h2-node --example h2_validator --target-dir /data/n42-build/agents -j8 2>&1 | grep -E '^test result|^error|FAILED|panicked' | head -8
bash target/fleet-runs/run-loop251.sh
