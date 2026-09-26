#!/bin/bash
# Waits for the box, builds the native binaries, runs the flood's own tests, generates the replay set once, then
# runs loop261.
cd /home/n42/src/n42/n42-rs
n=0
while ls /data/blockchain/.box-claim-* >/dev/null 2>&1 || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 240 ] && { echo "gave up waiting after 4 h"; exit 1; }; done
echo "box free at $(date +%H:%M); builds:"
PKGS="-p n42 --bin n42 -p n42-h2-node --example h2_validator --example tx_flood --example h2_keygen --example send_tx"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo build -j16 --release --target-dir target/native $PKGS > target/fleet-runs/build-native-loop261.log 2>&1; then echo "NATIVE BUILD FAILED"; grep -E '^error' -A6 target/fleet-runs/build-native-loop261.log | head -40; echo ALLDONE; exit 1; fi
echo "built at $(date +%H:%M); flood tests:"
if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo test -j16 --release --target-dir target/native -p n42-h2-node --example tx_flood > target/fleet-runs/test-flood-loop261.log 2>&1; then echo "FLOOD TESTS FAILED"; grep -E '^test |panicked|error' target/fleet-runs/test-flood-loop261.log | head -20; echo ALLDONE; exit 1; fi
grep -E '^test result' target/fleet-runs/test-flood-loop261.log
SET=/data/n42-pregen/o900000
if [ ! -f $SET/o900000-w0000.flood ]; then
  echo "generating the replay set at $(date +%H:%M)"
  mkdir -p $SET
  if ! target/native/release/examples/tx_flood --pregen-out $SET --pregen-txs 192000000 --alg ed25519 --chain-id 1143 --senders 6000 --pertx 32000 --offset 900000 --gasprice 1000000000000000000000000 --gas 21000 --recipients 2000000 --rpcbatch 500 --conc 64 > target/fleet-runs/pregen-loop261.log 2>&1; then echo "PREGEN FAILED"; tail -5 target/fleet-runs/pregen-loop261.log; echo ALLDONE; exit 1; fi
  tail -2 target/fleet-runs/pregen-loop261.log; du -sh $SET
fi
echo "set ready at $(date +%H:%M)"
bash target/fleet-runs/run-loop261.sh
