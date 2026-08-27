#!/usr/bin/env bash
# A HotStuff-2 devnet: one QMDB `n42` execution layer, four Rust validators,
# optionally one gov5 (Go) validator in place of the fourth.
#
#   scripts/devnet-fleet.sh <tag> <seconds> [--gov5] [--keep]
#
# Data lives under $N42_FLEET_DIR (default: /tmp/n42-fleet). Every process is
# left running afterwards so it can be inspected; the next run kills them.
# The devnet's dev validator secrets come from the genesis's seed
# (crates/chainspec/res/genesis/n42_devnet_validators.json); the gov5 member
# needs a built ../N42-gov5 checkout ($N42_GOV5) with
# docs/gov5-cancun-parent-beacon-root.patch applied.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
GOV5=$(cd "${N42_GOV5:-$REPO/../N42-gov5}" && pwd)
F=${N42_FLEET_DIR:-/tmp/n42-fleet}
TAG=${1:-run}; SECS=${2:-60}; shift 2 || true
WITH_GOV5=; KEEP=
for arg in "$@"; do case $arg in --gov5) WITH_GOV5=1;; --keep) KEEP=1;; esac; done
GENESIS=$REPO/crates/chainspec/res/genesis/n42_devnet.json
BIN=$REPO/target/debug
mkdir -p $F
[ -f $F/jwt.hex ] || openssl rand -hex 32 > $F/jwt.hex
if [ ! -d $F/keys ]; then
  mkdir -p $F/keys
  $BIN/examples/h2_keygen --count 4 --seed n42-devnet-validator --out-dir $F/keys > /dev/null
fi
pkill -f "^$BIN/examples/h2_validator" 2>/dev/null; pkill -f "^$BIN/n42 node" 2>/dev/null; pkill -f "^$GOV5/build/bin/n42 " 2>/dev/null; sleep 1
if [ -z "$KEEP" ]; then rm -rf $F/datadir $F/consensus-{0..3} $F/gov5; fi
RUST_LOG=${RUST_LOG_EL:-info} $BIN/n42 node --chain $GENESIS --datadir $F/datadir \
  --authrpc.port 18551 --authrpc.jwtsecret $F/jwt.hex --http --http.port 18545 --port 30313 \
  --disable-discovery --ipcdisable > $F/el-$TAG.log 2>&1 &
for _ in $(seq 1 60); do grep -aq "RPC auth server started" $F/el-$TAG.log 2>/dev/null && break; sleep 1; done
LAST=3; [ -n "$WITH_GOV5" ] && LAST=2
PEER=""; GOPEER=""
if [ -n "$WITH_GOV5" ]; then
  ADDR3=$(python3 -c "import json;print(json.load(open('$GENESIS'))['config']['hotstuff']['validators'][3]['address'])")
  if [ -z "$KEEP" ] || [ ! -d $F/gov5 ]; then
    $GOV5/build/bin/n42 init --chain private --profile n42 --data.dir $F/gov5 $GENESIS > $F/gov5-init-$TAG.log 2>&1
    mkdir -p $F/gov5/keystore && cp $F/keys/validator-3.key $F/gov5/keystore/bls_${ADDR3#0x}.key
    printf '%s' 4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e > $F/gov5/network-keys; chmod 600 $F/gov5/network-keys
  fi
  GOID=$($BIN/examples/h2_keygen --libp2p-peer-id $(cat $F/gov5/network-keys))
  GOPEER="--peer /ip4/127.0.0.1/tcp/30393/p2p/$GOID"
fi
for i in $(seq 0 $LAST); do
  # LATE_VALIDATOR=<index> LATE_DELAY=<secs> starts one Rust member late with
  # a fresh datadir, so it has to pull the chain from its peers by range.
  if [ "${LATE_VALIDATOR:-}" = "$i" ]; then
    # Its own execution layer, fresh, with no devp2p peers: the only way it
    # can get the chain is the pull this exercises.
    (sleep ${LATE_DELAY:-60}; rm -rf $F/consensus-$i $F/datadir-late
      RUST_LOG=${RUST_LOG_EL:-info} $BIN/n42 node --chain $GENESIS --datadir $F/datadir-late \
        --authrpc.port 18561 --authrpc.jwtsecret $F/jwt.hex --http --http.port 18555 --port 30323 \
        --disable-discovery --ipcdisable > $F/el-late-$TAG.log 2>&1 &
      for _ in $(seq 1 60); do grep -aq "RPC auth server started" $F/el-late-$TAG.log 2>/dev/null && break; sleep 1; done
      RUST_LOG=${RUST_LOG_V:-n42=debug} $BIN/examples/h2_validator --chain $GENESIS --index $i \
        --bls-key $(cat $F/keys/validator-$i.key) --el http://127.0.0.1:18561 --jwt $F/jwt.hex \
        --listen /ip4/127.0.0.1/tcp/$((19000+i)) --propose --datadir $F/consensus-$i $PEER ${DIALGO:-} \
        > $F/v$i-$TAG.log 2>&1) > /dev/null 2>&1 &
    continue
  fi
  RUST_LOG=${RUST_LOG_V:-n42=debug} $BIN/examples/h2_validator --chain $GENESIS --index $i \
    --bls-key $(cat $F/keys/validator-$i.key) --el http://127.0.0.1:18551 --jwt $F/jwt.hex \
    --listen /ip4/127.0.0.1/tcp/$((19000+i)) --propose --datadir $F/consensus-$i $PEER ${DIALGO:-} \
    > $F/v$i-$TAG.log 2>&1 &
  if [ $i = 0 ]; then
    for _ in $(seq 1 30); do grep -aq "node peer id" $F/v0-$TAG.log 2>/dev/null && break; sleep 1; done
    ID=$(grep -a "node peer id" $F/v0-$TAG.log | awk '{print $NF}')
    PEER="--peer /ip4/127.0.0.1/tcp/19000/p2p/$ID"
    if [ -n "$WITH_GOV5" ]; then
      # The Go member: standalone sync (it starts level with the chain and
      # follows by gossip), static peering onto node 0, mining as validator 3.
      # GOV5_DELAY=<secs> starts it late, so it has to catch up by asking the
      # Rust members for blocks (fetch-on-miss over block_by_hash).
      sleep ${GOV5_DELAY:-0}
      $GOV5/build/bin/n42 --chain private --profile n42 --data.dir $F/gov5 --mine --etherbase $ADDR3 \
        --http --http.port 28545 --port 30393 --p2p.no-discovery --p2p.min-sync-peers 0 \
        --p2p.peer /ip4/127.0.0.1/tcp/19000/p2p/$ID --log.level ${GOV5_LOG:-info} --log.console \
        > $F/gov5-$TAG.log 2>&1 &
      sleep 6
      DIALGO="$GOPEER"
    fi
  fi
done
sleep $SECS
echo "=== summary after ${SECS}s ($TAG) ==="
for i in $(seq 0 $LAST); do
  echo "v$i: commits=$(grep -ac '^COMMIT' $F/v$i-$TAG.log) bodies=$(grep -ac '^body' $F/v$i-$TAG.log) nobody=$(grep -ac 'NO BODY' $F/v$i-$TAG.log) timeouts=$(grep -ac 'WARN.*view timed out' $F/v$i-$TAG.log) views=$(grep -ac '^view' $F/v$i-$TAG.log)"
done
echo "EL: newPayload=$(grep -ac 'Received new payload' $F/el-$TAG.log) qmdb_roots=$(grep -ac 'strategy.*qmdb' $F/el-$TAG.log) warn=$(grep -ac 'WARN' $F/el-$TAG.log) err=$(grep -ac 'ERROR' $F/el-$TAG.log)"
height() { curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' http://127.0.0.1:$1 | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null; }
hash_at() { curl -s -X POST -H 'content-type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x$(printf %x $2)\",false]}" http://127.0.0.1:$1 | python3 -c "import sys,json;b=json.load(sys.stdin).get('result');print(b['hash'] if b else None)" 2>/dev/null; }
H1=$(height 18545); echo "reth height: $H1"
if [ -n "${LATE_VALIDATOR:-}" ]; then
  HL=$(height 18555); echo "late member: el height=$HL $(grep -a '^syncing\|^synced' $F/v$LATE_VALIDATOR-$TAG.log | tr '\n' ' ') commits=$(grep -ac '^COMMIT' $F/v$LATE_VALIDATOR-$TAG.log)"
  echo "block $HL: main=$(hash_at 18545 $HL) late=$(hash_at 18555 $HL)"
fi
if [ -n "$WITH_GOV5" ]; then
  GL=$F/gov5/log/n42.log
  echo "gov5: sealed=$(grep -ac 'sealed new block' $GL) committed=$(grep -ac 'block committed' $GL) errors=$(grep -ac '"level":"error"' $GL) height=$(height 28545)"
  H2=$(height 28545); M=$(( ${H2:-0} < ${H1:-0} ? ${H2:-0} : ${H1:-0} ))
  echo "block $M: reth=$(hash_at 18545 $M) gov5=$(hash_at 28545 $M)"
fi
