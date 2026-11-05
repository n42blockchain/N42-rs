#!/usr/bin/env bash
# One gated MobileAnchor devnet round with the phone surface, the packet sidecar and
# gov5's device harness, evidence written under $EVIDENCE_ROOT/<tag>:
#
#   scripts/devnet-mobileanchor.sh <tag> [--gov5] [--txload]
#
#   --gov5    three Rust validators and the gov5 member (validator 3) instead of four Rust ones
#   --txload  two send_tx senders at 2 tx/s each for the whole round
#
# What it does, in order (every step is logged with a UTC timestamp to run.log):
#   1. claims the box through /data/blockchain/gov5-work/box-gate.sh (BOX_ME=rust; FIFO,
#      wr-logs/BOX-CLAIM-PROTOCOL.md) and releases it on exit, whatever happens;
#   2. starts scripts/devnet-fleet.sh <tag> $SECS [--gov5] with MOBILEVERIFY=1 and PACKETD
#      (packetd beside validator 0) on $DEVNET_GENESIS, fleet dir $EVIDENCE/fleet, stdout in
#      fleet.out;
#   3. --txload: two send_tx senders (send_tx.out);
#   4. runs gov5's cmd/mobileverify-device against validator 1 (device.out), then dumps the
#      certificates of the blocks it verified;
#   5. after the fleet summary: devnet-header-roots.py over the Rust chain (hdrroots.out) and,
#      with --gov5, over gov5's chain too (hdrroots-gov5.out); per-block hashes on both
#      chains (hashes.out, first difference); the gov5 member's errors and warnings
#      (gov5-errors.out); per-block packet sources (packets.out: sidecar file, v1 relay
#      cache, gov5 cache, by leader);
#   6. stops every process the round started (anchored pkill on our own binary paths).
#
# Before step 1 the round takes the Rust streams' round lock
# ($ROUND_LOCK, /data/n42-build/audit-notes/devnet/.round.lock) and waits until the
# devnet ports are free and no other fleet's validators or nodes run: box-gate separates
# lanes with different BOX_ME names, not two rounds of the same lane, and on 2026-11-04 two
# such rounds shared the ports and each read the other's execution layer (a "genesis
# mismatch" that was no mismatch). A caller that already holds the lock through flock(1)
# is recognised by FLOCKER and not locked again.
#
# Environment (defaults in brackets):
#   SECS [360]  DEVNET_GENESIS [crates/chainspec/res/genesis/n42_devnet_mobileanchor.json]
#   DEVNET_BIN [/data/n42-build/mobile-target/debug]
#   PACKETD [/data/n42-build/gov5-wt-packetd/mobileverify-packetd]
#   N42_GOV5 [/data/n42-build/gov5-wt-mvdev]  (gov5 node at $N42_GOV5/build/bin/n42)
#   DEVICE [$N42_GOV5/build/mobileverify-device]  DEVICE_ARGS [-genesis $DEVNET_GENESIS]
#   EVIDENCE_ROOT [/data/n42-build/audit-notes/devnet]
#   TX_KEYS / TX_TO: senders' keys and recipients [anvil accounts 4,5 -> 6,7]
#   TX_DELAY [0]: seconds before the senders start (a chain whose senders are funded
#     only by the block reward)
#   NO_BOX_GATE=1 skips the claim (only when the caller already holds the box)
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:?usage: devnet-mobileanchor.sh <tag> [--gov5] [--txload]}; shift
WITH_GOV5=; TXLOAD=
for arg in "$@"; do case $arg in --gov5) WITH_GOV5=1;; --txload) TXLOAD=1;; *) echo "unknown arg $arg" >&2; exit 2;; esac; done
SECS=${SECS:-360}
GENESIS=${DEVNET_GENESIS:-$REPO/crates/chainspec/res/genesis/n42_devnet_mobileanchor.json}
BIN=${DEVNET_BIN:-/data/n42-build/mobile-target/debug}
PACKETD=${PACKETD:-/data/n42-build/gov5-wt-packetd/mobileverify-packetd}
GOV5=${N42_GOV5:-/data/n42-build/gov5-wt-mvdev}
DEVICE=${DEVICE:-$GOV5/build/mobileverify-device}
DEVICE_ARGS=${DEVICE_ARGS:--genesis $GENESIS}
EV=${EVIDENCE_ROOT:-/data/n42-build/audit-notes/devnet}/$TAG
F=$EV/fleet
CHAIN_ID=$(python3 -c "import json;print(json.load(open('$GENESIS'))['config']['chainId'])")
read -r -a KEYS <<< "${TX_KEYS:-0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a 0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba}"
read -r -a TOS <<< "${TX_TO:-0x976EA74026E726554dB657fA54763abd0C3a0aa9 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955}"
mkdir -p "$EV"
LOG=$EV/run.log
say() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG"; }
j() { curl -s -m 5 "$@"; }
height() { curl -s -m 5 -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "http://127.0.0.1:$1" \
  | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null; }

stop_round() {
  pkill -f "^$BIN/examples/send_tx " 2>/dev/null
  pkill -f "^$DEVICE " 2>/dev/null
  pkill -f "^$PACKETD " 2>/dev/null
  pkill -f "^$BIN/examples/h2_validator --chain $GENESIS " 2>/dev/null
  pkill -f "^$BIN/n42 node --chain $GENESIS " 2>/dev/null
  pkill -f "^$GOV5/build/bin/n42 --chain private --profile n42 --data.dir $F/gov5 " 2>/dev/null
  pkill -f "^bash $REPO/scripts/devnet-fleet.sh $TAG " 2>/dev/null
  sleep 3
  pkill -9 -f "^$BIN/examples/h2_validator --chain $GENESIS " 2>/dev/null
  pkill -9 -f "^$BIN/n42 node --chain $GENESIS " 2>/dev/null
  pkill -9 -f "^$GOV5/build/bin/n42 --chain private --profile n42 --data.dir $F/gov5 " 2>/dev/null
}

ROUND_LOCK=${ROUND_LOCK:-/data/n42-build/audit-notes/devnet/.round.lock}
if [ "${FLOCKER:-}" != "$ROUND_LOCK" ]; then
  exec 9>"$ROUND_LOCK"
  flock -n 9 || { say "round lock held by another round, waiting"; flock 9; }
  say "round lock taken"
fi
# The ports every round binds (two execution layers, four validators, two phone surfaces).
PORTS="18545 18551 19000 19001 19002 19003 21010 21011 28545 30313"
busy_ports() { ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | /usr/bin/grep -xF -f <(printf '%s\n' $PORTS) | sort -un | tr '\n' ' '; }
foreign_fleet() { ps -eo args | /usr/bin/grep -E '^[^ ]*/(examples/h2_validator|n42 node) --chain |^[^ ]*/n42 --chain private ' | /usr/bin/grep -vE "^$BIN/|^$GOV5/build/bin/n42 --chain private --profile n42 --data.dir $F/gov5 " | head -3; }
waited=0
while :; do
  bp=$(busy_ports); ff=$(foreign_fleet)
  [ -z "$bp" ] && [ -z "$ff" ] && break
  [ $((waited % 600)) -eq 0 ] && say "waiting: ports in use [$bp] foreign fleet [${ff:0:160}]"
  sleep 30; waited=$((waited + 30))
done
[ "$waited" -gt 0 ] && say "ports free after ${waited}s"

if [ "${NO_BOX_GATE:-}" != 1 ]; then
  export BOX_ME=rust BOX_LOG=$LOG
  # box-gate.sh reads optional variables unset; it runs without -u.
  set +u
  # shellcheck disable=SC1091
  . /data/blockchain/gov5-work/box-gate.sh
  say "box request filed"
  box_acquire
  set -u
  say "box claimed"
  trap 'stop_round; box_drop_claim; box_drop_request; say "box released"' EXIT
  trap 'exit 130' INT TERM
else
  trap 'stop_round' EXIT
fi

# A lane that runs a fleet without the gate still holds the round's ports. Starting anyway
# points packetd, send_tx and the device at its node (mv4h4b): refuse instead.
BUSY=$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | /usr/bin/grep -xE '1900[0-6]|18545|18551|28545|30313|2101[0-9]' | sort -u | tr '\n' ' ')
if [ -n "$BUSY" ]; then
  say "ABORT: ports in use before the fleet starts: $BUSY"
  exit 3
fi

rm -rf "$F"; mkdir -p "$F"
FLEET_FLAGS=; [ -n "$WITH_GOV5" ] && FLEET_FLAGS=--gov5
N42_FLEET_DIR=$F DEVNET_GENESIS=$GENESIS DEVNET_BIN=$BIN MOBILEVERIFY=1 PACKETD=$PACKETD N42_GOV5=$GOV5 \
  bash "$REPO/scripts/devnet-fleet.sh" "$TAG" "$SECS" $FLEET_FLAGS > "$EV/fleet.out" 2>&1 &
FLEET_PID=$!
T0=$(date +%s)
for i in 0 1; do
  for _ in $(seq 1 90); do j -f "http://127.0.0.1:2101$i/mobileverify/health" >/dev/null && break; sleep 1; done
  say "v$i health: $(j http://127.0.0.1:2101$i/mobileverify/health)"
done
if [ -n "$WITH_GOV5" ]; then
  say "gov5 init: $(/usr/bin/grep -a 'genesis' "$F/gov5-init-$TAG.log" | tail -1 | cut -c1-200)"
  say "genesis: reth=$(j -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' http://127.0.0.1:18545 | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["hash"])' 2>/dev/null) gov5=$(j -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' http://127.0.0.1:28545 | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["hash"])' 2>/dev/null)"
  # A member on another genesis never peers ("wrong fork digest version"): say so loudly.
  tail -1 "$LOG" | awk '{split($3,a,"=");split($4,b,"=");if(a[2]!=b[2])print "GENESIS MISMATCH: the gov5 member cannot join"}' | tee -a "$LOG"
fi

if [ -n "$TXLOAD" ]; then
  say "tx load: two senders at 2 tx/s after ${TX_DELAY:-0} s"
  sleep "${TX_DELAY:-0}"
  for k in 0 1; do
    "$BIN/examples/send_tx" --rpc http://127.0.0.1:18545 --key "${KEYS[$k]}" --to "${TOS[$k]}" \
      --chain-id "$CHAIN_ID" --rate 2 --seconds $((SECS - 30 - ${TX_DELAY:-0})) >> "$EV/send_tx.out" 2>&1 &
  done
fi

sleep 20
say "packetd so far: $(/usr/bin/grep -ac 'packetd: packet ' "$F/packetd-$TAG.log") packets; $(/usr/bin/grep -a 'EROR\|WARN' "$F/packetd-$TAG.log" | head -4)"
for i in 1 0; do say "latest v$i: $(j http://127.0.0.1:2101$i/mobileverify/latest)"; done

# shellcheck disable=SC2086
# Bounded: a device waiting on a chain that never certifies held the box 18 h (mv4h4b).
timeout "$SECS" "$DEVICE" -mv http://127.0.0.1:21011 -rpc http://127.0.0.1:18545 $DEVICE_ARGS -devices 2 -blocks 20 \
  -commit-wait 150s -settle 30s -skip-no-packet -packet-wait 3s > "$EV/device.out" 2>&1
say "device rc=$?: $(/usr/bin/grep -a SUMMARY "$EV/device.out")"
for n in $(/usr/bin/grep -a '^.* block [0-9]* certs=' "$EV/device.out" | sed 's/.* block \([0-9]*\) certs=.*/\1/'); do
  h=$(j -X POST -H 'content-type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x$(printf %x "$n")\",false]}" http://127.0.0.1:18545 | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["hash"])' 2>/dev/null)
  say "cert block $n $h: $(j "http://127.0.0.1:21011/mobileverify/cert/$h")"
done
for i in 0 1; do say "health v$i after device: $(j http://127.0.0.1:2101$i/mobileverify/health)"; done

wait $FLEET_PID
say "fleet summary: $(tr '\n' ' ' < "$EV/fleet.out")"
H=$(height 18545)
python3 "$REPO/scripts/devnet-header-roots.py" --rpc http://127.0.0.1:18545 --genesis "$GENESIS" --logs "$F" --tag "$TAG" --to "$H" > "$EV/hdrroots.out" 2>&1
say "header roots (rust chain): $(tail -2 "$EV/hdrroots.out" | tr '\n' ' ')"

if [ -n "$WITH_GOV5" ]; then
  G=$(height 28545)
  python3 "$REPO/scripts/devnet-header-roots.py" --rpc http://127.0.0.1:28545 --genesis "$GENESIS" --logs "$F" --tag "$TAG" --to "${G:-0}" > "$EV/hdrroots-gov5.out" 2>&1
  say "header roots (gov5 chain, height ${G:-?}): $(tail -2 "$EV/hdrroots-gov5.out" | tr '\n' ' ')"
  python3 - "$H" "${G:-0}" > "$EV/hashes.out" <<'EOF'
import json, sys, urllib.request
def blk(port, n):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":[hex(n),False]}).encode()
    r = json.load(urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}", body, {"content-type":"application/json"}), timeout=10))
    return r.get("result")
h, g = int(sys.argv[1]), int(sys.argv[2])
first = None; same = 0
for n in range(0, min(h, g) + 1):
    a, b = blk(18545, n), blk(28545, n)
    if a and b and a["hash"] == b["hash"]:
        same += 1; continue
    print(f"block {n}: reth {a and a['hash']} miner {a and a['miner']} txs {a and len(a['transactions'])} stateRoot {a and a['stateRoot']} receiptsRoot {a and a['receiptsRoot']} gasUsed {a and a['gasUsed']}")
    print(f"block {n}: gov5 {b and b['hash']} miner {b and b['miner']} txs {b and len(b['transactions'])} stateRoot {b and b['stateRoot']} receiptsRoot {b and b['receiptsRoot']} gasUsed {b and b['gasUsed']}")
    if first is None: first = n
print(f"heights reth={h} gov5={g} same={same} first-difference={first}")
EOF
  say "hashes: $(tail -1 "$EV/hashes.out")"
  GL=$F/gov5/log/n42.log
  /usr/bin/grep -a '"level":"\(error\|warn\|eror\|crit\)"' "$GL" > "$EV/gov5-errors.out" 2>/dev/null
  say "gov5: errors=$(/usr/bin/grep -ac '"level":"error"' "$GL") warns=$(/usr/bin/grep -ac '"level":"warn"' "$GL") first error: $(/usr/bin/grep -a -m1 '"level":"error"' "$GL" | cut -c1-400)"
fi

# Where each block's packet came from: the sidecar's output, validator 1's relay cache
# (the device's node), and gov5's own cache.
python3 - "$H" "$GENESIS" "$F" "${WITH_GOV5:-0}" > "$EV/packets.out" <<'EOF'
import json, os, sys, urllib.request, urllib.error
h, gen, F, gov5 = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4] == "1"
vals = {v["address"].lower(): i for i, v in enumerate(json.load(open(gen))["config"]["hotstuff"]["validators"])}
def blk(n):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":[hex(n),False]}).encode()
    return json.load(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:18545", body, {"content-type":"application/json"}), timeout=10))["result"]
def has(port, hsh):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/mobileverify/packet/{hsh}", timeout=5).read(); return True
    except urllib.error.HTTPError: return False
    except Exception: return None
agg = {}
for n in range(1, h + 1):
    b = blk(n); leader = vals.get(b["miner"].lower())
    side = os.path.exists(os.path.join(F, "packets", b["hash"] + ".bin"))
    v1 = has(21011, b["hash"]); g = has(21020, b["hash"]) if gov5 else None
    txs = len(b["transactions"])
    print(f"block {n} leader v{leader} txs {txs} sidecar {side} v1 {v1} gov5 {g}")
    k = (f"v{leader}", txs > 0, side, v1, g); agg[k] = agg.get(k, 0) + 1
for k, c in sorted(agg.items(), key=str):
    print(f"leader {k[0]} txs>0 {k[1]} sidecar {k[2]} v1-cache {k[3]} gov5-cache {k[4]}: {c} blocks")
EOF
say "packets: $(/usr/bin/grep -a '^leader' "$EV/packets.out" | tr '\n' ';')"
say "packetd: $(/usr/bin/grep -ac 'packetd: packet ' "$F/packetd-$TAG.log") packets, $(/usr/bin/grep -ac 'EROR\|WARN' "$F/packetd-$TAG.log") warn/error lines"
[ -n "$TXLOAD" ] && say "send_tx: $(/usr/bin/grep -ac nonce "$EV/send_tx.out") sent, $(/usr/bin/grep -aci 'error\|reject' "$EV/send_tx.out") error lines"
