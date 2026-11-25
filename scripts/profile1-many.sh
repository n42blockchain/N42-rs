#!/usr/bin/env bash
# A profile-1 round with many validators sharing few execution layers (gate 5 of
# docs/MIXED_PRODUCTION_STANDARD_V1_RC.md: >= 100 validators, several per
# execution layer). P1M_N `h2_validator`s over P1M_E `n42 node` execution layers;
# validator i drives layer i mod P1M_E. See docs/PROFILE1_100_VALIDATORS.md.
#
#   scripts/profile1-many.sh genesis <out> | init | up | status | timing | down
#
#   genesis <out>   P1M_GENESIS_BASE (the V1 genesis_8s.json) with its validator set
#                   replaced by P1M_N validators; nothing else changes. Validators 0-3
#                   are V1's (same keys, same addresses); validator i's BLS secret is
#                   0x00 || sha256("n42-profile1-test-validator-<i>")[1:] (TEST ONLY,
#                   the derivation of scripts/profile1-round.sh) and, from 4 on, its
#                   address sha256("n42-profile1-test-validator-address-<i>")[0:20].
#   init            copies P1M_GENESIS with "timestamp" = now, inits every layer
#   up              starts the layers (N42_IMPORT_ONCE=1: one import per block per
#                   layer however many keys bring it), then the validators, every
#                   validator dialling every other (full mesh)
#   status          per layer height and head; per validator led / timeouts / refusals
#   timing          per view led: build -> PrepareQC -> commit on the leader (ms)
#   down            SIGTERM validators, then layers (only this run dir's processes)
#
#   P1M_N=100 P1M_E=4 P1M_DIR=/data/n42-build/p1-many P1M_BIN=<release dir>
#   P1M_GENESIS=<file> (default $P1M_DIR/genesis-<N>.json, written by `genesis`)
#   P1M_P2P_BASE=31000  validator i listens on base+i (body channel base+1000+i)
#   P1M_EL_BASE=22000   layer e: HTTP base+e, authrpc base+200+e, devp2p base+300+e
#   P1M_CPUS            taskset list (default skips the faulty core 99/227)
#   P1M_VAL_THREADS=2   tokio workers per validator (--worker-threads)
#
# Every other N42_* variable is unset (profile 1 refuses the overrides); the ports
# stay off gov5's mixed-round ranges (307xx, 201xx, 21140+, 6210+).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
P1M_N=${P1M_N:-100}
P1M_E=${P1M_E:-4}
P1M_DIR=${P1M_DIR:-/data/n42-build/p1-many}
P1M_BIN=${P1M_BIN:-/data/n42-build/target-wt-gate5/release}
P1M_GENESIS_BASE=${P1M_GENESIS_BASE:-$REPO/crates/n42/qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json}
P1M_GENESIS=${P1M_GENESIS:-$P1M_DIR/genesis-$P1M_N.json}
P1M_P2P_BASE=${P1M_P2P_BASE:-31000}
P1M_EL_BASE=${P1M_EL_BASE:-22000}
P1M_CPUS=${P1M_CPUS:-0-98,100-226,228-255}
P1M_VAL_THREADS=${P1M_VAL_THREADS:-2}
P1M_RUST_LOG=${P1M_RUST_LOG:-info,n42=debug}
EL=$P1M_BIN/n42
VAL=$P1M_BIN/examples/h2_validator
KEYGEN=$P1M_BIN/examples/h2_keygen
G=$P1M_DIR/genesis.json
for v in $(compgen -e | /usr/bin/grep '^N42_'); do unset "$v"; done

p2p_port() { echo $((P1M_P2P_BASE + $1)); }
http_port() { echo $((P1M_EL_BASE + $1)); }
auth_port() { echo $((P1M_EL_BASE + 200 + $1)); }
devp2p_port() { echo $((P1M_EL_BASE + 300 + $1)); }
vdir() { echo "$P1M_DIR/v$1"; }
edir() { echo "$P1M_DIR/el$1"; }
layer_of() { echo $(($1 % P1M_E)); }
maddr() { echo "/ip4/127.0.0.1/tcp/$(p2p_port "$1")/p2p/$(cat "$(vdir "$1")/peer-id")"; }
# A process this run dir started; the bracket keeps pgrep from matching a shell.
val_re() { echo "^[${P1M_BIN:0:1}]${P1M_BIN:1}/examples/h2_validator --datadir $P1M_DIR/v[0-9]+/"; }
el_re() { echo "^[${P1M_BIN:0:1}]${P1M_BIN:1}/n42 node --datadir $P1M_DIR/el[0-9]+/"; }
port_busy() { ss -Hltn "sport = :$1" 2>/dev/null | /usr/bin/grep -q .; }
strip() { sed 's/\x1b\[[0-9;]*m//g' "$@"; }
rpc() { curl -s -m 5 -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "http://127.0.0.1:$1"; }
secret_of() { python3 -I -c "import hashlib,sys;print('0x00'+hashlib.sha256(f'n42-profile1-test-validator-{sys.argv[1]}'.encode()).hexdigest()[2:])" "$1"; }

cmd_genesis() {
  local out=${1:?out}
  [ -x "$KEYGEN" ] || { echo "missing $KEYGEN" >&2; exit 1; }
  local secrets=() i
  for i in $(seq 0 $((P1M_N - 1))); do secrets+=("$(secret_of "$i")"); done
  "$KEYGEN" --bls-public-key "${secrets[@]}" > "$out.pubkeys" || exit 1
  python3 -I - "$P1M_GENESIS_BASE" "$out.pubkeys" "$out" <<'PY' || exit 1
import hashlib, json, sys
base, pubs, out = sys.argv[1:4]
g = json.load(open(base))
keys = [l.strip() for l in open(pubs) if l.strip()]
v1 = g["config"]["hotstuff"]["validators"]
for i, entry in enumerate(v1):
    assert entry["blsKey"].lower() == keys[i].lower(), f"derivation differs from V1 at {i}"
vals = []
for i, key in enumerate(keys):
    if i < len(v1):
        vals.append(dict(v1[i]))
    else:
        addr = hashlib.sha256(f"n42-profile1-test-validator-address-{i}".encode()).hexdigest()[:40]
        vals.append({"address": "0x" + addr, "blsKey": key})
assert len({v["address"].lower() for v in vals}) == len(vals)
g["config"]["hotstuff"]["validators"] = vals
with open(out, "w") as f:
    json.dump(g, f, indent=2)
    f.write("\n")
n = len(vals); f_ = (n - 1) // 3
print(f"{out}: {n} validators, f = {f_}, quorum {n - f_}")
PY
  rm -f "$out.pubkeys"
}

cmd_init() {
  for b in "$EL" "$VAL" "$KEYGEN"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 1; }; done
  [ -f "$P1M_GENESIS" ] || { echo "no $P1M_GENESIS: run genesis first" >&2; exit 1; }
  if pgrep -f "$(val_re)|$(el_re)" >/dev/null; then echo "processes of $P1M_DIR are running; down first" >&2; exit 1; fi
  mkdir -p "$P1M_DIR"
  local now; now=$(date -u +%s)
  sed -E "s/^(\s*\"timestamp\": *\")0x[0-9a-fA-F]+(\")/\1$(printf '0x%x' "$now")\2/" "$P1M_GENESIS" > "$G"
  diff <(sed '/"timestamp"/d' "$P1M_GENESIS") <(sed '/"timestamp"/d' "$G") >/dev/null \
    || { echo "genesis copy differs beyond timestamp" >&2; exit 1; }
  [ -f "$P1M_DIR/jwt.hex" ] || openssl rand -hex 32 > "$P1M_DIR/jwt.hex"
  local n; n=$(python3 -I -c "import json,sys;print(len(json.load(open(sys.argv[1]))['config']['hotstuff']['validators']))" "$G")
  [ "$n" = "$P1M_N" ] || { echo "genesis has $n validators, P1M_N=$P1M_N" >&2; exit 1; }
  echo "genesis : $G timestamp $now sha256 $(sha256sum "$G" | cut -c1-16), $n validators over $P1M_E layers"
  local e i d
  for e in $(seq 0 $((P1M_E - 1))); do
    d=$(edir "$e"); rm -rf "$d"; mkdir -p "$d"
    taskset -c "$P1M_CPUS" "$EL" init --datadir "$d/el" --chain "$G" > "$d/init.log" 2>&1 \
      || { echo "n42 init failed for layer $e: $d/init.log" >&2; exit 1; }
  done
  echo "genesis hash (n42 init): $(strip "$(edir 0)/init.log" | /usr/bin/grep -aoE 'hash=0x[0-9a-f]{64}' | tail -1)"
  for i in $(seq 0 $((P1M_N - 1))); do
    d=$(vdir "$i"); rm -rf "$d"; mkdir -p "$d"; chmod 700 "$d"
    ( umask 077
      secret_of "$i" | tr -d '\n' > "$d/bls.key"
      python3 -I -c "import hashlib,sys;print(hashlib.sha256(f'n42-profile1-rs-node-key-{sys.argv[1]}'.encode()).hexdigest(),end='')" "$i" > "$d/node.key" )
    "$KEYGEN" --libp2p-peer-id "$(cat "$d/node.key")" > "$d/peer-id" || exit 1
  done
  echo "init: $P1M_N validator dirs, $P1M_E layers in $P1M_DIR"
}

cmd_up() {
  [ -f "$G" ] || { echo "no $G: init first" >&2; exit 1; }
  if pgrep -f "$(val_re)|$(el_re)" >/dev/null; then echo "processes of $P1M_DIR are running" >&2; exit 1; fi
  local e i p d
  for e in $(seq 0 $((P1M_E - 1))); do
    for p in $(http_port "$e") $(auth_port "$e") $(devp2p_port "$e"); do
      port_busy "$p" && { echo "port $p (layer $e) is in use; refusing to start" >&2; exit 1; }
    done
  done
  for i in $(seq 0 $((P1M_N - 1))); do
    for p in $(p2p_port "$i") $((1000 + $(p2p_port "$i"))); do
      port_busy "$p" && { echo "port $p (validator $i) is in use; refusing to start" >&2; exit 1; }
    done
  done
  date -u +%Y%m%dT%H%M%S > "$P1M_DIR/run-tag"
  for e in $(seq 0 $((P1M_E - 1))); do
    d=$(edir "$e")
    N42_IMPORT_ONCE=1 setsid taskset -c "$P1M_CPUS" "$EL" node --datadir "$d/el" --chain "$G" \
      --authrpc.addr 127.0.0.1 --authrpc.port "$(auth_port "$e")" --authrpc.jwtsecret "$P1M_DIR/jwt.hex" \
      --http --http.addr 127.0.0.1 --http.port "$(http_port "$e")" --http.api eth,net,web3,txpool \
      --ipcdisable --port "$(devp2p_port "$e")" --discovery.port "$(devp2p_port "$e")" \
      --disable-discovery --no-persist-peers --max-inbound-peers 0 --max-outbound-peers 0 --disable-tx-gossip \
      --log.file.max-files 0 --color never \
      > "$d/el.log" 2>&1 < /dev/null &
  done
  for e in $(seq 0 $((P1M_E - 1))); do
    local ok=; d=$(edir "$e")
    for _ in $(seq 1 60); do /usr/bin/grep -aq "RPC auth server started" "$d/el.log" && { ok=1; break; }; sleep 1; done
    [ -n "$ok" ] || { echo "layer $e did not start: $d/el.log" >&2; tail -5 "$d/el.log" >&2; exit 1; }
  done
  local addrs=(); for i in $(seq 0 $((P1M_N - 1))); do addrs+=("$(maddr "$i")"); done
  for i in $(seq 0 $((P1M_N - 1))); do
    local peers=() j; d=$(vdir "$i"); e=$(layer_of "$i")
    for j in $(seq 0 $((P1M_N - 1))); do [ "$j" = "$i" ] || peers+=(--peer "${addrs[$j]}"); done
    RUST_LOG=$P1M_RUST_LOG setsid taskset -c "$P1M_CPUS" "$VAL" --datadir "$d/consensus" \
      --chain "$G" --index "$i" --bls-key "$(cat "$d/bls.key")" --node-key "$d/node.key" \
      --el "http://127.0.0.1:$(auth_port "$e")" --el-rpc "http://127.0.0.1:$(http_port "$e")" --jwt "$P1M_DIR/jwt.hex" \
      --listen "/ip4/127.0.0.1/tcp/$(p2p_port "$i")" --worker-threads "$P1M_VAL_THREADS" --propose "${peers[@]}" \
      > "$d/v.log" 2>&1 < /dev/null &
  done
  sleep 5
  echo "up: $(pgrep -fc "$(el_re)") layers, $(pgrep -fc "$(val_re)") validators"
}

REFUSAL_RE='refus|profile 1:|profile-1|BAD BLOCK|bad block|conflicting commit|safety halt|SAFETY HALT|invalid block|InvalidBlock'
BENIGN_RE='batched (commit )?vote refused.*view mismatch|Connection refused|connection refused|failed to dial|Failed to dial|OutgoingConnectionError|eth_getProof refused'

cmd_status() {
  local e i d
  for e in $(seq 0 $((P1M_E - 1))); do
    local h hh
    h=$(rpc "$(http_port "$e")" eth_blockNumber '[]' | python3 -I -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null)
    hh=$(rpc "$(http_port "$e")" eth_getBlockByNumber '["latest",false]' | python3 -I -c "import sys,json;print(json.load(sys.stdin)['result']['hash'])" 2>/dev/null)
    echo "layer $e: height ${h:--} head ${hh:--}"
  done
  local led=0 tmo=0 ref=0 voters=0 halts=0 silent=()
  for i in $(seq 0 $((P1M_N - 1))); do
    d=$(vdir "$i")
    local l t r v
    l=$(strip "$d/v.log" 2>/dev/null | /usr/bin/grep -ac 'built a block to propose')
    t=$(strip "$d/v.log" 2>/dev/null | /usr/bin/grep -ac 'n42.h2.node: view timed out')
    r=$(strip "$d/v.log" 2>/dev/null | /usr/bin/grep -aE "$REFUSAL_RE" | /usr/bin/grep -avEc "$BENIGN_RE")
    v=$(strip "$d/v.log" 2>/dev/null | /usr/bin/grep -ac 'sending vote to leader')
    led=$((led + l)); tmo=$((tmo + t)); ref=$((ref + r))
    if [ "$v" -gt 0 ]; then voters=$((voters + 1)); else silent+=("$i"); fi
    [ -e "$d/consensus/safety-halt.json" ] && halts=$((halts + 1))
  done
  echo "validators: $(pgrep -fc "$(val_re)") alive, $voters voted (silent: ${silent[*]:-none}), views led $led, timeout lines $tmo, refusal lines $ref, halts $halts"
}

# Per view led: the leader's build, its PrepareQC and its commit, from its log.
cmd_timing() {
  local i
  for i in $(seq 0 $((P1M_N - 1))); do strip "$(vdir "$i")/v.log" | sed "s/^/$i /"; done | python3 -I -c '
import re, sys, statistics as st
from datetime import datetime
ts = re.compile(r"^(\d+) (\S+Z)\s")
view = re.compile(r"\bview[=: ]+(\d+)")
def t(s): return datetime.strptime(s[:26].rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f").timestamp()
ev = {}
for ln in sys.stdin:
    m = ts.match(ln); v = view.search(ln)
    if not m or not v: continue
    who, at, vw = int(m.group(1)), t(m.group(2)), int(v.group(1))
    for key, pat in (("build", "built a block to propose"), ("qc", "QC formed, entering pre-commit"), ("commit", "block committed!")):
        if pat in ln:
            ev.setdefault(vw, {}).setdefault(key, {})[who] = at
rows = []
for vw, e in sorted(ev.items()):
    if "build" not in e: continue
    leader, b = next(iter(e["build"].items()))
    q = e.get("qc", {}).get(leader); c = e.get("commit", {}).get(leader)
    rows.append((vw, leader, (q - b) * 1e3 if q else None, (c - b) * 1e3 if c else None))
qs = [r[2] for r in rows if r[2] is not None]; cs = [r[3] for r in rows if r[3] is not None]
leaders = {r[1] for r in rows}
print(f"views led {len(rows)} by {len(leaders)} distinct leaders")
for name, xs in (("build->PrepareQC ms", qs), ("build->commit ms", cs)):
    if xs:
        xs = sorted(xs)
        print(f"{name}: n {len(xs)} p50 {xs[len(xs)//2]:.0f} p90 {xs[int(len(xs)*0.9)]:.0f} max {xs[-1]:.0f}")
'
}

cmd_down() {
  local before; before=$(pgrep -fc "$(val_re)|$(el_re)")
  pkill -TERM -f "$(val_re)"
  for _ in $(seq 1 60); do pgrep -f "$(val_re)" >/dev/null || break; sleep 1; done
  pkill -TERM -f "$(el_re)"
  for _ in $(seq 1 240); do pgrep -f "$(el_re)" >/dev/null || break; sleep 1; done
  if pgrep -f "$(val_re)|$(el_re)" >/dev/null; then echo "STILL RUNNING after SIGTERM:"; pgrep -af "$(val_re)|$(el_re)" | cut -c1-150; exit 1; fi
  echo "down: all $before stopped"
}

case ${1:-} in
  genesis) shift; cmd_genesis "$@" ;;
  init) cmd_init ;;
  up) cmd_up ;;
  status) cmd_status ;;
  timing) cmd_timing ;;
  down) cmd_down ;;
  *) sed -n '2,32p' "$0"; exit 2 ;;
esac
