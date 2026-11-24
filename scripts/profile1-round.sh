#!/usr/bin/env bash
# A profile-1 round of n42-rs members: each member is its own `n42 node`
# execution layer plus one `h2_validator`, on a profile-1 genesis
# (docs/MIXED_PRODUCTION_STANDARD_V1_RC.md). Run all four validators for an
# all-Rust smoke, or a subset beside another client's validators (the mixed
# round of /data/blockchain/gov5-work/p1mixed/MIXED-ROUND-PLAN.md).
#
#   scripts/profile1-round.sh init | up | status | headers <from> <to> | down
#
#   P1_MEMBERS="0 1 2 3"  validator indices this script runs ("2 3" in the mixed round)
#   P1_GENESIS=<file>     the profile-1 genesis (default: the V1 genesis_8s.json)
#   P1_GENESIS_NOW=1      init copies the genesis with "timestamp" = now (only that
#                         field; the hash changes); 0 uses P1_GENESIS byte for byte
#   P1_EXTRA_PEERS="<multiaddr> ..."  more static peers (the other client's validators)
#   P1_DIR=<run dir>      everything lives here (default /data/n42-build/p1-round)
#   P1_BIN=<dir>          release dir holding n42 and examples/h2_validator, h2_keygen
#   P1_CPUS=<list>        taskset CPU list (default skips the faulty core 99/227)
#
# Ports, member i (0..3): libp2p TCP 3070i (body channel 3170i), EL HTTP 2014i,
# EL authrpc 2034i, EL devp2p 2044i (discovery off, no peers). gov5's 30700/30701/
# 30704, 20140/20141/20144, 21140+ and 6210+ are only bound for members 0, 1 --
# never run those beside gov5. Keys: BLS secret i = 0x00 || sha256("n42-profile1-
# test-validator-<i>")[1:] (TEST ONLY); libp2p node key i = sha256("n42-profile1-
# rs-node-key-<i>"), so the peer id is stable across runs.
#
# Every N42_* variable is unset for the members: profile 1 takes its values from
# the genesis and refuses the overrides (crates/n42/qmdb-reth/src/profile1.rs).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
P1_MEMBERS=${P1_MEMBERS:-0 1 2 3}
P1_GENESIS=${P1_GENESIS:-$REPO/crates/n42/qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json}
P1_GENESIS_NOW=${P1_GENESIS_NOW:-1}
P1_EXTRA_PEERS=${P1_EXTRA_PEERS:-}
P1_DIR=${P1_DIR:-/data/n42-build/p1-round}
P1_BIN=${P1_BIN:-/data/n42-build/target-wt-p1smoke/release}
P1_CPUS=${P1_CPUS:-0-98,100-226,228-255}
EL=$P1_BIN/n42
VAL=$P1_BIN/examples/h2_validator
KEYGEN=$P1_BIN/examples/h2_keygen
G=$P1_DIR/genesis.json
for v in $(compgen -e | /usr/bin/grep '^N42_'); do unset "$v"; done

p2p_port() { echo $((30700 + $1)); }
http_port() { echo $((20140 + $1)); }
auth_port() { echo $((20340 + $1)); }
devp2p_port() { echo $((20440 + $1)); }
mdir() { echo "$P1_DIR/m$1"; }
peer_id() { cat "$(mdir "$1")/peer-id"; }
maddr() { echo "/ip4/127.0.0.1/tcp/$(p2p_port "$1")/p2p/$(peer_id "$1")"; }
# The regex for a process this run dir started: the binary path, its first
# arguments, the run dir. The first character in brackets keeps pkill/pgrep
# from matching a shell whose command line merely contains the pattern.
mine_re() { echo "^[${P1_BIN:0:1}]${P1_BIN:1}/(n42 node --datadir|examples/h2_validator --datadir) $P1_DIR/m[0-9]/"; }

rpc() { # rpc <port> <method> <params json>
  curl -s -m 5 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "http://127.0.0.1:$1"; }
strip() { sed 's/\x1b\[[0-9;]*m//g' "$@"; }

port_busy() { ss -Hltn "sport = :$1" 2>/dev/null | /usr/bin/grep -q .; }

cmd_init() {
  for b in "$EL" "$VAL" "$KEYGEN"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 1; }; done
  if pgrep -f "$(mine_re)" >/dev/null; then echo "members of $P1_DIR are running; down first" >&2; exit 1; fi
  mkdir -p "$P1_DIR"
  if [ "$P1_GENESIS_NOW" = 1 ]; then
    local now; now=$(date -u +%s)
    # Only the timestamp field changes; the rest of the file is byte for byte.
    sed -E "s/^(\s*\"timestamp\": *\")0x[0-9a-fA-F]+(\")/\1$(printf '0x%x' "$now")\2/" "$P1_GENESIS" > "$G"
    diff <(sed '/"timestamp"/d' "$P1_GENESIS") <(sed '/"timestamp"/d' "$G") >/dev/null \
      || { echo "genesis copy differs beyond timestamp" >&2; exit 1; }
  else
    cp "$P1_GENESIS" "$G"
  fi
  [ -f "$P1_DIR/jwt.hex" ] || openssl rand -hex 32 > "$P1_DIR/jwt.hex"
  echo "genesis   : $G timestamp $(python3 -I -c "import json,sys;print(int(json.load(open(sys.argv[1]))['timestamp'],16))" "$G") sha256 $(sha256sum "$G" | cut -c1-16)"
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i")
    rm -rf "$d"; mkdir -p "$d"; chmod 700 "$d"
    python3 -I - "$i" "$G" "$d" <<'PY' || exit 1
import hashlib, json, os, sys
i, g, d = int(sys.argv[1]), sys.argv[2], sys.argv[3]
bls = "00" + hashlib.sha256(f"n42-profile1-test-validator-{i}".encode()).hexdigest()[2:]
node = hashlib.sha256(f"n42-profile1-rs-node-key-{i}".encode()).hexdigest()
for name, val in (("bls.key", "0x" + bls), ("node.key", node)):
    fd = os.open(os.path.join(d, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, val.encode()); os.close(fd)
vals = json.load(open(g))["config"]["hotstuff"]["validators"]
assert i < len(vals), f"index {i} not in the genesis set of {len(vals)}"
PY
    "$KEYGEN" --libp2p-peer-id "$(cat "$d/node.key")" > "$d/peer-id" || exit 1
    taskset -c "$P1_CPUS" "$EL" init --datadir "$d/el" --chain "$G" > "$d/init.log" 2>&1 \
      || { echo "n42 init failed for member $i: $d/init.log" >&2; tail -5 "$d/init.log" >&2; exit 1; }
    echo "member $i  : $(maddr "$i")  (EL http $(http_port "$i"), auth $(auth_port "$i"))"
  done
  local first; first=$(echo $P1_MEMBERS | awk '{print $1}')
  echo "genesis hash (n42 init): $(strip "$(mdir "$first")/init.log" | /usr/bin/grep -aoE 'hash=0x[0-9a-f]{64}' | tail -1)"
}

cmd_up() {
  [ -f "$G" ] || { echo "no $G: init first" >&2; exit 1; }
  if pgrep -f "$(mine_re)" >/dev/null; then echo "members of $P1_DIR already running" >&2; exit 1; fi
  for i in $P1_MEMBERS; do
    for p in $(p2p_port "$i") $((1000 + $(p2p_port "$i"))) $(http_port "$i") $(auth_port "$i") $(devp2p_port "$i"); do
      if port_busy "$p"; then echo "port $p (member $i) is in use; refusing to start" >&2; exit 1; fi
    done
  done
  local tag; tag=$(date -u +%Y%m%dT%H%M%S); echo "$tag" > "$P1_DIR/run-tag"
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i")
    setsid taskset -c "$P1_CPUS" "$EL" node --datadir "$d/el" --chain "$G" \
      --authrpc.addr 127.0.0.1 --authrpc.port "$(auth_port "$i")" --authrpc.jwtsecret "$P1_DIR/jwt.hex" \
      --http --http.addr 127.0.0.1 --http.port "$(http_port "$i")" --http.api eth,net,web3,txpool \
      --ipcdisable --port "$(devp2p_port "$i")" --discovery.port "$(devp2p_port "$i")" \
      --disable-discovery --no-persist-peers --max-inbound-peers 0 --max-outbound-peers 0 --disable-tx-gossip \
      --log.file.max-files 0 --color never \
      > "$d/el.log" 2>&1 < /dev/null &
  done
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i") ok=
    for _ in $(seq 1 60); do /usr/bin/grep -aq "RPC auth server started" "$d/el.log" && { ok=1; break; }; sleep 1; done
    [ -n "$ok" ] || { echo "member $i EL did not start: $d/el.log" >&2; tail -5 "$d/el.log" >&2; }
  done
  for i in $P1_MEMBERS; do
    local d peers=() j; d=$(mdir "$i")
    for j in $P1_MEMBERS; do [ "$j" = "$i" ] || peers+=(--peer "$(maddr "$j")"); done
    for j in $P1_EXTRA_PEERS; do peers+=(--peer "$j"); done
    RUST_LOG=${P1_RUST_LOG:-info,n42=debug} setsid taskset -c "$P1_CPUS" "$VAL" --datadir "$d/consensus" \
      --chain "$G" --index "$i" --bls-key "$(cat "$d/bls.key")" --node-key "$d/node.key" \
      --el "http://127.0.0.1:$(auth_port "$i")" --el-rpc "http://127.0.0.1:$(http_port "$i")" --jwt "$P1_DIR/jwt.hex" \
      --listen "/ip4/127.0.0.1/tcp/$(p2p_port "$i")" --propose "${peers[@]}" \
      > "$d/v.log" 2>&1 < /dev/null &
  done
  sleep 3
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i")
    echo "member $i up: $(strip "$d/v.log" | /usr/bin/grep -a -m1 'node peer id' | awk '{print $NF}') $(strip "$d/v.log" | /usr/bin/grep -a -m1 '^chain ')"
  done
  pgrep -af "$(mine_re)" | cut -c1-150
}

member_alive() { pgrep -fc "^[${P1_BIN:0:1}]${P1_BIN:1}/(n42 node|examples/h2_validator) --datadir $(mdir "$1")/"; }
el_alive() { pgrep -f "^[${P1_BIN:0:1}]${P1_BIN:1}/n42 node --datadir $(mdir "$1")/el " >/dev/null; }
height() { rpc "$(http_port "$1")" eth_blockNumber '[]' | python3 -I -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null; }
head_hash() { rpc "$(http_port "$1")" eth_getBlockByNumber '["latest",false]' | python3 -I -c "import sys,json;print(json.load(sys.stdin)['result']['hash'])" 2>/dev/null; }

# A line the round fails on: a profile-1 refusal, a refused header/vote,
# a bad block, a halt. A dial refused by a peer that is not up yet is not one.
REFUSAL_RE='refus|profile 1:|profile-1|BAD BLOCK|bad block|conflicting commit|safety halt|SAFETY HALT|invalid block|InvalidBlock'
BENIGN_RE='Connection refused|connection refused|failed to dial|Failed to dial|OutgoingConnectionError|eth_getProof refused'

cmd_status() {
  printf '%-6s %-7s %-68s %-5s %-8s %-8s %-6s %s\n' member height head led timeouts refusals halt alive
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i")
    local led tmo ref halt alive
    led=$(strip "$d/v.log" 2>/dev/null | /usr/bin/grep -ac 'built a block to propose')
    tmo=$(strip "$d/v.log" 2>/dev/null | /usr/bin/grep -ac 'view timed out')
    ref=$(cat "$d/v.log" "$d/el.log" 2>/dev/null | strip | /usr/bin/grep -aE "$REFUSAL_RE" | /usr/bin/grep -avEc "$BENIGN_RE")
    halt=no; [ -e "$d/consensus/safety-halt.json" ] && halt=YES
    alive=$(member_alive "$i")
    local h=- hh=-
    # Never read the RPC of a port this member does not own.
    if el_alive "$i"; then h=$(height "$i"); hh=$(head_hash "$i"); fi
    printf '%-6s %-7s %-68s %-5s %-8s %-8s %-6s %s\n' "$i" "$h" "$hh" "$led" "$tmo" "$ref" "$halt" "$alive/2"
  done
}

cmd_headers() {
  local from=${1:?from} to=${2:?to}
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i")
    el_alive "$i" || { echo "member $i: execution layer of $P1_DIR not running; no headers" >&2; continue; }
    # Columns: number ts hash gasUsed gasLimit ntx (the plan's parser format, no header row).
    python3 -I - "$(http_port "$i")" "$from" "$to" > "$P1_DIR/headers-node$i.tsv" <<'PY'
import json, sys, urllib.request
port, a, b = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
for lo in range(a, b + 1, 50):
    reqs = [{"jsonrpc": "2.0", "id": n, "method": "eth_getBlockByNumber", "params": [hex(n), False]}
            for n in range(lo, min(lo + 50, b + 1))]
    r = urllib.request.Request(f"http://127.0.0.1:{port}", json.dumps(reqs).encode(), {"content-type": "application/json"})
    for x in sorted(json.load(urllib.request.urlopen(r, timeout=20)), key=lambda x: x["id"]):
        h = x.get("result")
        if not h:
            continue
        print("\t".join([str(int(h["number"], 16)), str(int(h["timestamp"], 16)), h["hash"],
                         str(int(h["gasUsed"], 16)), str(int(h["gasLimit"], 16)), str(len(h.get("transactions", [])))]))
PY
    # One line per view led and per view timeout, in the form the plan's parser reads.
    mkdir -p "$P1_DIR/log-node$i"
    strip "$d/v.log" | python3 -I -c '
import calendar, json, re, sys
ts = re.compile(r"^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)(\.\d+)?Z")
view = re.compile(r"\bview[=: ]+(\d+)")
for ln in sys.stdin:
    m = ts.match(ln)
    if not m:
        continue
    v = view.search(ln)
    t = m.group(1) + " " + m.group(2)
    ms = calendar.timegm(__import__("time").strptime(t, "%Y-%m-%d %H:%M:%S")) * 1000 + int(float(m.group(3) or 0) * 1000)
    if "built a block to propose" in ln and v:
        print(json.dumps({"msg": "hotstuff: view changed", "isLeader": True, "view": int(v.group(1)), "tMs": ms, "time": t}))
    elif "view timed out" in ln:
        print(json.dumps({"msg": "view timed out", "view": int(v.group(1)) if v else None, "tMs": ms, "time": t}))
' > "$P1_DIR/log-node$i/n42-rs-views.log"
    echo "member $i: $(wc -l < "$P1_DIR/headers-node$i.tsv") headers -> $P1_DIR/headers-node$i.tsv; $(/usr/bin/grep -c isLeader "$P1_DIR/log-node$i/n42-rs-views.log") views led -> $P1_DIR/log-node$i/n42-rs-views.log"
  done
}

cmd_down() {
  local re; re=$(mine_re)
  local before; before=$(pgrep -fc "$re")
  echo "stopping $before processes of $P1_DIR (validators first)"
  pkill -TERM -f "^[${P1_BIN:0:1}]${P1_BIN:1}/examples/h2_validator --datadir $P1_DIR/m[0-9]/"
  for _ in $(seq 1 60); do pgrep -f "^[${P1_BIN:0:1}]${P1_BIN:1}/examples/h2_validator --datadir $P1_DIR/m[0-9]/" >/dev/null || break; sleep 1; done
  pkill -TERM -f "^[${P1_BIN:0:1}]${P1_BIN:1}/n42 node --datadir $P1_DIR/m[0-9]/"
  for _ in $(seq 1 240); do pgrep -f "$re" >/dev/null || break; sleep 1; done
  if pgrep -f "$re" >/dev/null; then
    echo "STILL RUNNING after SIGTERM (not killed):"; pgrep -af "$re" | cut -c1-150; exit 1
  fi
  echo "down: all $before stopped"
}

case ${1:-} in
  init) cmd_init ;;
  up) cmd_up ;;
  status) cmd_status ;;
  headers) shift; cmd_headers "$@" ;;
  down) cmd_down ;;
  *) sed -n '2,25p' "$0"; exit 2 ;;
esac
