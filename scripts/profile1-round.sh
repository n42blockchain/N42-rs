#!/usr/bin/env bash
# A profile-1 round of n42-rs members: each member is its own `n42 node`
# execution layer plus one `h2_validator`, on a profile-1 genesis
# (docs/MIXED_PRODUCTION_STANDARD_V1_RC.md). Run all four validators for an
# all-Rust smoke, or a subset beside another client's validators (the mixed
# round of /data/blockchain/gov5-work/p1mixed/MIXED-ROUND-PLAN.md).
#
#   scripts/profile1-round.sh init | up | status | headers <from> <to> | catchup <i> |
#                             load <tx/s> <seconds> | load-genesis <out> | stop | down |
#                             snapshot-join <i> <from>
#
#   stop                  SIGTERM P1_MEMBERS (validator, then EL), datadirs kept; `up`
#                         restarts them and catches up from where they stopped (the
#                         previous logs move to v.log.<tag> / el.log.<tag>)
#
#   snapshot-join <i> <from>  member i (initialised, not running) joins from a state
#                         snapshot of member <from> (docs/PROFILE1_SNAPSHOT_JOIN.md):
#                         <from> is stopped, `n42-init-snapshot export --bundle`ed (gov5's
#                         bundle layout) and restarted; once the chain is past
#                         N+P1_ANCHOR_HEADERS, headers max(N-255,1).. are read
#                         (debug_getRawHeader) from a running member and `anchor` adds
#                         next-header.rlp, commit-qc.bin and bundle.json; member i's
#                         datadirs are wiped, its EL is `init --bundle`ed (k=1: checked
#                         against N+1's root under a CommitQC), and it is started.
#                         Bundle and logs in P1_DIR/snap-<i>.
#
#   P1_MEMBERS="0 1 2 3"  validator indices this script runs ("2 3" in the mixed round);
#                         `up` may start a subset while other members of P1_DIR run
#                         (a late member: init all, `up` 0 1 2, later `up` 3)
#   P1_MEMBERS_ALL="..."  the members every started validator dials (default: every
#                         member initialised in P1_DIR), so a late one reaches everyone
#   P1_GENESIS=<file>     the profile-1 genesis (default: the V1 genesis_8s.json)
#   P1_GENESIS_NOW=1      init copies the genesis with "timestamp" = now (only that
#                         field; the hash changes); 0 uses P1_GENESIS byte for byte
#   P1_EXTRA_PEERS="<multiaddr> ..."  more static peers (the other client's validators)
#   P1_DIR=<run dir>      everything lives here (default /data/n42-build/p1-round)
#   P1_BIN=<dir>          release dir holding n42 and examples/h2_validator, h2_keygen
#   P1_CPUS=<list>        taskset CPU list (default skips the faulty core 99/227)
#   P1_LOAD=<tx/s>        `up` also starts `load` at that rate for P1_LOAD_SECONDS (3600)
#                         (P1_LOAD_MEMBERS, default the running ones of P1_MEMBERS)
#   P1_LOAD_TOOL=gov5     gov5's gate-3 load_core.py (P1_LOAD_PY; funds its senders from the
#                         V1 faucet, so the plain genesis works; 30 tx/s is the agreed rate)
#                         or send_tx: P1_LOAD_SENDERS=64 derived senders split over the
#                         members, which needs a genesis that funds them:
#
# `load-genesis <out>` (send_tx only) writes P1_GENESIS
# plus alloc entries for the P1_LOAD_SENDERS accounts (tx_flood / gov5 cmd/txflood
# derivation, offset 0) and the recipient 0x4242..42 (funded, so a transfer to it is
# 21,000 gas even under Amsterdam's EIP-8037); nothing else changes.
#
# Ports, member i: libp2p TCP P (body channel P+1000), EL HTTP H, authrpc H+200,
# devp2p H+300 (discovery off, no peers), with P/H = 30702/20142 and 30703/20143
# for members 2 and 3 (the plan's n42-rs ports) and 30712/20152, 30713/20153 for
# members 0 and 1. gov5's 30700/30701/30704, 20140/20141/20144, 21140+ and
# 6210+ are never bound. Keys: BLS secret i = 0x00 || sha256("n42-profile1-
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
P1_LOAD=${P1_LOAD:-}
P1_LOAD_SECONDS=${P1_LOAD_SECONDS:-3600}
P1_LOAD_SENDERS=${P1_LOAD_SENDERS:-64}
P1_LOAD_TOOL=${P1_LOAD_TOOL:-gov5}
P1_LOAD_PY=${P1_LOAD_PY:-/data/blockchain/gov5-work/p1mixed/gate3/load_core.py}
SEND_TX=$P1_BIN/examples/send_tx
LOAD_TO=0x4242424242424242424242424242424242424242
for v in $(compgen -e | /usr/bin/grep '^N42_'); do unset "$v"; done

# Members 2 and 3 take the ports the mixed-round plan reserves for n42-rs
# (30702/30703, 20142/20143); members 0 and 1 stay off gov5's 30700/30701 and
# 20140/20141 and use 30712/30713, 20152/20153.
shift_of() { if [ "$1" -lt 2 ]; then echo 12; else echo 0; fi; }
# P1_PORT_OFFSET=<n> moves every port of this script by n, for an all-Rust round
# while another client's round holds the plan's ports (30: 30730-30743, HTTP
# 20170-20183); a mixed round leaves it 0.
P1_PORT_OFFSET=${P1_PORT_OFFSET:-0}
p2p_port() { echo $((30700 + P1_PORT_OFFSET + $1 + $(shift_of "$1"))); }
http_port() { echo $((20140 + P1_PORT_OFFSET + $1 + $(shift_of "$1"))); }
auth_port() { echo $((20340 + P1_PORT_OFFSET + $1 + $(shift_of "$1"))); }
devp2p_port() { echo $((20440 + P1_PORT_OFFSET + $1 + $(shift_of "$1"))); }
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
  local all; all=$(members_all)
  for i in $P1_MEMBERS; do
    [ -f "$(mdir "$i")/peer-id" ] || { echo "member $i is not initialised in $P1_DIR" >&2; exit 1; }
    if [ "$(member_alive "$i")" != 0 ]; then echo "member $i of $P1_DIR already running" >&2; exit 1; fi
  done
  for i in $P1_MEMBERS; do
    for p in $(p2p_port "$i") $((1000 + $(p2p_port "$i"))) $(http_port "$i") $(auth_port "$i") $(devp2p_port "$i"); do
      if port_busy "$p"; then echo "port $p (member $i) is in use; refusing to start" >&2; exit 1; fi
    done
  done
  local tag; tag=$(date -u +%Y%m%dT%H%M%S); echo "$tag" > "$P1_DIR/run-tag"
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i")
    # A restart: keep the previous run's logs beside the new ones.
    if [ -f "$d/v.log" ]; then
      local old; old=$(cat "$d/up-tag" 2>/dev/null || echo prev)
      mv "$d/v.log" "$d/v.log.$old"; [ -f "$d/el.log" ] && mv "$d/el.log" "$d/el.log.$old"
    fi
    echo "$tag" > "$d/up-tag"
  done
  for i in $P1_MEMBERS; do
    local d; d=$(mdir "$i")
    setsid taskset -c "$P1_CPUS" "$EL" node --datadir "$d/el" --chain "$G" \
      --authrpc.addr 127.0.0.1 --authrpc.port "$(auth_port "$i")" --authrpc.jwtsecret "$P1_DIR/jwt.hex" \
      --http --http.addr 127.0.0.1 --http.port "$(http_port "$i")" --http.api eth,net,web3,txpool,debug \
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
    for j in $all; do [ "$j" = "$i" ] || peers+=(--peer "$(maddr "$j")"); done
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
  if [ -n "$P1_LOAD" ]; then cmd_load "$P1_LOAD" "$P1_LOAD_SECONDS"; fi
}

# Every member initialised in P1_DIR (P1_MEMBERS_ALL overrides).
members_all() {
  if [ -n "${P1_MEMBERS_ALL:-}" ]; then echo "$P1_MEMBERS_ALL"; return; fi
  local f; for f in "$P1_DIR"/m[0-9]/peer-id; do [ -f "$f" ] && basename "$(dirname "$f")" | cut -c2-; done | tr '\n' ' '
}

cmd_load_genesis() {
  local out=${1:?out}
  [ -x "$SEND_TX" ] || { echo "missing $SEND_TX" >&2; exit 1; }
  "$SEND_TX" --senders "$P1_LOAD_SENDERS" --print-addresses > "$out.senders" || exit 1
  python3 -I - "$P1_GENESIS" "$out" "$out.senders" "$LOAD_TO" <<'PY2' || exit 1
import json, sys
src, out, senders, sink = sys.argv[1:5]
g = json.load(open(src))
for a in open(senders).read().split():
    assert a.lower() not in {k.lower() for k in g["alloc"]}, a
    g["alloc"][a] = {"balance": hex(10**24)}
g["alloc"][sink] = {"balance": "0x1"}
open(out, "w").write(json.dumps(g, indent=2) + "\n")
PY2
  rm -f "$out.senders"
  echo "load genesis: $out ($P1_LOAD_SENDERS senders x 1e24 wei + recipient $LOAD_TO) sha256 $(sha256sum "$out" | cut -c1-64)"
}

# load <tx/s> <seconds>: send_tx processes over the loaded members, each with its
# own slice of the derived senders (disjoint nonce sequences), recorded in load.pids.
cmd_load() {
  local rate=${1:?tx/s} secs=${2:?seconds}
  local targets=() i
  for i in ${P1_LOAD_MEMBERS:-$P1_MEMBERS}; do el_alive "$i" && targets+=("$i"); done
  [ ${#targets[@]} -gt 0 ] || { echo "no running member to load" >&2; exit 1; }
  if [ "$P1_LOAD_TOOL" != send_tx ]; then
    # gov5's gate-3 load (read-only, run in place): funds its senders from the
    # genesis faucet, so it runs on the plain V1 genesis; one process, round
    # robin over the members' RPCs. The same workload gov5 runs.
    [ -f "$P1_LOAD_PY" ] || { echo "missing $P1_LOAD_PY" >&2; exit 1; }
    local urls=() ; for i in "${targets[@]}"; do urls+=("http://127.0.0.1:$(http_port "$i")"); done
    setsid python3 -I "$P1_LOAD_PY" --rpc "$(IFS=,; echo "${urls[*]}")" --rate "$rate" --duration "$secs" \
      --log "$P1_DIR/load-tx.log" >> "$P1_DIR/load.log" 2>&1 < /dev/null &
    echo $! >> "$P1_DIR/load.pids"
    echo "load: $rate tx/s for ${secs}s via $P1_LOAD_PY over members ${targets[*]}; log $P1_DIR/load.log"
    return
  fi
  [ -x "$SEND_TX" ] || { echo "missing $SEND_TX" >&2; exit 1; }
  local k=${#targets[@]} per=$((P1_LOAD_SENDERS / ${#targets[@]})) chain n=0
  chain=$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['config']['chainId'])" "$G")
  for i in "${targets[@]}"; do
    setsid "$SEND_TX" --rpc "http://127.0.0.1:$(http_port "$i")" --senders "$per" --offset $((n * per)) \
      --to "$LOAD_TO" --value 1 --chain-id "$chain" --rate "$(python3 -I -c "print($rate/$k)")" --seconds "$secs" \
      >> "$P1_DIR/load-m$i.log" 2>&1 < /dev/null &
    echo $! >> "$P1_DIR/load.pids"
    n=$((n + 1))
  done
  echo "load: $rate tx/s for ${secs}s over members ${targets[*]} ($per senders each); logs $P1_DIR/load-m*.log"
}

cmd_load_stop() {
  [ -f "$P1_DIR/load.pids" ] || return 0
  local p
  for p in $(cat "$P1_DIR/load.pids"); do
    # Only a send_tx this run dir started.
    [ -r "/proc/$p/cmdline" ] || continue
    if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | /usr/bin/grep -qE "^($SEND_TX |python3 -I $P1_LOAD_PY )"; then kill -TERM "$p"; fi
  done
  rm -f "$P1_DIR/load.pids"
}

# catchup <i>: when the member's first range request went out, when it reached the
# head (sync mode: live), how many blocks it pulled, its first vote and first led
# view after that, and every refusal / timeout / halt.
cmd_catchup() {
  local i=${1:?member}; local d; d=$(mdir "$i")
  python3 -I - "$REFUSAL_RE" "$BENIGN_RE" <(strip "$d/v.log") <<'PY2'
import re, sys
refusal, benign = re.compile(sys.argv[1]), re.compile(sys.argv[2])
ts = re.compile(r"^(\S+Z)\s")
kv = lambda ln, k: (re.search(r"\b" + k + r"=(\S+)", ln) or [None, None])[1]
first = {}
start = None; pulls = []; finished = []; refusals = []; timeouts = []
live_at = None
for ln in open(sys.argv[3], errors="replace"):
    m = ts.match(ln)
    if not m:
        continue
    t = m.group(1)
    start = start or t
    if "pulling the gap by range" in ln:
        pulls.append((t, kv(ln, "from"), kv(ln, "to")))
    elif "catch-up finished" in ln:
        finished.append((t, kv(ln, "from"), kv(ln, "height"), kv(ln, "target"), kv(ln, "complete")))
    elif "sync mode: live" in ln and live_at is None:
        live_at = t
    elif "n42.h2.node: view timed out" in ln:
        timeouts.append(t)
    if refusal.search(ln) and not benign.search(ln):
        refusals.append(ln.strip()[:200])
    after = live_at or (finished[-1][0] if finished else None)
    if after:
        for key, pat in (("vote", "sending vote to leader"), ("commit vote", "sending commit vote"), ("led", "built a block to propose")):
            if key not in first and pat in ln and t >= after:
                first[key] = (t, kv(ln, "view"))
print(f"validator start      : {start}")
if pulls:
    print(f"first range request  : {pulls[0][0]} from {pulls[0][1]} to {pulls[0][2]} ({len(pulls)} pulls started)")
else:
    print("first range request  : none")
for f in finished:
    print(f"catch-up finished    : {f[0]} from {f[1]} height {f[2]} target {f[3]} complete {f[4]}")
if pulls and finished:
    print(f"blocks pulled        : {int(finished[-1][2]) - int(pulls[0][1])}")
print(f"sync mode: live      : {live_at or 'none'}")
for k in ("vote", "commit vote", "led"):
    v = first.get(k)
    print(f"first {k:<15}: {v[0] + ' view ' + str(v[1]) if v else 'none'}")
print(f"view timeouts        : {len(timeouts)}" + (f" (first {timeouts[0]}, last {timeouts[-1]})" if timeouts else ""))
print(f"refusal lines        : {len(refusals)}")
for r in refusals[:5]:
    print("  " + r)
PY2
  if [ -e "$d/consensus/safety-halt.json" ]; then echo "halt                 : YES ($d/consensus/safety-halt.json)"; else echo "halt                 : no"; fi
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
    tmo=$(strip "$d/v.log" 2>/dev/null | /usr/bin/grep -ac 'n42.h2.node: view timed out')
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
    elif "n42.h2.node: view timed out" in ln:
        print(json.dumps({"msg": "view timed out", "view": int(v.group(1)) if v else None, "tMs": ms, "time": t}))
' > "$P1_DIR/log-node$i/n42.log"
    echo "member $i: $(wc -l < "$P1_DIR/headers-node$i.tsv") headers -> $P1_DIR/headers-node$i.tsv; $(/usr/bin/grep -c isLeader "$P1_DIR/log-node$i/n42.log") views led -> $P1_DIR/log-node$i/n42.log"
  done
}

# stop: one or more members down, datadirs kept (validator first, then its EL).
cmd_stop() {
  local i v e
  for i in $P1_MEMBERS; do
    v="^[${P1_BIN:0:1}]${P1_BIN:1}/examples/h2_validator --datadir $(mdir "$i")/"
    e="^[${P1_BIN:0:1}]${P1_BIN:1}/n42 node --datadir $(mdir "$i")/el "
    pkill -TERM -f "$v"
    for _ in $(seq 1 60); do pgrep -f "$v" >/dev/null || break; sleep 1; done
    pkill -TERM -f "$e"
    for _ in $(seq 1 240); do pgrep -f "$e" >/dev/null || break; sleep 1; done
    if pgrep -f "$v|$e" >/dev/null; then echo "member $i STILL RUNNING after SIGTERM" >&2; exit 1; fi
    echo "member $i stopped (datadir kept) at $(date -u +%H:%M:%S)"
  done
}

cmd_down() {
  cmd_load_stop
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


# snapshot-join <i> <from>: see the header.
cmd_snapshot_join() {
  # cmd_stop / cmd_up loop over a global `i`: this function names its members
  # sj_i / sj_from so their calls cannot change them (bash scoping is dynamic).
  local sj_i=${1:?member} sj_from=${2:?from member} snap="$P1_DIR/snap-$1" n src j
  local init_bin=$P1_BIN/n42-init-snapshot
  [ -x "$init_bin" ] || { echo "missing $init_bin" >&2; exit 1; }
  [ -f "$(mdir "$sj_i")/peer-id" ] || { echo "member $sj_i is not initialised in $P1_DIR" >&2; exit 1; }
  [ "$(member_alive "$sj_i")" = 0 ] || { echo "member $sj_i is running; stop it first" >&2; exit 1; }
  el_alive "$sj_from" || { echo "member $sj_from is not running" >&2; exit 1; }
  rm -rf "$snap"; mkdir -p "$snap"
  echo "snapshot-join: stopping member $sj_from to export at $(date -u +%H:%M:%S)"
  P1_MEMBERS=$sj_from cmd_stop
  taskset -c "$P1_CPUS" "$init_bin" export --datadir "$(mdir "$sj_from")/el" --chain "$G" \
    --bundle "$snap/bundle" > "$snap/export.log" 2>&1
  local rc=$?
  P1_MEMBERS=$sj_from cmd_up > "$snap/restart-$sj_from.log" 2>&1
  echo "member $sj_from restarted at $(date -u +%H:%M:%S)"
  [ $rc = 0 ] || { echo "export failed: $snap/export.log" >&2; tail -5 "$snap/export.log" >&2; exit 1; }
  n=$(strip "$snap/export.log" | /usr/bin/grep -aoE '^head: block [0-9]+' | awk '{print $3}')
  echo "export: $(strip "$snap/export.log" | /usr/bin/grep -aE '^(head|state|QMDB)' | tr '\n' ';')"
  # The anchor: N+1 and the headers after it, from a running member other than i.
  local want=$((n + ${P1_ANCHOR_HEADERS:-4}))
  src=
  for j in $(members_all); do [ "$j" != "$sj_i" ] && el_alive "$j" && { src=$j; break; }; done
  [ -n "$src" ] || { echo "no running member to read the anchor from" >&2; exit 1; }
  for _ in $(seq 1 ${P1_ANCHOR_WAIT:-600}); do [ "$(height "$src")" -ge "$want" ] 2>/dev/null && break; sleep 1; done
  [ "$(height "$src")" -ge "$want" ] || { echo "member $src did not reach block $want" >&2; exit 1; }
  # Headers max(N-255,1)..N+P1_ANCHOR_HEADERS: the anchor (N+1 and a later header
  # embedding its CommitQC) and the ancestors gov5's bundle carries.
  python3 -I - "$(http_port "$src")" $(( n > 256 ? n - 255 : 1 )) "$want" > "$snap/anchor.hex" <<'PY' || exit 1
import json, sys, urllib.request
port, a, b = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
reqs = [{"jsonrpc": "2.0", "id": k, "method": "debug_getRawHeader", "params": [hex(k)]} for k in range(a, b + 1)]
r = urllib.request.Request(f"http://127.0.0.1:{port}", json.dumps(reqs).encode(), {"content-type": "application/json"})
for x in sorted(json.load(urllib.request.urlopen(r, timeout=30)), key=lambda x: x["id"]):
    print(x["result"])
PY
  taskset -c "$P1_CPUS" "$init_bin" anchor --chain "$G" --bundle "$snap/bundle" --headers "$snap/anchor.hex" \
    > "$snap/anchor.log" 2>&1 || { echo "anchor failed: $snap/anchor.log" >&2; tail -5 "$snap/anchor.log" >&2; exit 1; }
  echo "$(strip "$snap/anchor.log" | /usr/bin/grep -a '^anchor:') (headers from member $src)"
  # gov5's bundle carries the genesis too (its validator set checks the QC).
  cp "$G" "$snap/bundle/genesis.json"
  local d; d=$(mdir "$sj_i")
  rm -rf "$d/el" "$d/consensus"
  taskset -c "$P1_CPUS" "$init_bin" init --datadir "$d/el" --chain "$G" --bundle "$snap/bundle" \
    > "$snap/init.log" 2>&1 || { echo "init failed: $snap/init.log" >&2; tail -5 "$snap/init.log" >&2; exit 1; }
  echo "init: $(strip "$snap/init.log" | /usr/bin/grep -aE '^(bundle|head|anchor|state|QMDB)' | tr '\n' ';')"
  echo "$n" > "$snap/height"
  P1_MEMBERS=$sj_i cmd_up
}

case ${1:-} in
  init) cmd_init ;;
  up) cmd_up ;;
  status) cmd_status ;;
  headers) shift; cmd_headers "$@" ;;
  catchup) shift; cmd_catchup "$@" ;;
  load) shift; cmd_load "$@" ;;
  load-genesis) shift; cmd_load_genesis "$@" ;;
  stop) cmd_stop ;;
  snapshot-join) shift; cmd_snapshot_join "$@" ;;
  down) cmd_down ;;
  *) sed -n '2,40p' "$0"; exit 2 ;;
esac
