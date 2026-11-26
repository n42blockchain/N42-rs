#!/usr/bin/env bash
# One stand-alone `n42 node` serving JSON-RPC to a block explorer, on a copy
# of a member's execution-layer datadir (no validator drives it, so the chain
# stands still: every request is a read). docs/EXPLORER_RPC_PERF.md.
#
#   scripts/explorer-node.sh up | down | pid
#
#   EX_DIR=<dir>        holds el/ (the datadir), genesis.json, jwt.hex
#                       (default /data/n42-build/explorer-rpc/chain)
#   EX_BIN=<n42>        the binary (default the profiling build of this lane)
#   EX_HTTP=<port>      HTTP JSON-RPC (default 20910); WS +1, authrpc +2, devp2p +3
#   EX_ARGS="<args>"    extra `n42 node` arguments (the settings under test)
#   EX_ENV="K=V .."     extra environment
#   EX_CPUS=<list>      taskset list (default skips the faulty core 99/227)
set -u
EX_DIR=${EX_DIR:-/data/n42-build/explorer-rpc/chain}
EX_BIN=${EX_BIN:-/data/n42-build/target-explorer-rpc/profiling/n42}
EX_HTTP=${EX_HTTP:-20910}
EX_CPUS=${EX_CPUS:-0-98,100-226,228-255}
PIDF=$EX_DIR/node.pid

case "${1:-}" in
  up)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "running: $(cat "$PIDF")" >&2; exit 1; fi
    for p in "$EX_HTTP" $((EX_HTTP + 1)) $((EX_HTTP + 2)) $((EX_HTTP + 3)); do
      ss -Hltn "sport = :$p" | /usr/bin/grep -q . && { echo "port $p busy" >&2; exit 1; }
    done
    [ -f "$EX_DIR/el.log" ] && mv "$EX_DIR/el.log" "$EX_DIR/el.log.$(date +%H%M%S)"
    # shellcheck disable=SC2086 # EX_ENV / EX_ARGS split on purpose
    env ${EX_ENV:-} setsid taskset -c "$EX_CPUS" "$EX_BIN" node --datadir "$EX_DIR/el" --chain "$EX_DIR/genesis.json" \
      --authrpc.addr 127.0.0.1 --authrpc.port $((EX_HTTP + 2)) --authrpc.jwtsecret "$EX_DIR/jwt.hex" \
      --http --http.addr 127.0.0.1 --http.port "$EX_HTTP" --http.api eth,net,web3,txpool,debug,trace \
      --ws --ws.addr 127.0.0.1 --ws.port $((EX_HTTP + 1)) --ws.api eth,net,web3 \
      --ipcdisable --port $((EX_HTTP + 3)) --discovery.port $((EX_HTTP + 3)) \
      --disable-discovery --no-persist-peers --max-inbound-peers 0 --max-outbound-peers 0 --disable-tx-gossip \
      --log.file.max-files 0 --color never ${EX_ARGS:-} > "$EX_DIR/el.log" 2>&1 < /dev/null &
    echo $! > "$PIDF"
    for _ in $(seq 1 120); do
      curl -s -m 2 -X POST -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "http://127.0.0.1:$EX_HTTP" \
        | /usr/bin/grep -q result && { echo "up: pid $(cat "$PIDF"), http $EX_HTTP"; exit 0; }
      sleep 1
    done
    echo "did not answer; see $EX_DIR/el.log" >&2; exit 1 ;;
  down)
    [ -f "$PIDF" ] || exit 0
    p=$(cat "$PIDF"); kill "$p" 2>/dev/null
    for _ in $(seq 1 60); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
    kill -0 "$p" 2>/dev/null && kill -9 "$p"
    rm -f "$PIDF"; echo "down" ;;
  pid) cat "$PIDF" ;;
  *) echo "usage: $0 up|down|pid" >&2; exit 2 ;;
esac
