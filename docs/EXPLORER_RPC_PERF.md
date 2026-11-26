# Serving a block explorer's indexer from an n42-rs node

Goal (owner, 2026-11-26): the testnet's Blockscout (`ETHEREUM_JSONRPC_VARIANT=geth`) indexes from an
n42-rs node's JSON-RPC and its sync is slow. Make the node serve the indexing workload so that the
indexer and the network are the bound, not the node.

Branch `perf/explorer-rpc`. Tools: `scripts/explorer-load.py` (the load generator),
`scripts/explorer-node.sh` (one stand-alone node on a copied datadir), `scripts/explorer-suite.sh`
(every fetcher on two block ranges), `scripts/explorer-threads.py` (CPU by thread name).

**In short.** On `main`, Blockscout's internal-transaction fetcher (per-transaction
`debug_traceTransaction`, its default) is the explorer's bottleneck by two to three orders of
magnitude: reth replays a block's prefix for every transaction it traces, so a block costs O(n^2)
executions -- 0.87 blocks/s at ~1,000 transactions a block, and 97 transactions/s (one
22,860-transaction block in four minutes) on the dense range. Answering it from one trace per block
(`N42_TRACE_BLOCK_CACHE_TXS`, on by default) gives 73k-81k transactions/s. The other fetchers were held
by jsonrpsee running a batch's calls one after the other, so a node gave an explorer only its 4-10
connections' worth of cores; `N42_RPC_BATCH_CONCURRENCY=16` lifts receipts 2.4x, coin balances
2.2-2.7x, code 1.4-1.9x and, with a 1 GB RocksDB block cache, `debug_traceBlockByNumber` 8x. With
those settings every fetcher is faster than Blockscout's default concurrency can use across a network
hop (section 5): **the node is no longer the bound; the explorer's per-fetcher concurrency x batch
over the round trip is.** Responses are byte-identical to `main`'s.

## 1. Workload model: what Blockscout sends

Blockscout's source is not on this host; the method list comes from `../N42-26/scripts/verify-blockscout-rpc.sh`
and `../N42-26/docker/blockscout.env`, `../N42-gov5/deployments/explorer/config.env` (geth variant,
`INDEXER_INTERNAL_TRANSACTIONS_TRACER_TYPE=callTracer`, HTTP + WS endpoints), the request shapes and
defaults from Blockscout's documented indexer environment variables. Assumptions are marked (A).

| Fetcher | Request (geth variant) | Batch x concurrency (Blockscout default env) |
|---|---|---|
| catch-up blocks | `eth_getBlockByNumber(n, true)` | 10 x 10 (`INDEXER_CATCHUP_BLOCKS_BATCH_SIZE`, `_CONCURRENCY`) |
| receipts | `eth_getTransactionReceipt(h)` per transaction | 250 x 10 (`INDEXER_RECEIPTS_BATCH_SIZE`, `_CONCURRENCY`) |
| receipts, per block (A: newer releases can use it) | `eth_getBlockReceipts(n)` | 10 x 10 (same as blocks) |
| internal transactions | `debug_traceTransaction(h, {tracer: callTracer, timeout})` per transaction | 10 x 4 (`INDEXER_INTERNAL_TRANSACTIONS_BATCH_SIZE`, `_CONCURRENCY`) |
| internal transactions, by block | `debug_traceBlockByNumber(n, {tracer: callTracer})` (`ETHEREUM_JSONRPC_GETH_TRACE_BY_BLOCK=true`; default off (A)) | 10 x 4 |
| coin balances | `eth_getBalance(addr, n)` for every address a block touches (from, to, miner), at that block: historical state | 500 x 4 (`INDEXER_COIN_BALANCES_BATCH_SIZE`, `_CONCURRENCY`) |
| token balances | `eth_call({to: token, data: balanceOf(holder)}, n)` | 100 x 10 (`INDEXER_TOKEN_BALANCES_BATCH_SIZE`, `_CONCURRENCY`) |
| contract code | `eth_getCode(addr, n)` | 50 x 4 (A) |
| realtime | WS `eth_subscribe newHeads`, then the head block as above | 1 |

Every fetcher sends JSON-RPC **batches** over keep-alive HTTP at a fixed concurrency, so the node sees
at most 4-10 requests at a time, each carrying 10-500 calls. The load generator reproduces exactly
that: each fetcher is `concurrency` worker processes pulling batches from a shared counter
(`--set fetcher.batch=N` / `fetcher.conc=N` override), measuring per-request latency, calls/s,
blocks/s, MB/s, errors and the node's CPU over the run (utime+stime from `/proc`). `--rtt-ms R
[--mbps M]` adds a network hop per request (R ms plus the response size at M Mbit/s), because with a
fixed concurrency a fetcher's ceiling is `concurrency x batch / (rtt + transfer + service time)`:
running with and without the hop tells a node-bound fetcher from a latency-bound one.
The client forks its workers (Python 3.14 defaults to `forkserver`, which unpickled the work list in
every worker and made the client the bound in the first runs) and decodes only answers that carry an
error or a null result, so it costs the bytes, not a JSON decode.

Not modelled: Blockscout's own database writes (they are the explorer's cost), token-instance and
NFT metadata fetchers, `trace_*` (parity variant). The chain carries plain transfers only (see 2), so
`tokens` calls an address without code (the request still opens historical state at the block) and
internal-transaction traces are single frames; the trace cache's correctness was checked with
`callTracer`, `callTracer{withLog}`, `flatCallTracer` and `prestateTracer`.

## 2. Setup

- Chain: a reflink copy of the catch-up bench member `m0` (`/data/n42-build/p1-catchup`, profile-1
  genesis, QMDB, 2,277 blocks, 14.9M transfers) under `/data/n42-build/explorer-rpc/chain`, served by
  one `n42 node` with no validator (the chain stands still; every request is a read),
  `--http.api eth,net,web3,txpool,debug,trace --ws`.
- Two ranges: **sparse** = blocks 200-399 (200 blocks, 199,440 transactions, ~1,000 a block,
  200,629 address-block pairs) and **dense** = blocks 1150-1249 (100 blocks, 2,285,700
  transactions, ~22,860 a block, 2,045,043 pairs). A testnet at 30 tx/s with 8 s blocks has ~240
  transactions a block, closer to the sparse range.
- Binary: `cargo build --profile profiling` of `origin/main` c3e028040 (base) and of this branch.
- Host: 256 threads, shared with other lanes; every run waits until other processes use under 12
  cores (`explorer-suite.sh`). `perf` is not available (`perf_event_paranoid=4`, a host setting this
  lane does not change), so CPU per method is the node's CPU over a single-fetcher run divided by its
  calls (`us/call` below) and CPU by thread name (`explorer-threads.py`).
- Correctness: `explorer-load.py dump` (two batches of every fetcher on 3 sparse and 1 dense block)
  and `/data/n42-build/explorer-rpc/trace-sample.py` (240 `debug_traceTransaction` answers: the
  first 12 and last 3 transactions of 4 blocks under four tracer configurations) are byte-identical
  between the base binary and this branch with the trace cache on and with batch concurrency 16
  (`/data/n42-build/explorer-rpc/diff/`).

## 3. Baseline (main, profile-1 defaults)

`S0` = base binary, default flags (profile-1 memory defaults on: `--cpu-cores 8`, 8 jemalloc arenas,
RocksDB block cache 32 MB). Each fetcher runs alone; blocks/s = calls/s over the calls a block needs;
`cores` = node CPU during the run; `us/call` = node CPU per call.

| range | fetcher (batch x conc) | calls/s | blocks/s | p50 / p99 ms | node cores | us CPU / call |
|---|---|---|---|---|---|---|
| sparse | blocks (10x10) | 1,930 | 1,930 | 45 / 51 | 6.7 | 3,451 |
| sparse | receipts (250x10) | 88,601 | 89 | 28 / 32 | 9.9 | 112 |
| sparse | block-receipts (10x10) | 1,106 | 1,106 | 71 / 94 | 5.6 | 5,100 |
| sparse | trace-tx (10x4) | 858 | **0.87** | 40 / 167 | 4.0 | 4,625 |
| sparse | trace-block (10x4) | 160 | 160 | 247 / 264 | 3.9 | 24,235 |
| sparse | balances (500x4) | 81,466 | 81 | 24 / 28 | 4.1 | 50 |
| sparse | tokens (100x10) | 176,306 | 176 | 5.5 / 5.9 | 9.8 | 56 |
| sparse | code (50x4) | 81,317 | 4,085 | 2.0 / 6.8 | 3.5 | 43 |
| dense | blocks | 75 | 75 | 1,233 / 1,283 | 7.1 | 94,786 |
| dense | receipts | 85,110 | 3.7 | 29 / 35 | 9.9 | 116 |
| dense | block-receipts | -- | -- | 745 / 1,225 | 5.4 | every batch refused |
| dense | trace-tx | **97** | **0.004** | 391 / 909 | 3.9 | 40,641 |
| dense | trace-block | 6.7 | 6.7 | 5,067 / 5,162 | 3.3 | 492,537 |
| dense | balances | 98,208 | 4.8 | 20 / 22 | 4.1 | 42 |
| dense | tokens | 190,064 | 9.3 | 5.4 / 6.5 | 9.7 | 51 |
| dense | code | 41,633 | 2,082 | 1.8 / 3.8 | 1.7 | 40 |

What it says:

1. **Internal transactions are the bottleneck.** `debug_traceTransaction` re-executes transactions
   `0..i` of the block before tracing `i` (reth `DebugApi::debug_trace_transaction` ->
   `inspect_transaction_in_block`): 4.6 ms of CPU per transaction at ~1,000 a block, 41 ms at ~22,860.
   The same blocks traced whole (`debug_traceBlockByNumber`) cost 24 us (sparse) and 22 us (dense) per
   transaction. Blockscout's geth variant traces per transaction unless
   `ETHEREUM_JSONRPC_GETH_TRACE_BY_BLOCK=true`.
2. **The node uses 4-10 cores, whatever the host has.** Each fetcher's node CPU equals its connection
   count: jsonrpsee 0.26 (`RpcService::batch`) awaits a batch's calls one after the other, and
   Blockscout sends everything as batches at a concurrency of 4-10.
3. **Historical state is not the dominant cost.** `eth_getBalance` and `eth_call` at the block of every
   address (2 million address-block pairs on the dense range) cost 40-56 us of CPU a call, below a
   receipt (112 us). With `N42_ACCOUNT_HISTORY` at its default the history index answers them (the
   QMDB reader hooks serve latest-state reads; historical reads go to MDBX and RocksDB). Their one
   sensitivity is the RocksDB block cache (point 5).
4. **Limits hit:** `eth_getBlockReceipts` batches of 10 dense blocks exceed reth's 160 MB
   `--rpc.max-response-size` (`-32011 The batch response was too large`); an explorer would retry them
   forever. No connection, tracing-permit or request-size limit was hit (a 500-call batch is 90 KB).
5. **Profile-1 memory defaults** (`S1`, `N42_P1_MEMORY=0`, base binary): tracing is 1.2-2.3x faster
   without them (`trace-block` 160 -> 361 blocks/s sparse, 6.7 -> 13.8 dense; `trace-tx` 858 -> 1,030),
   balances 1.3x on the sparse range; the rest within noise. Step 4 below pins this on the profile's
   32 MB RocksDB block cache, not on its 8 cores: `--cpu-cores 8` does not throttle RPC once batches
   run concurrently, and is the better setting for the small calls (step "rejected" below).

## 4. Steps

Each row is a full suite (`scripts/explorer-suite.sh`, 40 s cap per fetcher and range) on a fresh start
of the node, waiting for other lanes' load to drop under 12 cores before each run; calls/s, node cores
in brackets. Responses checked after every code step (section 2).

| step | change | fetcher (range) | before | after |
|---|---|---|---|---|
| 1 | `debug_traceTransaction` from a once-per-block trace (`bin/n42/src/trace_cache.rs`, on by default) | trace-tx sparse | 858 (4.0) | 25,603 (2.0) |
| | | trace-tx dense | 97 (3.9) | 30,154 (2.2) |
| | | everything else | | within noise (same code path) |
| 2 | a batch's calls run concurrently, `N42_RPC_BATCH_CONCURRENCY=16` (`crates/n42/engine-types/src/rpc_batch.rs`) | receipts sparse / dense | 86,784 (9.9) / 84,165 (9.9) | 212,685 (43.6) / 208,600 (42.5) |
| | | balances sparse / dense | 81,532 (4.1) / 96,086 (4.1) | 223,135 (40.9) / 218,793 (40.8) |
| | | tokens sparse / dense | 187,868 (9.7) / 180,315 (9.9) | 223,513 (23.0) / 229,128 (21.4) |
| | | code sparse / dense | 83,199 (3.3) / 42,367 (1.7) | 158,188 (25.4) / 57,958 (7.8) |
| | | trace-block sparse / dense | 161 (3.9) / 6.8 (3.3) | 856 (25.1) / 41.3 (24.4) |
| | | trace-tx sparse / dense | 25,603 / 30,154 | 32,822 / 29,964 |
| | | blocks sparse / dense | 1,749 / 73 | 1,898 / 63 |
| 3 | `--rpc.max-response-size 1024` (MB) | block-receipts dense | every batch refused | answered |
| 4 | `--db.rocksdb-block-cache-size 1GB` (profile 1: 32 MB) | trace-block sparse / dense | 856 / 41.3 | 1,351 (23.9) / 54.5 (21.7) |
| | | trace-tx sparse / dense | 32,822 / 29,964 | 72,816 (6.9) / 81,089 (7.9) |
| | | everything else | | within 5% |
| -- | rejected: `N42_P1_CORES=0` (host cores for tokio and rayon) on top of 2 | receipts | 212,685 (43.6) | 211,827 (**169.7**) |
| | | tokens | 223,513 (23.0) | 196,339 (**176.9**) |
| | | blocks dense | 63 | 117 (33.6) |
| -- | rejected: `N42_P1_MEMORY=0` on top of 2-3 | as `N42_P1_CORES=0`; its tracing gain is step 4's | | |
| -- | no effect: `--engine.cross-block-cache-size 4096` on top of 4; `RETH_RAYON_RPC_THREADS=32` | all | | within noise |

The recommended configuration is step 4 (`S7`); against the baseline (`S0`):

| fetcher | sparse S0 -> S7 (calls/s) | dense S0 -> S7 (calls/s) | node cores S7 (sparse / dense) |
|---|---|---|---|
| blocks | 1,930 -> 1,901 | 75 -> 70 | 17 / 17 |
| receipts | 88,601 -> 214,027 (2.4x) | 85,110 -> 210,258 (2.5x) | 39 / 41 |
| block-receipts | 1,106 -> 1,171 | refused -> 40 blocks/s | 6 / 6 |
| trace-tx | 858 -> 72,816 (**85x**) | 97 -> 81,089 (**836x**) | 7 / 8 |
| trace-block | 160 -> 1,351 (8.4x) | 6.7 -> 54.5 (8.2x) | 24 / 22 |
| balances | 81,466 -> 223,547 (2.7x) | 98,208 -> 217,457 (2.2x) | 41 / 41 |
| tokens | 176,306 -> 225,723 (1.3x) | 190,064 -> 226,500 (1.2x) | 22 / 23 |
| code | 81,317 -> 155,405 (1.9x) | 41,633 -> 57,070 (1.4x) | 25 / 6 |

Step 1, how: for `callTracer`, `flatCallTracer` and `prestateTracer` (the options minus `timeout` are
the key; JS tracers, the struct logger and blocks under 4 transactions go to reth's handler unchanged)
the node locates the transaction (`transaction_by_hash_with_meta`, `block_body_indices`), traces its
whole block once through reth's own `debug_traceBlockByHash` handler (same tracing permit, same
replay), keeps every transaction's result in an LRU bounded by transactions (`N42_TRACE_BLOCK_CACHE_TXS`,
default 200,000; a 22,860-transfer block's results are ~10 MB) and answers from it. Concurrent requests
for one block wait for the one trace (`tokio::sync::OnceCell`); a block whose trace fails is remembered
and its transactions take reth's path. A transaction's result is the one the per-transaction path
computes: same parent state, same preceding transactions, same tracer, same transaction context.
7 unit tests (`trace_cache_tests.rs`: reuse, single flight, the key, fallbacks, eviction, the JSON-RPC
surface); 240 sampled answers byte-identical to `main`'s.

Step 2, how: `ConcurrentBatchLayer`, the RPC middleware of `N42Node`'s add-ons, runs a batch's calls as
tokio tasks, at most `N42_RPC_BATCH_CONCURRENCY` at a time (default 1: jsonrpsee's own sequential
handler, unchanged), and assembles the answers in request order with jsonrpsee's
`BatchResponseBuilder` under the node's `--rpc.max-response-size`, so an oversized batch gets the same
`-32011`; notifications and invalid entries are handled as jsonrpsee does. 3 unit tests on a real
jsonrpsee server (peak concurrency = the limit, answers identical to the sequential path, errors,
notifications, the size bound). The layer sits inside reth's RPC metrics layer, so the metrics are
as on `main` (batches per transport, `calls_batched_total` per method).

Why `N42_P1_CORES=0` is rejected: with 256 tokio workers the small calls (receipts, balances, tokens)
burn 4-8x the CPU for the same or lower throughput. They plateau at ~210-230k calls/s on either
setting (a serial point inside the node, section 8), so extra workers only contend. Only the dense
`eth_getBlockByNumber` (17 MB of JSON a block, serialised on the tokio workers) gains.

## 5. Node-bound or latency-bound: a network hop

The explorer runs on another host. With a fixed concurrency `c` and batch `b`, a fetcher moves at most
`c x b / (rtt + transfer + service)` calls a second. `--rtt-ms R` adds R ms to every request (after the
answer, inside the measured latency); `--mbps M` adds the answer's transfer time at M Mbit/s. Calls/s:

| fetcher (b x c) | range | loopback main / branch | 10 ms main / branch | 50 ms main / branch | 10 ms + 1 Gbit/s branch | ceiling c x b / rtt at 10 / 50 ms |
|---|---|---|---|---|---|---|
| blocks (10x10) | sparse | 1,930 / 1,901 | 1,635 / 1,643 | 984 / 931 | 849 | 10,000 / 2,000 blocks/s |
| blocks | dense | 75 / 70 | 73 / 73 | 63 / 68 | 36 | same |
| receipts (250x10) | sparse | 88,601 / 214,027 | 65,550 / 138,475 | 31,646 / 45,789 | 122,135 | 250,000 / 50,000 |
| receipts | dense | 85,110 / 210,258 | 65,030 / 142,306 | 32,333 / 45,361 | 129,399 | same |
| trace-tx (10x4) | sparse | 858 / 72,816 | 722 / 3,733 | 433 / 784 | 3,698 | 4,000 / 800 |
| trace-tx | dense | 97 / 81,089 | 96 / 3,745 | 93 / 785 | 3,742 | same |
| balances (500x4) | sparse | 81,466 / 223,547 | 66,288 / 128,217 | 26,636 / 35,971 | 132,051 | 200,000 / 40,000 |
| balances | dense | 98,208 / 217,457 | 70,787 / 134,049 | 30,525 / 36,059 | 133,768 | same |
| tokens (100x10) | sparse | 176,306 / 225,723 | 72,273 / 87,320 | 18,025 / 19,328 | -- | 100,000 / 20,000 |
| tokens | dense | 190,064 / 226,500 | 71,653 / 89,323 | 18,064 / 19,333 | -- | same |
| block-receipts (10x10) | sparse / dense | 1,106 / 1,171; refused / 40 | -- | -- | 425 / 18 | 10,000 / 2,000 blocks/s |

"main" = `S0` (base binary, defaults), "branch" = `S7` (section 6). `--mbps` charges each connection
the full link rate (a shared link divides it by the concurrency), so the 1 Gbit/s column is an upper
bound for the large answers.

Reading it:

- **trace-tx**: on `main` node-bound at any hop (722 / 433 tx/s sparse, 96 / 93 dense at 10 / 50 ms,
  as on loopback: the O(n^2) replay). On the branch it sits on the latency ceiling, 3,733 at 10 ms and
  784 at 50 ms against 4,000 and 800: Blockscout's 10 x 4 = 40 transactions per round trip is now the
  bound. For a ~240-transaction testnet block that is 16 blocks/s at 10 ms, 3 at 50 ms.
- **receipts, balances**: the branch's service time (8-12 ms a batch) is small beside the hop, so it
  reaches 55-65% of the 10 ms ceiling and 90% of the 50 ms one; `main`'s 20-30 ms a batch keeps it at
  half the branch at 10 ms and 70-85% at 50 ms.
- **tokens**: both builds sit near the ceiling (4-5 ms a batch either way).
- **blocks**: latency plus serialisation on both builds (45 ms a 10-block batch sparse, 1.2 s dense);
  at 1 Gbit/s the dense blocks (17 MB each) are bandwidth-bound.

So with the branch every fetcher is bound by Blockscout's concurrency x batch over the hop; the lever
left is on the explorer's side (section 6).

## 6. Recommended settings for an explorer-serving node

Validator defaults are unchanged; these are for the node the explorer reads from (a profile-1 member's
execution layer with these flags serves it equally well; a non-validating node is preferable, so the
explorer's load never competes with block production).

```bash
N42_RPC_BATCH_CONCURRENCY=16 \
n42 node --chain <genesis> ... \
  --http --http.api eth,net,web3,debug,trace,txpool --ws --ws.api eth,net,web3 \
  --rpc.max-response-size 1024 \
  --db.rocksdb-block-cache-size 1GB
# kept: the profile-1 memory defaults (--cpu-cores 8; see section 4 "rejected")
# kept: N42_TRACE_BLOCK_CACHE_TXS=200000 (raise it if the explorer traces many large blocks out of
#       order), --rpc.max-tracing-requests (default host cores - 2), --rpc.max-connections (500)
```

`scripts/explorer-node.sh` starts exactly this on a copied datadir (`EX_ENV`, `EX_ARGS`).

On the Blockscout side (its environment), because with these settings the node outruns the hop:

- `INDEXER_INTERNAL_TRANSACTIONS_CONCURRENCY` (default 4) and `INDEXER_INTERNAL_TRANSACTIONS_BATCH_SIZE`
  (default 10): this fetcher moves 40 transactions per round trip; at 10 ms that is 4,000 transactions/s
  however fast the node. 16 x 50 moves 800 per round trip. Or `ETHEREUM_JSONRPC_GETH_TRACE_BY_BLOCK=true`
  (40 blocks per round trip; served by `debug_traceBlockByNumber`, steps 2 and 4).
- `INDEXER_CATCHUP_BLOCKS_CONCURRENCY` / `_BATCH_SIZE`, `INDEXER_RECEIPTS_CONCURRENCY`,
  `INDEXER_COIN_BALANCES_CONCURRENCY`: the same rule; the node holds ~200k calls/s per method.
- `INDEXER_DISABLE_INTERNAL_TRANSACTIONS_FETCHER=true` (N42-26's `blockscout.env`) is no longer needed
  for speed; it was set because tracing failed on the genesis, which `FIRST_BLOCK=1` avoids (reth
  refuses to trace block 0: `GenesisNotTraceable`).

## 7. Checklist for the remote (testnet) node

The explorer runs on another machine and nothing of its configuration was visible from here. To
compare the deployment with this reproduction:

1. **Startup arguments and environment** of the node the explorer reads (`ps -o args= -p <pid>`;
   `tr '\0' '\n' < /proc/<pid>/environ | grep -E 'N42_|MALLOC|RAYON|TOKIO'`): `--http.api` includes
   `debug` (and `trace`); `--ws` with `eth` in `--ws.api`; `--rpc.max-response-size`,
   `--rpc.max-connections`, `--rpc.max-tracing-requests`, `--db.rocksdb-block-cache-size`,
   `--cpu-cores`; `N42_RPC_BATCH_CONCURRENCY`, `N42_TRACE_BLOCK_CACHE_TXS`. `web3_clientVersion`
   names the commit: the trace cache and the batch layer exist only in builds containing this branch.
2. **Start-up log lines**: `profile 1 memory defaults: ...` (what the profile set) and
   `debug_traceTransaction answered from block traces ... max_txs=...` (the trace cache is on).
3. **Methods**: `../N42-26/scripts/verify-blockscout-rpc.sh <http> <ws>`; and
   `scripts/explorer-load.py --rpc <http> ws --ws <ws> --seconds 30`: newHeads must arrive once a block.
4. **The hop** from the explorer host: 20 x `curl -s -o /dev/null -w '%{time_total}\n' -X POST -H
   'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' <http>`
   for the RTT, one large `eth_getBlockByNumber(n, true)` for the bandwidth; place them in section 5.
5. **The node's RPC metrics** (`--metrics <addr>`, Prometheus text), read twice a minute apart while the
   explorer syncs. Calls inside a batch -- everything Blockscout sends -- are counted only in
   `reth_rpc_server_calls_batched_total{method}` (`calls_started/successful/failed_total` and
   `calls_time_seconds` cover single calls; checked on this node, the same on `main`); the batches in
   `reth_rpc_server_connections_batches_started_total` / `_finished_total` and
   `_batch_response_time_seconds` (quantiles) per transport, single requests in `_requests_started_total`
   / `_request_time_seconds`, connections in `_connections_opened_total`; the block and receipt caches in
   `reth_rpc_eth_cache_hits_total` and `_misses_total`. `calls_batched_total` per method over a minute is
   section 3-5's calls/s; batch response p50 in seconds while `debug_traceTransaction` dominates means
   the trace cache is off (or the build predates it); `-32011` in the explorer's log is the response
   size limit.
6. **The explorer's own settings and logs**: its `INDEXER_*` batch sizes and concurrencies,
   `ETHEREUM_JSONRPC_VARIANT`, `ETHEREUM_JSONRPC_GETH_TRACE_BY_BLOCK`, `ETHEREUM_JSONRPC_HTTP_TIMEOUT`,
   and its log for `-32011`, timeouts and re-queued ranges.
7. **The same load from the explorer host**: `scripts/explorer-load.py` is Python-stdlib only. Copy it
   there, `prepare --from A --to B` on a stretch of the testnet, then `run --fetchers <f>` per fetcher
   (`--pid` only on the node's host). Its numbers over the real network, beside section 5's, say which
   side is the bound.

## 8. What remains the bound

- **The explorer's concurrency over the round trip** (section 5) -- not the node -- for every fetcher
  at a realistic hop with Blockscout's default concurrency.
- **Inside the node, ~210-230k calls/s per method** for the small calls (receipts, balances, eth_call),
  on 8 or on 256 tokio workers alike: a serial point that more workers only contend on (CPU per call
  rises 4-8x). Not identified: `perf` is not allowed on this host and the thread names do not separate
  it (all `tokio-rt`). Candidates: reth's `EthStateCache` (one actor task serves every block and receipt
  lookup) and MDBX read-transaction setup per call. It is 50-100x above what a fetcher can draw across
  a 10 ms hop.
- **Dense `eth_getBlockByNumber`**: 17 MB of JSON a block, serialised on the tokio workers (70-117
  blocks/s, ~1.2 GB/s); any real link is the bound first.
- **`eth_getBlockReceipts` on 20k-transaction blocks**: 10-block batches are 160 MB+; with
  `--rpc.max-response-size 1024` they pass, at 40-66 blocks/s, 1.3-2.3 s a batch.
- Not measured here: contract-heavy blocks (this chain carries transfers only; deeper call trees make
  every trace and the cached results larger, the O(n^2) -> O(n) argument is unchanged), Blockscout's
  database side, the token-instance fetchers.

Next steps: run checklist 7 against the testnet node; if the explorer is latency-bound as expected,
raise its internal-transaction concurrency and batch size (or trace by block) first. On the node side,
find the ~220k calls/s serial point with a profiler on a host that allows one, and consider making the
explorer settings a named preset once the testnet confirms them.

