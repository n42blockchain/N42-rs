# Execution-path separation

N42-rs classifies execution on two independent axes: workload (`historical`
or `live`) and scheduling (`sequential`, intra-block `pevm`, or independent
blocks). A result is comparable only when both axes and the canonical-write
contract match.

| Stable path | Current entry | Canonical writes | What the number means |
| --- | --- | --- | --- |
| `historical_pevm` | External sibling `../pevm` research harness | None | Historical PEVM CPU/state-read throughput only |
| `historical_parallel_blocks` | Planned `n42-witness-replay`; independent witnessed blocks distributed to workers | None | Offline witness verification/replay throughput |
| `historical_sequential` | H2 `bodies_by_range` catch-up through ordered Engine API `newPayload` + FCU | Yes | Join/catch-up wall time and canonical execution cost |
| `live_sequential` | H2 leader build/import, follower proposal execution and commit FCU | Yes | Production live TPS and consensus cadence |

`live_pevm` is reserved but rejected before the raw Engine API adapter. The
current repository has no live PEVM executor that produces reth's complete
canonical execution output, receipts and state root. Sender-sharded transaction
selection or block-parallel historical replay must not be reported as live
parallel-EVM throughput.

The H2 range importer intentionally keeps one FCU per imported block for now.
Reth can stage short non-canonical chains, but changing a 1024-block range to a
single FCU without a real-engine restart/persistence E2E would turn a metrics
change into a recovery-semantics change. A bounded FCU interval can follow the
deferred test below.

## Metrics

- `n42_evm_path_duration_ms{path,phase}`
- `n42_evm_path_calls_total{path,phase,outcome}`

Engine outcomes are semantic, not merely RPC transport results:
`valid`, `invalid`, `syncing`, `accepted`, `error`, and `unsupported` are kept
separate. Payload resolution additionally uses `ok` and `missing`.

Live phases include build-start FCU, payload resolution, payload build,
`newPayload`, and commit FCU. Historical range imports use the same phase names
under `historical_sequential`, so dashboards can compare phase cost without
adding unrelated throughput series together.

## Deferred qualification

1. Start a Rust chain thousands of blocks ahead, join a late member and cross
   multiple 1024-block range requests against a real reth Engine API.
2. Repeat with process termination at every proposed FCU/persistence boundary;
   verify identical canonical head and state root after restart.
3. Only then A/B a small FCU interval (start with 4, hard-cap at 16) against the
   per-block baseline.
4. Before `live_pevm` can be enabled, require sequential differential blocks
   covering receipts, logs, state roots, SELFDESTRUCT/CREATE2, EIP-161, EIP-7702,
   pre/post-Prague rules, coinbase observation, and abort/re-execution cascades.
5. Run one-minute live tests with path-labelled phase latency, CPU, RSS, disk and
   network counters; never merge historical paths into the live TPS series.
