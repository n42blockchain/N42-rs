# Runtime knob reference (N42_* environment variables)

**Profiles.** `N42_PROFILE=x22` on `n42` and `h2_validator` applies the adopted configuration: at the
first statement of `main`, before any knob is read, every knob whose status below is `adopted` is set
to its X22 value unless the environment already sets it (a set knob always wins, `=0` included); the
binary prints one stderr line naming how many it set and which it kept. An unknown profile name exits
with status 2; unset, blank or `none` applies nothing. The table and its values live in
`crates/n42/env/src/profile.rs`, and a test there fails when its knobs and the `adopted` rows of this
file differ, so changing a row's status means changing the profile in the same commit. Since
2026-10-27 the profile reproduces the node-side environment of an X22 leg (loop351 stage fl): the
adopted stage sets X3..X22, the X22 base set (the loop351 `ALLA` line and its per-leg additions, each
row noting "X22 base set: `value`"), and the tuned values whose compiled default differs. Two groups
stay with the launcher: the `bench-only` rows the leg also passes (`N42_BENCH_UNSAFE`, which the gateway and the direct ingest need, `N42_FRAME_GATEWAYS`,
`N42_FRAME_ATTEST_MIN`, `N42_IMPORT_ONCE`, `N42_HASHED_TABLES=off`, `N42_QMDB_READS=on`,
`N42_ACCOUNT_HISTORY=off`, `N42_CANON_NOTIFY_LEAN=1`, `N42_SETTLEMENT_TAGS=legacy`, `N42_PERSIST_QMDB_IN_SCOPE=1`,
`N42_STORAGE_OP_METRICS=0`, `N42_LOCK_SITES=1`), and the non-`N42_*` variables `MALLOC_CONF`,
`TOKIO_WORKER_THREADS`, `RAYON_NUM_THREADS`. A knob whose Meaning says "Needs `frameBlocks` in the
genesis" is chain-gated: once the chain spec is parsed, and before any such knob is read, the binary
removes it again when the profile set it on a chain whose genesis does not set `frameBlocks: true`
(one stderr line names them); a value the operator set is never touched, so an explicit
`N42_FRAME_BLOCKS=1` on such a chain is still refused at start-up.

**Truthiness (since the knob-profile branch).** Every former presence-only and `!= "0"` switch is read
by `n42_env::flag`: on = `1|true|on|yes`, off = `0|false|off|no|""` (case-insensitive, trimmed),
anything else warns once and reads the default; so notes 4-5 below describe the tree before it.
Since audit 2026-10 E-10 every switch the x22 profile sets to `1` is read the same way (a test in
`crates/n42/env/src/profile.rs` scans the sources for one compared with `== "1"`); other `== "1"`
switches are unchanged. **An empty value is off**, also for a default-on switch: `NAME=` turns off
`N42_PARALLEL_STATE_COMMIT` or `N42_FOLLOWER_EXEC_GATE`, where unsetting the variable keeps the default.

1. Generated from an audit of the tree at commit 393cc1e70 (audit/maturity-2026-10): 273 knobs, plus the four the hardening branches added (`N42_TX_INGEST_ALLOW_REMOTE`, `N42_PAYLOAD_SERVE_ALLOW_REMOTE`, `N42_BENCH_UNSAFE`, `N42_RAW_CHANNEL_TIMEOUT_MS`) read by code under bin/n42, crates/n42, crates/chain-state and crates/storage; none is read from a config file or CLI flag.
2. Almost every knob is read once, behind a `OnceLock`/`static`, at first use. Set it in the environment before the process starts; changing it afterwards has no effect. A few are read at service construction without a cache ("startup"), still once per process.
3. No knob is read per call any more: the one HOT read the audit found, `N42_OWN_BLOCK_BY_HEADER` on the engine path in `crates/n42/h2-el-rpc/src/engine.rs`, is behind a `OnceLock` since audit/h2-hardening (`647f6709d`).
4. Truthiness is not uniform. Most switches test exactly `== "1"`; default-on switches test `!= "0"` (so `0` disables, anything else keeps them on); the `SF_*` knobs accept `1`/`on`/`true`; `N42_ACCOUNT_HISTORY` wants `off`; `N42_QMDB_READS` enables on any non-empty value other than `off`.
5. Fifteen knobs enable on any value, so `NAME=0` still turns them on (13 presence-only via `.is_ok()`, 2 "anything but `0`" where unset is off and an empty value enables): BLOCK_TOPIC_ALWAYS, FOLLOWER_DIRECT_IMPORT, FOLLOWER_EXEC_PROBE, NO_OWN_BLOCK_REUSE, PARALLEL_BUILD, PAYLOAD_SERVE_FRESH_BUFFERS, PRUNE_POOL_ON_IMPORT, TX_INGEST_ASYNC, TX_INGEST_DIRECT, TX_INGEST_UNBUFFERED, TX_QUEUE, TX_QUEUE_DRAINER, TWIG_NO_SIMD, BUILD_CHAIN, BUILD_ON_SEAL.
6. Same name, different effective condition: `N42_COMPACT_BODY` and `N42_BLOCK_BY_DESCRIPTION` are ANDed with `N42_BODY_ONCE` in h2-execution but not in tx-queue; `N42_BUILD_AHEAD_GATE` has two parsers (engine.rs accepts `seal|qc|send`, tx-queue only tests `seal`).
7. `N42_ED25519_BATCH` has a default conflict: 64 (max 256) in production (`tx-types/src/sender_cache.rs:203`) against 128 in an `#[ignore]`d timing test (`tx-types/src/alt_sig.rs:847`); the production value is 64, as CLAUDE.md says.
8. Several knobs are read independently in two places with the same rule (`N42_PARALLEL_STATE_COMMIT`, `N42_BUILD_ON_SEAL`, `N42_TENURE_FIRST_ON_OUTPUT`, `N42_VOTE_BEFORE_SLOT`, `N42_TX_QUEUE_DRAINER`, `N42_PAYLOAD_SERVE`, `N42_INGEST_VERIFY`); set them once, both sites see the environment.
9. Status: `adopted` = part of the measured X22 configuration (the cumulative X11..X22 stage sets in `scripts/fleet7-runs/run-loop351.sh` stage az and `docs/BREAKTHROUGH_DESIGN.md` rounds 10.193-10.230; stages after az live in the bench tree, so X13-X22 additions come from those rounds), `default` = on or tuned by a built-in default (an X22 value that differs from it makes the row `adopted`), `experimental` = measured and not adopted, `bench-only`, `unsafe-bench` (drops a safety property or is called a probe in code), `undocumented-before` (no mention in docs/ or CLAUDE.md before this file), `unknown` = documented but not classifiable from the docs. Dead names are listed at the end.
10. "Where read" is `crate:file:line` from the audit and drifts with edits; grep the knob name for the current site.


Status caveat: `adopted` follows the stage sets named above plus the X22 base set (2026-10-27); `experimental` means the knob appears in a measured round or a loop351 stage and is not in X22; `unknown` and the Meaning column (a truncated code-comment excerpt recovered by the audit) deserve a human pass.

## Node wiring (bin/n42)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_ANSWER_AT_INSERT` | off (1 enables) | `1` | Answer a deferred newPayload at insert (raw payload channel); logged at first read. | `bin/n42:answer_at_insert.rs:90` | adopted |
| `N42_BUILD_ON_OUTPUT` | off | `1` (or the knob's own value; see code) | N42_BUILD_ON_OUTPUT=1: a build on an own block starts at the parent's seal instead of at its StateReady (plan v6 attempt J). Off by default. X22 base set: `1`. | `bin/n42:payload_serve.rs:1389` | adopted |
| `N42_BUILD_ON_SEAL` | off (any value but 0 enables) | any value except `0` (empty enables) | Whether the validators build on seal (N42_BUILD_ON_SEAL, the same variable the validator reads; the fleet launcher sets it for both). It decides ... X22 base set: `1`. | `bin/n42:payload_serve.rs:1847; h2-node:service.rs:1203` | adopted |
| `N42_BUILD_START_ASYNC` | off | `1` (or the knob's own value; see code) | N42_BUILD_START_ASYNC=1 (plan v6, the seal gap's first term): the queue's hand-off of an own block -- the fold of its nonces and the partition of... X22 base set: `1`. | `bin/n42:payload_serve.rs:1354` | adopted |
| `N42_CARRY_ASYNC` | off | `1` (or the knob's own value; see code) | (N42_CARRY_ASYNC=1) instead of on the path the validator's vote waits for. Nothing reads the carry until the next block, ~650 ms later. | `bin/n42:follower_import.rs:3646` | unknown |
| `N42_CHECK_ON_PARENT_OUTPUT` | on (0 disables) | on unless `0` | by default; N42_CHECK_ON_PARENT_OUTPUT=0 turns it off. A follower's vote waited ~200 ms for the previous import to finish (loop155 A2: its carry,... | `bin/n42:follower_import.rs:354` | default |
| `N42_COMPACT_BODY_FILL` | 2 | integer | The largest miss worth asking for, as one part in N42_COMPACT_BODY_FILL of the block: 2 by default, so up to half a block is fetched by index. Ab... | `bin/n42:payload_serve.rs:1882` | undocumented-before |
| `N42_COMPACT_BODY_WAIT` | 20 | integer | ms the follower waits for the copy running beside the import. | `bin/n42:payload_serve.rs:1903` | undocumented-before |
| `N42_DIRECT_FAST_ANSWER` | off | `1` (or the knob's own value; see code) | the engine's own newPayload run behind the answer (N42_DIRECT_FAST_ANSWER=1, off by default). The block was validated here; the engine's pass i... | `bin/n42:payload_serve.rs:4078` | unknown |
| `N42_FOLLOWER_CHECK_ON_SHARDS` | on (0 disables) | on unless `0` | Child check/execution reads the parent through its kept shards; 0 waits for the merge. | `bin/n42:follower_import.rs:435` | undocumented-before |
| `N42_FOLLOWER_CHECK_THREADS` | 4 | integer | (N42_FOLLOWER_CHECK_THREADS, default 4), away from the execution's batches. The check takes no lock another check could hold. | `bin/n42:follower_import.rs:3694` | undocumented-before |
| `N42_FOLLOWER_COPY_ASIDE` | off | `1` (or the knob's own value; see code) | N42_FOLLOWER_COPY_ASIDE=1 (default off): a described block's owned RecoveredBlock -- the 163,000 transactions copied out of the queue, the seal... X22 base set: `1`. | `bin/n42:follower_import.rs:1637` | adopted |
| `N42_FOLLOWER_DIRECT_IMPORT` | off (any value enables) | presence only (`=0` still counts) | Execute another node's block with the plain block executor and check it against its header (main.rs wiring). | `bin/n42:main.rs:512` | experimental |
| `N42_FOLLOWER_EXEC_EARLY` | off | `1` (or the knob's own value; see code) | N42_FOLLOWER_EXEC_EARLY=1 (section 5 of docs/BREAKTHROUGH_DESIGN.md, step 5a): under deferred execution the block's execution starts the moment... X22 base set: `1`. | `bin/n42:follower_import.rs:3670` | adopted |
| `N42_FOLLOWER_EXEC_GATE` | on (0 disables) | on unless `0` | Takes the execution gate; N42_FOLLOWER_EXEC_GATE=0 runs without one. **One, not two.** The imports of several blocks are in flight at once by des... | `bin/n42:follower_import.rs:3636` | undocumented-before |
| `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT` | on (0 disables) | on unless `0` | N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT=0 turns it off. The follower-side twin of the leader's opener_on_built_parent (plan v4 step 2). It reads the... | `bin/n42:follower_import.rs:382` | default |
| `N42_FOLLOWER_EXEC_PROBE` | off (any value enables) | presence only (`=0` still counts) | After engine import, execute the foreign block once more with the plain executor (probe). | `bin/n42:main.rs:526` | unsafe-bench |
| `N42_FOLLOWER_FIELDS_EARLY` | off | `1` (or the knob's own value; see code) | N42_FOLLOWER_FIELDS_EARLY=1 (step 5a): under deferred execution this block's QMDB root -- the last of its execution fields, the one its child's v... X22 base set: `1`. | `bin/n42:follower_import.rs:3712` | adopted |
| `N42_FOLLOWER_PARALLEL` | off | `1` (or the knob's own value; see code) | A block of plain transfers executes on the worker pool (parallel_transfer). X22 base set: `1`. | `bin/n42:follower_import.rs:3757` | adopted |
| `N42_FOLLOWER_ROOT_ON_BUILD_POOL` | off | `1` (or the knob's own value; see code) | Run the follower QMDB root on the build pool. X22 base set: `1`. | `bin/n42:follower_import.rs:3746` | adopted |
| `N42_FOLLOWER_ROOT_THREADS` | 8 | integer | (N42_FOLLOWER_ROOT_THREADS, default 8). One root at a time: the forest's mutex is taken inside, on one of this pool's workers, and a worker that ... | `bin/n42:follower_import.rs:3735` | undocumented-before |
| `N42_FOLLOWER_SHARDS_KEPT` | 2 (valid 1..=8) | integer | FOLLOWER_SHARDS_KEPT, overridden by N42_FOLLOWER_SHARDS_KEPT (1..=8), as parent_outputs_kept. Read once. | `bin/n42:follower_import.rs:426` | default |
| `N42_HANDOFF_HEAD_MOVE` | not-parent (number alternative) | see Default | N42_HANDOFF_HEAD_MOVE, read once. The head move exists for one case: reth's tree drops an executed insert whose number is at or below its canonic... | `bin/n42:payload_serve.rs:495` | adopted |
| `N42_HANDOFF_ON_LANDED` | off | `1` (or the knob's own value; see code) | N42_HANDOFF_ON_LANDED=1, read once: a block executed on its parent's published output is handed to the engine once the parent's own direct import... | `bin/n42:follower_import.rs:116,3834` | experimental |
| `N42_HASHED_STATE` | on (0 disables) | on unless `0` | **N42_HASHED_STATE=0 stops the chain.** It is kept as the one-line reproduction, not as an option: loop106 ran it twice and the fleet produced ze... | `bin/n42:follower_import.rs:3607` | default |
| `N42_IMPORT_ONCE` | off | `1` (or the knob's own value; see code) | Several validator keys on one execution layer share each import (raw payload channel). Bench-only: seven validator keys on one execution layer, a bench topology. | `bin/n42:import_once.rs:45` | bench-only |
| `N42_NO_OWN_BLOCK_REUSE` | unset: own-block reuse on (any value disables) | presence only (`=0` still counts) | Disables reuse of the build's execution for the node's own sealed blocks. | `bin/n42:main.rs:493` | undocumented-before |
| `N42_PARALLEL_STATE_COMMIT` | on (0 disables) | on unless `0` | QMDB leaves and hashed post-state built on the worker pool; 0 = serial. | `bin/n42:follower_import.rs:3768; engine-types:assembler.rs:549` | default |
| `N42_PARENT_OUTPUTS_KEPT` | 4 (valid 2..=16) | integer | How many published outputs are kept, by N42_PARENT_OUTPUTS_KEPT (2..=16, default PARENT_OUTPUTS_KEPT). The check and the execution stack the unla... | `bin/n42:follower_import.rs:310` | default |
| `N42_PAYLOAD_SERVE` | unset: raw payload channel off (value: SocketAddr) | see Default | Address of the loopback raw payload channel beside the Engine API. | `bin/n42:main.rs:327,483` | unknown |
| `N42_PAYLOAD_SERVE_ALLOW_REMOTE` | off (1 enables) | `1` | Allow the raw payload channel to bind off loopback; refused otherwise (audit/ingest-hardening). | `bin/n42:payload_serve.rs` | default |
| `N42_PAYLOAD_SERVE_FRESH_BUFFERS` | off (any value enables) | presence only (`=0` still counts) | Payload serve uses fresh buffers per answer. | `bin/n42:payload_serve.rs:1911` | undocumented-before |
| `N42_PRUNE_ASYNC` | on (0 disables) | on unless `0` | (default; N42_PRUNE_ASYNC=0 makes the answer wait for it, the behaviour before round 43's loop98). | `bin/n42:payload_serve.rs:4086` | default |
| `N42_PRUNE_FEED_LEAN` | off | `1` (or the knob's own value; see code) | N42_PRUNE_FEED_LEAN=1 carries lean block summaries to the pruning thread instead of whole canonical notifications; default off, read and logged o... | `bin/n42:queue_prune.rs:100` | experimental |
| `N42_PRUNE_FREE_INLINE` | off | `1` (or the knob's own value; see code) | (N42_PRUNE_FREE_INLINE=1, default off: they go to the queue's freeing thread through n42_tx_queue::free_later once the wake is pruned and logged)... | `bin/n42:queue_prune.rs:114` | experimental |
| `N42_PRUNE_MAX_FOLD` | 0 | integer | N42_PRUNE_MAX_FOLD=<n> (default 0, unbounded): the most blocks one wake of the pruning thread folds; what is over is carried into the next wake, ... | `bin/n42:queue_prune.rs:489` | undocumented-before |
| `N42_PRUNE_MIN_FOLD` | 1 | integer | N42_PRUNE_MIN_FOLD=<n> (default 1: off) and N42_PRUNE_MIN_FOLD_MS=<ms> (default 200), read and logged once: the pruning thread holds a wake unt... | `bin/n42:queue_prune.rs:472` | adopted |
| `N42_PRUNE_MIN_FOLD_MS` | 1 | integer | N42_PRUNE_MIN_FOLD=<n> (default 1: off) and N42_PRUNE_MIN_FOLD_MS=<ms> (default 200), read and logged once: the pruning thread holds a wake unt... | `bin/n42:queue_prune.rs:473` | default |
| `N42_PRUNE_POOL_ON_IMPORT` | off (any value enables) | presence only (`=0` still counts) | Remove an imported block's txs from reth pool at import (measured, not adopted). | `bin/n42:main.rs:541` | unknown |
| `N42_QUEUE_PRUNE_THREAD` | off (1) | `1` | Canonical queue pruner runs on its own thread. | `bin/n42:queue_prune.rs:148` | adopted |
| `N42_QUEUE_WORK_OFFLOAD` | off | `1` (or the knob's own value; see code) | on a worker thread (N42_QUEUE_WORK_OFFLOAD=1) instead of on this path. Inline it walks the block twice -- once for the mined senders and nonces, ... | `bin/n42:payload_serve.rs:4066` | unknown |
| `N42_RAW_SHARED_DECODE` | off | `1` (or the knob's own value; see code) | Decode raw payload as slices of one shared buffer copy. | `bin/n42:payload_serve.rs:1853` | undocumented-before |
| `N42_ROAD_DISPATCH_WAIT` | off | `1` (or the knob's own value; see code) | or on its own with N42_ROAD_DISPATCH_WAIT=1 for the baseline leg. Off, the request's first byte is read exactly as before and the field reads 0. | `bin/n42:road_runtime.rs:112` | unknown |
| `N42_ROAD_RUNTIME` | off | `1` (or the knob's own value; see code) | Whether the raw payload channel runs on its own runtime (N42_ROAD_RUNTIME=1, off by default). X22 base set: `1`. | `bin/n42:road_runtime.rs:36` | adopted |
| `N42_ROAD_RUNTIME_WORKERS` | 4 (clamped 1..=16) | integer | Workers of the frame road's runtime. | `bin/n42:road_runtime.rs:42` | default |
| `N42_ROOT_HASHED_PARALLEL` | on (0 disables) | on unless `0` | pool (default; N42_ROOT_HASHED_PARALLEL=0 runs them one after the other). They read the same bundle and neither needs the other: the pair measure... | `bin/n42:follower_import.rs:3657` | default |
| `N42_SHARDS_MERGE_OFF_PATH` | on_path (1 concurrent, verify) | see Default | Shard merge off the hand-off path: 1 both halves concurrently, verify compares with the old merge. | `bin/n42:follower_import.rs:237,3931` | default |
| `N42_TENURE_FIRST_ON_OUTPUT` | off | `1` (or the knob's own value; see code) | N42_TENURE_FIRST_ON_OUTPUT=1 (defect 18b, docs/FLEET7_PLAN_V4.md 7.13): a build request on a sealed parent this node did not build is served on... X22 base set: `1`. | `bin/n42:payload_serve.rs:1399; h2-node:service.rs:1022` | adopted |
| `N42_THP_DISABLE` | off (1) | `1` | prctl PR_SET_THP_DISABLE for this process. | `bin/n42:main.rs:50` | bench-only |
| `N42_TX_INGEST` | unset: ingest server off (value: SocketAddr) | see Default | Address of the transaction ingest server (unauthenticated; loopback). | `bin/n42:main.rs:802` | unknown |
| `N42_TX_INGEST_ALLOW_REMOTE` | off (1 enables) | `1` | Allow the ingest server to bind off loopback; refused outright with `N42_TX_INGEST_DIRECT`, `N42_INGEST_VERIFY=shard|leader` or attested frames (audit/ingest-hardening). | `bin/n42:main.rs` | default |
| `N42_BENCH_UNSAFE` | off (1 enables) | `1` | Start-up acknowledgement required before `N42_INGEST_VERIFY=shard|leader`, `N42_FRAME_GATEWAYS` or `N42_TX_INGEST_DIRECT` is accepted (audit/ingest-hardening; gateways and direct since audit 2026-10 C-2/C-3). | `bin/n42:main.rs` | bench-only |
| `N42_TX_QUEUE` | off (any value enables) | presence only (`=0` still counts) | Enable the builder's tx queue (fed by ingest, pruned per canonical block). | `bin/n42:main.rs:607` | experimental |
| `N42_TX_QUEUE_DRAINER` | off (any value enables) | presence only (`=0` still counts) | Drain the queue inbox off the builder thread. | `bin/n42:main.rs:609,620` | experimental |
| `N42_VOTE_BEFORE_SLOT` | off (1) | `1` | Vote before the slot (held execution); incompatible with IMPORT_ONCE. | `bin/n42:import_once.rs:62; h2-execution:driver.rs:172` | experimental |
| `N42_WATCHDOG_STACKS` | off (1) | `1` | Watchdog dumps every thread's stack. | `bin/n42:main.rs:564` | bench-only |

## Builder and follower execution (engine-types, deferred-reverts)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_ANSWER_BEFORE_REVERTS` | off | `1` (or the knob's own value; see code) | Leader builds answer before their revert set is merged. | `deferred-reverts:lib.rs:41` | adopted |
| `N42_BUILDER_PREFETCH` | 0 | integer | Transactions the builder takes ahead of execution to prefetch accounts (0 = off). | `engine-types:payload.rs:5930` | default |
| `N42_BUILDER_PULLER` | 0 | integer | Builder puller count (0 = execute inline). X22 base set: `1024` (compiled default differs). | `engine-types:payload.rs:5835` | adopted |
| `N42_BUILDER_STALE_CHECK` | off | `1` (or the knob's own value; see code) | Builder stale-parent check. | `engine-types:payload.rs:5820` | unknown |
| `N42_BUILD_BATCHES` | 0 | integer | N42_BUILD_BATCHES=<n> (docs/SHARED_EXECUTION_SCOPE.md 16.4 item 4): the build's transfers in n batches of about equal size (whole sender grou... X22 base set: `128` (compiled default differs). | `engine-types:parallel_transfer.rs:1531` | adopted |
| `N42_BUILD_COLLECT_IN_PLACE` | off | `1` (or the knob's own value; see code) | (N42_BUILD_COLLECT_IN_PLACE=1) instead of moving them into one vector before the receipts and the body are built from them. The collect is one se... X22 base set: `1`. | `engine-types:parallel_transfer.rs:1876` | adopted |
| `N42_BUILD_DECLINE_EMPTY_STEP` | on (0 disables) | on unless `0` | N42_BUILD_DECLINE_EMPTY_STEP=0 turns off after_parallel_step (the serial loop always runs); on by default. | `engine-types:payload.rs:1293` | undocumented-before |
| `N42_BUILD_GRAFT_NO_CACHE` | off | `1` (or the knob's own value; see code) | Whether N42_BUILD_GRAFT_NO_CACHE=1 is set (see the graft in the parallel step). | `engine-types:payload.rs:5800` | unknown |
| `N42_BUILD_MLP` | 0 | integer | (N42_BUILD_MLP=<k>, 0 or unset = off): before a batch runs transaction i it converts the transaction k places ahead in the batch's order (its... | `engine-types:parallel_transfer.rs:983` | default |
| `N42_BUILD_ONE_WAVE` | off | `1` (or the knob's own value; see code) | N42_BUILD_ONE_WAVE=1: the build's batches are one per pool thread at most (batch_groups_one_wave) and handed to the pool all at once (execute_for... | `engine-types:parallel_transfer.rs:1518` | experimental |
| `N42_BUILD_PREFETCH` | off | `1` (or the knob's own value; see code) | its execution (N42_BUILD_PREFETCH=1, WarmAccounts): each batch the puller hands over is read on the worker pool while the pull and the prep run, ... | `engine-types:parallel_transfer.rs:959` | experimental |
| `N42_BUILD_REFUSE_STALE_PARENT` | off | `1` (or the knob's own value; see code) | N42_BUILD_REFUSE_STALE_PARENT=1: a build whose parent is below what the queue has been pruned through answers "parent stale" instead of pulling a... | `engine-types:payload.rs:1286` | undocumented-before |
| `N42_BUILD_SKIP_DECIDED` | on (0 disables) | on unless `0` | N42_BUILD_SKIP_DECIDED=0 turns it off. Such a build cannot produce a payload anyone will ask for -- the height is decided -- and what it does ins... | `engine-types:payload.rs:1421` | default |
| `N42_BUILD_VERIFY_BATCH` | 4_096 | integer | How many transactions a build verifies at a time: N42_BUILD_VERIFY_BATCH (4,096 by default). Large enough that the worker pool is filled by one b... | `engine-types:claimed_build.rs:73` | undocumented-before |
| `N42_BUILT_KEEP` | 3 (valid 3..=16) | integer | How many own built executions the stores keep (N42_BUILT_KEEP, 3..=16, default 3), read once. Why it is tunable: under pipeline depth 2 with N... | `engine-types:built_executions.rs:74` | default |
| `N42_DIRECT_RECEIPTS` | on (0 disables) | on unless `0` | one executor commit per transfer (N42_DIRECT_RECEIPTS=0 goes back to the commits). On since loop170-171: 1,514 early-sealed blocks over eight leg... | `engine-types:payload.rs:5810` | default |
| `N42_ENGINE_TAKE_SEALED` | off | `1` (or the knob's own value; see code) | Whether N42_ENGINE_TAKE_SEALED=1 is set; see find_or_take_sealed. X22 base set: `1`. | `engine-types:built_executions.rs:1108` | adopted |
| `N42_FAST_TRANSFER` | off | `1` (or the knob's own value; see code) | EVM with the plain-transfer fast path. | `engine-types:fast_transfer.rs:77` | experimental |
| `N42_FIELDS_AT_SEAL` | off (1 early, verify) | `1` | Rename the parent tree as soon as its record is filed (early) rather than after Complete. X22 base set: `1`. | `engine-types:fields_at_seal.rs:77` | adopted |
| `N42_FOLLOWER_BATCH_STATE` | on (0 disables) | on unless `0` | N42_FOLLOWER_BATCH_STATE=0 goes back to revm's State): the three cuts of step 4b (be80847cc, 921de3899) -- crate::batch_state::BatchState as th... | `engine-types:parallel_transfer.rs:4534` | default |
| `N42_FOLLOWER_BUILD_PATH` | off | `1` (or the knob's own value; see code) | Whether N42_FOLLOWER_BUILD_PATH=1 is set: a follower executes a block of plain transfers through the leader's own machinery (execute_transfers_bu... X22 base set: `1`. | `engine-types:parallel_transfer.rs:4875` | adopted |
| `N42_FOLLOWER_FRAME_SCAN` | off | `1` (or the knob's own value; see code) | Ingest sums its frames; the check reads the sums (frame positions taken whole from the index). X22 base set: `1`. Needs `frameBlocks` in the genesis. | `engine-types:frame_scan.rs:173` | adopted |
| `N42_FOLLOWER_FREE_ASYNC` | off | `1` (or the knob's own value; see code) | Whether N42_FOLLOWER_FREE_ASYNC=1 is set: the executor's own working memory -- the transactions' environments, the groups, the batches' bundles -... X22 base set: `1`. | `engine-types:parallel_transfer.rs:4395` | adopted |
| `N42_FOLLOWER_GRAFT` | off | `1` (or the knob's own value; see code) | Whether N42_FOLLOWER_GRAFT=1 is set: the follower folds the groups' bundles into the block's state with graft_bundles instead of one commit of th... X22 base set: `1`. | `engine-types:parallel_transfer.rs:4405` | adopted |
| `N42_FOLLOWER_GRAFT_INDEX` | off (1; RANGES=1 wins) | `1` | The same for a follower's import (N42_FOLLOWER_GRAFT_INDEX, N42_FOLLOWER_GRAFT_RANGES), switched apart from the leader's: the two sides of the ... | `engine-types:parallel_transfer.rs:2629` | undocumented-before |
| `N42_FOLLOWER_GRAFT_RANGES` | off (1) | `1` | N42_FOLLOWER_GRAFT_RANGES), switched apart from the leader's: the two sides of the graft have never wanted the same setting (graft_stream against... | `engine-types:parallel_transfer.rs:2629` | undocumented-before |
| `N42_FOLLOWER_GRAFT_STREAM` | on (0 disables) | on unless `0` | (N42_FOLLOWER_GRAFT_STREAM=0 goes back to grafting them after the execution). On: it is the side of the change that paid on the fleet, over four ... | `engine-types:parallel_transfer.rs:4372` | default |
| `N42_FOLLOWER_MERGE_BEHIND` | off | `1` (or the knob's own value; see code) | Whether N42_FOLLOWER_MERGE_BEHIND=1 is set: with the streamed graft, the grafted reverts (one per account the block touched, ~147,000 at the benc... | `engine-types:parallel_transfer.rs:4329` | unknown |
| `N42_FOLLOWER_PARTITION_AHEAD` | off | `1` (or the knob's own value; see code) | Whether N42_FOLLOWER_PARTITION_AHEAD=1 is set: the follower plans a block's transfers (plan_transfers: the environments and the partition, 19 ms ... X22 base set: `1`. | `engine-types:parallel_transfer.rs:4316` | adopted |
| `N42_FOLLOWER_PARTITION_HASH` | off | `1` (or the knob's own value; see code) | Whether N42_FOLLOWER_PARTITION_HASH=1 is set: the follower's partition finds the addresses a block repeats on the worker pool (partition_shared) ... X22 base set: `1`. | `engine-types:parallel_transfer.rs:684` | adopted |
| `N42_FOLLOWER_SENDER_GROUPS` | off | `1` (or the knob's own value; see code) | Whether N42_FOLLOWER_SENDER_GROUPS=1 is set: the follower groups a block's transfers by sender, as the builder does, instead of by connected comp... | `engine-types:parallel_transfer.rs:4342` | unknown |
| `N42_FRAME_WALK_REFUSE_INDEXED` | off | `1` (or the knob's own value; see code) | N42_FRAME_WALK_REFUSE_INDEXED=1: a build whose frame plan came back empty also refuses to walk the lanes while frames are in the live index (fram... | `engine-types:frame_blocks.rs:253` | unknown |
| `N42_FREEZE_AFTER_SEAL` | off | `1` (or the knob's own value; see code) | N42_FREEZE_AFTER_SEAL=1 (docs/SHARED_EXECUTION_SCOPE.md 15): with N42_SEAL_AT_EXEC=1 and the output shards, the shards' freeze (the index's c... X22 base set: `1`. | `engine-types:payload.rs:747` | adopted |
| `N42_FREEZE_POOL` | off (own enables) | see Default | N42_FREEZE_POOL=own (docs/SHARED_EXECUTION_SCOPE.md 16.2): the work behind the seal -- the output shards' freeze (its tasks and the frees it sp... X22 base set: `own`. | `engine-types:parallel_transfer.rs:882` | adopted |
| `N42_FREEZE_POOL_THREADS` | 16 | integer | pool of N42_FREEZE_POOL_THREADS threads (16 by default, n42-behind-*, in the layout's build set as the build pool's are, or the set N42_CORE_L... | `engine-types:parallel_transfer.rs:897` | default |
| `N42_FREEZE_SPLIT` | 1 (clamped 1..=MAX_FREEZE_SPLIT) | integer | N42_FREEZE_SPLIT=<k> (1 by default, at most MAX_FREEZE_SPLIT; docs/SHARED_EXECUTION_SCOPE.md 18.7 item 4b): the live freeze's heavy shard -- th... | `engine-types:output_shards.rs:1590` | default |
| `N42_GRAFT_BASE_SWAP` | on (0 disables) | on unless `0` | N42_GRAFT_BASE_SWAP=0 re-inserts every bundle, the behaviour before round 43's loop98). | `engine-types:parallel_transfer.rs:4380` | default |
| `N42_GRAFT_INDEX` | off (1; RANGES=1 wins) | `1` | The fold the leader's build uses: N42_GRAFT_INDEX=1 for GraftFold::Indexed, N42_GRAFT_RANGES=1 for GraftFold::IndexedRanges (which implies the ... | `engine-types:parallel_transfer.rs:2618` | unknown |
| `N42_GRAFT_PREFAULT` | off | `1` (or the knob's own value; see code) | step (N42_GRAFT_PREFAULT=1, GraftTarget). Off by default until a four-node leg says the execution beside it does not pay for it. | `engine-types:parallel_transfer.rs:2736` | experimental |
| `N42_GRAFT_RANGES` | off (1) | `1` | GraftFold::Indexed, N42_GRAFT_RANGES=1 for GraftFold::IndexedRanges (which implies the index), neither for the fold that is in place. Both off by... | `engine-types:parallel_transfer.rs:2618` | unknown |
| `N42_GRAFT_SHARDED` | off | `1` (or the knob's own value; see code) | Whether N42_GRAFT_SHARDED=1 is set: the in-place fold's insert (graft_bundles_direct) runs sharded by address on the build pool (graft_insert_sha... | `engine-types:parallel_transfer.rs:2104` | unknown |
| `N42_GRAFT_STREAM` | off | `1` (or the knob's own value; see code) | Whether N42_GRAFT_STREAM=1 is set: a builder folds each batch's bundle into the block's graft as that batch finishes (StagedGraft) instead of all... | `engine-types:parallel_transfer.rs:4358` | unknown |
| `N42_GRANDPARENT_SHARDS` | on (0 disables) | on unless `0` | parent alone) with N42_GRANDPARENT_SHARDS=0, else N42_LEADER_LAYERS (2 when unset; an invalid value is refused with a warning and 2 is used). | `engine-types:direct_build.rs:899` | default |
| `N42_HANDOFF_MOVE_BODY` | off (1) | `1` | header instead of copying it (N42_HANDOFF_MOVE_BODY=1, default off). The hand-off needs the block under the header consensus sealed, and the body... | `engine-types:built_executions.rs:895` | adopted |
| `N42_HANDOFF_NO_CLONE` | off (1) | `1` | store instead of copying the body for it (N42_HANDOFF_NO_CLONE=1, default off). The hand-off copies the build's body once for the engine's insert... | `engine-types:built_executions.rs:854` | adopted |
| `N42_LEADER_LAYERS` | 2 (valid 2..=8; 1 when direct build is off) | integer | Own blocks a chained build lays over the engine (depth). | `engine-types:direct_build.rs:888` | adopted |
| `N42_LIVE_INDEX_DEFER` | off | `1` (or the knob's own value; see code) | N42_LIVE_INDEX_DEFER=1 (live index only): a batch whose hand-over finds a shard's index lock busy twice (the rotated pass and one more) does not ... X22 base set: `1`. | `engine-types:output_shards.rs:153` | adopted |
| `N42_MERGE_AT_SHARDS_READY` | off | `1` (or the knob's own value; see code) | N42_MERGE_AT_SHARDS_READY=1 (off by default, docs/SHARED_EXECUTION_SCOPE.md 18.7 item 3): the leader's shard merge starts the moment the shards... | `engine-types:output_shards.rs:167` | experimental |
| `N42_MERGE_ELIDE` | off | `1` (or the knob's own value; see code) | N42_MERGE_ELIDE=1 (off by default, docs/MERGE_ELISION_DESIGN.md): the leader's merger hands out a thin bundle (FrozenShards::thin_state_first) ... | `engine-types:output_shards.rs:195` | adopted |
| `N42_MERGE_POOL_THREADS` | 16 | integer | The early merge's pool (n42-merge-*, N42_MERGE_POOL_THREADS, 16 by default): not the build pool (the child's execution runs there while the par... | `engine-types:output_shards.rs:253` | default |
| `N42_MERGE_SPLIT` | off | `1` (or the knob's own value; see code) | N42_MERGE_SPLIT=1 (off by default): the leader's merge after the fields' publication -- the one that runs when N42_MERGE_AT_SHARDS_READY is off... | `engine-types:output_shards.rs:180` | experimental |
| `N42_OUTPUT_INCREMENTAL` | off | `1` (or the knob's own value; see code) | N42_OUTPUT_INCREMENTAL=1 (live index only, with N42_FREEZE_AFTER_SEAL=1; off by default): the child build opens on the parent's output before t... | `engine-types:output_shards.rs:139` | experimental |
| `N42_OUTPUT_INDEX` | off | `1` (or the knob's own value; see code) | N42_OUTPUT_INDEX=1 (with N42_OUTPUT_SHARDS=<S>): the block's output is the batches' maps as the executor left them plus an index -- a map a sha... X22 base set: `1`. | `engine-types:output_shards.rs:96` | adopted |
| `N42_OUTPUT_INDEX_LIVE` | off | `1` (or the knob's own value; see code) | N42_OUTPUT_INDEX_LIVE=1 (index mode only): each batch enters its addresses into the shards' indexes as it ends, on its own thread with its map st... X22 base set: `1`. | `engine-types:output_shards.rs:115` | adopted |
| `N42_OUTPUT_SHARDS` | 0 (off; capped at MAX_SHARDS) | integer | N42_OUTPUT_SHARDS=<S>: the leader's parallel step writes the block's output into S address-range shards (16 or 64 are the sizes meant; at most ... X22 base set: `16` (compiled default differs). | `engine-types:output_shards.rs:80` | adopted |
| `N42_PARALLEL_BUILD` | off (any value enables) | presence only (`=0` still counts) | N42_PARALLEL_BUILD, read once: the block's transfers built in parallel groups. Whether N42_BUILD_GRAFT_NO_CACHE=1 is set (see the graft in the ... X22 base set: `1`. | `engine-types:payload.rs:5815` | adopted |
| `N42_PARALLEL_BUILD_THREADS` | 16 | integer | before, a follower import). N42_PARALLEL_BUILD_THREADS threads, 16 by default. Under N42_CORE_LAYOUT=isolate each thread pins itself to the lay... | `engine-types:parallel_transfer.rs:863` | adopted |
| `N42_PHASE_TIMERS` | off | `1` (or the knob's own value; see code) | Whether N42_PHASE_TIMERS=1 is set (plan v6 6.5/6.6): per-batch phase timers for the fast-transfer path -- where a transfer's time goes between it... | `engine-types:fast_transfer.rs:93` | bench-only |
| `N42_PLAN_AHEAD_BODY` | off | `1` (or the knob's own value; see code) | N42_PLAN_AHEAD_BODY=1 (docs/SHARED_EXECUTION_SCOPE.md 16.4 item 2): with N42_PLAN_AHEAD=1, N42_PULL_BY_FRAMES=1 and N42_SEAL_ON_COUNTERS=1... X22 base set: `1`. Needs `frameBlocks` in the genesis. | `engine-types:frame_blocks.rs:267` | adopted |
| `N42_PLAN_AHEAD_BODY_THREADS` | 8 | integer | N42_PLAN_AHEAD_BODY_THREADS threads (8 by default, n42-plan-body-*), so the next block's preparation does not take the build pool's workers fro... X22 base set: `16` (compiled default differs). Needs `frameBlocks` in the genesis. | `engine-types:parallel_transfer.rs:940` | adopted |
| `N42_PLAN_AHEAD_PARTS` | off | `1` (or the knob's own value; see code) | N42_PLAN_AHEAD_PARTS=1: the plan-ahead hook also finds the body's frame layout and transactions root with the plan (root_ahead), and a build seal... | `engine-types:frame_blocks.rs:656` | experimental |
| `N42_PLAN_AHEAD_WARM` | 0 | integer | The pool's thread count (N42_PLAN_AHEAD_WARM=<threads>); 0 (unset) is off. Read once. | `engine-types:warm_ahead.rs:53` | default |
| `N42_PULL_BY_FRAMES` | off | `1` (or the knob's own value; see code) | N42_PULL_BY_FRAMES, read once: a frame build takes its block's transactions out of the plan's frames at once (select) instead of through the pull... X22 base set: `1`. Needs `frameBlocks` in the genesis. | `engine-types:frame_blocks.rs:411` | adopted |
| `N42_QMDB_RENAME_DEFER` | off (1) | `1` | the forest (N42_QMDB_RENAME_DEFER=1, default off). The hand-off files the build's QMDB record under the sealed hash through the forest's lock, wh... | `engine-types:chain_alias.rs:113` | adopted |
| `N42_READ_DEPTH_COUNTS` | off | `1` (or the knob's own value; see code) | Whether N42_READ_DEPTH_COUNTS=1 is set. Read once; the env var is not re-checked after the first call. | `engine-types:direct_build.rs:267` | bench-only |
| `N42_READ_SET` | off | `1` (or the knob's own value; see code) | the parent's state (N42_READ_SET=1, docs/BREAKTHROUGH_DESIGN.md section 4, design A). Off by default. | `engine-types:parallel_transfer.rs:1220` | experimental |
| `N42_RECEIPTS_FUSED` | off | `1` (or the knob's own value; see code) | passes on the receipts pool (N42_RECEIPTS_FUSED=1, off by default): the per-chunk gas, then the receipts with their cumulative gas, instead of th... | `engine-types:payload.rs:1082` | adopted |
| `N42_RECEIPTS_ON_BUILD_POOL` | off | `1` (or the knob's own value; see code) | are idle once the execution has ended (N42_RECEIPTS_ON_BUILD_POOL=1, off by default). The pool behind the seal (N42_FREEZE_POOL=own) runs them ... | `engine-types:payload.rs:1039` | adopted |
| `N42_REGISTER_FREE_OFFLOCK` | off | `1` (or the knob's own value; see code) | is released, on a thread of its own (N42_REGISTER_FREE_OFFLOCK=1, default off), read and logged once. Off, the eviction drops them under the lock... | `deferred-reverts:lib.rs:56` | adopted |
| `N42_ROOT_OPS_AHEAD` | off | `1` (or the knob's own value; see code) | N42_ROOT_OPS_AHEAD=1 (docs/SHARED_EXECUTION_SCOPE.md 15): with the output shards on a block that seals early, the shards' QMDB leaf operations ... X22 base set: `1`. | `engine-types:payload.rs:761` | adopted |
| `N42_ROOT_OPS_BEFORE_GATE` | off | `1` (or the knob's own value; see code) | N42_ROOT_OPS_BEFORE_GATE=1 (docs/ROOT_FIELDS_RACE.md option B): on the output-shard path the leader's QMDB root job starts before rename_paren... | `engine-types:payload.rs:774` | adopted |
| `N42_SEAL_AT_EXEC` | off | `1` (or the knob's own value; see code) | N42_SEAL_AT_EXEC=1 (plan v6 attempt G2, FLEET7_PLAN_V4.md 6.6): a block that seals early is sealed and proposed right after the parallel step's... X22 base set: `1`. | `engine-types:payload.rs:697` | adopted |
| `N42_SEAL_FIRST` | on (0 disables) | on unless `0` | EarlySeal): on unless N42_SEAL_FIRST=0 (adopted after loop137-140, NATIVE_FLEET7.md); a precondition is the chain's deferredExecutionTime, ch... | `engine-types:payload.rs:683` | default |
| `N42_SEAL_ON_COUNTERS` | off | `1` (or the knob's own value; see code) | N42_SEAL_ON_COUNTERS=1 (docs/SHARED_EXECUTION_SCOPE.md 16.4 item 1; N42_SEAL_ON_COUNTS=1 is the same switch): with N42_SEAL_AT_EXEC=1 and t... X22 base set: `1`. | `engine-types:payload.rs:730` | adopted |
| `N42_SEAL_ON_COUNTS` | off | `1` (or the knob's own value; see code) | N42_SEAL_ON_COUNTS=1 is the same switch): with N42_SEAL_AT_EXEC=1 and the body made in the prep, every batch counts its transfers, their gas an... | `engine-types:payload.rs:730` | unknown |
| `N42_SEAL_SHORTFALL_DIV` | 64 | integer | seal it early: block_gas_limit / N42_SEAL_SHORTFALL_DIV, 0 to require the block to be full to the last transaction. The parallel step leaves out ... | `engine-types:payload.rs:1269` | default |
| `N42_SHARDS_BEFORE_RECEIPTS` | off | `1` (or the knob's own value; see code) | N42_SHARDS_BEFORE_RECEIPTS=1 (off by default, docs/SHARED_EXECUTION_SCOPE.md 18.7 item 4a): on a block that seals at the execution's end with i... | `engine-types:output_shards.rs:243` | experimental |
| `N42_SHARDS_READY_FIRST` | off | `1` (or the knob's own value; see code) | N42_SHARDS_READY_FIRST=1 (docs/SEALED_AT_FLOOR.md candidate 1): on a block sealed at the parallel step's end (N42_SEAL_AT_EXEC=1), the shards a... | `engine-types:payload.rs:712` | adopted |
| `N42_SHARD_MIX` | off | `1` (or the knob's own value; see code) | N42_SHARD_MIX=1 (off by default): the shard layout reads a mix of the whole address (address_mix) instead of its top sixteen bits. Hashed address... | `engine-types:output_shards.rs:447,3755` | adopted |
| `N42_SHARD_RECYCLE` | off | `1` (or the knob's own value; see code) | (N42_SHARD_RECYCLE=1; off by default). The fleet-liveness bench (tests/output_shards_bench.rs, bench_output_shards_fold_live: three blocks' s... | `engine-types:output_shards.rs:1850` | experimental |
| `N42_STATE_AFTER_PULL` | off | `1` (or the knob's own value; see code) | N42_STATE_AFTER_PULL=1 (plan v6 attempt G3, FLEET7_PLAN_V4.md 6.7): with the parallel build and the puller on, the builder opens the parent's s... X22 base set: `1`. | `engine-types:payload.rs:839` | adopted |
| `N42_STATE_READY_WITHOUT_MERGE` | off (1) | `1` | Answer an own block's header-only import once fields are published, before merge. | `engine-types:built_executions.rs:444` | adopted |
| `N42_TX_ROOT_THREADS` | unset: no dedicated pool (1..=128) | see Default | Size of a dedicated transactions-root rayon pool. | `engine-types:assembler.rs:185` | undocumented-before |

## Transaction queue (tx-queue)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_COMPACT_BODY_INDEX` | 1,000,000 | integer | Bound (entries) of the by-hash tx index used by compact bodies / senders-from-queue. | `tx-queue:lib.rs:1743` | undocumented-before |
| `N42_FRAME_ARCS` | on (0 disables) | on unless `0` | Frame index keeps Arc'd transactions; 0 fetches every frame from the lanes. | `tx-queue:lib.rs:1763` | undocumented-before |
| `N42_FRAME_ROAD` | off (1 road, count counts only) | `1` | Frame road mode: 1 road, count counts only. Needs `frameBlocks` in the genesis. | `tx-queue:road.rs:74` | adopted |
| `N42_FRAME_SELECT_PARALLEL` | on (0 disables) | on unless `0` | N42_FRAME_SELECT_PARALLEL, on unless 0: a frame build checks the frames the gas reaches at once on the worker pool and leaves the lanes' update... | `tx-queue:lib.rs:7338` | undocumented-before |
| `N42_FRAME_SWEEP_AT_TAKE` | on (0 disables) | on unless `0` | Frames a build takes whole leave the live frame index at the take. | `tx-queue:frames.rs:74` | default |
| `N42_HANDOFF_DONE_FIRST` | off | `1` (or the knob's own value; see code) | the block (N42_HANDOFF_DONE_FIRST=1, default off), read and logged once. On, TxQueue::hold_own_block also folds an eviction's drop accounting int... | `tx-queue:lib.rs:745` | adopted |
| `N42_LOCK_SITES` | off | `1` (or the knob's own value; see code) | N42_LOCK_SITES=1: the lanes' lock's holds summed by the caller that took them (file:line, holds, held and waited nanoseconds), so the 5 s inge... Bench-only: instrumentation (lock duty by caller), no effect on the chain. | `tx-queue:lib.rs:956` | bench-only |
| `N42_OWN_HOLD_BLOCKS` | 16 (valid 4..=1024) | integer | N42_OWN_HOLD_BLOCKS, read once: how many own blocks TxQueue::hold_own_block keeps until the chain settles their heights (default OWN_HOLD_BLOCKS,... | `tx-queue:lib.rs:2103` | default |
| `N42_PLAN_AHEAD` | off | `1` (or the knob's own value; see code) | N42_PLAN_AHEAD, read once: a frame build prepares its child's plan right after its own (Prepared). Off by default. X22 base set: `1`. Needs `frameBlocks` in the genesis. | `tx-queue:lib.rs:1582` | adopted |
| `N42_PLAN_AHEAD_WAIT_MS` | 0 | integer | N42_PLAN_AHEAD_WAIT_MS=<ms>, read once (unset or 0: off). With N42_PLAN_AHEAD=1, the next build's plan is prepared continuously from the take o... Needs `frameBlocks` in the genesis. | `tx-queue:lib.rs:1595` | adopted |
| `N42_PRUNE_LEAN` | off | `1` (or the knob's own value; see code) | Whether the canonical pruner runs lean (N42_PRUNE_LEAN=1, default off), read and logged once: it does not drain the inbox inside its holds (the b... | `tx-queue:lib.rs:486` | adopted |
| `N42_PRUNE_LEAN_DRAIN_TXS` | LEAN_DRAIN_PER_BLOCK | integer | (N42_PRUNE_LEAN_DRAIN_TXS, default LEAN_DRAIN_PER_BLOCK), read and logged once; a wake drains at most this times its blocks, and at most LEAN_DRA... | `tx-queue:lib.rs:499` | undocumented-before |
| `N42_QUEUE_FREE_THREADS` | 1 | integer | N42_QUEUE_FREE_THREADS=<n> (default 1) runs n of them, a channel of four each, offered in turn and the next tried when one is full. Round 10.17... | `tx-queue:lib.rs:668` | adopted |
| `N42_QUEUE_OFFLOCK` | off | `1` (or the knob's own value; see code) | N42_QUEUE_OFFLOCK, read once (default off): the queue's heavy steps run off the lanes' lock or in short bounded holds instead of one long one -- ... | `tx-queue:lib.rs:1620` | adopted |
| `N42_QUEUE_PLAN_SNAPSHOT` | off | `1` (or the knob's own value; see code) | N42_QUEUE_PLAN_SNAPSHOT, read once (default off); only with N42_QUEUE_OFFLOCK and the parallel frame selection. A test sets it per queue (TxQue... | `tx-queue:snapshot.rs:62` | experimental |
| `N42_ROAD_DEBT_SWEEP` | on (0 disables) | on unless `0` | N42_ROAD_DEBT_SWEEP=0 turns it off (on by default; off under N42_ROAD_STUCK_LEGACY=1): a frame build whose plan came back empty, with frames on... | `tx-queue:road.rs:234` | undocumented-before |
| `N42_ROAD_RESEED_AT_FLUSH` | off | `1` (or the knob's own value; see code) | N42_ROAD_RESEED_AT_FLUSH=1 (off by default): a flush seeds again, at once, every sender the road knew: from its lane's tail where the lane holds ... Needs `frameBlocks` in the genesis. | `tx-queue:road.rs:207` | adopted |
| `N42_ROAD_RETIRE_INDEX` | on | `0` turns it off | Road::retire finds the mined taken frames through an index by first-member sender instead of scanning every taken frame; same frames retired (MATURITY_HARDENING 6.4, adopted after the stage fm pair of 2026-10-27). X22 base set: `1`. Needs `frameBlocks` in the genesis. | `tx-queue:road.rs:273` | adopted |
| `N42_ROAD_RETIRE_INLINE` | off | `1` (or the knob's own value; see code) | runs (N42_ROAD_RETIRE_INLINE=1, default off: their transactions go to the freeing thread with the rest of the prune's garbage), read and logged o... | `tx-queue:lib.rs:637` | experimental |
| `N42_ROAD_STUCK_LEGACY` | off | `1` (or the knob's own value; see code) | N42_ROAD_STUCK_LEGACY=1 (off by default): the stuck flush fires on the first rule -- the gate shut with the debt not lower over ROAD_STUCK_BUILD... | `tx-queue:road.rs:219` | experimental |
| `N42_ROAD_TAKEN_BOUND` | on | `0` turns it off | A taken road frame not retired or handed back is forgotten once more than N42_OWN_HOLD_BLOCKS + 8 own blocks were held since its take; its give-back then goes the lanes' path with a flush, as at N42_ROAD_TAKEN_MAX. Gauge n42_road_taken_frames (MATURITY_HARDENING 6.4, adopted after the stage fm pair of 2026-10-27). X22 base set: `1`. Needs `frameBlocks` in the genesis. | `tx-queue:road.rs:265` | adopted |
| `N42_ROAD_TAKEN_MAX` | ROAD_TAKEN_MAX | integer | N42_ROAD_TAKEN_MAX=<frames>: the bound above, for the stage that measures what the remembered frames cost in memory (at the default, a map at its... | `tx-queue:road.rs:177` | default |
| `N42_SENDERS_FROM_QUEUE` | off | `1` (or the knob's own value; see code) | N42_SENDERS_FROM_QUEUE, read once: a follower takes the senders of a foreign block out of the by-hash index instead of looking each one up in the... | `tx-queue:lib.rs:1722` | unknown |
| `N42_TX_QUEUE_BATCH` | 1 | integer | Transactions per queue batch. | `tx-queue:lib.rs:7344` | default |
| `N42_TX_QUEUE_DRAIN_CHUNK` | 0 | integer | N42_TX_QUEUE_DRAIN_CHUNK=<n>, read once: the drainer (TxQueue::drain_now) holds the lanes' lock for at most n transactions at a time. 0 (the de... X22 base set: `8192` (compiled default differs). | `tx-queue:lib.rs:1657` | adopted |
| `N42_TX_QUEUE_DRAIN_RUNS` | off | `1` (or the knob's own value; see code) | N42_TX_QUEUE_DRAIN_RUNS=1, read once: the drainer's chunked and sliced drains (TxQueue::drain_now) take their batch off the lanes' lock, group it... | `tx-queue:lib.rs:1669` | adopted |
| `N42_TX_QUEUE_PARK_LANES` | 0 | integer | N42_TX_QUEUE_PARK_LANES. Parking is off because a parked lane is a sink. Nothing drains it -- that is the point -- but the generator keeps feedin... | `tx-queue:lib.rs:178` | default |
| `N42_TX_QUEUE_RUN` | 1 | integer | to the next: N42_TX_QUEUE_RUN, 1 by default (strict rotation). A block drawn from a deep queue by strict rotation alternates among every queued s... X22 base set: `64` (compiled default differs). | `tx-queue:lib.rs:1688` | adopted |

## Transaction ingest (tx-ingest)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_INGEST_RUNTIME` | off | `1` (or the knob's own value; see code) | Whether the ingest runs on its own runtime (N42_INGEST_RUNTIME=1, off by default). | `tx-ingest:runtime.rs:49` | experimental |
| `N42_INGEST_RUNTIME_WORKERS` | 8 (clamped 1..=64) | integer | Workers of the ingest's own runtime. | `tx-ingest:runtime.rs:55` | default |
| `N42_TX_INGEST_ASYNC` | off (any value enables) | presence only (`=0` still counts) | Ingest answers frames asynchronously. | `tx-ingest:lib.rs:1089` | experimental |
| `N42_TX_INGEST_ASYNC_FRAMES` | ASYNC_FRAMES_IN_FLIGHT | integer | N42_TX_INGEST_ASYNC_FRAMES: frames a connection may have recovering or awaiting admission before its next answer waits; the default above. | `tx-ingest:lib.rs:208` | default |
| `N42_TX_INGEST_BLOCK_TXS` | 0 | integer | Per-block allowance the ingest gate grants (0 = old gate). | `tx-ingest:lib.rs:1029` | undocumented-before |
| `N42_TX_INGEST_DIRECT` | off | `n42_env::flag`: 1/true/on/yes enable, 0/false/off/no disable | Ingest feeds the tx queue directly (queue is a tx's only holder), past the pool's checks; the node refuses it without `N42_BENCH_UNSAFE=1`. | `tx-ingest:lib.rs:456` | unsafe-bench |
| `N42_TX_INGEST_GATE_FOR_BLOCK` | off | `1` (or the knob's own value; see code) | Opt-in opening of the ingest gate while a block is pending. | `tx-ingest:lib.rs:562` | unknown |
| `N42_TX_INGEST_GATE_MAX_WAIT_MS` | 15_000 | integer | N42_TX_INGEST_GATE_MAX_WAIT_MS, 15 seconds by default, 0 to wait for ever (the behaviour before this). The gate is backpressure, not a rule: wait... | `tx-ingest:lib.rs:479` | default |
| `N42_TX_INGEST_GATE_STRICT` | off | `1` (or the knob's own value; see code) | that is. N42_TX_INGEST_GATE_STRICT=1 is the same as leaving the opt-in unset and is read for the older runners. | `tx-ingest:lib.rs:563` | undocumented-before |
| `N42_TX_INGEST_HIGH_WATER` | 90,000 | integer | Pool depth at which the ingest gate closes. | `tx-ingest:lib.rs:802` | default |
| `N42_TX_INGEST_RECOVER_NICE` | 0 | integer | The nice value recovery threads run at: N42_TX_INGEST_RECOVER_NICE, 0 by default. At 10 or more, the scheduler gives the builder's and the engine... | `tx-ingest:lib.rs:230` | default |
| `N42_TX_INGEST_RECOVER_PARALLEL` | unset: unlimited (n>0 bounds it) | see Default | N42_TX_INGEST_RECOVER_PARALLEL, unlimited by default. Unlimited, 64 connections with 8 frames in flight each are 512 blocking threads of secp256k... X22 base set: `24`. | `tx-ingest:lib.rs:351` | adopted |
| `N42_TX_INGEST_RECOVER_PIN` | 0 | integer | N42_TX_INGEST_RECOVER_PIN=1: each recovery thread is pinned to one physical core of the node's CPU set, round-robin, so two recoveries do not sha... | `tx-ingest:lib.rs:286` | undocumented-before |
| `N42_TX_INGEST_UNBUFFERED` | off (any value enables) | presence only (`=0` still counts) | Unbuffered read(2) per field on the ingest socket (A-B knob). | `tx-ingest:lib.rs:774` | unknown |

## Transaction types (tx-types)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_ALTSIG_SENDER_CACHE` | 1 << 20 | integer | Sized by N42_ALTSIG_SENDER_CACHE (entries, a power of two; default 2^20, about six blocks of the bench tier). X22 base set: `4194304` (compiled default differs). | `tx-types:sender_cache.rs:49` | adopted |
| `N42_ED25519_BATCH` | 64 (max 256) in prod; 128 in a #[ignore] timing test | integer | Ed25519 batch-verification size at ingest (prod: sender_cache.rs; timing test reads it too). X22 base set: `256` (compiled default differs). | `tx-types:alt_sig.rs:847; tx-types:sender_cache.rs:203` | adopted |
| `N42_ED25519_KEY_CACHE` | on (0 disables) | on unless `0` | key is the sender's, and senders repeat; N42_ED25519_KEY_CACHE=0 turns the cache off. Bounded by sharding: each of 256 shards keeps at most KEY_... | `tx-types:sender_cache.rs:230` | default |
| `N42_ED25519_MERGE` | on (0 disables) | on unless `0` | Merged Ed25519 batch verification (one key point per sender); 0 keeps one term per signature. Same cofactored verdict either way (no longer falls back to dalek's cofactorless verify_batch). | `tx-types:alt_sig.rs:415` | default |
| `N42_FRAME_ATTEST_MIN` | 1 (only read when FRAME_GATEWAYS is set) | integer | Distinct gateways a frame needs (with FRAME_GATEWAYS). Bench-only: only meaningful with the bench gateway key of `N42_FRAME_GATEWAYS`. | `tx-types:frame.rs:231` | bench-only |
| `N42_FRAME_BLOCKS` | off | `1` (or the knob's own value; see code) | N42_FRAME_BLOCKS=1, read once: this node builds, describes and checks frame-aligned blocks (phase B of step 1). Meaningful only on a chain whose ... X22 base set: `1`. Needs `frameBlocks` in the genesis. | `tx-types:frame.rs:88` | adopted |
| `N42_FRAME_GATEWAYS` | unset: no gateway attestation | see Default | List of frame gateways whose attestation a frame needs. Bench-only: a trusted bench gateway key, not a product trust root; the node refuses it without `N42_BENCH_UNSAFE=1`. | `tx-types:frame.rs:230` | bench-only |
| `N42_INGEST_SHARD` | unset (required as i/n when INGEST_VERIFY=shard) | see Default | This node's i/n shard of ingest signature work (INGEST_VERIFY=shard). | `tx-types:sender_cache.rs:163` | unsafe-bench |
| `N42_INGEST_VERIFY` | all (leader, shard) | see Default | N42_INGEST_VERIFY=leader, against the default all. The supply is a ceiling every member pays alike: each one ingests every transaction and veri... | `tx-types:sender_cache.rs:109,162` | unsafe-bench |

## QMDB state (qmdb-reth, twig-core, qmdb-state)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_ENGINE_EXEC_CACHE` | skip (on restores reth cache update) | see Default | on keeps reth cache update on executed inserts for QMDB chains (A/B). | `qmdb-reth:exec_cache.rs:49` | default |
| `N42_QMDB_APPEND_AHEAD_MB` | 64 | integer | MB of the QMDB append file populated ahead (0 = off). | `twig-core:prefault.rs:79` | default |
| `N42_QMDB_APPEND_REWALK` | 0 (off) | integer | Rewalk the append window not only when half is left. | `twig-core:prefault.rs:456` | default |
| `N42_QMDB_APPLY_SCRATCH` | 1 (on; 0 disables) | integer | Reuse apply temporaries between blocks. | `twig-core:prefault.rs:157` | default |
| `N42_QMDB_CANONICAL_DEFER` | off | `1` (or the knob's own value; see code) | N42_QMDB_CANONICAL_DEFER=1 (default off): a canonical head that arrives while the tree is leased out (N42_QMDB_COMPUTE_OFFLOCK) does not wait f... | `qmdb-reth:node_state.rs:211` | experimental |
| `N42_QMDB_CANONICAL_FATAL` | on (`0` disables) | on unless `0` | A canonical notification the QMDB log cannot follow (`is_fatal_canonical_error`: Poisoned, Uninitialised, State refusals) logs at error level and exits the node with code 1; `0` restores log-and-continue for benches. Log I/O errors are never fatal (the next head retries them). | `qmdb-reth:node_state.rs` (`canonical_fatal`), used in `bin/n42:main.rs` | default |
| `N42_QMDB_CHECKPOINT_RATIO` | 1 | integer | N42_QMDB_CHECKPOINT_RATIO: how many times the checkpoint's size the log may reach before the checkpoint is rewritten (default 1: the log is bound... | `qmdb-reth:node_state.rs:106` | default |
| `N42_QMDB_CHECKPOINT_SYNC` | off | `1` (or the knob's own value; see code) | N42_QMDB_CHECKPOINT_SYNC=1: rewrite the checkpoint from the live forest on the canonical follower, as before, instead of compacting the files on ... | `qmdb-reth:node_state.rs:96` | unknown |
| `N42_QMDB_COMPACT_NICE` | 10 | integer | N42_QMDB_COMPACT_NICE: the compaction thread's nice value (default 10), so its read, replay and write of the whole state yield to the builder and... | `qmdb-reth:node_state.rs:121` | default |
| `N42_QMDB_COMPUTE_OFFLOCK` | off | `1` (or the knob's own value; see code) | N42_QMDB_COMPUTE_OFFLOCK=1 (default off): a block's QMDB root (compute_operations, insert_block_operations, validate_block_operations) is c... | `qmdb-reth:node_state.rs:188` | adopted |
| `N42_QMDB_ENTRY_FILE` | off | `1` (or the knob's own value; see code) | N42_QMDB_ENTRY_FILE=1: the tree's entries live in qmdb/entries.log instead of the heap (docs/QMDB_ENTRY_LOG.md, step 1). Off until a round re... X22 base set: `1`. | `qmdb-reth:node_state.rs:412` | adopted |
| `N42_QMDB_ENTRY_BYTES_PER_LIVE_ALARM` | 2000 (0 disables) | integer | Entry bytes per live QMDB slot (`n42_qmdb_entry_bytes_per_live_slot`, sampled every 10 s) above which the node logs one warning per process; docs/QMDB_COMPACTION_DESIGN.md 3.7. | `bin/n42:main.rs` (QMDB health sampler) | default |
| `N42_QMDB_OFFSET_SEGMENTS_AHEAD` | 2 | integer | Offsets segments kept allocated ahead (N42_QMDB_OFFSET_SEGMENTS_AHEAD). | `twig-core:prefault.rs:98` | undocumented-before |
| `N42_QMDB_PARALLEL_APPLY` | off | `1` (or the knob's own value; see code) | Leased parallel compute for the QMDB apply. | `twig-core:qmdb_compat.rs:981` | adopted |
| `N42_QMDB_PARALLEL_WRITES` | off | `1` (or the knob's own value; see code) | (N42_QMDB_PARALLEL_WRITES=1, off by default; see QmdbCompatTree::parallel_writes), or what set_parallel_writes_on_this_thread chose for the apply... | `twig-core:qmdb_compat.rs:944` | experimental |
| `N42_QMDB_PERSIST_BATCH` | off | `1` (or the knob's own value; see code) | N42_QMDB_PERSIST_BATCH=1 (default off): QmdbNodeState::on_persisted lists a whole persistence batch's changes (and raises the read view's floor f... | `qmdb-reth:node_state.rs:220` | adopted |
| `N42_QMDB_READER_KEEP_CAP` | 64 blocks (1024 when hashed tables are off) | integer | Blocks of per-block records the forest keeps for the read view. | `qmdb-reth:node_state.rs:331` | default |
| `N42_QMDB_READS` | off (unset or off; any other non-empty value on) | see Default | Build the QMDB read view (on/verify). Bench-only: `on` is the bench's storage mode; a product node decides it separately. | `qmdb-reth:node_state.rs:310` | bench-only |
| `N42_QMDB_RETAIN_DEPTH` | unset: none (values >=2 only) | see Default | N42_QMDB_RETAIN_DEPTH: how many blocks below the head the forest keeps its records for (the sorted operations to re-apply a block after a move, a... X22 base set: `16`. | `qmdb-reth:node_state.rs:161` | adopted |
| `N42_QMDB_SETTLE_WAIT_MS` | 30000 | integer (ms; 0 = one try) | How long the persistence hook (`settle_through`, before the MDBX commit) waits for the QMDB delta log to reach the batch's last block; past it the batch is refused (`PersistUnsettled`) and persistence stops. | `qmdb-reth:node_state.rs` (`settle_wait`) | default |
| `N42_QMDB_TRIM_TWIGS` | on (0 disables) | on unless `0` | N42_QMDB_TRIM_TWIGS=0 keeps every twig's leaf nodes; by default a full twig below the retention window keeps only its root and bits, and a proof ... | `qmdb-reth:node_state.rs:174` | default |
| `N42_QMDB_UNDO_POOL` | 64 | integer | Undo list sets the pool keeps at most (N42_QMDB_UNDO_POOL), 0 when off. | `twig-core:prefault.rs:85` | default |
| `N42_ROOT_UPPER_DIRTY` | off | `1` (or the knob's own value; see code) | marked dirty only (N42_ROOT_UPPER_DIRTY=1, off by default), instead of comparing every twig slot with the cached leaf level; or what set_root_upp... | `twig-core:qmdb_compat.rs:996` | adopted |
| `N42_TWIG_POOL_FLOOR` | 512 | integer | Shared twig-node pool floor. | `twig-core:prefault.rs:65` | default |
| `N42_VIEW_JOURNAL_FILTER` | off | `1` (or the knob's own value; see code) | Filter that skips journals in view reads. | `qmdb-reth:read_view.rs:119` | experimental |
| `TWIG_NO_SIMD` | unset: SIMD autodetect (any value forces scalar) | presence only (`=0` still counts) | scalar; TWIG_NO_SIMD=1 forces scalar (A/B measurement, non-x86 parity). | `twig-core:simd.rs:68` | undocumented-before |

## HotStuff and execution seam (h2-execution, h2-node, h2-el-rpc, h2-net)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_RAW_CHANNEL_TIMEOUT_MS` | 8000 | integer ms | Deadline for one exchange on the raw payload channel; the client falls back to the Engine API on expiry (audit/h2-hardening). | `h2-el-rpc:engine.rs` | default |
| `N42_ANSWER_LAYOUT_ONLY` | off | `1` (or the knob's own value; see code) | N42_ANSWER_LAYOUT_ONLY, read once: the proposer tells its execution layer that a compact build-on-own answer may leave the transaction hash list ... X22 base set: `1`. Needs `frameBlocks` in the genesis. | `h2-execution:driver.rs:909` | adopted |
| `N42_BLOCK_BY_DESCRIPTION` | off | `1` (or the knob's own value; see code) | Follower checks a compact body by description; implies COMPACT_BODY. X22 base set: `1`. | `h2-execution:driver.rs:846; tx-queue:lib.rs:1708` | adopted |
| `N42_BLOCK_TOPIC_ALWAYS` | off (any value enables) | presence only (`=0` still counts) | Always publish the block body on the gossip topic (gov5 members need it). | `h2-node:service.rs:1183` | undocumented-before |
| `N42_BODY_ONCE` | off | `1` (or the knob's own value; see code) | N42_BODY_ONCE, read once: opt-in, and read on the validator's side, because that is the side that stops decoding the body. Off, everything takes ... X22 base set: `1`. | `h2-execution:driver.rs:828` | adopted |
| `N42_BODY_REQUEST_GRACE_MS` | 120 | integer | N42_BODY_REQUEST_GRACE_MS: how long a follower waits for a proposal's body to arrive on its own (the leader's push, the block topic) before askin... | `h2-node:service.rs:4829` | default |
| `N42_BUILD_AHEAD_AT_SEAL` | off | `1` (or the knob's own value; see code) | Chained build starts at the parent's seal (ChainState::defer_refused). | `h2-el-rpc:engine.rs:183` | adopted |
| `N42_BUILD_AHEAD_GATE` | send (seal is the alternative; qc = send) | see Default | What lets the chain start block N while the slot still holds the untaken build of N-1 (engine.rs); tx-queue reads seal to release replaced own bl... | `h2-el-rpc:engine.rs:229; tx-queue:lib.rs:732` | default |
| `N42_BUILD_CHAIN` | off (any value but 0 enables) | any value except `0` (empty enables) | N42_BUILD_CHAIN=1: the execution layer hands a block's header back the moment it seals it early, and the build after that block starts on it -- t... X22 base set: `1`. | `h2-node:service.rs:987` | adopted |
| `N42_BUILD_THROTTLE_HARD` | unset: throttle disabled (needed for any throttle) | see Default | Queue depth at which builds are held (throttle on only when > 0). X22 base set: `80` (compiled default differs). | `h2-node:build_throttle.rs:93` | adopted |
| `N42_BUILD_THROTTLE_MAX_HOLD_MS` | 2000 ms | integer | Longest a build is held by the throttle. | `h2-node:build_throttle.rs:94` | undocumented-before |
| `N42_BUILD_THROTTLE_SOFT` | = HARD when unset/invalid | integer | Queue depth where the soft delay band starts (must be < HARD). X22 base set: `48` (compiled default differs). | `h2-node:build_throttle.rs:92` | adopted |
| `N42_CHECK_AHEAD_QUEUE` | 2 (valid 0..=8) | integer | N42_CHECK_AHEAD_QUEUE, read once (default CHECK_AHEAD_QUEUE): under the service's N42_CHECK_AHEAD_UNHELD=1, how many blocks may wait in the imp... | `h2-execution:driver.rs:208` | default |
| `N42_CHECK_AHEAD_UNHELD` | off | `1` (or the knob's own value; see code) | N42_CHECK_AHEAD_UNHELD, read once (off by default): a block that runs far ahead of the execution layer's tip but which the driver can queue and c... | `h2-node:service.rs:609` | experimental |
| `N42_CHECK_BEFORE_SLOT` | off | `1` (or the knob's own value; see code) | N42_CHECK_BEFORE_SLOT, read once (off by default): a deferred block that arrives while every import slot is taken is *checked* at once by a check... | `h2-execution:driver.rs:188` | adopted |
| `N42_COMMIT_FCU_ASYNC` | off | `1` (or the knob's own value; see code) | N42_COMMIT_FCU_ASYNC, read once: opt-in, and only the *default* for a driver -- ExecutionDriver::set_commit_fcu_async is what a test uses, so the... X22 base set: `1`. | `h2-execution:driver.rs:918` | adopted |
| `N42_COMPACT_BODY` | off | `1` (or the knob's own value; see code) | Compact block body assembled from the by-hash index (needs BODY_ONCE). X22 base set: `1`. | `h2-execution:driver.rs:845; tx-queue:lib.rs:1697` | adopted |
| `N42_DEFERRED_IN_FLIGHT` | 2 (max 3) | integer | N42_DEFERRED_IN_FLIGHT, read once: how many deferred follower imports run at once (see DEFERRED_IN_FLIGHT). Valid 1..= DEFERRED_IN_FLIGHT_MAX; ... | `h2-execution:driver.rs:143` | default |
| `N42_FAR_AHEAD_BLOCKS` | 1 (valid 1..=8) | integer | held, read once from N42_FAR_AHEAD_BLOCKS (default FAR_AHEAD_BLOCKS). At depth-2 deferred execution (header N carries the execution of N-2) a vot... | `h2-node:service.rs:596` | default |
| `N42_FILL_REPLY_ON_DRAIN` | off | `1` (or the knob's own value; see code) | instead of waking the loop (N42_FILL_REPLY_ON_DRAIN=1, the behaviour before defect 17b). The drain runs only after some other event wakes the loo... | `h2-node:service.rs:831` | unknown |
| `N42_FILL_ROUNDS_MAX` | 3 | integer | N42_FILL_ROUNDS_MAX: how many times a follower asks peers for a block's missing transactions before it fetches the whole body instead (defect 18:... | `h2-node:service.rs:885` | default |
| `N42_GOSSIP_HANDLER_QUEUE` | 5000 | integer | Gossipsub handler queue length. X22 base set: `64` (compiled default differs). | `h2-net:config.rs:130` | adopted |
| `N42_GOSSIP_MAX_IHAVE` | 5000 | integer | Gossipsub max IHAVE messages. X22 base set: `500` (compiled default differs). | `h2-net:config.rs:131` | adopted |
| `N42_HALT_ON_COMMIT_INVALID` | on (0 disables) | on unless `0` | Stop voting and proposing (keep following) when the execution layer answers `Invalid` to a commit forkchoice; see docs/OPERATOR_FAULTS.md. | `h2-node:service.rs` (startup) | default |
| `N42_H2_MAX_INBOUND` | 128 | integer (0 or unparsable: the default) | Inbound libp2p connections accepted at most (audit 2026-10 B-3). A fleet of seven holds six. | `h2-net:transport.rs` (`max_inbound_connections`) | default |
| `N42_H2_REMEMBERED_BODIES` | REMEMBERED_BODIES | integer | How many bodies the store keeps: N42_H2_REMEMBERED_BODIES, else REMEMBERED_BODIES. An environment knob so a round can bookend the old 4,096 again... | `h2-node:service.rs:751` | default |
| `N42_H2_TRACE_MSGS` | off | `1` (or the knob's own value; see code) | N42_H2_TRACE_MSGS=1: one info line per consensus message sent or received, with its kind and view, so a round's hops can be timed across the flee... | `h2-node:service.rs:4795` | bench-only |
| `N42_MAX_GOSSIP_MB` | 1 MiB (1<<20 bytes) | integer | reads N42_MAX_GOSSIP_MB, and two clients on one chain that disagree about this do not merely differ in throughput — the one with the smaller cap ... | `h2-net:config.rs:57` | default |
| `N42_OWN_BLOCK_BY_HEADER` | on (0 disables) | on unless `0` | Own block is sent to the engine by header (channel); 0 sends the payload. | `h2-el-rpc:engine.rs:1439,1452` | undocumented-before |
| `N42_SETTLEMENT_TAGS` | split (legacy) | see Default | Forkchoice safe/finalized meaning: split or legacy (head=safe=finalized). Bench-only: `legacy` is a node-local RPC shape the bench keeps, not a consensus setting. | `h2-execution:settlement.rs:27` | bench-only |
| `N42_STRAGGLER_RULE` | all (quorum) | see Default | Straggler grace rule: quorum or all validators. | `h2-node:straggler.rs:61` | default |
| `N42_TAKE_COMPACT` | off | `1` (or the knob's own value; see code) | N42_TAKE_COMPACT, read once: the proposer asks its execution layer for a build-on-own answer *without the transactions* -- the header, the small ... X22 base set: `1`. | `h2-execution:driver.rs:892` | adopted |
| `N42_VOTE_AGGREGATE_VERIFY` | off | `1` (or the knob's own value; see code) | Batched vote verification on a leader. X22 base set: `1`. | `h2-node:service.rs:4790` | adopted |
| `N42_VOTE_LOG_FATAL_AFTER` | 3 | integer (`0` disables) | Consecutive vote-log write/fsync failures after which the validator stops and exits non-zero (code 3); see docs/OPERATOR_FAULTS.md. | `h2-node:service.rs` (startup) | default |
| `N42_VOTE_LOG_NOSYNC` | off | `1`, and only with `N42_BENCH_UNSAFE=1` (h2_validator refuses to start without it) | Skip the vote-log sync (bench knob; gives up crash safety). | `h2-node:persistence.rs:506` | unsafe-bench |
| `N42_VOTE_TRANSPORT` | gossip (direct, both) | see Default | Vote transport: direct, both, or gossip. X22 base set: `direct` (compiled default differs). Needs `frameBlocks` in the genesis: a chain a gov5 member can join keeps the mesh (audit 2026-10 E-5). | `h2-node:direct_votes.rs:43` | adopted |
| `N42_YAMUX_WINDOW_MB` | ignored (only logs a warning: unsupported by libp2p 0.57) | see Default | Yamux window; unsupported, only logs a warning. | `h2-net:config.rs:247` | bench-only |

## Chain state and storage provider (chain-state, storage/provider)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_ACCOUNT_HISTORY` | unset: index written; off skips it | see Default | Whether the AccountsHistory index write is skipped (N42_ACCOUNT_HISTORY=off). Read once; on, any other value or no value writes it (reth's be... Bench-only: `off` drops the AccountsHistory index. | `storage/provider:providers/n42_persist.rs:118` | bench-only |
| `N42_HASHED_TABLES` | unset: hashed state tables written (`off` stops them) | `off` | Whether the hashed state tables are no longer written (QMDB reader hooks). Read once. Bench-only: `off` is the bench's storage mode; a product node decides it separately. | `storage-api:n42_state.rs:81` | bench-only |
| `N42_ACCOUNT_HISTORY_SCAN_MAX` | DEFAULT_ACCOUNT_HISTORY_SCAN_MAX | integer | (N42_ACCOUNT_HISTORY_SCAN_MAX overrides). A read that finds no change within that many blocks of a longer range returns an error that names the m... | `storage/provider:providers/n42_persist.rs:155` | default |
| `N42_CANON_NOTIFY_LEAN` | off | `1` (or the knob's own value; see code) | Read once from N42_CANON_NOTIFY_LEAN (1 turns it on; default off). Measured in loop351 stage k (E=1, seven validator keys on one execution laye... Bench-only (audit 2026-10 E-1): notifications carry no execution outcome, so `logs`/receipt subscriptions, RPC caches and pool maintenance see nothing; was in X22 until 2026-10-28. | `chain-state:in_memory.rs:984` | bench-only |
| `N42_OVERLAY_FILTER` | on (0 disables) | on unless `0` | Whether the filters are on (N42_OVERLAY_FILTER=0 turns them off; on by default). | `storage/provider:providers/state/overlay_filter.rs:61` | default |
| `N42_OVERLAY_FILTER_CAP` | 1024 (floor 64) | integer | Max entries of the overlay filter side map. | `storage/provider:providers/state/overlay_filter.rs:55` | undocumented-before |
| `N42_OVERLAY_READS` | local overlay (upstream selects reth overlay) | see Default | N42: N42_OVERLAY_READS=upstream reads state under in-memory blocks through upstream's flattened OverlayStateProvider instead of MemoryOverlaySt... | `storage/provider:providers/blockchain_provider.rs:63` | experimental |
| `N42_PERSIST_QMDB_IN_SCOPE` | off | `1` (or the knob's own value; see code) | Whether on_state_persisted runs beside the backend writes (N42_PERSIST_QMDB_IN_SCOPE=1). Read once; any other value or no value keeps it after ... Bench-only: persistence ordering, superseded by the 6.3 hook. | `storage/provider:providers/n42_persist.rs:101` | bench-only |
| `N42_ROCKSDB_DIRECT_IO` | off | `1` (or the knob's own value; see code) | N42_ROCKSDB_DIRECT_IO=1: flushes and compactions bypass the page cache (direct I/O with a 1 MiB writable buffer), so the SST files RocksDB writ... | `storage/provider:providers/rocksdb/provider.rs:67` | unknown |
| `N42_ROCKSDB_MAX_WAL_MB` | 256 MiB | integer | RocksDB max total WAL size. | `storage/provider:providers/rocksdb/provider.rs:202` | default |
| `N42_ROCKSDB_NOSYNC` | off | `1` (or the knob's own value; see code) | Leave the RocksDB WAL write unsynced (bench knob). | `storage/provider:providers/rocksdb/provider.rs:56` | unsafe-bench |
| `N42_ROCKSDB_WRITE_BUFFER_MB` | 4096 MiB | integer | RocksDB shared memtable budget. | `storage/provider:providers/rocksdb/provider.rs:181` | default |
| `N42_SF_BULK_APPEND` | off (1/on/true) | `1`/`on`/`true` | Append static-file rows in bulk. | `storage/provider:providers/static_file/n42_sf.rs:166` | adopted |
| `N42_SF_DROP_CACHE` | off (1/on/true) | `1`/`on`/`true` | Ranged lagged DONTNEED of static-file pages after commit. | `storage/provider:providers/static_file/n42_sf.rs:72` | adopted |
| `N42_SF_DROP_CACHE_KEEP_MB` | 256 | integer | N42_SF_DROP_CACHE_KEEP_MB (default 256), read once: the tail of a data file, in bytes, whose pages drop_cache_after_commit leaves cached. | `storage/provider:providers/static_file/n42_sf.rs:83` | default |
| `N42_SF_EARLY_WRITEBACK` | off (1/on/true) | `1`/`on`/`true` | Start static-file writeback early. X22 base set: `1`. | `storage/provider:providers/static_file/n42_sf.rs:65` | adopted |
| `N42_SF_PARALLEL_ENCODE` | off (1/on/true) | `1`/`on`/`true` | Encode static-file rows in parallel. X22 base set: `1`. | `storage/provider:providers/static_file/n42_sf.rs:59` | adopted |
| `N42_STORAGE_OP_METRICS` | on (0 disables) | on unless `0` | Per-operation storage records; 0 skips them. | `storage/provider:providers/op_metrics.rs:18` | bench-only |

## Core layout (core-layout)

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_BACKGROUND_NICE` | unset: no change (value: nice 1..19 or idle) | see Default | Nice/idle priority applied to background-set threads. | `core-layout:lib.rs:542` | bench-only |
| `N42_CORE_LAYOUT` | off (isolate enables) | see Default | Pin build/critical/background thread sets onto disjoint cores (isolate). | `core-layout:lib.rs:414,731` | adopted |
| `N42_CORE_LAYOUT_BEHIND` | build (background/critical) | see Default | Which core set the freeze/"behind" pool runs on. | `core-layout:lib.rs:122` | adopted |
| `N42_CORE_LAYOUT_BUILD_CORES` | 16 | integer | Cores in the build set. | `core-layout:lib.rs:117` | adopted |
| `N42_CORE_LAYOUT_BUILD_SIBLINGS` | off (1) | `1` | Include SMT siblings in the build set. | `core-layout:lib.rs:118` | undocumented-before |
| `N42_CORE_LAYOUT_CRITICAL` | off (background enables) | see Default | Move the critical set to background priority. | `core-layout:lib.rs:127` | experimental |
| `N42_CORE_LAYOUT_CRITICAL_CORES` | 4 | integer | Cores in the critical set. | `core-layout:lib.rs:119` | adopted |
| `N42_CORE_LAYOUT_SIBLINGS` | off (background enables) | see Default | Put SMT siblings of the build cores in the background set. | `core-layout:lib.rs:121` | adopted |

## Test and bench helpers

| Knob | Default | Values | Meaning | Where read | Status |
|---|---|---|---|---|---|
| `N42_BENCH_SENDERS` | 100,000 (test) | integer | Test (ignored bench): senders for off-lock settle / plan-snapshot benches. | `tx-queue:offlock_tests.rs:579; tx-queue:snapshot_tests.rs:245` | bench-only |
| `N42_RELEASE_BENCH` | 44x163000 (ignored bench) | integer | Test (ignored bench): <blocks>x<ops> for forest release cost. | `qmdb-state:forest.rs:2334` | bench-only |
| `N42_SF_BENCH_DIR` | /data/n42-build/agents/persist-sf/bench (test) | see Default | Test: directory for static-file benches. | `storage/provider:providers/static_file/n42_sf_seg_tests.rs:309; storage/provider:providers/static_file/n42_sf_tests.rs:329` | bench-only |
| `N42_SF_BENCH_KEEP` | unset: bench dir removed (test) | see Default | Test: keep the bench dir. | `storage/provider:providers/static_file/n42_sf_tests.rs:423` | bench-only |
| `N42_SHARD_MIX_DUMP` | unset: test returns (test) | see Default | Test: path to dump shard-mix output. | `engine-types:output_shards.rs:3697,3756` | bench-only |
| `N42_SLED_COMPAT_WRITER_PATH` | unset (test) | see Default | Test: child-process writer path for sled compat. | `dependency-compat-tests:lib.rs:29` | bench-only |
| `N42_WRITE_VECTORS` | unset: compare to stored vectors (test) | see Default | Test: rewrite deferred_execution_vectors.json instead of comparing. | `n42-testing:dev.rs:1951,2365` | bench-only |

## Dead names (in docs, not read by any code in this tree)

These appear in docs/ or CLAUDE.md but in no `.rs` file. Some belong to unmerged bench-tree branches or were removed; `N42_NEW_PAYLOAD_TOTAL`, `N42_PAYLOAD_CACHE_HIT` and `N42_STATE_ROOT_SKIPPED` look like metric/counter names, `N42_CUSTOMIZATIONS` is a file name, and `N42_RETH_SOURCE` is read by `scripts/reth-sync.py` (so it is not dead).

- `N42_BEHIND_POOL_THREADS`
- `N42_BLOCK_DIRECT_ONLY`
- `N42_BUILD_READS_NO_CHANGESET`
- `N42_CHILD_ON_OUTPUT`
- `N42_CUSTOMIZATIONS (appears only in scripts/tests/examples)`
- `N42_DEFER_STATE_ROOT`
- `N42_DELTA_LOG`
- `N42_DENSE_IDS`
- `N42_FAULT_IMPORT_DELAY_MS`
- `N42_FAULT_PERSIST_DELAY_MS`
- `N42_FINISH_BREAKDOWN`
- `N42_NEW_PAYLOAD_EVM`
- `N42_NEW_PAYLOAD_TOTAL`
- `N42_NO_POST_STATE_MAP`
- `N42_ONE_PROBE_BODY_WAIT_MS`
- `N42_PACING_FROM_SEND`
- `N42_PAYLOAD_CACHE_HIT`
- `N42_PLAN_BODY_WAIT_MS`
- `N42_PRUNE_WATERMARK`
- `N42_QMDB_FLUSH_OFFLOCK`
- `N42_QMDB_VERIFY_ON_START`
- `N42_QUEUE_LEDGER_LOCK`
- `N42_RETH_SOURCE (appears only in scripts/tests/examples)`
- `N42_ROOT_LOOKUPS_EARLY`
- `N42_SKIP_STATE_ROOT`
- `N42_SKIP_TX_VERIFY`
- `N42_STATE_READ_QMDB`
- `N42_STATE_ROOT_SKIPPED`
- `N42_VIEW_JOURNAL_FILTER_ASYNC`

## Undocumented before this file

Read by code, named in no docs/ file and not in CLAUDE.md:

- `N42_BENCH_SENDERS`
- `N42_BLOCK_TOPIC_ALWAYS`
- `N42_BUILD_DECLINE_EMPTY_STEP`
- `N42_BUILD_REFUSE_STALE_PARENT`
- `N42_BUILD_THROTTLE_HARD`
- `N42_BUILD_THROTTLE_MAX_HOLD_MS`
- `N42_BUILD_VERIFY_BATCH`
- `N42_COMPACT_BODY_FILL`
- `N42_COMPACT_BODY_INDEX`
- `N42_COMPACT_BODY_WAIT`
- `N42_CORE_LAYOUT_BUILD_SIBLINGS`
- `N42_FOLLOWER_CHECK_ON_SHARDS`
- `N42_FOLLOWER_CHECK_THREADS`
- `N42_FOLLOWER_EXEC_GATE`
- `N42_FOLLOWER_GRAFT_INDEX`
- `N42_FOLLOWER_GRAFT_RANGES`
- `N42_FOLLOWER_ROOT_THREADS`
- `N42_FRAME_ARCS`
- `N42_FRAME_GATEWAYS`
- `N42_FRAME_SELECT_PARALLEL`
- `N42_NO_OWN_BLOCK_REUSE`
- `N42_OVERLAY_FILTER_CAP`
- `N42_OWN_BLOCK_BY_HEADER`
- `N42_PAYLOAD_SERVE_FRESH_BUFFERS`
- `N42_PRUNE_LEAN_DRAIN_TXS`
- `N42_PRUNE_MAX_FOLD`
- `N42_QMDB_OFFSET_SEGMENTS_AHEAD`
- `N42_RAW_SHARED_DECODE`
- `N42_READ_DEPTH_COUNTS`
- `N42_RELEASE_BENCH`
- `N42_ROAD_DEBT_SWEEP`
- `N42_SF_BENCH_DIR`
- `N42_SF_BENCH_KEEP`
- `N42_SHARDS_READY_FIRST`
- `N42_SHARD_MIX_DUMP`
- `N42_SLED_COMPAT_WRITER_PATH`
- `N42_TX_INGEST_BLOCK_TXS`
- `N42_TX_INGEST_GATE_STRICT`
- `N42_TX_INGEST_RECOVER_PIN`
- `N42_TX_ROOT_THREADS`
- `TWIG_NO_SIMD`
