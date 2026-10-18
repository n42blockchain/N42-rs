# Carried depth 3 for the Rust fleet

Design analysis, 2026-10-18. Code read at bench/main-x11t16 (2d2f4934e); nothing built or run. Sources: DEFERRED_DEPTH_2_DESIGN
(DD2, the depth-2 inventory this generalises), PHASE_D_DEFERRED_EXECUTION (PD), ROOT_PIPELINE_DESIGN (RP, C1/C2),
AFTER_MERGE_CUT (AMC), BUILD_AHEAD_RESULTS, ARCHITECTURE_TOWARD_5M (A5M), BREAKTHROUGH_DESIGN (BD) 10.162-10.163.
Rule at depth D: header N carries `result(A_D(N))`, the ancestor D blocks back **on N's own chain, by hash**; blocks
1..=D carry the genesis result. D=3: **the same four fields (stateRoot, receiptsRoot, logsBloom, gasUsed) carry N-3's
result instead of N-2's; no extra set, no header layout change.** The bench runs D=2 today (`n42_fleet7_bench_d2.json`).

## 1. Every place depth 2 is assumed, and the change for depth 3

The one structural difference: at D=2 the ancestor is named by the parent header (`parent.parent_hash`); at D=3 it is the
grandparent's parent, which no header in hand names. Everything else is a constant, a `>= 2` that is already generic, or a
capacity. Items marked **silent** would run without error on a D=3 genesis and carry N-2 (wrong rule, Rust nodes agreeing
with each other): they are the first-leg hazard and must be pinned by test vectors.

| # | file:line | depth-2 assumption today | change at D=3 |
| --- | --- | --- | --- |
| 1 | `crates/chainspec/src/qmdb.rs:114` `MAX_DEFERRED_EXECUTION_DEPTH = 2`, `:118` `SUPPORTED_... = 2`, `:191` range, `:143` Display messages | the rule and the build stop at 2 | MAX 3; SUPPORTED stays 2 until stage 3 (start-up refuses D=3: `NotImplemented`), then 3; messages "1..=3" |
| 2 | `crates/n42/h2-consensus/src/deferred_depth.rs:38` `MAX_DEPTH = 2`; `:42-49` `ParentLink {number, hash, parent_hash}`; `:70-76` `ancestor_hash` matches 1 / 2 | the ancestor must be reachable from the parent link | `ancestor_hash(parent, depth, lineage: impl Fn(&B256) -> Option<B256>)`: 3 = `lineage(parent.parent_hash)`; a miss is `CarriedError::AncestorUnknown`, never a fallback. `result_source` (`parent.number < depth`) and `certified_number` are already generic; add the D=3 column to the doc table and tests |
| 3 | `crates/n42/engine-types/src/hotstuff_consensus.rs:150-156` `ancestor_hash`: `depth <= 1 ? parent : parent.parent_hash` | **silent**: depth 3 returns the grandparent | `Option<B256>` through the lineage (item 4); callers `:191` `parent_link`, `:176-189` `ancestor_executed_fields`, `:203-211` `ancestor_result_is_recorded`, `:250-264` `..._or_built` (files under the depth-D hash) |
| 4 | `crates/n42/qmdb-reth/src/executed_fields.rs:55` `KEEP 256`, `:59` `ALIASES_KEPT 16`, `:171` `note_built` | registry by hash, sealed->built aliases; no parent links (DD2 item 15: "for D=3 the registry would need parent links") | a lineage map `note_parent(hash, parent_hash)` (256, evicted with the entries), written by every build (`payload.rs:469`: build N notes N-1 -> N-2, so build N-2 noted the N-3 link N needs) and by the follower's header check; `parent_of` falls back to the provider's `sealed_header(hash)` (restart, late joiner). Aliases: N-3's (sealed, built) was noted at build N-2, 16 entries reach it. `fields_from_descendants` (`:149`, takes `depth: u8`) is generic |
| 5 | `crates/n42/engine-types/src/payload.rs:207` and `:226-232` `Some(parent.parent_hash)` as the wait key | **silent**: the seal's wait and `missing_half` look at N-2 | the depth-D hash from item 3 (`parent_fields_wait_on` keeps its values); `:2195-2201` error names it |
| 6 | `payload.rs:469` `note_built` when `depth >= 2`; `:1509` gas limit over the carried `gasUsed` when `depth >= 2` | generic; the limit window (DD2 item 19) widens to three blocks | none in code; a unit test for a limit shrinking three times |
| 7 | `payload.rs:3776` `rename_parent`: `record_wait` when `carried_depth >= 2` (DD2 item 8, the barrier) | the root job of N waits for **N-1's** fields itself | unchanged and essential: depth moves the seal's wait, not the root's (N's tree still leases N-1's) |
| 8 | `bin/n42/src/follower_import.rs:650-661` `wait_for_ancestor_fields` via item 3; call sites `:2586`, `:3042` | **silent** through item 3 | inherits item 3; the vote road now waits N-3 |
| 9 | `follower_import.rs:300` `PARENT_OUTPUTS_KEPT 4` (env 2..=16), `:420` `FOLLOWER_SHARDS_KEPT 2`; `crates/n42/h2-execution/src/driver.rs:114` `DEFERRED_IN_FLIGHT 2`, `:129` `_MAX 3`; `crates/n42/h2-node/src/service.rs:568` `FAR_AHEAD_BLOCKS 1`; `engine-types/src/built_executions.rs:47` `DEFAULT_KEEP 3` (env 3..=16) | capacity for a check that runs <= 2 ahead of the tip | the vote no longer waits N-2's root, so checks run one block further ahead: in-flight MAX 3 -> 4, `PARENT_OUTPUTS_KEPT >= cap + 2` (DD2 4.4) -> 6-7, `FAR_AHEAD >= D` (bench sets 2 / 6 already), `BUILT_KEEP >= D + 2` (bench 5 / 8 already) |
| 10 | `driver.rs:1926-1930` `set_deferred_depth` refuses `> MAX_DEPTH`; `:1138` passes the depth to settlement | gate only | follows item 2 |
| 11 | `crates/n42/h2-execution/src/settlement.rs:257-261` `advance_at_depth`: `certified_number` + `lineage.ancestor_at` | already generic | `safe` = committed - 3; `finalized` = certified and <= persisted (unchanged rule, one block later); add a `|_| 3` case to `tests/settlement_tags.rs` |
| 12 | `bin/n42/src/main.rs:184` restart restores the frontier only when depth `== 2`: one parent's result (`remember_checkpoint_parent`) | at D=3 the first child after restart at H needs `result(H-2)`, the next `result(H-1)` | restore both: H-1 and H-2 roots (`persisted_state_root`) + receipts from the database, seeded in order |
| 13 | `main.rs:227-235` historical resolver `(1..=2).contains(&depth)` | refuses D=3 | `1..=MAX` (the loop over `descendants` is generic) |
| 14 | `crates/n42/qmdb-reth/src/recovery_frontier.rs:7-12` `Frontier {number, hash, parent_hash, parent_root}`; `node_state.rs:1952` skips the frontier save unless depth `== 2` | one ancestor per checkpoint frontier | the frontier codec gains `ancestors: [(hash, root); D-1]` (format version 2, v1 still read for D=2), saved when depth `>= 2`; a checkpoint must not compact away H-2's state before it is recorded |
| 15 | `bin/n42/examples/export_recovery_prefix.rs` | exports canonical blocks; a validated replay into a fresh EL verifies header B at B+D | export through `LAST_BLOCK + D` (three trailing headers) so the last block's result is checked |
| 16 | `bin/n42/src/main.rs:98`, `crates/n42/h2-node/examples/h2_validator.rs:187,490` `check_deferred_execution_depth` | generic | prints "depth 3"; fleet scripts' `f7_genesis_depth` already read it |
| 17 | genesis `crates/chainspec/res/genesis/n42_fleet7_bench_d2.json:101-106` (`deferredExecutionDepth: 2`, `extraData` 0xd2...) | the fork digest is genesis-hash[..4]: depth must change the hash | new `n42_fleet7_bench_d3.json` (and `n42_fleet3_bench_d3.json`): depth 3, `extraData` 0xd3..., `deferredExecutionTime: 0`; never edit the D=2 file |
| 18 | `crates/n42/n42-testing/src/dev.rs:2353` D=2 vector test; `crates/n42/qmdb-reth/tests/deferred_depth.rs:79-86` (3 is `OutOfRange`) | tests pin 2 | a D=3 vector test (`carries: [1, 2, 3, 4]` from block 4), parser tests for 3 and 4 |

Not depth-sensitive (read, no change): `fields_at_seal` early rename (keyed on N-1), the includability check on N-1's
**output** (`check_on_parent_output`), the execution chain exec(N-1) -> view -> exec(N), the committee link
(`parentBeaconRoot` from the parent header's `receiptsRoot` field), `normalize_to_gov5_h2_from_header`, `payload_serve.rs:672`
(`remember` under the sealed hash).

**Safety.** The carried result is a function of the chain by hash, so a header cannot carry "the wrong N-3". On the optimistic
path N-1 is committed when N is proposed; on the timeout path n-f voters locked on QC(N-2) when they voted N-1, so N-2 cannot be
replaced and N-3 is committed. A conflicting N-2' means N is on another chain: N built on N-1' over N-2' carries
`result(N-3)` of the common ancestor (same fields, different parent), checked against the result recorded under that hash.
What changes: a vote on N attests N-3's result, so a divergent execution of B is caught at B+3 (one block more of chain on a
disputed state than D=2); recovery is today's (mismatch -> no votes -> TC -> resync). `fields_mismatches` stays the gate.
**Lag.** `safe` moves to committed - 3: ~3 x 40 + 45 = ~165 ms from proposal to certified, ~+40 ms over D=2. `latest` reads
are unchanged (the QMDB view is the committed head). `eth_getBlockByNumber(N).stateRoot` is N-3's; proofs and receipts of B
anchor at header B+3; the base fee of N responds to block N-4's gas.

## 2. Expected effect (measured numbers, X17 on the 600M set)

| quantity | D=2 today | D=3 estimate | basis |
| --- | --- | --- | --- |
| `parent_fields_us` mean / p90 | 5.5-6 / 10-13 | ~0 / ~0 | fields(N-3) at seal(N-3) + 63 (p90 78-84); seal(N) at seal(N-3) + 3 x 40 = 120: 36-57 ms of slack (RP 0, AMC 4) |
| fields cycle floor | (63 + 2) / 2 = 33-37 | (63 + 2) / 3 = 22 | AMC 6 |
| builder floor (seal -> bundle(N-1) + par_run + tail) | 35.7-37.5 mean, `sealed_at` p50 31 | unchanged; an earlier seal start waits on output(N-1) instead (seen at every cut since cd) | AMC 3, 6; BD 10.163 (par_exec 16 ms memory-bound) |
| root | gated 24.5-26, cycle 29-32, util 0.57-0.61 | the seal no longer paces it: queue wait 2.9 -> 10.2, util 0.77-0.86 without C1 (RP 3 replay) | RP 2-3 |
| gate loop (sealed_at + L + c) / 6, vote window | 36.7-39.6; vote window open since 10.162 (quorum p90 8) | unchanged by depth | AMC 6, BD 10.162 |
| cost of one more block in flight | -- | +1..+3 ms of seal (two-ahead +3-4, five-block window +5) | BD 10.149, 10.153, 10.159 |

Gap = max(floors) + jitter (5-6 ms on every leg, AMC 1). With the fields floor gone the largest are the builder (35.7-37.5
mean) and the gate loop (33-37 with the answer before the merge, L -27):

| configuration | binding floor (mean) | estimated gap | M tx/s at 200k |
| --- | --- | --- | --- |
| X17, D=2 (measured) | builder / fields / gate within 3 ms | 42.3-43.5 | 4.60-4.75 |
| D=3 alone | builder 35.7-37.5, root 31-35 with its queue | 40.5-43.5 (incl. +1..3 in flight) | 4.6-4.95 |
| D=3 + C1 stages 1-2 (lookups early + overlay, gated root -5) | builder | 40-42 | 4.75-5.0 |
| D=3 + C1 + builder -5 (par_exec layout or delta log, A5M 4b) | root ~26-28 gated, builder ~31 | 36-38 | 5.25-5.55 |

So D=3 removes one floor of three and alone is worth +0..+4%: necessary for 5M at 200k, not sufficient. It pays only together
with C1 under the root and a cheaper build, which matches A5M section 9 (+0..+0.2 alone, +0.3..+0.5 combined).

## 3. Memory cost and risks

| item | cost at D=3 |
| --- | --- |
| executed-fields registry + lineage | ~330 + 64 B a block x 256: negligible |
| one more unlanded output on the EL (published output + shards: bundle ~60-120 MB at 200k) | +0.1-0.2 GB against EL peak RSS 50-54 GB; `N42_PARENT_OUTPUTS_KEPT` 6-7, `N42_BUILT_KEEP` >= 5 (bench 8), `N42_LEADER_LAYERS` 6 already covers N-3 |
| recovery frontier | two (hash, root) per checkpoint frontier instead of one: bytes |

| risk | likelihood | guard |
| --- | --- | --- |
| a silent `>= 2 -> parent_hash` path (items 3, 5, 8) carries N-2 on a D=3 chain; Rust nodes agree, gov5 would not | high on a naive bump | D=3 vector test (block 4 carries block 1); `carried_number` logged on the phases line and asserted by d3gate |
| lineage miss (tenure handover's `Published` parent, view change, restart) -> `ParentUnknown`, lost view | medium | provider fallback in `parent_of`; counter `lineage_miss`; a handover unit test |
| the root queue becomes the floor (RP 3) | high without C1 | run C1 stage 1 first; read `seal_to_root_start`, root util |
| the in-flight cost (five-block window collapsed 3 of 4 legs on hold/parent bounds) | medium | item 9 caps raised by env only; view timeouts and held-block WARNs counted |
| restart at D=3 untested; frontier format change | medium | stage 3 unit tests + `fleet7.sh roll --kill` |
| mixed-depth members not separated by transport | low (bench is all-Rust) | `extraData` 0xd3 changes the genesis hash and digest |
| divergence caught one block later; gas-limit window three blocks | low | `fields_mismatches` 0, item 6 test |

## 4. Staged plan (each stage default-off, one logical commit each, pushed)

The depth is a chain rule: it comes from the genesis only (`deferredExecutionDepth: 3`). An env override that can differ
between nodes is a fork, so the env role is an opt-in to *accept* it: `N42_DEFERRED_DEPTH3=1` raises SUPPORTED to 3 on that
binary; without it a D=3 genesis is refused at start-up (`NotImplemented`), both in `bin/n42` and `h2_validator`.

| stage | what | proof |
| --- | --- | --- |
| 0 | `carried_number` + `carried_depth` on the build phases line and the follower's check line (counters only) | D=2 legs read carried = N-2 everywhere |
| 1 | rule: MAX 3, `ancestor_hash` with lineage (items 2-4), `note_parent`; no wiring change at D<=2 | unit: D=3 table in `deferred_depth.rs`, registry lineage + alias reach, parser 3 accepted / 4 refused; all D=1/2 tests unchanged |
| 2 | wiring: builder seal wait, follower vote road, settlement, driver (items 5, 8, 10, 11), caps by env (item 9), `n42_fleet7_bench_d3.json`, the `N42_DEFERRED_DEPTH3` opt-in | `n42-testing` D=3 vector test (h2 harness, blocks 1-3 genesis, 4 carries 1); `tests/settlement_tags.rs` safe = committed - 3; `follower_import_tests` a header carrying N-2 at D=3 refused |
| 3 | recovery: frontier v2, restart restores H-1 and H-2, resolver and export at D (items 12-15) | unit: frontier codec v1/v2, restart seeds both; fleet: `roll --kill` of a member and of the EL mid-load, height advances, `fleet7-verify` clean |
| 4 | bench stage (X17 env + `F7_GENESIS=..._d3.json N42_DEFERRED_DEPTH3=1`), 2 legs against 2 D=2 controls, d3gate | `parent_fields_us` mean <= 0.5, p90 <= 1; `fields_mismatches` 0; invalid 0; `fleet7-verify` pass; committed - safe = 3 on every forkchoice; 0 view timeouts / TCs; `lineage_miss` 0; then drain M/s, `sealed_at`, gap, root util |
| 5 | the same with `N42_ROOT_LOOKUPS_EARLY=1` (RP C1 stage 1), then the overlay (stage 2) | root util <= 0.6, gap <= 41 (section 2 row 3) |

## 5. What gov5 must implement for cross-client D=3

- chainspec: `config.deferredExecutionDepth` parsed strictly, 1..=3, depth > 1 only with `deferredExecutionTime` <= genesis
  timestamp (it must already do this for 2 to join a D=2 fleet; if it implements only D=1 today, D=2 comes first).
- the builder's stamping (`ExecutedResultOfHeader`): the stored result of the **great-grandparent by hash** (parent header ->
  its parent's header -> that header's `ParentHash`), own sealed record for chained builds; blocks 1-3 stamp the genesis result.
- `CheckDeferredBlock`: header against the stored result of `A_3(N)`; includability against the **parent's** post-state
  (unchanged); a missing result = abstain, never a fallback to N-2.
- certification and RPC: execution certified at B+3 (`safe` lag 3); proofs and receipts of B anchored at header B+3.
- restart: two results behind the head persisted (gov5's changeset / `ExecutedResult` store keeps them); range sync verifies
  header B at B+3.
- unchanged: header layout and profile (`extraData` view/seal, difficulty, ommers, `withdrawalsRoot` rewards, requests), block
  gossip `[header, txs, verifiers, rewards]`, GossipSub parameters, `parentBeaconRoot` from the parent header's `ReceiptHash`.
- fixtures: a D=3 deferred-execution vector file (from stage 2's test) compared by SHA-256 on both sides, and a genesis with
  `extraData` 0xd3 so a D=2 member cannot share the digest.
