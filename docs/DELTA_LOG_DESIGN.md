# A per-block delta log in place of the post-state map

Design note, 2026-10-17, read-only on code (no build, no leg). Direction 4b of docs/ARCHITECTURE_TOWARD_5M.md.
Figures quote docs/AFTER_MERGE_CUT.md (AMC), docs/CYCLE_TAIL_ANALYSIS.md (CTA), docs/STAGE_BR_ANALYSIS.md and
BREAKTHROUGH_DESIGN.md (BD) on X17; anything else is an estimate and says so. Code read: `output_shards.rs`
(`FrozenShards`, `merged_timed`, `merged_on`), `payload.rs` (the `n42-shard-merge` thread), `built_executions.rs`,
`bin/n42/src/payload_serve.rs` (`own_block_by_header_with`, `hand_off_own_build`), `n42-deferred-reverts`, the vendored
`reth-provider` (`save_blocks_inner`, `write_state`, `memory_overlay.rs`), `reth-chain-state` (`n42_canon_notify_lean`),
`reth-storage-overlay` (`builder.rs`), and the upstream engine tree at v2.7.0 (`on_inserted_executed_block`).

## 1. Who reads the merged map

The map is `BundleState.state` (~190k `BundleAccount`s, ~70 MB) plus `reverts` and `contracts`, built on
`n42-shard-merge` after the QMDB root and published as `BlockExecutionOutput` at `StateReady` and `Complete`.
Times are after the seal on X17 means (AMC 4: root end ~63, merge end ~126, state ready 129, handed 150, canonical 157,
answer 189).

| consumer | when | what it reads | access | on L? | can be lazy? |
| --- | --- | --- | --- | --- | --- |
| own-block answer (`own_block_by_header_with` -> `built_executions::take`) | waits for `Stage::Complete` | nothing of the map: the header match, the block, fields; it waits only because `Complete` carries the map | -- | **yes: the whole merge is a wait** | yes |
| hand-off insert (`ExecutedInsert` -> tree `on_inserted_executed_block`) | state ready +21 | `execution_output.state` whole: the cross-block execution cache `update_with_guard` (when the cache's block is the parent); then stored in `TreeState` | sequential pass + kept | yes (before the answer) | only if the answer stops waiting for it |
| engine newPayload (header-only, after the insert) | +7 .. +32 | finds the block executed; reads no state | -- | yes (32 ms; gone with `N42_ANSWER_AT_INSERT`) | yes |
| child build | shards ready (~seal +9) | shards + residual (`ParentState::Sharded`, `N42_CHILD_ON_OUTPUT`) | random | no (done) | already |
| QMDB root / fields | seal +27 .. +63 | ops-ahead encode of the shards (`sorted_operations_from_execution` on the view) | sequential | no | already |
| hashed post-state | beside the root | `hashed_post_state_of(view)`; the map only when an account is destroyed | sequential | no | already |
| revert set | the late half of the merge | shard reverts, filled through `n42_deferred_reverts` (`resolve`, `complete_in_place`) | sequential | no (ABR) | already |
| output registry `register` | merge end -> state ready | the output's address; eviction frees an older map (32-36 ms p90, BD 10.144) | -- | yes (until the off-lock free) | -- |
| canonical notification | canonical | the outcome clone; empty under `N42_CANON_NOTIFY_LEAN=1` (in X17) | sequential clone | no | lean: no reader |
| in-memory reads (`MemoryOverlayStateProvider`: RPC, pool validation, `latest` callers) | from the insert until persisted | `execution_output.account / storage / bytecode` per in-memory block | **random** | no | yes, by shard probe |
| flattened overlay (`reth-storage-overlay` `extend_state`) | engine validation of a foreign child (tenure change), overlay builds | the whole state of each in-memory block | sequential | no | yes, from the delta |
| persistence (`save_blocks_inner`) | canonical + persistence lag | `n42_plain_reverts` (reverts), `to_plain_state_and_reverts` (accounts, storage), `contracts` | sequential, then sorted by address | no | yes |
| reorg / unwind | rare | in memory: the stored `ExecutedBlock`s; on disk: changesets via `get_state` | DB path | no | unchanged |

Two facts follow. (a) **No answer-path consumer reads the accounts**: the answer waits for the map only because the
hand-off inserts it into the tree before the answer, and `take` waits for `Complete`. (b) Every reader that wants the
whole map is a sequential pass over it (persistence, overlay flattening, the execution cache, notifications); the only
random reader is the in-memory state provider, which a probe into the frozen shards (`FrozenShards::get` + the residual)
serves as the child build already does.

## 2. The design

**Per block, kept:** the frozen shards (`Arc<FrozenShards>`, immutable, recycled on drop), the residual bundle (the
executor's few accounts, contracts, system-call reverts), the receipts, the hashed post-state, the QMDB prepared block.
**Added:** a `DeltaLog` built off-path by one sequential pass over the shards (or emitted per batch in the parallel step
and concatenated by shard range):

| field | content | size (200k transfers, ~190k accounts) |
| --- | --- | --- |
| `accounts` | address-sorted `(Address, nonce, balance, code_hash?, status)`; the residual laid over | ~64 B x 190k = ~12 MB |
| `originals` | the pre-block `(nonce, balance)` of each, for reverts / changesets | ~40 B x 190k = ~8 MB |
| `storage` | `(address, slot, old, new)` sorted; empty on transfers | 0 on the flood |
| `created` / `destroyed` | address lists (destroyed -> wipe marker) | ~0 |
| `contracts` | the shards' + residual's bytecodes | ~0 |

**Registry.** A generalisation of `n42-deferred-reverts` (`n42-deferred-state`): the published
`BlockExecutionOutput` is keyed by its address, and its entry holds `{shards, residual, delta: OnceLock, map: OnceLock}`.
`resolve_state(output)` returns the map if built, else a view: `account(addr)` probes shards then residual; `iter_sorted()`
walks the delta (built on first use). The registry keeps the output alive while its entry exists, so the address is not
reused -- the same contract as the revert registry.

**Exactness.** reth's `BlockExecutionOutput` / `BundleState` are concrete types; the upstream engine tree
(`on_inserted_executed_block`, `TreeState`, reorg re-inserts) holds and reads them. Hence the order of stages: stage 1
keeps a real, complete `BundleState` for every reth reader and only moves *when* it is built (behind the answer);
stage 3 hands the tree a thin bundle and requires every reader to resolve through the registry. Readers by crate:

| reader | crate | stage-3 treatment |
| --- | --- | --- |
| memory overlay `account/storage/bytecode` | vendored `reth-provider` | additive: `n42_deferred_state::account(&output, addr)` first |
| `extend_state` (flattened overlay) | vendored `reth-storage-overlay` | extend from `iter_sorted()` |
| `to_plain_state_and_reverts`, `n42_plain_reverts` | vendored `reth-provider` | build the `StateChangeset` / `PlainStateReverts` from the delta (already sorted) |
| notification outcome | vendored `reth-chain-state` | lean (no reader) or `n42_completed_outcome` materialises from the delta |
| execution cache update | **upstream engine tree** | cannot be patched: precondition (stage 0 counter) that it never updates on an own block, else the cache would hold N-1 values under N's hash -- a silent wrong read for a foreign child executed in the tree; fallback: materialise before the insert for the block a tenure hands over on |
| `TreeState` storage, reorg re-insert | upstream | the thin bundle travels; readers resolve; the registry entry lives as long as any `Arc` clone |

## 3. Cost

| quantity | today | stage 1 | stage 3 |
| --- | --- | --- | --- |
| merge on the answer path | 61.9 (serial), 42 (8 parts) | **0** (same 62 ms serial, behind the answer, on the background thread it uses today) | 0, no map |
| delta pass | -- | -- | est. 8-15 ms one thread off-path (sequential reads of ~270 hashbrown maps + a Vec push; radix sort of 190k x 64 B ~3-5 ms), vs 61.9 of random inserts into a 70 MB table |
| bytes per block | map ~70 MB + shards until `StateReady` (~70 MB, transient) | shards held +~65 ms longer (until the map; +~70 MB x 1.5 blocks transient) | shards (~70 MB) + delta ~20 MB; no map: **-50 MB per in-memory block** |
| retained | registry keep 3 + tree's in-memory blocks until persisted, each with a map | same | the same blocks, each shards + delta; no 200k-entry map frees (the BD 10.144-10.150 class) |
| persistence | `to_plain_state_and_reverts` + sort per block (part of 0.17 ms / 1k) | same | sorted input: est. -3..-8 ms a block |

**L and the gap (estimates on AMC 4, Vb).** Stage 1 files the answerable state at root end + ~3 ms (~66 after the
seal) and answers from the registry match without waiting for the insert or the engine's newPayload (Vab already showed
canonical -> answer 32 -> 0.8): **L 178-189 -> ~70-85**, p90 ~100. Floors (AMC 6): gate loop (sealed_at + L + c)/6 =
(36 + 80 + 13)/6 = 21.5, vote window (A + c)/4 with A = L - lead ~55 -> ~17: **both stop binding**; the gap falls to
max(builder 35.7-37.5, fields two-cycle 33-37, root 29-32, tick 30) + jitter ~5 = **~41-42 ms** (43.4 today; 4.75-4.9M/s
at 200k), and blocks in flight L / gap 4.2 -> ~2, which is what the five-block window and vote-at-check need. The
architecture note's ≤135 bound is conservative; the binding question is the seal (the merge's work does not change, only
its order, so the 10.155 failure -- new threads on the critical set -- does not recur; memory bandwidth is the risk).

## 4. Stages

| stage | gate | what changes | proof counters | risks |
| --- | --- | --- | --- | --- |
| 0 timers | none (always on, info line) | `answer_map_wait_us` (take -> `Complete` minus root end), `insert_cache_update` (did the tree's execution cache update on an own block, and its us), `overlay_reads_by_source` (bundle / historical) per in-memory block, `persist_plain_us` per block, in-memory blocks until persisted, foreign-child validations in the tree | the map wait = merge + register on L (expect 60-65 ms); cache updates on own blocks = 0 (precondition of stage 3) | none |
| 1 (one week) | `N42_STATE_READY_WITHOUT_MERGE=1` | `StateReady` and an answerable `Complete` filed at root end with `ParentState::Sharded` + receipts + hashed + fields; the own-block answer returns VALID from the match; the merge keeps its thread and order; the `ExecutedInsert` is sent when the map lands; a forkchoice naming N waits on `insert_landed(N)` (node-local barrier) | answer-path merge 61 -> ≤5 (target 0); L ≤135 (expect 70-85); `sealed_at` within +1 ms of the control; seal -> fields unchanged; `fcu_waited_for_insert` p99 ≤ 5 ms; `insert_outdated` 0; `fleet7-verify` clean, fields_mismatches 0 | ordering: a forkchoice or a foreign child before the insert (barrier + counter); a sibling after a TC (`head_move_needed` runs at the deferred insert); a destroyed account forces the map path (`stage1_fallback` counter); the answer no longer implies the tree has N -- vote semantics unchanged (PHASE_D 11) |
| 2 | `N42_DELTA_LOG=1` (+ `=verify`) | the delta pass off-path; persistence writes plain state and reverts from the delta, `extend_state` uses it; the map still built for the tree | `delta_pass_ms` ≤15; `persist_plain_us` -3..-8 ms; verify legs: delta-derived `StateChangeset` == map-derived, `delta_mismatches` 0; `fleet7-verify` + `roll --kill` recovery clean | changeset exactness (originals for accounts created in the block, wipe markers); SIGKILL between delta and persist (the delta is in memory only, like the map today) |
| 3 | `N42_NO_POST_STATE_MAP=1` | the tree gets a thin bundle (residual + contracts) registered with its shards + delta; every vendored reader resolves; the merge thread is gone | merge 0 everywhere; EL RSS -50 MB x in-memory blocks; no `register` eviction free; overlay reads == materialised reads on a sampled verify leg (`overlay_mismatches` 0); `insert_cache_update` stays 0 | an upstream reader of `execution_output.state` missed by the audit reads an empty map -- silent (verify mode materialises in background and compares); reth bumps can add readers (add to the bump checklist); RPC `eth_getBalance` at the head served by probes |

**Undo / reorg.** A block that is never committed: stage 1 inserts it late or not at all (dropped as outdated, no
canonical reader); stage 3's registry entry dies with the last `Arc`. On-disk unwind reads changesets written by
persistence, unchanged in stages 1-2 and checked by the verify leg in stage 2. In-memory reorg moves stored
`ExecutedBlock`s, whose thin bundles resolve as long as the entries live (they live with the `Arc`).

**Follower side.** On E=1 the followers import once through the shared EL, so they take the leader's path. A follower on
its own EL (gov5 interop, the Rust fleet) builds its bundle in the follower import; the delta applies there later, not on
L of this box. **gov5 interop:** stateRoot, receipts root, headers, the wire and the vote rule are byte-identical: the
root never read the map, and the delta is node-local memory.

## 5. Order and the decision rule

Stage 0 and 1 together are the one-week step of ARCHITECTURE_TOWARD_5M 10.B; they count if, on two X17 pairs, the
answer-path merge is ≤5 ms, L ≤135 with `sealed_at` within +1 ms, and the drain rate does not fall. Stage 1 alone takes
the merge off L without touching a reth type, so stage 2 (persistence, -3..-8 ms a block off-path) and stage 3 (memory,
the free class) are justified by memory and by direction 2 (vote at check: two to three blocks in flight instead of four),
not by the gap. Run the five-block window (`N42_FAR_AHEAD_BLOCKS=2`) on top of stage 1 as the cheap proxy for direction 2.
