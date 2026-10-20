# Merge elision: the leader's output without the merged bundle

Status: design, 2026-10-20. Background is in BREAKTHROUGH_DESIGN 10.187-10.191 (the floors after the frame road) and
10.113-10.118 (the build's execution is bound by memory latency per thread, and gets slower when work runs on its
cores' SMT siblings).

## 1. What the merge is and costs

After the fields are published, the leader clones every account of the frozen output shards, plus the residual laid
over them, into one fresh `AddressHashMap<BundleAccount>`. This is `OutputShards::merged_state_split`
(engine-types/src/output_shards.rs). It runs on `n42-shard-merge`, a background thread.

| measure (road + cuts + depth 3, RF3b) | value |
| --- | --- |
| `shard_merge_ms` / `merge_fill_us` | 74.5 / 74.6 ms a block, single thread |
| start / end | seal + 94 / seal + 169 ms (~1.8 merges in flight at a 42 ms gap) |
| accounts | ~147,000 a block, ~510 ns an account (latency-bound random inserts and clones) |
| demand | ~50 MB of cache lines a block, ~1.3 GB/s; not a bandwidth load on a 12-channel host |

It is off the seal chain. Its cost is where it runs. The background set includes the SMT siblings of the 64 build
cores (`N42_CORE_LAYOUT_SIBLINGS=background`), and the stage du sampler shows those siblings 25-46% busy during the
full window. 10.113 measured the build's execution at 13 ms with idle siblings and at 16-17 ms with the background on
them. The layout with idle siblings starved the rest of the layer (C16IDLE, 10.118), so it could not be kept. Taking
the merge out lowers the load on those siblings without taking CPUs from the layer.

## 2. Who reads the merged bundle (audit, bench configuration)

| consumer | reads | path | change |
| --- | --- | --- | --- |
| next own build: `built_executions::wait_for_state` | point lookups | critical | prefer the `Sharded` arm, which already exists (direct_build.rs ~1069) |
| tree's in-memory overlay (`MemoryOverlayStateProviderRef`, provider/src/providers/state/memory_overlay.rs: account, contains_key, storage, bytecode) | point lookups, newest block first | builds anchored in the tree, RPC | consult a sharded-output registry before `execution_output.state` |
| storage-overlay `BlockLayer::bundle` (builder.rs ~95) | point lookups | a foreign block on own parents | same registry |
| overlay filter `BlockFilter::build` (overlay_filter.rs ~171) | every key | background | build it from the shards' keys |
| metrics (`state.len()`) | lengths | off-path | shard sums |
| persistence v2 `write_state` | `contracts` only; reverts come from `n42_deferred_reverts` | background | keep `contracts` in the thin bundle |
| QMDB root, deferred reverts, lean notifications, exec cache (Skip), receipts | nothing from the map | | none |

Readers that iterate the whole map exist only in modes the bench does not run: non-lean canonical notifications,
`N42_ENGINE_EXEC_CACHE=on`, storage v1 `write_state`, hashed tables on, and `N42_FIELDS_AT_SEAL=verify`. Under
elision these modes must refuse it.

## 3. The design (`N42_MERGE_ELIDE=1`, default off)

1. **The thin output.** The merger thread builds `BlockExecutionOutput { state: thin, result }`. `thin` is the
   residual's accounts (already a `BundleState`), the contracts of every shard, and an empty revert list. The reverts
   are owed through `n42_deferred_reverts`, as `N42_ANSWER_BEFORE_REVERTS` already does. `state_size` is the shard sum.
2. **The registry.** `n42_sharded_output` is a small crate, or a module of storage-api so the vendored overlay can
   reach it. It maps `Arc::as_ptr(&execution_output)` to `Arc<FrozenShards>` plus the residual's address set, with the
   same lifetime rules as deferred-reverts: register before `state_ready` and remove when the block leaves memory
   (persisted and evicted, or unwound).
3. **Lookups.** One function, `n42_sharded_output::account(output, address)`, returns the shard's account with the
   residual laid over it, exactly what `merged_state_split` would have stored at that key. It falls back to
   `output.state.state.get(address)` when there is no registry entry. The same goes for storage slots and
   `contains_key`. The four overlay sites and `BlockLayer` call it. Bytecode stays in `thin.contracts`.
4. **The next own build.** `wait_for_state` returns `Sharded` for an elided entry even after `StateReady`.
5. **The filter.** It is built from the shards' address sets plus the residual's keys.
6. **The guard.** The knob is refused, with a warning and no elision, when any whole-map mode in section 2 is on.

## 4. Correctness

- Equivalence test: for random shards plus residual (including overlaid, destroyed and storage-changed accounts),
  every registry lookup equals a lookup in `merged_state_split`'s map, and the thin bundle's `contracts` and
  `state_size` equal the merged ones.
- Fleet gates: d2gate (fields mismatches 0, verify pass), and a follower RPC read of a few accounts against the
  leader's, through the existing verify.
- Lifetime: a counter of registry entries on the ingest line. It must stay bounded, at about the tree's in-memory
  blocks.

## 5. What it should show, and the test

- `shard_merge_ms` goes to ~0 and the background loses ~1.8 threads of latency-bound work.
- The deciding numbers are `par_exec_ms` (19-21 today; 13 is the idle-sibling bound) and `batch_cpu_max_ms`. If
  `par_exec` does not fall by at least 1.5 ms, the sibling-pressure hypothesis is wrong for the merge alone, and the
  next candidate is tokio's ingest load (17-19 CPUs, the largest background consumer, du sampler).
- Stage: X18 controls against road + cuts + depth 3 (dt's RF3 set) + `N42_MERGE_ELIDE=1`, two pairs. A third pair of
  RF3 without elision isolates the knob.

## 6. Stages

- Stage 0: registry, thin output, lookups, test of equivalence. Wire `wait_for_state` and the overlay. Default off.
- Stage 1: filter, metrics, guard. Fleet stage.
- Left for later: the follower's import output, which is merged the same way on non-leaders. At E=1 the leader's
  merge is the only one per block.
