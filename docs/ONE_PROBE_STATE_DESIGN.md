# One-probe state for the build: a dense per-block account layout resolved at plan time

Status: design, with a microbenchmark (`crates/n42/engine-types/tests/one_probe_bench.rs`). No
production code changes yet. Follows `docs/BREAKTHROUGH_DESIGN.md` 10.117-10.124; linked from there as
10.125.

## 1. The measured problem

The leader's build executes ~200,000 plain transfers in 15-16 ms on 64 threads (`par_exec` p50, X11 set,
10.121 and 10.124). What those threads wait for has been measured three ways:

- **Counters (10.117).** The `n42-build` threads retire 0.42 instructions per cycle, stall 74% of their
  dispatch slots in the back end, miss L1D 18.3 times per thousand instructions, and 2.7 of those per
  thousand go to DRAM. The box is 75% idle and its DRAM bandwidth is barely used (25 GB/s), so the build
  is bound by memory latency per thread, not by CPU count, bandwidth or locks.
- **Symbols (10.120).** About a third of a build thread's cycles are the recipient's read below the
  batch's own map: the parent layers (`FrozenShards::get` 5.0%, `MemoryOverlay::basic_account` 5.1%,
  `ShardLayer` 1.9%, `OverlayStateProvider` 1.7%, `WarmDb` 0.8%, samples on hashbrown's control-group
  probe and key compare) ~14%, the QMDB view ~7%, plus per-read software (~17%, removed in 10.121). The
  batch's own map is another ~14%; the loop with `transfer_plain` and the slot writes ~16%, part of which
  is skid from stalled loads.
- **What did not move the median (10.119, 10.121-10.124).** Lookahead hints down the chain
  (`N42_BUILD_MLP`), the per-read software cuts, idle hyperthread siblings (moves it, but starves the
  layer), and the warm read ahead (`N42_PLAN_AHEAD_WARM`: reading every account early on another pool;
  the read itself is the same dependent-miss chain, takes the whole 30 ms window, and contends with the
  build). What these share: they change *when* or *where* the probes run, not *how many* there are, and a
  hint cannot reach a deeper link of a chain whose next address only exists once the previous load
  returns.

So the cost is the **number of dependent cache-missing probes per transfer**. The way down is a layout
where a transfer reaches its sender and recipient in one access each, at addresses known before the
access, so that the accesses of consecutive transfers are independent and the out-of-order core (or a
prefetch k transfers ahead) overlaps them.

## 2. What a transfer touches today

Per transfer, in the batch loop (`crates/n42/engine-types/src/parallel_transfer.rs`
`execute_for_build_opts` 3915, the batch closure `run_batch` from 4012; the parent opened at 4018,
`ReadSetDb` at 4020, `BatchState::with_capacity` at 4024, `transfer_plain` at 4100, `commit_transfer`
at 4107, the slot at 4109):

1. The pooled transaction through `cands[i]` (`Arc<ValidPoolTransaction>`), converted to a `TxEnv`.
2. Three `basic()` reads in `fast_transfer.rs` `transfer_with`: sender 530, recipient 543, beneficiary
   557. Each goes to `BatchState::basic` (`batch_state.rs` 251): a hashbrown `AddressMap<BundleAccount>`
   sized `txs + txs/4 + 1`. With 128 batches of ~1,560 transfers that is 3,584 buckets of 260 bytes
   (a 240-byte `BundleAccount` plus its key): **~1.07 MB per batch map, larger than a Zen 5 core's 1 MB
   L2**, written fresh every block.
3. The sender hits the batch map after the first transfer of its run (runs of 16). The beneficiary always
   hits. The recipient almost never does: it falls through `ReadSetDb` -> `WarmDb` (empty) -> `CountedDb`
   -> `StateProviderDatabase` into the parent's stack, built by `direct_build.rs`
   `leader_layers::open_on` (~1005-1025): for each of the `N42_LEADER_LAYERS` (6 on the fleet, S2) kept
   blocks newest first, the block's residual as an executed-block overlay (`overlay_on_executed` 207,
   `MemoryOverlayStateProvider`), then its `ShardLayer` (`output_shards.rs` 2620-2650) ->
   `FrozenShards::read_account` / `get` (2048) -> `Indexed::get` (611): **a probe of the shard's
   address -> batch index, then a probe of the batch map it names**. Below the layers the QMDB view
   (`qmdb-reth/src/read_view.rs` `read_at` 458, `account` 493): the journals' filters, the offset index
   (`twig-core/src/index.rs` `SharedOffsetIndex::get` 388) over ~2M keys, then the key and the record in
   the mapped entry file.
4. `commit_transfer` (`batch_state.rs` 160) updates the three entries; the slot write is ~375 bytes.

### 2.1 Dependent misses per transfer, today

The flood's block: ~147,000 distinct accounts, recipients drawn from ~900,000, so a recipient is in a
given recent block with p ~ 0.15. With 6 kept layers a recipient walks on average
`sum_{k<6} 0.85^k` = 4.15 layers; 62% of recipients are found in one, 38% go to QMDB. Each block's
16-shard index is ~6.5 MB and six of them ~40 MB, more than a CCD's 32 MB L3, which the merge, the root
and persistence share (10.117), so the index and batch-map probes are L3 or DRAM.

| link (recipient unless said) | lines | per transfer |
| --- | --- | --- |
| batch map probe, absent (control group; map > L2) | 1 | 1.0 |
| absent layers: residual filter (cached) + index control group | 1 each | 0.85 x 4.15 = 3.5 |
| the layer that holds it: index group + bucket, then the batch map's group + entry | 4 | 0.62 x 4 = 2.5 |
| QMDB: journal filter, index bucket, key, record | ~4 | 0.38 x 4 = 1.5 |
| sender, first of its run (always in the parent's layer): batch probe + 4 | 5 | 5/16 = 0.3 |
| sender and beneficiary afterwards: batch map hits in a map larger than L2 | ~1-2 | ~1.5 |
| **dependent, cache-missing loads on the account path** | | **~10** |
| the new batch-map entry for the recipient (260 B into cold memory) | 4-5 written | ~5 RFO |
| the pooled transaction (unchanged by this design) | ~3 | 3 |

Every link of the recipient's walk depends on the previous one answering "not here", and none of their
addresses can be computed before the previous load returns -- the reason the lookahead hints of 10.119
did not help. The counters agree in order of magnitude: 18.3 L1D fills per thousand instructions at
~8,000 instructions per transfer is ~150 fills per transfer, ~20 of them DRAM (the rate also counts the
pool's spin and the rest of the loop).

## 3. What the plan knows, and when

The plan for block N+1 is made on the `n42-frame-settle` thread at build N's selection, while N is still
executing; with `N42_PLAN_AHEAD_BODY=1` its body is made on the plan-body pool (8 threads,
`n42-plan-body-*`) by `payload.rs` `make_prepared_build` (872-937): the candidates in plan order, every
transfer's `(sender, recipient)` key, the body, the hashes, the sender partition at the noted beneficiary
and the empty slots (`frame_blocks.rs` `PreparedBuild` 225, `parallel_transfer.rs` `PreparedExec` 916).
The window from the plan to N+1's batches is ~30-40 ms (10.122).

Three facts shape the options:

- **N's output does not exist at plan time; N's plan does.** The warm read (10.122) had to read at N's
  parent and exclude N's plan for this reason. But which accounts N writes is known exactly from N's plan
  (its senders and recipients) plus N's residual (beneficiary, withdrawals, system contracts), and
  N's *values* exist by the time N+1's batches run (the chained build waits for N's state,
  `built_executions::wait_for_state`).
- **The build of N+1 knows whether its parents were built from their plans.** `warm_ahead::Built`
  (151) and `warm_ahead::usable` (323) already check that build N sealed exactly its plan's take, from
  the prepared body, with nothing serial, on the base the read assumed, and that N+1 builds on that
  sealed hash.
- **Batches are whole sender groups** (`partition_by_sender` 824, `batch_groups_one_wave` 1576,
  `N42_BUILD_BATCHES=128`), so a sender belongs to one batch; a recipient can be credited by several
  batches, and the output index sums those (the conflicts map, `output_shards.rs` 586-640). The partition
  is already made with the plan, so the batch of every transaction is known at plan time.

## 4. The options

All three keep the execution order, the values read and the output shards' published form, so the
results are byte-identical by construction; they differ in how a value is found.

### (a) A long-lived account slot table

A global, stable id per address assigned on first sight (a slot table of ~1M accounts for the flood),
the in-flight outputs stored by that id: `cell[id] = (writer block, balance, nonce, flags)`, one 64-byte
line. The plan carries each transaction's two slot ids (one probe of the address -> slot map per address,
at plan time). The build reads `cell[id]` and uses it when its writer is an ancestor no newer ancestor
superseded; otherwise the chain.

- **Misses per transfer:** 1 line per account, address known from the plan: ~2 independent loads.
- **Correctness:** the cells are shared mutable state across builds. A build at the same height on
  another parent, a re-made plan, or a peer block overwrites cells that a later build on the original
  chain needs; the cell must name its writer and the reader must prove no non-plan ancestor wrote the
  account since (the same verified-prefix rule as (b), section 5.3), and keep a seqlock per cell against
  torn reads while a sibling build writes. Only one version per account exists, so a reader that needs
  an older version (a second build at a height, an RPC read at a block, the merge behind the seal) cannot
  be served from it.
- **Memory:** fixed, ~64 B x slots (64 MB for 1M), no per-block arrays.
- **Plan pool:** one probe per address of a ~1M-entry map, plus slot assignment under a shared allocator.
- **Changes:** a new global structure written by every block's batches (one 64 B random store per account
  per block), slot recycling for a real chain's unbounded account set while in-flight readers hold slot
  ids (the hard part), the seqlock, and the same validity bookkeeping as (b).
- **Follower:** unchanged.

### (b) Per-plan dense ids, the source resolved at plan time and carried with the plan

At plan time every distinct address of N+1's plan gets a dense block id `0..A` (A ~ 147k-192k); the
plan carries an address -> id table and, per transaction, `(sender id, recipient id)` and where each
account's value lives before the block: `(layer, index)` = "block s's dense output, entry i", or "the
chain". Each block's output is, besides the shards, a dense array `out[id]` in its own plan's ids. The
batches then read `layer[s].out[i]` -- one line at an address the plan names -- and keep their own state
as an array indexed by block id.

As stated in the brief, the resolution probes N's, N-1's, ... tables per address (up to `depth` probes,
~4 on average, on the plan pool). **The code suggests a better resolver:** plans are made in order, so a
**rolling last-writer table** (address -> `(plan seq, id)` of the newest plan that touched it) answers
the resolution in **one probe per address**, and is moved on to the new plan in the same pass (one
insert). That is (a)'s single probe without (a)'s shared mutable cells: each block's dense output is
immutable once its batches end, several versions coexist (one array per block), and an abandoned plan
only makes its entries unusable (section 5.3).

- **Misses per transfer:** the recipient's source line (1) and its batch-state line (1); the sender's
  batch-state line, hot after the run's first transfer; the plan's per-transaction record, read
  sequentially (hardware prefetch). Both account lines are computable from the plan k transfers ahead,
  so a lookahead finally has addresses to prefetch. ~2 independent loads, 0 dependent probes.
- **Correctness:** the prefix rule (5.3) per build; any reference outside it falls back to the chain.
- **Memory:** per block, the dense output 64 B x A (9.4 MB at 147k, 12 MB at 192k); per plan, the id
  table (~5 MB), the per-transaction records (32 B x 200k = 6.4 MB) and the lanes (~40k x 64 B = 2.5 MB);
  the rolling table ~(20 + 8) B x ~0.85M accounts plus hashbrown overhead, ~40 MB, once. A ring of
  D = 16 dense outputs is 150-190 MB, against the ~39 MB a kept `ShardLayer` costs per block today
  (~260 B an account).
- **Plan pool:** measured by the bench at 9-10 ms wall on 8 threads for 200k transfers (bucketing,
  dedupe, one rolling probe and one insert per address, first-touch flags and lanes), inside the
  30-40 ms window, beside what `make_prepared_build` already does there.
- **Changes:** additive. A new module, a field on `PreparedBuild`/`PreparedExec`, a database layer
  under `BatchState` that answers the current transaction's two accounts from the resolved references,
  a write-through of each batch's accounts to the block's dense output, and (stage 2-3) a dense batch
  state and a dense output index. No forked crate is touched.
- **Follower:** unchanged (it has no plan; a follower resolver at block arrival is a later option).

### (c) Prefetch-friendly open addressing, the hash carried with the plan

Keep the layered chain, but make every map an open-addressing table with a hash computed once at plan
time and carried per transaction; the build prefetches each layer's bucket for transaction i + k.

- **Misses per transfer:** the same ~10 loads, now prefetchable at the first level only: the index
  bucket of every layer (6 layers x 2 accounts = 12 prefetches per transfer, a large share of the ~24
  L1 miss buffers), and the batch map the index names is a second, dependent level (its bucket depends on
  the index entry), as are QMDB's index -> record links. 10.119/10.121 already tried exactly the
  first-level hint down this chain (`N42_BUILD_MLP`, reaching the QMDB index bucket after ax) and it
  left the median at 16 ms.
- **Correctness:** unaffected (the same chain, only hints).
- **Memory:** unchanged.
- **Changes:** custom tables replacing hashbrown in `FrozenShards`/`Indexed`, the overlay and the QMDB
  index; the provider is a `dyn StateProvider`, so the hash must travel through the forked
  `storage-api` (as `n42_prefetch_account` does).
- **Follower:** unchanged.

### 4.1 Comparison

| | (a) slot table | (b) resolved per-plan ids | (c) carried hash |
| --- | --- | --- | --- |
| dependent probes per transfer | 0 | 0 | ~10 (first level hinted) |
| account lines per transfer | ~2 | ~2 | ~10 |
| plan-time work | 1 probe + slot alloc / address | 1 probe + 1 insert / address | 1 hash / address |
| versions | one per account | one per block | n/a |
| different parent, re-made or topped-up plan | needs the prefix rule and seqlocks; overwritten cells lost for the original chain | prefix rule; abandoned plans unusable, nothing overwritten | n/a |
| memory | ~64 MB fixed + id recycling | ~10 MB / block in the ring, ~40 MB table | none |
| touches forked crates | no | no | yes (`storage-api`) |

**Recommended: (b) with the rolling last-writer table.** It removes the dependent chain as (a) does,
keeps every block's values immutable and versioned per block as the shards do today (no seqlock, no slot
recycling, no lost versions), its fallbacks are the existing chain, and it is additive.

## 5. The recommended design

### 5.1 Data structures (new module `crates/n42/engine-types/src/one_probe.rs`)

```rust
/// One account in a dense array: a cache line.
#[repr(C, align(64))]
struct Dense { balance: U256, nonce: u64, tag: u64 } // tag: 0 not loaded, 1 plain account, 2 absent

/// Where a value lives before the block: (source, index). Source: a plan sequence number in the ring,
/// or CHAIN (read through the build's provider stack by address).
type Src = u64;

/// One transaction of the plan, 32 bytes, in plan order.
struct PlanTx { s_bid: u32, r_bid: u32, s_src: Src, r_src: Src, s_lane: u32, r_lane: u32 }

/// What the plan hook makes and the build takes (on `PreparedBuild` / `PreparedExec`).
struct Resolved {
    seq: u64,                    // this plan's sequence number
    ident: u64,                  // the take's identity (`warm_ahead::segments_ident`)
    txs: Vec<PlanTx>,
    ids: AddressMap<u32>,        // address -> block id (residual checks, by-address reads)
    addrs: Vec<Address>,         // block id -> address
    srcs: Vec<Src>,              // block id -> pre-block source (lanes' fold, reverts)
    lane_of: Vec<(u32, u32)>,    // block id -> (first lane, writers) when several batches write it
    lanes: usize,
}

/// The rolling last-writer table: 64 shards by `address_mix`, address -> (plan seq << 32 | id).
/// Updated per plan, in plan order, each shard by one plan-pool thread.
struct Rolling { shards: Vec<AddressMap<u64>> }

/// One built block's dense output, immutable once its batches and lane fold are done.
struct DenseOutput { seq: u64, built: B256, base: B256, out: Box<[Dense]>, extra: Vec<Address> }

/// The ring: the last D outputs (`N42_ONE_PROBE_DEPTH`, 16 by default), newest first.
struct Ring { outputs: VecDeque<Arc<DenseOutput>> }
```

### 5.2 The flow

1. **Plan time** (`make_prepared_build`, on the plan-body pool, after the keys and the partition): bucket
   the plan's 2 x 200k occurrences by shard (counting sort), then per shard: dedupe into local ids, one
   `Rolling` probe per new address (the source: the newest plan that touched it and its id there, or
   CHAIN), one insert of `(this seq, id)`; assign global ids by shard offset; fill `PlanTx`; mark each
   batch's first touch of an id and count the batches that write it; give each id several batches write
   one lane per batch. The bench's `plan()` is this, 9-10 ms on 8 threads.
2. **Build start** (`payload.rs` near 1558, where `take_prepared` and `warm_ahead::take_for` 2284 are):
   take `Resolved` only if the take's identity is the build's (as the warm read). Compute the **verified
   prefix** (5.3): the ancestors N, N-1, ... each recorded in the ring as built whole from its plan on the
   previous one, up to the first that is not. Build the residual set: every `extra` address of the prefix
   blocks (beneficiary, withdrawal recipients, system contracts), and for each one in `ids` set its
   source to CHAIN (a few dozen probes).
3. **Batches**: no hash probe for plan accounts. `work[id]` (block-wide, made and touched with the plan
   like the slots) or the account's lane; on `tag == 0` it is loaded from its source -- `ring[s].out[i]`
   if s is in the prefix, else the chain by address. A transaction skipped by its sender's break leaves
   its recipient's entry at `tag == 0`, so the next touch loads it (the check is on the line the transfer
   uses anyway). The beneficiary keeps today's path (read once per batch, credits summed as
   `beneficiary_delta`).
4. **Batch end and fold**: exclusive ids are already final in `work`; the lanes are folded into `work`
   (`pre + sum(lane - pre)`, the conflicts map's rule); `work` becomes this block's `DenseOutput` in the
   ring when the block is recorded as built whole (`warm_ahead::note_built`'s place, `payload.rs` 2840).

### 5.3 Validity and fallbacks

A reference `(s, i)` is used only if plan s's block is in the build's **verified prefix**: the chain of
blocks N, N-1, ..., N-k+1 under the build such that each was sealed at its execution's end from exactly
its plan's take with nothing serial (`Built`), on the previous one's sealed hash, and the build's own
parent is N's sealed hash (`parent_built`). Why a prefix and not a set: the rolling table only sees
plans; a block in the ancestry that was not built from a plan (a peer's block, a topped-up plan, a
serial fallback, an engine-path build with no opener, a plan made again) may have written an account
whose table entry still names an older plan. Every block newer than s being a verified plan block
guarantees that the table's entry (the newest plan touching the account) is the newest writer.

| case | what happens |
| --- | --- |
| the build takes another plan than the one resolved (identity differs) | `Resolved` dropped; the plain path |
| N built from a topped-up or re-made plan, a peer's block, serial fallback, engine path | N is not verified; the prefix is empty; every reference falls back to the chain |
| an ancestor deeper than k is unverified | references to plans at or below it fall back |
| an entry names an abandoned plan (made again at the same height) | its seq is not in the prefix: chain |
| an address no plan in the ring touched | source CHAIN from the table: chain (stage 4 may read beneath the prefix) |
| an address in a prefix block's residual (fee credit, withdrawal, system call) | forced to CHAIN at build start |
| a plan older than the ring's depth | not in the ring: chain; entries pruned lazily by a sweep on the plan pool |
| the follower | not involved |

The chain fallback is today's path through the same provider stack, so it is always correct; the switch
off reproduces today exactly.

### 5.4 Expected misses per transfer, before and after

| | today | stage 1 | stage 2-3 |
| --- | --- | --- | --- |
| recipient, dependent probes | ~8.5 | 1 (batch map) | 0 |
| recipient, account lines | ~8.5 | 2 (map probe, resolved source) | 2 (work, source), independent |
| sender (amortised over the run) | ~0.3 + ~1.5 | ~0.1 + ~1.5 | ~0.06 + work line hot |
| new entry written | 260 B (4-5 lines) | 260 B + 64 B write-through | 64 B (1 line) |
| fallback to the chain | 100% of recipients walk it | (1 - 0.15)^D of recipients: 7% at D = 16, 0.6% at D = 32 | same |
| **dependent, cache-missing loads** | **~10** | **~2** | **~0 (~2 independent, prefetchable)** |

## 6. Microbenchmark

`crates/n42/engine-types/tests/one_probe_bench.rs` (ignored; release, pinned). A block of the flood's
shape -- 12,500 senders x 16 transfers in sender runs, recipients uniform over 900,000
(`tx_flood::recipient`'s address shape), 128 batches of whole sender groups -- over `OP_LAYERS` earlier
blocks kept in the output-index form (16 shards, address -> batch, then the batch's
`AddressHashMap<BundleAccount>`) above a 912,500-account base map standing in for QMDB. Paths:
`today` (a `BatchState`-shaped map of `BundleAccount` over the layer walk, the touched addresses handed
over by shard, then the index fold with conflicts summed), `stage1` (the same map over reads taken from
the plan's resolved references), `stage1d` (the same with every account resolved, so only the map's own
cost remains), `proto` (the recommended layout: a dense `work` array and lanes, the resolved
references, no hash probe) and `deep` (`proto` with the rolling table covering every account). Each
path's post-state is asserted equal to a serial application of the block (balances, nonces, the
beneficiary's fees). The uniform draw gives ~192k distinct accounts a block where the flood gives ~147k.

8 threads on cores 232-239 (`taskset`, `nice 19`, 7 rounds, p50; the shared box had a load of ~20):

| path | 2 layers | 6 layers |
| --- | --- | --- |
| today: execution / output fold | 25.0 / 2.1 ms | 27.2 / 2.2 ms |
| stage1: execution | 24.2 ms | 23.7 ms |
| stage1d: execution | 23.2 ms | 23.3 ms |
| proto: execution / lane fold / plan-time resolve | 3.0 / 0.4 / 9.1 ms | 2.6 / 0.4 / 9.7 ms |
| deep: execution / lane fold / plan-time resolve | 2.1 / 0.3 / 10.2 ms | 2.1 / 0.3 / 10.2 ms |
| post-states equal to the serial application | yes | yes |

`perf stat` of the `today` path (21 rounds minus 1, 6 layers): ~2,400 instructions, ~4,800 cycles,
48 L1D misses and 11.7 DRAM fills per transfer.

What the bench says, with its limits:

- The batch map is the larger cost in the bench: `stage1d` keeps 85-93% of `today`'s time. A
  `BundleAccount` map of 3,584 x 260 B buckets per batch is larger than L2 and written fresh every block,
  so each new entry is ~5 cold lines and each later hit an L3 access. The node's batch map is the same
  shape (`BatchState::with_capacity`, `txs + txs/4 + 1`). 10.120 put it at ~14% of the build's cycles;
  part of the loop's 16% is skid from those stalls.
- The layer walk is cheaper in the bench than in the node (no residual overlays, no
  `MemoryOverlayStateProvider`, no QMDB journals, offset index and entry file, no `dyn` provider), so
  `today - stage1` (1-4 ms of 25-27) understates what stage 1 removes there, where 10.120 measured the
  walk and QMDB at ~21% of cycles.
- `proto` is 8-10x faster than `today` on 8 threads because both costs go and the transfers' loads stop
  depending on each other. The node's build has work the bench leaves out and the design does not touch
  (the pooled transaction and its `TxEnv`, revm's checks, the ~375 B slot, the take of the bundle and the
  sink), so the node's gain is bounded by the share of the replaced parts: ~35% (walk 14 + QMDB 7 +
  batch map 14) of the build's cycles before 10.121's cuts, ~40% after. Removing ~85-90% of that gives
  16 ms -> ~10-11 ms, and the remaining misses become prefetchable from the plan (the `N42_BUILD_MLP` ring
  with resolved addresses instead of hints into hash tables): **8-10 ms is the target, to be measured on
  the fleet**.
- 64-thread numbers need the box (the brief's limit here was 8 cores). Run:
  `OP_THREADS=64 OP_LAYERS=6 cargo test --release -p n42-engine-types --test one_probe_bench -- --ignored --nocapture`
  pinned to the build set, with `OP_MODE=today|proto` for `perf stat` of one path.
- The plan-time resolve (9-10 ms on 8 threads, 200k transfers, ~192k accounts) fits the 30-40 ms window
  but adds to the plan-body pool's work; on the fleet it must be measured beside `made_us`.

## 7. Exact places that change

| stage | file:line | change |
| --- | --- | --- |
| 1 | `engine-types/src/one_probe.rs` (new) | `Dense`, `PlanTx`, `Resolved`, `Rolling`, `DenseOutput`, `Ring`, `resolve()`, `prefix()`, the switches |
| 1 | `engine-types/src/payload.rs` 872-937 `make_prepared_build` | after `partition_by_sender` and the batch assignment: `one_probe::resolve(&keys, &batches, seq, ident)` on the plan-body pool |
| 1 | `engine-types/src/frame_blocks.rs` 225 `PreparedBuild` | field `one_probe: Option<Arc<Resolved>>` |
| 1 | `engine-types/src/parallel_transfer.rs` 916 `PreparedExec` | the same field, passed into `execute_for_build_opts` 3915 |
| 1 | `engine-types/src/payload.rs` ~1558 (take_prepared), ~2284 (warm take) | identity check, `one_probe::prefix(parent_built, parent_header)`, residual set to CHAIN |
| 1 | `engine-types/src/parallel_transfer.rs` 4018-4024 | `OneProbeDb` between `ReadSetDb` and `BatchState`: before each `transfer_plain` (4100) the loop sets the transaction's two `(address, Src)`; `basic(address)` matching one of them loads the dense source instead of the chain |
| 1 | `engine-types/src/batch_state.rs` 160 `commit_transfer` | write-through of exclusive accounts' post-values into the block's dense array (one 64 B store) |
| 1 | `engine-types/src/payload.rs` 2840 (`note_built`) | the block's dense output pushed into the ring with `Built` |
| 2 | `engine-types/src/batch_state.rs` 62-251 | `DenseBatchState`: `work` + lanes by block id, `tag` load-on-first-touch; `take_bundle` builds the batch's `BundleState` from the touched ids at batch end (sequential, off the dependent path) |
| 2 | `engine-types/src/parallel_transfer.rs` 4024-4120 | the loop indexes `work` by `PlanTx`; `transfer_plain`'s checks kept as they are (a dense `transfer_dense` with the same checks, tested equal) |
| 3 | `engine-types/src/output_shards.rs` 586-640 `Indexed`, 2048 `get`, 2539 `view`, 2222 `merged` | `DenseIndexed`: the plan's `ids` as the index, the dense arrays as the accounts, reverts made at the merge behind the seal from `srcs`; `get(address)` is one probe of `ids` then one line |
| 4 | `direct_build.rs` 1005-1025 `open_on` | a CHAIN read opened beneath the verified prefix's layers |

No forked crate changes in stages 1-3; `storage-api`'s hint stays as it is.

## 8. Staged plan and switches

- **Stage 0 (this):** the design and the bench.
- **Stage 1, `N42_ONE_PROBE=1`** (off by default; needs `N42_PLAN_AHEAD_BODY=1`): the resolver, the
  ring, `OneProbeDb` and the write-through. The batch map stays. Phases fields: `one_probe_plan_us`,
  `one_probe_prefix` (verified depth), `one_probe_hits` (reads answered from the ring),
  `one_probe_chain` (fallbacks). Expected: the walk and QMDB (~21% of cycles) mostly gone.
- **Stage 2, `N42_ONE_PROBE=2`:** the dense batch state. Expected: the batch map's share gone from the
  transfer path (moved to a sequential pass at batch end).
- **Stage 3, `N42_ONE_PROBE=3`:** the dense output index in `output_shards`; the per-account
  `BundleAccount` is made only by the merge behind the seal.
- **Stage 4:** `N42_ONE_PROBE_DEPTH=<D>` sweep (16, 32), reads beneath the prefix, the MLP ring on
  resolved addresses, and a follower resolver at block arrival (`follower_import`), each separately
  switched.

Each stage is measured as stage at-az were: X11 controls alternating with the switch, `par_exec`
p50/p90, `sealed_at`, the round and window 1, and the plan-body pool's `made_us` and the new fields.

## 9. Tests

- `resolve_names_the_newest_writer`: three plans through `Rolling`; ids, sources, lanes, first touches;
  an account written by several batches and a sender that is also another batch's recipient.
- `a_build_on_resolved_reads_equals_the_plain_build` (as `a_build_on_the_warm_read_ahead_equals_the_plain_build`):
  N+1 built on N with `N42_ONE_PROBE=1, 2, 3` equals the plain build -- transfers, conversions, gas,
  skips, fees, grafted accounts, reverts and the state root's operations -- at layer depths 1, 2 and 6,
  with underfunded senders (a skipped sender's recipients left unloaded).
- `a_resolved_read_for_another_parent_is_not_used`: a peer's block, a topped-up plan, a re-made plan, a
  serial fallback and an engine-path parent each empty or shorten the prefix, and the result equals the
  plain build.
- `the_residual_accounts_read_the_chain`: the beneficiary, a withdrawal recipient and a system contract
  of a prefix block are read from the chain.
- `lanes_sum_like_the_conflicts_map`: the lane fold equals `Indexed`'s conflict sums.
- `tests/output_shards.rs` extended for stage 3: `view`, `merged`, `get` and `take` over `DenseIndexed`
  equal the index mode's.
- `tests/one_probe_bench.rs` (ignored): the timing and the equality above.

## 10. Stage 1, implementation

`N42_ONE_PROBE=1` (off by default; needs `N42_PLAN_AHEAD_BODY=1`), `N42_ONE_PROBE_DEPTH=<D>` (16, 1..=64),
in `crates/n42/engine-types/src/one_probe.rs`. What was built, and where it departs from sections 5-8:

- **Plan time** (`payload.rs` `make_prepared_build`, on the plan-body pool, under one lock so plans resolve
  in the order they are made): `resolve_with` buckets the 2n occurrences by `warm_shard`, dedupes each shard
  into local ids, sums the shards' offsets into dense ids, then per shard one probe and one insert of the
  rolling table (`seq << 32 | id`); an entry older than D plans resolves to `CHAIN` whether or not the sweep
  (every D plans, per shard, before the inserts) has removed it yet. The result, `Resolved`, holds one
  `PlanTx` a transaction -- 56 bytes, not 32: it carries the two addresses so the build can check each
  transaction against the plan as it runs -- the address -> id maps by shard, a "shared" flag per id, and the
  block's `DenseOut` (`Dense` = `[AtomicU64; 4]` balance, nonce, tag; 64 bytes, `align(64)`), made and
  touched on the plan pool. It travels on `PreparedBuild::one_probe`; no separate identity check is needed
  because the prepared build is only taken when its segments are the build's (`made_from`).
- **Write-through** happens after `commit_transfer` (`BatchState::after_commit`: one probe each of the
  batch map's two just-written entries), not inside it, through three new `AccountHint` methods with
  no-op defaults (`note_tx`, `written_accounts`, `write_through`; `ReadSetDb` forwards them). Only ids that
  transactions of a single sender touch are written: a sender's transactions are one group and a group is
  in one batch, so one batch's final value is the block's. Ids two senders touch (a recipient of two
  senders, a sender that is someone's recipient) are left empty and read through the chain: stage 1 has
  no lanes. An account with code is marked unheld; the beneficiary is never written.
- **Build side** (`payload.rs`, beside the warm take): the view is made when the build's keys are the
  plan's length; `Ring::prefix` follows builder hashes from the build's `parent_built` while each held
  output's `parent_built` names the next and the plan numbers decrease, and checks the first output's base
  against the grandparent. The residual set (the prefix blocks' beneficiaries and withdrawal recipients,
  `warm_ahead::SYSTEM`, this block's beneficiary) is a bitmap over the plan's ids. `OneProbeDb` sits
  between `ReadSetDb` and `WarmDb`: `note_tx(i, key)` sets the running transaction's `PlanTx` (or flags a
  mismatch, which keeps the block out of the ring); `basic` answers that transaction's sender or recipient
  from `prefix[seq].out[id]` when the reference is valid and the entry holds a plain account, as
  `AccountInfo::from(Account)` would (no code loaded), and from the chain otherwise. A block sealed at its
  execution's end from its whole take (the `warm_ahead::note_built` condition) and of the plan's length
  pushes its output into the ring.
- **Fields** on the `seal-first build phases` line: `one_probe_stage`, `one_probe_resolved` (the plan's
  distinct accounts), `one_probe_prefix` (verified depth), `one_probe_hits`, `one_probe_fallbacks` (a
  named account read through the chain: no valid reference, forced, or an unwritten entry),
  `one_probe_resolve_ms`.
- **Memory**: 64 B per distinct account per block (9.4 MB at 147k, 12 MB at 192k), held by the plan until
  its build ends and by the ring for D blocks; the rolling table ~1M entries at the flood's shape.
- **Tests**: `one_probe::tests` (`resolve_names_the_newest_writer`, `the_rolling_table_forgets_past_the_depth`,
  `a_large_plan_resolves_every_occurrence`, `the_prefix_follows_the_built_chain`,
  `a_dense_entry_holds_one_account`, `the_residual_accounts_read_the_chain`) and
  `parallel_transfer::tests::a_build_on_resolved_reads_equals_the_plain_build` (three consecutive blocks
  on three fixtures equal the plain builds in transfers, gas, outcomes, fees, accounts and reverts, the
  later ones with hits; a peer's parent finds no prefix and still equals; every written entry equals the
  block's post-state).

What stage 2 needs from stage 1: the plan's dense ids and `PlanTx` per transaction (to index a batch's
`work` array instead of the batch map), the `shared` flag replaced by per-batch lanes made at plan time
(which needs the batch assignment, i.e. `batch_groups_one_wave` at the build pool's width, moved to the
plan), the per-id source (`srcs`, today folded into `PlanTx` and dropped after) kept for the reverts, and
`BatchState`'s bundle made from the touched ids at batch end; the ring, the prefix rule, the residual
bitmap and the write-through into `DenseOut` carry over unchanged (stage 2 writes `work` itself as the
output).
