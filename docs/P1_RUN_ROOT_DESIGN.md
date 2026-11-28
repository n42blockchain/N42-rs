# The per-block QMDB root in a catch-up run: where it goes, and what to do about it

Plan item B1 (`docs/PLAN_P1_REMAINING_2026_11.md`). 2026-11-26, branch `design/p1-run-root`.

**Summary.** The ~0.12 ms an empty block's root costs in a range import is not hashing that
the state needs. About two thirds is hand-offs to the worker pool for work on five leaves, and
the rest is a whole-twig rehash (2,047 compressions) for those five leaves. Both are fixed
overhead and both are removed on this branch without changing what is computed, filed or
checked: the root of a 5-operation block goes from 85-105 us to 11 us in the micro-benchmark
(same roots). Every per-block version stays as it is. A per-run root is not needed, and the
analysis below says it should not be built: on profile 1 every intermediate root has a
consumer, the next header's deferred-execution check.

What is **not** measured here: the pull itself. Bench legs were out of scope for this work.
The expected pull rate in section 5 is a projection from the last legs' timers and needs one
empty-chain leg to confirm.

## 1. Where the 0.12 ms goes

### 1.1 In the node (existing timers)

Per block over the two default empty-chain legs of step 7 (`p1-catchup-empty/legs/s3e1`,
`s3e2`; EL log `range import` lines, 12,583 blocks, 51 calls each), microseconds:

| | s3e1 | s3e2 |
| --- | ---: | ---: |
| whole call | 143 | 161 |
| decode | 2.0 | 1.9 |
| checks (header, body, against parent) | 20.5 | 20.1 |
| execute | 15.1 | 16.3 |
| post-execution | 0.6 | 0.1 |
| `root` (main thread: building the operations, then waiting for the worker) | 91.8 | 107.8 |
| hashed state, hand-off | 2.9 | 2.9 |
| forkchoice | 3.3 | 4.4 |
| root worker's own time (`root_work_us`) | 111.6 | 128.4 |

The main thread's own work is about 45-50 us a block. The root worker needs 112-128 us, so
the main thread spends 92-108 us of every block waiting for it. The root chain is the bound,
as step 7 said.

### 1.2 Inside the root (micro-benchmark)

`crates/n42/qmdb-reth/examples/empty_block_root_bench.rs` seeds a forest in an entry file and
times `compute_operations` + `insert` from a plain thread, as the import's root worker runs
them, with rayon's global pool at 8 threads (profile 1's size). Block shape: 2 live keys
rewritten (reward accounts) and 3 new keys (system-contract ring-buffer slots), 100,000 live
keys, 20,000 timed blocks. The box was not quiet (load 25-38); the numbers moved by about 20%
between runs, the split did not.

Before (`--small-ops 0`), median microseconds, phase timers at 1 us resolution:

| phase | us | what it is |
| --- | ---: | --- |
| whole root | 85-103 | |
| retire | 22-30 | almost all `index.reserve`: a pool task per index shard (256) to reserve room for 5 keys |
| index | 20-26 | the inserts: a partition on the pool, then a pool task per shard |
| rehash | 28-31 | the block's twig recomputed whole: 2,047 compressions for 5 new leaves |
| delta + bookkeeping | 3-6 | the forest's delta, collected on the pool |
| leaf hashes, lookups, undo, writes | ~4 | each handed to the pool once |
| upper tree | 2 | a scan of every twig root (10 us at 8M live keys: it grows with the state) |

With the pool at one thread the same root is 45 us: the hand-offs alone are ~40 us at 8
threads. They are expensive because the root worker is not a pool thread. Every `par_iter` or
`join` from it injects a job, wakes a sleeping worker and blocks on a latch, and the block
apply does that about a dozen times. This also explains step 6's observation that the empty
root is 1.45 ms on the host's 254-thread pool and 0.12 ms on 8.

None of it is work the state needs:

- Hashing actually required for 5 leaves: 5 leaf hashes, ~15 twig nodes above them, the
  twig's bit set, the twig root, and ~log2(twigs) upper nodes. About 30 compressions.
- Version bookkeeping (undo record, delta, block record): under 2 us.
- Structural writes (entry file append, index, active bits): 1-2 us.

## 2. What was implemented: the small apply

A block of at most `N42_QMDB_SMALL_APPLY_OPS` leaf operations (default 256; 0 turns it off)
is applied on the calling thread:

- leaf hashes, index lookups, reserve and inserts, undo entries, the operations' encoding
  (`sorted_operations_from_execution`) and the forest's delta run inline;
- a twig that took new leaves rehashes only the nodes above the appended range
  (`Twig::recompute_range`). The appended slots are the only leaves an apply writes, and
  every other writer of a twig (a fresh twig's null levels, an undo, a hydration, a snapshot
  load) leaves its nodes consistent. Debug builds compare each ranged rehash with the full
  recompute;
- the upper tree is refreshed from the dirty twigs (the `N42_ROOT_UPPER_DIRTY` path, which
  the X22 profile already runs) instead of the scan of every twig.

The tree, the undo record, the delta and the root are the ones the pooled apply produces.
Larger blocks are untouched. Crates: `n42-twig-core`, `n42-qmdb-state`, `n42-qmdb-reth`; no
forked reth crate.

Tests: `a_small_apply_equals_the_pooled_one` (twig-core, with and without the `rayon`
feature): 700 blocks of 1-48 and 200 operations with creates, updates and deletes across
several twigs, a 300-operation block now and then, a revert and re-apply every seventh block,
on the heap and in an entry file; roots, undo records, cursors and snapshots equal, and the
root equal to the full fold. The existing suites of `n42-twig-core`, `n42-qmdb-state`
(including gov5's byte-exact `gov5_contract` roots), `n42-qmdb-reth` and `n42-env` pass with
the default on.

Micro-benchmark, before / after (median us, 8 pool threads, same head root in every pair):

| block | before | after | |
| --- | ---: | ---: | --- |
| 2 updates + 3 appends, 100k live | 85-103 | 11-12 | 8x; 11,600 -> 90,000 roots/s |
| same, 8M live | 115 | 23 | 5x (the rest is cache misses on a larger index) |
| 4 + 8 | 108 | 15 | |
| 20 + 30 | 115-142 | 28 | |
| 100 + 100 | 128 | 63 | |
| 300 + 300 | 290 | 158 | above the default bound: shown with the bound raised |
| 1,000 + 1,000 | 521 | 499 | the crossover |
| 4,000 + 4,000 | 1,014 | 1,943 | the pool wins |

The default bound of 256 is well under the crossover near 2,000.

What is left of the 11 us: twig path rehash 3, upper tree 1, writes 1, undo/retire/lookups
~1.5, and ~4 outside the phase timers (scratch buffers, the block record, the timers).

## 3. Who reads a per-block version

| consumer | what it reads | per block? |
| --- | --- | --- |
| the next header's check (deferred execution, A10/B13/AM19/AM25) | `root_of(parent)`, remembered by `executed_fields` | yes: header N+1 carries root N, and import refuses a header whose carried value differs from this node's execution |
| persistence (`n42_persist.rs` hook, `settle_through`, `take_block_deltas`) | each block's delta, chained by `base_next_slot`, appended to the delta log; `canonical_at(number, hash)` | yes |
| restart | the delta log replayed to the persisted head, checked against `HeadRoots` | per persisted head |
| read view / history (`block_changes_parts`, `history.rs`) | each block's operations and entry offsets, by block hash | yes |
| engine tree and builders (`fields_at_seal`, `payload.rs`, `main.rs`) | `root_of(hash)` for any block it holds | yes |
| reorg (`move_to`) | each block's undo | yes, above the commit |

## 4. Options

Costs are the root alone for a 5-operation block. A is measured; B-E are estimates from A's
phase split (what each option could still remove).

| option | root cost | per-block versions | safety | breaks | size |
| --- | ---: | --- | --- | --- | --- |
| A. small apply (done) | 11 us | kept, identical | none needed: same bytes | nothing | ~200 lines, `crates/n42/*` |
| B. batch a run's hashing, derive per-block roots from an incremental structure | ~8-9 us | kept | same bytes if done right | nothing, but a second apply path | medium, twig-core |
| C. defer intermediate roots until a consumer asks | ~6-7 us + replay on demand | records without roots | sound only if no consumer asks; on profile 1 the next header asks for every one | the deferred check becomes the trigger: no saving | medium |
| D. check only the run's last root against a committed header | ~6-7 us, or 0 with E | kept or merged | weaker, see 4.1 | a divergence that heals inside a run goes unseen | small in the import, plus C or E to save anything |
| E. one merged version per run | ~0.1 us a block | lost | needs D | persistence chain, read view, `root_of` per block, restart check; delta-log format; the vendored provider's hook | large, forked crates |

**B** saves little because A already brought the hashing down to ~30 compressions (3-4 us).
Per-block roots need each block's twig path, bit set and upper path; batching across blocks
can share only the upper levels of the path. At most 2-3 us.

**C** has no consumer-free root on profile 1. With deferred execution depth 1, header N+1
carries root N and its check runs for every block of the run. On a chain without deferred
execution the block's own header reads it. The only root "nobody reads" would be one the
checks stop reading, which is D.

### 4.1 D against the standard

The argument for D: a run handed to `importRange` is hash-linked under a verified commit QC
(step 6). By AM19/E14 the commit of N+1 certifies N's execution: 2f+1 members executed N
themselves (A13: CommitVote after own import) and agreed on the root header N+1 carries. So
every carried root inside the run is certified, and checking the last one seems enough,
because the QMDB tree is append-only and a divergence "stays in the tree".

That last step does not hold in general:

- A deletion retires a slot and appends nothing. "Deleted in block i, written again in
  block j" and "updated in block j" leave the same tree after j when the earlier state
  differs only by that deletion (the shape an account-removal rule applied by one client and
  not the other would have). The roots differ at i..j-1 and agree from j.
- Block boundaries are not in the tree. Roots at the boundaries are, and only the last would
  be compared.

So D turns "import refuses a header whose carried value differs" (AM25, and A10/B13's
check) into "import refuses a run whose last carried value differs". A member could then
hold blocks whose certified execution differs from its own, serve history at those heights
that 2f+1 members would not sign, and never report it. On a three-client chain the per-block
comparison is the cross-client divergence detector; profile 1 forbids skipping it elsewhere
(J4 makes n42-26 refuse to start with `N42_SKIP_STATE_ROOT` or `N42_DEFER_STATE_ROOT`,
which are the same idea). The carried receipts root, bloom and gas would still be checked per
block, but they do not cover state-only divergence.

D is also not needed any more. After A the root is off the critical path (section 5), so D
would buy nothing on the pull while weakening a rule. **Not recommended.**

**E** inherits D's weakening and adds the largest change of the list for the last ~11 us of
a block that then costs ~50 us for other reasons.

## 5. Expected pull rate

From section 1.1, with the root worker's time scaled by the micro-benchmark's ratio (112 us
-> roughly 15-20 us in the node, where execution shares the cores):

- root worker: ~15-20 us a block, no longer the longest stage;
- main thread: 45-50 us a block of its own work (checks 20, execute 15, the rest 10-15),
  less the pool hand-off that building the operations no longer makes;
- EL cost per empty block: 143 us -> **about 50 us**, i.e. ~20,000 blocks/s of import
  capacity against 7,000 now.

100 Mbit/s is 12,900 blocks/s at the bench's 970-byte blocks and 17,600 at chain 94's 710
bytes. The projection puts the EL above the first and near the second. Whether the pull
reaches it depends on stages this work did not measure once the EL stops being the bound:
the validator's side of `importRange` (the JSON payloads, anchor screening every 32nd block)
and persistence beside the run. One empty-chain leg (`scripts/catchup-bench.sh leg`, defaults,
then `CB_ENV=N42_QMDB_SMALL_APPLY_OPS=0` as the pair) settles it.

If the leg shows the main thread as the bound, the next cuts are in the import, not in QMDB:

1. `checks`, 20 us: the lean header rules per block. Worth a profile; nothing in them should
   cost 20 us for an empty block once the committee link is prefetched.
2. `execute`, 15 us: four system calls and the reward withdrawals through a fresh executor
   per block.
3. A second pipeline stage (checks beside execution) if both stay.

## 6. Recommendation

1. Take A (this branch) after one paired empty-chain leg. It changes no format, no rule and
   no consumer, and it also applies to the live path: every near-empty block's root on a
   follower and a leader gets the same cut.
2. Do not build a per-run root (D/E). Every intermediate root is read by the next header's
   check, the standard requires that check per block, and after A the root is not the bound.
3. Close B1's "design for a per-run root" as not needed; replace it with "confirm the pull
   with A, then profile `checks` and `execute` in the import" if the link rate is not reached.
