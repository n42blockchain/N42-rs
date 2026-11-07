# QMDB entry-file compaction: a root-neutral design

Status: design, 2026-10-27, amended 2026-10-28 (3.2 consequence, stage order). Item 6.2 of
`docs/MATURITY_HARDENING_2026_10.md`. Stages 0 and 2 are on main (c992a5ee4, 2026-10-30); the
slot-resolving view of stage 1 was measured at 2-4% and replaced, on 2026-11-03, by a view that
keeps locations (section 5, "Stage 1 as landed"); stages 3 and 4 landed with it on
`feat/qmdb-compact-stage34`, behind `N42_QMDB_COMPACT=1` (default off). Section 6 is the v2
portable snapshot proposed to gov5 (plan row E2 of `docs/PLAN_OPEN_ITEMS_2026_11.md`).

## 1. The problem, restated with the code's numbers

With `N42_QMDB_ENTRY_FILE=1` (the bench's R set since the E legs, `docs/NATIVE_FLEET7.md`
"Adopted for the bench") every state write appends one record `[key 32][len u32][value]` to
`qmdb/entries.log` (`twig-core/src/entry_store.rs`), slot N being the Nth record. Three things
grow with the append history and never with the live state:

| structure | per slot | at ~750k slots/s (fleet load) | freed by anything today |
| --- | --- | --- | --- |
| `entries.log` | ~150-300 B | ~200 MB/s | no |
| `Offsets` (`Vec<Box<[u64]>>`, 2^20-slot segments) | 8 B | ~6 MB/s of heap | only by undo `truncate` |
| `FileEntries.active` bits + `Twig.bits` | 1 bit + 1 bit | negligible | no |

`trim_dead_twigs` and `evict_twig_nodes_into` (`N42_QMDB_TRIM_TWIGS`) drop a twig's 128 KiB
leaf tree; they touch none of the three. `docs/QMDB_UPGRADE_PLAN.md` stage 4b proposed punching
fully dead twigs and measured 0 of 14,472 full twigs fully dead: a transfer workload kills
slots scattered over every twig, so whole-twig death never comes. Reclamation has to move live
records.

## 2. The constraint: the root is positional

`hash_leaf(key, value)` is hashed at the slot's position; twig roots and the world root follow
from slot numbers (`qmdb_compat.rs` `from_snapshot`). QMDB's own compaction re-appends live
entries at new slots, so the root changes and the schedule becomes a consensus rule shared
with gov5 (`docs/QMDB_PAPER_REVIEW.md` "No compaction", `docs/QMDB_UPGRADE_PLAN.md` 47, 287).
That is the fork-gated path and it is not the one taken here.

The root does not depend on where a slot's bytes live. `Offsets[slot]` is already an
indirection from slot to byte offset. So: **move bytes, keep slots.** A compaction that
rewrites a twig's records elsewhere and retargets `Offsets` for its 2048 slots changes no leaf,
no twig root, no proof and no export order. gov5 never sees it.

## 3. The design

### 3.1 Two files

`entries.log` stays the append-only slot-ordered log that undo truncates (`set_len`) and
`open_existing` walks. A second append-only file, `entries.relocated`, receives compacted
twigs. It is never truncated by undo, because compaction only takes twigs below the undo
horizon (section 3.4). `Offsets` encodes the file in the top bit of the `u64` (bit 63 =
relocated), leaving 63 bits of offset; the existing chunk/mmap machinery (`seal_tail`,
`Chunk`) is reused per file.

### 3.2 The compacted twig record

A twig is compacted as one contiguous group, slot order preserved, one record per slot:

```
[tag u8 = 0x01 live][slot u64][key 32][len u32][value]      a live slot, same payload as today
[tag u8 = 0x02 dead][slot u64][leaf_hash 32]                a dead slot: its leaf hash only
[tag u8 = 0x03 end ][twig u64][crc32 of the group]           group trailer
```

The dead record exists because an evicted twig is rehashed from its entries for proofs and
truncations (`hydrate`, `twig_leaf_nodes`), dead slots included; 32 bytes of hash replaces a
key, a length and a value that nothing will read again. `twig_leaf_nodes` learns the dead tag
and uses the stored hash. The slot number in each record is what lets `open_existing` rebuild
`Offsets` for a file that is no longer slot-ordered; the trailer lets a torn group be cut on
open exactly as a torn tail is today.

**Consequence found 2026-10-28, before stage 2:** gov5's portable snapshot is the complete
positional slot log, dead slots included, and its verifier (`verify_portable_stream`) hashes
`hash_leaf(key, value)` for every slot, so a tree whose dead slots keep only their leaf hash can
no longer export a verifiable v1 portable snapshot (the hash alone reproduces the root but not
the stream). A compacting node is therefore a *pruned* node: `portable_export` refuses on a tree
with hash-only slots and names the rule (export from a node that runs with compaction off, as
an archive node), the heap `QmdbSnapshot` carries the leaf hash for such entries so checkpoints
and `from_snapshot` still work, and a v2 portable format with hash-only tombstones is a separate
cross-client item to agree with gov5 before compacting nodes can serve bootstraps. The section 1
numbers stand: without dropping the dead payloads there is nothing to reclaim.

### 3.3 Reads: the view resolves slots, not bytes

`QmdbReadView`'s `SharedOffsetIndex` stores 40-bit byte offsets today and the view invalidates
itself at 1 TiB (`entry_view.rs` `VIEW_MAP_BYTES`, `read_view.rs` "entry file past 1 TiB").
It becomes key -> slot (40 bits name 2^40 slots: 17 days of history at 750k/s, versus 1 TiB of
bytes = ~1.5 hours at 200 MB/s), resolved through a shared, versioned `Offsets`:

- each segment of `Offsets` is `Box<[AtomicU64]>`; compaction stores the new location with a
  release store, readers load with acquire. A reader that loaded the old location keeps a
  valid pointer until the old bytes are punched;
- punching is deferred by one reader epoch: the view's existing per-thread `Frozen` slot locks
  and `advance` give the epoch. A compacted twig's old range joins a `punch_after` queue and is
  released only after every reader has passed the `advance` that followed the retarget;
- the journals (`JOURNAL_DEPTH` 64) record prior slots instead of prior offsets, which they
  can, because a slot's identity never changes.

This removes the 1 TiB invalidation as a side effect; it is the "same change" the audit's
section 6.2 calls for.

### 3.4 Which twigs, when

A twig is a candidate when (a) its last slot is below the persisted block's `next_slot` minus
`N42_QMDB_RETAIN_DEPTH` blocks of appends (so undo can never truncate into it, and no
unsettled delta refers to it), (b) its dead fraction is at least `N42_QMDB_COMPACT_DEAD_FRAC`
(default 0.5: a group then shrinks by at least ~45%, dead records costing 41 B against
~200 B), and (c) its old range is not already in `entries.relocated` with a dead fraction under
the threshold again (a twig may be compacted more than once; the second pass reads the first's
group). Candidates are taken oldest first, at most `N42_QMDB_COMPACT_TWIGS_PER_BLOCK` (default
4, ~1 MB of reads and ~0.5 MB of writes a block) on the pruner's thread model
(`N42_PRUNE_THREAD`): never on the import path, never under the forest lock for longer than
the 2048 `Offsets` stores.

Dead fraction per twig is a popcount over its 32 `u64` words of `active`; the scan is
incremental (a cursor that advances a few twigs a block), not a sweep.

### 3.5 Reclaiming the bytes

After the epoch (3.3) `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` over the old
range of `entries.log`, or of `entries.relocated` for a repeat compaction. Logical length is
unchanged, so every offset below stays valid and `open_existing`'s walk needs the punched
ranges: they are persisted in the checkpoint (`ForestCheckpoint.punched: Vec<(start, end)>`,
sorted, merged) and the walk skips them. A read of a punched byte returns zeros; it cannot
happen, because every slot in a punched range has been retargeted and the retarget preceded
the punch by an epoch; a debug assertion on the record tag catches it anyway.

`Offsets` itself does not shrink: slots are forever. Its growth (8 B a slot) is the remaining
leak and is bounded separately: a compacted twig's 2048 offsets are all inside one group of at
most 2048 x (41 + 4 + value) bytes, so they fit a per-twig `base u64 + u32 delta`, 4 B a slot,
as `docs/QMDB_ENTRY_LOG.md` section 3 already suggested. That is stage 4 below, not part of
the first landing.

### 3.6 Restart, checkpoint, export

- `open_existing` walks `entries.log` (skipping punched ranges) assigning slots sequentially,
  then `entries.relocated` assigning by the explicit slot in each record; a slot seen in both
  takes the relocated location. A torn group at the end of either file is cut.
- `ForestCheckpoint` gains `punched` and the relocated file length; `forest.log` deltas are
  unchanged (they flip `active` only, and compaction never changes `active`).
- `portable_export` / `snapshot()` iterate slots 0..len through `Offsets` as today; they read
  relocated records transparently and skip nothing, so gov5's portable snapshot verifier sees
  the same bytes.
- Compaction before the checkpoint that records it is lost on crash: the next open walks the
  old records still present (not yet punched: the punch happens only after the checkpoint
  that holds `punched`). Order: retarget -> epoch -> checkpoint -> punch.

### 3.7 Metrics (stage 0, land first)

Landed (stage 0) as gauges of the node's 10 s QMDB health sampler (`bin/n42/src/main.rs`), read
from `QmdbNodeState::entry_stats()` -> `QmdbForest::entry_stats()` ->
`QmdbCompatTree::entry_stats()` (`twig-core` `entry_store::EntryStoreStats`); the accessor
`try_lock`s the forest and skips the tick while the lock is held:

| gauge | source |
| --- | --- |
| `n42_qmdb_entry_file_bytes` | `FileEntries` bytes that belong to slots (heap mode: the entry `Vec`'s own bytes) |
| `n42_qmdb_entry_total_slots` | slots appended and not cut by an undo |
| `n42_qmdb_entry_live_slots` | the key index's length, both modes: O(1), where a popcount of `active` is linear in the slots (128 MB at 10^9 slots, under the forest lock every tick). It is an invariant, not an estimate: the index names every active slot once at rest (an open builds it from the active bits and refuses a duplicate active key; every apply, delete and undo changes a slot's bit and its index entry together); the unit tests check it against a count of the active slots |
| `n42_qmdb_offsets_bytes` | `Offsets` segments x 8 MiB (0 in the heap) |
| `n42_qmdb_index_bytes` | `index_bytes()` |
| `n42_qmdb_entry_chunks` | sealed mappings of the file (0 in the heap) |
| `n42_qmdb_entry_bytes_per_live_slot` | `file_bytes / max(live_slots, 1)` |

A warning, once per process, when the last passes `N42_QMDB_ENTRY_BYTES_PER_LIVE_ALARM`
(default 2,000, 0 disables). `n42_qmdb_entry_relocated_bytes` came with stage 2
(`EntryStoreStats::relocated_bytes`, the complete groups in `entries.relocated`), and the ratio
is now (file + relocated) over live slots; `n42_qmdb_entry_punched_bytes` comes with stage 3,
and the ratio then becomes (file + relocated - punched) over live slots. No per-100-block log line: the node has no periodic
QMDB-counter log to put it in (the read view's lag line is about the view, not the tree).

## 4. What this does not do

- It does not reclaim the leaf trees (`N42_QMDB_TRIM_TWIGS` already does) or the `Twig` structs.
- It does not change the root, the proofs, the portable snapshot or anything gov5 reads.
- It does not help the heap mode (`N42_QMDB_ENTRY_FILE` off): there the `Vec<Entry>` is the
  file; the same slot-stable relocation applies in principle but is not worth building.

## 5. Stages and verification

| stage | change | verification |
| --- | --- | --- |
| 0 | metrics of 3.7 (done in 301f82916) | unit tests; one fleet leg shows the growth rates in the table of section 1 |
| 1 | read view resolves slots through atomic `Offsets` (3.3), no relocation yet. Measured at 2-4% (below) and replaced by a view that keeps locations and is retargeted by a compaction ("Stage 1 as landed") | existing read-view and proof tests; an X22 control pair (the hot read path changes: expect noise) |
| 2 | `entries.relocated`, tagged records, `open_existing` from two files, `Offsets` top bit, checkpoint fields; compaction runs but never punches (landed on `design/qmdb-compact-stage2`: d0f98a5d6 refactor, 721c9e744 file and records, 7f96f529c `compact_twigs`, 4b07c285d checkpoint v2 and forest, be7b4e93a export refusal and gauge; differences from this design below the table) | tests: compact, restart, same root and same proofs; same portable snapshot bytes before and after; undo across a compacted boundary refused by construction (3.4a) and tested |
| 3 | scheduler on its own thread, epoch-deferred punching, the punched ranges in `entries.punched` ("Stage 3 as landed") | tests with a fake epoch; a fleet leg reads `entry_bytes_per_live_slot` falling to a plateau; `roll --kill` under load restarts on a punched file |
| 4 | per-twig `base + u32` offsets for compacted twigs ("Stage 4 as landed") | heap growth per slot halves on the metric; control pair |

Stage 1 cost (measured 2026-10-30 on `design/qmdb-compact-stage1-view`, which was not merged):

- **Fleet pairs (X22, win1 M/s).** Stage fx VS (wt-integ 20d3df758 against main): branch
  4.920 / 4.947 against 4.947. The branch also held the tree lease longer (11.3 / 12.1 ms a block
  against 10.0-10.9 on every other leg): dropping the per-slot offsets list had also dropped the
  `rayon::join` that kept `delta_of_applied` on the pool, and the leasing thread (`qmdb-root`, the
  builder's scoped root thread) is outside it. Fixed in 5713db709. VS2 (5713db709 against main):
  lease 10.34 / 11.19 against 10.69 / 10.78 ms, but win1 4.800 / 4.847 against 5.033 / 5.000 and
  rounds 437.2 / 438.6M against 452.8 / 453.0M. All four branch legs (4.800-4.947) lie below all
  five controls (4.947-5.033): a real 2-4% cost.
- **Where it goes.** Per view read, main takes two dependent random misses: the index bucket
  (key -> byte offset) and the record. The branch takes three: the bucket (key -> slot), the
  slot's 8-byte cell in `Offsets` (8 B for every slot ever written, far past the last-level cache,
  and a likely TLB miss), then the record. The directory pointer stays cached; the second resolve
  of the same slot hits the cache.
- **Micro-benchmark.** `read_view::bench_concurrent_reads` at 50M keys
  (`N42_BENCH_VIEW_KEYS=50000000`), 160k distinct reads, release, pinned to cores 112-127, two
  runs of each tree, us a read of pool time (cold / warm):

  | threads | at | main 9cd355183 | stage 1 | delta |
  | --- | --- | --- | --- | --- |
  | 1 | head | 0.451-0.465 / 0.452-0.454 | 0.623-0.639 / 0.630-0.660 | +0.17-0.19 |
  | 4 | head | 0.538-0.549 / 0.514-0.520 | 0.728-0.735 / 0.663-0.681 | +0.15-0.19 |
  | 16 | head | 0.548-0.591 / 0.553-0.627 | 0.849-0.864 / 0.693-0.731 | +0.07-0.30 |
  | 1 | 16 behind | 2.049-2.069 / 2.101-2.110 | 2.258-2.283 / 2.259-2.297 | +0.15-0.21 |
  | 16 | 16 behind | 2.437-2.475 / 2.404 (4.090 outlier) | 2.653-2.654 / 2.456-2.603 | +0.05-0.22 |

  The index-and-record read alone (`raw warm`, 1 thread) goes from 0.434-0.445 to 0.590-0.605 us.
  So every read pays about 0.16-0.19 us more, about one DRAM miss and a page walk: 35-40% on a read
  at the head. The hardware counters (`perf stat` of LLC and dTLB misses per read) were not taken:
  `perf_event_paranoid` was 4 on the host and needs 1.
- **Fix options, ranked.**
  1. Keep main's hot path. The index stores locations again (key -> byte offset), and a compaction
     rewrites the view's entries for a relocated twig: about 2,048 re-inserts of its live keys, done
     on the view's advance path under every reader slot's write lock, which is also stage 3's reader
     epoch. Journals keep their old offsets, which stay readable until the journals let go, which
     `punch_after` has to wait for anyway. The cost: one of the index value's 40 bits must say "this
     is in `entries.relocated`", which leaves 39 bits of byte offset, so each file is limited to
     2^39 B = 512 GiB. Past 512 GiB the view invalidates itself as it did past 1 TiB before stage 1
     (about 45 minutes of the fleet's ~200 MB/s): the limit comes back, halved, until stage 3's
     punching keeps the live span of `entries.log` bounded, or offsets become relative to a moving
     base.
  2. A variant: relocated entries hold their slot (flagged), and only those reads, which are old
     and cold keys, pay the `Offsets` cell. The same 39-bit limit for the main file.
  3. Mitigations that keep the slot index: transparent huge pages on the `Offsets` segments (cuts
     the page walk, not the miss), and prefetching the cell after the bucket in the batched build
     prefetch. Neither removes the dependent miss.
  4. Not useful: caching (slot, offset) in the index (a bucket is one `u64`, already full), or a
     per-view snapshot of `Offsets` (still one cell load per read).

Stage 1 as landed (2026-11-03, option 1 above), where it differs from 3.3:

- **The index keeps locations.** A key-index value is a *location*: bit 39 clear, the byte offset
  of the record in `entries.log`; set, the byte offset of a live record's key in
  `entries.relocated` (`twig_core::entry_view::RELOCATED_LOCATION`), from where a relocated live
  record has the main file's `[key][len][value]` shape. `EntryViewFiles` maps both files (512 GiB
  of address space each, `VIEW_MAP_BYTES`) and resolves a location with one branch and no memory
  read, so a read is the index bucket and the record, as on main before compaction. Past 512 GiB of
  `entries.log` the view invalidates itself as it did past 1 TiB (`past_view`): the limit is
  halved, and stage 3's punching does not lift it (a punched file keeps its length).
- **Retargeting.** `compact_twigs` reports each live key of a compacted twig with its location
  before and after (`CompactReport::moves`); `QmdbReadView::retarget` replaces the index entries
  under the view's advance lock (an entry the index does not hold at the old location invalidates
  the view) and publishes to every reader slot, which waits out every read that loaded an old
  location. Journals keep the old locations; `moved_unreachable` is true once every journal kept
  was filed after the retarget, which is when the old bytes may be punched. A step back through a
  journal filed before a retarget invalidates the view (undoing it would put an old location back).
- **The stage-2 copy is retired**, and `OffsetsReader` has no caller (it stays, and blocks stage 4's
  segment release while one is alive).
- **The extra miss is gone** (measured below).

Stage 1 fix measured (2026-11-04, `audit-notes/ci/c34-bench.log`): `read_view::bench_concurrent_reads`
(release, 2M keys, 160k distinct reads, the configuration main's copy of the bench has) on the
branch (0d097c98e), on the branch with half the keys moved into `entries.relocated`
(`N42_BENCH_VIEW_RELOCATED=1`) and on main (9002ca80e), two interleaved rounds, microseconds of
pool time per read:

| leg | 1 thread at head (cold / warm) | 16 threads at head | 1 thread 16 blocks back |
| --- | --- | --- | --- |
| main | 0.401-0.405 / 0.392-0.395 | 0.564-0.582 / 0.570-0.583 | 1.970-1.983 |
| branch | 0.405-0.406 / 0.389-0.393 | 0.582-0.586 / 0.561-0.578 | 1.944-1.962 |
| branch, relocated keys | 0.400-0.405 / 0.392-0.399 | 0.565-0.573 / 0.554-0.571 | 1.935-1.940 |

The stage-1 view on `design/qmdb-compact-stage1-view` read 0.17-0.27 us slower here; with the
index holding locations the branch reads at main's level, and a key whose record moved to
`entries.relocated` costs the same as one in `entries.log`. (Round 1's branch leg read 3.4-4.3 us
on the journal walk at 16 blocks back, outside every other leg's 1.9-2.8: the box's load was 8
with another lane building; round 2 reads level.)

Stage 2 as landed, where it differs from or adds to the text above:

- **Candidates (3.4).** Besides (a) a last slot below `below_slot`, the twig's last retirement
  must be before it too (`Twig::last_retired_at < below_slot`, the `trim_dead_twigs` rule): a
  twig that only has old slots can still have one retired by a block an undo record still holds,
  and undoing that block revives the slot, which would need its payload. (c) is read as "the
  slots that died since the twig's last group are at least the threshold, and at least one". A
  reopened tree reads every twig as never retired, so after a restart `below_slot` must also be
  at or below every undo record held across it; `QmdbForest::compact_twigs` clamps the horizon
  to the oldest cursor its own undo records can rewind to. Every group's leaves are hashed from
  its own bytes and checked against the twig's leaf root before it is written. The scan starts
  at twig 0 every call (no cursor yet: stage 3).
- **Read view offsets (3.3, order note).** `entry_offset(slot)` keeps answering in
  `entries.log` for a relocated slot, from a copy of the twig's main-file offsets kept per
  relocated twig (16 KiB a compacted twig). That is what keeps the view unchanged in this stage;
  stage 1 (slot-resolving view) or stage 3 (punching) retires the copy.
- **Open (3.6).** The walk of `entries.relocated` stops at the first group that is torn, fails
  its CRC, is malformed, or names a twig not wholly inside the kept slots (a shorter historical
  prefix, or a main file cut back by an archive restore), and a writable open cuts it there. In
  stage 2 that loses nothing; stage 3 must revisit it, because a cut group whose old range was
  punched would be lost data. `relocated_len` in the checkpoint is recorded, not enforced.
- **Checkpoint.** `ForestCheckpoint::VERSION` is 2 and is always written: a binary from before
  this stage refuses the checkpoint of a node that ran this one (its version check), so a
  downgrade needs a version 1 checkpoint written by hand. Version 1 reads as `relocated_len = 0`
  and serializes back to the same bytes (`legacy-codec` fixture test).
- **Snapshots and export (3.2 consequence).** `QmdbEntrySnapshot` carries `leaf_hash` in memory
  (`snapshot()`, `from_snapshot`, and `set_entry_file`, which writes such a slot as an empty
  placeholder in `entries.log` plus a group holding the hash). The serialized layout of heap
  checkpoints and deltas is unchanged, so serializing a hash-only entry is an error instead of a
  silent loss of the hash; no file-mode path serializes one. `portable_export` refuses with
  `NodeStateError::PortableCompacted`. The verification row's "same portable snapshot bytes
  before and after" cannot hold once a twig has a hash-only slot: the export is refused. The
  tests check the same root, twig roots and proofs instead, and the snapshot round trip.
- **Undo (3.4a).** Besides the store refusing a truncation into a relocated twig, `apply_undo`
  checks up front, before it changes anything, and returns `QmdbUndoError::RelocatedTwig` or
  `QmdbUndoError::HashOnlySlot` (a revival of a payload-less slot).

Each stage is a bench pair (X22 control against the change, `scripts/fleet7-runs` stage) before
it is adopted; stage 0 needs none. Stages 0-2 are additive and can land behind
`N42_QMDB_COMPACT=1` (default off until stage 3 has its field check).

Order note (2026-10-28): stage 2 lands before stage 1. Stage 2 never punches, so the old bytes of
a relocated twig stay where the read view's byte offsets point and the view needs no change;
stage 1 (slot-resolving view) is what stage 3's punching requires, and its bench pair waits for
the host's power supply (`docs/MATURITY_HARDENING_2026_10.md` 8.3). Stage 2 ships the mechanism
(`compact_twigs` on the tree, the second file, the two-file open, the checkpoint field, the
`relocated_bytes` gauge) with no production caller: stage 3 adds the scheduler.

Stage 3 as landed (2026-11-03, `feat/qmdb-compact-stage34`), where it differs from 3.4-3.6:

- **Schedule.** `qmdb-reth::entry_compaction`: with `N42_QMDB_COMPACT=1` a file-mode node runs
  thread `n42-qmdb-entcompact` (niced like the log's fold, `N42_QMDB_COMPACT_NICE`), woken by every
  `on_persisted` and once a second while punches wait. A round's budget is
  `N42_QMDB_COMPACT_TWIGS_PER_BLOCK` (4) per block persisted since the last round, at most 64; the
  dead share is `N42_QMDB_COMPACT_DEAD_FRAC` (0.5). The horizon is the slot count after the newest
  block in the delta log at or below `min(database persisted, logged) - N42_QMDB_COMPACT_RETAIN`
  (256 blocks): a restart stands at the database's head or above, so it never meets a group whose
  dead records name a kill its checkpoint does not hold (such a group is skipped at open, which
  would leave a punched twig unreadable). The forest clamps it further to its undo records, as in
  stage 2. The scan is incremental: a cursor in the forest, at most 16,384 twigs looked at a round.
- **Under the lock, no `fsync`.** `compact_twigs` writes the groups to `entries.relocated` (so the
  view's mapping sees them) and retargets the slots; the round syncs the file through a second
  handle after the lock is released, and `punch` syncs it again before it frees anything. A crash
  before the sync loses groups whose old bytes are all still in place.
- **The reader epoch** is the read view's: the round hands the moves to `QmdbReadView::retarget`
  and keeps the freed ranges with the returned ticket; a later round punches them, oldest first,
  once `moved_unreachable` says no journal can name them (with the default 64 journals, about 64
  persisted blocks later). Without a valid view a range is punched in the same round.
- **`entries.punched`, not the checkpoint.** The punched ranges are a file of their own beside the
  entry files (29-byte records: file, twig, start, end, CRC-32; `twig_core::punched`), appended and
  synced before the punch. Every opening reads it -- a restart, but also a read-only open at an
  archived checkpoint older than the latest punch, which the checkpoint would not have told -- and
  the checkpoint format is unchanged (still version 2, `relocated_len` still recorded only). A
  torn record ends the list; a writable open cuts it off.
- **Open.** The walk of `entries.log` jumps over each punched twig's range and gives its 2048 slots
  placeholder offsets; the walk of `entries.relocated` jumps over punched earlier groups. A group
  whose CRC fails is skipped, not the end of the walk (later groups may hold punched twigs), and
  a run of failing groups at the end of the file is a torn tail and is cut; a
  group naming a twig past the kept slots is skipped too, and a writable open disarms it (its CRC
  inverted in place) so a later open that keeps more slots never applies it to the records
  appended in their place (stage 2 cut the file there, which would now lose later groups). A
  punched twig left without a group, or a prefix that ends inside one, refuses the open. A writable
  open that keeps fewer slots drops the main-file holes past them from `entries.punched`.
- **Limits.** A clone of the tree (`try_clone`) taken before a compaction still names the old
  offsets and must not be read after the punch; nothing in the node keeps one across rounds. A
  read-only historical open (`from_entry_file_readonly`, the recovery frontier's root of an old
  block) at a block below a punched twig's horizon may refuse (`kills a live slot` group skipped,
  main range punched): the caller treats it as unavailable. A damaged latest group of a twig
  (a CRC that fails: a torn write, a bad sector) is not applied: the twig falls back to its
  previous intact group, which is older and holds a superset of the live records (the slots it
  names live that later died are dead in the checkpoint's bits and read as such), or to its
  records in `entries.log` when it has no earlier group. When those older bytes are already
  punched, the open refuses with "a punched twig without a group": the entry store lost data the
  checkpoint needs, and the node has to be restored (a portable snapshot from a peer, or a
  resync), not restarted. A thread per state: `initialize` run again on the same state finds the
  compaction thread running and starts no second one.
- **Metrics.** `EntryStoreStats::punched_bytes` and the gauge `n42_qmdb_entry_punched_bytes`;
  `bytes_per_live_slot` is (file + relocated - punched) / live. With the compaction on, the 10 s
  sampler also logs one `QMDB entry store` line a minute (per_live, file, relocated, punched, live,
  offsets, rounds, twigs) for a fleet leg to read.

Stage 3 in the field (2026-11-04, `audit-notes/ci/rollkill.log`, `ci/rk-c34{k90,k20,long}/`):
`rollkill-check.sh` on the branch natives with `N42_QMDB_ENTRY_FILE=1 N42_QMDB_COMPACT=1
N42_QMDB_COMPACT_RETAIN=8 N42_QMDB_COMPACT_DEAD_FRAC=0.05`, seven nodes at 200 tx/s, members 1-3
SIGKILLed and restarted in turn. The 90 s and 20 s first-kill legs (the 20 s one before the first
persistence) passed with zero fault lines but compacted nothing: four senders write ~10 slots a
block, so no twig filled in 118 blocks. A 1,260 s leg killed at heights 280, 301 and 323, after
every node had compacted twig 0 (101,879 B into `entries.relocated`, 130,843 B punched): each member
restarted on the punched files, committed again (zero fault lines), and then compacted and punched
twig 1 like the members never killed (204,436 B relocated, 261,332 B punched on every node).

Stage 4 as landed: an offsets segment (2^20 slots, 512 twigs, 8 MiB) whose every twig is relocated
and that lies wholly below the last slot is released (`Offsets::release_segment`, refused while an
`OffsetsReader` is alive); each of its twigs keeps its slots as `u32` starts from its group's base,
4 B a slot. A slot's offset is read from its cell as before when its segment is kept (no extra
load on the hot path: the segment pointer is loaded anyway), and from its twig's starts when the
segment is gone. So that segments do fill, a twig is a candidate whatever its dead share once 384
of the 512 twigs of its segment are relocated (`SEGMENT_MOP_UP_TWIGS`): such a twig is rewritten
for the heap, not the disk. Released segments are released again at open. `offsets_bytes` counts
the live segments at 8 MiB and each released twig's starts at 8 KiB.

## 6. A v2 portable snapshot with tombstones (plan row E2)

**Status (2026-11-07):** implemented on both clients, each on branch
`feat/qmdb-portable-snapshot-v2` (n42-rs: `9b5c247e0` codec, verifier and fixtures, `07a6aac03` node export/import and `--format`, `498efe605` lock; gov5: `e037a535`), neither merged. v1
stays the default and is byte-for-byte unchanged. The layout below becomes the cross-client
contract when both branches merge; until then it is a proposal with two implementations and a
shared fixture set (`crates/n42/twig-core/testdata/portable_v2/`, copied into gov5's
`lib/qmdb/testdata/portable_v2/`). Three gaps in the original text were filled while
implementing, listed under "Decisions taken while implementing" at the end of this section.
Still a proposal / open: a Rust importer for kind 3 (see decision 3), gov5 persisting an
imported tree (`FlushTo` with a leaf store is expected to work, untested), and the gov5 PR.


Why: a v1 portable snapshot (`QmdbPortableSnapshot`, `verify_portable_stream`, gov5's
`lib/qmdb` portable codec) is the complete positional slot log -- every slot, dead ones included,
as `[slot u64][active u8][key 32][len u32][value]` -- and its verifier hashes `hash_leaf(key,
value)` for each. A compacting node has dropped the payload of its compacted twigs' dead slots and
keeps only their leaf hashes, so it cannot produce v1 (`portable_export` refuses,
`NodeStateError::PortableCompacted`), and today only a node with compaction off can serve a
bootstrap. Nothing below changes the root or what a verifier proves; it changes what a slot record
may carry.

**Format.** Header as v1 with the magic's version byte bumped (`N42QMDB\x03`, v1 is
`N42QMDB\x01`; see decision 1 for why not `\x02`) and one more header field after `entry_count`: `tombstones u64`, the number of records of
kind 2 and 3 below (so a reader can size and a v1-only reader stops at the magic). Each slot record
starts `[slot u64][kind u8]`:

| kind | rest of the record | meaning | verifier |
| --- | --- | --- | --- |
| 0 | `[key 32][len u32][value]` | dead slot with its payload (as v1 `active = 0`) | leaf = `hash_leaf(key, value)`, bit 0 |
| 1 | `[key 32][len u32][value]` | live slot (as v1 `active = 1`) | leaf = `hash_leaf(key, value)`, bit 1 |
| 2 | `[leaf_hash 32]` | tombstone: a dead slot whose payload was dropped | leaf = `leaf_hash`, bit 0 |
| 3 | `[count u16][leaf_root 32]` | a run of `count` dead slots filling the rest of a twig from this slot, all tombstones | the twig's leaf tree root is `leaf_root`, every bit of the run 0; the next record's slot is `slot + count` |

Kind 3 lets a twig that died entirely (rare under transfers, `docs/QMDB_UPGRADE_PLAN.md` 4b, but
common under contract churn) cost 43 bytes. It is optional: an exporter may always write kind 2.
A kind 3 run may only start a twig (`slot % 2048 == 0`, `count == 2048`), so the verifier sets the
twig's leaf root directly instead of rebuilding 2048 leaves; partial runs are written as kind 2.
Records stay contiguous by slot (`slot` = the expected next slot, as v1), the value bound stays
`MAX_PORTABLE_VALUE_SIZE`, and the trailing Blake3 digest still covers every byte before it,
header included.

**Verification.** The streaming verifier keeps one twig: for kinds 0 and 1 it hashes as v1; for
kind 2 it sets the leaf to the stored hash; for kind 3 it sets the twig's leaf root and clears its
bits; the twig root, the fold of twig roots and the root check are v1's. A tombstone cannot be
checked on its own -- it is a hash -- but it is committed to by the twig root like every leaf, so a
wrong tombstone fails the root comparison exactly as a wrong value does. `live_count` counts kind 1.
A tombstone with the active bit set is not representable (kinds 2 and 3 are dead by definition).

**Import.** Both clients rebuild a tree whose tombstoned slots are hash-only. On the Rust side that
exists: `QmdbSnapshot` entries with `leaf_hash`, and `set_entry_file` writing such a twig as a
relocated group (stage 2). gov5 needs the equivalent in its entry store (a slot that holds a leaf
hash and no payload, refused by any path that needs the key: undo, revival, a v1 export).

**Who writes which.** An archive node (compaction off) keeps writing v1; a compacting node writes
v2 (or refuses v1, as now). A verifier accepts both magics. `n42-qmdb-export` / `n42-init-snapshot
export` gain `--format v2`; `init` reads either.

**Migration and cross-client contract.** v1 is unchanged and stays the default until gov5 ships a
v2 reader. The proposal goes to gov5 as a fixture set under `crates/n42/twig-core/testdata/`
(a small tree with live, dead-with-payload, tombstoned and whole-dead twigs, its v1 export from the
uncompacted copy and its v2 export from the compacted one, both verifying to the same root), checked
by SHA-256 of the raw bytes like the other cross-client fixtures. Until both clients read v2, a
fleet that compacts must keep at least one archive node (compaction off) to serve bootstraps. No
code is written for this section until gov5 agrees the layout.
(Superseded 2026-11-06: the coordinator decided to implement it on branches on both sides; see
the status line.)

**Decisions taken while implementing (2026-11-07).**

1. *Magic `N42QMDB\x03`, not `\x02`.* gov5 main already writes a different layout under
   `N42QMDB\x02`: the leaf-form snapshot (gov5 `df01cff7`, `lib/qmdb/portable_v2.go`,
   `n42-qmdb-export --leaf-form`: per twig leaf root, bits and optional leaf hashes, then live
   entries only), used on 2026-08-29 to bootstrap a Rust validator onto chain 94 (its Rust reader
   lives only on unmerged n42-rs branches). Two layouts must never share a magic, so the tombstone
   layout takes version byte 3. The name "v2" is kept for the tombstone layout in this document
   and in the flags (`--format v2`); gov5 calls the leaf form `leaf-form`.
2. *`entry_count` still equals `next_slot`* (slots covered, not records), as v1; the header's
   `tombstones` must equal the number of kind-2 plus kind-3 records or the snapshot is refused
   (`TombstoneCount`). A kind-3 record counts once.
3. *Kind 3 verifies everywhere but imports only on gov5.* A kind-3 run carries one leaf root, not
   2048 leaf hashes. gov5's tree holds such a twig natively (a pruned twig: leaf root, clear bits,
   no nodes), so its importer reads kind 3. The Rust entry store rebuilds every twig's leaves from
   its per-slot records on open (`twig_leaf_nodes`), so a leaf-root-only twig needs a new
   relocated-group record; until that exists the Rust importer refuses kind 3 with a typed error
   (`QmdbPortableError::DeadTwigNotImportable`) after checking its shape, and the Rust exporter
   writes kind 2 only (kind 3 is a library option, `QmdbPortableTree::encode(V2, true)`). gov5's
   exporter (`--format v2`) must write kind 3 for a twig whose leaves it no longer keeps (a hollow
   twig), so a gov5 v2 export of such a node does not import into Rust today: the first open item.

Where the paths that need a key refuse a tombstoned slot: Rust `QmdbUndoError::HashOnlySlot`
(undo revival), `NodeStateError::PortableCompacted` / `QmdbPortableError::HashOnlySlot` (v1
export), and a heap-mode node refuses to import tombstones (its checkpoint layout has no hash-only
slot); gov5 `*HashOnlySlotError` (`errors.Is(err, ErrHashOnlySlot)`) from `ApplyUndo`, the v1
`PortableSlotSource` and `FlushTo` without a leaf store.

