# QMDB entry-file compaction: a root-neutral design

Status: design, 2026-10-27. Item 6.2 of `docs/MATURITY_HARDENING_2026_10.md`. Nothing here is
implemented; the stages at the end say what lands first and how each is verified.

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

`n42_qmdb_entry_file_bytes`, `n42_qmdb_entry_relocated_bytes`, `n42_qmdb_entry_punched_bytes`,
`n42_qmdb_entry_live_slots`, `n42_qmdb_entry_total_slots`, `n42_qmdb_offsets_bytes`, and the
alarm `n42_qmdb_entry_bytes_per_live_slot` (file + relocated - punched, over live slots); a
warning when it passes `N42_QMDB_ENTRY_BYTES_PER_LIVE_ALARM` (default 2,000). All are
available today from `FileEntries` (slots, bytes), `index_bytes()`, and a popcount of `active`.

## 4. What this does not do

- It does not reclaim the leaf trees (`N42_QMDB_TRIM_TWIGS` already does) or the `Twig` structs.
- It does not change the root, the proofs, the portable snapshot or anything gov5 reads.
- It does not help the heap mode (`N42_QMDB_ENTRY_FILE` off): there the `Vec<Entry>` is the
  file; the same slot-stable relocation applies in principle but is not worth building.

## 5. Stages and verification

| stage | change | verification |
| --- | --- | --- |
| 0 | metrics of 3.7 | unit tests; one fleet leg shows the growth rates in the table of section 1 |
| 1 | read view resolves slots through atomic `Offsets` (3.3), no relocation yet | existing read-view and proof tests; an X22 control pair (the hot read path changes: expect noise) |
| 2 | `entries.relocated`, tagged records, `open_existing` from two files, `Offsets` top bit, checkpoint fields; compaction runs but never punches | tests: compact, restart, same root and same proofs; same portable snapshot bytes before and after; undo across a compacted boundary refused by construction (3.4a) and tested |
| 3 | scheduler on the pruner thread, epoch-deferred punching, `punched` in the checkpoint | tests with a fake epoch; a fleet leg reads `entry_bytes_per_live_slot` falling to a plateau; `roll --kill` under load restarts on a punched file |
| 4 | per-twig `base + u32` offsets for compacted twigs | heap growth per slot halves on the metric; control pair |

Each stage is a bench pair (X22 control against the change, `scripts/fleet7-runs` stage) before
it is adopted; stage 0 needs none. Stages 0-2 are additive and can land behind
`N42_QMDB_COMPACT=1` (default off until stage 3 has its field check).
