# Taking the QMDB root off the serial path

Read-only design analysis (no code changed, no leg run). Question: how to let two consecutive blocks' QMDB roots overlap so
that, once the leader builds two blocks ahead (docs/BUILD_AHEAD_AND_VOTE_PACE.md, k = 2), the gap floor falls below ~34 ms.
Sources: every `seal-first build phases` line with >= 190k transfers in `node0-el.log` of the X16 legs of loop351 stage cc
(BREAKTHROUGH_DESIGN 10.152): `bench-loop351D2S12P30T64X11T16Sra` (`N42_ROOT_UPPER_DIRTY=1 N42_ROOT_OPS_BEFORE_GATE=1`,
"pre-gate") and `...Sa` (X16 control); windows = 30 s from the first full block (~690 blocks each). Scripts kept outside the
repo (`rpd/parse.py`, `h.py`, `sim.py`). Code read at bench/main-x11t16.

## 0. The answer in brief

* With the two stage-cc root cuts in, **the gated root is 24.5-26.0 ms mean (0.57-0.61 of the 43 ms interval)**, not the
  36.7-37.7 ms the build-ahead replay assumed (that was the Rl legs, before the cuts). The serial root alone allows ~27 ms.
* What binds at depth 2 is the **latency** seal -> fields (63 ms mean, 78-84 p90), not the serial queue: N+2's seal waits
  N's fields, so gap >= (seal -> fields + 2) / 2. Of the 63 ms only ~3 ms is queueing behind N-1's root (replay); the rest is
  the head (seal -> gate open 35.6: shards ready 9.6, ops-ahead encode + sort 15, finish 2.8, sort + leaf hashes) and the
  gated apply (25). Overlapping roots therefore buys little at depth 2; **shortening the gated apply** buys half its cut.
* Replay (two-ahead, vote not binding): today's Sra chain gives 37.1 ms at the measured build pace and 34.8 even with a
  26 ms build. Moving N's index lookups (+ undo, dup check) out of the gated apply (C1) gives 34.9 / 33.4 (pace 31.3 / 30);
  with a shorter head on top 33.4 / 31.8. Depth 3 (C2) gives 33.0 / 31.4, but its root then queues (util 0.77-0.86) and
  wants C1 under it. Sharding the tree (C3) changes the consensus root and is rejected.
* **Recommended: C1, staged** -- first "lease early" (no overlay, no new invariant), then the overlay proper; C2 only if the
  gap reads <= 33 and `parent_fields` still binds.

## 1. The root's phases and what each needs of N-1 (means, ms; Sa = control, Sra = pre-gate; w1 / w3)

The tree is one positional structure (`twig-core/src/qmdb_compat.rs`, gov5's layout): every set appends at `next_slot`
(`first_slot + appended.len()`, no padding) and retires the key's old slot; twigs are 2,048 consecutive slots; the upper tree
folds twig roots in slot order. The key index (`index.rs`) is 256 shards by `key[0]`, buckets `fingerprint:24 | slot+1:40`,
a fingerprint hit verified by `entries.key(slot)`. N's apply leases the tree at N-1 (`forest.rs` `lease_tree(parent)`); with
pre-gate the job waits on `gate` (the parent's rename = N-1's fields, `payload.rs` root job) only for the apply.

| phase (log field) | runs | needs from N-1 | Sa w1 / w3 | Sra w1 / w3 |
| --- | --- | --- | --- | --- |
| ops-ahead encode + sort (own thread on the critical pool, from shards ready) | head | nothing | 10.0 + 5.5 | 9.9 + 5.3 |
| ops finish (`root_ops_finish_us`) | head (Sra) / gated (Sa) | nothing (N's shards, residual) | 2.6 / 2.5 | 2.7 / 2.9 |
| dup check (`root_sort_us`) | gated | nothing | 0.6 / 0.7 | 0.8 / 0.7 |
| leaf hashes (`LeafHashes::of`, no slot in the hash) | pre-gate in Sra | nothing | in lookups | in `root_pre_gate_us` |
| **lookups** (`held_slots`, `root_leaves_us`) | gated | **key index at N-1** (senders' slots were written by N-1) + `entries.key` of old slots | 5.2 / 6.9 | 4.9 / 4.6 |
| undo record (slots only) | gated | N's `held` only | 0.6 / 0.6 | 0.6 / 0.5 |
| retire (`retire_twigs`, entry bits) | gated | **N-1's twigs** (senders' old slots sit in N-1's ~9 tail twigs) | 3.2 / 3.4 | 2.9 / 2.9 |
| writes (appends, leaves, entry store, deletes' index removals) | gated | **`next_slot`, entry-file tail, the shared tail twig** | 5.7 / 6.2 | 7.1 / 5.8 |
| index inserts (`insert_sorted`, joined with the rehash) | gated | **the index after N-1's inserts** | 5.5 / 5.0 | 6.2 / 6.2 |
| twig rehash (`root_twig_rehash_us`) | gated | N-1's rehashed tail twigs | 3.6 / 3.9 | 4.4 / 4.6 |
| upper tree (`root_upper_us`) | gated | every twig root | 1.5 / **3.9** | 0.9 / 0.95 |
| delta + note (`root_delta_us`) | gated | N's undo | 2.1 / 2.0 | 2.5 / 2.3 |
| **gated compute (`root_compute_us`)** | | | **28.6 / 33.5** | **26.0 / 24.5** |
| pre-gate head (`root_pre_gate_us`; of it ops-ahead wait) / gate wait | | | -- | 19.4 (12.1) / 1.6; 18.8 (11.4) / 2.0 |
| seal -> root start; seal -> fields | | | 28.5; 63.7 / 35.1; 75.2 | 35.8; 63.2 / 35.5; 61.9 |
| gated root / interval (42.8-44.0 ms) | | | 0.79 / 0.86 | **0.61 / 0.57** |
| `parent_fields_us` mean / p90; share > 1 ms | | | 2.5 / 10.3, 31% -> 6.4 / 16.3, 57% | 2.9 / 11.4, 30% -> 2.9 / 11.4, 28% |
| twigs; dirty twigs | | | 32.5k -> 160k; 4.8-5.0k | 32.6k -> 161k; 4.7-4.8k |

The dirty-twig refresh holds the upper tree flat (0.9 ms at 161k twigs against 3.9), so Sra's gated root no longer grows
over the round. Only lookups, retire, writes, index inserts and rehash touch N-1's tree; of them only the **lookups read
and nothing else**: retire, writes and rehash mutate twigs N-1 also wrote (the tail twig, N-1's ~9 tail twigs), the inserts
mutate the index N-1 inserted into. Lookups + undo + dup check = 6.3 / 5.8 ms of the 26.0 / 24.5 (Sra).

## 2. Option C1 -- index overlay: N's lookups beside N-1's apply

**Exactness.** Slot allocation is sequential and contiguous: N-1's appends take `[first(N-1), first(N-1) + v(N-1))` in
sorted-key order, v = N-1's operations with a value, `first(N-1)` = `next_slot` after N-2. So the moment N-1's operations
are final (its head), the overlay is exact: `ov(k) = Some(first(N-1) + rank_v(k))` for N-1's sets, `None` (tombstone) for
its deletes. Then `index_{N-1}(k) = ov(k) if k in ops(N-1) else index_{N-2}(k)`, so N's `held` equals what the serial
apply reads, the rest of the apply is unchanged, and **the root is bit-identical by construction**. N's own slots need no
prediction beyond `first(N) = first(N-1) + v(N-1)`, which the apply already computes from the lease.

**The read window.** The index mutates only in N-1's index phase (inserts) and, for deletes, in its writes (removals; none
in a transfer block). Deferring removals into the index phase leaves `index_{N-2}` stable from N-2's inserts' end to
N-1's inserts' start (N-1's gate + ~15 ms). `entries.key(slot)` is read only for slots below `first(N-1)`: immutable
records (append-only file; retire flips separate bits). Needs: a read view of the index shards and of the entry keys of
flushed/old segments while N-1's job holds the leased tree mutably (today one `&mut` owner) -- an `IndexReadView` handed
out under an epoch flag, or N-1's job running N's lookups itself on the pool.

**Timing at k = 2, gap 32 (Sra means).** N's keys are known at shards ready (seal + 9.6; key = `gov5_account_key(address)`,
no sort needed: `held` is carried by key and permuted with the ops-ahead sort). N-1's gate opens at seal(N) + 3.6 and its
inserts start ~seal(N) + 19.8 and end ~seal(N) + 26; N's head ends at seal(N) + 34. So the lookups (4.9 ms on the pool)
fit either in the overlay window (from seal + 10) or, without the overlay, between N-1's inserts' end and N's head end
(gap - 23.8: ~8 ms at 32, ~6 at 30, short of the 4.9 needed below ~29). **Most of C1's value needs no overlay at today's pace**; the overlay keeps
it when the gap or a slow N-1 closes the second window.

**Cost.** Overlay: N-1's sorted (key, slot) list, 190k x 40 B = 7.6 MB, built at its head (it is `appended` taken early);
probe by binary search or a merge with N's sorted keys, ~1 ms CPU. The lookups move, not vanish: 4.9 ms of the 16
critical cores now beside N-1's apply and N's ops-ahead encode (already on that pool) -- the replay does not model that.

| replay (Sra chain, k = 2, vote not binding) | mean gap at build pace 31.3 / 30 / 26 | `parent_fields` mean (p90) at 31.3 | gated root / gap |
| --- | --- | --- | --- |
| today | 37.1 / 35.6 / 34.8 | 5.7 (16.3) | 0.68-0.73 |
| C1: lookups + undo + dup check out of the gated apply | **34.9 / 33.4 / 32.0** | 3.6 (10.8) | 0.57-0.62 |
| C1 + a shorter head (ops-ahead wait -70%, not designed here) | 33.4 / 31.8 / 29.5 | 2.1 (4.4) | 0.60-0.68 |
| C1b: also retire + writes beside N-1 (twig conflicts, not proposed) | 32.8 / 31.3 / 28.5 | 1.5 (1.2) | 0.35-0.40 |
| X16 control chain (Sa), today | 39.1 / 38.1 / 37.5 | 8.2 (18.7) | 0.80-0.84 |

## 3. Option C2 -- carried depth 3

The header carries `result(N-3)`; N's seal waits N-3's fields (one more interval, ~32-43 ms of slack). What changes
(the depth-2 inventory, docs/DEFERRED_DEPTH_2_DESIGN.md section 2.2, re-read for D = 3):

| place | change |
| --- | --- |
| `chainspec/src/qmdb.rs` | `SUPPORTED_DEFERRED_EXECUTION_DEPTH` 2 -> 3, parser accepts 1..=3; `deferredExecutionTime` unchanged (0), `deferredExecutionDepth: 3` |
| `h2-consensus/src/deferred_depth.rs`, `hotstuff_consensus.rs` `ancestor_hash` | `ParentLink` carries only `parent_hash`: N-3 needs the grandparent's parent -> a lineage lookup or a third hash in the link; blocks 1-3 read genesis |
| `qmdb-reth/src/executed_fields.rs` | registry by hash with no parent links (item 15: "for D=3 the registry would need parent links"); the sealed -> built alias must reach two own blocks back |
| `payload.rs` seal (`parent_executed_fields_or_built`), `fields_at_seal.rs` | wait for N-3; the early-rename safety argument (item 8) re-derived: N-1 and N-2 may both be unfiled at N's root start |
| `bin/n42/src/follower_import.rs` vote road | `wait_for_parent_fields` on N-3; `PARENT_OUTPUTS_KEPT`, `DEFERRED_IN_FLIGHT` sized for 4-5 unlanded ancestors |
| `h2-execution/src/settlement.rs` | `certified = committed - 3`: `safe` lags one block more |
| restart (`main.rs` seed, the fields journal) | header H+1 carries `result(H-2)`: the journal must hold two results behind the head; replay and late joiners the same |
| genesis files | new `*_d3.json` copies (never edit the D=1/2 files: same hash, different rule); gov5 must implement D=3 or the chain is Rust-only; mobile proofs pair N with header N+3 |

Effect (replay): `parent_fields` mean 5.7 -> 1.7 and the p90 to 0, gap 37.1 -> 33.0 at pace 31.3, 31.4 at 30 -- but the root
queue grows (wait 2.9 -> 10.2 ms, util 0.77-0.86): **the serial root becomes the floor** (Sa's chain at D=3 sticks at 35-36),
so C2 needs C1 below it (D=3 + C1: 32.2 / 30.9 / 27.5). Risks: consensus change shipped to every client; one more block in
flight everywhere -- the five-block window (`N42_FAR_AHEAD_BLOCKS=2`) collapsed 3 of 4 legs on the hold and parent bounds;
memory (`BUILT_KEEP`, own holds); the gas-limit window (item 19) widens to three blocks; recovery paths untested at D=3.

## 4. Option C3 -- a sharded tree (disjoint key ranges, combined roots)

`qmdb_compat` commits to one global positional order: slots append in block order, twigs are 2,048 consecutive slots, the
upper tree folds twig roots by position. Disjoint key-range shards with their own slot sequences give a different
`stateRoot`: a new consensus commitment (gov5 fixtures, the portable-snapshot verifier, proofs gain a shard level,
`n42-init-snapshot`). Within one block the work is already split by key range: sorted ops give contiguous slot ranges per
range and the writes/rehash/index run per range on the pool. Across blocks sharding overlaps nothing: shard s of N still
waits shard s of N-1, and on the same 16 cores the work is the same; it only shortens the serial residue (writes, upper
levels, delta), a guess of 25 -> 18-20 ms gated. Cost: a chain-format change; risk: highest. **Rejected.**

## 5. Recommendation: C1, staged and env-gated (each stage default off, one logical commit each)

| stage | knob | what | proof (two legs against two X16 + two-ahead controls) |
| --- | --- | --- | --- |
| 0 | none | timers: N's keys-known, N-1's inserts start/end and N's head end (seal-relative), so each block's window is known | windows measured; nothing else moves |
| 1 | `N42_ROOT_LOOKUPS_EARLY=1` | N's job leases the tree as soon as N-1's fields are in, even with its head unfinished, and runs the lookups by key (from the shards) beside the head; `held` is permuted with the ops-ahead sort; no overlay, no new invariant | `root_lookups_early` share >= 80%; gated compute -4.5..-5.5 ms; fields_mismatches 0 |
| 2 | `N42_ROOT_LOOKUP_OVERLAY=1` (`=verify` re-runs `held_slots` gated and counts) | the overlay of section 2: removals deferred into the index phase, an index read view while N-1 is leased, N's lookups from seal + ~10 | `root_overlay_mismatches` 0 on a verify leg; early share ~100% at gap <= 32 |
| 3 | (separate design) | the head: ops-ahead encode + sort wait (11.5 ms) on the shared critical pool | seal -> gate open -5 |
| 4 | `deferredExecutionDepth: 3` genesis | C2, only if the gap reads <= 33 with 1-3 and `parent_fields` still binds | as section 3 |

Counters for C1 (stages 1-2) on the two-ahead set: gated root / mean gap <= 0.6 in every window; `parent_fields_us` p90
<= 3 ms (today 11.4 at a 43 ms gap) and mean <= 2; mean gap <= 34 (replay 33.4-34.9); seal -> fields <= 58 mean;
`fields_mismatches` 0, `fleet7-verify` clean, `N42_FIELDS_AT_SEAL=verify` on one leg; drain rate scored against the
controls. Caveats: the replay has no vote bound (k = 2 vote pace 32.4, BUILD_AHEAD section 6), no core contention between N's
lookups and N-1's apply, and reads ~1-1.4 ms high on its base; treat its rows as upper bounds on the gain.
