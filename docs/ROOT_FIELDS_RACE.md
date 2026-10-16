# The root and fields race on X15

Read-only analysis of the X15 legs of loop351 stage ca (`bench-loop351D2S12P30T64X11T16Qs{a,b}`, 600M set, layout
`b64/c16/bg128/behind-bg`, `N42_ROOT_OPS_AHEAD=1`, `N42_QMDB_COMPUTE_OFFLOCK=1`, parallel apply engaged: the layer logs
`QMDB block apply parallel_apply=true rayon_threads=16`). Source: every `seal-first build phases` line of `node0-el.log` with
>= 190k transfers, windows = 30 s from the round's first full block. Follows docs/X15_BUILD_NEXT.md section 3 (cut 1).
Scripts kept outside the repo (`rf/parse.py`, `ana.py`, `gate.py`, `sim.py`). Code read at bench/main-x11t16.

## 1. The root per block over the round (p50 / mean, ms)

| part (log field) | Qsa w1 | Qsa w2 | Qsa w3 | Qsb w1 | Qsb w3 | w1 -> w3 p50 |
| --- | --- | --- | --- | --- | --- | --- |
| root duration (start -> end) | 32.6 / 34.7 | 35.0 / 37.1 | 36.3 / 39.1 | 33.0 / 34.6 | 38.2 / 41.7 | +3.7 / +5.2 |
| . compute (`root_compute_us`) | 27.2 / 29.3 | 31.2 / 32.4 | 33.0 / 34.9 | 27.6 / 29.0 | 34.5 / 37.8 | +5.8 / +6.9 |
| .. lookups (`root_leaves_us`; leaf hashes are pre-lease) | 4.4 / 5.7 | 5.3 / 6.3 | 5.6 / 6.6 | 4.2 / 5.5 | 6.6 / 7.9 | +1.2 / +2.4 |
| .. writes | 4.3 / 5.7 | 4.9 / 6.7 | 5.3 / 6.6 | 4.7 / 6.1 | 5.2 / 6.9 | +1.0 / +0.5 |
| .. index inserts (joined with the rehash) | 4.4 / 5.2 | 4.2 / 5.3 | 4.3 / 5.3 | 4.4 / 5.4 | 4.3 / 5.6 | 0 |
| .. rehash + upper tree (`root_rehash_us`) | 4.1 / 4.9 | 5.5 / 6.9 | 6.9 / 8.4 | 4.2 / 5.2 | 7.1 / 8.6 | **+2.9** |
| .. retire / delta / sort / undo | 2.4 / 1.4 / 0.5 / 0.5 | 2.6 / 1.4 / 0.5 / 0.5 | 2.6 / 1.4 / 0.6 / 0.5 | 2.2 / 1.4 / 0.5 / 0.4 | 3.0 / 1.2 / 0.5 / 0.5 | +0.2..0.8 |
| . ops finish (residual merged in) | 2.3 / 2.7 | 2.1 / 2.5 | 2.2 / 2.5 | 2.2 / 2.6 | 2.2 / 2.6 | 0 |
| . rest of the job (pre-lease leaf hashes, publication) | ~3.1 | ~1.7 | ~1.1 | ~3.2 | ~1.5 | |
| ops ahead encode / sort (own thread, off the chain) | 8.6 / 4.6 | 8.6 / 5.3 | 8.9 / 5.3 | 8.1 / 4.8 | 10.4 / 5.2 | Qsa +0.3, Qsb +2.3 |
| distinct accounts per block (`merge_accounts`) | 190.7k | 190.0k | 191.5k | 190.6k | 192.0k | flat |
| seal -> root start / root gated by the previous root (start <= prev end + 3 ms) | 29.1 / 64% | 33.3 / 67% | 35.5 / 70% | 28.7 / 59% | 37.9 / 77% | |
| seal -> fields published (mean) | 65.7 | 71.5 | 77.2 | 64.0 | 83.3 | +11.5 / +19.3 |
| root duration / block interval | 0.82 | 0.85 | 0.87 | 0.81 | 0.91 | |
| **parent_fields wait mean; share > 1 ms** | **3.5; 37%** | **5.7; 50%** | **7.5; 56%** | **2.8; 31%** | **10.5; 70%** | |

`root_index_us` and `root_rehash_us` run under one `rayon::join` and are both timed from its start, so the phases overlap and
`root_apply_total_us` over-counts. The phase's wall is max(index, rehash) + the upper tree: index binds in w1 (4.4 vs 4.1),
the rehash in w3 (6.9 vs 4.3). That is why the rehash's +2.9 reaches the duration almost whole.

**What grows is the tree's size, not the block.** The accounts a block touches are flat (190-192k), Qsa's ops-ahead encode
(fixed work per account) moves +3%, while the rehash + upper tree grows +70%. Per block the tree appends ~190k entries =
~93 twigs of 2,048: from ~33k twigs mid-w1 to ~160k mid-w3 (cap 65,536 -> 131,072 during w1/w2, 262,144 at the round's
end). The dirty set does not grow with it: senders' old entries sit in the previous block's ~9 tail twigs and recipients'
(uniform draw over 2M, re-touched every ~11.7 blocks) in the last ~60 blocks' twigs, ~5-7k bit-dirty twigs, steady once the
recipients exist. Three per-block passes are O(twigs) instead of O(dirty) (`twig-core/src/qmdb_compat.rs`):
`QmdbCompatTree::root` compares every `twigs[i].root` (a 368-byte `Twig` stride) with the cached upper leaf, serially, over
`cap` slots; `rehash_dirty` partitions by zipping all twigs with `dirty`; `retire_twigs` resizes `dirty` to all twigs. The
first is the suspect for the +2.9 ms (~22 ns a twig over ~130k extra twigs); the log sums `rehash_us + root_us`, so the split
is an inference to prove. The lookups (+1.2), writes (+1.0, root page faults 54 -> 72 a block) are the index and the entry
file under a growing heap. Qsb w3 also has a host-wide slowdown (ops encode +28%, which the tree does not touch).

## 2. Why the root is serial, and what can overlap

The root job of N starts 0.1 ms after `rename_parent` returns (seal -> rename 28.9 -> 35.1 ms), which files N-1 under its
seal and waits for N-1's fields (`PARENT_FIELDS_WAIT`, DEFERRED_DEPTH_2_DESIGN item 8). N's apply then leases the tree
at N-1 (`lease_tree(parent)`): next_slot, the key index (every sender's old slot was written by N-1), the twigs' bits. So the
chain is one queue at 0.82-0.91 utilisation, and N's seal waits for N-2's fields: the wait is that queue's tail.

| idea | needs N-1's tree? | verdict |
| --- | --- | --- |
| ops finish (2.2-2.5) + pre-lease leaf hashes (~2-3) | no (N's own shards, LeafHashes::of) | they run **after** the gate today, inside the duration: move them before it (option B) |
| N's lookups (`held_slots`, 4.4-6.6) beside N-1's apply | yes: senders' slots come from N-1's index inserts | only with an appended-slot overlay over the index (option C2) |
| split rehash by twig range | -- | already per twig on the pool (leaf twigs a task each, bit twigs in 512s); what is serial is the O(cap) upper scan and the levels under 1,024 parents |
| incremental rehash / upper tree | -- | the cache exists, its change detection is O(cap): make it O(dirty) (option A) |
| more critical cores (C16 -> C24/C32) | -- | no idle cores: build 64, critical 16, background = 24 physical + 80 siblings carrying ~27 busy threads in the flood (tokio ~17, plan-body ~3.5, storage ~2.8). Amdahl from 10.114 (C4 -> C16: root 35 -> 27 p50) gives ~24 ms serial: C24 -0.9 ms, C32 -1.4 ms, and it takes cores from the background that 10.113 showed must not starve |

## 3. Options (expected from a replay of the measured roots: same seals, root queue re-run with the cut, waits scaled to the observed)

Replay: root start = max(ops ahead done, previous end + 1 ms), duration less the ops-ahead join wait; it reads 3.1 / 4.5 /
5.6 ms (Qsa) against the observed 3.5 / 5.7 / 7.5, so the rows give replay ratio x observed. No feedback: a faster seal gives
about a quarter back (SEALED_AT_FLOOR section 3).

| option | kind | duration cut | parent_fields mean w1 / w2 / w3 (Qsa; Qsb) | share > 1 ms | sealed_at drift w1->w3 | risk |
| --- | --- | --- | --- | --- | --- | --- |
| now | -- | -- | 3.5 / 5.7 / 7.5; 2.8 / 5.5 / 10.5 | 37-56%; 31-70% | +4.4; +5.7 | |
| **A. upper tree O(dirty)** + split timer | small code change (twig-core) | the rehash's growth, 0 -> 2.9 p50 by w3 | 2.7 / 3.0 / 3.5; 1.9 / 3.4 / 5.2 | 25-28%; 23-31% | ~+1; ~+3 | low: same root (`root_full` check, `fields_mismatches` 0) |
| **B. root head before the gate** | small-to-medium (payload.rs root job order) | ~5 (finish + leaf hashes) | 2.5 / 3.5 / 5.0; 1.9 / 3.8 / 6.9 | 25-32%; 22-42% | keeps the drift | low-moderate: N's head shares the 16 cores with N-1's apply |
| A + B | both | ~5 + growth | 2.0 / 2.4 / 2.9; 1.4 / 2.6 / 4.5 | 20-21%; 17-26% | ~+1; ~+3 | as above |
| C1. carried depth 3 | design change (`MAX_DEFERRED_EXECUTION_DEPTH` = 2; consensus rule, followers, gov5) | none: +1 interval (~42 ms) of slack | ~0 while utilisation < 1 | ~0 | gone | high: own-block hold bound, the five-block window (`N42_FAR_AHEAD_BLOCKS=2`) collapsed 3 of 4 legs |
| C2. index overlay: N's lookups beside N-1's apply | design change (twig-core KeyIndex + forest lease) | 4.4-6.6 off the chain | with A+B: <= 2 in every window (estimate, not replayed) | < 20% | gone | moderate: a second reader of the index during inserts |
| D. C24 / C32 + `RAYON_NUM_THREADS` | knob (`N42_CORE_LAYOUT_CRITICAL_CORES`) | ~1-1.4 | -0.3..-0.5 | | | background starvation (10.113) |

A+B is expected to take ~3-3.5 ms off the mean parent_fields wait and most of the drift; it reaches the <= 2 ms target in
w1-w2 only. Every window at <= 2 needs C2 (or C1) on top, or a lower block size.

## 4. Smallest first: A, and its proof counters

1. A no-behaviour change first: log `root_us` apart from `rehash_us` (`root_upper_us`), plus `root_twigs` and
   `root_dirty_twigs`. It proves or kills the inference of section 1 on one leg: `root_upper_us` w1 -> w3 should grow
   ~+2.5 ms with `root_twigs`, `root_dirty_twigs` flat (~5-7k).
2. Then A: `root()` refreshes from the block's dirty twig ids (collected in `rehash_dirty`, or kept beside `dirty`) instead
   of scanning `cap` slots; `rehash_dirty` iterates the ids. Shape changes (cap crossing a power of two) keep the full rebuild.
   Tests: the cached root equals `root_full` (the existing debug assertion) across random blocks and a cap crossing.
3. Legs: two against two X15 controls, scored by drain rate; one leg with `N42_FIELDS_AT_SEAL=verify`.

Proof counters for A: `root_rehash_us` (now rehash + upper) w3 p50 <= 4.5 and within 0.6 ms of w1; `root_upper_us` p50 <=
0.5 ms in every window; root duration w3 - w1 <= +2 ms; `parent_fields_us` mean w3 <= 4 and the > 1 ms share <= 30%; drift
of `sealed_at` mean w1 -> w3 <= +2; `fields_mismatches` 0, `fleet7-verify` clean. Then B, whose counters are the full target:
`parent_fields_us` mean <= 2 in every window, share <= 25%, root duration / interval <= 0.75, a new `root_head_us` (finish +
leaf hashes, now before the gate) with ops-ahead -> root start <= 1 ms on gated roots.
