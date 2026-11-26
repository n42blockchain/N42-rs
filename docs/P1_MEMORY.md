# Profile-1 member memory (n42 + h2_validator)

Branch `perf/p1-memory` (2026-11-26). Goal: a smaller memory footprint for a profile-1
member -- the `n42` execution layer (EL) and its `h2_validator` -- idle, under steady load
and during catch-up, without changing behaviour or wire formats. Fleet7 / bench chains are
untouched: every change applies only on a genesis that declares `"n42Profile": 1`, and
`N42_P1_MEMORY=0` turns all of it off.

## Result

RSS per process, MiB, median of the phase (8 s blocks, four members, 150 tx/s total; catch-up: the
peak, two legs each):

| phase | EL before | EL after | validator before | validator after | member before | member after |
|---|---|---|---|---|---|---|
| idle (5 min) | 485 | 206 | 186 | 53 | 671 | 259 (-61%) |
| steady load (10 min, 150 tx/s) | 681 | 323 | 196 | 65 | 877 | 388 (-56%) |
| after load (3 min) | 739 | 346 | 196 | 62 | 935 | 408 (-56%) |
| catch-up of 3,020 blocks (VmHWM) | 1,031-1,042 | 449-456 | 219-222 | 87-92 | 1,253-1,261 | 541-543 (-57%) |

"before" = the same binary with `N42_P1_MEMORY=0` (identical to `main` at 027c47322), in the
same round as "after" (round v3, below); thread count EL 1,569 -> 343, validator
515 -> 273.

## How it is measured

- `scripts/p1-memory-round.sh` runs four profile-1 members with `scripts/profile1-round.sh`
  (`P1_PORT_OFFSET=120`) on the V1 genesis
  (`crates/n42/qmdb-reth/testdata/profile1/gov5/V1/genesis_8s.json`: 8 s blocks, four
  validators, 480M gas limit) plus 64 funded senders (`load-genesis`):
  - `steady <name>`: idle, then `send_tx` load at 150 tx/s total (4 x 37.5 tx/s, every
    transaction accepted, `0 rejected`), then idle again ("post");
  - `produce` / `catchup <name>`: a 500 ms copy of the same genesis loaded at 150 tx/s
    for 25 min gives a chain of ~3,000 blocks; member 3 is wiped, re-initialised and pulls
    it by range from members 0 and 1 (two of four: no quorum, the chain stands still).
- `scripts/p1-memory-sample.py` samples every member process each 5 s (1 s in catch-up):
  VmRSS, VmHWM, RssAnon, RssFile, threads, and the EL's jemalloc counters (`--metrics`:
  allocated / active / resident / retained). Tables give the median (max) over a phase,
  the first 60 s skipped.
- One variant per member in one round (`PM_ENV_<i>`, `PM_EL_ARGS_<i>`): the four members
  share the chain, the load and the box, so a column difference is the variant. Leader
  turns rotate (tenure 1), so every member leads a quarter of the blocks.
- Every member runs `MALLOC_CONF=prof:true,lg_prof_sample:19` (heap profiles through the
  EL's `/debug/pprof/heap`, read with `go tool pprof -traces`), in every variant.
- Host: 254 logical CPUs (members on `0-98,100-226,228-255`), 136 GB; other lanes' rounds
  ran beside these, so each round lists the box's 1-minute load. Memory is per process
  and does not depend on the load the way timings do, but the thread counts -- and so
  most of the baseline -- depend on the core count (see "Why the host matters").

Build: `cargo build --profile profiling -p n42 --features jemalloc-prof --bin n42` and the
`h2_validator`, `h2_keygen`, `send_tx` examples of `n42-h2-node`. Binaries are snapshotted
in `/data/n42-build/p1-memory/bin-{base,new,new2,new3}`; every run's samples, smaps, heap
profiles and logs are under `/data/n42-build/p1-memory/runs/<name>/`.

## Baseline (round `base`, main 027c47322, 2026-11-26 11:59-12:30 UTC)

Box load: idle 0.8 (max 1.9), load 6.2 (17.9), post 12.9 (21.5).

| phase | EL RSS | EL VmHWM | EL threads | EL jemalloc allocated / resident | validator RSS | validator threads |
|---|---|---|---|---|---|---|
| idle (10 min) | 487-499 (505-515) | 515 | 1,569 | 2,570 / 2,815 | 188-189 (191) | 515 |
| load 150 tx/s (15 min) | 704-715 (776-785) | 785 | 1,825 | 2,775 / 3,090 | 198-199 (201) | 515 |
| post (5 min) | 772-794 (800) | 800 | 1,825 | 2,827 / 3,170 | 197-198 (200) | 515 |

(ranges over the four members.) Where it goes:

- **Threads.** The EL had 1,569 threads idle and 1,825 under load: tokio's 254 workers,
  reth's `cpu-NN`, `rpc-NN` pools (254 each), the RPC eth API's `blocking-NN` rayon pool
  (254, sized by rayon's default), 255 `payload-convert` workers, and rayon's global pool
  (256 unnamed threads: clap's chain parser computes the QMDB genesis root on it before reth
  can build it with its own size -- "Failed to build global thread pool" in every EL log).
  The validator had 515: rayon's global pool (254) and `blst`'s verification pool (254,
  `ThreadPool::default()`, one per CPU, not configurable), with 4 tokio workers. Every
  thread keeps the stack pages it once touched (smaps: 562 4 MiB mappings holding 133 MiB
  in one EL, 244 2 MiB ones holding 25 MiB) and its jemalloc thread cache.
- **jemalloc arenas.** The validator uses jemalloc too (the `tikv-jemallocator` override
  exports `malloc`, so `MALLOC_CONF` applies to it). jemalloc makes 4 arenas per CPU, 1,016
  here; each thread takes one, and an arena keeps its dirty pages until it allocates again
  (no background purging by default).
- **reth's cross-block execution cache** (`--engine.cross-block-cache-size`, 4 GiB default):
  a `fixed-cache` allocated whole at the first payload, 2.2 GB of the 2.57 GB jemalloc
  "allocated" at idle (heap profile: 2,048 + 128 MiB under `validate_payload`). Its pages
  are resident only once touched (2.3 MiB at idle), so it costs little at first and grows
  with every account a block touches; on the QMDB path the node writes it only on reth's
  own payload execution (`exec_cache.rs`), but it never shrinks.
- **QMDB prefault pools** (`twig-core/src/prefault.rs`, tuned for fleet7's 163,000-op blocks):
  512 clean twig trees (64 MiB, `calloc < top_up` 62 MiB in the heap profile), a 64 MiB
  populated append window, two 8 MiB offsets segments -- in the EL **and** in the
  validator, which opens a QMDB tree once to compute the genesis root.
- **RocksDB** (transaction hash index): a 128 MiB block cache, 48 + 16 MiB at open.
- Live heap growth under load: ~145 MiB sampled between idle and the end of the load
  phase (execution outputs, receipts, the engine tree's in-memory blocks), most of it still
  held after the load ("post" > "load").

Catch-up (observed, not ours): a `scripts/catchup-bench.sh` leg of the catch-up lane
(perf/p1-catchup, chain of 2,277 heavy blocks, 2,000-40,000 tx/s phases at 500 ms),
sampled read-only at 13:3x UTC: the catching-up member's EL 6.8 GB median, **10.3 GB max
(VmHWM 11.2 GB)**, jemalloc allocated 11.5 GB max; its validator 1.75 GB median, **5.3 GB
max (VmHWM 5.6 GB)**; the two serving ELs 3.6-3.7 GB (1.3 GB of it file pages). Box load
94 (160). Catch-up is the peak of a member's life; see "Catch-up" below for our chain.

## Steps (change, before, after)

Each step was measured as one member variant beside an unchanged member in the same round.
RSS MiB median, EL / validator.

### Round v1 (old binary, variants by flag/env; 12:34-12:53 UTC, load idle 15.6, load 6.5, post 1.9)

| member | variant | idle EL / val | load EL / val | post EL / val | EL threads |
|---|---|---|---|---|---|
| m0 | none | 491 / 186 | 686 / 197 | 742 / 197 | 1,569 |
| m1 | `--engine.cross-block-cache-size 256` (val: `MALLOC_ARENA_MAX=2`) | 494 / 186 | 686 / 197 | 754 / 195 | 1,569 |
| m2 | `--cpu-cores 8`, `RAYON_NUM_THREADS=8` | 351 / 149 | 483 / 159 | 502 / 159 | 339 |
| m3 | `MALLOC_CONF=...,background_thread:true,narenas:8` | 356 / 142 | 545 / 154 | 580 / 150 | 1,573 |

- The cross-block cache does not show in 25 minutes (its pages fill slowly); it caps a
  growth that is otherwise unbounded up to 2.2 GB, and drops jemalloc's "allocated" from
  2.57 GB to 0.53 GB.
- `MALLOC_ARENA_MAX` does nothing: the validator does not run on glibc malloc.
- Thread pools and jemalloc arenas are the two big levers, each ~140 MiB on the EL idle.

### Round v2 (new binary; m0 `N42_P1_MEMORY=0`; 13:17-13:36 UTC, load idle 193, load 10.7, post 1.1)

| member | variant | idle EL / val | load EL / val | post EL / val | EL threads |
|---|---|---|---|---|---|
| m0 | defaults off | 489 / 186 | 678 / 196 | 717 / 196 | 1,569 |
| m1 | in-process defaults (pools, caches, prefault) | 311 / 77 | 442 / 86 | 477 / 86 | 585 |
| m2 | m1 + `background_thread:true` | 295 / 76 | 405 / 87 | 430 / 84 | 589 |
| m3 | m1 + `background_thread:true,narenas:8` | 223 / 53 | 335 / 65 | 361 / 62 | 589 |

(m1 here lacked the `RAYON_NUM_THREADS` default: 254 `blocking-NN` and 255
`payload-convert` threads remained, fixed in 93c724a6e.)

- The QMDB prefault pools were most of the validator: 186 -> 77 MiB.
- Background purging alone: -16 to -47 MiB on the EL. An arena per core: another -70 MiB on
  the EL and -23 MiB on the validator.

### Round v3 (final binary e1dc2e60c; 13:38-13:56 UTC, load idle 6.2, load 1.9, post 2.1)

Every member applies the in-process defaults and re-execs itself with
`MALLOC_CONF=narenas:N,background_thread:true,<operator's options>`; m0 has them off.
22,501 transactions per sender process, 0 rejected; all four members at the same head
(134) at the end, no halt, one view timeout each, as in v2.

| member | variant | idle EL / val | load EL / val | post EL / val | EL / val threads |
|---|---|---|---|---|---|
| m0 | `N42_P1_MEMORY=0` | 485 / 186 | 681 / 196 | 739 / 195 | 1,569-1,825 / 515 |
| m1 | defaults (cores 8) | 206 / 53 | 323 / 65 | 346 / 62 | 343-353 / 273 |
| m2 | `N42_P1_CORES=4` | 206 / 53 | 314 / 66 | 343 / 62 | 323-329 / 269 |
| m3 | `N42_P1_CORES=16` | 209 / 54 | 329 / 66 | 352 / 62 | 383-401 / 281 |

- EL -58% idle, -53% under load; validator -72% idle, -67% under load. jemalloc's
  "retained" (address space held, not resident) drops from 2.4 GB to 0.2 GB.
- 4, 8 or 16 cores differ by under 15 MiB: the remaining threads no longer scale with the
  host, so 8 is kept (the build and the catch-up get more parallelism than 4).
- Threads left: the EL's 255 `payload-convert` workers (a reth/engine-types pool sized by
  the host, not by rayon's default; ~1 MiB stacks barely touched) and the validator's
  `blst` pool (254 threads named `h2_validator`, `ThreadPool::default()` in `blst::mt`).
  Each costs little resident memory now that its arena is shared.
- Heap that remains in the EL (v2 m3 after the load, 416 MiB sampled live, mostly
  untouched): the cross-block cache 128 MiB (256 MiB cap), RocksDB 48 + 16 + 8 MiB, the
  static-file writers 48 + 5 MiB (`get_writer`), execution outputs 28 MiB, the twig pool
  8 + 3 MiB, receipt ZSTD dictionary 6 MiB.

### Catch-up (rounds cu-base/cu-new and cu-new2/cu-base2, 14:24-14:35 UTC)

Chain: the V1 genesis at 500 ms, 150 tx/s for 25 min, 3,019-3,034 blocks. Member 3 is
wiped, re-initialised and pulls the chain by range from members 0 and 1 (which run the
defaults in every leg); its own variant is `N42_P1_MEMORY=0` (base) or the defaults.
Two pairs, the second in the reverse order. Sampled every second; the sampler starts
once the members are up, so the first blocks (269 base, 1,280 defaults) were pulled
before the first sample -- VmHWM covers them.

| leg | box load at start / end | EL VmHWM | EL RSS median | EL threads | validator VmHWM | blocks/s (sampled window) |
|---|---|---|---|---|---|---|
| cu-base | 60 / 284 | 1,031 | 1,022 | 1,823 | 222 | 83 (269 -> 3,019 in 34 s) |
| cu-new | 27 / 25 | 456 | 412 | 351 | 87 | 405 (1,280 -> 3,022 in 4.4 s) |
| cu-new2 | 5 / 5 | 449 | 414 | 351 | 92 | 400 |
| cu-base2 | 2 / 217 | 1,042 | 1,029 | 1,824 | 219 | 87 (272 -> 3,034 in 35 s) |

- The catch-up peak falls by 57% (EL -56%, validator -60%).
- And it is ~4.7x faster on this host, in both orders: with 1,823 threads the base member
  alone drove the box's load from 2 to 217-284 (its 254-thread pools spinning on small
  blocks), while the defaults left it at 5-25. A member on a small host would not see
  this ratio; it does say 8 cores are not the bound of a range catch-up of 8-second-class
  blocks. The defaults' EL RSS falls back to ~410 MiB once at the head.
- Not compared here: the catch-up lane's heavy chain (2,000-40,000 tx/s phases), where
  the peak is the engine's in-memory blocks and the range-sync buffers (baseline section),
  not the pools.

## What changed (all on a profile-1 genesis only)

`crates/n42/qmdb-reth/src/profile1_memory.rs` holds the knobs and the genesis check;
`bin/n42/src/profile1_memory.rs` and `h2_validator` apply them. The genesis file named by
`--chain` is read before clap's parser (which computes the genesis root on rayon's global
pool and opens a QMDB tree), so everything is in place before the first thread.

| what | default before | profile 1 | knob (operator value wins) | applies to |
|---|---|---|---|---|
| jemalloc arenas, background purging | 4 x CPUs, off | `narenas:N42_P1_CORES,background_thread:true` (one `exec` of itself with `MALLOC_CONF`; same pid and argv) | `MALLOC_CONF` with `narenas` (the operator's options come after ours otherwise) | n42, h2_validator |
| rayon pools of default size (global, RPC `blocking-NN`) | CPUs | `RAYON_NUM_THREADS=N42_P1_CORES` | `RAYON_NUM_THREADS` | n42, h2_validator |
| tokio workers, reth `cpu`/`rpc`/proof/prewarm pools | CPUs | `--cpu-cores N42_P1_CORES` | `--cpu-cores` | n42 |
| reth cross-block execution cache | 4,096 MiB | 256 MiB | `--engine.cross-block-cache-size`, `N42_P1_CROSS_BLOCK_CACHE_MB` | n42 |
| RocksDB block cache | 128 MiB | 32 MiB | `--db.rocksdb-block-cache-size`, `N42_P1_ROCKSDB_CACHE_MB` | n42 |
| QMDB twig pool floor | 512 trees (64 MiB) | 16 (2 MiB) | `N42_TWIG_POOL_FLOOR` | n42, h2_validator |
| QMDB append populate-ahead | 64 MiB | 8 MiB | `N42_QMDB_APPEND_AHEAD_MB` | n42, h2_validator |
| QMDB offsets segments ahead | 2 (16 MiB) | 1 | `N42_QMDB_OFFSET_SEGMENTS_AHEAD` | n42, h2_validator |

`N42_P1_CORES` defaults to 8 (never more than the host has; `0` keeps the host's count and
also leaves the allocator alone); `N42_P1_MEMORY=0` turns every row off. Both binaries print
one stderr line listing what they set. None of these values is consensus-visible: thread
counts, cache sizes and when a page is faulted; the blocks, roots, votes and wire bytes
are the same.

Recommended profile-1 settings: the defaults above (nothing to pass). On a host where a
member must catch up thousands of blocks quickly, `N42_P1_CORES=16` trades memory for
parallel execution (see v3).

## Why the host matters

Most of the baseline is per-thread and per-arena memory, and both counts follow the CPUs
the process may run on: the box here has 254. A member on an 8-16 core machine starts
with ~30-60 threads per pool and 32-64 arenas, so its "before" is much closer to "after";
the cross-block cache, the RocksDB cache and the QMDB pools do not depend on the host.

## Biggest remaining consumers / next steps

1. **Catch-up** is the peak by an order of magnitude (the catch-up lane's heavy chain:
   EL 10 GB, validator 5 GB). The EL's share is the engine tree's in-memory blocks and
   their execution outputs between persistences, plus the reth payload path that fills
   the cross-block cache (now capped at 256 MiB); the validator's is the range-sync
   buffers (`sync_pipeline.rs`, byte-capped at 256 MiB ready, 4 x 128-block slots, a
   64-block import queue) and the decoded blocks behind them. Those buffers belong to the
   catch-up lane (perf/p1-catchup) and were left alone here; a profile-1 cap on the slots
   and the ready bytes is the next lever there. reth's persistence threshold was not
   lowered: it is the SIGKILL-recovery setting of the QMDB node (see the reth-bump notes).
2. **The EL's steady heap** after the pools: RocksDB (~72 MiB with a 32 MiB block cache:
   write buffers and statistics), the static-file writers (~53 MiB, one per segment, open
   for the node's life), the cross-block cache as it fills (up to 256 MiB), and execution
   outputs held by the engine tree until persistence (~30 MiB at 150 tx/s).
3. **Threads that still follow the host:** 255 `payload-convert` workers in the EL and
   `blst`'s 254-thread pool in the validator. Sizing `payload-convert` by `--cpu-cores`
   and giving blst a profile-1 pool (it has no knob: `blst::mt::da_pool` is a
   `ThreadPool::default()`; the verification would have to go through the single-threaded
   entry points) would save their stacks and thread caches, a few MiB each now.
4. **File pages** (~65-69 MiB `RssFile`, the binary and MDBX/QMDB mappings) are shared and
   reclaimable; they were not targeted.
