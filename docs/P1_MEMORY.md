# Profile-1 member memory (n42 + h2_validator)

Branch `perf/p1-memory` (2026-11-26). Goal: a smaller memory footprint for a profile-1
member -- the `n42` execution layer (EL) and its `h2_validator` -- idle, under steady load
and during catch-up, without changing behaviour or wire formats. Fleet7 / bench chains are
untouched: every change applies only on a genesis that declares `"n42Profile": 1`, and
`N42_P1_MEMORY=0` turns all of it off.

## Result

RSS per process, MiB, median of the phase (8 s blocks, four members, 150 tx/s total; round v4)
and the catch-up peak (VmHWM):

| phase | EL before | EL after | validator before | validator after | member before | member after |
|---|---|---|---|---|---|---|
| idle (4 min) | 483 | 193 | 185 | 43 | 668 | 236 (-65%) |
| steady load (7 min, 150 tx/s) | 656 | 291-294 | 195 | 51 | 851 | 343 (-60%) |
| after load (2 min) | 701 | 302-305 | 194 | 47 | 895 | 351 (-61%) |
| catch-up, 3,020 light blocks (peak) | 1,031-1,042 | 449-456 | 219-222 | 87-92 | 1,253-1,261 | 541-543 (-57%) |
| catch-up, heavy chain of 2,277 blocks (peak) | 5,580-5,621 | 2,857 | 1,018-1,103 | 958 | 6,598-6,724 | 3,815 (-43%) |

"before" = the same binary with `N42_P1_MEMORY=0` (`main`'s behaviour), in the same round as
"after". Threads: EL 1,569-1,825 -> 96-107, validator 515 -> 27. The light catch-up was
4.7x faster with the defaults and the heavy one 17-24% faster (20.3 against 16.9-17.1
blocks/s; base members drive this 254-CPU box's load to 180-250). The light catch-up row
predates blst's pool and the heavy row is h5-ef (every default, the entry file included).

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
- Threads left: 255 named `payload-convert` in the EL and 263 named `h2_validator` in the
  validator. Both are blst's verification pool (`ThreadPool::default()` in `blst::mt`, one
  thread per CPU, made at the first aggregate-signature check; its unnamed threads take the
  name of the thread that made it). Round v4 sizes it.
- Heap that remains in the EL (v2 m3 after the load, 416 MiB sampled live, mostly
  untouched): the cross-block cache 128 MiB (256 MiB cap), RocksDB 48 + 16 + 8 MiB, the
  static-file writers 48 + 5 MiB (`get_writer`), execution outputs 28 MiB, the twig pool
  8 + 3 MiB, receipt ZSTD dictionary 6 MiB.

### Round v4 (blst's pool sized, 209899a49; 14:55-15:08 UTC, load idle 1.6, load 1.0, post 17.7)

blst has no setting for its pool, so `n42_h2_primitives::bls::pool::size_verification_pool`
makes it first (one Miller loop through the pooled entry point) from a helper thread whose CPU
mask holds `N42_P1_CORES` CPUs (`num_cpus` counts the calling thread's mask), then gives the
workers (`n42-bls-pool`) the process's full mask back. Same verification code, 8 workers.
Phases 4 / 7 / 2 min; m0 `N42_P1_MEMORY=0`, m1-m3 the defaults (identical, three samples).

| member | idle EL / val | load EL / val | post EL / val | EL / val threads |
|---|---|---|---|---|
| m0 (off) | 483 / 185 | 656 / 195 | 701 / 194 | 1,568-1,825 / 515 |
| m1-m3 | 192-193 / 43 | 291-294 / 51 | 302-305 / 47 | 96-107 / 27 |

Against v3's defaults: EL threads 343 -> 97, validator 273 -> 27; EL -13 MiB idle and
~-30 MiB under load, validator -10 to -15 MiB.

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
### Catch-up on the heavy chain (rounds hv-*, 18:44-19:44 UTC, binary 209899a49)

The catch-up lane's chain (`scripts/catchup-bench.sh`, a copy of its serving members): 2,277
blocks at 500 ms, 14.9M transactions, 1.78 GB, phases of 2,000-40,000 tx/s (blocks up to
22,857 transactions). Member 3 pulls it from members 0 and 1 (defaults on); `leg`'s own
report gives the speed, `p1-memory-sample.py` the memory each second; `hv-prof` adds
`MALLOC_CONF=prof:true` and an EL heap profile every 8 s.

| leg | member 3 | box load before / after | blocks/s | EL VmHWM | EL RSS median | validator VmHWM | validator median |
|---|---|---|---|---|---|---|---|
| hv-base | `N42_P1_MEMORY=0` | 0.6 / 180 | 15.9 | 5,592 | 4,238 | 1,135 | 958 |
| hv-baseb | `N42_P1_MEMORY=0` | 7.5 / 192 | 16.9 | 5,594 | 4,299 | 1,150 | 927 |
| hv-p1 | defaults (8) | 125 (a build) / 28 | 19.6 | 4,788 | 3,299 | 1,061 | 728 |
| hv-p1b | defaults (8) | 5.0 / 7.7 | 19.8 | 4,761 | 3,360 | 877 | 696 |
| hv-prof | defaults + heap profiles | 0.5 / 6.8 | 19.7 | 4,706 | 3,412 | 912 | 693 |
| hv-p1c32 | `N42_P1_CORES=32` | 20.5 / 26 | 26.8 | 5,241 | 3,505 | 803 | 595 |

- The defaults lower the heavy catch-up's EL peak by 15% (5.59 -> 4.71-4.79 GB) and its
  median by 21%, the validator's peak by 8-24%, and catch up 17-24% *faster* than the base
  (the base member alone takes the box's load to 180-192).
- `N42_P1_CORES=32` is 36% faster again (26.8 blocks/s, the speed of the catch-up lane's
  `--cpu-cores 32` legs) for +0.45-0.5 GB of EL peak; in steady state 16 cores cost
  ~10 MiB over 8 (v3). Execution is the bound (`new_payload` 45 ms a block at 8 cores,
  31 ms at 32; the pull itself is not).
- What remains is not threads. The EL's heap at hv-prof's peak (3.43 GB sampled live,
  `go tool pprof -traces` plus `addr2line` for the inlined frames):

  | what | MiB | where |
  |---|---|---|
  | QMDB entries in the heap | 1,024 | one `Vec` in `n42_twig_core::entry_store::Entries` (heap mode, ~160 B per entry, grown by doubling), `apply_ops_recorded_phased` |
  | receipts copied into reth's RPC state cache | 756 | `reth_rpc_eth_types::cache::ChainChange::new` clones every canonical block's receipts; the receipt cache is bounded at 1 GiB |
  | `RocksDB` memtables (transaction hash index, history) | 479 | 128 MiB per column family, a 4 GiB budget (`N42_ROCKSDB_WRITE_BUFFER_MB`) |
  | reth cross-block cache | 128 | its 256 MiB profile-1 bound |
  | execution outputs, receipts, logs of the blocks in flight | ~400 | `validate_payload`, `eip7708_transfer_log` |

### Heavy chain, the EL heap levers (rounds h5-*, h6-*, 20:35-22:40 UTC)

Binary 99fa092f3 (`bin-new5`: main's catch-up step 3 merged, the RPC caches bounded at
64 MiB each, 4c64a1f3f). Same chain and method; box load 3-11 at every start.

| leg | member 3 | blocks/s | EL VmHWM | EL RSS median | validator VmHWM |
|---|---|---|---|---|---|
| h5-base, h5-baseb | `N42_P1_MEMORY=0` | 16.9, 17.1 | 5,580, 5,621 | 4,301, 4,336 | 1,018, 1,103 |
| h5-p1, h5-p1b, h5-prof | defaults | 20.3, 20.3, 20.1 | 3,482, 3,591, 3,630 | 2,293, 2,294, 2,322 | 1,004, 1,008, 1,000 |
| h5-ef | defaults + `N42_QMDB_ENTRY_FILE=1` | 20.4 | 2,857 | 2,227 | 958 |
| h5-wb | defaults + `N42_ROCKSDB_WRITE_BUFFER_MB=128` | stopped at block 817 | -- | -- | -- |

- The RPC cache bound takes the EL peak from 4.71-4.79 GB (hv-p1) to 3.48-3.63 GB at the
  same speed: -36% against the base peak, -47% on the median.
- The entry file takes another 0.63-0.77 GB off the peak (2.86 GB, -49% against the base)
  at the same speed; its file pages (`RssFile` 336 MiB median) are reclaimable.
  Adopted as a profile-1 default (5533af98a): a heap-mode datadir migrates once at the
  next start and then stays in file mode. SIGKILL test (`kill-ef`, four members at 500 ms,
  150 tx/s): member 2 started in heap mode, was SIGKILLed under load, restarted in file
  mode (migration), SIGKILLed again 2 s after that restart, then three more times at
  40-70 s; every restart restored from the entry file and the four heads matched (417)
  with no halt.
- `N42_ROCKSDB_WRITE_BUFFER_MB=128` **stops a catch-up for good**, twice (hv-wb on a busy
  box, h5-wb on a quiet one), right after `RocksDB`'s first budget-triggered flush: the
  flush finishes (`AccountsHistory`, 82 ms), then neither `RocksDB` nor the engine logs
  anything again; the engine never receives the next payload and the validator's request
  times out. The budget's write stall (`WriteBufferManager` with `allow_stall`) waits
  until memtable memory falls below the budget, and a flushed memtable is freed only once
  nothing references it -- a provider's history snapshot keeps its cached iterators, and
  with them the memtables they were created on, until it is dropped
  (`DatabaseProvider::history_rocksdb_snapshot`). Not adopted. 5b8fb0177 adds
  `N42_ROCKSDB_WRITE_BUFFER_STALL=0` (default unchanged): the budget then only triggers
  flushes. With it the catch-up completes every time (h6-wbns, h6-wbns2 at 128 MiB,
  h6-wb256ns at 256 MiB: 20.3-20.4 blocks/s), which confirms the stall as the cause, but the
  EL peak moves only 3.42-3.55 GB against the defaults' 3.48-3.63 GB -- inside the spread.
  The budget is therefore left at upstream's 4 GiB with the stall on; nothing is adopted.

### The explorer workload with the 64 MiB RPC caches (explorer-rc, 22:25-22:31 UTC)

`scripts/explorer-load.py` (Blockscout's receipts fetchers) against member 3's EL alone on
the heavy chain (blocks 1-2,277), 60 s per fetcher, the profile-1 bound (`cap64`) and
reth's (`reth`: 2 GiB / 1 GiB / 500 MiB) alternated twice:

| fetcher | cap64 | reth | EL VmHWM cap64 / reth |
|---|---|---|---|
| receipts (`eth_getTransactionReceipt`, 250 x 10) | 86,620 / 87,767 calls/s | 88,004 / 88,083 calls/s | 3.5 / 4.3 GB |
| block-receipts (`eth_getBlockReceipts`, 10 x 10) | 216.0 / 225.4 blocks/s | 225.4 / 227.8 blocks/s | 6.8-7.1 / 10.6-11.6 GB |

Within the runs' spread (-0.3 to -1.6% on receipts); p50/p99 latency the same. Both
variants hit the same 320 "batch response was too large" errors on block-receipts (10
heavy blocks' receipts exceed the 160 MiB response limit), a property of the chain.

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
| blst verification pool | CPUs | `N42_P1_CORES` (`n42-bls-pool-*`, full CPU mask) | `N42_P1_CORES` | n42, h2_validator |
| RPC state cache (blocks, receipts, block access lists) | 2 GiB, 1 GiB, 500 MiB | 64 MiB each | `--rpc-cache.max-{blocks,receipts,bals}-bytes`, `N42_P1_RPC_CACHE_MB` | n42 |
| QMDB entries | in the heap | in `qmdb/entries.log` (one-way: a migrated datadir stays in file mode) | `N42_QMDB_ENTRY_FILE` | n42 |

`N42_P1_CORES` defaults to 8 (never more than the host has; `0` keeps the host's count and
also leaves the allocator alone); `N42_P1_MEMORY=0` turns every row off. Both binaries print
one stderr line listing what they set. None of these values is consensus-visible: thread
counts, cache sizes and when a page is faulted; the blocks, roots, votes and wire bytes
are the same.

Recommended profile-1 settings: the defaults above (nothing to pass). On a host where a
member must catch up thousands of blocks quickly, `N42_P1_CORES=32` catches up 36% faster
for ~0.5 GB more EL peak (hv-p1c32); in steady state 16 cores cost ~10 MiB over 8 (v3).

## Why the host matters

Most of the baseline is per-thread and per-arena memory, and both counts follow the CPUs
the process may run on: the box here has 254. A member on an 8-16 core machine starts
with ~30-60 threads per pool and 32-64 arenas, so its "before" is much closer to "after";
the cross-block cache, the RocksDB cache and the QMDB pools do not depend on the host.

## Biggest remaining consumers / next steps

1. **Catch-up** is still the peak: EL 2.9 GB, validator ~0.95 GB on the heavy chain. The
   EL's remainder is `RocksDB`'s memtables (~480 MiB), the blocks in flight and their
   execution outputs (~400 MiB), the cross-block cache (256 MiB bound); reth's canonical
   in-memory state holds only 6-15 blocks throughout (its metrics), so the engine's
   in-memory block limit is not a lever, and the persistence threshold stays (SIGKILL
   recovery). The validator's is the range-sync pipeline (`sync_pipeline.rs`: 4 x
   128-block slots in flight, 256 MiB ready, a 64-block import queue). That belongs to the
   catch-up lane; byte budgets (~192 MiB requested in flight, 64 MiB ready, a byte-bounded
   import queue) were handed to it.
2. **The EL's steady heap** after the pools: RocksDB (~72 MiB with a 32 MiB block cache:
   write buffers and statistics), the static-file writers (~53 MiB, one per segment, open
   for the node's life), the cross-block cache as it fills (up to 256 MiB), and execution
   outputs held by the engine tree until persistence (~30 MiB at 150 tx/s).
3. **Threads:** none follow the host any more (EL 97-107, validator 27; v4).
4. **File pages** (~65-69 MiB `RssFile`, the binary and MDBX/QMDB mappings) are shared and
   reclaimable; they were not targeted. With the entry file the EL's `RssFile` grows to
   ~340-600 MiB during a heavy catch-up (the entry file's pages), also reclaimable.
5. **Not done:** the `RocksDB` memtable budget (see h5-wb / h6-*: a stall hazard below
   ~256 MiB with upstream's write stall, no gain without it); the steady-state rounds
   (v1-v4) predate the RPC-cache bound and the entry file, which matter for catch-up and
   for a long-lived node's growth (heap entries grow with every state entry ever written).

## RocksDB memtables (B6, branch `perf/p1-memory-2`, 2026-11-27)

**What holds the memory.** Not an iterator and not a snapshot: `RocksDBProvider` opens
an `OptimisticTransactionDB`, and `OptimisticTransactionDB::Open` sets
`max_write_buffer_size_to_maintain = -1` on every column family whose value is 0
(librocksdb-sys 10.4.2, `optimistic_transaction_db_impl.cc`), i.e. a memtable history of
`max_write_buffer_number x write_buffer_size` = 2 x 128 MiB per column family, kept so a
transaction can check its keys for conflicts in memory. A flushed memtable moves into that
history (`MemTableListVersion::Remove`) instead of being freed, stays charged to the write
buffer manager, and is trimmed only when the history exceeds its bound
(`MemoryAllocatedBytesExcludingLast() + usage`, so the newest flushed memtable is never
counted) -- in practice by a later write to the same column family. The node never checks a
transaction conflict: production writes `WriteBatch`es (`commit_batch`) and reads snapshots;
`RocksTx` is used only in tests. The history is dead memory.

**Why a small budget stalled for good.** With the write stall on, a write waits while
`memory_usage() >= budget`, and a flush is triggered only when the mutable memtables exceed
7/8 of the budget or half of it while over budget (`WriteBufferManager::ShouldFlush`). The
first budget-triggered flush moves ~7/8 of the budget into the history; the next write
finds the budget exceeded with less than half of it mutable, so it neither flushes nor
proceeds, and only a write could trim the history. Reproduced in a unit test with no
iterator and no snapshot open (`test_small_budget_with_upstream_memtables_stalls_for_good`,
ignored because it leaves a blocked thread): 32 MiB budget, two column families, the writer
stops after ~28 MiB with each column family holding one flushed memtable (15.8 MB each, 2 MB
unflushed, `rocksdb.num-snapshots` 0). That is the h5-wb / hv-wb hang (catch-up stopped
right after the first budget flush) and why `N42_ROCKSDB_WRITE_BUFFER_STALL=0` moved the
peak only inside the spread: without the stall the budget triggers flushes, but every
flushed memtable still sits in the history.

**Footprint** (ad-hoc test, 1 GiB written in 64 KiB values to two column families,
`size-all-mem-tables` at the end):

| configuration | memtables held | of which unflushed | write time |
|---|---|---|---|
| upstream (4 GiB budget, 128 MiB memtables, history -1) | 573 MiB | 62 MiB | 1.61 s |
| `N42_ROCKSDB_MEMTABLE_MB=128` | 8 MiB | 8 MiB | 1.52 s |
| `N42_ROCKSDB_MEMTABLE_MB=256` | 17 MiB | 17 MiB | 1.47 s |

511 of upstream's 573 MiB are flushed history (two 128 MiB memtables per column family),
the same order as the ~480 MiB of memtables in the heavy catch-up's heap profile.

**Change** (be474d0f0, additive, off by default): `N42_ROCKSDB_MEMTABLE_MB=<n>` sets the
write buffer manager to n MiB, every column family's memtable to n/32 (1-128 MiB) and its
history bound to one memtable (a positive `max_write_buffer_size_to_maintain`, which
`OptimisticTransactionDB` keeps). The history of five column families then stays under half
the budget, so a stalled write always ends with a flush. Builder methods
`with_memtable_budget` / `with_write_buffer_manager_size`;
`test_bounded_memtable_budget_does_not_stall` writes 256 MiB through a 32 MiB budget and
checks the memtables stay under it. `N42_ROCKSDB_WRITE_BUFFER_MB` is unchanged.

## Heap rounds and the profile-1 memtable default (2026-11-28)

Two `steady` rounds, four members each on the 8 s genesis, 300 s idle, 150 tx/s for 90 min,
300 s idle; members 0-1 on main's RocksDB settings, members 2-3 with
`N42_ROCKSDB_MEMTABLE_MB=128`; a jemalloc heap profile of every EL every 15 min
(`MALLOC_CONF=prof:true,lg_prof_sample:19`, profiling build with `jemalloc-prof`).
`heap1`: main 9b373ce00 + this branch (RocksDB 10.4.2); `heap2`: the same with `rocksdb`
0.25.0 (RocksDB 11.8.1, branch `inv/rocksdb-0.25`). Profiles were diffed per allocation
stack with `/data/n42-build/p1-memory/tools/heapdiff.py` (raw profiles, `addr2line` over
the top stacks only: 30 s instead of ~11 min for `go tool pprof -traces` on this binary).

EL VmRSS / `je_allocated`, MiB, end of each 15-min bin of the load phase:

| round | members | 15 | 30 | 45 | 60 | 75 | 90 |
|---|---|---|---|---|---|---|---|
| heap1 | 0-1 (main) | 400/755 | 486/839 | 523-534/877-879 | 545-557/893-895 | 562-573/908 | 580-585/929 |
| heap1 | 2-3 (knob) | 391-401/750-753 | 473-478/829 | 505-512/853-855 | 506-517/853-855 | 508-519/853-854 | 514-515/857-860 |
| heap2 | 0-1 (main) | 401-404/758-760 | 497-501/843-844 | 526-535/879-880 | 559/895-897 | 567-583/913-914 | 592-596/931-932 |
| heap2 | 2-3 (knob) | 403-405/754-756 | 485-490/832-834 | 507-510/855-858 | 510-512/854-858 | 511-515/859-861 | 519/860-864 |

Where the heap went (member 0 / member 2 of heap1, in-use bytes by allocation stack):

- 0-60 min, both: +120 MiB per 30 min, mostly the RPC state cache filling to its profile-1
  bounds -- the transactions `convert_payload_to_block` decodes (kept as the cache's blocks,
  0.7 -> 47 -> 92 MiB), receipts and logs cloned by `ChainChange::new` (~60 MiB), the
  `EthStateCache` LRU table -- plus the fee-history cache. All of them stop growing by
  60 min: they are bounded caches, not leaks (the decoded blocks hold ~90 MiB against the
  64 MiB `--rpc-cache.max-blocks-bytes`, so the cache's size estimate reads low by ~1.4x).
- 60-105 min, member 0 (main): +40.9 MiB, of which +45.4 MiB is RocksDB's memtable arena
  (`ConcurrentArena::AllocateAligned`, 80 MiB held) -- the flushed-memtable history of
  `AccountsHistory`, `StoragesHistory` and `TransactionHashNumbers`, which flush every
  10-20 min at 128 MiB ("Write Buffer Full") and keep up to two flushed memtables each.
- 60-105 min, member 2 (knob): +2.4 MiB in total; what grows is the Prometheus exporter's
  histogram sketches (only with `--metrics`) and the fee-history cache.

No allocation on the block-import or execution path grows once the caches are full.
RocksDB 11.8.1 behaves like 10.4.2 (same curves within 1-2%): the upstream report of
the history being charged to the write buffer manager (facebook/rocksdb#15535, fix PR
#15551 open, not in any release as of 11.15.1) is not fixed by upgrading; the knob is
the remedy. The bump compiles without changes and passes the provider's 96 RocksDB tests.

**Change:** `N42_ROCKSDB_MEMTABLE_MB=128` joins the profile-1 env defaults
(`STORAGE_KNOBS` in `crates/n42/qmdb-reth/src/profile1_memory.rs`; an operator's value
wins). Same expected effect on the mixed fleet's n42-rs member: mem7's EL grew 196 ->
1,085 MiB in 3.5 h with the history tables flushing on the same 10-20 min cadence.

**Heavy catch-up with the default** (2026-11-28 05:00-05:25 EST, `scripts/catchup-bench.sh`
legs on the catch-up lane's 2,277-block heavy chain, binary fbab5b278, member 3 pulls from
genesis; `hm-off*` = `N42_ROCKSDB_MEMTABLE_MB=0`, upstream memtables): no stall, the same
speed, a 20% lower EL peak.

| leg | import 1..2,277 | member 3 EL VmRSS median/max | RssAnon max | je_allocated max |
|---|---|---|---|---|
| hm-off | 112.2 s | 2,233 / 2,881 MiB | 2,333 | 2,243 |
| hm-off2 | 112.7 s | 2,296 / 2,906 MiB | 2,312 | 2,207 |
| hm-def | 112.7 s | 1,743 / 2,314 MiB | 1,828 | 1,738 |
| hm-def2 | 112.7 s | 1,749 / 2,304 MiB | 1,839 | 1,759 |
