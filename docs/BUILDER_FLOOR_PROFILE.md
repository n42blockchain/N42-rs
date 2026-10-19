# Where the builder's 16 ms go, from a perf profile

Read-only analysis, 2026-10-18, of the leader's execution layer during a steady-state leg of loop351
(`perf-loop351D2S12P30T64X11T16bX11prof-*.data` under `target/fleet-runs/`, profiling binary = release + full debuginfo).
The leg drained **4.536M tx/s**; today's controls read 4.64-4.78M/s, so the profiled leg is ~3-5% slow (the profiler's cost).
Nothing was built or run for this document.

| file | events | scope | length | samples |
| --- | --- | --- | --- | --- |
| `...-build.data` | cycles, -F 499, DWARF call graphs (4 KB stacks) | the 64 `n42-build` threads (cores 0-63) | 8.05 s | 75,160 |
| `...-miss.data` | `ls_dmnd_fills_from_sys.dram_io_all`, `.all`, cycles; **all at period 400,000** (the last `-c` won) | same threads | 6 s | 1,323 / 5,287 / 1.34M |

Caveats. User-space call chains did not unwind (every user symbol's children = self), so shares are self time and callers come
from reading the source. Kernel frames are unresolved (`kptr_restrict`). The DRAM event has 1,323 samples: a 10% share is
+-0.8 points, a 1% share is noise.

## Scale

* On-CPU: 75,160 samples / (499 Hz x 8.05 s x 64 threads) = **29% busy, 71% asleep** (rayon parks idle workers in futex;
  sleeping threads are not sampled). Effective clock 580.9G cycles / 75,160 samples / 499 Hz = 3.86 GHz.
* At 4.536M/s, 8.05 s is ~183 blocks of 200k: **12.9 ms on-CPU per thread per block**, equal to the batch CPU floor the phase
  lines measure (wall sum / 64 = 12.9 mean, X15_BUILD_NEXT 1). So the 64 threads do little besides `par_exec`, and
  **1% of build-thread cycles = 0.13 ms of the per-block CPU floor** (0.16 ms if scaled to the 16 ms wall).
* The miss window was busier (535G cycles in 6 s = 36%; ~136 blocks): 19.7k cycles = 5.1 us of thread time per transfer.

## 1. Cycles by group (self time; ms = share x 0.13)

| group | symbols (largest first) | build cycles | ms / block | miss-window cycles |
| --- | --- | --- | --- | --- |
| **state lookups, total** | rows below | **48.5%** | **6.3** | 50.2% |
| . parent / in-memory layers | `MemoryOverlayStateProvider::basic_account` (N42 6.31, Eth 1.93), `FrozenShards::get` 3.35, `ShardLayer::basic_account` 2.04, `OverlayStateProvider::basic_account_from_db` 1.84, `enter_part` 1.78 | 18.1% | 2.3 | 22.8% |
| . batch map + warm cache | `BatchState::basic` 7.60, `batch_state::loaded` 2.78, `rustc_entry<Address,BundleAccount>` 2.08, `WarmDb::basic` 0.91, `get_mut` 0.65 | 14.0% | 1.8 | 9.1% |
| . address hashing (every probe) | `<[u8;20] as Hash>::hash::<FbHasher<20>>` 3.97 + 0.50 + `foldhash` seed 1.31 | 5.8% | 0.75 | 0.8% |
| . QMDB read view | journal `find_map` over `JournalData` 2.49 + 0.56, `QmdbReadView::account` 1.25, `SharedOffsetIndex::get` 0.74, `EntryFileView::record` 0.41 | 5.6% | 0.73 | 3.4% |
| . **changeset scans (historical fallback)** | `NippyJarCursor::next_row_with_cols` 1.74, `get_account_before_block` 0.96, jar/cursor drops 0.92, `get_one` 0.39, jar map 0.70 | **4.9%** | **0.64** | **11.9%** |
| transfer execution | batch loop (`execute_for_build_opts::{closure#4}`, the inlined fast path) 9.81, `alt_sig_tx_env` 2.62, `U256::overflowing_add/sub` 2.53, `commit_transfer` 1.57, `TxEnv` drop 0.40 | 18.6% | 2.4 | 14.0% |
| bundle building at each thread's end | `take_bundle` `retain` 3.26, `RevertToSlot` map `from_iter` 2.16, `update_and_create_revert` 1.73, `BundleState::account` 0.75, `OutputShards::add` 1.22 | 9.1% | 1.2 | 11.2% |
| kernel (unresolved; most likely futex sleep/wake and page faults) | | 7.0% | 0.9 | 6.2% |
| libc (unresolved, `0x1a73xx`: memmove/memcpy) | | 5.1% | 0.65 | 9.0% |
| rayon / crossbeam-epoch / locks | `Global::try_advance` 0.86, epoch pin 0.54, `Stealer::steal` 0.21, `lock_shared_slow` 0.28, `Once` 0.24 | 3.2% | 0.41 | 4.1% |
| hashing (blake3, QMDB keys) | `blake3_compress_in_place_avx512` 1.22, `blake3::hash` 0.59 | 1.9% | 0.24 | 0.4% |
| decode (`LegacyAccount::from_compact`) | | 1.3% | 0.17 | 0.8% |
| tx selection / body prep on the pool | `BodyAhead` 0.85, `frame_blocks::select`, unzip | 1.4% | 0.18 | 0.9% |
| jemalloc | (no symbol above 0.1%) | <0.3% | - | - |

Half of the build's CPU is finding accounts, not executing transfers. The changeset scans differ 2.4x between the two
windows: they are bursty, per block (section 4, item 1).

## 2. Where the DRAM fills come from (miss window)

| group | DRAM fills (`dram_io_all`) | all L1D demand fills (`.all`) | top symbols (DRAM share) |
| --- | --- | --- | --- |
| parent / in-memory layers | **28.2%** | 31.0% | `FrozenShards::get` 9.45, `MemoryOverlay::basic_account` 5.67 + 2.04, `ShardLayer` 4.61, `BundleState::account` (in-memory blocks' bundles) 4.54, `enter_part` 3.70 |
| batch map + warm cache | 17.6% | 9.1% | `BatchState::basic` 10.36, `WarmDb::basic` 5.59, `rustc_entry` 1.36 |
| transfer execution | 14.4% | 10.1% | **`alt_sig_tx_env` 7.79** (first touch of the cold pooled 0x50 body), batch loop 5.29, `AltSigTx::clone` 0.76 |
| bundle building | 13.2% | 8.8% | `take_bundle` `retain` 8.69, `OutputShards::add` 2.19 |
| libc memmove | 9.9% | 9.0% | |
| changeset scans | 4.0% | 4.6% | `next_row_with_cols` 3.02 |
| QMDB read view | 3.3% | 2.8% | `SharedOffsetIndex::get` 2.04, `::read` 0.91 |
| rayon / epoch | 1.4% | **10.6%** | `Global::try_advance` 6.9% of L1 fills: the global epoch line bouncing between CCDs on every steal |

Headline: 529M DRAM fills and 2.11G L1D demand fills in 6 s over ~27.2M transfers = **19.5 DRAM fills and 78 L1 misses per
transfer; 25% of L1 misses go to DRAM.** That is 88M fills/s x 64 B = 5.6 GB/s: **latency-bound, not bandwidth-bound**. With
1,010 cycles of thread time per DRAM fill, ~19.5 x ~120 ns = 2.3 us of the 5.1 us per transfer is exposed DRAM latency if the
misses do not overlap: roughly 45% of the floor. The misses are dependent probes: a cold recipient walks batch map -> warm
cache -> parent shards -> each in-memory block's filter / bundle -> execution overlay -> (history check) -> QMDB journals ->
offset index -> entry, about eight hash probes deep, each in a different structure. The claim "memory-bound" holds in this
sense; more cores cannot shorten a chain of dependent misses, which is why doubling them did not help.

## 3. Rayon idle and the 4.9 ms imbalance

On-CPU rayon / epoch / lock time is 3.2% (0.4 ms per block); kernel 7% (0.9 ms) is most likely the futex park / wake around
it. The imbalance is **not spinning**: per-block on-CPU time (12.9 ms) equals the CPU floor, so the 4.9 ms between floor and
last batch end is threads asleep after their last batch, invisible to a cycles profile. Without user call chains or a
per-batch tag the profile cannot name the straggler. Two candidates the source shows: (a) each thread's `take_bundle` +
`sink` (1.2 ms CPU, section 1) run after its last batch (`parallel_transfer.rs:4215-4225`), so the thread that claims the last
batch adds them to the tail if the span is closed after them; (b) the changeset scans are bursty (4.9% vs 11.9% between
windows) and fall on cold recipients, so a batch that draws many of them runs long. Unequal per-sender group sizes cannot be
judged from samples; the phase lines' per-batch spans are the instrument for that.

## 4. Hot spots in the source

| # | where | what it costs | why |
| --- | --- | --- | --- |
| 1 | `crates/storage/storage-overlay/src/provider.rs:420-446` -> `crates/storage/provider/src/providers/database/n42_account_history.rs:44-64, 84-92` | 4.9-11.9% of cycles (0.6-1.5 ms) | when the overlay's anchor is below the database tip (`historical_fallback`, `provider.rs:359-383`), every account that reaches the database first asks `account_history_info`; under `N42_ACCOUNT_HISTORY=off` (bench set) that is `n42_first_account_change`, one static-file changeset lookup **per block from the anchor to the tip**, per cold account, before the QMDB reader answers |
| 2 | `crates/n42/engine-types/src/batch_state.rs:251-257` (`basic`), `:70-78` (`loaded`) | 14.0% cycles, 17.6% DRAM | the batch map entry per account; `loaded` builds a `BundleAccount` whose empty `storage` map draws a foldhash seed (`gen_per_hasher_seed` 1.31%) for every one of ~215k accounts |
| 3 | `crates/n42/engine-types/src/output_shards.rs:2088-2096, 635-641` (`FrozenShards::get`), `:3069-3075` (`ShardLayer`), `crates/storage/provider/src/providers/state/memory_overlay.rs:168-` (`overlay_basic_account`) | 18.1% cycles, 28% DRAM | one probe per layer: parent output index then shard map, then each in-memory block's filter and `BundleState::account` |
| 4 | `crates/n42/engine-types/src/batch_state.rs:181-227` (`take_bundle`) | 7.9% cycles, 13% DRAM | a generic `TransitionAccount` per account (clones of info / original), `update_and_create_revert`, a `RevertToSlot` map built from an empty storage iterator; the thread's map walked cold at the end |
| 5 | `crates/n42/tx-types/src/evm.rs:18-37` (`alt_sig_tx_env`), called from the look-ahead at `parallel_transfer.rs:4157` | 2.6% cycles, 7.8% DRAM | first touch of each pooled 0x50 transaction body, plus `input` / `access_list` clones |

The transfer arithmetic itself (`fast_transfer.rs:447-600`, the inlined body of the batch loop at
`parallel_transfer.rs:3967`) is cheap; its 9.8% self share is mostly the stalls of the reads inlined into it.

## 5. Recommendation, ranked by expected ms of the 16

| rank | change | expected | confidence |
| --- | --- | --- | --- |
| 1 | **Skip the per-block changeset scan for the builder's reads.** When `historical_fallback` is set and the QMDB reader is `On`, answer from QMDB at the anchor's version (the read view is versioned through its journals) or re-anchor the overlay at the database tip, instead of `n42_first_account_change` per cold account. First add a counter of fallback reads and scan length per build, to confirm how often it fires. | **0.6-1.5 ms** CPU, and part of the exec-only tail (the bursty blocks) | medium: cost measured in two windows; frequency per block and the reader's version range not checked |
| 2 | Transfer-only `take_bundle`: build the present `BundleAccount` and an `AccountRevert` with empty storage directly (no `TransitionAccount`, no `update_and_create_revert`, no `RevertToSlot` map); give `loaded` a storage map with the fixed hasher (no per-map seed). Byte-equal bundle, testable against the existing `take_bundle` tests. | 0.4-0.7 ms (of 1.2 ms), on the thread's tail | medium-high on cost, medium on saving |
| 3 | One merged address index over the in-memory layers (parent shards + in-memory blocks + execution overlay): one probe instead of one per layer. This is the "index overlay" of ARCHITECTURE_TOWARD_5M rank 1. | 1-1.5 ms | low-medium; weeks of work |
| 4 | Prefetch the transaction body further ahead in the look-ahead (`parallel_transfer.rs:4150-4158`), and drop the empty `input` / `access_list` clones for plain transfers | 0.2-0.3 ms | low |

**No single change is credibly >= 2 ms of the 16.** Ranks 1 and 2 are local, low-risk and together worth 1.0-2.2 ms of the CPU
floor; whether that shortens `par_exec`'s wall time by the same amount depends on the tail (section 3). Anything beyond needs
the layer collapse (rank 3) or fewer cold accounts per transfer, because the floor is a chain of dependent DRAM misses
(~19.5 per transfer), not compute and not bandwidth.

Next measurement: rerun with frame-pointer call graphs (`--call-graph fp` on a build with `-C force-frame-pointers=yes`) or
LBR, so the callers of the hot symbols and the batch / thread-tail split can be read, and add the fallback-read counter of
rank 1.
