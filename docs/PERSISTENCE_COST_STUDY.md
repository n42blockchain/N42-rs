# Persistence cost study: what one `save_blocks` batch spends, and what can be removed or moved

Offline study (2026-10-04): code reading plus python over the metrics dumps that the loop317-loop319
runners saved (`/data/blockchain/rust-fleet3-bench/bench-<tag>/metrics-node0.txt`) and the
`save stages` lines in `scripts/fleet7-runs/results/loop31{7,8,9}.out`. No node was run, no code was
changed. Everything labelled "estimate" is reasoning, not a measurement; section 8 lists the timers
that turn the estimates into numbers.

Why it matters: at the 120 ms cycle persistence beside the chain costs about 0.67 s per 6-block batch
(`docs/BREAKTHROUGH_DESIGN.md` 10.65-10.67). The goal cycle is 109 ms. A persistence thread that is slower
than the chain lets the leader's unpersisted blocks grow until the node collapses (10.66 addendum).

## 1. Summary

1. **The "110 ms a block" figure averages in empty blocks.** In loop317 BASE, 1,959 blocks were persisted
   but only 1,190 carried transactions (`TransactionBlocks` entries; 161,350 transfers and 157,337
   account changesets per such block). Persistence wall is 211 s, so a **full block costs about 178 ms**,
   against a 120-136 ms cycle: during the flood persistence is about 1.3-1.5x too slow, not "barely
   keeping up". The leg survives only because the flood is bounded and empty blocks are nearly free.
2. **One step is the critical path: the RocksDB account-history index** (`write_account_history`,
   about 119 of 178 ms per full block). Everything in static files (about 70 ms) runs beside it and is
   hidden. Storage history is empty on a transfer chain; transaction lookup is already skipped by
   `--prune.transaction-lookup.full`; MDBX, hashed state and trie writes cost under 1 ms a batch.
3. **The superlinear part is not RocksDB or static files** (both grow 2.6-2.9x for 2.1x the blocks): it
   is the residual between `save_blocks_total` and the slower of the two backends. It is 19 ms per full
   block at 6-block batches and 82 ms per full block at 14-block batches (4.3x for 2.1x). The residual is
   code that runs serially outside the parallel scope: the per-block QMDB `on_state_persisted` (forest
   lock, entry-file flush, 157k-key read-view advance) and, before the scope, the `to_plain_state_reverts`
   conversion on the global rayon pool. Which of the two grows is not separable from existing metrics.
4. **No existing switch removes a step.** `--prune.account-history.full` does not skip the write in this
   tree (the RocksDB writer does not consult it); `N42_ROCKSDB_NOSYNC=1` was measured and changes nothing;
   `N42_HASHED_TABLES=off` and `N42_STORAGE_OP_METRICS=0` are already on in every fleet runner. The
   switches that can still be tried are a bigger RocksDB block cache, a bigger WAL cap, direct I/O and
   `--prune.sender-recovery.full` (section 5). The large effects need code (section 6).

## 2. Where the numbers come from, and two traps

* `reth_storage_providers_database_save_blocks_*` histograms: `_sum` is seconds summed over the leg for
  node 0, `_count` is batches (the `commit_*` ones are counted per provider commit, which also includes
  the pruner's commits, hence 485 against 304). `reth_consensus_engine_beacon_persistence_duration` is the
  whole persistence cycle of one batch (`on_save_blocks`: provider, `save_blocks`, `commit`, BAL flush).
* **Do not read the `quantile=` lines of these metrics.** They come from a time-windowed summary: in the
  loop317 BASE dump `commit_rocksdb` has max 3.8 ms while its sum is 33 s over 485 commits. They show the
  idle tail only. Only the `_sum` and `_count` lines are usable, so no per-batch distribution exists.
* `reth_static_files_jar_provider_write_duration_seconds_sum{segment="storage-change-sets"}` is `inf`
  and the per-segment operation histograms are zero under `N42_STORAGE_OP_METRICS=0`: there is **no
  per-segment static-file time and no per-column-family RocksDB time** in any dump. The split of the
  RocksDB 119 ms between map building, point reads and batch building below is therefore not measured.
* loop319's node-0 dump has near-empty database gauges (10 transaction blocks), so per-full-block figures
  use loop317 and loop318 (1,190 and 1,192 full blocks). loop319's `save stages` sums are consistent
  with loop317's (1,906 blocks, 211.7 s) and are used only for batch totals.

## 3. The work of one batch, step by step

Configuration of every fleet leg (`scripts/fleet7-env.sh`, `run-loop317/318/319.sh`): storage v2 (the
default: `--storage.v2` true, `crates/node/core/src/node_config.rs`), `--prune.transaction-lookup.full`,
`N42_HASHED_TABLES=off`, `N42_QMDB_READS=on`, `N42_STORAGE_OP_METRICS=0`, `--db.rocksdb-block-cache-size
64MB`, `--engine.persistence-threshold 8`, `--engine.memory-block-buffer-target 6`, masking blocks 0,
`--engine.persistence-backpressure-threshold 1024`. The persistence thread runs
`PersistenceService::on_save_blocks` (reth-engine-tree `persistence.rs`), which calls
`DatabaseProvider::save_blocks` (`crates/storage/provider/src/providers/database/provider.rs`
`save_blocks_inner`) and then `provider_rw.commit()`.

Per-batch means are loop317 BASE (304 batches, 6.44 blocks, 695 ms). Per-full-block means divide the
leg's sums by its 1,190 full blocks. BASEb, WARM and loop318 BASE/BASEb agree within 4%.

| # | Step (code) | Where it lands | Volume per full block | Runs | ms / batch | ms / full block |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `tx_nums` (last `TransactionBlocks` key), `plain_reverts` = `to_plain_state_reverts()` for each block (`par_iter`, **global rayon pool**) | memory | 157k account reverts | before the scope; parallel across blocks | part of 75 | part of 19 |
| 1a | `write_account_history` (`rocksdb/provider.rs`): build a `BTreeMap<Address, Vec<u64>>` from the reverts (serial), `par_iter` one point `get` of each address's last shard plus `append` (storage pool, 16 threads), then push every shard into one `WriteBatch` (serial) | RocksDB CF `AccountsHistory` (key address + u64, value roaring list of block numbers, shards of up to 2,000 numbers) | about 157k keys read and 157k written (about 0.9-1.0M a batch; 2.0-3.3M distinct keys in the table, 411-896 MB, memtables 350-414 MB, SSTs 197-548 MB) | parallel with 1b and 2; **critical path** | **465** (RocksDB task total) | **119** |
| 1b | `write_storage_history` | CF `StoragesHistory` | 0 on transfers (5,876 entries in the whole leg) | with 1a | about 0 | about 0 |
| 1c | `write_tx_hash_numbers` | CF `TransactionHashNumbers` | **skipped**: `prune_tx_lookup` is `Full` (`rocksdb/provider.rs` `write_tx_hash`) | - | 0 | 0 |
| 2 | `StaticFileProvider::write_blocks_data`: one task per segment on the storage pool, each ends in `sync_all()` | static files | see 2a-2f | parallel segments, slowest sets the time | **272** (hidden under 1a) | **69-73** |
| 2a | `Transactions` segment (`append_transaction` per transaction) | `static_files/transactions` | 161k rows, 203 B each = 32.8 MB (38.97 GB per 192.0M rows) | | | largest segment by bytes |
| 2b | `TransactionSenders` | `transaction-senders` | 161k x 28 B = 4.5 MB | | | |
| 2c | `Receipts` | `receipts` | 161k x 15 B = 2.4 MB | | | |
| 2d | `AccountChangeSets` (sort by address, `append_change` per entry) | `account-change-sets` | 157k entries x 31 B = 4.9 MB | | | |
| 2e | `StorageChangeSets` | `storage-change-sets` | about 0 | | | |
| 2f | `Headers` | `headers` | 1 header, 0.45 KB | | | |
| 3 | MDBX in the scope: `insert_block_mdbx_only` (`HeaderNumbers`, `BlockBodyIndices`, `TransactionBlocks`, `BlockWithdrawals`), `write_state` (writes nothing: receipts and changesets go to static files), `update_pipeline_stages`, `Finish` checkpoint | MDBX | a few rows | serial, in the scope | 0.4 (`save_blocks_mdbx` 0.12 s per leg) | 0.1 |
| 4 | Hashed state and trie updates | skipped by `N42_HASHED_TABLES=off` (`write_hashed_state`); `write_trie_updates_sorted` of an empty merge | 0 | - | under 0.01 | 0 |
| 5 | `update_history_indices` | no-op on v2 (it only runs the v1 MDBX path) | 0 | - | 0.001 | 0 |
| 6 | `n42_state::registered().on_state_persisted` (`node_state.rs` `on_persisted`): per block `with_forest` lock, `flush_entries_for_sync`, `block_changes`, `raise_floor`, `QmdbReadView::advance` (157k-key `index.get` in parallel, `apply_sorted` on the view index), `note_reader_lag` | QMDB read view (memory plus the entry file's tail flush) | 157k keys a block | **serial, after the scope joins**, inside `save_blocks_total` but in neither the `rocksdb` nor `sf` timer | part of 75 | part of 19 |
| 7 | `provider_rw.commit()`: `static_file_provider.finalize()`, `rocksdb.commit_batches` (every pending batch written in order, the last with a WAL sync), MDBX `commit` | all three stores | WAL write plus memtable insert of step 1a's batch | serial, after step 6 | **147** (RocksDB 110, SF 34, MDBX 3) | **38** (RocksDB 28, SF 9, MDBX 1) |
| 8 | BAL store flush, pending finalized/safe numbers | small | - | serial | about 8 | about 2 |

Not on this thread (so not in the 0.67 s): the QMDB tree's own durability (entry file, `forest.ckpt`), the
pruner (`prune_before` 180 runs, 0.41 s a leg; `TransactionLookup` segment 0.11 s a leg).

### Reconciliation (loop317 BASE, per batch of 6.44 blocks)

| Quantity | ms |
| --- | --- |
| RocksDB task (1a-1c), the longer of the two backends | 465 |
| static-file tasks (2), shorter, hidden | 272 |
| `save_blocks_total` | 540 |
| residual `total - max(rocksdb, sf)` (steps 0, 3, 6 and scope join) | **75** |
| `commit` (RocksDB 110 + static files 34 + MDBX 3) | 147 |
| left over (step 8, `tx_nums`, checkpoints) = persistence cycle 695 - 540 - 147 | 8 |
| **persistence cycle** | **695** |

So 67% of the batch is the RocksDB task, 11% is the residual, 21% is the commit (three quarters of
which is the RocksDB write of the same batch), and the static files, at 39% of the cycle, add nothing
as long as RocksDB is slower. Seen per full block: 178 ms = 119 (RocksDB) + 19 (residual) + 38 (commit) +
2. Removing the account-history step entirely would expose the static files: about 70 + 19 + 9 + 1 + 2 =
**about 100 ms** per full block (estimate for the sum; each term is a measurement above).

What is unaccounted for: the 75 ms residual is two code regions with no timer (steps 0 and 6), and the
119 ms RocksDB task is three phases with no timer (map build, parallel reads, batch build). Estimates
from the loop314 profile and from operation counts, not measurements: about 1.0M BTreeMap inserts of a
20-byte key (serial, hundreds of ms in total is possible), about 0.9M point reads on 16 threads, about
0.9M serial `WriteBatch` puts with key and roaring-value encoding. The profile (`BREAKTHROUGH_DESIGN.md`
section on loop314) puts `write_account_history` at 5.6% of the `storage-*` family's samples and
`rocksdb::BlockBasedTable::Get` at 1.9%: the serial user-space part of the function is larger than the
read cost.

## 4. Why batch cost is superlinear (the P32 leg)

All figures per leg, `batch_size` mean in brackets.

| Leg | Batch (blocks) | Cycle ms | RocksDB | SF | Residual | Commit RocksDB | Commit SF | Residual per full block |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| loop317 BASE | 6.4 | 695 | 465 | 272 | 75 | 110 | 34 | 19 ms |
| loop317 P32 | 13.7 | 2,491 | 1,219 | 787 | **863** | 293 | 79 | **82 ms** |
| ratio P32 / BASE | 2.1x | 3.6x | 2.6x | 2.9x | **11.5x** | 2.7x | 2.3x | 4.3x |

The blocks per batch more than double (13.7 against 6.4) while the residual grows 11.5x per batch. The
backends grow mildly superlinear (RocksDB 2.6x, SF 2.9x). Reading the code, the residual is the sum
of steps 0 and 6:

* Step 6 does one `with_forest` lock acquisition, one entry-file flush and one 157k-key view advance
  **per block**, serially, and the forest lock is the lock the chain's own root computation and block
  import take. A 14-block batch holds the persistence thread through 14 lock hand-offs against a chain
  that is building and importing at 8 blocks a second, so the wait for the lock, not the work under it,
  can grow with the batch. `on_persisted` also pins the read view's journals for the whole batch
  (`hold_journals_from`), so a batch larger than `JOURNAL_DEPTH` (64) never trims.
* Step 0's `par_iter` runs on the global rayon pool, which at the bench (`RAYON_NUM_THREADS=16`, the build
  pool) is busy with block building; 14 conversions of 157k reverts wait behind it.

Both are consistent with the data; the data cannot tell them apart (section 8, timer 1). The RocksDB
side adds a second mechanism worth testing: `DEFAULT_MAX_TOTAL_WAL_SIZE` is 256 MiB, and one 14-block
batch writes more WAL than that (estimate: 0.9M keys x about 150-300 B a block-batch, 6.4 blocks to 14
blocks = 150-300 MB to 330-650 MB), so large batches force a flush of the 128 MB memtable and can stall
the writer; the commit grows 2.7x for 2.1x the blocks, which fits.

Other legs agree on the direction: loop318 COMPACT (8.6 blocks per batch, a lagging leader) has a
residual of 51 ms per block (BASE 11-13), loop319 COMPACT (7.9 blocks) 38 ms, CBP32 and CBP16 (backpressure
holding the count) 10-11 ms. The residual is small when batches stay near 4-6 blocks and large when
the lag makes them 8-14, which is also when the node is in trouble: **the residual is what turns a
lagging persistence thread into a collapsing one**, because lag makes batches bigger and bigger batches
make the thread slower per block.

## 5. Who reads what each step writes, and what skipping it breaks

| Step / data | Read by | If skipped or deferred | Rollback / recovery implication |
| --- | --- | --- | --- |
| `AccountsHistory` (RocksDB) | `HistoricalStateProvider` (`eth_getBalance`, `eth_getCode`, `eth_getTransactionCount`, `eth_getStorageAt`, `eth_call`, `eth_getProof`, tracing at a block older than the in-memory chain): `account_history_info` seeks `(address, block)` and answers "changed at block X, read X's changeset" or "unchanged, read latest" | **Wrong answers, not errors, if it merely lags**: an address changed in a block above the indexed tip is reported unchanged and the latest value is returned. A deferred index therefore needs a `visible_tip` (the index checkpoint) and, above it, a fallback that scans the account changesets from the tip back to the block. Within `JOURNAL_DEPTH` (64) blocks of the head the QMDB view's journals answer first (`read_view.rs`; how far the historical hook goes is not verified here) | Unwind: `unwind_account_history_indices` reads the changesets; with no index above the checkpoint there is nothing to unwind. Restart: `heal_accounts_history` compares the `IndexAccountHistory` checkpoint with the account-changeset static-file tip and **unwinds** entries above the checkpoint; it does not rebuild missing ones. A deferred indexer must own that checkpoint and `update_pipeline_stages` must stop advancing it for the batch, or the healer would believe the index complete |
| `StoragesHistory` | same, for slots | nothing on a transfer chain; on a contract chain the same fallback applies | same, `heal_storages_history` |
| `TransactionHashNumbers` | `eth_getTransactionByHash`, `eth_getTransactionReceipt`, logs by tx, `debug_*` by hash | **already off in every fleet leg** (`--prune.transaction-lookup.full`): by-hash lookups of persisted transactions return nothing on the bench fleet. A node that keeps the capability pays 161k puts a block (estimate 30-50 ms, not measured) on the same path | `heal_transaction_hash_numbers` rebuilds from the transactions segment in batches, so a deferred build from static files is already a supported recovery shape |
| `Transactions` segment | `bodies_by_range` serving (with headers, withdrawals), RPC block and transaction bodies, `eth_getLogs` receipts join, reorg re-execution, the sender recovery fallback | cannot be skipped: the only copy of the bodies | `take_block_and_execution_above` reads them |
| `TransactionSenders` | RPC convenience (`from`), re-execution, pool re-injection after a reorg | skippable with `--prune.sender-recovery.full` (`static_file_write_ctx`: `write_senders` false): senders are recoverable from the signature (secp256k1) or the Ed25519 public key (0x50, `N42TxEnvelope`); costs a recovery per read | none |
| `Receipts` | `eth_getTransactionReceipt`, `eth_getLogs`, receipts root re-checks | cannot be skipped (a prune mode only applies while no receipts exist in static files, `receipts_prunable`) | needed by unwind of receipts-dependent consumers |
| `AccountChangeSets` / `StorageChangeSets` | **rollback source** (`take_state_above`), the history index builder and its healer, the historical read (value before the change) | must stay (owner rule); they are also the source a deferred history index would be built from, in sequential sorted form | the whole point |
| `Headers` | everything | cannot be skipped | |
| MDBX `BlockBodyIndices`, `TransactionBlocks`, `HeaderNumbers`, `BlockWithdrawals`, stage checkpoints | block lookup, body assembly, withdrawals (the block reward is paid as withdrawals), `Finish` checkpoint is the persistence frontier checked at the start of every `save_blocks` | cannot be skipped; 0.4 ms a batch | |
| Hashed state / trie tables | the latest-state reader when QMDB reads are off | off already (`N42_HASHED_TABLES=off`, requires `N42_QMDB_READS=on` and a registered reader, `check_hashed_tables_setting`) | QMDB is the state; restart recovery comes from its own checkpoint |
| `on_state_persisted` (QMDB view advance) | the QMDB read view the database's readers use (state reads at the persisted block, `N42_QMDB_READS=on`) | the view must be advanced before the batch's commit, or database readers at the old version are answered by a view that has moved or not at all (the `hold_journals_from` comment records the loop279 rejection of valid blocks). It does not depend on the scope's output, so it can run **during** the scope instead of after it | `on_state_unwound` steps the view back through its journals |

Sync serving to peers (`bodies_by_range`) reads the transactions, headers and withdrawals above, and the
unpersisted tail from memory; it does not touch either history index. The pruner is not enabled beyond
the transaction-lookup segment.

## 6. Existing switches

| Switch | Where read | What it does to a batch | Used today | Verdict |
| --- | --- | --- | --- | --- |
| `--prune.transaction-lookup.full` | `rocksdb/provider.rs` `write_blocks_data` (`write_tx_hash`), `database/provider.rs` v1 path | skips step 1c and the MDBX path | **yes**, in every loop316-319 leg through `F7_EL_EXTRA` (not in `fleet7-env.sh` itself; a leg that omits it would pay step 1c) | already taken; the capability is off on the bench |
| `--prune.sender-recovery.full` | `static_file_write_ctx` (`write_senders`) | skips segment 2b (about 10% of static-file bytes) | no | testable, hidden today under step 1a |
| `--prune.account-history.full`, `--prune.storage-history.full` | pruner only | **does not skip the write** in this tree: `write_account_history = storage_v2` is unconditional (`rocksdb/provider.rs`); the setting only adds pruner deletes later | no | not a lever; would add work |
| `--prune.receipts.*` | `static_file_write_ctx.receipts_prunable` | only while no receipts exist in static files | no | not a lever |
| `N42_HASHED_TABLES=off` | `crates/storage/storage-api/src/n42_state.rs` `hashed_tables_off()`, `database/provider.rs` | skips step 4 | **yes** (`D=` line) | taken |
| `N42_STORAGE_OP_METRICS=0` | `providers/op_metrics.rs` `enabled()` | no per-operation histogram on 157k gets and puts a block and 500k static-file appends | **yes** (6 occurrences in `run-loop319.sh`; the RocksDB operation histograms are zero in the dumps) | taken |
| `N42_ROCKSDB_NOSYNC=1` | `rocksdb/provider.rs` `rocksdb_nosync()` (`commit_batches`) | leaves the WAL write unsynced | loop317 NOSYNC leg only | **measured no effect** (cycle 659 against 672-695; `commit_rocksdb` 88 against 110 ms a batch, but the cycle did not move), so the commit is the write into WAL and memtable, not the fsync |
| `N42_ROCKSDB_WRITE_BUFFER_MB` | `write_buffer_manager_size()`, default 4096 | the memtable budget; lowers memory, not time (the per-CF buffer is a constant 128 MB) | no | not a speed lever |
| `N42_ROCKSDB_MAX_WAL_MB` | `max_total_wal_size()`, default 256 | WAL cap; below one batch's WAL it forces memtable flushes inside the write | no | **test**: 1024 |
| `N42_ROCKSDB_DIRECT_IO=1` | `rocksdb_direct_io()` | flush and compaction bypass the page cache | no | test; aimed at page-cache pressure, not at the writer |
| `--db.rocksdb-block-cache-size` | `fleet7-env.sh` line 446, hard-coded `64MB` (reth default 128) | block cache of the 16 KB-block, LZ4 `AccountsHistory` SSTs (197-548 MB) read by 157k gets a block | **64 MB** | **test**: 1-2 GB; needs a script edit (an `F7_ROCKSDB_CACHE` variable) because the argument is not overridable through `F7_EL_EXTRA` |
| `--engine.persistence-threshold` / `--engine.memory-block-buffer-target` (`F7_PERSIST_THRESHOLD`, `F7_BLOCK_BUFFER_TARGET`) | `fleet7-env.sh` 538-539 | batch size; threshold 32 measured **worse** (section 4) | 8 and 6 | smaller batches (4-6) bound the residual but add a per-batch fixed cost of about 37 ms (commit SF 34 + MDBX 3), so the useful range is 5-8; no gain expected |
| `--engine.persistence-backpressure-threshold` (`F7_PERSIST_BACKPRESSURE`) | `fleet7-env.sh` 546 | stalls the engine loop, not persistence | 1024 | measured in loop319: holds the count, costs 3-18% of window 1 |
| `--engine.suppress-persistence-during-build` | `fleet7-env.sh` 503 | delays persistence | no | measured 3% lower (`NATIVE_FLEET7.md`) |
| storage pool size | `DEFAULT_STORAGE_POOL_THREADS` = 16 in reth-tasks | the threads steps 1a and 2 share (up to 6 static-file tasks occupy threads that block in `sync_all`) | default | no flag found in this tree |

`scripts/fleet3-env.sh` is not a separate launcher for this: the fleet runners source `fleet7-env.sh`
with `F7_NODES=3` and the `fleet3-bench` root, so the arguments above are the whole set.

## 7. Ranked plan

### (a) Today, existing switches only (one leg each, against BASE and BASEb)

Setup common to all: the loop319 COMPACT configuration (the 3-node `run-loop319.sh` `$C $R $D $A2` line)
and read `save stages` plus `memsample.py` (`in_mem_state_num_blocks`).

1. **`N42_ROCKSDB_MAX_WAL_MB=1024`**. Hypothesis: the 256 MiB cap forces memtable flushes inside the batch
   write. Prediction (estimate): commit RocksDB falls from 110 to under 80 ms a batch if true, unchanged if
   false. Cheapest test, no risk.
2. **Block cache 1 GB** (edit `fleet7-env.sh` line 446 to `${F7_ROCKSDB_CACHE:-64MB}` and pass
   `F7_ROCKSDB_CACHE=1GB`; seven nodes x 1 GB is 7 GB of RAM against the memory pressure notes). Hypothesis:
   the point reads are SST-miss bound. Prediction (estimate): 0-30 ms off the 119 ms; nothing if the reads hit
   memtables (the memtables hold 350-414 MB against 197-548 MB of SST, so many do).
3. **`F7_EL_EXTRA="... --prune.sender-recovery.full"`**. Expected effect on the cycle today: about zero
   (static files are hidden); run it paired with a leg that removes RocksDB (b1) to see the exposed floor.
4. **`N42_ROCKSDB_DIRECT_IO=1`** combined with 1: only if the page-cache storm notes (`thp-heap-reclaim`) show
   a link; low priority.
5. A control leg at `F7_PERSIST_THRESHOLD=6 F7_BLOCK_BUFFER_TARGET=4` to place the batch-size optimum
   (expected flat).

Nothing here removes the 119 ms step; at best 1 and 2 remove a quarter of it. The real levers are code.

### (b) Smallest code changes, ranked by saving per block (estimates; every item keeps the capability)

| Rank | Change | Saving per full block (estimate) | Risk | What it costs in section 5 terms |
| --- | --- | --- | --- | --- |
| 1 | **Account-history index as a mode: `off` / `deferred`.** `write_blocks_data` skips `write_account_history` (and `update_pipeline_stages` leaves `IndexAccountHistory` at the indexed height). A background job reads `AccountChangeSets` from static files every N blocks and builds the index in a sorted bulk pass: sort `(address, block)` for the whole range, write finished shards keyed by `(address, highest_block_in_range)` with `SstFileWriter` and `ingest_external_file` (no memtable, no WAL, no per-address point read; reth's shard keys already allow several shards an address). `HistoricalStateProvider` gets `visible_tip` = the index checkpoint and a changeset-scan fallback above it. | **about 78 ms** (178 to about 100: RocksDB 119 and commit-RocksDB 28 leave the critical path, exposing static files 70 + 19 + 10); the job's CPU (estimate 20-40 ms of one core a block) moves off the persistence thread | medium: the fallback must be exact (a lagging index answers wrongly, section 5); the healer must be taught that a checkpoint behind the changeset tip is a deferred index, not damage | historical reads above the indexed tip are slower (a scan of at most N blocks of sorted changesets) until the job catches up; by default `deferred` with N about 64 keeps every historical read exact |
| 2 | **Run `on_state_persisted` inside the scope** (beside the RocksDB and static-file tasks) instead of after the join. It needs only the block list, and its contract is "before the commit". Together with timers 1-2 in section 8 split `plain_reverts` out of it. | up to 19 ms (the residual hides under the 119 ms RocksDB task, or under the 70 ms of static files after rank 1); the 82 ms of P32 batches the same way | low: same ordering against the commit; the forest lock is already taken inside `on_persisted` | none |
| 3 | **Add the timers of section 8** (spans in `save_blocks_inner` around steps 0, 1a's three phases, 6 per block, and the per-segment static-file task) | 0, but turns every estimate here into a number; do this before ranks 1-2 are sized | none | none |
| 4 | Cheaper in-place account history if rank 1 is not taken: build the per-address list with parallel per-block vectors and a `par_sort_unstable` of `(address, block)` instead of a serial `BTreeMap`, build the `WriteBatch` per chunk in parallel and push the chunks as separate pending batches, turn on memtable whole-key filtering (`memtable_whole_key_filtering` with `memtable_prefix_bloom_ratio`) for `AccountsHistory` so a point read does not probe every memtable | 30-50 ms (serial map and batch building) plus 10-20 ms (memtable probes); both are guesses until the timers exist | low-medium: the data written is byte-identical, only the building changes | none |
| 5 | **Transaction lookup, if the capability is turned back on**, as a deferred build from the `Transactions` segment (the existing `heal_transaction_hash_numbers` shape: ranges, batches) instead of 161k puts on the critical path | avoids an estimated 30-50 ms that is not in today's numbers | low | by-hash lookups wait for the job |
| 6 | Static files after rank 1 becomes the floor (70 ms for 44.6 MB, 640 MB/s with six fsyncs): `--prune.sender-recovery.full` (-4.5 MB), one combined sync in `finalize()` instead of a `sync_all` per segment task plus `finalize` (the code syncs in `write_segment` and then again in `finalize`), compressing or trimming the 203-byte transaction row | 5-15 ms | medium: the SF-versus-checkpoint recovery assumes fsynced segments | senders recomputed on read |
| 7 | Commit once per two batches or write the RocksDB batches from the scope into the memtable directly (skip the second serial pass of the same bytes) | up to 28 ms of commit-RocksDB after rank 4 | medium: crash window | none |

Expected end state if ranks 1 and 2 are done: about 90 ms per full block (static files 70 + commit 10 + MDBX
1 + residual hidden), i.e. persistence about 1.3x faster than the 109 ms goal cycle on its own critical
path, with the residual no longer growing with the batch. Rank 1 alone gets 178 to about 100 ms, below the
120-136 ms cycle but not below 109 ms with margin.

## 8. What this study could not measure (do these first)

Offline data has no per-phase time inside the 465 ms RocksDB task, the 75 ms residual or the 272 ms of
static files. Four spans, each a few lines, would settle sections 3 and 4 in one WARM leg:

1. In `save_blocks_inner`: the `plain_reverts` conversion, and each block's `on_persisted` (lock wait, flush,
   `advance` separately): separates the two candidates for the superlinear residual.
2. In `write_account_history`: map build, parallel reads, batch build (three `Instant` pairs).
3. In `write_blocks_data` (static files): the elapsed time of each segment task including its `sync_all`
   (the existing per-segment histograms are zeroed by `N42_STORAGE_OP_METRICS=0` and the changeset one is
   `inf`).
4. RocksDB's own statistics at the end of a leg: `rocksdb.stall.micros`, WAL bytes written and the flush
   count, to confirm or refute the WAL-cap stall in section 4.

A bench-only environment switch that makes `write_account_history` return immediately would give the exact
upper bound of rank 1 in one leg (history reads are wrong in that leg; the QMDB chain does not read history
during the flood), and a second leg with `--prune.sender-recovery.full` on top gives the static-file floor.

## 9. Implementation (2026-10-04): what the code reading confirmed or corrected

Items 2, 3 and the measuring half of item 1 of section 7(b) are in the tree
(`crates/storage/provider/src/providers/n42_persist.rs`, `database/n42_account_history.rs`,
tests in `database/n42_persist_tests.rs`). No fleet leg has run them yet; the numbers above are still
the estimates they were.

### Timers (section 8 items 1-3)

All are histograms in reth's `storage.providers.database` scope with a `save_blocks_` prefix, so the
runners' `save stages` regex picks them up (`_sum` seconds over the leg, `_count` batches). The dump
prints only the ten largest sums; read `metrics-node0.txt` for the rest.

| Metric (`reth_storage_providers_database_...`) | What it times |
| --- | --- |
| `save_blocks_pre_scope` | `save_blocks_inner` start to the scope: `tx_nums`, write contexts, the reverts conversion (step 0) |
| `save_blocks_plain_reverts` | the `to_plain_state_reverts` `par_iter` alone (part of `pre_scope`) |
| `save_blocks_scope` | the parallel scope from start to join (steps 1-5, includes the QMDB advance when in scope) |
| `save_blocks_post_scope` | scope join to the end of `save_blocks` (step 6 when not in scope) |
| `save_blocks_qmdb_persisted` | `on_state_persisted` for the batch, wherever it runs |
| `save_blocks_account_history_{map,reads,batch}` | the three phases of `write_account_history` (step 1a) |
| `save_blocks_sf_{headers,transactions,senders,receipts,account_changesets,storage_changesets}` | each static-file segment task including its `sync_all` (step 2a-2f) |

The per-backend commit (step 7) was already timed (`save_blocks_commit_{sf,rocksdb,mdbx}`), so nothing
was added there. RocksDB's own statistics (section 8 item 4) are not wired.

### `N42_PERSIST_QMDB_IN_SCOPE=1` (item 2): confirmed, with one correction

* Confirmed: `QmdbNodeState::on_persisted` reads only the block list, the forest (under its lock) and the
  read view; it never touches the database transaction, so its only ordering constraint is "before the
  commit". It now runs on its own named thread (`persist-qmdb`), started before the scope and joined after
  it (`run_with_qmdb_persisted`). A plain thread rather than a storage-pool task: `QmdbReadView::advance`
  uses `par_iter`, which inside a storage-pool worker would run on the storage pool beside the RocksDB
  task instead of on the global pool as today.
* Correction: the study described step 6 as running "after the scope joins" as if only a successful batch
  advanced the view. In the code it runs after the MDBX closure succeeded but **before** the static-file
  and RocksDB results are collected, so a failed backend task already leaves the view advanced. In scope,
  an MDBX failure does too. A failed batch is fatal to persistence either way.
* Default off. Switch-off equivalence is tested at the database level (identical rows, changesets,
  checkpoints, latest state) and at the call level (one call, same blocks, before return).

### `N42_ACCOUNT_HISTORY=off` (item 1, the measuring half)

Default `on` is today's code path byte for byte (the write flag is true, no marker is ever written). With
`off` a storage-v2 batch skips only the `AccountsHistory` task; the static-file `AccountChangeSets` task is
untouched. Corrections to section 5:

* **The marker cannot be the frozen `IndexAccountHistory` checkpoint.** `check_pipeline_consistency`
  (`crates/node/builder/src/launch/common.rs`) compares every stage checkpoint with the first stage's at
  launch and runs the pipeline to the tip if any is behind, which would rebuild the index over the gap
  on every restart. So the checkpoint advances as before and the gap is a separate row:
  `StageCheckpoints["N42AccountHistoryGap"]` = the first block whose index entries are missing, written in
  the batch's own MDBX transaction (it is visible in `reth db stage-checkpoints`). It stays until an
  unwind goes below it (`update_pipeline_stages_after_unwind`); turning the mode back `on` does not close
  it (the index above the gap is incomplete), only a future indexer or that unwind does.
* **One choke point for historical account reads.** Every history lookup goes through
  `DatabaseProvider::account_history_info` (`HistoryReader`); `storage-overlay`'s historical fallback and
  `get_account_before_block` resolve its answer. The RocksDB lookup already takes a `visible_tip`. With a
  gap `g` at or below the tip: a read at `b < g` asks the index with the tip lowered to `g - 1`;
  `InChangeset` and `NotYetWritten` are final (the index is complete below `g`; an account with no entry
  before `g` did not exist at `b`), `InPlainState`/`MaybeInPlainState` are settled by the first changeset
  for the address in `g..=tip`. A read at `b >= g` scans `b..=tip`: the first changeset found holds the
  value, none means the latest value. Each block costs one segment lookup and a binary search of that
  block's address-sorted changeset (about 17 reads at 157k entries). A scan that finds nothing within
  `N42_ACCOUNT_HISTORY_SCAN_MAX` blocks (default 100,000) returns an error naming the mode. Reads are
  therefore exact or an error, never wrong; they get slower as the gap grows.
* **Healer.** With the checkpoint advancing, a normal restart has `checkpoint == sf_tip` and heals
  nothing. In the crash shape (static files and RocksDB committed, MDBX not) `heal_accounts_history`
  would unwind index entries for every address in the changesets above the checkpoint; with a marker at
  or below `checkpoint + 1` it now returns without touching anything (entries there are not trusted by
  reads anyway), and never returns an unwind target for it.
* **Paths that do not depend on the index**, checked in the code: latest-state reads (QMDB reader at the
  `Finish` version, or the hashed tables) never consult history; the QMDB reader is unaffected;
  `remove_state_above` rolls state back from the changesets alone; the index unwind in
  `unwind_trie_state_from` finds nothing to remove inside the gap; the pruner is not enabled for account
  history.
* **Storage history left on.** `write_storage_history` has the same shape but is near zero on transfer
  blocks (5,876 entries a leg); putting it under the mode needs a second marker plus the same fallback in
  `storage_history_info` and `heal_storages_history`, which is not trivial enough for this step.

### Design note: the deferred indexer (not built)

A background job owns the gap: it reads `AccountChangeSets` for `g..=min(tip, g + N - 1)` from static files,
sorts `(address, block)`, appends each address's blocks to its last shard (the same shard keys as today,
so a read path change is not needed), commits the RocksDB batch, then advances the marker to the next
unindexed block in one MDBX transaction (deleting it when it reaches the tip with the mode `on`). Because
reads trust only blocks below the marker, the job may run at any pace and crash at any point: a batch
written but not recorded is overwritten by the next pass. Large passes can use `SstFileWriter` plus
`ingest_external_file` instead of the memtable. With the mode `off` and the job keeping `N` near 64, every
historical read stays a short scan.

### Fleet legs (one each, against a BASE with the same binary)

The timers need no switch. Append to the leg's environment line (the EL inherits it, like the `D=`
variables):

1. BASE: nothing (timers only).
2. `N42_PERSIST_QMDB_IN_SCOPE=1`: expect `save_blocks_qmdb_persisted` unchanged and `save_blocks_post_scope`
   to fall by it.
3. `N42_ACCOUNT_HISTORY=off`: the exact upper bound of rank 1; expect `save_blocks_rocksdb` and
   `save_blocks_commit_rocksdb` near zero and the static files exposed.
4. Both together, optionally with `--prune.sender-recovery.full` in `F7_EL_EXTRA` for the static-file
   floor.
