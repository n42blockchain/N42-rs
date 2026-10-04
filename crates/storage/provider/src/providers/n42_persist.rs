//! N42: persistence-cycle timers and switches (`docs/PERSISTENCE_COST_STUDY.md`).
//!
//! * Timers for the phases of one `save_blocks` batch that reth's own metrics leave untimed: the
//!   work before the parallel scope (and the plain-state reverts conversion inside it), the scope
//!   itself, the work after it, the QMDB read view's `on_state_persisted`, the three phases of the
//!   `RocksDB` account-history write and each static-file segment task. They share reth's
//!   `storage.providers.database` scope and a `save_blocks_` prefix, so they land beside the
//!   existing `save_blocks_*` histograms (`_sum` / `_count`) in a metrics dump.
//! * `N42_PERSIST_QMDB_IN_SCOPE=1` runs `on_state_persisted` beside the backend writes instead of
//!   after them (default off).
//! * `N42_ACCOUNT_HISTORY=on|off` (default `on`): with `off` a storage-v2 batch skips the
//!   `AccountsHistory` index write. Account changesets are written as before. The first skipped
//!   block is recorded durably as the account-history gap (see [`ACCOUNT_HISTORY_GAP_KEY`]);
//!   historical account reads at or above it answer from the changesets instead of the index.

use metrics::Histogram;
use reth_metrics::Metrics;
use reth_static_file_types::StaticFileSegment;
use alloy_eips::BlockNumHash;
use alloy_primitives::BlockNumber;
use reth_storage_api::n42_state::N42StateReader;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::{cell::Cell, sync::OnceLock, time::Duration};

/// Timers of one persistence batch that reth's `DatabaseProviderMetrics` does not have.
#[derive(Metrics)]
#[metrics(scope = "storage.providers.database")]
pub(crate) struct N42PersistMetrics {
    /// Everything in `save_blocks` before the parallel scope (`tx_nums`, write contexts, the
    /// plain-state reverts conversion).
    pub(crate) save_blocks_pre_scope: Histogram,
    /// The plain-state reverts conversion (`to_plain_state_reverts` per block, global rayon pool).
    pub(crate) save_blocks_plain_reverts: Histogram,
    /// The parallel scope (static files, `RocksDB` and MDBX writes) from start to join.
    pub(crate) save_blocks_scope: Histogram,
    /// Everything in `save_blocks` after the scope joined (includes `on_state_persisted` unless
    /// `N42_PERSIST_QMDB_IN_SCOPE=1`).
    pub(crate) save_blocks_post_scope: Histogram,
    /// The QMDB read view's `on_state_persisted` for the batch, wherever it runs.
    pub(crate) save_blocks_qmdb_persisted: Histogram,
    /// `write_account_history`: building the per-address block lists from the reverts.
    pub(crate) save_blocks_account_history_map: Histogram,
    /// `write_account_history`: reading and extending each address's last shard.
    pub(crate) save_blocks_account_history_reads: Histogram,
    /// `write_account_history`: encoding the shards into the write batch.
    pub(crate) save_blocks_account_history_batch: Histogram,
    /// Static-file `Headers` segment task, including its `sync_all`.
    pub(crate) save_blocks_sf_headers: Histogram,
    /// Static-file `Transactions` segment task, including its `sync_all`.
    pub(crate) save_blocks_sf_transactions: Histogram,
    /// Static-file `TransactionSenders` segment task, including its `sync_all`.
    pub(crate) save_blocks_sf_senders: Histogram,
    /// Static-file `Receipts` segment task, including its `sync_all`.
    pub(crate) save_blocks_sf_receipts: Histogram,
    /// Static-file `AccountChangeSets` segment task, including its `sync_all`.
    pub(crate) save_blocks_sf_account_changesets: Histogram,
    /// Static-file `StorageChangeSets` segment task, including its `sync_all`.
    pub(crate) save_blocks_sf_storage_changesets: Histogram,
}

impl N42PersistMetrics {
    /// Records the elapsed time of one static-file segment task.
    pub(crate) fn record_segment(&self, segment: StaticFileSegment, elapsed: Duration) {
        let histogram = match segment {
            StaticFileSegment::Headers => &self.save_blocks_sf_headers,
            StaticFileSegment::Transactions => &self.save_blocks_sf_transactions,
            StaticFileSegment::TransactionSenders => &self.save_blocks_sf_senders,
            StaticFileSegment::Receipts => &self.save_blocks_sf_receipts,
            StaticFileSegment::AccountChangeSets => &self.save_blocks_sf_account_changesets,
            StaticFileSegment::StorageChangeSets => &self.save_blocks_sf_storage_changesets,
            #[allow(unreachable_patterns)]
            _ => return,
        };
        histogram.record(elapsed);
    }
}

/// The process's persistence timers.
pub(crate) fn metrics() -> &'static N42PersistMetrics {
    static METRICS: OnceLock<N42PersistMetrics> = OnceLock::new();
    METRICS.get_or_init(N42PersistMetrics::default)
}

thread_local! {
    /// Test-only override of `N42_PERSIST_QMDB_IN_SCOPE`, per thread (`save_blocks` reads it on
    /// the calling thread).
    static QMDB_IN_SCOPE_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    /// Test-only override of `N42_ACCOUNT_HISTORY=off`, per thread.
    static ACCOUNT_HISTORY_OFF_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    /// Test-only override of `N42_ACCOUNT_HISTORY_SCAN_MAX`, per thread.
    static ACCOUNT_HISTORY_SCAN_MAX_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Whether `on_state_persisted` runs beside the backend writes (`N42_PERSIST_QMDB_IN_SCOPE=1`).
/// Read once; any other value or no value keeps it after the scope (the default).
pub(crate) fn persist_qmdb_in_scope() -> bool {
    if let Some(value) = QMDB_IN_SCOPE_OVERRIDE.with(Cell::get) {
        return value;
    }
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_PERSIST_QMDB_IN_SCOPE").is_ok_and(|v| v.trim() == "1"))
}

/// Test helper: overrides `N42_PERSIST_QMDB_IN_SCOPE` on this thread (`None` restores the env).
#[cfg(test)]
pub(crate) fn set_qmdb_in_scope_override(value: Option<bool>) {
    QMDB_IN_SCOPE_OVERRIDE.with(|cell| cell.set(value));
}

/// Whether the `AccountsHistory` index write is skipped (`N42_ACCOUNT_HISTORY=off`). Read once;
/// `on`, any other value or no value writes it (reth's behaviour).
pub(crate) fn account_history_off() -> bool {
    if let Some(value) = ACCOUNT_HISTORY_OFF_OVERRIDE.with(Cell::get) {
        return value;
    }
    static OFF: OnceLock<bool> = OnceLock::new();
    *OFF.get_or_init(|| {
        let off = std::env::var("N42_ACCOUNT_HISTORY").is_ok_and(|v| v.trim() == "off");
        if off {
            tracing::info!(
                target: "providers::db",
                "N42_ACCOUNT_HISTORY=off: the AccountsHistory index is not written; account \
                 changesets are, and historical account reads above the gap scan them"
            );
        }
        off
    })
}

/// Test helper: overrides `N42_ACCOUNT_HISTORY=off` on this thread (`None` restores the env).
#[cfg(test)]
pub(crate) fn set_account_history_off_override(value: Option<bool>) {
    ACCOUNT_HISTORY_OFF_OVERRIDE.with(|cell| cell.set(value));
}

/// `StageCheckpoints` key of the account-history gap marker: its block number is the first block
/// whose `AccountsHistory` entries are missing (written in `N42_ACCOUNT_HISTORY=off`). Entries at
/// or above it are not trusted by historical reads, the restart healer leaves the range alone, and
/// an unwind below it removes the marker. The `IndexAccountHistory` stage checkpoint advances as
/// before, so the launch-time pipeline consistency check is not triggered by the gap.
pub(crate) const ACCOUNT_HISTORY_GAP_KEY: &str = "N42AccountHistoryGap";

/// Default cap on the number of blocks a historical account read scans in the gap
/// (`N42_ACCOUNT_HISTORY_SCAN_MAX` overrides). A read that finds no change within that many blocks
/// of a longer range returns an error that names the mode instead of a slow or wrong answer.
const DEFAULT_ACCOUNT_HISTORY_SCAN_MAX: u64 = 100_000;

/// The gap-scan cap in force.
pub(crate) fn account_history_scan_max() -> u64 {
    if let Some(value) = ACCOUNT_HISTORY_SCAN_MAX_OVERRIDE.with(Cell::get) {
        return value;
    }
    static MAX: OnceLock<u64> = OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("N42_ACCOUNT_HISTORY_SCAN_MAX")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(DEFAULT_ACCOUNT_HISTORY_SCAN_MAX)
    })
}

/// Test helper: overrides `N42_ACCOUNT_HISTORY_SCAN_MAX` on this thread (`None` restores it).
#[cfg(test)]
pub(crate) fn set_account_history_scan_max_override(value: Option<u64>) {
    ACCOUNT_HISTORY_SCAN_MAX_OVERRIDE.with(|cell| cell.set(value));
}

/// The error a historical account read returns when the gap it would scan exceeds the cap.
pub(crate) fn account_history_scan_too_long(
    gap_from: BlockNumber,
    from: BlockNumber,
    to: BlockNumber,
) -> ProviderError {
    ProviderError::other(std::io::Error::other(format!(
        "historical account read needs a changeset scan of blocks {from}..={to}: the \
         AccountsHistory index is missing from block {gap_from} (N42_ACCOUNT_HISTORY=off), and \
         the scan exceeds N42_ACCOUNT_HISTORY_SCAN_MAX={}",
        account_history_scan_max()
    )))
}

fn timed_on_state_persisted(reader: &dyn N42StateReader, blocks: &[BlockNumHash]) {
    let start = std::time::Instant::now();
    reader.on_state_persisted(blocks);
    metrics().save_blocks_qmdb_persisted.record(start.elapsed());
}

/// Runs `scope` (the backend writes of a batch) and the QMDB read view's `on_state_persisted` for
/// `blocks`, both before the batch's commit, which the caller does after this returns.
///
/// * `in_scope == false` (today's order): `scope` first; `on_state_persisted` only if it returned
///   `Ok`.
/// * `in_scope == true`: `on_state_persisted` on its own thread, started before `scope` and joined
///   after it. The view's advance needs only the block list and the QMDB forest, never the
///   database transaction, and its contract is "before the commit", which the join keeps. Its own
///   parallel work runs on the global rayon pool as before (a plain thread, not a storage-pool
///   worker). The difference: if `scope` fails, the view has already advanced, as it already does
///   today when a static-file or `RocksDB` task fails; a failed batch is fatal to persistence
///   either way. If the thread cannot be spawned, the sequential order is used.
pub(crate) fn run_with_qmdb_persisted<R>(
    reader: Option<&dyn N42StateReader>,
    blocks: &[BlockNumHash],
    in_scope: bool,
    scope: impl FnOnce() -> ProviderResult<R>,
) -> ProviderResult<R> {
    let Some(reader) = reader.filter(|_| !blocks.is_empty()) else { return scope() };
    if !in_scope {
        let result = scope()?;
        timed_on_state_persisted(reader, blocks);
        return Ok(result)
    }
    std::thread::scope(|threads| {
        let handle = std::thread::Builder::new()
            .name("persist-qmdb".to_string())
            .spawn_scoped(threads, move || timed_on_state_persisted(reader, blocks));
        match handle {
            Ok(handle) => {
                let result = scope();
                let joined = handle.join();
                let result = result?;
                joined.map_err(|_| {
                    ProviderError::other(std::io::Error::other(
                        "QMDB on_state_persisted thread panicked",
                    ))
                })?;
                Ok(result)
            }
            Err(_) => {
                let result = scope()?;
                timed_on_state_persisted(reader, blocks);
                Ok(result)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, BlockNumber, B256, U256};
    use reth_primitives_traits::Account;
    use std::sync::Mutex;

    /// Records each `on_state_persisted` call with the thread it ran on.
    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<(Vec<BlockNumHash>, Option<String>)>>,
    }

    impl N42StateReader for Recorder {
        fn account(&self, _: &Address, _: BlockNumber) -> Option<Option<Account>> {
            None
        }
        fn storage(&self, _: &Address, _: &B256, _: BlockNumber) -> Option<Option<U256>> {
            None
        }
        fn on_state_persisted(&self, blocks: &[BlockNumHash]) {
            let name = std::thread::current().name().map(str::to_string);
            self.calls.lock().expect("recorder lock").push((blocks.to_vec(), name));
        }
        fn on_state_unwound(&self, _: BlockNumber) {}
    }

    fn blocks() -> Vec<BlockNumHash> {
        (1..=3u64).map(|n| BlockNumHash::new(n, B256::with_last_byte(n as u8))).collect()
    }

    #[test]
    fn in_scope_and_after_scope_make_the_same_call() {
        for in_scope in [false, true] {
            let recorder = Recorder::default();
            let result =
                run_with_qmdb_persisted(Some(&recorder), &blocks(), in_scope, || Ok(7u32));
            assert_eq!(result.ok(), Some(7));
            let calls = recorder.calls.lock().expect("recorder lock");
            assert_eq!(calls.len(), 1, "exactly one call, before return (in_scope={in_scope})");
            assert_eq!(calls[0].0, blocks());
            // In scope it ran on its own thread, beside the scope; otherwise on the caller's.
            assert_eq!(calls[0].1.as_deref() == Some("persist-qmdb"), in_scope);
        }
    }

    #[test]
    fn after_scope_skips_the_call_when_the_scope_fails() {
        let recorder = Recorder::default();
        let result: ProviderResult<()> = run_with_qmdb_persisted(Some(&recorder), &blocks(), false, || {
            Err(ProviderError::other(std::io::Error::other("scope failed")))
        });
        assert!(result.is_err());
        assert!(recorder.calls.lock().expect("recorder lock").is_empty());
    }

    #[test]
    fn in_scope_returns_the_scope_error_after_joining() {
        let recorder = Recorder::default();
        let result: ProviderResult<()> = run_with_qmdb_persisted(Some(&recorder), &blocks(), true, || {
            Err(ProviderError::other(std::io::Error::other("scope failed")))
        });
        assert!(result.is_err());
        // The view advanced (documented): the thread was joined before the error returned.
        assert_eq!(recorder.calls.lock().expect("recorder lock").len(), 1);
    }

    #[test]
    fn no_reader_or_no_blocks_runs_only_the_scope() {
        let recorder = Recorder::default();
        for in_scope in [false, true] {
            assert_eq!(run_with_qmdb_persisted(None, &blocks(), in_scope, || Ok(1u8)).ok(), Some(1));
            assert_eq!(run_with_qmdb_persisted(Some(&recorder), &[], in_scope, || Ok(2u8)).ok(), Some(2));
        }
        assert!(recorder.calls.lock().expect("recorder lock").is_empty());
    }
}
