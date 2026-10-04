//! N42: persistence-cycle timers and switches (`docs/PERSISTENCE_COST_STUDY.md`).
//!
//! * Timers for the phases of one `save_blocks` batch that reth's own metrics leave untimed: the
//!   work before the parallel scope (and the plain-state reverts conversion inside it), the scope
//!   itself, the work after it, the QMDB read view's `on_state_persisted`, the three phases of the
//!   `RocksDB` account-history write and each static-file segment task. They share reth's
//!   `storage.providers.database` scope and a `save_blocks_` prefix, so they land beside the
//!   existing `save_blocks_*` histograms (`_sum` / `_count`) in a metrics dump.

use metrics::Histogram;
use reth_metrics::Metrics;
use reth_static_file_types::StaticFileSegment;
use std::{sync::OnceLock, time::Duration};

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
