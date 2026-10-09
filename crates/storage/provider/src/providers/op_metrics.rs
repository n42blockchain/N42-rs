//! N42: a switch for the per-operation storage metrics.
//!
//! The static-file writer records a counter and a duration histogram for every
//! appended transaction, receipt and sender, and the `RocksDB` provider for
//! every point read and write. At the fleet's tier that is ~500,000 records a
//! persisted block on the `storage-*` threads (the loop314 profile:
//! `Generational<Atomic<u64>>` 6.4% and the prometheus histogram 1.9% of that
//! family). `N42_STORAGE_OP_METRICS=0` turns those per-operation records off;
//! any other value, or no value, keeps them (reth's behaviour). The gauges
//! (segment sizes, file counts) are not affected.

use std::sync::OnceLock;

/// Whether the per-operation storage metrics are recorded. Read once from
/// `N42_STORAGE_OP_METRICS`; the variable is not re-checked afterwards.
pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("N42_STORAGE_OP_METRICS").map_or(true, |v| v.trim() != "0"))
}
