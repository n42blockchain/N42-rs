// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's QMDB read view as the process's latest-state reader
//! (`reth_storage_api::n42_state`, `docs/QMDB_UPGRADE_PLAN.md` stage 6).

use std::sync::Arc;

use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, BlockNumber, B256, U256};
use reth_primitives_traits::Account;
use reth_storage_api::n42_state::{self, N42StateReader, PersistRefused, ReadsMode};
use tracing::error;

use crate::QmdbNodeState;

/// Answers state reads from the node's QMDB read view and moves the view as
/// the database persists. Before the database commits a persisted batch it
/// makes the QMDB delta log durable through the batch's last block, or
/// refuses the batch ([`QmdbNodeState::settle_through`]).
#[derive(Debug, Clone)]
pub struct QmdbStateReader {
    state: QmdbNodeState,
    /// How long a persisted batch waits for the log (`N42_QMDB_SETTLE_WAIT_MS`).
    settle_wait: std::time::Duration,
}

impl QmdbStateReader {
    /// A reader over `state` whose persistence hook waits up to `settle_wait`
    /// for the delta log (the node uses `N42_QMDB_SETTLE_WAIT_MS`).
    pub const fn new(state: QmdbNodeState, settle_wait: std::time::Duration) -> Self {
        Self { state, settle_wait }
    }
}

impl N42StateReader for QmdbStateReader {
    fn account(&self, address: &Address, version: BlockNumber) -> Option<Option<Account>> {
        self.state.read_view_ref()?.account(address, version)
    }

    fn storage(&self, address: &Address, slot: &B256, version: BlockNumber) -> Option<Option<U256>> {
        self.state.read_view_ref()?.storage(address, slot, version)
    }

    fn prefetch_account(&self, address: &Address) {
        if let Some(view) = self.state.read_view_ref() {
            view.prefetch_account(address);
        }
    }

    fn on_state_persisted(&self, blocks: &[BlockNumHash]) {
        // Persistence calls the checked hook; a refusal here is already logged.
        let _ = self.on_state_persisted_checked(blocks);
    }

    /// The delta log is settled through the batch's last block first (the
    /// database must never commit past it), then the read view advances.
    /// A log that cannot be settled refuses the batch, and the view stays.
    fn on_state_persisted_checked(&self, blocks: &[BlockNumHash]) -> Result<(), PersistRefused> {
        if let Some(last) = blocks.last() {
            if let Err(err) = self.state.settle_through(last.number, last.hash, self.settle_wait) {
                error!(
                    target: "n42.qmdb",
                    block = last.number, block_hash = %last.hash, error = %err,
                    "QMDB delta log not settled through a block the database was about to commit; refusing the batch"
                );
                return Err(PersistRefused::new(err));
            }
        }
        let blocks: Vec<(u64, B256)> = blocks.iter().map(|block| (block.number, block.hash)).collect();
        self.state.on_persisted(&blocks);
        Ok(())
    }

    fn on_state_unwound(&self, block: BlockNumber) {
        self.state.on_unwound(block);
    }
}

/// Set once a reader with a read view was registered while `N42_QMDB_READS`
/// consults it ([`register_state_reader`] returned `true`).
static VIEW_REGISTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether `N42_HASHED_TABLES=off` can hold: it needs `N42_QMDB_READS=on` and a registered
/// reader with a read view, since nothing else would answer the latest state once the tables
/// stop being written. Called at startup, after registration.
pub fn check_hashed_tables_setting() -> Result<(), &'static str> {
    if n42_state::hashed_tables_off() &&
        (n42_state::mode() != ReadsMode::On || n42_state::registered().is_none() || !VIEW_REGISTERED.load(std::sync::atomic::Ordering::Acquire))
    {
        return Err("N42_HASHED_TABLES=off stops writing HashedAccounts/HashedStorages, which only a registered QMDB read view in N42_QMDB_READS=on replaces; this node has none");
    }
    Ok(())
}

/// Registers the node's QMDB state as the process's state reader. Returns
/// whether it answers reads: `N42_QMDB_READS` asks for them and
/// initialisation built the view.
///
/// It is registered on every initialised QMDB node, reads or not, because
/// its persistence hook is what orders the QMDB delta log before the
/// database's commit ([`QmdbNodeState::settle_through`]). With
/// `N42_QMDB_READS=off` the providers never consult it for reads, and
/// without a view the hook only settles the log.
pub fn register_state_reader(state: &QmdbNodeState) -> bool {
    if !state.is_initialized() {
        return false;
    }
    let answers = n42_state::mode() != ReadsMode::Off && state.read_view_ref().is_some();
    let registered = n42_state::register(Arc::new(QmdbStateReader::new(state.clone(), crate::node_state::settle_wait())));
    if registered && answers {
        VIEW_REGISTERED.store(true, std::sync::atomic::Ordering::Release);
    }
    registered && answers
}
