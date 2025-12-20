// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{Address, BlockHash, BlockNumber};
use n42_primitives::Snapshot;
use reth_storage_errors::provider::ProviderResult;

/// ly
pub trait SnapshotProvider {
    /// get snapshot by block id
    fn load_snapshot(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Snapshot>>;

    /// get snapshot by block hash
    fn load_snapshot_by_hash(&self, block_hash: &BlockHash) -> ProviderResult<Option<Snapshot>>;
}

pub trait SnapshotProviderWriter {
    /// save snapshot
    fn save_snapshot(&self, id: BlockNumber, snapshot: Snapshot) -> ProviderResult<bool>;

    /// save snapshot by hash
    fn save_snapshot_by_hash(
        &self,
        block_hash: &BlockHash,
        snapshot: Snapshot,
    ) -> ProviderResult<()>;

    fn save_signer_by_hash(&self, block_hash: &BlockHash, signer: Address) -> ProviderResult<()>;
}
