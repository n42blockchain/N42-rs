// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::BlockHash;
use n42_primitives::{BeaconBlock, BeaconState};

#[derive(Debug, Clone, Hash, Default)]
/// Key-value storage of beacon blocks and states.
pub struct Storage {
    init_data: String,
    genesis_hash: BlockHash,
}

impl Storage {
    /// Creates the storage from its initial data and the genesis block hash.
    pub const fn new(init_data: String, genesis_hash: BlockHash) -> Self {
        Self {
            init_data,
            genesis_hash,
        }
    }

    /// Returns the beacon block with the given hash.
    pub fn get_beacon_block_by_hash(&self, _block_hash: BlockHash) -> eyre::Result<BeaconBlock> {
        todo!()
    }

    /// Stores a beacon block under its hash.
    pub fn save_beacon_block_by_hash(
        &self,
        _block_hash: BlockHash,
        _beacon_block: BeaconBlock,
    ) -> eyre::Result<()> {
        todo!()
    }

    /// Returns the hash of the beacon block that belongs to an execution block hash.
    pub fn get_beacon_block_hash_by_eth1_hash(
        &self,
        block_hash: BlockHash,
    ) -> eyre::Result<BlockHash> {
        if block_hash == self.genesis_hash {
            return Ok(self.genesis_hash);
        }
        todo!()
    }

    /// Stores the beacon block hash that belongs to an execution block hash.
    pub fn save_beacon_block_hash_by_eth1_hash(
        &self,
        _eth1_block_hash: BlockHash,
        _beacon_block_hash: BlockHash,
    ) -> eyre::Result<()> {
        todo!()
    }

    /// Returns the beacon state stored for a beacon block hash.
    pub fn get_beacon_state_by_beacon_hash(
        &self,
        block_hash: BlockHash,
    ) -> eyre::Result<BeaconState> {
        if block_hash == self.genesis_hash {
            return Ok(Default::default());
        }
        todo!()
    }

    /// Stores the beacon state that results from a beacon block hash.
    pub fn save_beacon_state_by_beacon_hash(
        &self,
        _block_hash: BlockHash,
        _beacon_state: BeaconState,
    ) -> eyre::Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn test_storage_new() {
        let genesis_hash = B256::ZERO;
        let storage = Storage::new("test_data".to_string(), genesis_hash);
        assert_eq!(storage.genesis_hash, genesis_hash);
        assert_eq!(storage.init_data, "test_data");
    }

    #[test]
    fn test_storage_default() {
        let storage = Storage::default();
        assert_eq!(storage.genesis_hash, B256::ZERO);
        assert_eq!(storage.init_data, "");
    }

    #[test]
    fn test_get_beacon_block_hash_by_eth1_hash_genesis() {
        let genesis_hash = B256::random();
        let storage = Storage::new("test".to_string(), genesis_hash);

        // Should return genesis hash when queried with genesis hash
        let result = storage.get_beacon_block_hash_by_eth1_hash(genesis_hash);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), genesis_hash);
    }

    #[test]
    fn test_get_beacon_state_by_beacon_hash_genesis() {
        let genesis_hash = B256::random();
        let storage = Storage::new("test".to_string(), genesis_hash);

        // Should return default BeaconState when queried with genesis hash
        let result = storage.get_beacon_state_by_beacon_hash(genesis_hash);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.slot, 0);
    }

    #[test]
    fn test_storage_clone() {
        let genesis_hash = B256::random();
        let storage = Storage::new("test".to_string(), genesis_hash);
        let cloned = storage.clone();

        assert_eq!(storage.genesis_hash, cloned.genesis_hash);
        assert_eq!(storage.init_data, cloned.init_data);
    }
}
