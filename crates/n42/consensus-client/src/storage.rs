use alloy_primitives::{BlockHash};
use n42_primitives::{BeaconBlock, BeaconState};

#[derive(Debug, Clone, Hash, Default)]
pub struct Storage {
    init_data: String,
    genesis_hash: BlockHash,
}

impl Storage {
    pub fn new(init_data: String, genesis_hash: BlockHash) -> Self {
        Self {
            init_data,
            genesis_hash,
        }
    }

    pub fn get_beacon_block_by_hash(&self, block_hash: BlockHash) -> eyre::Result<BeaconBlock> {
        todo!()
    }

    pub fn save_beacon_block_by_hash(&self, block_hash: BlockHash, beacon_block: BeaconBlock) -> eyre::Result<()> {
        todo!()
    }

    pub fn get_beacon_block_hash_by_eth1_hash(&self, block_hash: BlockHash) -> eyre::Result<BlockHash> {
        if block_hash == self.genesis_hash {
            return Ok(self.genesis_hash)
        }
        todo!()
    }

    pub fn save_beacon_block_hash_by_eth1_hash(&self, eth1_block_hash: BlockHash, beacon_block_hash: BlockHash) -> eyre::Result<()> {
        todo!()
    }

    pub fn get_beacon_state_by_beacon_hash(&self, block_hash: BlockHash) -> eyre::Result<BeaconState> {
        if block_hash == self.genesis_hash {
            return Ok(Default::default())
        }
        todo!()
    }

    pub fn save_beacon_state_by_beacon_hash(&self, block_hash: BlockHash, beacon_state: BeaconState) -> eyre::Result<()> {
        todo!()
    }

}
