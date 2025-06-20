use alloy_primitives::{BlockHash};
use crate::beacon::{BeaconBlock};

pub fn fetch_beacon_block(block_hash: BlockHash) -> eyre::Result<BeaconBlock> {
    todo!()
}

pub fn broadcast_beacon_block(block_hash: BlockHash, beacon_block: &BeaconBlock) -> eyre::Result<()> {
    todo!()
}
