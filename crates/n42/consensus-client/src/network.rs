use alloy_primitives::{BlockHash};
use crate::beacon::{BeaconBlock};

pub fn fetch_beacon_block(block_hash: BlockHash) -> eyre::Result<BeaconBlock> {
    let beacon_block = Default::default();
    Ok(beacon_block)
}

pub fn broadcast_beacon_block(block_hash: BlockHash, beacon_block: &BeaconBlock) -> eyre::Result<()> {
    Ok(())
}
