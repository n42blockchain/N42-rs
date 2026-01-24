// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::BlockHash;
use n42_primitives::BeaconBlock;

pub fn fetch_beacon_block(block_hash: BlockHash) -> eyre::Result<BeaconBlock> {
    todo!()
}

pub fn broadcast_beacon_block(
    block_hash: BlockHash,
    beacon_block: &BeaconBlock,
) -> eyre::Result<()> {
    todo!()
}
