// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

use alloy_primitives::{Address, BlockHash, BlockNumber, B256};
use auto_impl::auto_impl;
use n42_primitives::{
    BeaconBlock, BeaconBlockChangeset, BeaconState, BeaconStateChangeset, Validator,
};
use reth_storage_errors::ProviderResult;
use std::ops::RangeInclusive;

#[auto_impl(&, Arc, Box)]
pub trait BeaconReader {
    fn get_beaconstate_by_blockhash(
        &self,
        blockhash: BlockHash,
    ) -> ProviderResult<Option<BeaconState>>;
    fn get_beaconblock_by_blockhash(
        &self,
        blockhash: BlockHash,
    ) -> ProviderResult<Option<BeaconBlock>>;
}

#[auto_impl(&, Arc, Box)]
pub trait BeaconWriter {
    fn unwind_beacon(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<()>;
    fn write_beaconstate(&self, changes: BeaconStateChangeset) -> ProviderResult<()>;
    fn remove_beaconstate(&self, range: Vec<BlockHash>) -> ProviderResult<()>;
    // fn unwind_beaconblock(&self,range:RangeInclusive<BlockNumber>)->ProviderResult<()>;
    fn write_beaconblock(&self, changes: BeaconBlockChangeset) -> ProviderResult<()>;
    fn remove_beaconblock(&self, range: Vec<BlockHash>) -> ProviderResult<()>;
}

pub trait BeaconProvider {
    /// get beacon block by block hash
    fn get_beacon_block_by_hash(
        &self,
        block_hash: &BlockHash,
    ) -> ProviderResult<Option<BeaconBlock>>;

    fn get_beacon_state_by_hash(
        &self,
        block_hash: &BlockHash,
    ) -> ProviderResult<Option<BeaconState>>;

    fn get_beacon_block_hash_by_eth1_hash(
        &self,
        block_hash: &BlockHash,
    ) -> ProviderResult<Option<BlockHash>>;

    fn get_tree_by_hash_for_validator(
        &self,
        tree_hash: &B256,
    ) -> ProviderResult<Option<merkle_db_rs::tree::Tree<Validator>>>;

    fn get_tree_by_hash_for_u64(
        &self,
        tree_hash: &B256,
    ) -> ProviderResult<Option<merkle_db_rs::tree::Tree<u64>>>;
}

pub trait BeaconProviderWriter {
    /// save beacon block by hash
    fn save_beacon_block_by_hash(
        &self,
        block_hash: &BlockHash,
        beacon_block: BeaconBlock,
    ) -> ProviderResult<()>;

    fn save_beacon_state_by_hash(
        &self,
        block_hash: &BlockHash,
        beacon_state: BeaconState,
    ) -> ProviderResult<()>;

    fn save_beacon_block_hash_by_eth1_hash(
        &self,
        eth1_block_hash: &BlockHash,
        beacon_block_hash: BlockHash,
    ) -> ProviderResult<()>;

    fn save_tree_by_hash_for_validator(
        &self,
        tree_hash: &B256,
        tree: merkle_db_rs::tree::Tree<Validator>,
    ) -> ProviderResult<()>;

    fn save_tree_by_hash_for_u64(
        &self,
        tree_hash: &B256,
        tree: merkle_db_rs::tree::Tree<u64>,
    ) -> ProviderResult<()>;
}
