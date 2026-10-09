// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! reth v2.5.1's in-memory overlay state provider (N42), kept because reth v2.7.0 removed it
//! from `reth-chain-state`.
//!
//! It reads an account by walking the in-memory blocks' bundles (newest first) and then the
//! historical provider: no per-tip work at open. `reth-storage-overlay`'s
//! `OverlayStateProvider`, which v2.7.0 uses instead, flattens every in-memory block above the
//! persisted anchor into one map per tip before its first read; at 147k accounts a block that
//! flattening put ~100 ms in front of every follower import (loop308,
//! `docs/RETH_2_7_0_UPGRADE.md`). `BlockchainProvider` therefore opens state under in-memory blocks with this type
//! (`N42_OVERLAY_READS=upstream` restores the flattened overlay), and the N42 builder and
//! follower import lay executed parents that are not yet in the tree with it. Ported unchanged
//! apart from `multiproof_v2` (added to `StateProofProvider` upstream) and the crate paths.
//!
//! N42: each in-memory block's reads first consult its address filter
//! ([`overlay_filter`](super::overlay_filter)): a filter miss skips the block's bundle, so a read
//! that no in-memory block touched costs one filter probe a block instead of one hash-map
//! probe a block. `N42_OVERLAY_FILTER=0` turns it off.

use reth_chain_state::ExecutedBlock;
use alloy_consensus::BlockHeader;
use alloy_primitives::{
    keccak256, Address, BlockNumber, Bytes, StorageKey, StorageValue, B256, U256,
};
use reth_storage_api::errors::ProviderResult;
use reth_primitives_traits::{Account, Bytecode, NodePrimitives};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateProviderBox, StateRootProvider, StorageRootProvider,
};
use reth_trie::{
    updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, TrieInput, DecodedMultiProofV2, MultiProofTargetsV2,
};
use revm::database::BundleState;
use std::{borrow::Cow, sync::OnceLock};

use super::overlay_filter::{self, FilterCell, FilterKey};

/// The filter slots of `in_memory`, one a block in the same order (none when the filters are off).
fn filters_of<N: NodePrimitives>(in_memory: &[ExecutedBlock<N>]) -> Vec<Option<FilterCell>> {
    if !overlay_filter::enabled() {
        return Vec::new()
    }
    in_memory.iter().map(|block| overlay_filter::filter_for(&block.execution_output)).collect()
}

/// A state provider that stores references to in-memory blocks along with their state as well as a
/// reference of the historical state provider for fallback lookups.
#[allow(missing_debug_implementations)]
pub struct MemoryOverlayStateProviderRef<
    'a,
    N: NodePrimitives,
> {
    /// Historical state provider for state lookups that are not found in memory blocks.
    historical: Box<dyn StateProvider + 'a>,
    /// The collection of executed parent blocks. Expected order is newest to oldest.
    in_memory: Cow<'a, [ExecutedBlock<N>]>,
    /// Lazy-loaded in-memory trie data.
    trie_input: OnceLock<TrieInput>,
    /// N42: the blocks' address filters, in `in_memory`'s order (empty when off).
    filters: Cow<'a, [Option<FilterCell>]>,
}

impl<'a, N: NodePrimitives> MemoryOverlayStateProviderRef<'a, N> {
    /// Create new memory overlay state provider.
    ///
    /// ## Arguments
    ///
    /// - `in_memory` - the collection of executed ancestor blocks in reverse.
    /// - `historical` - a historical state provider for the latest ancestor block stored in the
    ///   database.
    pub fn new(historical: Box<dyn StateProvider + 'a>, in_memory: Vec<ExecutedBlock<N>>) -> Self {
        let filters = Cow::Owned(filters_of(&in_memory));
        Self { historical, in_memory: Cow::Owned(in_memory), trie_input: OnceLock::new(), filters }
    }

    /// N42: the filter slot of the block at `index` (`None`: probe it).
    #[inline(always)]
    fn filter(&self, index: usize) -> Option<&FilterCell> {
        self.filters.get(index).and_then(Option::as_ref)
    }

    /// Turn this state provider into a state provider
    pub fn boxed(self) -> Box<dyn StateProvider + 'a> {
        Box::new(self)
    }

    /// Return lazy-loaded trie state aggregated from in-memory blocks.
    fn trie_input(&self) -> &TrieInput {
        self.trie_input.get_or_init(|| {
            let mut input = TrieInput::default();
            // Iterate from oldest to newest
            for block in self.in_memory.iter().rev() {
                let data = block.trie_data();
                input.nodes.extend_from_sorted(&data.sorted.trie_updates);
                input.state.extend_from_sorted(&data.sorted.hashed_state);
            }
            input
        })
    }

    fn merged_hashed_storage(&self, address: Address, storage: HashedStorage) -> HashedStorage {
        let state = &self.trie_input().state;
        let mut hashed = state.storages.get(&keccak256(address)).cloned().unwrap_or_default();
        hashed.extend(&storage);
        hashed
    }
}

impl<N: NodePrimitives> BlockHashReader for MemoryOverlayStateProviderRef<'_, N> {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        for block in self.in_memory.iter() {
            if block.recovered_block().number() == number {
                return Ok(Some(block.recovered_block().hash()));
            }
        }

        self.historical.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        let range = start..end;
        let mut earliest_block_number = None;
        let mut in_memory_hashes = Vec::with_capacity(range.size_hint().0);

        // iterate in ascending order (oldest to newest = low to high)
        for block in self.in_memory.iter() {
            let block_num = block.recovered_block().number();
            if range.contains(&block_num) {
                in_memory_hashes.push(block.recovered_block().hash());
                earliest_block_number = Some(block_num);
            }
        }

        // `self.in_memory` stores executed blocks in ascending order (oldest to newest).
        // However, `in_memory_hashes` should be constructed in descending order (newest to oldest),
        // so we reverse the vector after collecting the hashes.
        in_memory_hashes.reverse();

        let mut hashes =
            self.historical.canonical_hashes_range(start, earliest_block_number.unwrap_or(end))?;
        hashes.append(&mut in_memory_hashes);
        Ok(hashes)
    }
}

impl<N: NodePrimitives> AccountReader for MemoryOverlayStateProviderRef<'_, N> {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        let key = FilterKey::address(address);
        let mut skips = 0;
        for (index, block) in self.in_memory.iter().enumerate() {
            if !overlay_filter::may_hold_account(self.filter(index), key) {
                skips += 1;
                continue
            }
            if let Some(account) = block.execution_output.account(address) {
                overlay_filter::record(skips, index as u64 + 1 - skips);
                return Ok(account);
            }
        }
        overlay_filter::record(skips, self.in_memory.len() as u64 - skips);

        self.historical.basic_account(address)
    }
}

impl<N: NodePrimitives> StateRootProvider for MemoryOverlayStateProviderRef<'_, N> {
    fn state_root(&self, state: HashedPostState) -> ProviderResult<B256> {
        self.state_root_from_nodes(TrieInput::from_state(state))
    }

    fn state_root_from_nodes(&self, mut input: TrieInput) -> ProviderResult<B256> {
        input.prepend_self(self.trie_input().clone());
        self.historical.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.state_root_from_nodes_with_updates(TrieInput::from_state(state))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        mut input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        input.prepend_self(self.trie_input().clone());
        self.historical.state_root_from_nodes_with_updates(input)
    }
}

impl<N: NodePrimitives> StorageRootProvider for MemoryOverlayStateProviderRef<'_, N> {
    // TODO: Currently this does not reuse available in-memory trie nodes.
    fn storage_root(&self, address: Address, storage: HashedStorage) -> ProviderResult<B256> {
        let merged = self.merged_hashed_storage(address, storage);
        self.historical.storage_root(address, merged)
    }

    // TODO: Currently this does not reuse available in-memory trie nodes.
    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> ProviderResult<reth_trie::StorageProof> {
        let merged = self.merged_hashed_storage(address, storage);
        self.historical.storage_proof(address, slot, merged)
    }

    // TODO: Currently this does not reuse available in-memory trie nodes.
    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        let merged = self.merged_hashed_storage(address, storage);
        self.historical.storage_multiproof(address, slots, merged)
    }
}

impl<N: NodePrimitives> StateProofProvider for MemoryOverlayStateProviderRef<'_, N> {
    fn proof(
        &self,
        mut input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        input.prepend_self(self.trie_input().clone());
        self.historical.proof(input, address, slots)
    }

    fn multiproof(
        &self,
        mut input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        input.prepend_self(self.trie_input().clone());
        self.historical.multiproof(input, targets)
    }

    fn multiproof_v2(
        &self,
        mut input: TrieInput,
        targets: MultiProofTargetsV2,
    ) -> ProviderResult<DecodedMultiProofV2> {
        input.prepend_self(self.trie_input().clone());
        self.historical.multiproof_v2(input, targets)
    }

    fn witness(
        &self,
        mut input: TrieInput,
        target: HashedPostState,
        mode: reth_trie::ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        input.prepend_self(self.trie_input().clone());
        self.historical.witness(input, target, mode)
    }
}

impl<N: NodePrimitives> HashedPostStateProvider for MemoryOverlayStateProviderRef<'_, N> {
    fn hashed_post_state(&self, bundle_state: &BundleState) -> ProviderResult<HashedPostState> {
        let mut hashed_state = self.historical.hashed_post_state(bundle_state)?;

        for (address, account) in bundle_state.state() {
            // Accounts created in this bundle cannot have parent storage to zero.
            if !account.was_destroyed() || account.original_info.is_none() {
                continue
            }

            let hashed_address = keccak256(address);
            let Some(parent_storage) = self.trie_input().state.storages.get(&hashed_address) else {
                continue
            };
            let storage = &mut hashed_state.storages.entry(hashed_address).or_default().storage;
            for hashed_slot in parent_storage.storage.keys() {
                storage.entry(*hashed_slot).or_insert(U256::ZERO);
            }
        }

        Ok(hashed_state)
    }
}

impl<N: NodePrimitives> StateProvider for MemoryOverlayStateProviderRef<'_, N> {
    fn storage(
        &self,
        address: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        // A bundle answers a slot only for an address it holds: the address filter covers it.
        let key = FilterKey::address(&address);
        let mut skips = 0;
        for (index, block) in self.in_memory.iter().enumerate() {
            if !overlay_filter::may_hold_account(self.filter(index), key) {
                skips += 1;
                continue
            }
            if let Some(value) = block.execution_output.storage(&address, storage_key.into()) {
                overlay_filter::record(skips, index as u64 + 1 - skips);
                return Ok(Some(value));
            }
        }
        overlay_filter::record(skips, self.in_memory.len() as u64 - skips);

        self.historical.storage(address, storage_key)
    }
}

impl<N: NodePrimitives> BytecodeReader for MemoryOverlayStateProviderRef<'_, N> {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        let key = FilterKey::code_hash(code_hash);
        for (index, block) in self.in_memory.iter().enumerate() {
            if !overlay_filter::may_hold_code(self.filter(index), key) {
                continue
            }
            if let Some(contract) = block.execution_output.bytecode(code_hash) {
                return Ok(Some(contract));
            }
        }

        self.historical.bytecode_by_hash(code_hash)
    }
}

/// An owned state provider that stores references to in-memory blocks along with their state as
/// well as a reference of the historical state provider for fallback lookups.
#[allow(missing_debug_implementations)]
pub struct MemoryOverlayStateProvider<N: NodePrimitives> {
    /// Historical state provider for state lookups that are not found in memory blocks.
    historical: StateProviderBox,
    /// The collection of executed parent blocks. Expected order is newest to oldest.
    in_memory: Vec<ExecutedBlock<N>>,
    /// Lazy-loaded in-memory trie data.
    trie_input: OnceLock<TrieInput>,
    /// N42: the blocks' address filters, in `in_memory`'s order (empty when off).
    filters: Vec<Option<FilterCell>>,
}

impl<N: NodePrimitives> MemoryOverlayStateProvider<N> {
    /// Create new memory overlay state provider.
    ///
    /// ## Arguments
    ///
    /// - `in_memory` - the collection of executed ancestor blocks in reverse.
    /// - `historical` - a historical state provider for the latest ancestor block stored in the
    ///   database.
    pub fn new(historical: StateProviderBox, in_memory: Vec<ExecutedBlock<N>>) -> Self {
        let filters = filters_of(&in_memory);
        Self { historical, in_memory, trie_input: OnceLock::new(), filters }
    }

    /// N42: this provider with its address filters dropped, so every read probes every
    /// block's bundle (the unfiltered walk, for comparisons and benches).
    pub fn without_filters(mut self) -> Self {
        self.filters = Vec::new();
        self
    }

    /// Returns a new provider that takes the `TX` as reference
    #[inline(always)]
    fn as_ref(&self) -> MemoryOverlayStateProviderRef<'_, N> {
        MemoryOverlayStateProviderRef {
            historical: Box::new(self.historical.as_ref()),
            in_memory: Cow::Borrowed(&self.in_memory),
            trie_input: self.trie_input.clone(),
            filters: Cow::Borrowed(&self.filters),
        }
    }

    /// Wraps the [`Self`] in a `Box`.
    pub fn boxed(self) -> StateProviderBox {
        Box::new(self)
    }
}

// Delegates all provider impls to [`MemoryOverlayStateProviderRef`]
reth_storage_api::macros::delegate_provider_impls!(MemoryOverlayStateProvider<N> where [N: NodePrimitives]);
