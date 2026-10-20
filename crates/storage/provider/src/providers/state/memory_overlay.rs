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
//!
//! N42: a block handed out with a thin bundle over its output shards (`N42_MERGE_ELIDE`) is
//! read through its registry entry ([`n42_sharded_output`]), resolved once when the provider is
//! built: the thin bundle, then the shards -- what the merged bundle would hold at the key.

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
use n42_sharded_output::Shards;
use revm::database::BundleAccount;

/// The filter slots of `in_memory`, one a block in the same order (none when the filters are off).
fn filters_of<N: NodePrimitives>(in_memory: &[ExecutedBlock<N>]) -> Vec<Option<FilterCell>> {
    if !overlay_filter::enabled() {
        return Vec::new()
    }
    in_memory.iter().map(|block| overlay_filter::filter_for(&block.execution_output)).collect()
}

/// N42: the shard sets of `in_memory`'s elided outputs, one slot a block in the same order (empty
/// when none of them is elided, as with `N42_MERGE_ELIDE` off).
fn sharded_of<N: NodePrimitives>(in_memory: &[ExecutedBlock<N>]) -> Vec<Option<Shards>> {
    let sharded: Vec<Option<Shards>> =
        in_memory.iter().map(|block| n42_sharded_output::shards_of(&*block.execution_output)).collect();
    if sharded.iter().all(Option::is_none) {
        return Vec::new()
    }
    sharded
}

/// N42: the account the block at `index` holds at `address`: its bundle's, or for an elided
/// output its thin bundle's and then its shards'.
#[inline(always)]
fn block_account<'b, N: NodePrimitives>(
    block: &'b ExecutedBlock<N>,
    sharded: &'b [Option<Shards>],
    index: usize,
    address: &Address,
) -> Option<&'b BundleAccount> {
    let shards = sharded.get(index).and_then(Option::as_deref);
    n42_sharded_output::account(shards, &block.execution_output.state, address)
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
    /// N42: the blocks' shard sets, in `in_memory`'s order (empty when no block is elided).
    sharded: Cow<'a, [Option<Shards>]>,
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
        let sharded = Cow::Owned(sharded_of(&in_memory));
        Self {
            historical,
            in_memory: Cow::Owned(in_memory),
            trie_input: OnceLock::new(),
            filters,
            sharded,
        }
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
        overlay_basic_account(&self.in_memory, &self.filters, &self.sharded, &*self.historical, address)
    }

    fn n42_prefetch_account(&self, address: &Address) -> bool {
        overlay_prefetch_account(&self.in_memory, &self.filters, &self.sharded, &*self.historical, address)
    }
}

/// N42: an account read through the overlay: the blocks newest first (a filter miss skips
/// the block's bundle), else `historical`. Shared by the borrowed and the owned provider, so
/// the owned one reads without building a [`MemoryOverlayStateProviderRef`] per call (a boxed
/// `historical` allocated and freed on every read).
fn overlay_basic_account<N: NodePrimitives, H: AccountReader + ?Sized>(
    in_memory: &[ExecutedBlock<N>],
    filters: &[Option<FilterCell>],
    sharded: &[Option<Shards>],
    historical: &H,
    address: &Address,
) -> ProviderResult<Option<Account>> {
    let key = FilterKey::address(address);
    let mut skips = 0;
    for (index, block) in in_memory.iter().enumerate() {
        if !overlay_filter::may_hold_account(filters.get(index).and_then(Option::as_ref), key) {
            skips += 1;
            continue
        }
        if let Some(account) = block_account(block, sharded, index, address) {
            overlay_filter::record(skips, index as u64 + 1 - skips);
            return Ok(account.info.as_ref().map(Into::into));
        }
    }
    overlay_filter::record(skips, in_memory.len() as u64 - skips);

    historical.basic_account(address)
}

/// N42: the read's walk as a hint -- the blocks' filters and bundle maps probed newest first
/// (the probes are the prefetch), stopping at the block that holds the account, else passed to
/// `historical`. No counter is recorded.
fn overlay_prefetch_account<N: NodePrimitives, H: AccountReader + ?Sized>(
    in_memory: &[ExecutedBlock<N>],
    filters: &[Option<FilterCell>],
    sharded: &[Option<Shards>],
    historical: &H,
    address: &Address,
) -> bool {
    let key = FilterKey::address(address);
    for (index, block) in in_memory.iter().enumerate() {
        if overlay_filter::may_hold_account(filters.get(index).and_then(Option::as_ref), key) &&
            block_account(block, sharded, index, address).is_some()
        {
            return true;
        }
    }
    historical.n42_prefetch_account(address)
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
            if let Some(value) = block_account(block, &self.sharded, index, &address)
                .and_then(|account| account.storage_slot(storage_key.into()))
            {
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
    /// N42: the blocks' shard sets, in `in_memory`'s order (empty when no block is elided).
    sharded: Vec<Option<Shards>>,
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
        let sharded = sharded_of(&in_memory);
        Self { historical, in_memory, trie_input: OnceLock::new(), filters, sharded }
    }

    /// N42: this provider with its address filters dropped, so every read probes every
    /// block's bundle (the unfiltered walk, for comparisons and benches).
    pub fn without_filters(mut self) -> Self {
        self.filters = Vec::new();
        self
    }

    /// Returns a new provider that takes the `TX` as reference
    #[inline(always)]
    pub(crate) fn as_ref(&self) -> MemoryOverlayStateProviderRef<'_, N> {
        MemoryOverlayStateProviderRef {
            historical: Box::new(self.historical.as_ref()),
            in_memory: Cow::Borrowed(&self.in_memory),
            trie_input: self.trie_input.clone(),
            filters: Cow::Borrowed(&self.filters),
            sharded: Cow::Borrowed(&self.sharded),
        }
    }

    /// Wraps the [`Self`] in a `Box`.
    pub fn boxed(self) -> StateProviderBox {
        Box::new(self)
    }
}

// N42: the account reads directly, without a [`MemoryOverlayStateProviderRef`] built per call
// (the build's recipient reads came through here: a box allocated and freed on every read).
impl<N: NodePrimitives> AccountReader for MemoryOverlayStateProvider<N> {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        overlay_basic_account(&self.in_memory, &self.filters, &self.sharded, &*self.historical, address)
    }

    fn n42_prefetch_account(&self, address: &Address) -> bool {
        overlay_prefetch_account(&self.in_memory, &self.filters, &self.sharded, &*self.historical, address)
    }
}

// Delegates every other provider impl to [`MemoryOverlayStateProviderRef`]
reth_storage_api::macros::delegate_provider_impls!(@except_account MemoryOverlayStateProvider<N> where [N: NodePrimitives]);

#[cfg(test)]
mod elided_tests {
    use super::*;
    use crate::test_utils::{ExtendedAccount, MockEthProvider};
    use alloy_consensus::Header;
    use alloy_primitives::map::AddressHashMap;
    use reth_trie::ComputedTrieData;
    use reth_ethereum_primitives::EthPrimitives;
    use reth_execution_types::{BlockExecutionOutput, BlockExecutionResult};
    use reth_primitives_traits::SealedBlock;
    use revm::{
        database::{states::StorageSlot, AccountStatus},
        state::AccountInfo,
    };
    use std::sync::Arc;

    struct Map(AddressHashMap<BundleAccount>);

    impl n42_sharded_output::ShardedState for Map {
        fn shard_account(&self, address: &Address) -> Option<&BundleAccount> {
            self.0.get(address)
        }
        fn shard_accounts(&self) -> usize {
            self.0.len()
        }
        fn for_each_shard_account(&self, f: &mut dyn FnMut(&Address, &BundleAccount)) {
            for (address, account) in &self.0 {
                f(address, account);
            }
        }
    }

    fn account(nonce: u64, slot: Option<(u64, u64)>) -> BundleAccount {
        let storage = slot
            .map(|(slot, value)| (U256::from(slot), StorageSlot::new_changed(U256::ZERO, U256::from(value))))
            .into_iter()
            .collect();
        BundleAccount {
            info: Some(AccountInfo { nonce, ..Default::default() }),
            original_info: None,
            storage,
            status: AccountStatus::Changed,
        }
    }

    fn block(number: u64, state: BundleState) -> ExecutedBlock {
        let sealed = SealedBlock::<reth_ethereum_primitives::Block>::from_sealed_parts(
            reth_primitives_traits::SealedHeader::new(
                Header { number, ..Default::default() },
                B256::with_last_byte(number as u8),
            ),
            Default::default(),
        );
        let output = Arc::new(BlockExecutionOutput {
            result: BlockExecutionResult {
                receipts: vec![],
                requests: Default::default(),
                gas_used: 0,
                blob_gas_used: 0,
            },
            state,
        });
        ExecutedBlock::new(Arc::new(sealed.try_recover().expect("recovers")), output, ComputedTrieData::default())
    }

    /// `N42_MERGE_ELIDE`: a block handed out with a thin bundle is read through its shards --
    /// account, slot and the prefetch hint, newest block first over an older plain block and
    /// the historical state -- and, unregistered, its thin bundle alone is what it holds.
    #[test]
    fn an_elided_block_is_read_through_its_shards() {
        let (a, b, c, d) = (
            Address::with_last_byte(0xa1),
            Address::with_last_byte(0xb2),
            Address::with_last_byte(0xc3),
            Address::with_last_byte(0xd4),
        );
        let mut shards = AddressHashMap::default();
        shards.insert(a, account(11, Some((1, 7))));
        shards.insert(b, account(12, None));
        let mut thin = BundleState::default();
        thin.state.insert(b, account(22, Some((2, 9))));
        let newer = block(2, thin);
        let mut older_state = BundleState::default();
        older_state.state.insert(c, account(31, None));
        older_state.state.insert(a, account(1, None));
        let older = block(1, older_state);
        let historical = MockEthProvider::default();
        historical.add_account(d, ExtendedAccount::new(41, U256::ZERO));
        let open = || {
            MemoryOverlayStateProvider::new(Box::new(historical.clone()), vec![newer.clone(), older.clone()])
                .without_filters()
        };
        let nonce = |provider: &MemoryOverlayStateProvider<EthPrimitives>, address: Address| {
            provider.basic_account(&address).expect("read").map(|account| account.nonce)
        };

        let plain = open();
        assert_eq!(nonce(&plain, a), Some(1), "unregistered: the older block answers");
        n42_sharded_output::register(&newer.execution_output, Arc::new(Map(shards)));
        let elided = open();
        assert_eq!(
            (nonce(&elided, a), nonce(&elided, b), nonce(&elided, c), nonce(&elided, d)),
            (Some(11), Some(22), Some(31), Some(41))
        );
        assert_eq!(elided.storage(a, U256::from(1).into()).expect("slot"), Some(U256::from(7)));
        assert_eq!(elided.storage(b, U256::from(2).into()).expect("slot"), Some(U256::from(9)));
        assert!(elided.n42_prefetch_account(&a));
        let filter = overlay_filter::BlockFilter::build(&newer.execution_output);
        assert!(filter.may_hold_account(FilterKey::address(&a)), "the filter holds the shards' keys");
        assert_eq!(nonce(&plain, a), Some(1), "a provider built before the registration reads as built");
    }
}
