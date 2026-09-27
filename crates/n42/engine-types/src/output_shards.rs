// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The block's output partitioned by address range: no graft, no state wait
//! (`docs/BREAKTHROUGH_DESIGN.md` section 3, `N42_OUTPUT_SHARDS`).
//!
//! The leader's parallel step executes by sender group, and each batch used to
//! hand its per-batch bundle to a graft that folded every batch's accounts into
//! the block's one `BundleState` map: ~147,000 cache-missing inserts, 40 ms on
//! one thread (`docs/FLEET7_PLAN_V4.md` 6.6), with the chained build waiting
//! 20-29 ms for it (6.13). A sharded insert that then *merged* the shards into
//! that one map was 2.6x slower (6.19): the merge was the cost.
//!
//! Here a batch writes each account it touched into the shard that owns the
//! address (the address's top bits), under that shard's own lock, as the batch
//! ends -- inside the execution, on the batch's thread. Nothing is merged
//! before the seal or before the next build can read the block's state: the
//! chained build's overlay reads the shard set directly ([`ShardLayer`], one
//! probe into one shard by prefix), under the few accounts the block's own
//! executor changed after the batches (the fee credit, the withdrawals, the
//! system calls), which are laid over it as an ordinary executed block. The one
//! contiguous `BundleState` the engine, the QMDB root and the published
//! execution need is built behind the seal ([`FrozenShards::merged_with`]),
//! after the next build has been let go.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, OnceLock, PoisonError, TryLockError,
};

use alloy_primitives::{
    map::{AddressHashMap, AddressHashSet, B256HashMap},
    Address, BlockNumber, Bytes, StorageKey, StorageValue, B256, U256,
};
use reth_primitives_traits::{Account, Bytecode};
use revm::bytecode::Bytecode as RevmBytecode;
use reth_revm::db::State;
use reth_storage_api::{
    errors::ProviderResult, AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider,
    StateProofProvider, StateProvider, StateProviderBox, StateRootProvider, StorageRootProvider,
};
use reth_trie::{
    updates::TrieUpdates, AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm::{
    database::{AccountRevert, BundleAccount, BundleState},
    state::{AccountStatus, EvmState},
    Database,
};

/// The most shards a block's output is split into.
const MAX_SHARDS: usize = 256;

/// `N42_OUTPUT_SHARDS=<S>`: the leader's parallel step writes the block's
/// output into `S` address-range shards (16 or 64 are the sizes meant; at most
/// 256). `0`, unset or unparsable: off, the graft as before. Read once.
pub fn output_shards() -> usize {
    static SHARDS: OnceLock<usize> = OnceLock::new();
    *SHARDS.get_or_init(|| {
        std::env::var("N42_OUTPUT_SHARDS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(0, |n| n.min(MAX_SHARDS))
    })
}

/// The shard of `shards` that owns `address`: the address's top sixteen bits,
/// scaled. Addresses are hashes, so the shards fill evenly.
fn shard_index(address: &Address, shards: usize) -> usize {
    let top = u16::from_be_bytes([address.0[0], address.0[1]]) as usize;
    (top * shards) >> 16
}

/// One address range's accounts, their reverts, and the beneficiary credit
/// the batches left in it.
#[derive(Debug, Default)]
struct Shard {
    state: AddressHashMap<BundleAccount>,
    state_size: usize,
    reverts: Vec<(Address, AccountRevert)>,
    beneficiary_delta: U256,
}

impl Shard {
    /// One batch's accounts of this range folded in, with the rules of
    /// `StagedGraft::add` (`parallel_transfer.rs`): the beneficiary is left
    /// out with its credit summed; an account an earlier batch wrote has this
    /// batch's change added to it (every batch read the parent, so each
    /// change is a delta on the same original) and keeps the first revert.
    fn add(&mut self, beneficiary: Address, run: Vec<(Address, BundleAccount)>, reverts: Vec<(Address, AccountRevert)>, reserve: usize) {
        if self.state.is_empty() {
            self.state.reserve(reserve);
            self.reverts.reserve(reserve);
        }
        let mut repeated: AddressHashSet = Default::default();
        for (address, account) in run {
            let Some(info) = account.info.as_ref() else { continue };
            let (new_balance, new_nonce) = (info.balance, info.nonce);
            let (old_balance, old_nonce) = match &account.original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            if address == beneficiary {
                self.beneficiary_delta = self.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                repeated.insert(address);
                continue;
            }
            if let Some(staged) = self.state.get_mut(&address).and_then(|a| a.info.as_mut()) {
                repeated.insert(address);
                staged.balance = if new_balance >= old_balance {
                    staged.balance.saturating_add(new_balance - old_balance)
                } else {
                    staged.balance.saturating_sub(old_balance - new_balance)
                };
                staged.nonce += new_nonce - old_nonce;
                continue;
            }
            self.state_size += account.size_hint();
            self.state.insert(address, account);
        }
        for (address, revert) in reverts {
            if !repeated.contains(&address) {
                self.reverts.push((address, revert));
            }
        }
    }
}

/// The block's output while the batches run: one lock a shard.
#[derive(Debug)]
pub struct OutputShards {
    beneficiary: Address,
    shards: Vec<Mutex<Shard>>,
    contracts: Mutex<B256HashMap<RevmBytecode>>,
    per_shard: usize,
    /// Pool time inside [`Self::add`], lock waits excluded, nanoseconds.
    insert_ns: AtomicU64,
    /// Pool time waiting for a shard's lock, nanoseconds.
    wait_ns: AtomicU64,
}

impl OutputShards {
    /// `shards` address ranges (at least one) for a block expected to touch
    /// `capacity` accounts.
    pub fn new(beneficiary: Address, capacity: usize, shards: usize) -> Self {
        let count = shards.clamp(1, MAX_SHARDS);
        Self {
            beneficiary,
            shards: (0..count).map(|_| Mutex::new(Shard::default())).collect(),
            contracts: Mutex::new(Default::default()),
            per_shard: capacity / count + 1,
            insert_ns: AtomicU64::new(0),
            wait_ns: AtomicU64::new(0),
        }
    }

    /// One batch's bundle written into the shards, on the batch's thread:
    /// sorted by range with no lock held, then each range's lock taken once.
    pub fn add(&self, bundle: BundleState) {
        let at = std::time::Instant::now();
        let mut waited = std::time::Duration::ZERO;
        let BundleState { state: accounts, contracts, mut reverts, .. } = bundle;
        let taken = std::mem::take(&mut *reverts);
        if !contracts.is_empty() {
            self.contracts.lock().unwrap_or_else(PoisonError::into_inner).extend(contracts);
        }
        let count = self.shards.len();
        let mut by_shard: Vec<Vec<(Address, BundleAccount)>> = (0..count).map(|_| Vec::new()).collect();
        for (address, account) in accounts {
            by_shard[shard_index(&address, count)].push((address, account));
        }
        let mut reverts_by_shard: Vec<Vec<(Address, AccountRevert)>> = (0..count).map(|_| Vec::new()).collect();
        for (address, revert) in taken.into_iter().flatten() {
            reverts_by_shard[shard_index(&address, count)].push((address, revert));
        }
        for (index, (run, reverts)) in by_shard.into_iter().zip(reverts_by_shard).enumerate() {
            if run.is_empty() && reverts.is_empty() {
                continue;
            }
            let mut shard = match self.shards[index].try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    let wait_at = std::time::Instant::now();
                    let guard = self.shards[index].lock().unwrap_or_else(PoisonError::into_inner);
                    waited += wait_at.elapsed();
                    guard
                }
            };
            shard.add(self.beneficiary, run, reverts, self.per_shard);
        }
        self.wait_ns.fetch_add(waited.as_nanos() as u64, Ordering::Relaxed);
        self.insert_ns.fetch_add(at.elapsed().saturating_sub(waited).as_nanos() as u64, Ordering::Relaxed);
    }

    /// The batches are done: the shards lose their locks, so every reader
    /// after this probes without one.
    pub fn freeze(self) -> FrozenShards {
        FrozenShards {
            beneficiary: self.beneficiary,
            shards: self.shards.into_iter().map(|shard| shard.into_inner().unwrap_or_else(PoisonError::into_inner)).collect(),
            contracts: self.contracts.into_inner().unwrap_or_else(PoisonError::into_inner),
            insert_ns: self.insert_ns.into_inner(),
            wait_ns: self.wait_ns.into_inner(),
        }
    }
}

/// The block's output after the batches: the shard set, read without locks.
#[derive(Debug, Default)]
pub struct FrozenShards {
    beneficiary: Address,
    shards: Vec<Shard>,
    contracts: B256HashMap<RevmBytecode>,
    insert_ns: u64,
    wait_ns: u64,
}

impl FrozenShards {
    /// How many address ranges.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Pool time the batches spent writing into the shards, milliseconds.
    pub const fn insert_ms(&self) -> u64 {
        self.insert_ns / 1_000_000
    }

    /// Pool time the batches spent waiting for a shard's lock, milliseconds.
    pub const fn wait_ms(&self) -> u64 {
        self.wait_ns / 1_000_000
    }

    /// The account `address` as the batches left it: one probe, into the
    /// shard that owns the address.
    pub fn get(&self, address: &Address) -> Option<&BundleAccount> {
        if self.shards.is_empty() {
            return None;
        }
        self.shards[shard_index(address, self.shards.len())].state.get(address)
    }

    /// Whether the batches wrote `address`.
    pub fn holds(&self, address: &Address) -> bool {
        self.get(address).is_some()
    }

    /// The accounts written, over every shard.
    pub fn accounts(&self) -> usize {
        self.shards.iter().map(|shard| shard.state.len()).sum()
    }

    /// The beneficiary's credit the batches summed, not applied.
    pub fn beneficiary_delta(&self) -> U256 {
        self.shards.iter().fold(U256::ZERO, |sum, shard| sum.saturating_add(shard.beneficiary_delta))
    }

    /// A contract the batches deployed.
    pub fn bytecode(&self, code_hash: &B256) -> Option<&RevmBytecode> {
        self.contracts.get(code_hash)
    }

    /// The accounts the block's own state already holds in its cache (a
    /// pre-execution system call's): their changes go on top of the block's
    /// values, not the parent's, so they leave the shards and are committed
    /// to `state` as deltas -- `install_staged`'s rule, without the install.
    /// Returns how many were committed.
    pub fn take_cached<DB: Database>(&mut self, state: &mut State<DB>) -> usize {
        if state.cache.accounts.is_empty() || self.shards.is_empty() {
            return 0;
        }
        let count = self.shards.len();
        let mut slow: AddressHashMap<(U256, U256, u64, bool)> = Default::default();
        let cached: Vec<Address> = state.cache.accounts.keys().copied().collect();
        for address in cached {
            let shard = &mut self.shards[shard_index(&address, count)];
            let Some(account) = shard.state.remove(&address) else { continue };
            shard.state_size -= account.size_hint();
            let Some(info) = account.info.as_ref() else { continue };
            let (new_balance, new_nonce) = (info.balance, info.nonce);
            let (old_balance, old_nonce) = match &account.original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            let entry = slow.entry(address).or_insert((U256::ZERO, U256::ZERO, 0, true));
            if new_balance >= old_balance {
                entry.0 = entry.0.saturating_add(new_balance - old_balance);
            } else {
                entry.1 = entry.1.saturating_add(old_balance - new_balance);
            }
            entry.2 += new_nonce - old_nonce;
            entry.3 &= account.original_info.is_none();
            shard.reverts.retain(|(reverted, _)| *reverted != address);
        }
        if slow.is_empty() {
            return 0;
        }
        let mut changes: EvmState = Default::default();
        for (address, (add, sub, nonce, original_absent)) in slow {
            let Some(cached) = state.cache.accounts.get(&address) else { continue };
            let existed = cached.account.is_some();
            let mut merged = cached.account.as_ref().map(|a| a.info.clone()).unwrap_or_default();
            merged.balance = merged.balance.saturating_add(add).saturating_sub(sub);
            merged.nonce += nonce;
            let mut account = revm::state::Account::from(merged);
            account.status = AccountStatus::Touched;
            if !existed && original_absent {
                account.status |= AccountStatus::Created;
            }
            changes.insert(address, account);
        }
        let committed = changes.len();
        revm::DatabaseCommit::commit(state, changes);
        committed
    }

    /// The shards folded into one map after all, for a build that needs the
    /// block's state in its executor (a serial loop, a cache-reading finish):
    /// installed by `install_staged` exactly as a streamed graft is.
    pub fn into_staged(self) -> crate::parallel_transfer::StagedGraft {
        let total = self.accounts();
        let mut state: AddressHashMap<BundleAccount> = Default::default();
        state.reserve(total);
        let mut reverts = Vec::with_capacity(total);
        let (mut size, mut delta) = (0usize, U256::ZERO);
        for shard in self.shards {
            size += shard.state_size;
            delta = delta.saturating_add(shard.beneficiary_delta);
            state.extend(shard.state);
            reverts.extend(shard.reverts);
        }
        crate::parallel_transfer::StagedGraft::from_parts(self.beneficiary, state, size, self.contracts, reverts, delta)
    }

    /// The block's one `BundleState`: the shards' accounts with `residual` --
    /// what the block's executor changed after the batches, merged and taken
    /// with its reverts -- laid over them, and the shards' reverts appended
    /// to the block's revert set (`append_reverts`, which drops the second
    /// revert of an account both touched). The same bundle a graft followed
    /// by the same executor changes leaves. Built behind the seal: the shards
    /// are shared with the next build's overlay, so they are copied, not
    /// moved.
    pub fn merged_with(&self, residual: BundleState) -> BundleState {
        let BundleState { state: mut newer, contracts: newer_contracts, reverts: block_reverts, state_size: newer_size, .. } =
            residual;
        let total: usize = self.accounts() + newer.len();
        let mut state: AddressHashMap<BundleAccount> = Default::default();
        state.reserve(total);
        let mut size = newer_size;
        let mut reverts = Vec::with_capacity(self.shards.iter().map(|shard| shard.reverts.len()).sum());
        for shard in &self.shards {
            size += shard.state_size;
            for (address, account) in &shard.state {
                match newer.remove(address) {
                    Some(mut over) => {
                        // Changed again after the batches: the newer value,
                        // against the parent's original the shard carries.
                        size = size.saturating_sub(account.size_hint() + over.size_hint());
                        over.original_info = account.original_info.clone();
                        let mut storage = account.storage.clone();
                        storage.extend(std::mem::take(&mut over.storage));
                        over.storage = storage;
                        size += over.size_hint();
                        state.insert(*address, over);
                    }
                    None => {
                        state.insert(*address, account.clone());
                    }
                }
            }
            reverts.extend(shard.reverts.iter().cloned());
        }
        state.extend(newer);
        let mut contracts = self.contracts.clone();
        contracts.extend(newer_contracts);
        let reverts_size = block_reverts.iter().map(Vec::len).sum();
        let mut bundle = BundleState { state, contracts, reverts: block_reverts, state_size: size, reverts_size };
        crate::parallel_transfer::append_reverts(&mut bundle, reverts);
        bundle
    }
}

/// The parent's shard set as a state provider layer: an account or slot the
/// batches wrote is answered by its shard, anything else by `historical`. The
/// parent's executor-side changes (the residual) are laid over this as an
/// ordinary executed block by `overlay_on_executed`.
///
/// The root and proof methods delegate to `historical`: the parent filed at
/// `StateReady` carries no trie data either (`executed_from_output`), so the
/// overlay this replaces answered them the same way.
#[allow(missing_debug_implementations)]
pub struct ShardLayer {
    historical: StateProviderBox,
    shards: Arc<FrozenShards>,
}

impl ShardLayer {
    /// `shards` over `historical`.
    pub fn new(historical: StateProviderBox, shards: Arc<FrozenShards>) -> Self {
        Self { historical, shards }
    }

    fn as_ref(&self) -> &(dyn StateProvider + Send + 'static) {
        &*self.historical
    }
}

impl AccountReader for ShardLayer {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        match self.shards.get(address) {
            // `BundleState::account`'s answer, as the overlay gives it.
            Some(account) => Ok(account.info.as_ref().map(Into::into)),
            None => self.historical.basic_account(address),
        }
    }
}

impl StateProvider for ShardLayer {
    fn storage(&self, account: Address, storage_key: StorageKey) -> ProviderResult<Option<StorageValue>> {
        if let Some(value) = self.shards.get(&account).and_then(|a| a.storage_slot(storage_key.into())) {
            return Ok(Some(value));
        }
        self.historical.storage(account, storage_key)
    }
}

impl BytecodeReader for ShardLayer {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        if let Some(code) = self.shards.bytecode(code_hash) {
            return Ok(Some(Bytecode(code.clone())));
        }
        self.historical.bytecode_by_hash(code_hash)
    }
}

reth_storage_api::macros::delegate_impls_to_as_ref!(
    for ShardLayer =>
    BlockHashReader {
        fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>>;
        fn canonical_hashes_range(&self, start: BlockNumber, end: BlockNumber) -> ProviderResult<Vec<B256>>;
    }
    StateRootProvider {
        fn state_root(&self, state: HashedPostState) -> ProviderResult<B256>;
        fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256>;
        fn state_root_with_updates(&self, state: HashedPostState) -> ProviderResult<(B256, TrieUpdates)>;
        fn state_root_from_nodes_with_updates(&self, input: TrieInput) -> ProviderResult<(B256, TrieUpdates)>;
    }
    StorageRootProvider {
        fn storage_root(&self, address: Address, storage: HashedStorage) -> ProviderResult<B256>;
        fn storage_proof(&self, address: Address, slot: B256, storage: HashedStorage) -> ProviderResult<StorageProof>;
        fn storage_multiproof(&self, address: Address, slots: &[B256], storage: HashedStorage) -> ProviderResult<StorageMultiProof>;
    }
    StateProofProvider {
        fn proof(&self, input: TrieInput, address: Address, slots: &[B256]) -> ProviderResult<AccountProof>;
        fn multiproof(&self, input: TrieInput, targets: MultiProofTargets) -> ProviderResult<MultiProof>;
        fn witness(&self, input: TrieInput, target: HashedPostState, mode: ExecutionWitnessMode) -> ProviderResult<Vec<Bytes>>;
    }
    HashedPostStateProvider {
        fn hashed_post_state(&self, bundle_state: &BundleState) -> ProviderResult<HashedPostState>;
    }
);
