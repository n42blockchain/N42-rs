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
//! Here a batch hands its bundle over whole as it ends, with the addresses it
//! touched listed by the shard that owns each (the address's top bits), on
//! the batch's thread: no lock, no account moved. When the batches are done
//! the fold is one parallel pass on the build pool, a task a shard, each
//! copying its range's accounts out of every batch's map straight into its
//! shard's map with the exact capacity reserved -- nothing written that
//! another task reads, nothing locked. (v2 moved every account into a
//! per-range vector inside the execution first: 55 ms of pool time on the
//! bench's block for a 1 ms faster fold, `tests/output_shards_bench.rs`.)
//! (loop273: the
//! first shape, every batch inserting into the shard maps under per-shard
//! locks as it ended, cost 122-138 ms of pool time and 535-637 ms of waiting,
//! `docs/BREAKTHROUGH_DESIGN.md` 10.8.) Nothing is merged
//! before the seal or before the next build can read the block's state: the
//! chained build's overlay reads the shard set directly ([`ShardLayer`], one
//! probe into one shard by prefix), under the few accounts the block's own
//! executor changed after the batches (the fee credit, the withdrawals, the
//! system calls), which are laid over it as an ordinary executed block. The
//! QMDB root and the hashed post-state read the shards directly
//! ([`FrozenShards::view`]); the one contiguous `BundleState` the engine and the
//! published execution need is built behind the seal beside them
//! ([`FrozenShards::merged`], on the build pool), after the next build has been
//! let go.
//!
//! `N42_OUTPUT_INDEX=1` ([`output_index`]) keeps the batches' maps as the
//! block's output and folds only an index over them (address -> batch, a
//! 22-byte entry, a task a shard): no account is copied unless several
//! batches wrote it, in which case it is summed into the shard's conflicts
//! map (`docs/BREAKTHROUGH_DESIGN.md` 10.14: the v4 fold is bound by the 264
//! bytes an account it moves). Reads, the view and the merge go through the
//! index; the results are the v4 fold's (`tests/output_shards.rs`).

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, OnceLock, PoisonError,
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

/// `N42_OUTPUT_INDEX=1` (with `N42_OUTPUT_SHARDS=<S>`): the block's output is
/// the batches' maps as the executor left them plus an index -- a map a shard
/// from address to the batch that wrote it, 22 bytes an entry -- instead of
/// shard maps every account is copied into (`docs/BREAKTHROUGH_DESIGN.md`
/// 10.14: the fold's tasks are bound by the 264 bytes an account they move).
/// Accounts several batches wrote are summed into a small map a shard (the
/// conflicts). `0`, unset or anything else: the v4 fold. Read once.
pub fn output_index() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_OUTPUT_INDEX").is_ok_and(|v| v.trim() == "1"))
}

/// `N42_OUTPUT_INDEX_LIVE=1` (index mode only): each batch enters its
/// addresses into the shards' indexes as it ends, on its own thread with its
/// map still in its cache, under a lock a shard taken in an order rotated by
/// the batch's number (a busy shard passed over and come back to), so the
/// freeze is left with the conflicts alone. The index build after the last
/// batch was 14 ms on the fleet (1 on the bench) for ~9,000 inserts a task
/// (docs/BREAKTHROUGH_DESIGN.md 10.32): the address lists read cold, on
/// the leader's chain before the seal. The same index, conflicts and kept
/// reverts come out, with the batches numbered in the order they began their
/// inserts rather than the order they were pushed -- as arbitrary an order
/// as that one, and the one every rule here is indifferent to. Off by
/// default: under contention the batches' ends can wait on each other
/// (loop273's first shape, whole accounts moved under such locks, waited
/// 535-637 ms a block; an entry here is 22 bytes). Read once.
pub fn output_index_live() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_OUTPUT_INDEX_LIVE").is_ok_and(|v| v.trim() == "1"))
}

/// `N42_LIVE_INDEX_DEFER=1` (live index only): a batch whose hand-over finds
/// a shard's index lock busy twice (the rotated pass and one more) does not
/// wait for it: the shard is left to the freeze, which enters the batch's
/// addresses there under the same rules. loop341 measured the waits this
/// removes: the hand-over (`shard_append_ms`) was 251 ms of pool time a block
/// against 227 ms of the batches' time off the CPU (r = 0.99 over 1,453
/// blocks; 541 / 520 ms with 48 threads), ~4 blocking lock calls a batch.
/// The same index, conflicts and kept reverts come out (the batches' order
/// at a shard is as arbitrary as before). Off by default. Read once.
pub fn live_index_defer() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_LIVE_INDEX_DEFER").is_ok_and(|v| v.trim() == "1"))
}

/// How a live hand-over treats a busy shard: wait for it (the default),
/// leave it to the freeze (`N42_LIVE_INDEX_DEFER=1`), or, for tests, leave
/// every other shard to the freeze whatever its lock says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveDefer {
    Wait,
    Busy,
    Forced,
}

/// One thread's live-index hand-over counters, cumulative (see
/// [`LiveLockCounts`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiveLockCounts {
    /// Shard locks the hand-over blocked on (the try passes found them busy).
    pub waits: u64,
    /// Nanoseconds blocked on them.
    pub wait_ns: u64,
    /// Nanoseconds the thread held shard locks entering addresses.
    pub hold_ns: u64,
    /// Shards left to the freeze (`N42_LIVE_INDEX_DEFER=1`).
    pub deferred: u64,
}

impl LiveLockCounts {
    /// The calling thread's counts now.
    pub fn now() -> Self {
        LIVE_LOCKS.try_with(std::cell::Cell::get).unwrap_or_default()
    }

    /// The counts between `earlier` and `self`.
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            waits: self.waits.saturating_sub(earlier.waits),
            wait_ns: self.wait_ns.saturating_sub(earlier.wait_ns),
            hold_ns: self.hold_ns.saturating_sub(earlier.hold_ns),
            deferred: self.deferred.saturating_sub(earlier.deferred),
        }
    }

    fn add(f: impl FnOnce(&mut Self)) {
        let _ = LIVE_LOCKS.try_with(|cell| {
            let mut counts = cell.get();
            f(&mut counts);
            cell.set(counts);
        });
    }
}

std::thread_local! {
    static LIVE_LOCKS: std::cell::Cell<LiveLockCounts> = const {
        std::cell::Cell::new(LiveLockCounts { waits: 0, wait_ns: 0, hold_ns: 0, deferred: 0 })
    };
}

/// One batch's addresses and kept reverts of one shard entered into that
/// shard's index part: `StagedGraft::add`'s rules as the frozen index build
/// applies them, the conflicting accounts' sums left to the freeze (their
/// order is the order of `drops`).
fn enter_part(
    part: &mut IndexPart,
    id: u16,
    accounts: &AddressHashMap<BundleAccount>,
    reverts: &[(Address, AccountRevert)],
    addresses: &[Address],
    revert_at: &[u32],
) {
    let mut repeated: AddressHashSet = Default::default();
    for address in addresses {
        match part.index.entry(*address) {
            alloy_primitives::map::hash_map::Entry::Vacant(slot) => {
                slot.insert(id);
            }
            alloy_primitives::map::hash_map::Entry::Occupied(mut held) => {
                let Some(account) = accounts.get(address) else { continue };
                repeated.insert(*address);
                part.size_less += account.size_hint();
                let first = *held.get();
                if first != CONFLICT {
                    part.drops.push((first, *address));
                    held.insert(CONFLICT);
                }
                part.drops.push((id, *address));
            }
        }
    }
    for &pos in revert_at {
        let Some((address, _)) = reverts.get(pos as usize) else { continue };
        if repeated.is_empty() || !repeated.contains(address) {
            part.kept.push((id, pos));
        }
    }
}

/// The index's mark for an account several batches wrote: it is read from
/// the shard's conflicts map, not from a batch's.
const CONFLICT: u16 = u16::MAX;

/// `staged` with the change `account` made to the parent's value added:
/// `StagedGraft::add`'s rule for an account an earlier batch wrote.
fn add_delta(staged: &mut revm::state::AccountInfo, account: &BundleAccount) {
    let Some(info) = account.info.as_ref() else { return };
    let (new_balance, new_nonce) = (info.balance, info.nonce);
    let (old_balance, old_nonce) = match &account.original_info {
        Some(orig) => (orig.balance, orig.nonce),
        None => (U256::ZERO, 0),
    };
    staged.balance = if new_balance >= old_balance {
        staged.balance.saturating_add(new_balance - old_balance)
    } else {
        staged.balance.saturating_sub(old_balance - new_balance)
    };
    staged.nonce += new_nonce - old_nonce;
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
    ///
    /// The batch's map is read in place, shared with the other ranges'
    /// tasks: an account is cloned once, into its slot of this range's map,
    /// and only when it is new here (a repeated one adds its delta).
    fn add<'a>(
        &mut self,
        beneficiary: Address,
        run: impl Iterator<Item = (&'a Address, &'a BundleAccount)>,
        reverts: impl Iterator<Item = &'a (Address, AccountRevert)>,
    ) {
        let mut repeated: AddressHashSet = Default::default();
        for (&address, account) in run {
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
            // One probe: the entry both says whether an earlier batch wrote
            // the account and is where a new one goes.
            match self.state.entry(address) {
                alloy_primitives::map::hash_map::Entry::Occupied(mut held) => {
                    repeated.insert(address);
                    if let Some(staged) = held.get_mut().info.as_mut() {
                        staged.balance = if new_balance >= old_balance {
                            staged.balance.saturating_add(new_balance - old_balance)
                        } else {
                            staged.balance.saturating_sub(old_balance - new_balance)
                        };
                        staged.nonce += new_nonce - old_nonce;
                        continue;
                    }
                    // Held without an info (never: only an account with
                    // one is put in): replaced, as an insert would.
                    repeated.remove(&address);
                    self.state_size += account.size_hint();
                    held.insert(account.clone());
                }
                alloy_primitives::map::hash_map::Entry::Vacant(slot) => {
                    self.state_size += account.size_hint();
                    slot.insert(account.clone());
                }
            }
        }
        for (address, revert) in reverts {
            if repeated.is_empty() || !repeated.contains(address) {
                self.reverts.push((*address, revert.clone()));
            }
        }
    }
}

/// One batch's output as the batch left it -- its account map, whole, and
/// its reverts in one list -- with, for each address range, the addresses
/// of its accounts there (in the map's order) and the positions of its
/// reverts there.
struct BatchOut {
    accounts: AddressHashMap<BundleAccount>,
    reverts: Vec<(Address, AccountRevert)>,
    addresses: Vec<Vec<Address>>,
    revert_at: Vec<Vec<u32>>,
    /// Index mode: the size of the accounts kept in `accounts` (the
    /// beneficiary and accounts without an info taken out at the hand-over).
    size: usize,
    /// Index mode: the beneficiary's credit this batch made.
    beneficiary_delta: U256,
    /// Live index mode: the number the batch's index entries carry (its
    /// position in the frozen output), `usize::MAX` when not entered.
    live_id: usize,
    /// Live index mode: the shards this batch left to the freeze
    /// (`N42_LIVE_INDEX_DEFER=1`), empty when it entered every one.
    deferred: Vec<u16>,
}

/// One batch's map and reverts kept as the block's output (index mode).
struct IndexedBatch {
    accounts: AddressHashMap<BundleAccount>,
    reverts: Vec<(Address, AccountRevert)>,
}

/// The block's output in index mode: the batches' maps, a map a shard from
/// address to the batch holding it ([`CONFLICT`]: the shard's conflicts map
/// holds it, summed), and the reverts kept, a `(batch, position)` pair each.
/// Every account is in exactly one place: a conflicting one was taken out of
/// the batches' maps after the fold.
struct Indexed {
    batches: Vec<IndexedBatch>,
    index: Vec<AddressHashMap<u16>>,
    conflicts: Vec<AddressHashMap<BundleAccount>>,
    kept: Vec<Vec<(u16, u32)>>,
    state_size: usize,
    beneficiary_delta: U256,
    conflict_count: usize,
}

impl std::fmt::Debug for Indexed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Indexed")
            .field("batches", &self.batches.len())
            .field("shards", &self.index.len())
            .field("conflicts", &self.conflict_count)
            .finish()
    }
}

impl Indexed {
    fn get(&self, address: &Address) -> Option<&BundleAccount> {
        let shard = shard_index(address, self.index.len());
        match *self.index.get(shard)?.get(address)? {
            CONFLICT => self.conflicts.get(shard)?.get(address),
            id => self.batches.get(id as usize)?.accounts.get(address),
        }
    }

    fn revert(&self, (id, at): (u16, u32)) -> Option<&(Address, AccountRevert)> {
        self.batches.get(id as usize)?.reverts.get(at as usize)
    }

    /// Every account, each once: the batches' maps, then the conflicts.
    fn iter(&self) -> impl Iterator<Item = (&Address, &BundleAccount)> {
        self.batches.iter().flat_map(|batch| batch.accounts.iter()).chain(self.conflicts.iter().flatten())
    }

    /// `address` taken out of the output with its kept reverts; its size
    /// taken off.
    fn take(&mut self, address: &Address) -> Option<BundleAccount> {
        let shard = shard_index(address, self.index.len());
        let id = self.index.get_mut(shard)?.remove(address)?;
        let account = match id {
            CONFLICT => self.conflicts.get_mut(shard)?.remove(address)?,
            id => self.batches.get_mut(id as usize)?.accounts.remove(address)?,
        };
        self.state_size = self.state_size.saturating_sub(account.size_hint());
        let batches = &self.batches;
        if let Some(kept) = self.kept.get_mut(shard) {
            kept.retain(|&(id, at)| {
                batches.get(id as usize).and_then(|b| b.reverts.get(at as usize)).is_none_or(|(a, _)| a != address)
            });
        }
        Some(account)
    }
}

/// What one index task built for its shard.
#[derive(Debug, Default)]
struct IndexPart {
    index: AddressHashMap<u16>,
    conflicts: AddressHashMap<BundleAccount>,
    kept: Vec<(u16, u32)>,
    /// `(batch, address)`: the conflicting accounts to take out of the
    /// batches' maps.
    drops: Vec<(u16, Address)>,
    /// The size of the repeated occurrences (counted once, at the first).
    size_less: usize,
}

impl std::fmt::Debug for BatchOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchOut").field("accounts", &self.accounts.len()).field("reverts", &self.reverts.len()).finish()
    }
}

/// The block's output while the batches run: each batch's map handed over
/// whole as the batch ends, split by address range only at the fold.
#[derive(Debug)]
pub struct OutputShards {
    beneficiary: Address,
    count: usize,
    /// One entry a batch, in the order the batches ended. The lock is taken
    /// once a batch, for one push.
    batches: Mutex<Vec<BatchOut>>,
    contracts: Mutex<B256HashMap<RevmBytecode>>,
    /// Pool time inside [`Self::add`] (the hand-over), nanoseconds.
    append_ns: AtomicU64,
    /// Index mode ([`output_index`]): the fold builds an index over the
    /// batches' maps instead of copying their accounts into shard maps.
    index: bool,
    /// Live index mode ([`output_index_live`]): the shards' indexes, filled
    /// by the batches as they end; `None` otherwise.
    live: Option<Vec<Mutex<IndexPart>>>,
    /// The next live batch number.
    live_next: std::sync::atomic::AtomicUsize,
    /// What a busy shard lock does to a live hand-over.
    live_defer: LiveDefer,
}

impl OutputShards {
    /// `shards` address ranges (at least one) for a block expected to touch
    /// `_capacity` accounts (each shard's map is sized at the fold), in the
    /// mode `N42_OUTPUT_INDEX` names.
    pub fn new(beneficiary: Address, capacity: usize, shards: usize) -> Self {
        Self::with_index(beneficiary, capacity, shards, output_index())
    }

    /// [`Self::new`] with the mode given: `index` builds an index over the
    /// batches' maps at the fold, otherwise the accounts are copied into
    /// shard maps (v4).
    pub fn with_index(beneficiary: Address, capacity: usize, shards: usize, index: bool) -> Self {
        Self::with_index_live(beneficiary, capacity, shards, index, index && output_index_live())
    }

    /// [`Self::with_index`] with the live index ([`output_index_live`])
    /// given: each shard's index sized for its share of `capacity` accounts
    /// and a quarter more (a fuller shard's map grows as any map does).
    pub fn with_index_live(beneficiary: Address, capacity: usize, shards: usize, index: bool, live: bool) -> Self {
        let count = shards.clamp(1, MAX_SHARDS);
        let each = capacity / count + capacity / (4 * count) + 16;
        let live = (index && live).then(|| {
            (0..count)
                .map(|_| {
                    Mutex::new(IndexPart {
                        index: AddressHashMap::with_capacity_and_hasher(each, Default::default()),
                        kept: Vec::with_capacity(each),
                        ..Default::default()
                    })
                })
                .collect()
        });
        Self {
            beneficiary,
            count,
            batches: Mutex::new(Vec::with_capacity(64)),
            contracts: Mutex::new(Default::default()),
            append_ns: AtomicU64::new(0),
            index,
            live,
            live_next: std::sync::atomic::AtomicUsize::new(0),
            live_defer: if live_index_defer() { LiveDefer::Busy } else { LiveDefer::Wait },
        }
    }

    /// Tests: whether a live hand-over leaves busy shards to the freeze
    /// (`N42_LIVE_INDEX_DEFER=1`'s rule), whatever the environment says; with
    /// `forced`, every other shard of every batch is left to it, busy or not.
    #[doc(hidden)]
    pub fn set_live_defer(&mut self, on: bool, forced: bool) {
        self.live_defer = match (on, forced) {
            (_, true) => LiveDefer::Forced,
            (true, false) => LiveDefer::Busy,
            (false, false) => LiveDefer::Wait,
        };
    }

    /// The live index's inserts for one batch (see [`output_index_live`]):
    /// its addresses and kept reverts entered into every shard's index under
    /// that shard's lock, the shards visited from `id` on and a busy one
    /// passed over while another is free. `StagedGraft::add`'s rules as the
    /// frozen index build applies them, the conflicting accounts' sums left
    /// to the freeze (their order is the order of `drops`).
    ///
    /// Returns the shards left to the freeze (`defer` other than
    /// [`LiveDefer::Wait`]); the thread's [`LiveLockCounts`] take the waits,
    /// the time held and the shards left.
    #[allow(clippy::too_many_arguments)]
    fn enter_live(
        live: &[Mutex<IndexPart>],
        id: u16,
        accounts: &AddressHashMap<BundleAccount>,
        reverts: &[(Address, AccountRevert)],
        addresses: &[Vec<Address>],
        revert_at: &[Vec<u32>],
        defer: LiveDefer,
    ) -> Vec<u16> {
        let count = live.len();
        let mut hold_ns = 0u64;
        let mut enter = |part: &mut IndexPart, shard: usize| {
            let at = std::time::Instant::now();
            enter_part(
                part,
                id,
                accounts,
                reverts,
                addresses.get(shard).map_or(&[][..], Vec::as_slice),
                revert_at.get(shard).map_or(&[][..], Vec::as_slice),
            );
            hold_ns += at.elapsed().as_nanos() as u64;
        };
        let mut left: Vec<usize> = Vec::new();
        let mut deferred: Vec<u16> = Vec::new();
        for k in 0..count {
            let shard = (id as usize + k) % count;
            if defer == LiveDefer::Forced && (id as usize + shard) % 2 == 1 {
                deferred.push(shard as u16);
                continue;
            }
            match live[shard].try_lock() {
                Ok(mut part) => enter(&mut part, shard),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => enter(&mut poisoned.into_inner(), shard),
                Err(std::sync::TryLockError::WouldBlock) => left.push(shard),
            }
        }
        let (mut waits, mut wait_ns) = (0u64, 0u64);
        for shard in left {
            if defer != LiveDefer::Wait {
                // One more try: the pass above took a while; a shard still
                // busy now is the freeze's.
                match live[shard].try_lock() {
                    Ok(mut part) => enter(&mut part, shard),
                    Err(std::sync::TryLockError::Poisoned(poisoned)) => enter(&mut poisoned.into_inner(), shard),
                    Err(std::sync::TryLockError::WouldBlock) => deferred.push(shard as u16),
                }
                continue;
            }
            let at = std::time::Instant::now();
            let mut part = live[shard].lock().unwrap_or_else(PoisonError::into_inner);
            waits += 1;
            wait_ns += at.elapsed().as_nanos() as u64;
            enter(&mut part, shard);
        }
        let shards_left = deferred.len() as u64;
        LiveLockCounts::add(|counts| {
            counts.waits += waits;
            counts.wait_ns += wait_ns;
            counts.hold_ns += hold_ns;
            counts.deferred += shards_left;
        });
        deferred
    }

    /// One batch's bundle handed over whole, on the batch's thread, with its
    /// addresses listed by range: no account is moved and no shard map
    /// touched. (v2 moved every 264-byte account into a vector of its range
    /// here, inside the execution: 55 ms of pool time on the bench's block,
    /// 30-37 on the fleet's -- `tests/output_shards_bench.rs`. A list of
    /// addresses is a twelfth of the bytes; the account is copied once, at
    /// the fold, straight into its range's map.)
    pub fn add(&self, bundle: BundleState) {
        let at = std::time::Instant::now();
        let BundleState { state: accounts, contracts, mut reverts, .. } = bundle;
        let mut taken = std::mem::take(&mut *reverts);
        // One transition merge leaves one list: taken as it is.
        let reverts = if taken.len() == 1 { taken.pop().unwrap_or_default() } else { taken.into_iter().flatten().collect() };
        if !contracts.is_empty() {
            self.contracts.lock().unwrap_or_else(PoisonError::into_inner).extend(contracts);
        }
        let count = self.count;
        let each = |n: usize| n / count + n / (4 * count) + 1;
        let mut accounts = accounts;
        let mut addresses: Vec<Vec<Address>> = (0..count).map(|_| Vec::with_capacity(each(accounts.len()))).collect();
        let (mut size, mut beneficiary_delta, mut beneficiary_out) = (0usize, U256::ZERO, false);
        if self.index {
            // The map stays the block's output, so what `Shard::add` would
            // leave out of it is taken out here, on the batch's thread with
            // its accounts still in its cache: an account without an info
            // (its revert kept) and the beneficiary (its credit summed, its
            // revert dropped).
            let mut gone: Vec<Address> = Vec::new();
            for (address, account) in &accounts {
                match account.info.as_ref() {
                    None => gone.push(*address),
                    Some(info) if *address == self.beneficiary => {
                        let old = account.original_info.as_ref().map_or(U256::ZERO, |orig| orig.balance);
                        beneficiary_delta = beneficiary_delta.saturating_add(info.balance.saturating_sub(old));
                        beneficiary_out = true;
                        gone.push(*address);
                    }
                    Some(_) => {
                        size += account.size_hint();
                        addresses[shard_index(address, count)].push(*address);
                    }
                }
            }
            for address in &gone {
                accounts.remove(address);
            }
        } else {
            for address in accounts.keys() {
                addresses[shard_index(address, count)].push(*address);
            }
        }
        let mut revert_at: Vec<Vec<u32>> = (0..count).map(|_| Vec::with_capacity(each(reverts.len()))).collect();
        for (at, (address, _)) in reverts.iter().enumerate() {
            if beneficiary_out && *address == self.beneficiary {
                continue;
            }
            revert_at[shard_index(address, count)].push(at as u32);
        }
        // Live index: numbered and entered now, on this thread. A block of
        // more batches than an index entry can name is frozen the ordinary
        // way (every batch's lists are kept either way).
        let mut live_id = usize::MAX;
        let mut deferred = Vec::new();
        if let Some(live) = self.live.as_deref() {
            let id = self.live_next.fetch_add(1, Ordering::Relaxed);
            if id < CONFLICT as usize {
                live_id = id;
                deferred =
                    Self::enter_live(live, id as u16, &accounts, &reverts, &addresses, &revert_at, self.live_defer);
            }
        }
        let out = BatchOut { accounts, reverts, addresses, revert_at, size, beneficiary_delta, live_id, deferred };
        self.batches.lock().unwrap_or_else(PoisonError::into_inner).push(out);
        self.append_ns.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    /// The batches are done: the fold. One task a shard on the build pool,
    /// each walking every batch's map (in the order the batches ended) for
    /// the accounts of its range and building the shard's map with
    /// `StagedGraft::add`'s rules. Every batch read the parent, so an account
    /// several batches wrote gets their deltas summed in any order, and each
    /// of their reverts is the same parent value. The batches' maps are
    /// freed on the pool afterwards, off the caller's path.
    pub fn freeze(self) -> FrozenShards {
        self.freeze_on(crate::parallel_transfer::behind_pool())
    }

    /// [`Self::freeze`] with its tasks and its frees on `pool`: the build
    /// pool by default, a pool of its own with `N42_FREEZE_POOL=own`
    /// ([`crate::parallel_transfer::behind_pool`]). The pool decides only
    /// where the tasks run; the frozen shards are the same.
    pub fn freeze_on(self, pool: &rayon::ThreadPool) -> FrozenShards {
        let at = std::time::Instant::now();
        let beneficiary = self.beneficiary;
        let count = self.count;
        let batches = self.batches.into_inner().unwrap_or_else(PoisonError::into_inner);
        if self.index && batches.len() < CONFLICT as usize {
            let contracts = self.contracts.into_inner().unwrap_or_else(PoisonError::into_inner);
            let mut batches = batches;
            // Live: every batch numbered 0..n and entered, in number order.
            batches.sort_unstable_by_key(|batch| batch.live_id);
            let entered = batches.iter().enumerate().all(|(i, batch)| batch.live_id == i);
            if let (Some(live), true) = (self.live, entered) {
                let parts = live.into_iter().map(|part| part.into_inner().unwrap_or_else(PoisonError::into_inner)).collect();
                return freeze_live(pool, at, beneficiary, count, batches, contracts, self.append_ns.into_inner(), parts);
            }
            return freeze_indexed(pool, at, beneficiary, count, batches, contracts, self.append_ns.into_inner());
        }
        let transposed = std::time::Instant::now();
        let batches_ref = &batches;
        let fold = move |index: usize| {
            let probe = TaskProbe::start();
            // A map the pool kept from an earlier block (its pages resident),
            // or a fresh one.
            let mut shard = recycled_shard();
            // The exact capacity: every batch listed its addresses here.
            let wanted: usize = batches_ref.iter().map(|batch| batch.addresses[index].len()).sum();
            shard.state.reserve(wanted);
            shard.reverts.reserve(batches_ref.iter().map(|batch| batch.revert_at[index].len()).sum());
            for batch in batches_ref {
                shard.add(
                    beneficiary,
                    batch.addresses[index].iter().filter_map(|address| batch.accounts.get_key_value(address)),
                    batch.revert_at[index].iter().filter_map(|at| batch.reverts.get(*at as usize)),
                );
            }
            (shard, probe.finish())
        };
        let folded: Vec<(Shard, TaskCost)> = {
            use rayon::prelude::*;
            pool.install(|| (0..count).into_par_iter().map(fold).collect())
        };
        let done = std::time::Instant::now();
        // Freed on the pool, a job a batch, off the caller's path.
        for batch in batches {
            pool.spawn(move || drop(batch));
        }
        let split = fold_split(folded.iter().map(|(_, cost)| cost), at, transposed, done);
        let shards: Vec<Shard> = folded.into_iter().map(|(shard, _)| shard).collect();
        let fold_ns = at.elapsed().as_nanos() as u64;
        log_folded(fold_ns, &split, None, false);
        FrozenShards {
            beneficiary,
            shards,
            indexed: None,
            contracts: self.contracts.into_inner().unwrap_or_else(PoisonError::into_inner),
            append_ns: self.append_ns.into_inner(),
            fold_ns,
            index_build_ns: 0,
            split,
        }
    }
}

/// A freeze running on a thread of its own ([`OutputShards::freeze_on_thread`]):
/// the frozen shards, the freeze's own wall, and the moment it ended.
pub type FreezeHandle = std::thread::JoinHandle<(FrozenShards, std::time::Duration, std::time::Instant)>;

impl OutputShards {
    /// [`Self::freeze`] on a thread of its own, joined by the caller when it
    /// first reads the shards (`N42_FREEZE_AFTER_SEAL`): the same call on the
    /// same input, only started where the batches end and finished beside
    /// whatever the caller does meanwhile. `Err` gives the shards back when
    /// no thread could be had (`None` only if they were lost, which the
    /// failed spawn cannot do: its closure is dropped unrun).
    pub fn freeze_on_thread(self) -> Result<FreezeHandle, Option<Box<Self>>> {
        let slot = std::sync::Arc::new(Mutex::new(Some(self)));
        let taken = std::sync::Arc::clone(&slot);
        let spawned = std::thread::Builder::new().name("n42-freeze".into()).spawn(move || {
            let at = std::time::Instant::now();
            let shards = taken.lock().unwrap_or_else(PoisonError::into_inner).take();
            // Always present: the slot is filled before the spawn and emptied
            // only here or, when the spawn failed, by the caller.
            let frozen = shards.map(Self::freeze).unwrap_or_default();
            (frozen, at.elapsed(), std::time::Instant::now())
        });
        match spawned {
            Ok(handle) => Ok(handle),
            Err(_) => Err(slot.lock().unwrap_or_else(PoisonError::into_inner).take().map(Box::new)),
        }
    }
}

/// Where the fold's wall goes: the set-up, the wait for the pool's first
/// thread, the spread of the tasks' starts, the slowest task's own work, and
/// the collect after the last one; and what the tasks' own work is made of
/// (CPU time, faults, migrations).
fn fold_split<'a>(
    costs: impl Iterator<Item = &'a TaskCost> + Clone,
    at: std::time::Instant,
    transposed: std::time::Instant,
    done: std::time::Instant,
) -> FoldSplit {
    let costs = || costs.clone();
    let first = costs().map(|cost| cost.start).min().unwrap_or(done);
    let last_start = costs().map(|cost| cost.start).max().unwrap_or(done);
    let last_end = costs().map(|cost| cost.end).max().unwrap_or(done);
    let task_max = costs().map(|cost| cost.end.duration_since(cost.start)).max().unwrap_or_default();
    FoldSplit {
        transpose_us: transposed.duration_since(at).as_micros() as u64,
        queue_us: first.saturating_duration_since(transposed).as_micros() as u64,
        skew_us: last_start.duration_since(first).as_micros() as u64,
        task_max_us: task_max.as_micros() as u64,
        tail_us: done.saturating_duration_since(last_end).as_micros() as u64,
        task_cpu_max_us: costs().map(|cost| cost.cpu_ns).max().unwrap_or(0) / 1000,
        task_minflt_max: costs().map(|cost| cost.minflt).max().unwrap_or(0),
        task_minflt_sum: costs().map(|cost| cost.minflt).sum(),
        task_migrated: costs().filter(|cost| cost.migrated).count() as u64,
        task_nivcsw_max: costs().map(|cost| cost.nivcsw).max().unwrap_or(0),
        pending_max: 0,
        pending_us_max: 0,
        drops_max: 0,
    }
}

/// The "output shards folded" line: `shard_fold_ms` is the fold's wall in
/// either mode; `index` (index build wall, conflicts) in index mode.
fn log_folded(fold_ns: u64, split: &FoldSplit, index: Option<(u64, usize)>, live: bool) {
    let (index_build_ns, index_conflicts) = index.unwrap_or((0, 0));
    tracing::info!(
        target: "payload_builder",
        index = u8::from(index.is_some()),
        // `N42_OUTPUT_INDEX_LIVE=1`: the index was entered by the batches;
        // `index_build_us` is then the conflicts' sums alone.
        index_live = u8::from(live),
        shard_fold_ms = fold_ns / 1_000_000,
        fold_us = fold_ns / 1000,
        index_build_ms = index_build_ns / 1_000_000,
        index_build_us = index_build_ns / 1000,
        index_conflicts,
        transpose_us = split.transpose_us,
        queue_us = split.queue_us,
        skew_us = split.skew_us,
        task_max_us = split.task_max_us,
        tail_us = split.tail_us,
        task_cpu_max_us = split.task_cpu_max_us,
        task_minflt_max = split.task_minflt_max,
        task_minflt_sum = split.task_minflt_sum,
        task_migrated = split.task_migrated,
        task_nivcsw_max = split.task_nivcsw_max,
        pending_max = split.pending_max,
        pending_us_max = split.pending_us_max,
        drops_max = split.drops_max,
        "output shards folded"
    );
}

/// The index mode's fold: one task a shard on the build pool, each building
/// its shard's index (`address -> batch`, the exact capacity reserved) from
/// every batch's address list for the shard, in the order the batches ended.
/// No account is read unless several batches wrote it: then the first
/// batch's account is cloned into the shard's conflicts map and every later
/// batch's change added to it (`StagedGraft::add`'s rules: deltas in batch
/// order, the first revert kept), and the index marks it [`CONFLICT`].
/// After the tasks the conflicting accounts are taken out of the batches'
/// maps, so every account lives in exactly one place.
fn freeze_indexed(
    pool: &rayon::ThreadPool,
    at: std::time::Instant,
    beneficiary: Address,
    count: usize,
    batches: Vec<BatchOut>,
    contracts: B256HashMap<RevmBytecode>,
    append_ns: u64,
) -> FrozenShards {
    let transposed = std::time::Instant::now();
    let batches_ref = &batches;
    let build = move |shard: usize| {
        let probe = TaskProbe::start();
        let wanted: usize = batches_ref.iter().map(|batch| batch.addresses[shard].len()).sum();
        let mut part = IndexPart {
            index: AddressHashMap::with_capacity_and_hasher(wanted, Default::default()),
            kept: Vec::with_capacity(batches_ref.iter().map(|batch| batch.revert_at[shard].len()).sum()),
            ..Default::default()
        };
        for (id, batch) in batches_ref.iter().enumerate() {
            let id = id as u16;
            let mut repeated: AddressHashSet = Default::default();
            for address in &batch.addresses[shard] {
                match part.index.entry(*address) {
                    alloy_primitives::map::hash_map::Entry::Vacant(slot) => {
                        slot.insert(id);
                    }
                    alloy_primitives::map::hash_map::Entry::Occupied(mut held) => {
                        let Some(account) = batch.accounts.get(address) else { continue };
                        repeated.insert(*address);
                        part.size_less += account.size_hint();
                        let first = *held.get();
                        if first != CONFLICT {
                            if let Some(base) = batches_ref.get(first as usize).and_then(|b| b.accounts.get(address)) {
                                part.conflicts.insert(*address, base.clone());
                            }
                            part.drops.push((first, *address));
                            held.insert(CONFLICT);
                        }
                        part.drops.push((id, *address));
                        if let Some(staged) = part.conflicts.get_mut(address).and_then(|a| a.info.as_mut()) {
                            add_delta(staged, account);
                        }
                    }
                }
            }
            for &pos in &batch.revert_at[shard] {
                let Some((address, _)) = batch.reverts.get(pos as usize) else { continue };
                if repeated.is_empty() || !repeated.contains(address) {
                    part.kept.push((id, pos));
                }
            }
        }
        (part, probe.finish())
    };
    let built: Vec<(IndexPart, TaskCost)> = {
        use rayon::prelude::*;
        pool.install(|| (0..count).into_par_iter().map(build).collect())
    };
    let done = std::time::Instant::now();
    finish_indexed(pool, at, transposed, done, beneficiary, count, batches, contracts, append_ns, built, None)
}

/// The live index's freeze ([`output_index_live`]): the indexes and kept
/// reverts are built; what is left is the conflicting accounts' sums, one
/// task a shard with any, in `drops` order -- the first batch's account
/// cloned, every later one's change added, as [`freeze_indexed`] does.
#[allow(clippy::too_many_arguments)]
fn freeze_live(
    pool: &rayon::ThreadPool,
    at: std::time::Instant,
    beneficiary: Address,
    count: usize,
    batches: Vec<BatchOut>,
    contracts: B256HashMap<RevmBytecode>,
    append_ns: u64,
    parts: Vec<IndexPart>,
) -> FrozenShards {
    let transposed = std::time::Instant::now();
    let batches_ref = &batches;
    // `N42_LIVE_INDEX_DEFER=1`: the batches a shard was left by, in batch
    // number order, entered here before the sums (the batches are sorted by
    // number, so a batch's position is its number).
    let mut pending: Vec<Vec<u16>> = vec![Vec::new(); parts.len()];
    for (id, batch) in batches.iter().enumerate() {
        for &shard in &batch.deferred {
            if let Some(list) = pending.get_mut(shard as usize) {
                list.push(id as u16);
            }
        }
    }
    let any_pending = pending.iter().any(|list| !list.is_empty());
    let sum = move |(mut part, pending): (IndexPart, Vec<u16>), shard: usize| {
        let probe = TaskProbe::start();
        let entries = pending.len() as u64;
        for id in pending {
            let Some(batch) = batches_ref.get(id as usize) else { continue };
            enter_part(
                &mut part,
                id,
                &batch.accounts,
                &batch.reverts,
                batch.addresses.get(shard).map_or(&[][..], Vec::as_slice),
                batch.revert_at.get(shard).map_or(&[][..], Vec::as_slice),
            );
        }
        let pending_us = probe.start.elapsed().as_micros() as u64;
        let drops = part.drops.len() as u64;
        for (id, address) in &part.drops {
            let Some(account) = batches_ref.get(*id as usize).and_then(|b| b.accounts.get(address)) else { continue };
            match part.conflicts.get_mut(address) {
                Some(staged) => {
                    if let Some(info) = staged.info.as_mut() {
                        add_delta(info, account);
                    }
                }
                None => {
                    part.conflicts.insert(*address, account.clone());
                }
            }
        }
        (part, probe.finish(), (entries, pending_us, drops))
    };
    let summed: Vec<(IndexPart, TaskCost, (u64, u64, u64))> = {
        use rayon::prelude::*;
        if any_pending || parts.iter().any(|part| !part.drops.is_empty()) {
            let work: Vec<(IndexPart, Vec<u16>)> = parts.into_iter().zip(pending).collect();
            pool.install(|| work.into_par_iter().enumerate().map(|(shard, item)| sum(item, shard)).collect())
        } else {
            parts.into_iter().map(|part| (part, TaskProbe::start().finish(), (0, 0, 0))).collect()
        }
    };
    let done = std::time::Instant::now();
    let (mut pending_max, mut pending_us_max, mut drops_max) = (0u64, 0u64, 0u64);
    let built: Vec<(IndexPart, TaskCost)> = summed
        .into_iter()
        .map(|(part, cost, (entries, pending_us, drops))| {
            pending_max = pending_max.max(entries);
            pending_us_max = pending_us_max.max(pending_us);
            drops_max = drops_max.max(drops);
            (part, cost)
        })
        .collect();
    let pending = (pending_max, pending_us_max, drops_max);
    finish_indexed(pool, at, transposed, done, beneficiary, count, batches, contracts, append_ns, built, Some(pending))
}

/// What both index freezes end with: the batches' maps kept as the output,
/// the conflicting accounts taken out of them, the sizes and the
/// beneficiary's credit summed.
#[allow(clippy::too_many_arguments)]
fn finish_indexed(
    pool: &rayon::ThreadPool,
    at: std::time::Instant,
    transposed: std::time::Instant,
    done: std::time::Instant,
    beneficiary: Address,
    count: usize,
    batches: Vec<BatchOut>,
    contracts: B256HashMap<RevmBytecode>,
    append_ns: u64,
    built: Vec<(IndexPart, TaskCost)>,
    // The live freeze's (`Some`): the most entries, the longest entry pass
    // and the most drops of one task (`FoldSplit::pending_max`).
    live: Option<(u64, u64, u64)>,
) -> FrozenShards {
    let index_build_ns = done.duration_since(transposed).as_nanos() as u64;
    let mut split = fold_split(built.iter().map(|(_, cost)| cost), at, transposed, done);
    if let Some((pending_max, pending_us_max, drops_max)) = live {
        (split.pending_max, split.pending_us_max, split.drops_max) = (pending_max, pending_us_max, drops_max);
    }
    let live = live.is_some();
    let mut state_size = 0usize;
    let mut beneficiary_delta = U256::ZERO;
    let mut kept_batches = Vec::with_capacity(batches.len());
    let mut lists = Vec::with_capacity(batches.len());
    for batch in batches {
        state_size += batch.size;
        beneficiary_delta = beneficiary_delta.saturating_add(batch.beneficiary_delta);
        kept_batches.push(IndexedBatch { accounts: batch.accounts, reverts: batch.reverts });
        lists.push((batch.addresses, batch.revert_at));
    }
    // The address lists are done with: freed on the pool.
    pool.spawn(move || drop(lists));
    let (mut index, mut conflicts, mut kept) =
        (Vec::with_capacity(count), Vec::with_capacity(count), Vec::with_capacity(count));
    let mut conflict_count = 0usize;
    // The conflicting accounts leave the batches' maps: grouped by batch
    // here (the pairs alone), removed a batch a task on the build pool --
    // serial, the removals read ~9,000 cold map slots on the seal's path.
    let mut drops_of: Vec<Vec<Address>> = vec![Vec::new(); kept_batches.len()];
    for (part, _) in &built {
        for (id, address) in &part.drops {
            if let Some(list) = drops_of.get_mut(*id as usize) {
                list.push(*address);
            }
        }
    }
    {
        use rayon::prelude::*;
        let removals: usize = drops_of.iter().map(Vec::len).sum();
        if removals >= 1024 {
            pool.install(|| {
                kept_batches.par_iter_mut().zip(drops_of.par_iter()).for_each(|(batch, list)| {
                    for address in list {
                        batch.accounts.remove(address);
                    }
                })
            });
        } else {
            for (batch, list) in kept_batches.iter_mut().zip(&drops_of) {
                for address in list {
                    batch.accounts.remove(address);
                }
            }
        }
    }
    for (part, _) in built {
        state_size = state_size.saturating_sub(part.size_less);
        conflict_count += part.conflicts.len();
        index.push(part.index);
        conflicts.push(part.conflicts);
        kept.push(part.kept);
    }
    let fold_ns = at.elapsed().as_nanos() as u64;
    log_folded(fold_ns, &split, Some((index_build_ns, conflict_count)), live);
    FrozenShards {
        beneficiary,
        shards: Vec::new(),
        indexed: Some(Box::new(Indexed {
            batches: kept_batches,
            index,
            conflicts,
            kept,
            state_size,
            beneficiary_delta,
            conflict_count,
        })),
        contracts,
        append_ns,
        fold_ns,
        index_build_ns,
        split,
    }
}

/// Whether a block's shard maps go back to [`SHARD_POOL`] when its frozen
/// shards drop, for a later block's fold to fill with its pages resident
/// (`N42_SHARD_RECYCLE=1`; off by default). The fleet-liveness bench
/// (`tests/output_shards_bench.rs`, `bench_output_shards_fold_live`: three
/// blocks' shards and bundles held, the parent's merge and roots beside)
/// takes 3-9 minor faults a block with fresh maps -- jemalloc reuses its
/// dirty pages -- and ~2,000 only with 16-32 busy threads on the fold's
/// cores, where recycling removes them but saves nothing measurable
/// (task 26.6-27.2 -> 24.8-27.3 ms at 24 load threads) and the clearing
/// thread costs the idle fold 2-3 ms. Kept for a fleet leg whose
/// `task_minflt_sum` says the node faults where the bench does not.
pub fn shard_recycle() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_SHARD_RECYCLE").is_ok_and(|v| v.trim() == "1"))
}

/// Shard maps kept with their capacity: a few blocks' worth (the parent's
/// shards, the grandparent's in its merge, the one being folded).
static SHARD_POOL: Mutex<Vec<Shard>> = Mutex::new(Vec::new());

/// How many maps the pool keeps at most.
const SHARD_POOL_MAX: usize = 4 * 16;

/// A cleared shard from the pool, or a new one.
fn recycled_shard() -> Shard {
    if !shard_recycle() {
        return Shard::default();
    }
    let kept = SHARD_POOL.lock().unwrap_or_else(PoisonError::into_inner).pop();
    kept.unwrap_or_default()
}

impl Drop for FrozenShards {
    fn drop(&mut self) {
        if self.shards.is_empty() || !shard_recycle() {
            return;
        }
        let mut shards = std::mem::take(&mut self.shards);
        // Cleared off the dropping thread (a pass over every entry, a few ms
        // for the fleet's block): the last holder may be a build.
        let spawned = std::thread::Builder::new().name("n42-shard-recycle".into()).spawn(move || {
            n42_core_layout::background_thread();
            for shard in &mut shards {
                shard.state.clear();
                shard.reverts.clear();
                shard.state_size = 0;
                shard.beneficiary_delta = U256::ZERO;
            }
            let mut pool = SHARD_POOL.lock().unwrap_or_else(PoisonError::into_inner);
            let room = SHARD_POOL_MAX.saturating_sub(pool.len());
            pool.extend(shards.into_iter().take(room));
        });
        if let Err(error) = spawned {
            tracing::debug!(target: "payload_builder", %error, "the shard maps were freed, not recycled");
        }
    }
}

/// The block's output after the batches: the shard set, read without locks.
#[derive(Debug, Default)]
pub struct FrozenShards {
    beneficiary: Address,
    /// v4: the shard maps the accounts were copied into (empty in index mode).
    shards: Vec<Shard>,
    /// Index mode: the batches' maps and the index over them.
    indexed: Option<Box<Indexed>>,
    contracts: B256HashMap<RevmBytecode>,
    append_ns: u64,
    fold_ns: u64,
    index_build_ns: u64,
    split: FoldSplit,
}

/// What [`FrozenShards::merged_timed`] spent, microseconds: the account map,
/// the revert set (copied and sorted), their assembly, and the whole (the
/// first two overlap when the merge runs them at once).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeSplit {
    /// The account map.
    pub state_us: u64,
    /// The revert set, copied and sorted.
    pub reverts_us: u64,
    /// The sorted reverts appended to the block's own.
    pub append_us: u64,
    /// The whole merge.
    pub total_us: u64,
}

/// The fold's wall time taken apart ([`OutputShards::freeze`]), microseconds:
/// what the node's fold number is made of, which a bench off the node cannot
/// say (the fold itself is 3.5-5 ms of 16 threads on the block's shape,
/// `tests/output_shards_bench.rs`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FoldSplit {
    /// Batch-major runs moved to shard-major.
    pub transpose_us: u64,
    /// From the hand-off to the pool to the first task's start.
    pub queue_us: u64,
    /// From the first task's start to the last one's.
    pub skew_us: u64,
    /// The slowest task's own work.
    pub task_max_us: u64,
    /// From the last task's end to the pool handing the shards back.
    pub tail_us: u64,
    /// The largest CPU time one task used (its thread's CPU clock): against
    /// `task_max_us`, wall much above CPU is a task blocked (faults waiting
    /// on a lock, the thread descheduled), CPU near wall is work.
    pub task_cpu_max_us: u64,
    /// The most minor page faults one task took (`RUSAGE_THREAD`).
    pub task_minflt_max: u64,
    /// The minor page faults of every task together.
    pub task_minflt_sum: u64,
    /// Tasks that ended on another CPU than they started on.
    pub task_migrated: u64,
    /// The most involuntary context switches one task took (its thread
    /// preempted by another runnable thread on its CPU).
    pub task_nivcsw_max: u64,
    /// Live index with `N42_LIVE_INDEX_DEFER=1`: the most batches one task
    /// entered at the freeze (the shards they left), the longest such entry
    /// pass in one task (us), and the most conflicting occurrences one task
    /// summed (`drops`). What the freeze's slowest task is made of.
    pub pending_max: u64,
    /// See `pending_max`.
    pub pending_us_max: u64,
    /// See `pending_max`.
    pub drops_max: u64,
}

/// One fold task's own cost, read from its thread: wall, CPU time, minor
/// faults and the CPU it ran on at the start and the end.
#[derive(Debug, Clone, Copy)]
struct TaskProbe {
    start: std::time::Instant,
    cpu_ns: u64,
    minflt: u64,
    nivcsw: u64,
    on_cpu: i32,
}

/// What [`TaskProbe::finish`] measured.
#[derive(Debug, Clone, Copy)]
struct TaskCost {
    start: std::time::Instant,
    end: std::time::Instant,
    cpu_ns: u64,
    minflt: u64,
    nivcsw: u64,
    migrated: bool,
}

impl TaskProbe {
    fn start() -> Self {
        let (cpu_ns, minflt, nivcsw, on_cpu) = thread_counters();
        Self { start: std::time::Instant::now(), cpu_ns, minflt, nivcsw, on_cpu }
    }

    fn finish(self) -> TaskCost {
        let end = std::time::Instant::now();
        let (cpu_ns, minflt, nivcsw, on_cpu) = thread_counters();
        TaskCost {
            start: self.start,
            end,
            cpu_ns: cpu_ns.saturating_sub(self.cpu_ns),
            minflt: minflt.saturating_sub(self.minflt),
            nivcsw: nivcsw.saturating_sub(self.nivcsw),
            migrated: on_cpu != self.on_cpu,
        }
    }
}

/// The calling thread's CPU time (ns), minor faults, involuntary context
/// switches and current CPU.
#[cfg(target_os = "linux")]
fn thread_counters() -> (u64, u64, u64, i32) {
    // SAFETY: both calls only write into the zeroed structs passed to them.
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let cpu_ns = if libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) == 0 {
            (ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64)
        } else {
            0
        };
        let mut usage: libc::rusage = std::mem::zeroed();
        let (minflt, nivcsw) = if libc::getrusage(libc::RUSAGE_THREAD, &mut usage) == 0 {
            (usage.ru_minflt.max(0) as u64, usage.ru_nivcsw.max(0) as u64)
        } else {
            (0, 0)
        };
        (cpu_ns, minflt, nivcsw, libc::sched_getcpu())
    }
}

#[cfg(not(target_os = "linux"))]
fn thread_counters() -> (u64, u64, u64, i32) {
    (0, 0, 0, -1)
}

impl FrozenShards {
    /// The fold's wall time taken apart.
    pub const fn fold_split(&self) -> FoldSplit {
        self.split
    }

    /// How many address ranges.
    pub fn shard_count(&self) -> usize {
        self.indexed.as_ref().map_or(self.shards.len(), |indexed| indexed.index.len())
    }

    /// Whether the output is the batches' maps under an index (`N42_OUTPUT_INDEX`).
    pub fn is_indexed(&self) -> bool {
        self.indexed.is_some()
    }

    /// Index mode: the accounts several batches wrote (summed into the
    /// shards' conflicts maps); 0 otherwise.
    pub fn index_conflicts(&self) -> usize {
        self.indexed.as_ref().map_or(0, |indexed| indexed.conflict_count)
    }

    /// Index mode: the wall time of the parallel index build, microseconds.
    pub const fn index_build_us(&self) -> u64 {
        self.index_build_ns / 1000
    }

    /// Pool time the batches spent splitting their accounts by range, summed
    /// over the batches, milliseconds.
    pub const fn append_ms(&self) -> u64 {
        self.append_ns / 1_000_000
    }

    /// The fold's wall time, the parallel pass building the shard maps,
    /// milliseconds.
    pub const fn fold_ms(&self) -> u64 {
        self.fold_ns / 1_000_000
    }

    /// The account `address` as the batches left it: one probe, into the
    /// shard that owns the address.
    /// In index mode: a probe into the shard's index, then one into the
    /// batch's map it names (or the shard's conflicts map).
    pub fn get(&self, address: &Address) -> Option<&BundleAccount> {
        if let Some(indexed) = &self.indexed {
            return indexed.get(address);
        }
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
        if let Some(indexed) = &self.indexed {
            return indexed.index.iter().map(|index| index.len()).sum();
        }
        self.shards.iter().map(|shard| shard.state.len()).sum()
    }

    /// The beneficiary's credit the batches summed, not applied.
    pub fn beneficiary_delta(&self) -> U256 {
        if let Some(indexed) = &self.indexed {
            return indexed.beneficiary_delta;
        }
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
        if state.cache.accounts.is_empty() || (self.shards.is_empty() && self.indexed.is_none()) {
            return 0;
        }
        let count = self.shards.len();
        let mut slow: AddressHashMap<(U256, U256, u64, bool)> = Default::default();
        let cached: Vec<Address> = state.cache.accounts.keys().copied().collect();
        for address in cached {
            let account = match self.indexed.as_mut() {
                Some(indexed) => {
                    let Some(account) = indexed.take(&address) else { continue };
                    account
                }
                None => {
                    let shard = &mut self.shards[shard_index(&address, count)];
                    let Some(account) = shard.state.remove(&address) else { continue };
                    shard.state_size -= account.size_hint();
                    shard.reverts.retain(|(reverted, _)| *reverted != address);
                    account
                }
            };
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
    pub fn into_staged(mut self) -> crate::parallel_transfer::StagedGraft {
        if let Some(indexed) = self.indexed.take() {
            let Indexed { batches, conflicts, kept, state_size, beneficiary_delta, .. } = *indexed;
            let mut state: AddressHashMap<BundleAccount> = Default::default();
            state.reserve(batches.iter().map(|b| b.accounts.len()).sum::<usize>() + conflicts.iter().map(|c| c.len()).sum::<usize>());
            let mut slots: Vec<Vec<Option<(Address, AccountRevert)>>> = Vec::with_capacity(batches.len());
            for batch in batches {
                state.extend(batch.accounts);
                slots.push(batch.reverts.into_iter().map(Some).collect());
            }
            for shard in conflicts {
                state.extend(shard);
            }
            let mut reverts = Vec::with_capacity(kept.iter().map(Vec::len).sum());
            for (id, at) in kept.into_iter().flatten() {
                if let Some(revert) = slots.get_mut(id as usize).and_then(|batch| batch.get_mut(at as usize)).and_then(Option::take) {
                    reverts.push(revert);
                }
            }
            let contracts = std::mem::take(&mut self.contracts);
            return crate::parallel_transfer::StagedGraft::from_parts(
                self.beneficiary,
                state,
                state_size,
                contracts,
                reverts,
                beneficiary_delta,
            );
        }
        let total = self.accounts();
        let mut state: AddressHashMap<BundleAccount> = Default::default();
        state.reserve(total);
        let mut reverts = Vec::with_capacity(total);
        let (mut size, mut delta) = (0usize, U256::ZERO);
        for shard in std::mem::take(&mut self.shards) {
            size += shard.state_size;
            delta = delta.saturating_add(shard.beneficiary_delta);
            state.extend(shard.state);
            reverts.extend(shard.reverts);
        }
        let contracts = std::mem::take(&mut self.contracts);
        crate::parallel_transfer::StagedGraft::from_parts(self.beneficiary, state, size, contracts, reverts, delta)
    }

    /// The block's one `BundleState`: the shards' accounts with `residual` --
    /// what the block's executor changed after the batches, merged and taken
    /// with its reverts -- laid over them, and the shards' reverts appended
    /// to the block's revert set (`append_reverts`, which drops the second
    /// revert of an account both touched). The same bundle a graft followed
    /// by the same executor changes leaves. The shards are shared with the
    /// next build's overlay, so they are copied, not moved.
    pub fn merged_with(&self, residual: BundleState) -> BundleState {
        self.merged(&residual)
    }

    /// [`Self::merged_with`] without taking the residual: the shards' accounts
    /// cloned straight into the one map with its capacity reserved, on the
    /// caller's thread (the build pool stays free for the next build). Built
    /// behind the seal, beside the roots, which read [`Self::view`] instead.
    pub fn merged(&self, residual: &BundleState) -> BundleState {
        self.merged_timed(residual, false).0
    }

    /// [`Self::merged`], timed in its two halves, and with `concurrent` the
    /// halves run at once: the account map on this thread, the revert set
    /// (the shards' reverts copied and sorted, the larger part of a block of
    /// transfers' merge after the map) on a scoped thread of its own. Neither
    /// half reads the other's result; the bundle is assembled from both in
    /// the same order either way, so it is the same bundle
    /// (`N42_SHARDS_MERGE_OFF_PATH`, `docs/INDUSTRY_SURVEY_2026_10.md` 11.12).
    pub fn merged_timed(&self, residual: &BundleState, concurrent: bool) -> (BundleState, MergeSplit) {
        let started = std::time::Instant::now();
        let reverts_job = || {
            let at = std::time::Instant::now();
            let reverts = self.merged_reverts();
            (reverts, at.elapsed().as_micros() as u64)
        };
        let state_job = || {
            let at = std::time::Instant::now();
            let state = self.merged_state(residual);
            (state, at.elapsed().as_micros() as u64)
        };
        let (((state, size), state_us), (reverts, reverts_us)) = if concurrent {
            std::thread::scope(|scope| {
                let reverts = std::thread::Builder::new()
                    .name("n42-merge-reverts".into())
                    .spawn_scoped(scope, reverts_job);
                let state = state_job();
                let reverts = match reverts {
                    Ok(handle) => handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                    // No thread to be had: the half here, after the other.
                    Err(_) => reverts_job(),
                };
                (state, reverts)
            })
        } else {
            let state = state_job();
            (state, reverts_job())
        };
        let mut contracts = self.contracts.clone();
        contracts.extend(residual.contracts.iter().map(|(hash, code)| (*hash, code.clone())));
        let block_reverts = residual.reverts.clone();
        let reverts_size = block_reverts.iter().map(Vec::len).sum();
        let state_size = usize::try_from(size.max(0)).unwrap_or(usize::MAX);
        let mut bundle = BundleState { state, contracts, reverts: block_reverts, state_size, reverts_size };
        let append_at = std::time::Instant::now();
        crate::parallel_transfer::append_sorted_reverts(&mut bundle, reverts);
        let split = MergeSplit {
            state_us,
            reverts_us,
            append_us: append_at.elapsed().as_micros() as u64,
            total_us: started.elapsed().as_micros() as u64,
        };
        (bundle, split)
    }

    /// The merged account map and its size: the shards' accounts with the
    /// residual's laid over them, each account cloned once into the one map.
    fn merged_state(&self, residual: &BundleState) -> (AddressHashMap<BundleAccount>, i128) {
        let newer = &residual.state;
        let total: usize = self.accounts() + newer.len();
        let mut state: AddressHashMap<BundleAccount> = Default::default();
        state.reserve(total);
        let mut size = residual.state_size as i128;
        size += self.indexed.as_ref().map_or(0, |indexed| indexed.state_size as i128);
        // One pass, each account cloned straight into its slot of the one
        // map: the copy into per-shard vectors on the build pool first, then
        // moved into the map, wrote and read every account a second time and
        // put sixteen threads of memory traffic beside the roots. (Index
        // mode: the batches' maps and the conflicts, each account once.)
        size += self.shards.iter().map(|shard| shard.state_size as i128).sum::<i128>();
        let mut put = |map: &AddressHashMap<BundleAccount>| {
            if newer.is_empty() {
                state.extend(map.iter().map(|(address, account)| (*address, account.clone())));
                return;
            }
            for (address, account) in map {
                match newer.get(address) {
                    Some(over) => {
                        let merged = overlaid(account, over);
                        size += merged.size_hint() as i128 - account.size_hint() as i128 - over.size_hint() as i128;
                        state.insert(*address, merged);
                    }
                    None => {
                        state.insert(*address, account.clone());
                    }
                }
            }
        };
        for shard in &self.shards {
            put(&shard.state);
        }
        if let Some(indexed) = &self.indexed {
            for map in indexed.batches.iter().map(|batch| &batch.accounts).chain(indexed.conflicts.iter()) {
                put(map);
            }
        }
        for (address, account) in newer {
            if !self.holds(address) {
                state.insert(*address, account.clone());
            }
        }
        (state, size)
    }

    /// The shards' reverts, copied and sorted by address as `append_reverts`
    /// sorts them, ready for [`crate::parallel_transfer::append_sorted_reverts`].
    fn merged_reverts(&self) -> Vec<(Address, AccountRevert)> {
        let mut reverts = Vec::with_capacity(self.shards.iter().map(|shard| shard.reverts.len()).sum());
        for shard in &self.shards {
            reverts.extend(shard.reverts.iter().cloned());
        }
        if let Some(indexed) = &self.indexed {
            reverts.reserve(indexed.kept.iter().map(Vec::len).sum());
            reverts.extend(indexed.kept.iter().flatten().filter_map(|&slot| indexed.revert(slot)).cloned());
        }
        crate::parallel_transfer::sort_reverts(&mut reverts);
        reverts
    }

    /// The accounts both the batches and the block's executor changed, as
    /// the merge leaves them (the newer value against the parent's original,
    /// the storage of both): the few [`Self::view`] cannot point into the
    /// shards or the residual for. Usually none.
    pub fn overlaps(&self, residual: &BundleState) -> Vec<(Address, BundleAccount)> {
        residual
            .state
            .iter()
            .filter_map(|(address, over)| self.get(address).map(|account| (*address, overlaid(account, over))))
            .collect()
    }

    /// The block's post-state accounts without a merge: the shards' (less
    /// the overlapping ones), the residual's not in the shards, and
    /// `overlaps` ([`Self::overlaps`]) -- each address once, the same set of
    /// values [`Self::merged`] holds. What the QMDB root
    /// (`n42_qmdb_reth::sorted_operations_from_accounts`) and the hashed
    /// post-state ([`hashed_post_state_of`]) read behind the seal.
    pub fn view<'a>(
        &'a self,
        residual: &'a BundleState,
        overlaps: &'a [(Address, BundleAccount)],
    ) -> Vec<(&'a Address, &'a BundleAccount)> {
        let mut view = Vec::with_capacity(self.accounts() + residual.state.len());
        for shard in &self.shards {
            if overlaps.is_empty() {
                view.extend(shard.state.iter());
            } else {
                view.extend(shard.state.iter().filter(|(address, _)| !residual.state.contains_key(*address)));
            }
        }
        if let Some(indexed) = &self.indexed {
            if overlaps.is_empty() {
                view.extend(indexed.iter());
            } else {
                view.extend(indexed.iter().filter(|(address, _)| !residual.state.contains_key(*address)));
            }
        }
        view.extend(residual.state.iter().filter(|(address, _)| !self.holds(address)));
        view.extend(overlaps.iter().map(|(address, account)| (address, account)));
        view
    }
}

/// An account the batches wrote and the executor changed again: the newer
/// value, against the parent's original the shard carries, with the storage
/// of both (the newer slots winning).
fn overlaid(account: &BundleAccount, over: &BundleAccount) -> BundleAccount {
    let mut merged = over.clone();
    merged.original_info = account.original_info.clone();
    let mut storage = account.storage.clone();
    storage.extend(over.storage.iter().map(|(slot, value)| (*slot, *value)));
    merged.storage = storage;
    merged
}

/// The hashed post-state of a block's accounts given as a list
/// ([`FrozenShards::view`]): the provider's chunked `hashed_post_state` over a
/// bundle (`hashed_post_state_from_bundle`), without the bundle. It does not
/// zero a destroyed account's storage from the database: a caller whose
/// accounts include one (`BundleAccount::was_destroyed` with an original)
/// goes through the provider instead.
pub fn hashed_post_state_of(accounts: &[(&Address, &BundleAccount)]) -> HashedPostState {
    const PARALLEL_FROM: usize = 8192;
    if accounts.len() < PARALLEL_FROM {
        return HashedPostState::from_bundle_state::<reth_trie::KeccakKeyHasher>(accounts.iter().copied());
    }
    use rayon::prelude::*;
    let chunks: Vec<HashedPostState> = accounts
        .par_chunks(4096)
        .map(|chunk| HashedPostState::from_bundle_state::<reth_trie::KeccakKeyHasher>(chunk.iter().copied()))
        .collect();
    let mut hashed = HashedPostState::with_capacity(accounts.len());
    for chunk in chunks {
        hashed.extend(chunk);
    }
    hashed
}

/// Whether any of `accounts` was destroyed over an existing account: its
/// storage has to be zeroed from the database, which only the provider's
/// `hashed_post_state` does.
pub fn any_destroyed(accounts: &[(&Address, &BundleAccount)]) -> bool {
    accounts.iter().any(|(_, account)| account.was_destroyed() && account.original_info.is_some())
}

/// The parent's shard set as a state provider layer: an account or slot the
/// batches wrote is answered by its shard, anything else by `historical`. In
/// index mode (`N42_OUTPUT_INDEX=1`) the same layer is the index layer: a
/// probe into the shard's index, then one into the batch's map it names or
/// the shard's conflicts map ([`FrozenShards::get`]). The
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
        fn multiproof_v2(&self, input: TrieInput, targets: reth_trie::MultiProofTargetsV2) -> ProviderResult<reth_trie::DecodedMultiProofV2>;
        fn witness(&self, input: TrieInput, target: HashedPostState, mode: ExecutionWitnessMode) -> ProviderResult<Vec<Bytes>>;
    }
    HashedPostStateProvider {
        fn hashed_post_state(&self, bundle_state: &BundleState) -> ProviderResult<HashedPostState>;
    }
);

#[cfg(test)]
mod frozen_tests {
    use super::*;
    use revm::{database::BundleState, state::AccountInfo};

    fn addr(i: u8) -> Address {
        Address::with_last_byte(i)
    }

    fn info(nonce: u64, balance: u64) -> AccountInfo {
        AccountInfo { nonce, balance: U256::from(balance), ..Default::default() }
    }

    /// A batch's bundle: each `(address, before, after)` moved from one value to the other.
    type Move = (u8, (u64, u64), (u64, u64));

    fn batch(moves: &[Move]) -> BundleState {
        let mut builder = BundleState::builder(1..=1);
        for (a, (n0, b0), (n1, b1)) in moves {
            builder = builder
                .state_original_account_info(addr(*a), info(*n0, *b0))
                .state_present_account_info(addr(*a), info(*n1, *b1));
        }
        builder.build()
    }

    /// Two batches that both wrote account 5 (a conflict) and the beneficiary 1.
    fn frozen(index: bool) -> FrozenShards {
        let shards = OutputShards::with_index_live(addr(1), 8, 4, index, false);
        shards.add(batch(&[(2, (0, 100), (1, 90)), (5, (0, 50), (0, 60)), (1, (0, 0), (0, 7))]));
        shards.add(batch(&[(3, (0, 100), (1, 80)), (5, (0, 50), (0, 70)), (1, (0, 0), (0, 7))]));
        shards.freeze()
    }

    #[test]
    fn both_modes_hold_the_same_accounts() {
        for index in [false, true] {
            let frozen = frozen(index);
            assert_eq!(frozen.is_indexed(), index);
            assert_eq!(frozen.shard_count(), 4, "index {index}");
            // Account 5 is one account, however many batches wrote it; the beneficiary is not an account here.
            let held: Vec<u8> = (1..=6).filter(|a| frozen.holds(&addr(*a))).collect();
            assert_eq!(held, vec![2, 3, 5], "index {index}");
            assert_eq!(frozen.accounts(), 3, "index {index}");
            assert!(frozen.get(&addr(9)).is_none());
            assert_eq!(frozen.get(&addr(2)).and_then(|a| a.info.as_ref()).map(|i| i.balance), Some(U256::from(90u64)));
            assert_eq!(frozen.get(&addr(3)).and_then(|a| a.info.as_ref()).map(|i| i.nonce), Some(1));
            // Both batches credited the beneficiary 7: summed, not applied.
            assert_eq!(frozen.beneficiary_delta(), U256::from(14u64), "index {index}");
        }
    }

    #[test]
    fn conflicting_writes_sum_their_deltas_in_both_modes() {
        for index in [false, true] {
            let frozen = frozen(index);
            let five = frozen.get(&addr(5)).expect("written by both");
            // Each batch moved 50 -> 60 and 50 -> 70, so the block's net is +10 +20 on the parent's 50.
            assert_eq!(five.info.as_ref().map(|i| i.balance), Some(U256::from(80u64)), "index {index}");
            assert_eq!(five.original_info.as_ref().map(|i| i.balance), Some(U256::from(50u64)), "index {index}");
            if index {
                assert_eq!(frozen.index_conflicts(), 1);
            } else {
                assert_eq!(frozen.index_conflicts(), 0);
            }
        }
    }

    #[test]
    fn the_merge_and_the_view_hold_the_same_accounts_with_and_without_an_executor_change() {
        for index in [false, true] {
            let frozen = frozen(index);
            // The executor changed account 2 again (a withdrawal) and created 8.
            let residual = BundleState::builder(1..=1)
                .state_original_account_info(addr(2), info(1, 90))
                .state_present_account_info(addr(2), info(1, 95))
                .state_present_account_info(addr(8), info(0, 3))
                .build();
            let overlaps = frozen.overlaps(&residual);
            assert_eq!(overlaps.len(), 1, "only account 2 was written by both");
            assert_eq!(overlaps[0].0, addr(2));
            // The newer value over the parent's original.
            assert_eq!(overlaps[0].1.info.as_ref().map(|i| i.balance), Some(U256::from(95u64)));
            assert_eq!(overlaps[0].1.original_info.as_ref().map(|i| i.balance), Some(U256::from(100u64)));

            let merged = frozen.merged(&residual);
            let view = frozen.view(&residual, &overlaps);
            let mut viewed: Vec<(Address, Option<U256>)> =
                view.iter().map(|(a, acc)| (**a, acc.info.as_ref().map(|i| i.balance))).collect();
            viewed.sort_by_key(|(a, _)| *a);
            let mut merged_accounts: Vec<(Address, Option<U256>)> =
                merged.state.iter().map(|(a, acc)| (*a, acc.info.as_ref().map(|i| i.balance))).collect();
            merged_accounts.sort_by_key(|(a, _)| *a);
            assert_eq!(viewed, merged_accounts, "index {index}: the view is the merge without the copy");
            assert_eq!(merged.state.len(), 4, "2, 3, 5 and the executor's 8");
            assert_eq!(merged.state[&addr(2)].info.as_ref().map(|i| i.balance), Some(U256::from(95u64)));
            assert_eq!(frozen.merged_with(residual.clone()).state.len(), 4);
            // With nothing for the executor to add, the merge is the shards alone.
            let bare = frozen.merged(&BundleState::default());
            assert_eq!(bare.state.len(), 3);
            assert!(frozen.overlaps(&BundleState::default()).is_empty());
        }
    }

    /// `N42_SHARDS_MERGE_OFF_PATH`: the merge with its two halves at once is
    /// the same bundle as the merge one half after the other -- accounts,
    /// sizes, contracts and the sorted revert set -- in both modes, at a size
    /// that takes the parallel revert sort (4,096 and more), with conflicting
    /// writes and an executor change over the shards.
    #[test]
    fn the_concurrent_merge_is_the_on_path_merge() {
        let wide = |i: u32| Address::from_word(B256::from(U256::from(0x1000_0000u64 + u64::from(i))));
        for (index, live) in [(false, false), (true, false), (true, true)] {
            let shards = OutputShards::with_index_live(addr(1), 12_000, 16, index, live);
            for batch_no in 0..8u32 {
                let mut builder = BundleState::builder(1..=1);
                for i in 0..1_200u32 {
                    let account = wide(batch_no * 1_200 + i);
                    builder = builder
                        .state_original_account_info(account, info(0, 1_000))
                        .state_present_account_info(account, info(1, 900 + u64::from(i % 7)))
                        .revert_account_info(1, account, Some(Some(info(0, 1_000))));
                }
                // One account every batch writes: a conflict in index mode.
                builder = builder
                    .state_original_account_info(addr(5), info(0, 50))
                    .state_present_account_info(addr(5), info(0, 50 + u64::from(batch_no)))
                    .revert_account_info(1, addr(5), Some(Some(info(0, 50))));
                shards.add(builder.build());
            }
            let frozen = shards.freeze();
            let residual = BundleState::builder(1..=1)
                .state_original_account_info(wide(3), info(1, 900))
                .state_present_account_info(wide(3), info(1, 950))
                .state_present_account_info(addr(8), info(0, 3))
                .revert_account_info(1, addr(8), Some(None))
                .build();
            let on_path = frozen.merged(&residual);
            let (concurrent, split) = frozen.merged_timed(&residual, true);
            let (sequential, _) = frozen.merged_timed(&residual, false);
            assert_eq!(on_path.state.len(), 9_600 + 2, "index {index} live {live}");
            assert!(on_path.reverts.iter().map(Vec::len).sum::<usize>() >= 4_096);
            assert_eq!(concurrent, on_path, "index {index} live {live}: concurrent against on-path");
            assert_eq!(sequential, on_path, "index {index} live {live}: sequential against on-path");
            assert!(split.total_us >= split.append_us);
        }
    }

    #[test]
    fn the_timing_accessors_report_in_the_units_they_name() {
        let at = std::time::Instant::now();
        let plain = frozen(false);
        let wall_ms = at.elapsed().as_millis() as u64;
        // The ranged fold builds no index, and its wall is inside what the caller saw.
        assert_eq!(plain.index_build_us(), 0);
        assert!(plain.fold_ms() <= wall_ms, "fold {} ms of {} ms", plain.fold_ms(), wall_ms);
        assert!(plain.append_ms() <= wall_ms);
        // One task's own work never exceeds the whole fold's wall.
        assert!(plain.fold_split().task_max_us <= (plain.fold_ms() + 1) * 1000 + 1000);
        // The indexed fold reports its index build separately, inside the fold.
        let indexed = frozen(true);
        assert!(indexed.index_build_us() / 1000 <= indexed.fold_ms() + 1);
    }

    #[test]
    fn a_hashed_post_state_over_a_list_matches_the_bundles() {
        let bundle = batch(&[(2, (0, 100), (1, 90)), (3, (0, 100), (1, 80)), (4, (2, 5), (3, 6))]);
        let list: Vec<(&Address, &BundleAccount)> = bundle.state.iter().collect();
        let from_list = hashed_post_state_of(&list);
        let from_bundle = HashedPostState::from_bundle_state::<reth_trie::KeccakKeyHasher>(bundle.state.iter());
        assert_eq!(from_list.accounts.len(), 3);
        assert_eq!(from_list, from_bundle);
        assert!(!any_destroyed(&list));
    }

    #[test]
    fn a_shard_request_is_clamped_to_at_least_one_range() {
        let shards = OutputShards::with_index_live(addr(1), 0, 0, false, false);
        shards.add(batch(&[(2, (0, 1), (0, 2))]));
        let frozen = shards.freeze();
        assert_eq!(frozen.shard_count(), 1);
        assert!(frozen.holds(&addr(2)));
        // An empty block freezes to nothing, and nothing answers.
        let empty = OutputShards::with_index_live(addr(1), 0, 3, false, false).freeze();
        assert_eq!((empty.accounts(), empty.beneficiary_delta()), (0, U256::ZERO));
        assert!(!empty.holds(&addr(2)));
        assert!(empty.merged(&BundleState::default()).state.is_empty());
    }
}
