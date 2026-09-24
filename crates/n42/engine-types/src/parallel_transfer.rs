// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: Apache-2.0

//! A follower's execution of a block of plain transfers on the worker pool.
//!
//! The serial import executes 163,000 transfers in ~145 ms, one after the
//! other, on one core, while the box has thirty more idle; and that execution
//! is on the fleet's cycle twice over (the followers vote after it, the
//! leader builds ahead against it). Plain transfers between externally owned
//! accounts conflict only through the accounts they touch, so the block is
//! partitioned into groups that share no sender or recipient, each group is
//! executed in block order on its own [`State`] over the parent, and the
//! groups' account changes are folded into one state as *deltas* -- which is
//! what lets the block's rewards (withdrawals) and the beneficiary's tips,
//! both applied to accounts several groups may touch, come out the same as
//! the serial executor's.
//!
//! Anything the transfer path refuses -- a contract call, a transaction the
//! path would send to the interpreter, a transfer to or from the beneficiary
//! -- makes the whole block fall back to the serial executor: this path is
//! never wrong, only absent.

use alloy_primitives::{Address, U256};
use n42_tx_types::{Block, N42Primitives as EthPrimitives, Receipt};
use alloy_consensus::TransactionEnvelope as _;
use reth_evm::{
    execute::{BlockExecutionError, BlockExecutor as _, BlockExecutorFactory},
    ConfigureEvm, Evm as _, EvmFactory as _,
};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{RecoveredBlock, SignedTransaction};
use reth_revm::db::State;
use revm::{
    context::TxEnv,
    database::{states::bundle_state::BundleRetention, states::CacheAccount, AccountRevert, BundleAccount, BundleState, PlainAccount},
    state::{Account, AccountStatus},
    Database, DatabaseCommit,
};

use crate::fast_transfer::N42EvmFactory;

/// The block executor factory of a node with the transfer path: what
/// [`execute_transfers`] requires of its EVM configuration.
pub type FastExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<reth_chainspec::ChainSpec>;

/// The executor's phase timings, in milliseconds: partitioning, the groups'
/// execution (wall), the merge into the block's state, the finish.
#[derive(Debug, Clone, Copy, Default)]
pub struct Phases {
    /// Partitioning the transactions into conflict-free groups.
    pub partition_ms: u64,
    /// Of `partition_ms`: the transactions' EVM environments, built on the
    /// worker pool.
    pub env_us: u64,
    /// Packing the groups into batches and staging the graft, between the
    /// partition and the execution.
    pub batch_us: u64,
    /// The groups' execution on the worker pool, wall time.
    pub groups_ms: u64,
    /// The batches' gas placed in block order after the execution.
    pub gas_us: u64,
    /// The block's receipts, built in block order from that gas.
    pub receipts_us: u64,
    /// Freeing the transactions' environments, the groups and the batches'
    /// bundles, done here rather than at the return so the line can name it.
    pub drop_us: u64,
    /// The whole call, so a caller's `exec_ms` minus this is what it spends
    /// outside the executor (loop202: 40 of the follower's 133 ms had no
    /// name because the line stopped at the four phases below).
    pub total_us: u64,
    /// Folding the groups' changes into the block's state.
    pub merge_ms: u64,
    /// Of `merge_ms`: the graft (or fold) of the batches' bundles.
    pub graft_ms: u64,
    /// Of `merge_ms`: the state's own transition merge and the bundle take.
    pub take_ms: u64,
    /// Of `merge_ms`: appending and sorting the grafted reverts.
    pub reverts_ms: u64,
    /// The batches' results placed in candidate order (the build).
    pub collect_ms: u64,
    /// Pre- and post-execution changes and the bundle.
    pub finish_ms: u64,
    /// How many groups there were.
    pub groups: usize,
    /// How many batches of groups ran (the build's [`execute_for_build`]
    /// runs a sender per group and several groups per batch).
    pub batches: usize,
    /// `N42_PHASE_TIMERS=1` (plan v6 6.5/6.6): the block's transfers summed
    /// over every batch that ran part of it -- see
    /// [`crate::fast_transfer::TransferTimers`]. Zero when the flag is off.
    pub transfer_timers: crate::fast_transfer::TransferTimers,
}

/// Why the parallel path did not run; the caller executes serially.
#[derive(Debug)]
pub enum NotParallel {
    /// A transaction the transfer path does not take (index).
    NotATransfer(usize),
    /// A transfer to or from the block's beneficiary (index).
    TouchesBeneficiary(usize),
    /// A transfer failed on the path (index, message): the serial executor
    /// produces the exact error.
    Failed(usize, String),
    /// The parent's state could not be opened for a group.
    NoState,
}

impl std::fmt::Display for NotParallel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotATransfer(i) => write!(f, "transaction {i} is not a plain transfer"),
            Self::TouchesBeneficiary(i) => write!(f, "transaction {i} touches the beneficiary"),
            Self::Failed(i, m) => write!(f, "transaction {i} failed on the transfer path: {m}"),
            Self::NoState => write!(f, "the parent's state could not be opened"),
        }
    }
}

/// Disjoint-set forest over the accounts a block touches.
struct Groups {
    parent: Vec<usize>,
}

impl Groups {
    fn with_capacity(n: usize) -> Self {
        Self { parent: Vec::with_capacity(n) }
    }
    /// A party of its own, returned as its index. The forest grows with the
    /// map of addresses rather than after it, so the partition needs no
    /// second pass over the block to union what the first pass already saw.
    fn add(&mut self) -> usize {
        let next = self.parent.len();
        self.parent.push(next);
        next
    }
    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.parent[a] = b;
        }
    }
}


/// Partitions transfers into groups that share no sender or recipient: the
/// groups can execute in any order relative to each other. Returns the groups
/// (indices into `txs`, in order) and the number of distinct parties.
///
/// [`partition_shared`] is the same partition with the search for the
/// addresses that repeat done on the worker pool; `N42_FOLLOWER_PARTITION_HASH=1`
/// picks it.
///
/// Three things this does that the straightforward version did not, all of
/// them the same partition (loop202: the phase was 31-33 ms on a four-node
/// leg, 190 ns a transfer for what is two hash look-ups and a union):
///
/// - **The sender's party is memoised across a run.** The queue lays a
///   sender's transactions out in runs (`N42_TX_QUEUE_RUN`, 64 on the fleet;
///   a block's 163,000 transfers come from ~380 senders), so the previous
///   transaction's sender is the same address almost every time and half the
///   hashing is a comparison instead. The memo returns what the map would,
///   so the parties, the unions and the groups are identical.
/// - **The map is sized for the parties a block has, not two per
///   transaction.** A full transfer block has ~380 senders and ~150,000
///   distinct recipients (a leg's `updated`), so `txs.len() * 2` asked for
///   twice the buckets it ever fills, and this phase is memory-bound.
/// - **The forest grows with the map** and the unions happen in the first
///   pass, in the same order, which removes the edge list (2.6 MB a block)
///   and a pass over it. Only the sender's party is kept per transaction,
///   since that is all the grouping pass reads.
pub fn partition(txs: &[TxEnv], beneficiary: Address) -> Result<(Vec<Vec<usize>>, usize), NotParallel> {
    let mut index_of: alloy_primitives::map::AddressHashMap<usize> = alloy_primitives::map::AddressHashMap::default();
    index_of.reserve(txs.len());
    let mut sets = Groups::with_capacity(txs.len());
    let mut of_tx: Vec<usize> = Vec::with_capacity(txs.len());
    let mut last_caller: Option<(Address, usize)> = None;
    for (i, tx) in txs.iter().enumerate() {
        let alloy_primitives::TxKind::Call(to) = tx.kind else {
            return Err(NotParallel::NotATransfer(i));
        };
        if !tx.data.is_empty() {
            return Err(NotParallel::NotATransfer(i));
        }
        if tx.caller == beneficiary || to == beneficiary {
            return Err(NotParallel::TouchesBeneficiary(i));
        }
        let from = match last_caller {
            Some((address, party)) if address == tx.caller => party,
            _ => {
                let party = *index_of.entry(tx.caller).or_insert_with(|| sets.add());
                last_caller = Some((tx.caller, party));
                party
            }
        };
        let to_party = *index_of.entry(to).or_insert_with(|| sets.add());
        sets.union(from, to_party);
        of_tx.push(from);
    }
    let parties = index_of.len();
    drop(index_of);
    let mut group_of_root: Vec<usize> = vec![usize::MAX; parties];
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, from) in of_tx.iter().enumerate() {
        let root = sets.find(*from);
        if group_of_root[root] == usize::MAX {
            group_of_root[root] = groups.len();
            groups.push(Vec::new());
        }
        groups[group_of_root[root]].push(i);
    }
    Ok((groups, parties))
}

/// Whether `N42_FOLLOWER_PARTITION_HASH=1` is set: the follower's partition
/// finds the addresses a block repeats on the worker pool
/// ([`partition_shared`]) instead of probing one map per transaction.
///
/// Off by default until a leg reads it: the partition is 31-33 ms of a
/// four-node follower's 131-136 ms execution (loop202) and the bench says
/// this halves it, but loop91 is the warning -- a partition made 20 ms
/// cheaper by grouping differently gave every millisecond back in the
/// batches. This one returns the same groups, so there is nothing to give
/// back, which is exactly what a leg has to confirm.
pub fn partition_hash() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_PARTITION_HASH").is_ok_and(|v| v == "1"))
}

/// A 64-bit hash of an address, for [`partition_shared`]'s duplicate search.
/// The address's own bytes are already a hash; the multiply is there so that
/// two accounts differing only in their low bytes -- which the flood's
/// recipients do -- do not collide.
#[inline]
fn address_hash(address: &Address) -> u64 {
    let mut low = [0u8; 8];
    low.copy_from_slice(&address.0[12..]);
    let mut high = [0u8; 8];
    high.copy_from_slice(&address.0[4..12]);
    let a = u64::from_le_bytes(low).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let b = u64::from_le_bytes(high).wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    let mut h = a ^ b.rotate_left(31) ^ u64::from(u32::from_le_bytes([address.0[0], address.0[1], address.0[2], address.0[3]]));
    h ^= h >> 29;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^ (h >> 32)
}

/// [`partition`] with the search for the addresses a block repeats done on
/// the worker pool.
///
/// The serial partition is one random probe of a ~260,000-bucket map per
/// transaction, and almost every one of them is wasted: of a full block's
/// 163,000 recipients ~150,000 appear once and so join nothing. What the
/// grouping needs is only the addresses that appear more than once, or that
/// are also senders, and those come out of sorting 163,000 hashes on the
/// pool -- sequential work that scales -- leaving a serial pass that probes
/// a table of ~10,000 entries, which is L2-resident.
///
/// Two addresses whose hashes collide land in one group. That is sound: a
/// group is a set of transactions that must not run beside another, and a
/// coarser partition is still one -- the transactions of a group execute in
/// block order on a state of their own either way. At 163,000 addresses the
/// chance of one collision is about 1 in 10^9.
pub fn partition_shared(txs: &[TxEnv], beneficiary: Address) -> Result<(Vec<Vec<usize>>, usize), NotParallel> {
    use rayon::prelude::*;

    // The shape checks, on the pool, reported at the earliest index the
    // serial partition would have reached.
    let refused = txs
        .par_iter()
        .enumerate()
        .filter_map(|(i, tx)| {
            let alloy_primitives::TxKind::Call(to) = tx.kind else {
                return Some((i, NotParallel::NotATransfer(i)));
            };
            if !tx.data.is_empty() {
                return Some((i, NotParallel::NotATransfer(i)));
            }
            if tx.caller == beneficiary || to == beneficiary {
                return Some((i, NotParallel::TouchesBeneficiary(i)));
            }
            None
        })
        .min_by_key(|(i, _)| *i);
    if let Some((_, why)) = refused {
        return Err(why);
    }
    let to_hash: Vec<u64> =
        txs.par_iter().map(|tx| tx.kind.to().map_or(0, address_hash)).collect();

    // The senders and their parties: ~380 a block, and the queue lays each
    // one's transactions out in a run, so the memo answers nearly every
    // transaction with a comparison.
    let mut sets = Groups::with_capacity(txs.len() / 8 + 64);
    let mut party_of: alloy_primitives::map::AddressHashMap<usize> = alloy_primitives::map::AddressHashMap::default();
    let mut of_tx: Vec<usize> = Vec::with_capacity(txs.len());
    let mut last_caller: Option<(Address, usize)> = None;
    for tx in txs {
        let from = match last_caller {
            Some((address, party)) if address == tx.caller => party,
            _ => {
                let party = *party_of.entry(tx.caller).or_insert_with(|| sets.add());
                last_caller = Some((tx.caller, party));
                party
            }
        };
        of_tx.push(from);
    }

    // The addresses that can join two senders: a recipient the block names
    // twice, or one that is a sender. A sender starts in the table under its
    // own party, so a transfer to it unions with that sender and not with a
    // party of its own.
    let mut shared: std::collections::HashMap<u64, usize, alloy_primitives::map::FbBuildHasher<8>> =
        std::collections::HashMap::with_capacity_and_hasher(party_of.len() * 2, Default::default());
    for (address, party) in &party_of {
        shared.insert(address_hash(address), *party);
    }
    let mut sorted = to_hash.clone();
    sorted.par_sort_unstable();
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i + 1;
        while j < sorted.len() && sorted[j] == sorted[i] {
            j += 1;
        }
        if j - i > 1 {
            let next = &mut sets;
            shared.entry(sorted[i]).or_insert_with(|| next.add());
        }
        i = j;
    }
    drop(sorted);

    // The unions, over a table small enough to stay in cache.
    for (i, hash) in to_hash.iter().enumerate() {
        if let Some(party) = shared.get(hash) {
            sets.union(of_tx[i], *party);
        }
    }
    let parties = sets.parent.len();
    drop(shared);
    drop(to_hash);

    let mut group_of_root: Vec<usize> = vec![usize::MAX; parties];
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, from) in of_tx.iter().enumerate() {
        let root = sets.find(*from);
        if group_of_root[root] == usize::MAX {
            group_of_root[root] = groups.len();
            groups.push(Vec::new());
        }
        groups[group_of_root[root]].push(i);
    }
    Ok((groups, parties))
}

/// Groups candidate transfers by sender: every sender's transfers, in
/// candidate order, form one group. `keys` is each candidate's (sender,
/// recipient). Recipients do not join groups -- a transfer only adds to its
/// recipient's balance, and additions commute, so [`graft_bundles`] can fold
/// batches that share a recipient in any order. (Grouping by connected
/// component, as the follower's [`partition`] does, merges a full block of
/// random transfers into a handful of giant groups: round 43.)
///
/// Returns `Err` when a candidate touches the beneficiary.
pub fn partition_by_sender(keys: &[(Address, Address)], beneficiary: Address) -> Result<Vec<Vec<usize>>, NotParallel> {
    let mut group_of: alloy_primitives::map::AddressHashMap<usize> = alloy_primitives::map::AddressHashMap::default();
    group_of.reserve(keys.len() / 8);
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, (sender, to)) in keys.iter().enumerate() {
        if *sender == beneficiary || *to == beneficiary {
            return Err(NotParallel::TouchesBeneficiary(i));
        }
        let next = groups.len();
        let g = *group_of.entry(*sender).or_insert(next);
        if g == next {
            groups.push(Vec::new());
        }
        groups[g].push(i);
    }
    Ok(groups)
}

/// The worker pool the build's batches run on: its own, so that they do not
/// queue behind the global pool's other jobs (the QMDB root of the block
/// before, a follower import). `N42_PARALLEL_BUILD_THREADS` threads, 16 by
/// default.
pub fn build_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::env::var("N42_PARALLEL_BUILD_THREADS").ok().and_then(|v| v.parse().ok()).filter(|n| *n > 0).unwrap_or(16);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("n42-build-{i}"))
            .build()
            .expect("a thread pool for the parallel build")
    })
}

/// Whether the leader's parallel build reads the block's accounts ahead of
/// its execution (`N42_BUILD_PREFETCH=1`, [`WarmAccounts`]): each batch the
/// puller hands over is read on the worker pool while the pull and the prep
/// run, and the execution's batches read those accounts from memory rather
/// than through the parent's state provider. Off by default until a leg says
/// the execution falls by more than the pool time it costs.
pub fn build_prefetch() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_PREFETCH").is_ok_and(|v| v == "1"))
}

/// Shards of [`WarmAccounts`]: enough that the pool's prefetch jobs seldom
/// meet on one lock, few enough that each job takes every lock once.
const WARM_SHARDS: usize = 64;

/// The shard an address lands in: its first byte, which is uniform for the
/// flood's addresses and for anything derived from a hash.
#[inline]
fn warm_shard(address: &Address) -> usize {
    address.0[0] as usize % WARM_SHARDS
}

/// An account as the parent's state answers it.
type WarmInfo = Option<revm::state::AccountInfo>;

/// The block's accounts as the parent's state has them, read ahead of the
/// execution (`N42_BUILD_PREFETCH=1`).
///
/// The layer the parallel build's batches read is the parent's state
/// provider itself -- `StateProviderDatabase<StateProviderBox>`, a
/// `MemoryOverlayStateProvider` over the chain's state at the grandparent,
/// whose base answers from the QMDB read view -- behind each batch's own
/// `State` cache, which starts empty. Nothing there can be warmed from
/// another thread: the read view (`QmdbReadView`) keeps no cache, only an
/// offset index and a mapping of the entry file, and a batch's `State` is
/// made on the batch's thread. So the prefetch keeps its own layer: what the
/// provider answered for each address, consulted by [`WarmDb`] before the
/// provider. Written by the pool's jobs through per-shard locks while the
/// pull runs, then [`frozen`](Self::freeze) into plain maps the batches read
/// without a lock.
#[derive(Debug)]
pub struct WarmAccounts {
    shards: Vec<std::sync::Mutex<alloy_primitives::map::AddressHashMap<WarmInfo>>>,
    /// The jobs' own time, summed over the pool's threads.
    busy_us: std::sync::atomic::AtomicU64,
}

impl Default for WarmAccounts {
    fn default() -> Self {
        Self::new()
    }
}

impl WarmAccounts {
    /// An empty layer.
    pub fn new() -> Self {
        Self { shards: (0..WARM_SHARDS).map(|_| Default::default()).collect(), busy_us: Default::default() }
    }

    /// Reads `addresses` from `db` and keeps what it answered. A read that
    /// fails is left out: the batch that needs the account reads it from the
    /// provider itself and meets the error there, as it would without the
    /// prefetch. Repeats next to each other (a sender's run) are read once.
    pub fn fill<G: Database>(&self, addresses: &[Address], db: &mut G) {
        let at = std::time::Instant::now();
        let mut by_shard: Vec<Vec<(Address, WarmInfo)>> = vec![Vec::new(); WARM_SHARDS];
        let mut last: Option<Address> = None;
        for &address in addresses {
            if last == Some(address) {
                continue;
            }
            last = Some(address);
            if let Ok(info) = db.basic(address) {
                by_shard[warm_shard(&address)].push((address, info));
            }
        }
        for (shard, found) in self.shards.iter().zip(by_shard) {
            if found.is_empty() {
                continue;
            }
            shard.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(found);
        }
        self.busy_us.fetch_add(at.elapsed().as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// The jobs' own time so far, in microseconds, summed over threads.
    pub fn busy_us(&self) -> u64 {
        self.busy_us.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The layer, read-only, once every job that fills it is done.
    pub fn freeze(self) -> FrozenWarm {
        FrozenWarm {
            shards: self
                .shards
                .into_iter()
                .map(|shard| shard.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner))
                .collect(),
        }
    }
}

/// [`WarmAccounts`] after the prefetch: plain maps, read without a lock.
#[derive(Debug, Default)]
pub struct FrozenWarm {
    shards: Vec<alloy_primitives::map::AddressHashMap<WarmInfo>>,
}

impl FrozenWarm {
    /// What the prefetch read for `address`: `None` if it did not read it,
    /// `Some(None)` for an account the parent's state does not have.
    #[inline]
    pub fn get(&self, address: &Address) -> Option<&WarmInfo> {
        self.shards.get(warm_shard(address))?.get(address)
    }

    /// How many accounts it holds.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.len()).sum()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A batch's view of the parent's state with the prefetched accounts in
/// front: an account the prefetch read is answered from memory, anything
/// else -- code, storage, block hashes, an account it did not read -- from
/// `inner`. The answers are the parent's either way, so the block is the
/// same byte for byte.
#[derive(Debug)]
pub struct WarmDb<'a, G> {
    warm: &'a FrozenWarm,
    inner: G,
}

impl<'a, G> WarmDb<'a, G> {
    /// `inner` behind `warm`.
    pub const fn new(warm: &'a FrozenWarm, inner: G) -> Self {
        Self { warm, inner }
    }
}

impl<G: Database> Database for WarmDb<'_, G> {
    type Error = G::Error;

    #[inline]
    fn basic(&mut self, address: Address) -> Result<WarmInfo, Self::Error> {
        match self.warm.get(&address) {
            Some(info) => Ok(info.clone()),
            None => self.inner.basic(address),
        }
    }

    fn code_by_hash(&mut self, code_hash: alloy_primitives::B256) -> Result<revm::state::Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: revm::primitives::StorageKey,
    ) -> Result<revm::primitives::StorageValue, Self::Error> {
        self.inner.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<alloy_primitives::B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

/// Whole groups packed into at most `2 x workers` batches of about equal
/// size (a couple of thousand transfers each), in group order: what one
/// worker executes on one view of the parent's state.
pub fn batch_groups(groups: &[Vec<usize>], total: usize, workers: usize) -> Vec<Vec<&Vec<usize>>> {
    let wanted = (total / 2048).clamp(1, workers.max(1) * 2);
    let per_batch = total.div_ceil(wanted).max(1);
    let mut batches: Vec<Vec<&Vec<usize>>> = Vec::with_capacity(wanted + 1);
    let mut current: Vec<&Vec<usize>> = Vec::new();
    let mut filled = 0usize;
    for group in groups {
        current.push(group);
        filled += group.len();
        if filled >= per_batch {
            batches.push(std::mem::take(&mut current));
            filled = 0;
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// One transfer executed for a block being built: its index in the candidate
/// list, the transaction as `convert` produced it, the EVM's result, and the
/// gas it used. Its state changes are in its batch's bundle
/// ([`BuildRun::bundles`]).
#[derive(Debug)]
pub struct BuiltTransfer<T> {
    /// Index into the candidates.
    pub index: usize,
    /// The transaction, as `convert` produced it.
    pub tx: T,
    /// The EVM's result, for the receipt.
    pub result: revm::context::result::ExecutionResult<revm::context::result::HaltReason>,
    /// Gas used.
    pub gas_used: u64,
}

/// What [`execute_for_build`] produced.
#[derive(Debug)]
pub struct BuildRun<T> {
    /// The transfers that executed, in candidate order, which is the order
    /// they take in the block.
    pub executed: Vec<BuiltTransfer<T>>,
    /// Candidates the transfer path refused (a nonce that is not the
    /// account's, a balance short, a shape it does not take): left for the
    /// serial builder, in candidate order.
    pub skipped: Vec<usize>,
    /// Each batch's changes against the parent's state, with reverts, for
    /// [`graft_bundles`].
    pub bundles: Vec<BundleState>,
    /// Phase timings.
    pub phases: Phases,
    /// [`execute_for_build_in_place`] only: the transfers where the batches
    /// left them, one slot per candidate, a slot empty for a skipped one.
    /// `executed` is then empty; [`BuildRun::executed_refs`] reads them in
    /// block order and [`BuildRun::take_executed`] collects them.
    pub slots: Vec<std::sync::OnceLock<BuiltTransfer<T>>>,
}

impl<T> Default for BuildRun<T> {
    fn default() -> Self {
        Self {
            executed: Vec::new(),
            skipped: Vec::new(),
            bundles: Vec::new(),
            phases: Phases::default(),
            slots: Vec::new(),
        }
    }
}

impl<T> BuildRun<T> {
    /// The executed transfers in block order, whether collected or still in
    /// their slots.
    pub fn executed_refs(&self) -> Vec<&BuiltTransfer<T>> {
        if self.slots.is_empty() {
            self.executed.iter().collect()
        } else {
            self.slots.iter().filter_map(std::sync::OnceLock::get).collect()
        }
    }

    /// The executed transfers in block order, collected out of their slots
    /// if [`execute_for_build_in_place`] left them there: the move
    /// [`execute_for_build`] makes before it returns.
    pub fn take_executed(&mut self) -> Vec<BuiltTransfer<T>> {
        if !self.slots.is_empty() {
            self.executed = std::mem::take(&mut self.slots).into_iter().filter_map(|slot| slot.into_inner()).collect();
        }
        std::mem::take(&mut self.executed)
    }
}

/// Whether the builder leaves the executed transfers in their slots
/// (`N42_BUILD_COLLECT_IN_PLACE=1`) instead of moving them into one vector
/// before the receipts and the body are built from them.
///
/// The collect is one serial move of every transfer -- the transaction, its
/// result, ~470 bytes each, 77 MB for a 163,000-transfer block -- and it was
/// 18 ms of the leader's build on the four-node fleet (loop214-218,
/// `par_collect_ms`). In place, the order is a vector of references built by
/// one pass over the slots, and the block's body and receipts are made from
/// those on the worker pool, where the move was going to happen anyway. Off
/// by default until a four-node leg measures it.
pub fn build_collect_in_place() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_COLLECT_IN_PLACE").is_ok_and(|v| v == "1"))
}

/// Folds bundles that were each computed against the parent's state into
/// one set of changes on `state`, the block's state as it stands: every
/// account gets what the bundles changed it by, added to what `state` holds
/// (an account two bundles credited gets both credits; one a reward reached
/// and a transfer touched gets both). The beneficiary is left out and its
/// total credit returned, for the caller to apply with the block's other
/// credits. Nothing is committed here.
pub fn fold_bundles<DB: Database>(
    state: &mut State<DB>,
    bundles: &[revm::database::BundleState],
    beneficiary: Address,
) -> Result<(revm::state::EvmState, U256), <State<DB> as Database>::Error> {
    let mut changes: revm::state::EvmState = Default::default();
    changes.reserve(bundles.iter().map(|b| b.state.len()).sum::<usize>() + 1);
    let mut beneficiary_delta = U256::ZERO;
    for bundle in bundles {
        for (address, account) in &bundle.state {
            let BundleAccount { info, original_info, .. } = account;
            let (new_balance, new_nonce) = match info {
                Some(info) => (info.balance, info.nonce),
                None => continue,
            };
            let (old_balance, old_nonce) = match original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            if *address == beneficiary {
                beneficiary_delta = beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                continue;
            }
            // Another bundle's change to the same account is already in
            // `changes`; otherwise the block's view, loaded so the transition
            // records the parent's original.
            let (mut merged, existed) = match changes.remove(address) {
                Some(acc) => (acc.info, !acc.status.contains(AccountStatus::Created)),
                None => {
                    let current = state.basic(*address)?;
                    let existed = current.is_some();
                    (current.unwrap_or_default(), existed)
                }
            };
            merged.balance = if new_balance >= old_balance {
                merged.balance.saturating_add(new_balance - old_balance)
            } else {
                merged.balance.saturating_sub(old_balance - new_balance)
            };
            if new_nonce != old_nonce {
                merged.nonce += new_nonce - old_nonce;
            }
            let mut acc = Account::from(merged);
            acc.status = AccountStatus::Touched;
            if !existed && original_info.is_none() {
                acc.status |= AccountStatus::Created;
            }
            changes.insert(*address, acc);
        }
    }
    Ok((changes, beneficiary_delta))
}

/// What [`graft_bundles`] left for the caller.
#[derive(Debug, Default)]
pub struct Graft {
    /// The beneficiary's total credit across the bundles, not applied.
    pub beneficiary_delta: U256,
    /// The grafted accounts' reverts. They belong to the block's revert set,
    /// which the state's own merge creates later: append them to it once the
    /// bundle is taken (see [`append_reverts`]).
    pub reverts: Vec<(Address, AccountRevert)>,
    /// Accounts grafted.
    pub accounts: usize,
    /// Accounts the block's state already held and that went in as deltas
    /// through a commit instead.
    pub committed: usize,
    /// [`graft_bundles_indexed`] only, microseconds: the batches' maps
    /// emptied into lists with the bucket of each account, on the pool.
    pub prepare_us: u64,
    /// [`graft_bundles_indexed`] only: sorting that list into the order the
    /// block's map lays its buckets out.
    pub sort_us: u64,
    /// [`graft_bundles_indexed`] only: the merge pass -- what each account
    /// turns out to be -- which the ranges run on the pool.
    pub merge_us: u64,
    /// [`graft_bundles_indexed`] only: the writes into the block's map.
    pub apply_us: u64,
    /// [`graft_bundles_indexed`] only: the batches' reverts filtered on the
    /// pool and appended in whole.
    pub reverts_us: u64,
    /// `N42_PHASE_TIMERS=1` (plan v6 6.5): [`graft_bundles_direct`] only (the
    /// default in-place fold) -- [`install_target`] and [`take_base_bundle`],
    /// the base bundle's swap or move into the block's map. Zero otherwise
    /// (including on [`GraftFold::Indexed`]/[`GraftFold::IndexedRanges`] and
    /// [`install_staged`], which have their own phases above or none).
    pub direct_base_ms: u64,
    /// `N42_PHASE_TIMERS=1`, [`graft_bundles_direct`] only: the map and
    /// revert-list `reserve` calls sized for what is left after the base.
    pub direct_reserve_ms: u64,
    /// `N42_PHASE_TIMERS=1`, [`graft_bundles_direct`] only: each bundle's
    /// accounts probed into the block's map and inserted or added.
    pub direct_insert_ms: u64,
    /// `N42_PHASE_TIMERS=1`, [`graft_bundles_direct`] only: each bundle's
    /// reverts, filtered against the accounts already grafted and appended.
    pub direct_reverts_ms: u64,
    /// `N42_PHASE_TIMERS=1`, [`graft_bundles_direct`] only: the accounts the
    /// block's own cache already held, summed as deltas and committed once.
    pub direct_other_ms: u64,
}

/// Grafts the batches' bundles onto the block's state directly: each account
/// goes into the state's cache and bundle as its batch left it (the batch's
/// original is the parent's, which is what the block's state holds for an
/// account nothing before it touched), an account two batches touched gets
/// both changes added together, and the beneficiary is left out with its
/// credit returned. This goes around the state's transition machinery, which
/// is the point: committing 160,000 accounts through it and merging the
/// transitions cost more than executing the transfers did (round 43). The
/// few accounts the block's state already has in its cache (a system
/// contract, an earlier transaction's) are applied as deltas through a
/// commit, as [`fold_bundles`] does for all.
///
/// Each bundle must have been built with [`BundleRetention::Reverts`] against
/// the parent's state.
pub fn graft_bundles<DB: Database>(
    state: &mut State<DB>,
    bundles: Vec<BundleState>,
    beneficiary: Address,
) -> Result<Graft, <State<DB> as Database>::Error> {
    graft_bundles_with(state, bundles, beneficiary, true)
}

/// The largest bundle becomes the block's bundle instead of being copied
/// into an empty one, when nothing stands in its way: the follower's
/// partition by connected component puts most of a block of random
/// transfers into one giant group (round 43: 317 groups, one of them
/// nearly the whole block), and re-inserting its 140,000 accounts was the
/// bulk of an 84 ms merge. Only when the cache is not kept (the builder's
/// state needs the cache entries), the block's bundle is still empty and
/// no account of it is one the block's state already holds or the
/// beneficiary -- those go through the delta paths of the fold that follows.
///
/// The bundle taken is removed from `bundles`; what is left is the fold's
/// work, whichever fold runs ([`graft_bundles_with`], [`graft_bundles_indexed`]).
fn take_base_bundle<DB: Database>(
    state: &mut State<DB>,
    bundles: &mut Vec<BundleState>,
    beneficiary: Address,
    keep_cache: bool,
    graft: &mut Graft,
) {
    if keep_cache || !state.bundle_state.state.is_empty() || !graft_base_swap() {
        return;
    }
    let Some(largest) = (0..bundles.len()).max_by_key(|&i| bundles[i].state.len()) else { return };
    let clear = {
        let base = &bundles[largest];
        !base.state.is_empty()
            && !base
                .state
                .keys()
                .any(|address| *address != beneficiary && state.cache.accounts.contains_key(address))
    };
    if !clear {
        return;
    }
    let base = bundles.swap_remove(largest);
    let BundleState { state: mut accounts, contracts, mut reverts, mut state_size, .. } = base;
    // The beneficiary -- every transfer's fee lands on it, so every bundle
    // holds it -- goes as a delta like everywhere else in the fold, and its
    // revert is dropped with it.
    if let Some(account) = accounts.remove(&beneficiary) {
        state_size -= account.size_hint();
        let new_balance = account.info.as_ref().map(|i| i.balance).unwrap_or_default();
        let old_balance = account.original_info.as_ref().map(|i| i.balance).unwrap_or_default();
        graft.beneficiary_delta = graft.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
    }
    graft.accounts += accounts.len();
    if state.bundle_state.state.capacity() >= accounts.len() {
        // Memory mapped for the graft ([`GraftTarget`]): the base goes into
        // it rather than replacing it -- the same accounts, and the map the
        // rest of the graft writes stays the one whose pages are resident.
        state.bundle_state.state.extend(accounts);
    } else {
        state.bundle_state.state = accounts;
    }
    state.bundle_state.state_size = state_size;
    state.bundle_state.contracts.extend(contracts);
    graft
        .reverts
        .extend(std::mem::take(&mut *reverts).into_iter().flatten().filter(|(address, _)| *address != beneficiary));
}

/// [`graft_bundles`] with a say over the state's cache: a follower's block
/// state is read again only for the beneficiary's credit and discarded once
/// its bundle is taken, so it can skip the cache insert per account
/// (`keep_cache = false`); a builder, whose serial loop and post-execution
/// changes may read the grafted accounts, keeps it.
pub fn graft_bundles_with<DB: Database>(
    state: &mut State<DB>,
    bundles: Vec<BundleState>,
    beneficiary: Address,
    keep_cache: bool,
) -> Result<Graft, <State<DB> as Database>::Error> {
    graft_bundles_direct(state, bundles, beneficiary, keep_cache, None)
}

/// Puts a [`GraftTarget`]'s memory in as the block's bundle map and the
/// graft's revert list, if the block's bundle is still empty and has no
/// memory of its own. The largest bundle may still become the base after
/// this: [`take_base_bundle`] moves it into the target's map rather than
/// putting its own map in the target's place.
fn install_target<DB: Database>(state: &mut State<DB>, target: Option<GraftTarget>, graft: &mut Graft) {
    if let Some(target) = target
        && state.bundle_state.state.is_empty()
        && state.bundle_state.state.capacity() == 0
    {
        state.bundle_state.state = target.accounts;
        graft.reverts = target.reverts;
    }
}

fn graft_bundles_direct<DB: Database>(
    state: &mut State<DB>,
    bundles: Vec<BundleState>,
    beneficiary: Address,
    keep_cache: bool,
    target: Option<GraftTarget>,
) -> Result<Graft, <State<DB> as Database>::Error> {
    // `N42_PHASE_TIMERS=1` (plan v6 6.5): checkpoints at the granularity this
    // function already works at -- once around the base swap, once around
    // the reserves, twice per bundle (insert, then reverts) -- so timing
    // costs one `Instant::now` pair per phase per bundle (tens of them a
    // block), not one per account or per transfer.
    let timers = crate::fast_transfer::phase_timers();
    let now = || timers.then(std::time::Instant::now);
    let ns = |a: std::time::Instant, b: std::time::Instant| b.saturating_duration_since(a).as_nanos();
    let mut graft = Graft::default();
    let mut bundles = bundles;
    let t0 = now();
    install_target(state, target, &mut graft);
    take_base_bundle(state, &mut bundles, beneficiary, keep_cache, &mut graft);
    let t1 = now();
    if let (Some(a), Some(b)) = (t0, t1) {
        graft.direct_base_ms = (ns(a, b) / 1_000_000) as u64;
    }
    let total: usize = bundles.iter().map(|b| b.state.len()).sum();
    if keep_cache {
        state.cache.accounts.reserve(total);
    }
    state.bundle_state.state.reserve(total);
    graft.reverts.reserve(total);
    let t2 = now();
    if let (Some(a), Some(b)) = (t1, t2) {
        graft.direct_reserve_ms = (ns(a, b) / 1_000_000) as u64;
    }
    let mut insert_ns = 0u128;
    let mut reverts_ns = 0u128;
    // Accounts the block's state already holds: their deltas are summed here
    // and applied in one commit at the end. Summed, because the block's cache
    // is what each delta is computed against and it does not change until that
    // commit: two batches touching such an account used to leave only the
    // last one's change (`two_bundles_touching_an_account_the_block_holds`).
    // Per address: what to add, what to subtract, the nonce to add, and
    // whether every batch saw the account absent.
    let mut slow: alloy_primitives::map::HashMap<Address, (U256, U256, u64, bool)> = Default::default();
    for bundle in bundles {
        let BundleState { state: accounts, reverts, .. } = bundle;
        // Addresses this bundle changed that an earlier one had already put
        // in: their reverts are the earlier one's.
        let mut repeated: alloy_primitives::map::AddressHashSet = Default::default();
        let t_insert_start = now();
        for (address, account) in accounts {
            let Some(info) = account.info.as_ref() else { continue };
            let (new_balance, new_nonce) = (info.balance, info.nonce);
            let (old_balance, old_nonce) = match &account.original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            if address == beneficiary {
                graft.beneficiary_delta = graft.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                repeated.insert(address);
                continue;
            }
            // One probe of the block's map per account: the entry both says
            // whether an earlier bundle put the account in and is where a new
            // one goes (a look-up and then an insert was two probes into a
            // 43 MB table, each a cache miss).
            let vacant = match state.bundle_state.state.entry(address) {
                revm::primitives::hash_map::Entry::Occupied(mut held) => {
                    // An earlier bundle put it in (or an earlier merge did, in
                    // which case the cache holds the block's view too): added
                    // to what is there, in both places.
                    repeated.insert(address);
                    let add = |info: &mut revm::state::AccountInfo| {
                        info.balance = if new_balance >= old_balance {
                            info.balance.saturating_add(new_balance - old_balance)
                        } else {
                            info.balance.saturating_sub(old_balance - new_balance)
                        };
                        info.nonce += new_nonce - old_nonce;
                    };
                    if let Some(info) = held.get_mut().info.as_mut() {
                        add(info);
                    }
                    if let Some(info) = state.cache.accounts.get_mut(&address).and_then(|a| a.account.as_mut()) {
                        add(&mut info.info);
                    }
                    continue;
                }
                revm::primitives::hash_map::Entry::Vacant(vacant) => vacant,
            };
            if state.cache.accounts.contains_key(&address) {
                // The block's state has its own view of this account; a
                // delta through the ordinary path, summed with any other
                // batch's and committed once below.
                repeated.insert(address);
                let entry = slow.entry(address).or_insert((U256::ZERO, U256::ZERO, 0, true));
                if new_balance >= old_balance {
                    entry.0 = entry.0.saturating_add(new_balance - old_balance);
                } else {
                    entry.1 = entry.1.saturating_add(old_balance - new_balance);
                }
                entry.2 += new_nonce - old_nonce;
                entry.3 &= account.original_info.is_none();
                continue;
            }
            if keep_cache {
                state.cache.accounts.insert(
                    address,
                    CacheAccount {
                        account: Some(PlainAccount { info: info.clone(), storage: Default::default() }),
                        status: account.status,
                    },
                );
            }
            state.bundle_state.state_size += account.size_hint();
            vacant.insert(account);
            graft.accounts += 1;
        }
        let t_insert_end = now();
        if let (Some(a), Some(b)) = (t_insert_start, t_insert_end) {
            insert_ns += ns(a, b);
        }
        let mut reverts = reverts;
        for (address, revert) in std::mem::take(&mut *reverts).into_iter().flatten() {
            if !repeated.contains(&address) {
                graft.reverts.push((address, revert));
            }
        }
        let t_reverts_end = now();
        if let (Some(a), Some(b)) = (t_insert_end, t_reverts_end) {
            reverts_ns += ns(a, b);
        }
    }
    graft.direct_insert_ms = (insert_ns / 1_000_000) as u64;
    graft.direct_reverts_ms = (reverts_ns / 1_000_000) as u64;
    let t3 = now();
    if !slow.is_empty() {
        let mut changes: revm::state::EvmState = Default::default();
        for (address, (add, sub, nonce, original_absent)) in slow {
            let cached = state.cache.accounts.get(&address).expect("only an address the cache holds is summed here");
            let existed = cached.account.is_some();
            let mut merged = cached.account.as_ref().map(|a| a.info.clone()).unwrap_or_default();
            merged.balance = merged.balance.saturating_add(add).saturating_sub(sub);
            merged.nonce += nonce;
            let mut acc = Account::from(merged);
            acc.status = AccountStatus::Touched;
            if !existed && original_absent {
                acc.status |= AccountStatus::Created;
            }
            changes.insert(address, acc);
        }
        graft.committed = changes.len();
        state.commit(changes);
    }
    let t4 = now();
    if let (Some(a), Some(b)) = (t3, t4) {
        graft.direct_other_ms = (ns(a, b) / 1_000_000) as u64;
    }
    Ok(graft)
}

/// How the batches' bundles become the block's one bundle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GraftFold {
    /// [`graft_bundles_with`]: bundle after bundle, account after account,
    /// each one probed in the block's map and written where its hash puts it.
    /// A full block's map is ~50 MB, so every account is two probes and a
    /// write into a line nothing has touched: 56-64 ms of the leader's build
    /// (loop214, `par_fold_ms` less `par_commit_ms`), and no thread count
    /// moves it because it is memory latency, not work.
    #[default]
    Direct,
    /// [`graft_bundles_indexed`]: every batch's accounts are listed once with
    /// the bucket the block's map will put each of them in, the list is
    /// sorted on the worker pool, and the merge walks it in that order -- so
    /// the writes into the block's map go region by region instead of all
    /// over it, and an account two batches touched is its own neighbour in
    /// the list rather than a probe that finds it.
    Indexed,
    /// [`graft_bundles_indexed`] with the merge pass split over ranges of
    /// that same order and run on the worker pool. The sharded graft's lock
    /// traffic is not here: a range shares no structure with the others, it
    /// folds its own slice of every batch's bundle and the ranges' outputs
    /// are concatenated in order.
    IndexedRanges,
}

fn fold_from_env(index: &str, ranges: &str) -> GraftFold {
    if std::env::var(ranges).is_ok_and(|v| v == "1") {
        GraftFold::IndexedRanges
    } else if std::env::var(index).is_ok_and(|v| v == "1") {
        GraftFold::Indexed
    } else {
        GraftFold::Direct
    }
}

/// The fold the leader's build uses: `N42_GRAFT_INDEX=1` for
/// [`GraftFold::Indexed`], `N42_GRAFT_RANGES=1` for
/// [`GraftFold::IndexedRanges`] (which implies the index), neither for the
/// fold that is in place. Both off by default until a four-node leg says
/// `par_fold_ms` fell and the roots agree.
///
/// The bench does not say it will (`bench_build_run`, 162,000 transfers,
/// 16 threads pinned, three rounds each): into a freshly reserved map the
/// fold in place grafts in 42-45 ms, the index in 60-62 and the index over
/// ranges in 53-55; into memory mapped beside the execution
/// ([`GraftTarget`]) 26.5-27, 43 and 35.5-36. Writing the map in bucket
/// order saves less than listing, sorting and moving every account a second
/// time costs; what the graft was paying for was the page faults, and
/// those go for any order. Kept, switched off, for a leg on a loaded node,
/// where locality may be worth more than on an idle one.
pub fn build_graft_fold() -> GraftFold {
    static FOLD: std::sync::OnceLock<GraftFold> = std::sync::OnceLock::new();
    *FOLD.get_or_init(|| fold_from_env("N42_GRAFT_INDEX", "N42_GRAFT_RANGES"))
}

/// The same for a follower's import (`N42_FOLLOWER_GRAFT_INDEX`,
/// `N42_FOLLOWER_GRAFT_RANGES`), switched apart from the leader's: the two
/// sides of the graft have never wanted the same setting ([`graft_stream`]
/// against [`follower_graft_stream`]). It is read only where the follower
/// grafts the bundles after the execution -- with the streamed graft on,
/// which is the follower's default, the fold is [`StagedGraft`]'s.
pub fn follower_graft_fold() -> GraftFold {
    static FOLD: std::sync::OnceLock<GraftFold> = std::sync::OnceLock::new();
    *FOLD.get_or_init(|| fold_from_env("N42_FOLLOWER_GRAFT_INDEX", "N42_FOLLOWER_GRAFT_RANGES"))
}

/// [`graft_bundles_with`] or [`graft_bundles_indexed`], by `fold`. Every
/// fold leaves the same block: the same accounts with the same values, the
/// same reverts, the same beneficiary credit (`the_indexed_fold_equals_the_graft`).
///
/// `target`: memory mapped for the block's bundle ahead of the graft
/// ([`GraftTarget::prefaulted`]), taken if the block's bundle is still
/// empty. It changes where the accounts are written, never what is written.
pub fn graft_bundles_folded<DB: Database>(
    state: &mut State<DB>,
    bundles: Vec<BundleState>,
    beneficiary: Address,
    keep_cache: bool,
    fold: GraftFold,
    target: Option<GraftTarget>,
) -> Result<Graft, <State<DB> as Database>::Error> {
    match fold {
        GraftFold::Direct => graft_bundles_direct(state, bundles, beneficiary, keep_cache, target),
        GraftFold::Indexed => graft_indexed_into(state, bundles, beneficiary, keep_cache, false, target),
        GraftFold::IndexedRanges => graft_indexed_into(state, bundles, beneficiary, keep_cache, true, target),
    }
}

/// The memory a graft writes, mapped before the graft runs: the block's
/// bundle map and the graft's revert list, each sized for the block and
/// each page of it already touched once, then emptied.
///
/// The graft's cost is mostly first touches, not probes. One full block's
/// worth of accounts (161,760, 264 bytes an entry) inserted into a map the
/// graft has just reserved: 27-30 ms in random order and 29-30 in the order
/// of the map's buckets; into the same map once its pages are mapped: 18 ms
/// in random order and 7.5-7.7 in bucket order (`bench_map_insert`, 16
/// threads pinned, idle box). The fleet's allocator hands a table this size
/// fresh pages every block (`oversize_threshold:0`, `thp:never`), so on the
/// leader's chain the graft pays a page fault for every fifteen accounts --
/// unless the pages were faulted while the batches executed, which is what
/// this is for: [`GraftTarget::prefaulted`] runs beside the parallel step
/// (`N42_GRAFT_PREFAULT=1`, [`graft_prefault`]).
#[derive(Debug, Default)]
pub struct GraftTarget {
    accounts: revm::primitives::AddressMap<BundleAccount>,
    reverts: Vec<(Address, AccountRevert)>,
    /// How long the prefault took, microseconds.
    pub prefault_us: u64,
}

impl GraftTarget {
    /// A bundle map with room for `accounts` accounts and a revert list with
    /// room for as many reverts, both mapped: one entry inserted into every
    /// run of seven buckets of the map (a 4 KB page holds fifteen entries,
    /// so every page holds a whole run and is written at least once), the
    /// revert list filled with empty reverts; then both emptied. What is
    /// left is capacity whose pages are resident.
    pub fn prefaulted(accounts: usize) -> Self {
        use std::hash::BuildHasher as _;
        let at = std::time::Instant::now();
        let mut map: revm::primitives::AddressMap<BundleAccount> = Default::default();
        map.reserve(accounts);
        let buckets = destination_buckets(map.capacity());
        let mask = buckets - 1;
        let entry = std::mem::size_of::<(Address, BundleAccount)>().max(1) as u64;
        let run = (4096 / entry / 2).max(1);
        let runs = buckets.div_ceil(run) as usize;
        let mut touched = vec![false; runs];
        let mut left = runs;
        let hasher = map.hasher().clone();
        let empty = BundleAccount::new(None, None, Default::default(), revm::database::AccountStatus::LoadedNotExisting);
        // A key per run, found by trying keys until each run has one: about
        // `runs x ln(runs)` hashes (~0.4M for a full block's map), bounded so
        // that a hasher that never reaches some run cannot keep this going.
        let limit = buckets.saturating_mul(64);
        let mut k = 0u64;
        while left > 0 && k < limit {
            let mut bytes = [0u8; 20];
            bytes[..8].copy_from_slice(&k.to_le_bytes());
            bytes[19] = 0xfa;
            let address = Address::from(bytes);
            let run_of = ((hasher.hash_one(address) & mask) / run) as usize;
            if let Some(seen) = touched.get_mut(run_of)
                && !*seen
            {
                *seen = true;
                left -= 1;
                map.insert(address, empty.clone());
            }
            k += 1;
        }
        map.clear();
        let mut reverts: Vec<(Address, AccountRevert)> = Vec::with_capacity(accounts);
        reverts.resize_with(accounts, Default::default);
        reverts.clear();
        Self { accounts: map, reverts, prefault_us: at.elapsed().as_micros() as u64 }
    }

    /// The accounts the map has room for without growing.
    pub fn capacity(&self) -> usize {
        self.accounts.capacity()
    }
}

/// Whether the leader's build maps the graft's memory beside the parallel
/// step (`N42_GRAFT_PREFAULT=1`, [`GraftTarget`]). Off by default until a
/// four-node leg says the execution beside it does not pay for it.
pub fn graft_prefault() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_GRAFT_PREFAULT").is_ok_and(|v| v == "1"))
}

/// The bucket count of a hash table that reports `capacity`: hashbrown puts
/// a key at `hash & (buckets - 1)` and a table of eight buckets or more
/// reports `buckets * 7 / 8`. It orders the fold's writes and nothing else,
/// so a wrong answer would cost locality, never correctness.
const fn destination_buckets(capacity: usize) -> u64 {
    if capacity == 0 {
        return 1;
    }
    (capacity.saturating_mul(8).saturating_add(6) / 7).next_power_of_two() as u64
}

/// One batch's touch of one account: the bucket the block's map will put it
/// in, which batch holds it and where in that batch's list of accounts.
/// Sorted by (bucket, address, batch, position), which puts every touch of
/// one account together, in batch order, inside the run of touches that
/// share a region of the block's map.
#[derive(Debug, Clone, Copy)]
struct Touch {
    bucket: u32,
    address: Address,
    part: u32,
    pos: u32,
}

/// What one address's touches turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Touched {
    /// The block's map already held it when the fold began: a delta on what
    /// is there, in the map and in the cache.
    Held,
    /// The block's *cache* held it: a delta the fold commits at the end,
    /// through the state's own machinery.
    Cached,
    /// Neither: the first batch's account goes in as it is and the rest are
    /// added to it.
    Fresh,
}

/// One range of the fold's order, folded on its own.
#[derive(Debug, Default)]
struct FoldRange {
    /// The accounts no one held, in the order the block's map wants them:
    /// the batch, the bin and the position its value is taken from. Twelve
    /// bytes an account, because nearly every one of a block's 147,000 is
    /// here.
    fresh: Vec<(u32, u32, u32)>,
    /// What the batches after the first added to a few of those accounts:
    /// the index into `fresh`, then what to add, subtract and bump. About
    /// one account in ten on a bench-shaped block.
    fresh_deltas: Vec<(u32, U256, U256, u64)>,
    held: Vec<(Address, (U256, U256, u64))>,
    cached: Vec<(Address, (U256, U256, u64, bool))>,
    /// (batch, address) for every touch whose revert the block does not
    /// take, because another touch of that account carries it already.
    repeated: Vec<(u32, Address)>,
    beneficiary_delta: U256,
}

/// How many bins one batch's accounts are split into as they leave its map.
/// A bin is a contiguous range of the block's map's buckets, so a bin of a
/// full block is ~1 MB of accounts against the ~57 MB the block touches: the
/// merge and the apply both walk the touches in bucket order, and binning
/// the accounts the same way keeps what they read inside one bin.
const FOLD_BINS: usize = 64;

/// The accounts of one batch, taken out of its bundle's map and split into
/// [`FOLD_BINS`] bins so the fold can address them by (bin, position).
type PartAccounts = Vec<Vec<Option<(Address, BundleAccount)>>>;

/// One batch's bundle, opened for the fold on that batch's own thread.
#[derive(Debug)]
struct Prepared {
    entries: PartAccounts,
    touches: Vec<Touch>,
    reverts: Vec<(Address, AccountRevert)>,
    contracts: alloy_primitives::map::B256HashMap<revm::bytecode::Bytecode>,
}

/// Folds one range of the sorted touches. Reads the batches' accounts and
/// the block's two maps, writes nothing: every change it finds is in the
/// [`FoldRange`] it returns, which is what lets the ranges run beside each
/// other. The rules are [`graft_bundles_with`]'s, per address instead of per
/// touch -- the block's map is probed once for an account rather than once
/// for each batch that touched it.
fn fold_range(
    touches: &[Touch],
    parts: &[PartAccounts],
    bin_shift: u32,
    held: &(dyn Fn(&Address) -> bool + Sync),
    cached: &(dyn Fn(&Address) -> bool + Sync),
    beneficiary: Address,
) -> FoldRange {
    let mut out = FoldRange { fresh: Vec::with_capacity(touches.len()), ..Default::default() };
    let mut i = 0usize;
    while i < touches.len() {
        let address = touches[i].address;
        let mut j = i + 1;
        while j < touches.len() && touches[j].address == address {
            j += 1;
        }
        let mut kind: Option<Touched> = None;
        let mut inserter: Option<(u32, u32, u32)> = None;
        let (mut add, mut sub, mut nonce) = (U256::ZERO, U256::ZERO, 0u64);
        let mut original_absent = true;
        for touch in &touches[i..j] {
            let Some((_, account)) =
                parts[touch.part as usize][(touch.bucket >> bin_shift) as usize][touch.pos as usize].as_ref()
            else {
                continue;
            };
            // An account with nothing left of it contributes no value and no
            // repetition -- its revert is the block's, as it is in
            // `graft_bundles_with`.
            let Some(info) = account.info.as_ref() else { continue };
            let (new_balance, new_nonce) = (info.balance, info.nonce);
            let (old_balance, old_nonce) = match &account.original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            if address == beneficiary {
                out.beneficiary_delta =
                    out.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                out.repeated.push((touch.part, address));
                continue;
            }
            let settled = *kind.get_or_insert_with(|| {
                if held(&address) {
                    Touched::Held
                } else if cached(&address) {
                    Touched::Cached
                } else {
                    Touched::Fresh
                }
            });
            if settled == Touched::Fresh && inserter.is_none() {
                inserter = Some((touch.part, touch.bucket >> bin_shift, touch.pos));
                continue;
            }
            if new_balance >= old_balance {
                add = add.saturating_add(new_balance - old_balance);
            } else {
                sub = sub.saturating_add(old_balance - new_balance);
            }
            nonce += new_nonce - old_nonce;
            original_absent &= account.original_info.is_none();
            out.repeated.push((touch.part, address));
        }
        match kind {
            None => {}
            Some(Touched::Held) => out.held.push((address, (add, sub, nonce))),
            Some(Touched::Cached) => out.cached.push((address, (add, sub, nonce, original_absent))),
            Some(Touched::Fresh) => {
                if let Some(at) = inserter {
                    if !add.is_zero() || !sub.is_zero() || nonce != 0 {
                        out.fresh_deltas.push((out.fresh.len() as u32, add, sub, nonce));
                    }
                    out.fresh.push(at);
                }
            }
        }
        i = j;
    }
    out
}

/// [`graft_bundles_with`] over an index of where the block's map will put
/// each account, instead of over the map itself.
///
/// The graft's cost is not the work, it is the shape: a full block's bundle
/// map is ~50 MB and the accounts arrive in the order their batches
/// executed, so every one of 158,000 accounts is a probe and a write into
/// memory nothing has touched -- 56-64 ms that no thread count moves
/// (`docs/FLEET7_PATH_AUDIT.md`, the graft's representation). Here each
/// batch's accounts are taken out of its map once, on the worker pool, and
/// listed with the bucket the block's map will put them in; the list is
/// sorted there too; and the merge then walks the block's map region by
/// region. Two batches that touched one account are neighbours in that list,
/// so the duplicate is found by looking left rather than by probing.
///
/// `ranges`: the merge pass itself split over ranges of the same order and
/// run on the pool ([`GraftFold::IndexedRanges`]). A range folds its own
/// slice, shares nothing, and the outputs are concatenated -- only the
/// writes into the block's one map stay on this thread, because that map is
/// one map.
///
/// The block it leaves is [`graft_bundles_with`]'s, account for account,
/// revert for revert. Two things are stated rather than implied: the deltas
/// of an account several batches touched are summed and applied once (where
/// the fold in place applies each in turn -- the same value unless a balance
/// saturates, which a transfer cannot make happen), and a batch's contracts
/// are carried over (the fold in place drops them, which is invisible while
/// only transfers take this path).
pub fn graft_bundles_indexed<DB: Database>(
    state: &mut State<DB>,
    bundles: Vec<BundleState>,
    beneficiary: Address,
    keep_cache: bool,
    ranges: bool,
) -> Result<Graft, <State<DB> as Database>::Error> {
    graft_indexed_into(state, bundles, beneficiary, keep_cache, ranges, None)
}

fn graft_indexed_into<DB: Database>(
    state: &mut State<DB>,
    bundles: Vec<BundleState>,
    beneficiary: Address,
    keep_cache: bool,
    ranges: bool,
    target: Option<GraftTarget>,
) -> Result<Graft, <State<DB> as Database>::Error> {
    use rayon::prelude::*;
    use std::hash::BuildHasher as _;

    let mut graft = Graft::default();
    let mut bundles = bundles;
    install_target(state, target, &mut graft);
    take_base_bundle(state, &mut bundles, beneficiary, keep_cache, &mut graft);
    let total: usize = bundles.iter().map(|b| b.state.len()).sum();
    if total == 0 {
        for bundle in &mut bundles {
            graft.reverts.extend(std::mem::take(&mut *bundle.reverts).into_iter().flatten());
        }
        return Ok(graft);
    }
    if keep_cache {
        state.cache.accounts.reserve(total);
    }
    state.bundle_state.state.reserve(total);
    graft.reverts.reserve(total);
    // Read after the reserve: what the block's map will be while the fold
    // fills it, so the buckets the touches are sorted by are the buckets it
    // uses. Nothing below makes it grow again.
    let hasher = state.bundle_state.state.hasher().clone();
    let buckets = destination_buckets(state.bundle_state.state.capacity());
    let mask = buckets - 1;
    // A bin is `buckets / FOLD_BINS` of the block's map, so an account's bin
    // is the top bits of its bucket.
    let bin_shift = buckets.trailing_zeros().saturating_sub(FOLD_BINS.trailing_zeros());

    // Each batch's accounts out of its map and into a list, on the batch's
    // own thread, with the bucket of each. This is the one copy the index
    // costs, and it is the only part of the graft that parallelises.
    let at = std::time::Instant::now();
    let prepared: Vec<Prepared> = bundles
        .into_par_iter()
        .enumerate()
        .map(|(part, bundle)| {
            let BundleState { state: accounts, contracts, mut reverts, .. } = bundle;
            let reverts: Vec<(Address, AccountRevert)> = std::mem::take(&mut *reverts).into_iter().flatten().collect();
            // Counted off the keys alone first (one cache line of an
            // account's six), so every bin is allocated at its exact size
            // and nothing is grown or moved twice. The hash is taken again
            // below rather than kept, because two passes over a map are
            // only in the same order by implementation, and a hash of
            // twenty bytes is two nanoseconds.
            let mut counts = [0u32; FOLD_BINS];
            for address in accounts.keys() {
                counts[((hasher.hash_one(*address) & mask) >> bin_shift) as usize] += 1;
            }
            let mut entries: PartAccounts =
                counts.iter().map(|count| Vec::with_capacity(*count as usize)).collect();
            let mut touches: Vec<Touch> = Vec::with_capacity(accounts.len());
            for (address, account) in accounts {
                let bucket = (hasher.hash_one(address) & mask) as u32;
                let bin = (bucket >> bin_shift) as usize;
                touches.push(Touch { bucket, address, part: part as u32, pos: entries[bin].len() as u32 });
                entries[bin].push(Some((address, account)));
            }
            Prepared { entries, touches, reverts, contracts }
        })
        .collect();
    let mut parts: Vec<PartAccounts> = Vec::with_capacity(prepared.len());
    let mut revert_lists: Vec<Vec<(Address, AccountRevert)>> = Vec::with_capacity(prepared.len());
    let mut touches: Vec<Touch> = Vec::with_capacity(total);
    for part in prepared {
        parts.push(part.entries);
        revert_lists.push(part.reverts);
        touches.extend(part.touches);
        state.bundle_state.contracts.extend(part.contracts);
    }
    graft.prepare_us = at.elapsed().as_micros() as u64;
    let at = std::time::Instant::now();
    touches.par_sort_unstable_by(|a, b| {
        a.bucket.cmp(&b.bucket).then_with(|| a.address.cmp(&b.address)).then_with(|| (a.part, a.pos).cmp(&(b.part, b.pos)))
    });

    graft.sort_us = at.elapsed().as_micros() as u64;
    let at = std::time::Instant::now();
    // The ranges, cut on an address boundary so no account is folded twice.
    let workers = rayon::current_num_threads().max(1);
    let span = if ranges { (touches.len() / (workers * 4).max(1)).max(1) } else { touches.len() };
    let mut bounds: Vec<usize> = vec![0];
    let mut cut = span;
    while cut < touches.len() {
        while cut < touches.len() && touches[cut].address == touches[cut - 1].address {
            cut += 1;
        }
        if cut >= touches.len() {
            break;
        }
        bounds.push(cut);
        cut += span;
    }
    bounds.push(touches.len());

    let folded: Vec<FoldRange> = {
        let in_bundle = &state.bundle_state.state;
        let in_cache = &state.cache.accounts;
        let held = |address: &Address| in_bundle.contains_key(address);
        let cached = |address: &Address| in_cache.contains_key(address);
        let cuts: Vec<(usize, usize)> = bounds.windows(2).map(|w| (w[0], w[1])).collect();
        if ranges {
            cuts.into_par_iter()
                .map(|(from, to)| fold_range(&touches[from..to], &parts, bin_shift, &held, &cached, beneficiary))
                .collect()
        } else {
            cuts.into_iter()
                .map(|(from, to)| fold_range(&touches[from..to], &parts, bin_shift, &held, &cached, beneficiary))
                .collect()
        }
    };
    drop(touches);
    graft.merge_us = at.elapsed().as_micros() as u64;
    let at = std::time::Instant::now();

    // The ranges are in the order the block's map lays its buckets out, and
    // so are the accounts inside each: this loop writes the map from one end
    // to the other rather than all over it.
    let mut slow: alloy_primitives::map::AddressHashMap<(U256, U256, u64, bool)> = Default::default();
    let mut repeated: Vec<alloy_primitives::map::AddressHashSet> =
        (0..parts.len()).map(|_| Default::default()).collect();
    for range in folded {
        graft.beneficiary_delta = graft.beneficiary_delta.saturating_add(range.beneficiary_delta);
        let mut deltas = range.fresh_deltas.into_iter().peekable();
        for (at, (part, bin, pos)) in range.fresh.into_iter().enumerate() {
            let delta = if deltas.peek().is_some_and(|(which, ..)| *which as usize == at) {
                deltas.next()
            } else {
                None
            };
            let Some((address, mut account)) = parts[part as usize][bin as usize][pos as usize].take() else {
                continue;
            };
            if let Some((_, add, sub, nonce)) = delta
                && let Some(info) = account.info.as_mut()
            {
                info.balance = info.balance.saturating_add(add).saturating_sub(sub);
                info.nonce += nonce;
            }
            if keep_cache && let Some(info) = account.info.as_ref() {
                state.cache.accounts.insert(
                    address,
                    CacheAccount {
                        account: Some(PlainAccount { info: info.clone(), storage: Default::default() }),
                        status: account.status,
                    },
                );
            }
            state.bundle_state.state_size += account.size_hint();
            state.bundle_state.state.insert(address, account);
            graft.accounts += 1;
        }
        for (address, (add, sub, nonce)) in range.held {
            if let Some(info) = state.bundle_state.state.get_mut(&address).and_then(|a| a.info.as_mut()) {
                info.balance = info.balance.saturating_add(add).saturating_sub(sub);
                info.nonce += nonce;
            }
            if let Some(cached) = state.cache.accounts.get_mut(&address).and_then(|a| a.account.as_mut()) {
                cached.info.balance = cached.info.balance.saturating_add(add).saturating_sub(sub);
                cached.info.nonce += nonce;
            }
        }
        for (address, entry) in range.cached {
            slow.insert(address, entry);
        }
        for (part, address) in range.repeated {
            if let Some(set) = repeated.get_mut(part as usize) {
                set.insert(address);
            }
        }
    }
    drop(parts);
    graft.apply_us = at.elapsed().as_micros() as u64;

    // The reverts, batch by batch and in the order the fold in place leaves
    // them: the ones whose account another touch carries are dropped. The
    // dropping is done on the pool, a batch to itself, and what is left is
    // appended in whole -- a memcpy a batch rather than a push and a
    // look-up per revert. A full block has as many reverts as accounts and
    // each is ~210 bytes, which made this a third of the fold (bench: 16 ms
    // of 51).
    let at = std::time::Instant::now();
    let mut kept = revert_lists;
    kept.par_iter_mut().zip(repeated.par_iter()).for_each(|(reverts, repeated)| {
        if !repeated.is_empty() {
            reverts.retain(|(address, _)| !repeated.contains(address));
        }
    });
    for mut part in kept {
        graft.reverts.append(&mut part);
    }
    graft.reverts_us = at.elapsed().as_micros() as u64;

    if !slow.is_empty() {
        let mut changes: revm::state::EvmState = Default::default();
        for (address, (add, sub, nonce, original_absent)) in slow {
            let Some(cached) = state.cache.accounts.get(&address) else {
                // Only an address the cache held is summed here; if that ever
                // stops being true the block would silently lose a change.
                tracing::error!(target: "payload_builder", %address, "the indexed fold summed an address the cache does not hold");
                continue;
            };
            let existed = cached.account.is_some();
            let mut merged = cached.account.as_ref().map(|a| a.info.clone()).unwrap_or_default();
            merged.balance = merged.balance.saturating_add(add).saturating_sub(sub);
            merged.nonce += nonce;
            let mut acc = Account::from(merged);
            acc.status = AccountStatus::Touched;
            if !existed && original_absent {
                acc.status |= AccountStatus::Created;
            }
            changes.insert(address, acc);
        }
        graft.committed = changes.len();
        state.commit(changes);
    }
    Ok(graft)
}

/// A graft built beside the execution: each batch's bundle is folded into a
/// bundle of the graft's own the moment that batch finishes, on that batch's
/// thread, while the others are still executing. The block's state is not
/// touched until [`install_staged`], so a batch that fails leaves nothing
/// behind -- and the work the leader's serial chain used to do after the
/// execution (a `BundleAccount` per touched account moved into one map, 60 ms
/// of a full block) is done by the time the last batch lands.
///
/// The rules are [`graft_bundles_with`]'s, against the staged bundle instead
/// of the block's: an account two batches touched gets both changes added
/// together, the beneficiary is left out with its credit returned, and an
/// account the block's state already holds is summed into a delta the install
/// commits.
#[derive(Debug)]
pub struct StagedGraft {
    beneficiary: Address,
    state: alloy_primitives::map::AddressHashMap<BundleAccount>,
    state_size: usize,
    contracts: alloy_primitives::map::B256HashMap<revm::bytecode::Bytecode>,
    reverts: Vec<(Address, AccountRevert)>,
    /// Per held address: what to add, what to subtract, the nonce to add, and
    /// whether every batch saw the account absent.
    slow: alloy_primitives::map::AddressHashMap<(U256, U256, u64, bool)>,
    graft: Graft,
    capacity: usize,
}

impl StagedGraft {
    /// A staged graft for a block whose beneficiary is `beneficiary`.
    /// `capacity` is the accounts the block is expected to touch, reserved
    /// once instead of grown a batch at a time. Which accounts the block's
    /// own state already holds is settled by [`install_staged`], which is
    /// where the state is known -- a follower's pre-execution system calls
    /// run while the batches are still going.
    pub fn new(beneficiary: Address, capacity: usize) -> Self {
        Self {
            beneficiary,
            state: Default::default(),
            state_size: 0,
            contracts: Default::default(),
            reverts: Vec::new(),
            slow: Default::default(),
            graft: Graft::default(),
            capacity,
        }
    }

    /// Whether the staged bundle carries `address`.
    pub fn holds(&self, address: &Address) -> bool {
        self.state.contains_key(address)
    }

    /// Folds one batch's bundle in. The first one is taken whole where it can
    /// be (as [`graft_bundles_with`]'s base swap does): the map it already
    /// built becomes the staged one rather than being copied into an empty.
    pub fn add(&mut self, bundle: BundleState) {
        let BundleState { state: accounts, contracts, mut reverts, state_size, .. } = bundle;
        let taken = std::mem::take(&mut *reverts);
        if self.state.is_empty()
            && self.graft.accounts == 0
            && graft_base_swap()
            && !accounts.is_empty()
        {
            let mut accounts = accounts;
            let mut state_size = state_size;
            if let Some(account) = accounts.remove(&self.beneficiary) {
                state_size -= account.size_hint();
                let new_balance = account.info.as_ref().map(|i| i.balance).unwrap_or_default();
                let old_balance = account.original_info.as_ref().map(|i| i.balance).unwrap_or_default();
                self.graft.beneficiary_delta = self.graft.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
            }
            self.graft.accounts += accounts.len();
            self.state = accounts;
            self.state.reserve(self.capacity.saturating_sub(self.state.len()));
            self.state_size = state_size;
            self.contracts.extend(contracts);
            self.reverts.reserve(self.capacity);
            self.reverts
                .extend(taken.into_iter().flatten().filter(|(address, _)| *address != self.beneficiary));
            return;
        }
        self.contracts.extend(contracts);
        let mut repeated: alloy_primitives::map::AddressHashSet = Default::default();
        for (address, account) in accounts {
            let Some(info) = account.info.as_ref() else { continue };
            let (new_balance, new_nonce) = (info.balance, info.nonce);
            let (old_balance, old_nonce) = match &account.original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            if address == self.beneficiary {
                self.graft.beneficiary_delta = self.graft.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                repeated.insert(address);
                continue;
            }
            if let Some(staged) = self.state.get_mut(&address).and_then(|a| a.info.as_mut()) {
                // An earlier batch staged it: added to what is there.
                repeated.insert(address);
                staged.balance = if new_balance >= old_balance {
                    staged.balance.saturating_add(new_balance - old_balance)
                } else {
                    staged.balance.saturating_sub(old_balance - new_balance)
                };
                staged.nonce += new_nonce - old_nonce;
                continue;
            }
            if self.state.is_empty() {
                self.state.reserve(self.capacity);
                self.reverts.reserve(self.capacity);
            }
            self.state_size += account.size_hint();
            self.state.insert(address, account);
            self.graft.accounts += 1;
        }
        for (address, revert) in taken.into_iter().flatten() {
            if !repeated.contains(&address) {
                self.reverts.push((address, revert));
            }
        }
    }
}

/// A staged graft split across shards, one lock each, so the batches fold
/// into it at the same time instead of queueing on one mutex.
///
/// Which shard an account belongs to is the top byte of its address, so a
/// batch's accounts spread over every shard and two batches collide only on
/// the shard, never on the account -- the fold itself is the same work as
/// [`StagedGraft`]'s, done in parallel. What the shards cannot do is become
/// reth's `BundleState`, which is one map: [`ShardedGraft::merge`] builds that
/// and is the cost this design has to move off the chain rather than remove
/// (see `docs/FLEET7_PATH_AUDIT.md`, the graft's representation).
#[derive(Debug)]
pub struct ShardedGraft {
    beneficiary: Address,
    shards: Vec<std::sync::Mutex<GraftShard>>,
    capacity: usize,
}

/// One shard's accounts and the reverts of the blocks that filled it.
#[derive(Debug, Default)]
pub struct GraftShard {
    state: alloy_primitives::map::AddressHashMap<BundleAccount>,
    state_size: usize,
    reverts: Vec<(Address, AccountRevert)>,
    beneficiary_delta: U256,
}

impl ShardedGraft {
    /// `shards` locks over an expected `capacity` accounts.
    pub fn new(beneficiary: Address, capacity: usize, shards: usize) -> Self {
        let shards = (0..shards.max(1))
            .map(|_| std::sync::Mutex::new(GraftShard::default()))
            .collect();
        Self { beneficiary, shards, capacity }
    }

    fn shard_of(&self, address: &Address) -> usize {
        (address.0[0] as usize) * self.shards.len() / 256
    }

    /// Folds one batch's bundle in, taking each shard's lock once for the run
    /// of accounts that belongs to it.
    pub fn add(&self, bundle: BundleState) {
        let BundleState { state: accounts, mut reverts, .. } = bundle;
        let taken = std::mem::take(&mut *reverts);
        // Sorted into the shards first, with no lock held: the locks are then
        // taken once each rather than once an account.
        let mut by_shard: Vec<Vec<(Address, BundleAccount)>> = vec![Vec::new(); self.shards.len()];
        for (address, account) in accounts {
            by_shard[self.shard_of(&address)].push((address, account));
        }
        let mut reverts_by_shard: Vec<Vec<(Address, AccountRevert)>> = vec![Vec::new(); self.shards.len()];
        for (address, revert) in taken.into_iter().flatten() {
            reverts_by_shard[self.shard_of(&address)].push((address, revert));
        }
        let per_shard = self.capacity / self.shards.len() + 1;
        for (index, run) in by_shard.into_iter().enumerate() {
            let reverts = std::mem::take(&mut reverts_by_shard[index]);
            if run.is_empty() && reverts.is_empty() {
                continue;
            }
            let mut shard = self.shards[index].lock().expect("a graft shard's lock");
            if shard.state.is_empty() {
                shard.state.reserve(per_shard);
                shard.reverts.reserve(per_shard);
            }
            let mut repeated: alloy_primitives::map::AddressHashSet = Default::default();
            for (address, account) in run {
                let Some(info) = account.info.as_ref() else { continue };
                let (new_balance, new_nonce) = (info.balance, info.nonce);
                let (old_balance, old_nonce) = match &account.original_info {
                    Some(orig) => (orig.balance, orig.nonce),
                    None => (U256::ZERO, 0),
                };
                if address == self.beneficiary {
                    shard.beneficiary_delta = shard.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                    repeated.insert(address);
                    continue;
                }
                if let Some(staged) = shard.state.get_mut(&address).and_then(|a| a.info.as_mut()) {
                    repeated.insert(address);
                    staged.balance = if new_balance >= old_balance {
                        staged.balance.saturating_add(new_balance - old_balance)
                    } else {
                        staged.balance.saturating_sub(old_balance - new_balance)
                    };
                    staged.nonce += new_nonce - old_nonce;
                    continue;
                }
                shard.state_size += account.size_hint();
                shard.state.insert(address, account);
            }
            for (address, revert) in reverts {
                if !repeated.contains(&address) {
                    shard.reverts.push((address, revert));
                }
            }
        }
    }

    /// The one map reth's `BundleState` is: every shard's accounts moved into
    /// it. This is the part the shards do not remove.
    pub fn merge(self) -> (alloy_primitives::map::AddressHashMap<BundleAccount>, usize, Vec<(Address, AccountRevert)>, U256) {
        let mut state: alloy_primitives::map::AddressHashMap<BundleAccount> = Default::default();
        state.reserve(self.capacity);
        let mut reverts = Vec::with_capacity(self.capacity);
        let (mut size, mut delta) = (0usize, U256::ZERO);
        for shard in self.shards {
            let shard = shard.into_inner().expect("a graft shard's lock");
            size += shard.state_size;
            delta = delta.saturating_add(shard.beneficiary_delta);
            state.extend(shard.state);
            reverts.extend(shard.reverts);
        }
        (state, size, reverts, delta)
    }

    /// The accounts staged, over every shard.
    pub fn accounts(&self) -> usize {
        self.shards.iter().map(|shard| shard.lock().expect("a graft shard's lock").state.len()).sum()
    }
}

/// Puts a [`StagedGraft`] on the block's state: its bundle becomes the block's
/// where the block has none yet (the usual case for a block whose transfers
/// all ran in the parallel step), and is grafted account by account where it
/// has one. The deltas of the accounts the block already held are committed.
/// `keep_cache` fills the state's cache as [`graft_bundles_with`] does, for a
/// block whose serial loop or post-execution changes may read a staged account.
pub fn install_staged<DB: Database>(
    state: &mut State<DB>,
    staged: StagedGraft,
    keep_cache: bool,
) -> Result<Graft, <State<DB> as Database>::Error> {
    let StagedGraft { beneficiary, state: mut accounts, mut state_size, contracts, reverts, mut slow, mut graft, .. } = staged;
    graft.reverts = reverts;
    // Accounts the block's state holds of its own (a pre-execution system
    // call's, an earlier transaction's): their changes go on top of the
    // block's values, not the parent's, so they leave the staged bundle and
    // become deltas. The cache holds a handful of them, so this looks them up
    // rather than every staged account.
    if !state.cache.accounts.is_empty() {
        let cached: Vec<Address> = state.cache.accounts.keys().copied().collect();
        for address in cached {
            let Some(account) = accounts.remove(&address) else { continue };
            state_size -= account.size_hint();
            graft.accounts -= 1;
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
            graft.reverts.retain(|(reverted, _)| *reverted != address);
        }
    }
    if state.bundle_state.state.is_empty() {
        if keep_cache {
            state.cache.accounts.reserve(accounts.len());
            for (address, account) in &accounts {
                if let Some(info) = account.info.as_ref() {
                    state.cache.accounts.insert(
                        *address,
                        CacheAccount {
                            account: Some(PlainAccount { info: info.clone(), storage: Default::default() }),
                            status: account.status,
                        },
                    );
                }
            }
        }
        state.bundle_state.state = accounts;
        state.bundle_state.state_size = state_size;
        state.bundle_state.contracts.extend(contracts);
    } else {
        // The block's state already carries a bundle (an earlier graft, or a
        // merge of its own): the staged accounts go through the account-by-
        // account path, which adds to what is there.
        let bundle = BundleState { state: accounts, contracts, reverts: Default::default(), state_size, reverts_size: 0 };
        let merged = graft_bundles_with(state, vec![bundle], beneficiary, keep_cache)?;
        graft.accounts = merged.accounts;
        graft.committed = merged.committed;
        graft.beneficiary_delta = graft.beneficiary_delta.saturating_add(merged.beneficiary_delta);
    }
    if !slow.is_empty() {
        let mut changes: revm::state::EvmState = Default::default();
        for (address, (add, sub, nonce, original_absent)) in slow {
            let cached = state.cache.accounts.get(&address).expect("only an address the cache held is summed here");
            let existed = cached.account.is_some();
            let mut merged = cached.account.as_ref().map(|a| a.info.clone()).unwrap_or_default();
            merged.balance = merged.balance.saturating_add(add).saturating_sub(sub);
            merged.nonce += nonce;
            let mut acc = Account::from(merged);
            acc.status = AccountStatus::Touched;
            if !existed && original_absent {
                acc.status |= AccountStatus::Created;
            }
            changes.insert(address, acc);
        }
        graft.committed += changes.len();
        state.commit(changes);
    }
    Ok(graft)
}

/// Appends a graft's reverts to a taken bundle's revert set for the block
/// (the last one, which the state's merge created; a new one if the merge
/// found nothing to revert). An account the block touched again after the
/// graft (a later transaction's sender, a withdrawal's recipient) got a
/// second revert from the merge, back to the grafted value: that one is
/// dropped, since the block's revert is to the parent's value, which the
/// graft's carries -- and two entries for one account in a block's
/// changeset fail persistence's history index (round 43, `UnsortedInput`).
/// The set is sorted by address, as the merge leaves it.
pub fn append_reverts(bundle: &mut BundleState, reverts: Vec<(Address, AccountRevert)>) {
    if reverts.is_empty() {
        return;
    }
    if bundle.reverts.is_empty() {
        bundle.reverts.push(Vec::new());
    }
    let last = bundle.reverts.len() - 1;
    // Sorted by address as revm's own merge leaves them; on the worker pool,
    // a block's 147,000 reverts being too many for one thread on the
    // follower's critical path.
    let mut reverts = reverts;
    sort_reverts(&mut reverts);
    let merged = &mut bundle.reverts[last];
    if merged.is_empty() {
        // The block's merge had nothing of its own to revert: the graft's set
        // becomes the block's, moved rather than copied into it.
        *merged = reverts;
    } else {
        // The block's own reverts are a handful -- the beneficiary, the
        // withdrawals' recipients -- so each is looked up in the graft's
        // sorted set rather than the graft's 147,000 being put in a set of
        // their own (5-8 ms of a follower's import, loop174).
        let mut few: Vec<(Address, AccountRevert)> = std::mem::take(merged)
            .into_iter()
            .filter(|(address, _)| reverts.binary_search_by_key(address, |(address, _)| *address).is_err())
            .collect();
        few.sort_unstable_by_key(|(address, _)| *address);
        // Merged into the graft's set from the back: every entry of it moves
        // at most once, and no second buffer of 147,000 reverts is allocated.
        let (mut i, mut k) = (reverts.len(), reverts.len() + few.len());
        reverts.resize_with(k, Default::default);
        while let Some(entry) = few.pop() {
            while i > 0 && reverts[i - 1].0 > entry.0 {
                reverts.swap(k - 1, i - 1);
                i -= 1;
                k -= 1;
            }
            reverts[k - 1] = entry;
            k -= 1;
        }
        *merged = reverts;
    }
    bundle.reverts_size = bundle.reverts.iter().map(Vec::len).sum();
}

/// By address, on the worker pool where there are enough of them to pay for it.
fn sort_reverts(reverts: &mut [(Address, AccountRevert)]) {
    if reverts.len() >= 4096 {
        use rayon::prelude::*;
        reverts.par_sort_unstable_by_key(|(address, _)| *address);
    } else {
        reverts.sort_unstable_by_key(|(address, _)| *address);
    }
}

/// Executes candidate transfers for a block being built, one group per
/// sender ([`partition_by_sender`]), the groups spread over batches on the
/// worker pool, each batch on its own view of the parent's state from `open`
/// and yielding its own bundle.
///
/// Unlike [`execute_transfers`], which must reproduce a sealed block exactly,
/// this may drop candidates: one the transfer path refuses is reported in
/// `skipped` and the group goes on (a later transfer of the same sender then
/// fails its nonce check and is skipped too, which keeps the sender's order).
/// A sender's view lacks what other groups credit it in the same block, so a
/// transfer that only those credits would fund is skipped rather than built:
/// conservative, and the serial builder that follows may still take it.
///
/// The caller grafts the bundles onto the block's state with
/// [`graft_bundles`]: committing each transfer's state on its own is what
/// the serial path spends half its time on (round 43: 112 ms of execution,
/// 110 ms of commits and 55 ms of transition merging for 163,000 transfers),
/// and one commit of the folded changes ([`fold_bundles`]) costs the same.
///
/// Returns `Err` when the candidates are not all plain transfers away from
/// the beneficiary: then the serial builder takes all of them.
pub fn execute_for_build<T, G>(
    evm_env: &reth_evm::EvmEnv,
    keys: &[(Address, Address)],
    convert: &(dyn Fn(usize) -> (T, TxEnv) + Sync),
    open: &(dyn Fn() -> Option<G> + Sync),
) -> Result<BuildRun<T>, NotParallel>
where
    T: Send + Sync,
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    execute_for_build_with(evm_env, keys, convert, open, None)
}

/// [`execute_for_build_with`], with the executed transfers left in their
/// slots ([`BuildRun::slots`]) rather than collected into
/// [`BuildRun::executed`] when `in_place` is set
/// ([`build_collect_in_place`]).
pub fn execute_for_build_in_place<T, G>(
    evm_env: &reth_evm::EvmEnv,
    keys: &[(Address, Address)],
    convert: &(dyn Fn(usize) -> (T, TxEnv) + Sync),
    open: &(dyn Fn() -> Option<G> + Sync),
    on_bundle: Option<&(dyn Fn(BundleState) + Sync)>,
    in_place: bool,
) -> Result<BuildRun<T>, NotParallel>
where
    T: Send + Sync,
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    execute_for_build_run(evm_env, keys, convert, open, on_bundle, in_place)
}

/// [`execute_for_build`] with somewhere for each batch's bundle to go as that
/// batch finishes: `on_bundle` is called on the batch's own thread, while the
/// others are still executing ([`StagedGraft`]). With a sink the run's
/// `bundles` come back empty, and a run that fails leaves whatever the sink
/// collected to be dropped.
pub fn execute_for_build_with<T, G>(
    evm_env: &reth_evm::EvmEnv,
    keys: &[(Address, Address)],
    convert: &(dyn Fn(usize) -> (T, TxEnv) + Sync),
    open: &(dyn Fn() -> Option<G> + Sync),
    on_bundle: Option<&(dyn Fn(BundleState) + Sync)>,
) -> Result<BuildRun<T>, NotParallel>
where
    T: Send + Sync,
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    execute_for_build_run(evm_env, keys, convert, open, on_bundle, false)
}

fn execute_for_build_run<T, G>(
    evm_env: &reth_evm::EvmEnv,
    keys: &[(Address, Address)],
    convert: &(dyn Fn(usize) -> (T, TxEnv) + Sync),
    open: &(dyn Fn() -> Option<G> + Sync),
    on_bundle: Option<&(dyn Fn(BundleState) + Sync)>,
    in_place: bool,
) -> Result<BuildRun<T>, NotParallel>
where
    T: Send + Sync,
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let beneficiary = evm_env.block_env.beneficiary;
    let mut phases = Phases::default();
    let at = std::time::Instant::now();
    let groups = partition_by_sender(keys, beneficiary)?;
    phases.groups = groups.len();
    // Batches of whole groups, about equal in transfers: a couple of
    // thousand transfers each, at most two per worker. Each batch opens its
    // own view of the parent, which is not free.
    let pool = build_pool();
    let workers = pool.current_num_threads().max(1);
    let batches = batch_groups(&groups, keys.len(), workers);
    phases.batches = batches.len();
    phases.partition_ms = at.elapsed().as_millis() as u64;

    let at = std::time::Instant::now();
    // Each result goes into its candidate's slot from the batch's own
    // thread: collecting the batches' vectors and sorting them by index was
    // 80-150 ms of a full block's build (loop138-139).
    let slots: Vec<std::sync::OnceLock<BuiltTransfer<T>>> = (0..keys.len()).map(|_| std::sync::OnceLock::new()).collect();
    let slots_ref = &slots;
    type BatchResult = (Vec<usize>, Option<BundleState>, crate::fast_transfer::TransferTimers);
    let results: Vec<Result<BatchResult, NotParallel>> = pool.install(|| {
        use rayon::prelude::*;
        batches
            .par_iter()
            .map(|members| {
                let db = open().ok_or(NotParallel::NoState)?;
                let mut state = State::builder().with_database(db).with_bundle_update().build();
                let mut skipped = Vec::new();
                {
                    let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(&mut state, evm_env.clone());
                    for group in members {
                        let mut rest = group.iter();
                        for &i in rest.by_ref() {
                            // Converted here, on the batch's thread: the
                            // conversion of a full block was 55-100 ms of
                            // the builder's own thread otherwise.
                            let (tx, env) = convert(i);
                            match evm.transfer(&env) {
                                Ok(Some(out)) => {
                                    let gas_used = out.result.gas_used();
                                    evm.db_mut().commit(out.state);
                                    if slots_ref[i].set(BuiltTransfer { index: i, tx, result: out.result, gas_used }).is_err() {
                                        return Err(NotParallel::Failed(i, "executed twice".to_string()));
                                    }
                                }
                                Ok(None) => {
                                    // The sender's later transfers would only
                                    // fail their nonce check: skipped unrun.
                                    skipped.push(i);
                                    break;
                                }
                                Err(err) => return Err(NotParallel::Failed(i, err.to_string())),
                            }
                        }
                        skipped.extend(rest.copied());
                    }
                }
                state.merge_transitions(BundleRetention::Reverts);
                let bundle = state.take_bundle();
                // Drained here, on the batch's own thread, right after its
                // transfers are done: `N42_PHASE_TIMERS=1` only (see
                // `fast_transfer::drain_timers`; zero and free otherwise). An
                // error path above returns before this and leaves whatever it
                // accumulated for a later call on this thread to drain --
                // rare (`NotParallel`, which sends the whole block to the
                // serial executor) and diagnostic-only.
                let timers = crate::fast_transfer::drain_timers();
                match on_bundle {
                    // Folded into the staged graft here, on this batch's
                    // thread: the work is off the builder's chain, and the
                    // sink's lock only ever holds one batch at a time.
                    Some(sink) => {
                        sink(bundle);
                        Ok((skipped, None, timers))
                    }
                    None => Ok((skipped, Some(bundle), timers)),
                }
            })
            .collect()
    });
    phases.groups_ms = at.elapsed().as_millis() as u64;

    let at = std::time::Instant::now();
    let mut run = BuildRun { phases, ..Default::default() };
    for r in results {
        let (skipped, bundle, timers) = r?;
        run.skipped.extend(skipped);
        if let Some(bundle) = bundle {
            run.bundles.push(bundle);
        }
        run.phases.transfer_timers.add(timers);
    }
    // Candidate order, as the serial builder would have laid the block out
    // (each sender's transfers were run in that order, and the graft does
    // not care): round 43's followers imported a sender-grouped block 35%
    // slower than the serial builder's. The slots are in that order already.
    if in_place {
        run.slots = slots;
    } else {
        run.executed = slots.into_iter().filter_map(|slot| slot.into_inner()).collect();
    }
    run.skipped.sort_unstable();
    run.phases.collect_ms = at.elapsed().as_millis() as u64;
    Ok(run)
}

/// Executes `block` with its transfers spread over the worker pool, or says
/// why it cannot. `main_db` is the parent's state the block's own executor
/// runs its pre- and post-execution changes on; `open` yields a fresh view of
/// the same parent for each group.
pub fn execute_transfers<EvmConfig, DB, G>(
    evm_config: &EvmConfig,
    block: &RecoveredBlock<Block>,
    main_db: DB,
    open: &(dyn Fn() -> Option<G> + Sync),
) -> Result<Result<(BlockExecutionOutput<Receipt>, Phases), NotParallel>, BlockExecutionError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, BlockExecutorFactory = FastExecutorFactory>,
    DB: Database + std::fmt::Debug,
    DB::Error: Send + Sync + 'static,
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    execute_transfers_with(evm_config, block, main_db, open, follower_graft(), follower_sender_groups())
}

/// Whether `N42_FOLLOWER_SENDER_GROUPS=1` is set: the follower groups a
/// block's transfers by sender, as the builder does, instead of by connected
/// component. A block of random transfers is ~200 components with a few
/// giant ones (partition 35-43 ms, the largest group setting the wall time);
/// by sender it is ~400 groups packed into 2 x workers batches. A transfer
/// that only another sender's credit in the same block would fund is refused
/// by its batch's view and sends the block to the serial path, as any
/// refusal does -- correct, and rare outside adversarial blocks.
pub fn follower_sender_groups() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_SENDER_GROUPS").is_ok_and(|v| v == "1"))
}

/// Whether `N42_GRAFT_STREAM=1` is set: a builder folds each batch's bundle
/// into the block's graft as that batch finishes ([`StagedGraft`]) instead of
/// all of them after the execution.
///
/// Off, and measured so (loop176, three pairs): the leader's fold falls 73 ->
/// 43-49 ms but its parallel step rises 78-84 -> 143-159, because the fold is
/// memory bandwidth and page faults rather than work that can be scheduled --
/// on a node whose ingest and imports are already using that bandwidth there
/// is nothing for it to hide in, and overlapping it costs more than it saves.
/// The bench, on an idle box, reads the opposite (5 ms against 49), which is
/// what makes it worth keeping behind a flag.
pub fn graft_stream() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_GRAFT_STREAM").is_ok_and(|v| v == "1"))
}

/// Whether a follower's import folds its batches' bundles the same way
/// (`N42_FOLLOWER_GRAFT_STREAM=0` goes back to grafting them after the
/// execution). On: it is the side of the change that paid on the fleet, over
/// four pairs of legs and with no invalid block among them -- the import
/// 344-363 -> 330-355 ms (loop176) and 355-356 -> 331-337 (loop177), since
/// the merge it removes is larger than the execution it lengthens, and fewer
/// imports run past 600 ms. The import gates both the vote and the build
/// after a tenure change. The leader's side of it costs and stays off
/// ([`graft_stream`]).
pub fn follower_graft_stream() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_GRAFT_STREAM").map_or(true, |v| v != "0"))
}

/// Whether the graft takes the largest bundle as the block's bundle (default;
/// `N42_GRAFT_BASE_SWAP=0` re-inserts every bundle, the behaviour before round
/// 43's loop98).
fn graft_base_swap() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_GRAFT_BASE_SWAP").map_or(true, |v| v != "0"))
}

/// Whether `N42_FOLLOWER_FREE_ASYNC=1` is set: the executor's own working
/// memory -- the transactions' environments, the groups, the batches'
/// bundles -- is freed on the worker pool rather than on the thread that
/// executed the block.
///
/// Off by default: on an idle bench it is worth 5-6 ms of a 120 ms call
/// ([`Phases::drop_us`]), and whether it is worth more on a node, where the
/// same 32 MB of environments is freed under the fleet's allocator settings
/// while the import thread is the chain's critical path, is a leg's question.
/// Nothing reads any of it again, so the only cost is a job on the pool.
pub fn free_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_FREE_ASYNC").is_ok_and(|v| v == "1"))
}

/// Whether `N42_FOLLOWER_GRAFT=1` is set: the follower folds the groups'
/// bundles into the block's state with [`graft_bundles`] instead of one
/// commit of the folded changes (round 43: the commit and its transition
/// merge were 265 ms of a 736 ms import of a block touching 147,000
/// accounts).
pub fn follower_graft() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_GRAFT").is_ok_and(|v| v == "1"))
}

/// [`execute_transfers`] with the fold chosen by the caller: `graft` folds
/// the groups' bundles with [`graft_bundles`], otherwise they are folded
/// with [`fold_bundles`] and committed.
pub fn execute_transfers_with<EvmConfig, DB, G>(
    evm_config: &EvmConfig,
    block: &RecoveredBlock<Block>,
    main_db: DB,
    open: &(dyn Fn() -> Option<G> + Sync),
    graft: bool,
    sender_groups: bool,
) -> Result<Result<(BlockExecutionOutput<Receipt>, Phases), NotParallel>, BlockExecutionError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, BlockExecutorFactory = FastExecutorFactory>,
    DB: Database + std::fmt::Debug,
    DB::Error: Send + Sync + 'static,
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut phases = Phases::default();
    let call_at = std::time::Instant::now();
    let evm_env = evm_config.evm_env(block.header()).map_err(BlockExecutionError::other)?;
    let beneficiary = evm_env.block_env.beneficiary;

    // The transactions' environments, and the partition.
    let at = std::time::Instant::now();
    // The environments on the worker pool: serially they were a third of a
    // 163,000-transfer block's 50 ms partition phase (round 43, loop94).
    let txs: Vec<TxEnv> = {
        use rayon::prelude::*;
        let recovered: Vec<_> = block.transactions_recovered().collect();
        recovered.par_iter().map(|tx| evm_config.tx_env(*tx)).collect()
    };
    phases.env_us = at.elapsed().as_micros() as u64;
    // Address-keyed with the fixed-bytes hasher: the default hasher was
    // ~29 ms of a 163,000-transfer block's partition.
    let groups: Vec<Vec<usize>> = if sender_groups {
        let mut keys: Vec<(Address, Address)> = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let alloy_primitives::TxKind::Call(to) = tx.kind else { return Ok(Err(NotParallel::NotATransfer(i))) };
            if !tx.data.is_empty() {
                return Ok(Err(NotParallel::NotATransfer(i)));
            }
            keys.push((tx.caller, to));
        }
        match partition_by_sender(&keys, beneficiary) {
            Ok(groups) => groups,
            Err(why) => return Ok(Err(why)),
        }
    } else {
        let components = if partition_hash() { partition_shared(&txs, beneficiary) } else { partition(&txs, beneficiary) };
        match components {
            Ok((groups, _)) => groups,
            Err(why) => return Ok(Err(why)),
        }
    };
    phases.partition_ms = at.elapsed().as_millis() as u64;
    phases.groups = groups.len();
    let at = std::time::Instant::now();
    // By sender the groups are many and small: packed into batches like the
    // builder's. By component each group is its own batch.
    let batches: Vec<Vec<&Vec<usize>>> = if sender_groups {
        batch_groups(&groups, txs.len(), rayon::current_num_threads())
    } else {
        groups.iter().map(|g| vec![g]).collect()
    };
    phases.batches = batches.len();

    // The batches, on the worker pool. Each yields its bundle (the accounts
    // it changed, with their originals) and the gas each transaction used --
    // or, with `N42_GRAFT_STREAM=1`, folds the bundle into the block's graft
    // there and then ([`StagedGraft`]) and yields only the gas.
    let staged = (graft && follower_graft_stream())
        .then(|| std::sync::Mutex::new(StagedGraft::new(beneficiary, txs.len())));
    phases.batch_us = at.elapsed().as_micros() as u64;
    let at = std::time::Instant::now();
    type FollowerBatchResult =
        (Option<revm::database::BundleState>, Vec<(usize, u64)>, crate::fast_transfer::TransferTimers);
    let results: Vec<Result<FollowerBatchResult, NotParallel>> = {
        use rayon::prelude::*;
        batches
            .par_iter()
            .map(|members| {
                let db = open().ok_or(NotParallel::NoState)?;
                let mut state = State::builder().with_database(db).with_bundle_update().build();
                let mut gas = Vec::with_capacity(members.iter().map(|g| g.len()).sum());
                {
                    let mut evm =
                        N42EvmFactory::with_fast_transfers(true).create_evm(&mut state, evm_env.clone());
                    for &i in members.iter().flat_map(|g| g.iter()) {
                        match evm.transfer(&txs[i]) {
                            Ok(Some(out)) => {
                                gas.push((i, out.result.gas_used()));
                                evm.db_mut().commit(out.state);
                            }
                            Ok(None) => return Err(NotParallel::NotATransfer(i)),
                            Err(err) => return Err(NotParallel::Failed(i, err.to_string())),
                        }
                    }
                }
                state.merge_transitions(BundleRetention::Reverts);
                let bundle = state.take_bundle();
                // See the leader's batch loop above: drained here, on the
                // batch's own thread, `N42_PHASE_TIMERS=1` only.
                let timers = crate::fast_transfer::drain_timers();
                match staged.as_ref() {
                    Some(staged) => {
                        staged.lock().expect("the staged graft's lock").add(bundle);
                        Ok((None, gas, timers))
                    }
                    None => Ok((Some(bundle), gas, timers)),
                }
            })
            .collect()
    };
    phases.groups_ms = at.elapsed().as_millis() as u64;
    let at = std::time::Instant::now();
    let mut bundles = Vec::with_capacity(results.len());
    let mut gas_of = vec![0u64; txs.len()];
    for r in results {
        match r {
            Ok((bundle, gas, timers)) => {
                for (i, g) in gas {
                    gas_of[i] = g;
                }
                if let Some(bundle) = bundle {
                    bundles.push(bundle);
                }
                phases.transfer_timers.add(timers);
            }
            Err(why) => return Ok(Err(why)),
        }
    }
    phases.gas_us = at.elapsed().as_micros() as u64;

    // The block's own executor: pre-execution changes (the system calls),
    // then -- with no transactions -- the post-execution changes (the
    // rewards), on the main state.
    let at = std::time::Instant::now();
    let mut state = State::builder().with_database(main_db).with_bundle_update().build();
    let result = {
        let ctx = evm_config.context_for_block(block.sealed_block()).map_err(BlockExecutionError::other)?;
        let evm = evm_config.evm_with_env(&mut state, evm_env.clone());
        let mut executor = evm_config.create_executor(evm, ctx);
        executor.apply_pre_execution_changes()?;
        let (_, result) = executor.finish()?;
        result
    };
    phases.finish_ms = at.elapsed().as_millis() as u64;

    // The groups' changes, as deltas on whatever the main state holds now:
    // an account a reward reached and a transfer touched gets both.
    let at = std::time::Instant::now();
    let err = |e: &dyn std::fmt::Display| BlockExecutionError::other(std::io::Error::other(e.to_string()));
    let (mut changes, beneficiary_delta, grafted) = if let Some(staged) = staged {
        let staged = staged.into_inner().expect("the staged graft's lock");
        let grafted = install_staged(&mut state, staged, false).map_err(|e| err(&e))?;
        (revm::state::EvmState::default(), grafted.beneficiary_delta, Some(grafted.reverts))
    } else if graft {
        // Taken rather than moved so the teardown below can free whatever
        // the chosen fold left behind.
        let grafted =
            graft_bundles_folded(&mut state, std::mem::take(&mut bundles), beneficiary, false, follower_graft_fold(), None)
                .map_err(|e| err(&e))?;
        (revm::state::EvmState::default(), grafted.beneficiary_delta, Some(grafted.reverts))
    } else {
        let (changes, delta) = fold_bundles(&mut state, &bundles, beneficiary).map_err(|e| err(&e))?;
        (changes, delta, None)
    };
    phases.graft_ms = at.elapsed().as_millis() as u64;
    if !beneficiary_delta.is_zero() {
        let current = state.basic(beneficiary).map_err(|e| err(&e))?;
        let existed = current.is_some();
        let mut merged = current.unwrap_or_default();
        merged.balance = merged.balance.saturating_add(beneficiary_delta);
        let mut acc = Account::from(merged);
        acc.status = AccountStatus::Touched;
        if !existed {
            acc.status |= AccountStatus::Created;
        }
        changes.insert(beneficiary, acc);
    }
    if !changes.is_empty() {
        state.commit(changes);
    }
    state.merge_transitions(BundleRetention::Reverts);
    let mut bundle = state.take_bundle();
    let taken = at.elapsed().as_millis() as u64;
    phases.take_ms = taken - phases.graft_ms;
    if let Some(reverts) = grafted {
        append_reverts(&mut bundle, reverts);
    }
    phases.merge_ms = at.elapsed().as_millis() as u64;
    phases.reverts_ms = phases.merge_ms - taken;

    // Receipts in block order, gas cumulated.
    let at = std::time::Instant::now();
    let mut cumulative = 0u64;
    let receipts: Vec<Receipt> = block
        .body()
        .transactions()
        .enumerate()
        .map(|(i, tx)| {
            cumulative += gas_of[i];
            Receipt { tx_type: tx.tx_type(), success: true, cumulative_gas_used: cumulative, logs: Vec::new() }
        })
        .collect();
    phases.receipts_us = at.elapsed().as_micros() as u64;
    let result = reth_execution_types::BlockExecutionResult { receipts, gas_used: cumulative, ..result };

    // The teardown, here rather than at the return: 163,000 transaction
    // environments, the groups and the batches' bundles are freed either way,
    // and a caller that reads `total_us` against its own `exec_ms` would
    // otherwise see them as time nothing named.
    //
    // `N42_FOLLOWER_FREE_ASYNC=1` hands the owned parts to the pool. The
    // environments alone are ~32 MB a full block, and with the fleet's
    // allocator settings (`oversize_threshold:0, dirty_decay_ms:2000`) a
    // block's worth of them is page work, not free-list work: 5 ms on an idle
    // bench, and the import thread is the one place it must not be. The
    // batches only borrow the groups, so they are freed here either way.
    let at = std::time::Instant::now();
    drop(batches);
    if free_async() {
        rayon::spawn(move || {
            drop(txs);
            drop(groups);
            drop(bundles);
            drop(gas_of);
        });
    } else {
        drop(groups);
        drop(txs);
        drop(bundles);
        drop(gas_of);
    }
    phases.drop_us = at.elapsed().as_micros() as u64;

    phases.total_us = call_at.elapsed().as_micros() as u64;
    Ok(Ok((BlockExecutionOutput { state: bundle, result }, phases)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, Signed, TxEip1559};
    use alloy_primitives::{Bytes, Signature, TxKind, B256};
    use reth_chainspec::MAINNET;
    use reth_ethereum_primitives::TransactionSigned;
    use reth_evm::execute::Executor as _;
    use reth_primitives_traits::{Recovered, SealedBlock};
    use revm::database::{CacheDB, EmptyDB};
    use revm::state::AccountInfo;

    fn addr(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    /// One shared copy of a bench's accounts, read through an `Arc`.
    ///
    /// The parallel executor opens a database per batch, and the benches
    /// below hand it a `CacheDB`. Cloning one that holds the flood's two
    /// million accounts, 240 times a block, would be all the bench measured;
    /// on a node every batch opens a state provider over the same store.
    #[derive(Debug, Clone)]
    struct SharedDb(std::sync::Arc<CacheDB<EmptyDB>>);

    impl Database for SharedDb {
        type Error = <CacheDB<EmptyDB> as revm::DatabaseRef>::Error;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            revm::DatabaseRef::basic_ref(&*self.0, address)
        }

        fn code_by_hash(&mut self, code_hash: B256) -> Result<revm::state::Bytecode, Self::Error> {
            revm::DatabaseRef::code_by_hash_ref(&*self.0, code_hash)
        }

        fn storage(
            &mut self,
            address: Address,
            index: U256,
        ) -> Result<U256, Self::Error> {
            revm::DatabaseRef::storage_ref(&*self.0, address, index)
        }

        fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
            revm::DatabaseRef::block_hash_ref(&*self.0, number)
        }
    }

    /// A block of `n` transfers among `senders` accounts, every sender
    /// paying a few recipients in turn, some of them fresh, some shared.
    fn fixture(senders: u64, per: u64) -> (RecoveredBlock<Block>, CacheDB<EmptyDB>) {
        let mut db = CacheDB::new(EmptyDB::default());
        let beneficiary = addr(1);
        db.insert_account_info(beneficiary, AccountInfo { balance: U256::from(7), ..Default::default() });
        let mut txs = Vec::new();
        let mut recovered = Vec::new();
        for s in 0..senders {
            let sender = addr(100 + s);
            db.insert_account_info(sender, AccountInfo { balance: U256::from(10u128.pow(21)), nonce: 3, ..Default::default() });
            for k in 0..per {
                // Recipients: another sender (shared), a fresh account, and
                // the same fresh account again from a different sender.
                let to = match k % 3 {
                    0 => addr(100 + (s + 1) % senders),
                    1 => addr(10_000 + s * per + k),
                    _ => addr(20_000 + k),
                };
                let inner = TxEip1559 {
                    chain_id: 1,
                    nonce: 3 + k,
                    gas_limit: 21_000,
                    max_fee_per_gas: 10_000_000_000,
                    max_priority_fee_per_gas: 1_000_000_000,
                    to: TxKind::Call(to),
                    value: U256::from(1_000 + k),
                    input: Bytes::new(),
                    ..Default::default()
                };
                let signed = Signed::new_unchecked(inner, Signature::test_signature(), B256::random());
                let tx = n42_tx_types::N42TxEnvelope::from(TransactionSigned::from(signed));
                txs.push(tx.clone());
                recovered.push(sender);
            }
        }
        // Past the merge on mainnet, so the serial executor pays no
        // block reward: the builder path credits only the fees.
        let header = Header {
            number: 20_000_000,
            beneficiary,
            gas_limit: 1_000_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            timestamp: 1_800_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        };
        let body = n42_tx_types::BlockBody {
            transactions: txs,
            ommers: Vec::new(),
            withdrawals: Some(vec![alloy_eips::eip4895::Withdrawal { index: 0, validator_index: 0, address: addr(100), amount: 5 }].into()),
        };
        let block = SealedBlock::seal_slow(Block { header, body });
        (RecoveredBlock::new_sealed(block, recovered), db)
    }

    #[test]
    fn parallel_matches_serial() {
        parallel_matches_serial_with(false, false);
    }

    #[test]
    fn parallel_matches_serial_with_the_graft() {
        parallel_matches_serial_with(true, false);
    }

    #[test]
    fn parallel_matches_serial_by_sender_with_the_graft() {
        parallel_matches_serial_with(true, true);
    }

    #[test]
    fn parallel_matches_serial_by_sender_with_the_fold() {
        parallel_matches_serial_with(false, true);
    }

    fn parallel_matches_serial_with(graft: bool, sender_groups: bool) {
        let (block, db) = fixture(8, 6);
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let serial = evm_config.executor(db.clone()).execute(&block).expect("serial execution");
        let (parallel, phases) = execute_transfers_with(&evm_config, &block, db.clone(), &|| Some(db.clone()), graft, sender_groups)
            .expect("no execution error")
            .expect("the block qualifies");
        assert!(phases.groups >= 1);
        assert_eq!(parallel.result.gas_used, serial.result.gas_used, "gas used");
        assert_eq!(parallel.result.receipts, serial.result.receipts, "receipts");
        assert_eq!(parallel.result.requests, serial.result.requests, "requests");
        assert_eq!(parallel.state.state.len(), serial.state.state.len(), "accounts in the bundle");
        for (address, theirs) in &serial.state.state {
            let ours = parallel.state.state.get(address).unwrap_or_else(|| panic!("account {address} missing"));
            assert_eq!(ours.info, theirs.info, "info {address}");
            assert_eq!(ours.original_info, theirs.original_info, "original {address}");
            assert_eq!(ours.status, theirs.status, "status {address}");
        }
        assert_eq!(parallel.state.reverts.len(), serial.state.reverts.len(), "revert blocks");
        let mut ours: Vec<_> = parallel.state.reverts[0].iter().map(|(a, r)| (*a, r.clone())).collect();
        let mut theirs: Vec<_> = serial.state.reverts[0].iter().map(|(a, r)| (*a, r.clone())).collect();
        ours.sort_by_key(|(a, _)| *a);
        theirs.sort_by_key(|(a, _)| *a);
        assert_eq!(ours, theirs, "reverts");
    }


    /// With the cache not kept and the block's bundle still empty, the
    /// largest bundle is taken whole as the block's bundle and the others
    /// are grafted onto it: an account both hold is added as a delta and
    /// keeps the base's revert.
    #[test]
    fn the_largest_bundle_becomes_the_base_and_the_rest_are_grafted_onto_it() {
        let info = |balance: u64, nonce: u64| AccountInfo { balance: U256::from(balance), nonce, ..Default::default() };
        // (address, balance and nonce after, balance and nonce before or None for a fresh account)
        let bundle = |accounts: &[(Address, u64, u64, Option<(u64, u64)>)]| {
            let mut b = BundleState::builder(0..=0);
            for (address, balance, nonce, original) in accounts {
                b = b.state_present_account_info(*address, info(*balance, *nonce));
                b = match original {
                    Some((ob, on)) => b
                        .state_original_account_info(*address, info(*ob, *on))
                        .revert_account_info(0, *address, Some(Some(info(*ob, *on)))),
                    None => b.revert_account_info(0, *address, Some(None)),
                };
            }
            b.build()
        };
        let big = bundle(&[(addr(1), 90, 1, Some((100, 0))), (addr(2), 10, 0, None), (addr(3), 5, 0, None)]);
        let small = bundle(&[(addr(2), 5, 0, None), (addr(4), 7, 0, None)]);
        let mut state = State::builder().with_database(CacheDB::new(EmptyDB::default())).with_bundle_update().build();
        let graft = graft_bundles_with(&mut state, vec![small, big], addr(9), false).expect("graft");
        assert_eq!(graft.accounts, 4, "three from the base, one grafted; the shared one is a delta");
        assert_eq!(graft.committed, 0);
        assert_eq!(state.bundle_state.state.len(), 4);
        let shared = state.bundle_state.state.get(&addr(2)).and_then(|a| a.info.as_ref()).expect("shared account");
        assert_eq!(shared.balance, U256::from(15), "the small bundle's credit added onto the base's");
        assert_eq!(state.bundle_state.state.get(&addr(1)).and_then(|a| a.info.as_ref()).map(|i| i.nonce), Some(1));
        let mut reverted: Vec<Address> = graft.reverts.iter().map(|(a, _)| *a).collect();
        reverted.sort();
        assert_eq!(reverted, vec![addr(1), addr(2), addr(3), addr(4)], "one revert per account, the shared one the base's");
    }

    /// Two batches touching an account the block's state already holds both
    /// land: their deltas are summed against the block's value, which does not
    /// change until the graft's one commit at the end.
    #[test]
    fn two_bundles_touching_an_account_the_block_holds() {
        let info = |balance: u64, nonce: u64| AccountInfo { balance: U256::from(balance), nonce, ..Default::default() };
        let bundle = |address: Address, after: (u64, u64), before: (u64, u64)| {
            BundleState::builder(0..=0)
                .state_present_account_info(address, info(after.0, after.1))
                .state_original_account_info(address, info(before.0, before.1))
                .revert_account_info(0, address, Some(Some(info(before.0, before.1))))
                .build()
        };
        let held = addr(5);
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(held, info(100, 0));
        let mut state = State::builder().with_database(db).with_bundle_update().build();
        // The block's state already read the account: it is in the cache, so
        // the graft cannot stage it and takes the delta path for it.
        assert_eq!(state.basic(held).unwrap().map(|a| a.balance), Some(U256::from(100)));
        let first = bundle(held, (110, 1), (100, 0));
        let second = bundle(held, (105, 0), (100, 0));
        let graft = graft_bundles_with(&mut state, vec![first, second], addr(9), true).expect("graft");
        assert_eq!(graft.committed, 1, "one account committed as a delta");
        assert_eq!(graft.accounts, 0, "nothing was staged");
        let after = state.cache.accounts.get(&held).and_then(|a| a.account.as_ref()).expect("the account").info.clone();
        assert_eq!(after.balance, U256::from(115), "both batches' credits, not just the last one's");
        assert_eq!(after.nonce, 1, "the first batch's nonce bump");
    }

    /// Everything the fold leaves behind, in an order that does not depend
    /// on which fold left it: a hash map's iteration order does, and nothing
    /// downstream of the graft reads it (the QMDB operations and the hashed
    /// post-state are both sorted by their own key).
    #[derive(Debug, PartialEq, Eq)]
    struct FoldSnapshot {
        accounts: Vec<(Address, Option<AccountInfo>, Option<AccountInfo>, revm::database::AccountStatus)>,
        state_size: usize,
        cache: Vec<(Address, Option<AccountInfo>)>,
        reverts: Vec<(Address, AccountRevert)>,
        grafted: usize,
        committed: usize,
        beneficiary_delta: U256,
    }

    fn fold_fixture_info(balance: u64, nonce: u64) -> AccountInfo {
        AccountInfo { balance: U256::from(balance), nonce, ..Default::default() }
    }

    /// Four batches of a block whose accounts overlap the way a real one's
    /// do: two recipients every batch pays, a recipient that is another
    /// batch's sender, the beneficiary every batch credits from the same
    /// starting balance, one account the block's own state may already hold,
    /// and a revert for every one of them.
    fn fold_fixture_bundles(beneficiary: Address, held: Address, batches: u64) -> Vec<BundleState> {
        let info = fold_fixture_info;
        let mut bundles = Vec::new();
        for batch in 0..batches {
            let mut b = BundleState::builder(0..=0);
            let sender = addr(100 + batch);
            b = b
                .state_present_account_info(sender, info(1_000 - 10 * (batch + 1), batch + 1))
                .state_original_account_info(sender, info(1_000, 0))
                .revert_account_info(0, sender, Some(Some(info(1_000, 0))));
            for k in 0..6u64 {
                // The first two are shared by every batch; the rest are this
                // batch's own.
                let to = if k < 2 { addr(1_000 + k) } else { addr(2_000 + batch * 6 + k) };
                b = b.state_present_account_info(to, info(1 + batch, 0)).revert_account_info(0, to, Some(None));
            }
            // Another batch's sender, paid here: an account two batches hold
            // with the same original.
            let cross = addr(100 + (batch + 1) % batches);
            b = b
                .state_present_account_info(cross, info(1_007, 0))
                .state_original_account_info(cross, info(1_000, 0))
                .revert_account_info(0, cross, Some(Some(info(1_000, 0))));
            b = b
                .state_present_account_info(held, info(100 + batch + 1, 0))
                .state_original_account_info(held, info(100, 0))
                .revert_account_info(0, held, Some(Some(info(100, 0))));
            b = b
                .state_present_account_info(beneficiary, info(7 + batch + 1, 0))
                .state_original_account_info(beneficiary, info(7, 0))
                .revert_account_info(0, beneficiary, Some(Some(info(7, 0))));
            bundles.push(b.build());
        }
        bundles
    }

    /// The fixture folded in two goes -- so the second one finds the block's
    /// bundle already carrying the first's accounts, which is the path a
    /// builder takes when its serial loop ran before the graft.
    fn fold_fixture_run(fold: GraftFold, keep_cache: bool, held_in_cache: bool) -> FoldSnapshot {
        let beneficiary = addr(9);
        let held = addr(5);
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(held, fold_fixture_info(100, 0));
        let mut state = State::builder().with_database(db).with_bundle_update().build();
        if held_in_cache {
            // Read by the block's own state before the graft: the account is
            // in the cache, so the fold must take the delta path for it.
            assert_eq!(state.basic(held).expect("the held account").map(|a| a.balance), Some(U256::from(100)));
        }
        let mut bundles = fold_fixture_bundles(beneficiary, held, 4);
        let rest = bundles.split_off(2);
        let mut grafted = 0usize;
        let mut committed = 0usize;
        let mut delta = U256::ZERO;
        let mut reverts = Vec::new();
        for half in [bundles, rest] {
            let graft = graft_bundles_folded(&mut state, half, beneficiary, keep_cache, fold, None).expect("the fold");
            grafted += graft.accounts;
            committed += graft.committed;
            delta = delta.saturating_add(graft.beneficiary_delta);
            reverts.extend(graft.reverts);
        }
        let mut accounts: Vec<(Address, Option<AccountInfo>, Option<AccountInfo>, revm::database::AccountStatus)> = state
            .bundle_state
            .state
            .iter()
            .map(|(address, account)| (*address, account.info.clone(), account.original_info.clone(), account.status))
            .collect();
        accounts.sort_by_key(|(address, ..)| *address);
        let mut cache: Vec<(Address, Option<AccountInfo>)> = state
            .cache
            .accounts
            .iter()
            .map(|(address, account)| (*address, account.account.as_ref().map(|a| a.info.clone())))
            .collect();
        cache.sort_by_key(|(address, _)| *address);
        reverts.sort_by_key(|(address, _)| *address);
        FoldSnapshot {
            accounts,
            state_size: state.bundle_state.state_size,
            cache,
            reverts,
            grafted,
            committed,
            beneficiary_delta: delta,
        }
    }

    /// The indexed fold leaves the block exactly where the fold in place
    /// does -- the same accounts with the same values and originals, the
    /// same size, the same cache, the same reverts, the same beneficiary
    /// credit -- with the cache kept and not, and with the held account in
    /// the block's state and not (which is also the base swap on and off).
    #[test]
    fn the_indexed_fold_equals_the_graft() {
        for keep_cache in [false, true] {
            for held_in_cache in [false, true] {
                let direct = fold_fixture_run(GraftFold::Direct, keep_cache, held_in_cache);
                assert!(!direct.accounts.is_empty(), "the fixture folds something");
                for fold in [GraftFold::Indexed, GraftFold::IndexedRanges] {
                    let other = fold_fixture_run(fold, keep_cache, held_in_cache);
                    assert_eq!(other, direct, "{fold:?}, keep_cache {keep_cache}, held in cache {held_in_cache}");
                }
            }
        }
    }

    /// The same, on a block big enough for the index to sort and for the
    /// ranges to be more than one: 4,000 accounts over sixteen batches,
    /// with the shared recipients a real block has.
    #[test]
    fn the_indexed_fold_equals_the_graft_on_a_block() {
        let beneficiary = addr(9);
        let info = fold_fixture_info;
        let bundles = |batches: u64, per: u64| -> Vec<BundleState> {
            let mut out = Vec::new();
            let mut seed = 0x9e3779b97f4a7c15u64;
            for batch in 0..batches {
                let mut b = BundleState::builder(0..=0);
                let sender = addr(100 + batch);
                b = b
                    .state_present_account_info(sender, info(1_000_000 - per * (batch + 1), per))
                    .state_original_account_info(sender, info(1_000_000, 0))
                    .revert_account_info(0, sender, Some(Some(info(1_000_000, 0))));
                for _ in 0..per {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    // Drawn from a space a tenth the size of the block, so
                    // most accounts are one batch's and some are several.
                    let to = addr(1_000_000 + seed % (batches * per / 10));
                    b = b.state_present_account_info(to, info(1 + batch, 0)).revert_account_info(0, to, Some(None));
                }
                b = b
                    .state_present_account_info(beneficiary, info(7 + batch + 1, 0))
                    .state_original_account_info(beneficiary, info(7, 0))
                    .revert_account_info(0, beneficiary, Some(Some(info(7, 0))));
                out.push(b.build());
            }
            out
        };
        let make = |fold: GraftFold, prefault: bool| {
            let mut state =
                State::builder().with_database(CacheDB::new(EmptyDB::default())).with_bundle_update().build();
            // A target smaller than the block, so the graft also grows it.
            let target = prefault.then(|| GraftTarget::prefaulted(1_000));
            let graft =
                graft_bundles_folded(&mut state, bundles(16, 500), beneficiary, false, fold, target).expect("the fold");
            let mut accounts: Vec<(Address, Option<AccountInfo>, revm::database::AccountStatus)> = state
                .bundle_state
                .state
                .iter()
                .map(|(address, account)| (*address, account.info.clone(), account.status))
                .collect();
            accounts.sort_by_key(|(address, ..)| *address);
            let mut reverts = graft.reverts;
            reverts.sort_by_key(|(address, _)| *address);
            (accounts, state.bundle_state.state_size, reverts, graft.accounts, graft.beneficiary_delta)
        };
        let direct = make(GraftFold::Direct, false);
        assert!(direct.0.len() > 500, "the fixture is a block, not a handful");
        for fold in [GraftFold::Direct, GraftFold::Indexed, GraftFold::IndexedRanges] {
            for prefault in [false, true] {
                assert_eq!(make(fold, prefault), direct, "{fold:?}, prefault {prefault}, on a block");
            }
        }
    }

    /// An account a batch created and destroyed again -- no present value,
    /// no original, a revert of its own -- alone and as another batch's
    /// recipient, beside a sender that is also paid: every fold leaves the
    /// block what the fold in place does, including the reverts it keeps
    /// for the account that has no value.
    #[test]
    fn the_indexed_fold_equals_the_graft_on_a_destroyed_account() {
        let beneficiary = addr(9);
        let info = fold_fixture_info;
        let destroyed = addr(700);
        let destroyed_then_paid = addr(701);
        let bundles = || -> Vec<BundleState> {
            let first = BundleState::builder(0..=0)
                .state_present_account_info(addr(100), info(900, 1))
                .state_original_account_info(addr(100), info(1_000, 0))
                .revert_account_info(0, addr(100), Some(Some(info(1_000, 0))))
                .state_address(destroyed)
                .revert_address(0, destroyed)
                .state_address(destroyed_then_paid)
                .revert_address(0, destroyed_then_paid)
                .state_present_account_info(addr(101), info(1_050, 0))
                .state_original_account_info(addr(101), info(1_000, 0))
                .revert_account_info(0, addr(101), Some(Some(info(1_000, 0))))
                .state_present_account_info(beneficiary, info(8, 0))
                .state_original_account_info(beneficiary, info(7, 0))
                .revert_account_info(0, beneficiary, Some(Some(info(7, 0))))
                .build();
            let second = BundleState::builder(0..=0)
                .state_present_account_info(addr(101), info(940, 1))
                .state_original_account_info(addr(101), info(1_000, 0))
                .revert_account_info(0, addr(101), Some(Some(info(1_000, 0))))
                .state_present_account_info(destroyed_then_paid, info(10, 0))
                .revert_account_info(0, destroyed_then_paid, Some(None))
                .state_present_account_info(addr(100), info(1_010, 0))
                .state_original_account_info(addr(100), info(1_000, 0))
                .revert_account_info(0, addr(100), Some(Some(info(1_000, 0))))
                .state_present_account_info(beneficiary, info(9, 0))
                .state_original_account_info(beneficiary, info(7, 0))
                .revert_account_info(0, beneficiary, Some(Some(info(7, 0))))
                .build();
            vec![first, second]
        };
        let make = |fold: GraftFold, keep_cache: bool, prefault: bool| {
            let mut state =
                State::builder().with_database(CacheDB::new(EmptyDB::default())).with_bundle_update().build();
            let target = prefault.then(|| GraftTarget::prefaulted(64));
            let graft =
                graft_bundles_folded(&mut state, bundles(), beneficiary, keep_cache, fold, target).expect("the fold");
            let mut accounts: Vec<(Address, Option<AccountInfo>, Option<AccountInfo>, revm::database::AccountStatus)> = state
                .bundle_state
                .state
                .iter()
                .map(|(address, account)| (*address, account.info.clone(), account.original_info.clone(), account.status))
                .collect();
            accounts.sort_by_key(|(address, ..)| *address);
            let mut reverts = graft.reverts;
            reverts.sort_by_key(|(address, _)| *address);
            (accounts, state.bundle_state.state_size, reverts, graft.accounts, graft.beneficiary_delta)
        };
        for keep_cache in [false, true] {
            let direct = make(GraftFold::Direct, keep_cache, false);
            assert!(direct.2.iter().any(|(address, _)| *address == destroyed), "the destroyed account's revert is kept");
            assert_eq!(direct.4, U256::from(3), "the beneficiary's credit from both batches");
            let sender = direct.0.iter().find(|(address, ..)| *address == addr(101)).expect("the paid sender");
            assert_eq!(sender.1.as_ref().map(|i| (i.balance, i.nonce)), Some((U256::from(990), 1)));
            for fold in [GraftFold::Direct, GraftFold::Indexed, GraftFold::IndexedRanges] {
                for prefault in [false, true] {
                    assert_eq!(make(fold, keep_cache, prefault), direct, "{fold:?}, keep_cache {keep_cache}, prefault {prefault}");
                }
            }
        }
    }

    /// What one full block's worth of inserts into the block's bundle map
    /// costs, taken apart: a fresh table against one whose pages are already
    /// mapped, and accounts in random order against the order of the
    /// table's buckets. Plan v5 attempt D's question -- is the graft the
    /// probes, the page faults or the bytes.
    #[test]
    #[ignore = "timing"]
    fn bench_map_insert() {
        use std::hash::BuildHasher as _;
        let n = 161_760usize;
        let info = AccountInfo { balance: U256::from(5u64), nonce: 1, ..Default::default() };
        let account = BundleAccount::new(Some(info.clone()), Some(info), Default::default(), revm::database::AccountStatus::Changed);
        let mut seed = 0x9e3779b97f4a7c15u64;
        let addresses: Vec<Address> = (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                addr(seed)
            })
            .collect();
        eprintln!("BundleAccount {} bytes, (Address, BundleAccount) {} bytes", std::mem::size_of::<BundleAccount>(), std::mem::size_of::<(Address, BundleAccount)>());
        for round in 0..3 {
            let mut fresh: BundleState = BundleState::default();
            let at = std::time::Instant::now();
            fresh.state.reserve(n);
            let reserve = at.elapsed();
            let at = std::time::Instant::now();
            for address in &addresses {
                fresh.state.insert(*address, account.clone());
            }
            let random_fresh = at.elapsed();
            fresh.state.clear();
            let at = std::time::Instant::now();
            for address in &addresses {
                fresh.state.insert(*address, account.clone());
            }
            let random_mapped = at.elapsed();
            let hasher = fresh.state.hasher().clone();
            let mut sorted = addresses.clone();
            let mask = (fresh.state.capacity() * 8 / 7).next_power_of_two() as u64 - 1;
            sorted.sort_by_key(|a| hasher.hash_one(*a) & mask);
            fresh.state.clear();
            let at = std::time::Instant::now();
            for address in &sorted {
                fresh.state.insert(*address, account.clone());
            }
            let sorted_mapped = at.elapsed();
            let mut other: BundleState = BundleState::default();
            other.state.reserve(n);
            let at = std::time::Instant::now();
            for address in &sorted {
                other.state.insert(*address, account.clone());
            }
            let sorted_fresh = at.elapsed();
            // The bytes alone: a vector of the same entries written in order.
            let at = std::time::Instant::now();
            let mut flat: Vec<(Address, BundleAccount)> = Vec::with_capacity(n);
            for address in &addresses {
                flat.push((*address, account.clone()));
            }
            let flat_fresh = at.elapsed();
            eprintln!(
                "round {round}: reserve {reserve:?}; random into fresh {random_fresh:?}, into mapped {random_mapped:?}; bucket order into fresh {sorted_fresh:?}, into mapped {sorted_mapped:?}; a flat vector {flat_fresh:?}"
            );
            drop((fresh, other, flat));
        }
    }

    /// The build-mode run, committed in its order with the beneficiary
    /// credited once, ends in the same state as the serial executor.
    #[test]
    fn build_run_matches_serial() {
        use alloy_consensus::Transaction as _;
        let (block, db) = fixture(8, 6);
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let serial = evm_config.executor(db.clone()).execute(&block).expect("serial execution");
        let evm_env = evm_config.evm_env(block.header()).expect("env");
        let envs: Vec<TxEnv> = block.transactions_recovered().map(|tx| evm_config.tx_env(tx)).collect();
        let keys: Vec<(Address, Address)> = envs.iter().map(|e| (e.caller, e.kind.to().copied().unwrap())).collect();
        let run = execute_for_build(&evm_env, &keys, &|i| ((), envs[i].clone()), &|| Some(db.clone())).expect("a block of transfers");
        assert!(run.skipped.is_empty(), "{:?}", run.skipped);
        assert_eq!(run.executed.len(), envs.len());
        assert_eq!(run.phases.groups, 8, "one group per sender");
        assert!(run.phases.batches >= 1);

        let beneficiary = evm_env.block_env.beneficiary;
        let base_fee = evm_env.block_env.basefee;
        let txs: Vec<_> = block.transactions_recovered().collect();
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let mut fees = U256::ZERO;
        let mut gas = 0u64;
        for built in &run.executed {
            let tip = txs[built.index].effective_tip_per_gas(base_fee).unwrap_or_default();
            fees += U256::from(tip) * U256::from(built.gas_used);
            gas += built.gas_used;
        }
        let graft = graft_bundles(&mut state, run.bundles, beneficiary).unwrap();
        assert_eq!(graft.beneficiary_delta, fees, "the batches credited the beneficiary the summed tips");
        assert_eq!(graft.committed, 0, "nothing was in the block's cache yet");
        assert!(!state.cache.accounts.contains_key(&beneficiary), "beneficiary left out");
        let mut changes = revm::state::EvmState::default();
        let current = state.basic(beneficiary).unwrap();
        let existed = current.is_some();
        let mut info = current.unwrap_or_default();
        info.balance += graft.beneficiary_delta;
        let mut account = Account::from(info);
        account.status = AccountStatus::Touched;
        if !existed {
            account.status |= AccountStatus::Created;
        }
        changes.insert(beneficiary, account);
        state.commit(changes);
        // The block executor pays the withdrawal at finish; the builder's
        // parallel step does not, so apply it here before comparing.
        for w in block.body().withdrawals.as_ref().unwrap().iter() {
            let mut info = state.basic(w.address).unwrap().unwrap_or_default();
            info.balance += U256::from(w.amount_wei());
            let mut account = Account::from(info);
            account.status = AccountStatus::Touched;
            let mut changes = revm::state::EvmState::default();
            changes.insert(w.address, account);
            state.commit(changes);
        }
        state.merge_transitions(BundleRetention::Reverts);
        let mut bundle = state.take_bundle();
        append_reverts(&mut bundle, graft.reverts);

        assert_eq!(gas, serial.result.gas_used, "gas used");
        assert_eq!(bundle.state.len(), serial.state.state.len(), "accounts in the bundle");
        for (address, theirs) in &serial.state.state {
            let ours = bundle.state.get(address).unwrap_or_else(|| panic!("account {address} missing"));
            assert_eq!(ours.info, theirs.info, "info {address}");
            assert_eq!(ours.original_info, theirs.original_info, "original {address}");
            assert_eq!(ours.status, theirs.status, "status {address}");
        }
        // The reverts: one set for the block, the same entry per account.
        assert_eq!(bundle.reverts.len(), 1);
        assert_eq!(serial.state.reverts.len(), 1);
        let ours: std::collections::BTreeMap<_, _> = bundle.reverts[0].iter().cloned().collect();
        let theirs: std::collections::BTreeMap<_, _> = serial.state.reverts[0].iter().cloned().collect();
        assert_eq!(ours.len(), theirs.len(), "reverts");
        for (address, revert) in &theirs {
            assert_eq!(ours.get(address), Some(revert), "revert {address}");
        }
    }

    /// An account the block's state already holds leaves the staged bundle at
    /// the install and becomes a delta, exactly as the graft after the
    /// execution makes it one -- including its revert, which is the block's
    /// own, not the graft's.
    #[test]
    fn a_staged_graft_delta_matches_the_graft_for_an_account_the_block_holds() {
        let info = |balance: u64, nonce: u64| AccountInfo { balance: U256::from(balance), nonce, ..Default::default() };
        let bundle = |address: Address, after: (u64, u64), before: (u64, u64)| {
            BundleState::builder(0..=0)
                .state_present_account_info(address, info(after.0, after.1))
                .state_original_account_info(address, info(before.0, before.1))
                .revert_account_info(0, address, Some(Some(info(before.0, before.1))))
                .build()
        };
        let held = addr(5);
        let fresh = addr(6);
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(held, info(100, 0));
        db.insert_account_info(fresh, info(7, 0));
        let bundles = || {
            vec![
                bundle(held, (110, 1), (100, 0)),
                {
                    let mut b = BundleState::builder(0..=0)
                        .state_present_account_info(held, info(105, 0))
                        .state_original_account_info(held, info(100, 0))
                        .revert_account_info(0, held, Some(Some(info(100, 0))));
                    b = b
                        .state_present_account_info(fresh, info(9, 0))
                        .state_original_account_info(fresh, info(7, 0))
                        .revert_account_info(0, fresh, Some(Some(info(7, 0))));
                    b.build()
                },
            ]
        };

        let mut after = State::builder().with_database(db.clone()).with_bundle_update().build();
        assert_eq!(after.basic(held).unwrap().map(|a| a.balance), Some(U256::from(100)), "the block read it");
        let grafted = graft_bundles_with(&mut after, bundles(), addr(9), true).expect("graft");

        let mut beside = State::builder().with_database(db.clone()).with_bundle_update().build();
        assert_eq!(beside.basic(held).unwrap().map(|a| a.balance), Some(U256::from(100)));
        let mut staged = StagedGraft::new(addr(9), 4);
        for b in bundles() {
            staged.add(b);
        }
        let installed = install_staged(&mut beside, staged, true).expect("install");

        assert_eq!(installed.committed, grafted.committed, "committed as deltas");
        assert_eq!(installed.accounts, grafted.accounts, "staged accounts");
        let balance = |state: &State<CacheDB<EmptyDB>>, address: Address| {
            state.cache.accounts.get(&address).and_then(|a| a.account.as_ref()).map(|a| (a.info.balance, a.info.nonce))
        };
        assert_eq!(balance(&beside, held), balance(&after, held), "the held account");
        assert_eq!(balance(&beside, held), Some((U256::from(115), 1)), "both batches' deltas");
        assert_eq!(
            beside.bundle_state.state.get(&fresh).and_then(|a| a.info.as_ref()).map(|i| i.balance),
            after.bundle_state.state.get(&fresh).and_then(|a| a.info.as_ref()).map(|i| i.balance),
            "the staged account",
        );
        let sorted = |mut reverts: Vec<(Address, AccountRevert)>| {
            reverts.sort_by_key(|(address, _)| *address);
            reverts
        };
        assert_eq!(sorted(installed.reverts), sorted(grafted.reverts), "reverts");
    }

    /// The staged graft, folded bundle by bundle beside the execution and
    /// installed at the end, lands exactly where the graft after the
    /// execution does: the same accounts, the same reverts, the same credit.
    #[test]
    fn a_staged_graft_lands_where_the_graft_does() {
        let (block, db) = fixture(8, 6);
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let evm_env = evm_config.evm_env(block.header()).expect("env");
        let envs: Vec<TxEnv> = block.transactions_recovered().map(|tx| evm_config.tx_env(tx)).collect();
        let keys: Vec<(Address, Address)> = envs.iter().map(|e| (e.caller, e.kind.to().copied().unwrap())).collect();
        let run = execute_for_build(&evm_env, &keys, &|i| ((), envs[i].clone()), &|| Some(db.clone())).expect("a block of transfers");
        let beneficiary = evm_env.block_env.beneficiary;

        let mut after = State::builder().with_database(db.clone()).with_bundle_update().build();
        let grafted = graft_bundles(&mut after, run.bundles.clone(), beneficiary).expect("graft");

        let mut beside = State::builder().with_database(db.clone()).with_bundle_update().build();
        let mut staged = StagedGraft::new(beneficiary, keys.len());
        for bundle in run.bundles {
            staged.add(bundle);
        }
        let installed = install_staged(&mut beside, staged, true).expect("install");

        assert_eq!(installed.beneficiary_delta, grafted.beneficiary_delta, "the beneficiary's credit");
        assert_eq!(installed.committed, grafted.committed);
        assert_eq!(beside.bundle_state.state.len(), after.bundle_state.state.len(), "accounts");
        assert_eq!(beside.bundle_state.state_size, after.bundle_state.state_size, "state size");
        for (address, theirs) in &after.bundle_state.state {
            let ours = beside.bundle_state.state.get(address).unwrap_or_else(|| panic!("account {address} missing"));
            assert_eq!(ours.info, theirs.info, "info {address}");
            assert_eq!(ours.original_info, theirs.original_info, "original {address}");
            assert_eq!(ours.status, theirs.status, "status {address}");
        }
        assert_eq!(beside.cache.accounts.len(), after.cache.accounts.len(), "the cache both keep");
        let sorted = |mut reverts: Vec<(Address, AccountRevert)>| {
            reverts.sort_by_key(|(address, _)| *address);
            reverts
        };
        assert_eq!(sorted(installed.reverts), sorted(grafted.reverts), "reverts");
    }

    /// An account the block touches again after the graft -- here a sender
    /// that a later, serially executed transfer debits -- keeps one revert
    /// in the block's set, the graft's, to the parent's value.
    #[test]
    fn a_later_touch_of_a_grafted_account_keeps_the_grafts_revert() {
        let (block, db) = fixture(3, 2);
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let evm_env = evm_config.evm_env(block.header()).expect("env");
        let envs: Vec<TxEnv> = block.transactions_recovered().map(|tx| evm_config.tx_env(tx)).collect();
        let keys: Vec<(Address, Address)> = envs.iter().map(|e| (e.caller, e.kind.to().copied().unwrap())).collect();
        // Graft all but the last transfer; run the last one serially after.
        let n = envs.len() - 1;
        let run = execute_for_build(&evm_env, &keys[..n], &|i| ((), envs[i].clone()), &|| Some(db.clone())).expect("transfers");
        assert_eq!(run.executed.len(), n);
        let beneficiary = evm_env.block_env.beneficiary;
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let graft = graft_bundles(&mut state, run.bundles, beneficiary).unwrap();
        let last = &envs[n];
        let sender = last.caller;
        let grafted_sender = state.cache.accounts.get(&sender).and_then(|a| a.account.as_ref()).map(|a| a.info.clone()).expect("the sender was grafted");
        {
            let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(&mut state, evm_env.clone());
            let out = evm.transfer(last).unwrap().expect("a transfer");
            evm.db_mut().commit(out.state);
        }
        state.merge_transitions(BundleRetention::Reverts);
        let mut bundle = state.take_bundle();
        // Before the append: the merge's revert for the sender, to the grafted value.
        let merged: Vec<_> = bundle.reverts[0].iter().filter(|(a, _)| *a == sender).collect();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].1.account, revm::database::states::reverts::AccountInfoRevert::RevertTo(grafted_sender));
        append_reverts(&mut bundle, graft.reverts);
        let reverts: Vec<_> = bundle.reverts[0].iter().filter(|(a, _)| *a == sender).collect();
        assert_eq!(reverts.len(), 1, "one revert for the sender");
        let parent = db.clone().basic(sender).unwrap().unwrap();
        assert_eq!(reverts[0].1.account, revm::database::states::reverts::AccountInfoRevert::RevertTo(parent));
        let mut addresses: Vec<Address> = bundle.reverts[0].iter().map(|(a, _)| *a).collect();
        let sorted = { let mut v = addresses.clone(); v.sort(); v };
        assert_eq!(addresses, sorted, "sorted by address");
        addresses.dedup();
        assert_eq!(addresses.len(), bundle.reverts[0].len(), "no account twice");
        assert_eq!(bundle.reverts_size, bundle.reverts[0].len());
    }

    /// The block's own reverts are merged into the graft's sorted set from the
    /// back: everything ends sorted, an account both carry keeps the graft's
    /// (to the parent's value), and nothing appears twice.
    #[test]
    fn the_blocks_own_reverts_merge_into_the_grafts_sorted_set() {
        use revm::database::states::reverts::{AccountInfoRevert, Reverts};
        let revert = |nonce: u64| AccountRevert {
            account: AccountInfoRevert::RevertTo(AccountInfo { nonce, ..Default::default() }),
            ..Default::default()
        };
        // The graft's: 5,000 addresses in no order, past the parallel sort's threshold.
        let mut seed = 0x243f6a8885a308d3u64;
        let mut grafted: Vec<(Address, AccountRevert)> = (0..5_000u64)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (addr(1_000 + i), revert(i))
            })
            .collect();
        grafted.swap(0, 4_999);
        grafted.swap(17, 2_500);
        // The block's own: two the graft also carries, and three it does not
        // -- one below every grafted address, one above, one between.
        let own = vec![
            (addr(1_017), revert(999_017)),
            (addr(4_000), revert(999_000)),
            (addr(1), revert(1)),
            (addr(9_999), revert(2)),
            (addr(500), revert(3)),
        ];
        let mut bundle = BundleState {
            state: Default::default(),
            contracts: Default::default(),
            reverts: Reverts::new(vec![own]),
            state_size: 0,
            reverts_size: 0,
        };
        append_reverts(&mut bundle, grafted);

        let merged = &bundle.reverts[0];
        assert_eq!(merged.len(), 5_000 + 3, "the graft's, plus the block's own that it does not carry");
        let addresses: Vec<Address> = merged.iter().map(|(address, _)| *address).collect();
        let mut sorted = addresses.clone();
        sorted.sort();
        assert_eq!(addresses, sorted, "sorted by address");
        sorted.dedup();
        assert_eq!(sorted.len(), merged.len(), "no account twice");
        let at = |address: Address| {
            merged.iter().find(|(held, _)| *held == address).map(|(_, revert)| revert.clone()).expect("present")
        };
        assert_eq!(at(addr(1_017)), revert(17), "the graft's revert, not the block's later one");
        assert_eq!(at(addr(500)), revert(3), "the block's own, which the graft does not carry");
        assert_eq!(at(addr(1)), revert(1), "below every grafted address");
        assert_eq!(at(addr(9_999)), revert(2), "above every grafted address");
        assert_eq!(bundle.reverts_size, merged.len());
    }

    /// A full bench-tier block (163,000 transfers, 6,000 senders, recipients
    /// drawn from two million) through the serial transfer path and through
    /// `execute_for_build`, timed. `cargo test -p n42-engine-types --release
    /// A block of `senders x per` transfers to recipients drawn at random
    /// from `space` accounts (the bench's shape: 6,000 x 27 over 2,000,000
    /// gives ~147,000 distinct accounts), the senders interleaved as the
    /// queue lays them out.
    fn random_fixture(senders: u64, per: u64, space: u64, run: usize, spread: u64) -> (RecoveredBlock<Block>, CacheDB<EmptyDB>) {
        let mut db = CacheDB::new(EmptyDB::default());
        let beneficiary = addr(1);
        db.insert_account_info(beneficiary, AccountInfo { balance: U256::from(7), ..Default::default() });
        let mut by_sender: Vec<Vec<(n42_tx_types::N42TxEnvelope, Address)>> = Vec::with_capacity(senders as usize);
        let mut seed = 0x9e3779b97f4a7c15u64;
        for s in 0..senders {
            let sender = addr(100 + s);
            db.insert_account_info(sender, AccountInfo { balance: U256::from(10u128.pow(21)), nonce: 0, ..Default::default() });
            let mut lane = Vec::with_capacity(per as usize);
            for k in 0..per {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                // `space` 0: each sender draws from its own range of
                // `spread` x per addresses (repeats only within a sender, as
                // the fleet's flood mostly produces: ~210 components a
                // block); otherwise a shared space, where a few thousand
                // repeats join every sender into one component.
                let to =
                    if space == 0 { addr(1_000_000 + s * per * spread + seed % (per * spread)) } else { addr(1_000_000 + seed % space) };
                let inner = TxEip1559 {
                    chain_id: 1,
                    nonce: k,
                    gas_limit: 21_000,
                    max_fee_per_gas: 10_000_000_000,
                    max_priority_fee_per_gas: 1_000_000_000,
                    to: TxKind::Call(to),
                    value: U256::from(1_000 + k),
                    input: Bytes::new(),
                    ..Default::default()
                };
                let signed = Signed::new_unchecked(inner, Signature::test_signature(), B256::random());
                lane.push((n42_tx_types::N42TxEnvelope::from(TransactionSigned::from(signed)), sender));
            }
            by_sender.push(lane);
        }
        // Interleaved as the queue lays them out: `run` transactions of a
        // sender, then the next sender's.
        let mut txs = Vec::with_capacity((senders * per) as usize);
        let mut recovered = Vec::with_capacity((senders * per) as usize);
        let mut k = 0usize;
        while k < per as usize {
            for lane in &by_sender {
                for (tx, sender) in &lane[k..(k + run).min(per as usize)] {
                    txs.push(tx.clone());
                    recovered.push(*sender);
                }
            }
            k += run;
        }
        let header = Header {
            number: 20_000_000,
            beneficiary,
            gas_limit: 10_000_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            timestamp: 1_800_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        };
        let body = n42_tx_types::BlockBody { transactions: txs, ommers: Vec::new(), withdrawals: Some(Vec::new().into()) };
        let block = SealedBlock::seal_slow(Block { header, body });
        (RecoveredBlock::new_sealed(block, recovered), db)
    }

    /// Where the follower's parallel execution of a bench-shaped block goes,
    /// by component groups (the follower's default) and by sender groups,
    /// with the graft.
    ///
    /// ```text
    /// RAYON_NUM_THREADS=16 taskset -c 0-31 \
    ///   cargo test --release -p n42-engine-types --lib bench_follower_import -- --ignored --nocapture
    /// ```
    ///
    /// The line it prints carries the same fields as a node's
    /// `parallel import phases`, so a leg and a bench can be read against
    /// each other. What it reads against loop202 (four nodes, pacing 225,
    /// 163,000-transfer blocks, `RAYON_NUM_THREADS=16`): the executor's whole
    /// call 121 ms against the leg's `exec_ms` 131-136, partition 17 against
    /// 31-33, groups 88 against 55-56, merge 6 against 8-10. So it
    /// reproduces the phases inside 2x and the leg is the slower box; what it
    /// does *not* reproduce is the unnamed part, 6-8 ms here against ~37 on a
    /// node, which is why `drop_us` is worth a flag and a leg
    /// ([`free_async`]).
    ///
    /// `BENCH_SENDERS`/`BENCH_PER`/`BENCH_RUN`/`BENCH_SPREAD` shape the block
    /// and `BENCH_PREFILL`/`BENCH_SPARE` the state it executes on; the
    /// defaults are the fleet's.
    #[test]
    #[ignore = "timing"]
    fn bench_follower_import() {
        let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        // `BENCH_SPREAD` 8: a sender's 429 transfers draw from 3,432
        // addresses, so ~400 of them are distinct and the block touches
        // ~150,000 accounts, the leg's `updated`.
        // Defaults: the fleet's block shape. A leg's own numbers pin it --
        // the builder's `par_groups` is 378-384 distinct senders a block and
        // its `updated` is 150,800-151,535 accounts (loop202 C225a), so a
        // block is ~380 senders paying ~429 recipients each, nearly all of
        // them distinct, which the follower's component partition reads as
        // the 222-345 groups its line reports.
        let (senders, per, space, run) =
            (env("BENCH_SENDERS", 380), env("BENCH_PER", 429), env("BENCH_SPACE", 0), env("BENCH_RUN", 64));
        let (block, mut db) = random_fixture(senders, per, space, run as usize, env("BENCH_SPREAD", 8));
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let mut distinct: std::collections::HashSet<Address> = Default::default();
        for (sender, tx) in block.transactions_with_sender() {
            distinct.insert(*sender);
            if let alloy_primitives::TxKind::Call(to) = alloy_consensus::Transaction::kind(tx) {
                distinct.insert(to);
            }
        }
        // `BENCH_PREFILL=1` (the default): every account the block touches is
        // already in the database, and beside it `BENCH_SPARE` more. A fleet
        // node reads the recipients of a full block from a state that holds
        // the flood's two million accounts; a database that answers `None`
        // without touching memory makes the groups phase look cheaper than it
        // is on a node.
        if env("BENCH_PREFILL", 1) == 1 {
            // The senders are already there with the balance and nonce the
            // block needs; only the recipients are added, and the spare
            // accounts beside them are what makes the look-up miss its cache.
            for address in &distinct {
                if !db.cache.accounts.contains_key(address) {
                    db.insert_account_info(*address, AccountInfo { balance: U256::from(1u64), ..Default::default() });
                }
            }
            for i in 0..env("BENCH_SPARE", 2_000_000) {
                db.insert_account_info(addr(30_000_000 + i), AccountInfo { balance: U256::from(1u64), ..Default::default() });
            }
        }
        println!(
            "block: {} transfers, {} distinct accounts, {} in the database, {} rayon threads",
            block.transaction_count(),
            distinct.len(),
            db.cache.accounts.len(),
            rayon::current_num_threads(),
        );
        let db = SharedDb(std::sync::Arc::new(db));
        for (label, graft, sender_groups) in [("components+graft", true, false), ("senders+graft", true, true), ("components+fold", false, false)] {
            for round in 0..3 {
                let at = std::time::Instant::now();
                let (out, phases) =
                    execute_transfers_with(&evm_config, &block, db.clone(), &|| Some(db.clone()), graft, sender_groups)
                        .expect("no execution error")
                        .expect("the block qualifies");
                // The same fields the node's `parallel import phases` line
                // carries, in the same order, so a bench table and a leg's
                // line can be read against each other.
                let named = phases.partition_ms * 1_000
                    + phases.batch_us
                    + phases.groups_ms * 1_000
                    + phases.gas_us
                    + phases.finish_ms * 1_000
                    + phases.merge_ms * 1_000
                    + phases.receipts_us
                    + phases.drop_us;
                println!(
                    "{label} #{round}: call {} ms  partition {} (env {}) batch {} groups {} ({} groups, {} batches) gas {} merge {} [graft {} take {} reverts {}] finish {} receipts {} drop {} other {}  -> {} accounts, {} reverts",
                    at.elapsed().as_millis(),
                    phases.partition_ms,
                    phases.env_us / 1000,
                    phases.batch_us / 1000,
                    phases.groups_ms,
                    phases.groups,
                    phases.batches,
                    phases.gas_us / 1000,
                    phases.merge_ms,
                    phases.graft_ms,
                    phases.take_ms,
                    phases.reverts_ms,
                    phases.finish_ms,
                    phases.receipts_us / 1000,
                    phases.drop_us / 1000,
                    phases.total_us.saturating_sub(named) / 1000,
                    out.state.state.len(),
                    out.state.reverts.iter().map(Vec::len).sum::<usize>(),
                );
            }
        }
    }

    /// A full bench-tier block (162,000 transfers, 6,000 senders, recipients
    /// drawn from two million) through the serial transfer path and through
    /// [`execute_for_build`], timed -- with the three phases the build pays
    /// after the execution named apart, because those are what plan v5
    /// attempt D is about: the *collect* (the batches' results placed in
    /// candidate order), the *commit* (the receipts and the block's body) and
    /// the *fold* (the graft of the batches' bundles).
    ///
    /// ```text
    /// RAYON_NUM_THREADS=16 taskset -c 0-31 \
    ///   cargo test --release -p n42-engine-types --lib bench_build_run -- --ignored --nocapture
    /// ```
    ///
    /// The transactions are the builder's own (`Recovered<N42TxEnvelope>`,
    /// ~400 bytes each): with a unit payload the collect moves nothing and
    /// reads a tenth of what a node's does.
    ///
    /// What it reads against loop214 (four nodes, 163,000-transfer blocks,
    /// `RAYON_NUM_THREADS=16`): the leg's `par_exec_ms` 72-81,
    /// `par_collect_ms` 18, `par_commit_ms` 18-22 and the graft
    /// (`par_fold_ms` less `par_commit_ms`) 56-64. The bench, idle box
    /// (2026-09-23): exec 94-96, collect 4-5, commit 9.5-10.5, graft 42-54,
    /// the transactions root beside it 13.5-16 -- the graft within 1.3x of
    /// the leg's, the commit at half, the collect at a quarter (the node's
    /// transactions are the pool's, allocated by other threads, and its
    /// memory is shared with three other nodes). With the transfers left
    /// in their slots and the graft's memory mapped beside the execution:
    /// collect 0, commit 5, graft 26.5-27, exec +2-3.
    #[test]
    #[ignore = "timing"]
    fn bench_build_run() {
        use rayon::prelude::*;
        let senders = 6_000u64;
        let per = 27u64;
        let mut db = CacheDB::new(EmptyDB::default());
        let beneficiary = addr(1);
        db.insert_account_info(beneficiary, AccountInfo { balance: U256::from(7), ..Default::default() });
        let mut envs = Vec::new();
        let mut seed = 0x9e3779b97f4a7c15u64;
        for s in 0..senders {
            let sender = addr(100 + s);
            db.insert_account_info(sender, AccountInfo { balance: U256::from(10u128.pow(21)), nonce: 0, ..Default::default() });
            for k in 0..per {
                seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                let to = addr(1_000_000 + seed % 2_000_000);
                let mut env = TxEnv::default();
                env.caller = sender;
                env.kind = TxKind::Call(to);
                env.value = U256::from(1_000 + k);
                env.gas_limit = 21_000;
                env.gas_price = 10_000_000_000;
                env.gas_priority_fee = Some(1_000_000_000);
                env.nonce = k;
                env.tx_type = 2;
                env.chain_id = Some(1);
                envs.push(env);
            }
        }
        // Interleave senders as the queue does.
        let mut order: Vec<TxEnv> = Vec::with_capacity(envs.len());
        for k in 0..per as usize {
            for s in 0..senders as usize {
                order.push(envs[s * per as usize + k].clone());
            }
        }
        let envs = order;
        // The transactions themselves, as the builder hands them to the
        // batches: the collect and the commit move these, not the envs.
        let signed: Vec<n42_tx_types::N42TxEnvelope> = envs
            .iter()
            .map(|env| {
                let inner = TxEip1559 {
                    chain_id: 1,
                    nonce: env.nonce,
                    gas_limit: env.gas_limit,
                    max_fee_per_gas: env.gas_price,
                    max_priority_fee_per_gas: env.gas_priority_fee.unwrap_or_default(),
                    to: env.kind,
                    value: env.value,
                    input: Bytes::new(),
                    ..Default::default()
                };
                let signed = Signed::new_unchecked(inner, Signature::test_signature(), B256::random());
                n42_tx_types::N42TxEnvelope::from(TransactionSigned::from(signed))
            })
            .collect();
        let header = Header { number: 20_000_000, beneficiary, gas_limit: 5_000_000_000, base_fee_per_gas: Some(1_000_000_000), timestamp: 1_800_000_000, ..Default::default() };
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let evm_env = evm_config.evm_env(&header).expect("env");
        let keys: Vec<(Address, Address)> = envs.iter().map(|e| (e.caller, e.kind.to().copied().unwrap_or_default())).collect();
        let convert = |i: usize| (Recovered::new_unchecked(signed[i].clone(), envs[i].caller), envs[i].clone());
        println!("block: {} transfers, {} rayon threads", envs.len(), rayon::current_num_threads());
        for round in 0..3 {
            let at = std::time::Instant::now();
            let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
            let mut in_transfer = std::time::Duration::ZERO;
            let mut in_commit = std::time::Duration::ZERO;
            {
                let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(&mut state, evm_env.clone());
                for env in &envs {
                    let t = std::time::Instant::now();
                    let out = evm.transfer(env).unwrap().expect("a transfer");
                    in_transfer += t.elapsed();
                    let t = std::time::Instant::now();
                    evm.db_mut().commit(out.state);
                    in_commit += t.elapsed();
                }
            }
            let serial = at.elapsed();
            let at = std::time::Instant::now();
            state.merge_transitions(BundleRetention::PlainState);
            let bundle = state.take_bundle();
            let merge = at.elapsed();
            eprintln!("serial: transfer {in_transfer:?} commit {in_commit:?} merge {merge:?} ({} accounts)", bundle.state.len());

            // The build's own phases, once per fold, each on its own run of
            // the same block. The fold is the one that differs; the others
            // are printed so a leg's line can be read against this.
            let mut direct: Option<(usize, usize, U256, usize, usize)> = None;
            // (fold, collect in place, graft memory mapped beside the step)
            let configs = [
                (GraftFold::Direct, false, false),
                (GraftFold::Indexed, false, false),
                (GraftFold::IndexedRanges, false, false),
                (GraftFold::Direct, true, false),
                (GraftFold::Direct, true, true),
                (GraftFold::Indexed, true, true),
                (GraftFold::IndexedRanges, true, true),
            ];
            for (fold, in_place, prefault) in configs {
                let at = std::time::Instant::now();
                let (run, target) = std::thread::scope(|scope| {
                    let target = prefault.then(|| scope.spawn(|| GraftTarget::prefaulted(keys.len() + keys.len() / 4)));
                    let run = execute_for_build_in_place(&evm_env, &keys, &convert, &|| Some(db.clone()), None, in_place)
                        .expect("a block of transfers");
                    (run, target.map(|job| job.join().expect("the prefault does not panic")))
                });
                let par = at.elapsed();
                let prefault_us = target.as_ref().map_or(0, |t| t.prefault_us);
                let BuildRun { executed, bundles, skipped, phases, slots } = run;
                // The receipts and the body, as the builder builds them for a
                // block that seals early (`par_commit_ms`): out of the
                // collected vector, or out of the slots by reference
                // (`N42_BUILD_COLLECT_IN_PLACE`).
                let at = std::time::Instant::now();
                let (executed_count, transactions, tx_senders, receipts) = if in_place {
                    let refs: Vec<&BuiltTransfer<_>> = slots.iter().filter_map(std::sync::OnceLock::get).collect();
                    let mut cumulative = Vec::with_capacity(refs.len());
                    let mut tx_gas = 0u64;
                    for built in &refs {
                        tx_gas += built.gas_used;
                        cumulative.push(tx_gas);
                    }
                    let transactions: Vec<n42_tx_types::N42TxEnvelope> =
                        refs.par_iter().map(|built| built.tx.inner().clone()).collect();
                    let tx_senders: Vec<Address> = refs.par_iter().map(|built| built.tx.signer()).collect();
                    let receipts: Vec<Receipt> = refs
                        .par_iter()
                        .zip(cumulative.par_iter())
                        .map(|(built, cumulative_gas_used)| Receipt {
                            tx_type: <n42_tx_types::N42TxEnvelope as alloy_consensus::TransactionEnvelope>::tx_type(built.tx.inner()),
                            success: built.result.is_success(),
                            cumulative_gas_used: *cumulative_gas_used,
                            logs: built.result.logs().to_vec(),
                        })
                        .collect();
                    (refs.len(), transactions, tx_senders, receipts)
                } else {
                    let executed_count = executed.len();
                    let mut cumulative = Vec::with_capacity(executed_count);
                    let mut tx_gas = 0u64;
                    for built in &executed {
                        tx_gas += built.gas_used;
                        cumulative.push(tx_gas);
                    }
                    let (transactions, rest): (Vec<n42_tx_types::N42TxEnvelope>, Vec<(Address, Receipt)>) = executed
                        .into_par_iter()
                        .zip(cumulative.into_par_iter())
                        .map(|(built, cumulative_gas_used)| {
                            let tx_type =
                                <n42_tx_types::N42TxEnvelope as alloy_consensus::TransactionEnvelope>::tx_type(built.tx.inner());
                            let receipt = Receipt {
                                tx_type,
                                success: built.result.is_success(),
                                cumulative_gas_used,
                                logs: built.result.into_logs(),
                            };
                            let (tx, sender) = built.tx.into_parts();
                            (tx, (sender, receipt))
                        })
                        .unzip();
                    let (tx_senders, receipts): (Vec<Address>, Vec<Receipt>) = rest.into_par_iter().unzip();
                    (executed_count, transactions, tx_senders, receipts)
                };
                let commit = at.elapsed();
                // Freed off the chain, as the builder frees them.
                build_pool().spawn(move || drop(slots));
                // The fold, on a state of the block's own: `keep_cache` false
                // is what a block that seals early uses.
                // The transactions root runs beside it on the global pool,
                // as the builder runs it for a block that seals early:
                // `par_fold_ms` is the longer of the two.
                let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
                let at = std::time::Instant::now();
                let (graft, grafted, root_took) = std::thread::scope(|scope| {
                    let txs: &[n42_tx_types::N42TxEnvelope] = &transactions;
                    let root = scope.spawn(move || {
                        let at = std::time::Instant::now();
                        let root = crate::assembler::parallel_transaction_root(txs);
                        (root, at.elapsed())
                    });
                    let graft = graft_bundles_folded(&mut state, bundles, beneficiary, false, fold, target).expect("the fold");
                    let grafted = at.elapsed();
                    let (_root, root_took) = root.join().expect("the transactions root job does not panic");
                    (graft, grafted, root_took)
                });
                let beside = at.elapsed();
                let at = std::time::Instant::now();
                state.merge_transitions(BundleRetention::Reverts);
                let mut bundle = state.take_bundle();
                let reverts = graft.reverts.len();
                let accounts = graft.accounts;
                let delta = graft.beneficiary_delta;
                let inside = format!(
                    "prepare {} sort {} merge {} apply {} reverts {}",
                    graft.prepare_us / 1000,
                    graft.sort_us / 1000,
                    graft.merge_us / 1000,
                    graft.apply_us / 1000,
                    graft.reverts_us / 1000,
                );
                append_reverts(&mut bundle, graft.reverts);
                let merge = at.elapsed();
                // The first half of the builder's `roots_ms`: the QMDB
                // operations, walked out of the bundle and sorted by key.
                let at = std::time::Instant::now();
                let ops = n42_qmdb_reth::sorted_operations_from_execution(&bundle, true);
                let ops_took = at.elapsed();
                eprintln!(
                    "round {round} {fold:?} in_place {in_place} prefault {prefault} ({} ms beside): par {par:?} (partition {} ms, {} groups in {} batches, exec {} ms, collect {} ms, skipped {}) commit {commit:?} graft {grafted:?} [{inside}] tx root {root_took:?} graft|root {beside:?} (fold ~ commit + this) state_ready merge {merge:?} qmdb ops {ops_took:?} ({} ops) -> {} accounts, {} committed, {} reverts, {} txs, {} receipts",
                    prefault_us / 1000,
                    phases.partition_ms,
                    phases.groups,
                    phases.batches,
                    phases.groups_ms,
                    phases.collect_ms,
                    skipped.len(),
                    ops.len(),
                    bundle.state.len(),
                    graft.committed,
                    bundle.reverts[0].len(),
                    transactions.len(),
                    receipts.len(),
                );
                assert_eq!(tx_senders.len(), transactions.len());
                let here = (bundle.state.len(), accounts, delta, reverts, executed_count);
                match &direct {
                    None => direct = Some(here),
                    Some(theirs) => assert_eq!(&here, theirs, "{fold:?} folds the block the way the fold in place does"),
                }
            }

            // The same block again, with each batch folding its bundle into
            // the staged graft as it finishes: what the execution hides and
            // what is left for the install.
            let (_, grafted_accounts, delta, revert_count, executed_count) = direct.expect("the direct fold ran");
            let at = std::time::Instant::now();
            let staged = std::sync::Mutex::new(StagedGraft::new(beneficiary, keys.len()));
            let sink = |bundle: BundleState| staged.lock().expect("the staged graft's lock").add(bundle);
            let streamed_run =
                execute_for_build_with(&evm_env, &keys, &convert, &|| Some(db.clone()), Some(&sink))
                    .expect("a block of transfers");
            let streamed_groups = at.elapsed();
            let at = std::time::Instant::now();
            let mut streamed_state = State::builder().with_database(db.clone()).with_bundle_update().build();
            let installed =
                install_staged(&mut streamed_state, staged.into_inner().expect("the staged graft's lock"), false).unwrap();
            let installed_ms = at.elapsed();
            assert_eq!(installed.accounts, grafted_accounts, "the staged graft holds the same accounts");
            assert_eq!(installed.beneficiary_delta, delta);
            assert_eq!(streamed_run.executed.len(), executed_count);
            // The same block again with the fold spread over shards, one lock
            // each: what the single mutex costs the parallel step is the
            // question (loop176: +65 ms on the fleet), and what the shards
            // cannot remove is the one map reth's bundle is.
            let shard_count: usize = std::env::var("BENCH_GRAFT_SHARDS").ok().and_then(|v| v.parse().ok()).unwrap_or(64);
            let at = std::time::Instant::now();
            let sharded = ShardedGraft::new(beneficiary, keys.len(), shard_count);
            let shard_sink = |bundle: BundleState| sharded.add(bundle);
            let sharded_run =
                execute_for_build_with(&evm_env, &keys, &convert, &|| Some(db.clone()), Some(&shard_sink))
                    .expect("a block of transfers");
            let sharded_groups = at.elapsed();
            let staged_accounts = sharded.accounts();
            let at = std::time::Instant::now();
            let (merged_state, _size, merged_reverts, merged_delta) = sharded.merge();
            let merged_ms = at.elapsed();
            assert_eq!(sharded_run.executed.len(), executed_count);
            assert_eq!(merged_state.len(), grafted_accounts, "the shards hold what the graft does");
            assert_eq!(staged_accounts, grafted_accounts);
            assert_eq!(merged_delta, delta);
            assert_eq!(merged_reverts.len(), revert_count);
            eprintln!(
                "round {round}: serial {serial:?}; streamed: execution+fold {streamed_groups:?}, install {installed_ms:?}"
            );
            eprintln!(
                "round {round}: sharded ({shard_count} shards): execution+fold {sharded_groups:?}, merge to one map {merged_ms:?}"
            );
        }
    }

    /// [`partition`] memoises a sender's party across the run the queue lays
    /// its transactions out in, which is only sound if it still returns the
    /// connected components of the block's sender/recipient graph. Checked
    /// as the three properties that define them, at run lengths 1, 7 and 64,
    /// so no layout can pass by accident.
    #[test]
    fn the_partition_is_the_components_whatever_the_run_length() {
        let beneficiary = addr(1);
        let env_for =
            |from: Address, to: Address| TxEnv { caller: from, kind: TxKind::Call(to), gas_limit: 21_000, ..Default::default() };
        for run in [1usize, 7, 64] {
            // 40 senders, 12 transfers each; every third recipient is another
            // sender's, so some senders share a component and some do not.
            let senders = 40u64;
            let per = 12u64;
            let mut lanes: Vec<Vec<TxEnv>> = Vec::new();
            for s in 0..senders {
                let from = addr(100 + s);
                let mut lane = Vec::new();
                for k in 0..per {
                    let to = if k % 3 == 0 { addr(100 + (s * 7 + k) % senders) } else { addr(10_000 + s * per + k) };
                    if to == from {
                        lane.push(env_for(from, addr(20_000 + s * per + k)));
                    } else {
                        lane.push(env_for(from, to));
                    }
                }
                lanes.push(lane);
            }
            let mut txs: Vec<TxEnv> = Vec::new();
            let mut k = 0usize;
            while k < per as usize {
                for lane in &lanes {
                    txs.extend_from_slice(&lane[k..(k + run).min(per as usize)]);
                }
                k += run;
            }
            let (groups, parties) = partition(&txs, beneficiary).expect("a block of transfers");

            // Every transaction in exactly one group, in block order.
            let mut seen: Vec<usize> = groups.iter().flatten().copied().collect();
            assert_eq!(seen.len(), txs.len(), "run {run}: every transaction once");
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), txs.len(), "run {run}: no transaction twice");
            for group in &groups {
                let mut order = group.clone();
                order.sort_unstable();
                assert_eq!(*group, order, "run {run}: a group is in block order");
            }

            // No address in two groups, and two transactions that share one
            // in the same group: together, the connected components.
            let mut group_of: std::collections::HashMap<Address, usize> = Default::default();
            for (g, group) in groups.iter().enumerate() {
                for &i in group {
                    for address in [txs[i].caller, txs[i].kind.to().copied().expect("a call")] {
                        let held = *group_of.entry(address).or_insert(g);
                        assert_eq!(held, g, "run {run}: {address} is in two groups");
                    }
                }
            }
            assert_eq!(group_of.len(), parties, "run {run}: the parties counted are the addresses touched");
        }
    }

    /// `N42_FOLLOWER_PARTITION_HASH=1` ([`partition_shared`]) must be the
    /// same partition as [`partition`], not merely a valid one: the groups,
    /// in the same order, and the same refusal at the same index. Chosen by
    /// calling the two functions, so the test does not depend on the flag.
    #[test]
    fn the_hash_partition_is_the_serial_one() {
        let beneficiary = addr(1);
        let env_for =
            |from: Address, to: Address| TxEnv { caller: from, kind: TxKind::Call(to), gas_limit: 21_000, ..Default::default() };
        // Three shapes: recipients of their own, recipients two senders
        // share, and recipients that are senders.
        for (senders, per, run, shape) in [(40u64, 12u64, 1usize, 0u8), (40, 12, 7, 1), (37, 23, 64, 2), (5, 3, 2, 2)] {
            let mut lanes: Vec<Vec<TxEnv>> = Vec::new();
            for s in 0..senders {
                let from = addr(100 + s);
                let mut lane = Vec::new();
                for k in 0..per {
                    let to = match shape {
                        0 => addr(10_000 + s * per + k),
                        1 => {
                            if k % 4 == 0 {
                                addr(10_000 + (s * per + k) % 17)
                            } else {
                                addr(10_000 + s * per + k)
                            }
                        }
                        _ => {
                            if k % 3 == 0 {
                                addr(100 + (s * 7 + k) % senders)
                            } else {
                                addr(10_000 + s * per + k)
                            }
                        }
                    };
                    lane.push(env_for(from, if to == from { addr(20_000 + s * per + k) } else { to }));
                }
                lanes.push(lane);
            }
            let mut txs: Vec<TxEnv> = Vec::new();
            let mut k = 0usize;
            while k < per as usize {
                for lane in &lanes {
                    txs.extend_from_slice(&lane[k..(k + run).min(per as usize)]);
                }
                k += run;
            }
            let (serial, _) = partition(&txs, beneficiary).expect("a block of transfers");
            let (shared, _) = partition_shared(&txs, beneficiary).expect("a block of transfers");
            assert_eq!(shared, serial, "shape {shape}, run {run}: the same groups in the same order");

            // The same refusal, at the same index, for a block that is not
            // all transfers and for one that pays the beneficiary.
            let mut not_a_transfer = txs.clone();
            not_a_transfer[3].data = alloy_primitives::Bytes::from_static(&[1]);
            assert!(
                matches!(
                    (partition(&not_a_transfer, beneficiary), partition_shared(&not_a_transfer, beneficiary)),
                    (Err(NotParallel::NotATransfer(a)), Err(NotParallel::NotATransfer(b))) if a == 3 && b == 3
                ),
                "shape {shape}: both refuse transaction 3"
            );
            let mut pays_beneficiary = txs.clone();
            pays_beneficiary[2].kind = TxKind::Call(beneficiary);
            assert!(
                matches!(
                    (partition(&pays_beneficiary, beneficiary), partition_shared(&pays_beneficiary, beneficiary)),
                    (Err(NotParallel::TouchesBeneficiary(a)), Err(NotParallel::TouchesBeneficiary(b))) if a == 2 && b == 2
                ),
                "shape {shape}: both refuse transaction 2"
            );
        }
    }

    /// The bench's block shape through both partitions: 163,000 transfers is
    /// where they could differ and a 500-transfer fixture could not show it.
    #[test]
    fn the_hash_partition_is_the_serial_one_on_a_full_block() {
        let (block, _) = random_fixture(64, 200, 0, 64, 8);
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let evm_env = evm_config.evm_env(block.header()).expect("an environment");
        let txs: Vec<TxEnv> = block.transactions_recovered().map(|tx| evm_config.tx_env(tx)).collect();
        let beneficiary = evm_env.block_env.beneficiary;
        let (serial, _) = partition(&txs, beneficiary).expect("a block of transfers");
        let (shared, _) = partition_shared(&txs, beneficiary).expect("a block of transfers");
        assert_eq!(shared, serial, "the same groups in the same order");
    }

    #[test]
    fn a_transfer_to_the_beneficiary_falls_back() {
        let (mut block, db) = fixture(2, 1);
        // Point the first transfer at the beneficiary.
        let hash = block.hash();
        let mut raw = block.clone_sealed_block().into_block();
        if let n42_tx_types::N42TxEnvelope::Eth(TransactionSigned::Eip1559(signed)) = &mut raw.body.transactions[0] {
            let (mut tx, sig, _) = signed.clone().into_parts();
            tx.to = TxKind::Call(addr(1));
            *signed = Signed::new_unchecked(tx, sig, B256::random());
        }
        let senders = block.senders().to_vec();
        block = RecoveredBlock::new_unhashed(raw, senders);
        let _ = hash;
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let out = execute_transfers(&evm_config, &block, db.clone(), &|| Some(db.clone())).expect("no execution error");
        assert!(matches!(out, Err(NotParallel::TouchesBeneficiary(0))), "{out:?}");
    }

    /// A run's block as the builder takes it: each transfer's gas and
    /// outcome in candidate order, and the batches' bundles grafted onto the
    /// parent's state with the graft's reverts appended.
    fn grafted_run(run: BuildRun<()>, db: &CacheDB<EmptyDB>, beneficiary: Address) -> (Vec<(usize, u64, bool)>, BundleState, U256) {
        let executed: Vec<(usize, u64, bool)> = run
            .slots
            .iter()
            .filter_map(std::sync::OnceLock::get)
            .map(|built| (built.index, built.gas_used, built.result.is_success()))
            .collect();
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let graft = graft_bundles(&mut state, run.bundles, beneficiary).expect("the graft reads a CacheDB");
        state.merge_transitions(BundleRetention::Reverts);
        let mut bundle = state.take_bundle();
        append_reverts(&mut bundle, graft.reverts);
        (executed, bundle, graft.beneficiary_delta)
    }

    /// `N42_BUILD_PREFETCH`: a build whose batches read the prefetched layer
    /// first -- with some accounts prefetched and the rest not, and one
    /// account the parent does not have -- builds the same block as a build
    /// that reads the parent's state alone: the same transfers, gas and
    /// outcomes in the same order, and the same grafted state and reverts.
    #[test]
    fn a_prefetched_build_equals_the_plain_one() {
        let (block, mut db) = random_fixture(40, 30, 2_000, 8, 8);
        // Some recipients the parent already holds, so the prefetch reads
        // both present and absent accounts.
        for r in (0..2_000u64).step_by(3) {
            db.insert_account_info(addr(1_000_000 + r), AccountInfo { balance: U256::from(5 + r), nonce: r % 4, ..Default::default() });
        }
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let evm_env = evm_config.evm_env(block.header()).expect("env");
        let beneficiary = evm_env.block_env.beneficiary;
        let envs: Vec<TxEnv> = block.transactions_recovered().map(|tx| evm_config.tx_env(tx)).collect();
        let keys: Vec<(Address, Address)> = envs.iter().map(|e| (e.caller, e.kind.to().copied().unwrap_or_default())).collect();
        let convert = |i: usize| ((), envs[i].clone());

        let plain = execute_for_build_in_place(&evm_env, &keys, &convert, &|| Some(db.clone()), None, true).expect("a block of transfers");
        assert!(plain.skipped.is_empty(), "{:?}", plain.skipped);

        // Every other pulled batch of 64 prefetched, on the pool, as the
        // builder does it.
        let warm = WarmAccounts::new();
        build_pool().in_place_scope(|scope| {
            for (n, chunk) in keys.chunks(64).enumerate() {
                if n % 2 == 1 {
                    continue;
                }
                let addresses: Vec<Address> =
                    chunk.iter().map(|(sender, _)| *sender).chain(chunk.iter().map(|(_, to)| *to)).collect();
                let (warm, db) = (&warm, &db);
                scope.spawn(move |_| warm.fill(&addresses, &mut db.clone()));
            }
        });
        let warm = warm.freeze();
        assert!(!warm.is_empty() && warm.len() < 40 + 2_000, "a partial prefetch: {}", warm.len());
        let prefetched = execute_for_build_in_place(&evm_env, &keys, &convert, &|| Some(WarmDb::new(&warm, db.clone())), None, true)
            .expect("a block of transfers");
        assert!(prefetched.skipped.is_empty(), "{:?}", prefetched.skipped);

        let (ours, our_bundle, our_fees) = grafted_run(prefetched, &db, beneficiary);
        let (theirs, their_bundle, their_fees) = grafted_run(plain, &db, beneficiary);
        assert_eq!(ours.len(), envs.len());
        assert_eq!(ours, theirs, "transfers, gas and outcomes");
        assert_eq!(our_fees, their_fees, "the beneficiary's tips");
        assert_eq!(our_bundle.state.len(), their_bundle.state.len(), "accounts");
        for (address, theirs) in &their_bundle.state {
            assert_eq!(our_bundle.state.get(address), Some(theirs), "account {address}");
        }
        assert_eq!(our_bundle.reverts.len(), their_bundle.reverts.len());
        for (ours, theirs) in our_bundle.reverts.iter().zip(their_bundle.reverts.iter()) {
            let ours: std::collections::BTreeMap<_, _> = ours.iter().cloned().collect();
            let theirs: std::collections::BTreeMap<_, _> = theirs.iter().cloned().collect();
            assert_eq!(ours, theirs, "reverts");
        }
    }

    /// The parent's state as the fleet's leader reads it, in miniature: the
    /// parent block's changes (a hash map probe, as reth's in-memory overlay
    /// makes one per block it holds) over the QMDB read view
    /// (`N42_QMDB_READS=on`), which reads an offset index and then the
    /// record out of a mapping of the entry file.
    #[derive(Debug, Clone)]
    struct ViewDb {
        view: std::sync::Arc<n42_qmdb_reth::QmdbReadView>,
        head: u64,
        overlay: std::sync::Arc<alloy_primitives::map::AddressHashMap<Option<AccountInfo>>>,
    }

    impl Database for ViewDb {
        type Error = std::convert::Infallible;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            if let Some(info) = self.overlay.get(&address) {
                return Ok(info.clone());
            }
            // As `StateProviderDatabase` converts it: no code loaded.
            Ok(self.view.account(&address, self.head).flatten().map(AccountInfo::from))
        }

        fn code_by_hash(&mut self, _code_hash: B256) -> Result<revm::state::Bytecode, Self::Error> {
            Ok(revm::state::Bytecode::default())
        }

        fn storage(
            &mut self,
            _address: Address,
            _index: revm::primitives::StorageKey,
        ) -> Result<revm::primitives::StorageValue, Self::Error> {
            Ok(U256::ZERO)
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    /// Plan v6 attempt H on the bench: a full block of the fleet's shape --
    /// 163,008 transfers in runs of 64 (2,547 senders of 6,000), recipients
    /// drawn from two million -- executed on the build's pool with its state
    /// served from a QMDB read view over a two-million-account entry file,
    /// behind the parent block's changes (150,000 accounts), and executed
    /// again with the block's accounts prefetched (`N42_BUILD_PREFETCH`), in
    /// pulled batches of 1,024 as the fleet's puller hands them over.
    ///
    /// ```text
    /// RAYON_NUM_THREADS=16 taskset -c 0-31 \
    ///   cargo test --release -p n42-engine-types --lib bench_build_prefetch -- --ignored --nocapture
    /// ```
    ///
    /// Prints the execution (`par_exec_ms`) without and with the prefetch,
    /// and the prefetch's wall time and summed pool time (`par_prefetch_ms`).
    /// Idle here, the prefetch is extra wall time; on the fleet it runs beside
    /// the pull and the prep (32 ms).
    ///
    /// What it reads (2026-09-24, idle box): exec 32-35 without the prefetch,
    /// 16-17 with it -- half the leg's 65, so the fleet's read path is the
    /// heavier one -- and the prefetch 35-37 ms of wall, 545-585 ms of pool
    /// time for 159,230 accounts: 3.5 us a read with sixteen threads reading,
    /// where one thread alone reads the same accounts at ~0.7 us. The reads
    /// contend with each other; what on (the view's one `versions` lock is
    /// the only state every read shares) is not measured here.
    #[test]
    #[ignore = "timing"]
    fn bench_build_prefetch() {
        use n42_twig_core::qmdb_compat::{encode_gov5_account_value, gov5_account_key, GOV5_EMPTY_CODE_HASH};
        use std::io::Write as _;
        let senders = 6_000u64;
        let recipients = 2_000_000u64;
        let run = 64u64;
        let block_senders = 2_547u64;
        let sender_of = |s: u64| addr(100 + s);
        let recipient_of = |r: u64| addr(1_000_000 + r);

        // The entry file: `[key 32][len u32 LE][value]` per account.
        let dir = std::env::temp_dir().join(format!("n42-bench-build-prefetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("entries.log");
        let mut live = Vec::with_capacity((senders + recipients) as usize);
        {
            let mut out = std::io::BufWriter::new(std::fs::File::create(&path).expect("the entry file"));
            let mut offset = 0u64;
            let mut put = |address: Address, nonce: u64, balance: U256| {
                let key = gov5_account_key(&address.0 .0);
                let value = encode_gov5_account_value(nonce, &balance.to_be_bytes::<32>(), &GOV5_EMPTY_CODE_HASH);
                out.write_all(&key).expect("write");
                out.write_all(&(value.len() as u32).to_le_bytes()).expect("write");
                out.write_all(&value).expect("write");
                live.push((key, offset));
                offset += 36 + value.len() as u64;
            };
            // The beneficiary exists, as on the chain (the fast path leaves
            // an empty coinbase to the interpreter).
            put(addr(1), 0, U256::from(7));
            for s in 0..senders {
                put(sender_of(s), 0, U256::from(10u128.pow(21)));
            }
            for r in 0..recipients {
                put(recipient_of(r), r % 3, U256::from(1 + r));
            }
            out.flush().expect("flush");
        }
        let view = n42_qmdb_reth::QmdbReadView::build(&path, (1, B256::ZERO), live).expect("the read view");
        // The parent block's changes: 150,000 accounts it touched.
        let mut overlay = alloy_primitives::map::AddressHashMap::default();
        for i in 0..150_000u64 {
            let r = (i * 13) % recipients;
            let account = reth_primitives_traits::Account { nonce: r % 3, balance: U256::from(2 + r), bytecode_hash: None };
            overlay.insert(recipient_of(r), Some(AccountInfo::from(account)));
        }
        let db = ViewDb { view, head: 1, overlay: std::sync::Arc::new(overlay) };

        let beneficiary = addr(1);
        let mut envs = Vec::new();
        let mut seed = 0x9e3779b97f4a7c15u64;
        for s in 0..block_senders {
            for k in 0..run {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let mut env = TxEnv::default();
                env.caller = sender_of(s);
                env.kind = TxKind::Call(recipient_of(seed % recipients));
                env.value = U256::from(1_000 + k);
                env.gas_limit = 21_000;
                env.gas_price = 10_000_000_000;
                env.gas_priority_fee = Some(1_000_000_000);
                env.nonce = k;
                env.tx_type = 2;
                env.chain_id = Some(1);
                envs.push(env);
            }
        }
        let header = Header { number: 20_000_000, beneficiary, gas_limit: 5_000_000_000, base_fee_per_gas: Some(1_000_000_000), timestamp: 1_800_000_000, ..Default::default() };
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let evm_env = evm_config.evm_env(&header).expect("env");
        let keys: Vec<(Address, Address)> = envs.iter().map(|e| (e.caller, e.kind.to().copied().unwrap_or_default())).collect();
        let convert = |i: usize| ((), envs[i].clone());
        println!("block: {} transfers, {} pool threads", envs.len(), build_pool().current_num_threads());
        // One thread alone reading the same accounts: what a read costs
        // without the other fifteen reading beside it.
        {
            let addresses: Vec<Address> = keys[..20_480].iter().map(|(_, to)| *to).collect();
            let warm = WarmAccounts::new();
            warm.fill(&addresses, &mut db.clone());
            println!("serial prefetch: {} reads in {} us ({} ns a read)", addresses.len(), warm.busy_us(), warm.busy_us() * 1000 / addresses.len() as u64);
        }
        for round in 0..4 {
            let plain = execute_for_build_in_place(&evm_env, &keys, &convert, &|| Some(db.clone()), None, true).expect("a block of transfers");
            let at = std::time::Instant::now();
            let warm = WarmAccounts::new();
            build_pool().in_place_scope(|scope| {
                for chunk in keys.chunks(1_024) {
                    let addresses: Vec<Address> =
                        chunk.iter().map(|(sender, _)| *sender).chain(chunk.iter().map(|(_, to)| *to)).collect();
                    let (warm, db) = (&warm, &db);
                    scope.spawn(move |_| warm.fill(&addresses, &mut db.clone()));
                }
            });
            let prefetch_wall = at.elapsed();
            let busy_ms = warm.busy_us() / 1000;
            let warm = warm.freeze();
            let prefetched = execute_for_build_in_place(&evm_env, &keys, &convert, &|| Some(WarmDb::new(&warm, db.clone())), None, true)
                .expect("a block of transfers");
            assert_eq!(plain.skipped.len(), prefetched.skipped.len());
            let executed = plain.slots.iter().filter(|slot| slot.get().is_some()).count();
            assert_eq!(executed, envs.len(), "every transfer executed");
            println!(
                "round {round}: exec plain {} ms, prefetched {} ms; prefetch wall {} ms, pool {} ms ({} accounts); batches {}",
                plain.phases.groups_ms,
                prefetched.phases.groups_ms,
                prefetch_wall.as_millis(),
                busy_ms,
                warm.len(),
                plain.phases.batches,
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
