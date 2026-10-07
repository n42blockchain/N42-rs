// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The execution results of the blocks this node built, kept so its own
//! block can be imported without being executed a second time.
//!
//! A leader executes its block once to build it and, on this chain, once
//! more to import it: consensus seals the header (view, QC, signature in
//! `extra_data`), the hash changes, and the execution layer sees a block it
//! has never met. reth's engine can insert an already-executed block
//! (`InsertExecutedBlock`, the path sequencers use), but the payload types
//! carry no execution result; this store carries it, keyed by the hash the
//! builder gave the block, for the raw payload channel to find when the
//! sealed block comes back. At the bench tier the second execution is ~500
//! ms on the leader's critical path, ahead of the build that could otherwise
//! start the moment the block exists.

use alloy_primitives::B256;
use n42_tx_types::{Block, Receipt};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_trie::{updates::TrieUpdates, HashedPostState};
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, OnceLock},
};

/// What the engine needs to insert a block as executed.
#[derive(Debug, Clone)]
pub struct BuiltExecution {
    /// The block as built, under the builder's hash; its body and senders are
    /// the sealed block's too.
    pub block: Arc<RecoveredBlock<Block>>,
    /// The bundle state and receipts of executing it.
    pub execution_output: Arc<BlockExecutionOutput<Receipt>>,
    /// The hashed post-state, as the builder computed it.
    pub hashed_state: Arc<HashedPostState>,
    /// Trie updates, empty on a chain whose root is not the trie's.
    pub trie_updates: Arc<TrieUpdates>,
}

/// How many recent builds are kept. A leader's block is sealed and comes
/// back within a view, so one is in flight and one may be the build ahead
/// -- and, sealing before the finish, one more still finishing behind it;
/// each is ~100 MB at 163,000 transactions (block, bundle state, receipts),
/// and on a box whose page cache is the contended resource every retained
/// hundred megabytes is a hundred megabytes of state pages evicted.
const KEEP: usize = 3;

/// How far a build that was sealed before it finished has come
/// (docs/PHASE_D_DEFERRED_EXECUTION.md section 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// The block is sealed and published; its state is still being folded.
    Sealed,
    /// The post-state is final: the next block can be built on it. The
    /// execution kept here has the bundle, but placeholder receipts and
    /// hashed state.
    StateReady,
    /// Everything: the executed block the engine takes at the handoff.
    Complete,
}

/// A build, at whatever stage it has reached.
#[derive(Debug, Clone)]
struct Entry {
    stage: Stage,
    /// The block, from the seal on.
    block: Arc<RecoveredBlock<Block>>,
    /// The execution, from `StateReady` on (provisional until `Complete`).
    execution: Option<BuiltExecution>,
    /// `N42_OUTPUT_SHARDS`: the post-state as the shard set and the few
    /// accounts the executor changed after it, between [`shards_ready`] and
    /// `StateReady` (dropped then: the full bundle serves every later reader).
    shards: Option<ShardedParent>,
}

/// A build's post-state before its one bundle exists: the batches' output
/// shards and, laid over them, what the block's executor changed afterwards
/// (`crate::output_shards`). Only the next build's overlay reads it.
#[derive(Debug, Clone)]
pub struct ShardedParent {
    /// The executor's own changes (fee credit, withdrawals, system calls),
    /// merged and taken; its receipts are empty.
    pub residual: Arc<BlockExecutionOutput<Receipt>>,
    /// The batches' accounts, by address range.
    pub shards: Arc<crate::output_shards::FrozenShards>,
}

/// What [`wait_for_state`] found: the post-state as one bundle, or, earlier,
/// as the shard set.
#[derive(Debug, Clone)]
pub enum ParentState {
    /// `StateReady` or later.
    Full(BuiltExecution),
    /// [`shards_ready`], before `StateReady`.
    Sharded(ShardedParent),
}

/// How long a caller waits for a stage a build has not reached: a finish
/// behind the seal is ~250 ms on a full block, so this is a stall guard, not
/// a budget.
const WAIT: std::time::Duration = std::time::Duration::from_secs(3);

fn store() -> &'static (Mutex<VecDeque<(B256, Entry)>>, Condvar) {
    static STORE: OnceLock<(Mutex<VecDeque<(B256, Entry)>>, Condvar)> = OnceLock::new();
    STORE.get_or_init(|| (Mutex::new(VecDeque::with_capacity(KEEP)), Condvar::new()))
}

/// The store's hard bound: only builds still finishing behind their seal may
/// take it past [`KEEP`].
const KEEP_FINISHING: usize = 2 * KEEP;

fn put(built_hash: B256, entry: Entry) {
    let (store, advanced) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    let evicted = put_into(&mut store, built_hash, entry);
    drop(store);
    advanced.notify_all();
    free_off_path(evicted);
}

/// [`put`]'s change to the store, returning what left it instead of dropping
/// it under the store's lock: an evicted `Complete` entry holds a full
/// block's bundle, receipts and hashed state, whose free was `seal_remember_ms`
/// 3 ms (p90 5) on the seal's path (`docs/SHARED_EXECUTION_SCOPE.md` 16.3).
/// The store after it is the store `retain` + [`make_room`] + `push_back`
/// left: the same entries in the same order.
fn put_into(store: &mut VecDeque<(B256, Entry)>, built_hash: B256, entry: Entry) -> Vec<Entry> {
    let mut evicted = Vec::new();
    while let Some(at) = store.iter().position(|(hash, _)| *hash == built_hash) {
        if let Some((_, old)) = store.remove(at) {
            evicted.push(old);
        }
    }
    make_room_into(store, &mut evicted);
    store.push_back((built_hash, entry));
    evicted
}

/// Drops evicted entries on a thread of their own (`n42-built-free`), off
/// the caller's path and the store's lock; inline if that thread cannot be
/// had. Nothing reads an entry once it left the store.
fn free_off_path(evicted: Vec<Entry>) {
    if evicted.is_empty() {
        return;
    }
    static FREE: OnceLock<Option<Mutex<std::sync::mpsc::Sender<Vec<Entry>>>>> = OnceLock::new();
    let sender = FREE.get_or_init(|| {
        let (send, receive) = std::sync::mpsc::channel::<Vec<Entry>>();
        std::thread::Builder::new()
            .name("n42-built-free".into())
            .spawn(move || {
                while let Ok(entries) = receive.recv() {
                    drop(entries);
                }
            })
            .ok()
            .map(|_| Mutex::new(send))
    });
    let unsent = match sender {
        Some(sender) => sender.lock().unwrap_or_else(|p| p.into_inner()).send(evicted).err().map(|err| err.0),
        None => Some(evicted),
    };
    drop(unsent);
}

/// Frees a slot for one more build. A finished build goes first, oldest
/// first; a build still finishing behind its seal is evicted only past
/// [`KEEP_FINISHING`]. Its advances are dropped once it has left the store
/// ([`advance`]), so evicting it loses the block for its own import
/// ("the execution layer no longer holds own block"). loop320 FASb: with the
/// fields published at the seal three own builds were finishing at once at
/// the tenure handover, a given-up build ahead on the old parent had been
/// filed finished beside them, and the oldest finishing build was evicted
/// for the newest. Keeping a finishing entry costs nothing its finish does
/// not hold anyway.
#[cfg(test)]
fn make_room(store: &mut VecDeque<(B256, Entry)>) {
    while store.len() >= KEEP {
        if let Some(at) = store.iter().position(|(_, entry)| entry.stage == Stage::Complete) {
            store.remove(at);
        } else if store.len() >= KEEP_FINISHING {
            store.pop_front();
        } else {
            break;
        }
    }
}

/// [`make_room`], the evicted entries handed to `evicted` rather than dropped.
fn make_room_into(store: &mut VecDeque<(B256, Entry)>, evicted: &mut Vec<Entry>) {
    while store.len() >= KEEP {
        let removed = if let Some(at) = store.iter().position(|(_, entry)| entry.stage == Stage::Complete) {
            store.remove(at)
        } else if store.len() >= KEEP_FINISHING {
            store.pop_front()
        } else {
            break;
        };
        if let Some((_, entry)) = removed {
            evicted.push(entry);
        }
    }
}

/// Remembers a finished build under the hash the builder gave it.
pub fn remember(built_hash: B256, execution: BuiltExecution) {
    put(built_hash, Entry { stage: Stage::Complete, block: execution.block.clone(), execution: Some(execution), shards: None });
}

/// A block sealed before its finish: known from here on, waited for by
/// whoever needs its state or its execution.
pub fn remember_pending(built_hash: B256, block: Arc<RecoveredBlock<Block>>) {
    put(built_hash, Entry { stage: Stage::Sealed, block, execution: None, shards: None });
}

/// The pending build's post-state is final (`execution` carries the bundle;
/// receipts and hashed state are placeholders until [`complete`]).
pub fn state_ready(built_hash: B256, execution: BuiltExecution) {
    advance(built_hash, Stage::StateReady, execution);
}

/// The pending build's post-state is final as a shard set
/// (`N42_OUTPUT_SHARDS`): the next build may read it through
/// [`wait_for_state`] before the one bundle `StateReady` carries is built.
pub fn shards_ready(built_hash: B256, parent: ShardedParent) {
    let (store, advanced) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, entry)) = store.iter_mut().find(|(hash, _)| *hash == built_hash)
        && entry.stage < Stage::StateReady
    {
        entry.shards = Some(parent);
    }
    drop(store);
    advanced.notify_all();
}

/// The pending build is finished.
pub fn complete(built_hash: B256, execution: BuiltExecution) {
    advance(built_hash, Stage::Complete, execution);
}

fn advance(built_hash: B256, stage: Stage, execution: BuiltExecution) {
    let (store, advanced) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    match store.iter_mut().find(|(hash, _)| *hash == built_hash) {
        Some((_, entry)) => {
            entry.stage = stage;
            entry.execution = Some(execution);
            entry.shards = None;
        }
        // Evicted (a finish that ran longer than KEEP builds), or never
        // pending: not re-filed -- that would evict a live build the engine
        // or the next build still needs.
        None => {
            tracing::debug!(target: "n42.built_executions", %built_hash, ?stage, "a build advanced after it left the store; dropped");
        }
    }
    drop(store);
    // A copy on the handed list (taken before it was complete) is refreshed.
    if stage == Stage::Complete {
        let mut handed = handed().lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, kept)) = handed.iter_mut().find(|(hash, _)| *hash == built_hash) {
            *kept = execution_of(&store_get(built_hash)).unwrap_or_else(|| kept.clone());
        }
    }
    advanced.notify_all();
}

fn store_get(built_hash: B256) -> Option<Entry> {
    let (store, _) = store();
    let store = store.lock().unwrap_or_else(|p| p.into_inner());
    store.iter().find(|(hash, _)| *hash == built_hash).map(|(_, entry)| entry.clone())
}

fn execution_of(entry: &Option<Entry>) -> Option<BuiltExecution> {
    entry.as_ref().and_then(|entry| entry.execution.clone())
}

/// A pending build whose finish behind the seal failed: gone from the
/// store, so its waiters return at once rather than at their deadline.
pub fn fail(built_hash: B256) {
    let (store, advanced) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    store.retain(|(hash, _)| *hash != built_hash);
    drop(store);
    advanced.notify_all();
}

/// The stage `built_hash` has reached, if it is known here.
pub fn stage_of(built_hash: B256) -> Option<Stage> {
    store_get(built_hash).map(|entry| entry.stage)
}

/// Waits until the build under `built_hash` reaches `stage`, up to [`WAIT`],
/// and gives its execution then. A build not filed here (or already handed to
/// the engine) is looked for on the handed list at once.
pub fn wait_for(built_hash: B256, stage: Stage) -> Option<BuiltExecution> {
    let (store, advanced) = store();
    let deadline = std::time::Instant::now() + WAIT;
    let mut guard = store.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        match guard.iter().find(|(hash, _)| *hash == built_hash) {
            Some((_, entry)) if entry.stage >= stage => return entry.execution.clone(),
            Some(_) => {}
            None => {
                drop(guard);
                let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
                return handed.iter().rev().find(|(hash, _)| *hash == built_hash).map(|(_, built)| built.clone());
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = advanced.wait_timeout(guard, deadline - now).unwrap_or_else(|p| p.into_inner());
        guard = g;
    }
}

/// [`wait_for`] `StateReady`, or the shard set if [`shards_ready`] comes
/// first: the post-state the next build opens on.
pub fn wait_for_state(built_hash: B256) -> Option<ParentState> {
    let (store, advanced) = store();
    let deadline = std::time::Instant::now() + WAIT;
    let mut guard = store.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        match guard.iter().find(|(hash, _)| *hash == built_hash) {
            Some((_, entry)) if entry.stage >= Stage::StateReady => return entry.execution.clone().map(ParentState::Full),
            Some((_, entry)) if entry.shards.is_some() => return entry.shards.clone().map(ParentState::Sharded),
            Some(_) => {}
            None => {
                drop(guard);
                let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
                return handed
                    .iter()
                    .rev()
                    .find(|(hash, _)| *hash == built_hash)
                    .map(|(_, built)| ParentState::Full(built.clone()));
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = advanced.wait_timeout(guard, deadline - now).unwrap_or_else(|p| p.into_inner());
        guard = g;
    }
}

/// The build whose block is `number` on `parent` with these roots and gas,
/// if one was kept -- the fields a seal cannot change, which together pin
/// the transactions and the state they produced. The caller still proves the
/// sealed header hashes to the hash it was given before trusting this. A
/// build still finishing behind its seal is waited for, up to [`WAIT`].
pub fn find(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>) -> Option<(B256, BuiltExecution)> {
    find_at(parent, number, state_root, receipts_root, gas_used, transactions_root, Stage::Complete)
}

/// [`find`] at a given stage.
pub fn find_at(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>, stage: Stage) -> Option<(B256, BuiltExecution)> {
    let (store, advanced) = store();
    let deadline = std::time::Instant::now() + WAIT;
    let mut guard = store.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        let found = guard
            .iter()
            .rev()
            .find(|(_, entry)| matches_block(&entry.block, parent, number, state_root, receipts_root, gas_used, transactions_root))
            .map(|(hash, entry)| (*hash, entry.stage, entry.execution.clone()));
        match found {
            Some((hash, at, Some(built))) if at >= stage => return Some((hash, built)),
            Some(_) => {}
            None => return None,
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = advanced.wait_timeout(guard, deadline - now).unwrap_or_else(|p| p.into_inner());
        guard = g;
    }
}

/// [`find`], taking the build out of the store: the caller becomes the
/// block's only holder and can move it instead of cloning its body.
pub fn take(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>) -> Option<(B256, BuiltExecution)> {
    let taken = {
        // Complete first (waiting for a finish behind the seal), then out.
        let (hash, built) = find(parent, number, state_root, receipts_root, gas_used, transactions_root)?;
        let (store, _) = store();
        let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(at) = store.iter().rposition(|(h, _)| *h == hash) {
            store.remove(at);
        }
        (hash, built)
    };
    // Kept a little longer for the build on the sealed block: the own-block
    // import that takes the build and that build leave the validator in the
    // same breath on separate connections, and the import wins the race more
    // often than not (loop110 S1: 49 of 52 on-seal builds refused, silently).
    // The execution is four `Arc`s, so the copy costs nothing; the budget is
    // the store's.
    let mut handed = handed().lock().unwrap_or_else(|p| p.into_inner());
    handed.retain(|(hash, _)| *hash != taken.0);
    while handed.len() >= KEEP {
        handed.pop_front();
    }
    handed.push_back(taken.clone());
    Some(taken)
}

/// Builds [`take`] handed to the engine, still findable by [`find_kept`].
fn handed() -> &'static Mutex<VecDeque<(B256, BuiltExecution)>> {
    static HANDED: OnceLock<Mutex<VecDeque<(B256, BuiltExecution)>>> = OnceLock::new();
    HANDED.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

/// The kept build matching these fields, at whatever stage it has reached,
/// without waiting: its builder hash, its block, and its execution when it
/// has one (`StateReady` on). A build is filed before its seal is handed out
/// (`remember_pending`), so a request naming the sealed header always finds
/// it here -- what a build started at the parent's seal needs
/// (`N42_BUILD_ON_OUTPUT`), which waits for the state only when it opens it.
pub fn find_kept_sealed(
    parent: B256,
    number: u64,
    state_root: B256,
    receipts_root: B256,
    gas_used: u64,
    transactions_root: Option<B256>,
) -> Option<(B256, Arc<RecoveredBlock<Block>>, Option<BuiltExecution>)> {
    {
        let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
        if let Some((hash, built)) = handed.iter().rev().find(|(_, built)| matches_build(built, parent, number, state_root, receipts_root, gas_used, transactions_root)) {
            return Some((*hash, built.block.clone(), Some(built.clone())));
        }
    }
    let (store, _) = store();
    let store = store.lock().unwrap_or_else(|p| p.into_inner());
    store
        .iter()
        .rev()
        .find(|(_, entry)| matches_block(&entry.block, parent, number, state_root, receipts_root, gas_used, transactions_root))
        .map(|(hash, entry)| (*hash, entry.block.clone(), entry.execution.clone()))
}

/// [`find`], also among the builds already taken by the engine's import --
/// what a build on the sealed block wants, whichever of the two requests the
/// execution layer served first.
pub fn find_kept(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>) -> Option<(B256, BuiltExecution)> {
    find_kept_at(parent, number, state_root, receipts_root, gas_used, transactions_root, Stage::Complete)
}

/// [`find_kept`] at a given stage: the build on the sealed block needs the
/// parent's post-state (`StateReady`), not its receipts.
pub fn find_kept_at(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>, stage: Stage) -> Option<(B256, BuiltExecution)> {
    // The handed list first: a build the engine already took is complete,
    // and looking there costs nothing where a wait on the store would.
    {
        let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(found) = handed.iter().rev().find(|(_, built)| matches_build(built, parent, number, state_root, receipts_root, gas_used, transactions_root)) {
            return Some(found.clone());
        }
    }
    find_at(parent, number, state_root, receipts_root, gas_used, transactions_root, stage)
}

fn matches_build(built: &BuiltExecution, parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>) -> bool {
    matches_block(&built.block, parent, number, state_root, receipts_root, gas_used, transactions_root)
}

/// Under deferred execution the state root, receipts root and gas are the
/// parent's, the same for every sibling built on that parent: the
/// transactions root, when the caller has it, is what tells them apart.
fn matches_block(block: &RecoveredBlock<Block>, parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>) -> bool {
    let header = block.header();
    header.parent_hash == parent
        && header.number == number
        && header.state_root == state_root
        && header.receipts_root == receipts_root
        && header.gas_used == gas_used
        && transactions_root.is_none_or(|root| header.transactions_root == root)
}

/// The sealed blocks this node has handed to the engine as executed, kept
/// for the engine's own `newPayload` of the same block, which follows the
/// hand-off as the check that the insert landed (and the fallback when it
/// did not). Its conversion of the payload would decode every transaction
/// again -- 48 ms at 163,000 transactions, on the leader's path between one
/// proposal and the next build -- to produce the block that is already here.
fn sealed_store() -> &'static Mutex<VecDeque<(B256, SealedBlock<Block>)>> {
    static STORE: OnceLock<Mutex<VecDeque<(B256, SealedBlock<Block>)>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

/// Keeps the sealed block under its sealed hash.
pub fn remember_sealed(sealed_hash: B256, block: SealedBlock<Block>) {
    {
        let mut hints = sealed_hints().lock().unwrap_or_else(|p| p.into_inner());
        hints.retain(|(hash, _)| *hash != sealed_hash);
        while hints.len() >= SEALED_HINTS {
            hints.pop_front();
        }
        hints.push_back((sealed_hash, block.body().transactions.len()));
    }
    let mut store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    store.retain(|(hash, _)| *hash != sealed_hash);
    while store.len() >= KEEP {
        store.pop_front();
    }
    store.push_back((sealed_hash, block));
}

/// How many sealed hashes [`sealed_here_with_transactions`] remembers: the
/// sealed blocks themselves are retired after [`KEEP`], their hashes and
/// transaction counts stay much longer, so a header-only payload for a
/// block whose body is gone is recognised as such.
const SEALED_HINTS: usize = 256;

fn sealed_hints() -> &'static Mutex<VecDeque<(B256, usize)>> {
    static HINTS: OnceLock<Mutex<VecDeque<(B256, usize)>>> = OnceLock::new();
    HINTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(SEALED_HINTS)))
}

/// Whether this node sealed `hash` itself with a non-empty body: a payload
/// for it that carries no transactions is the header-only own-block payload
/// (`request::OWN_BLOCK`) whose sealed block the store no longer holds, not
/// an empty block.
pub fn sealed_here_with_transactions(hash: B256) -> bool {
    let hints = sealed_hints().lock().unwrap_or_else(|p| p.into_inner());
    hints.iter().any(|(sealed, transactions)| *sealed == hash && *transactions > 0)
}

/// The sealed block under this hash, if one was kept; taken out, so a
/// payload converted twice decodes the second time.
pub fn take_sealed(sealed_hash: B256) -> Option<SealedBlock<Block>> {
    let mut store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    let at = store.iter().position(|(hash, _)| *hash == sealed_hash)?;
    store.remove(at).map(|(_, block)| block)
}

/// The sealed block under this hash, left in the store: the engine converts
/// a header-only own-block payload more than once on some paths (a sibling
/// re-proposed after a TC was converted, then executed with the *empty*
/// transaction list the payload carries: loop147-150), and every conversion
/// must find the body. The store's bound (`KEEP`) retires it.
pub fn find_sealed(sealed_hash: B256) -> Option<SealedBlock<Block>> {
    let store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    store.iter().find(|(hash, _)| *hash == sealed_hash).map(|(_, block)| block.clone())
}

/// [`find_sealed`] for a caller whose payload carries `transactions` in full:
/// with `N42_ENGINE_TAKE_SEALED=1`, a remembered block of that many
/// transactions is moved out of the store instead of copied (14 ms and 3 more
/// to free the copy at 163,000 transactions, `bench_vote_road_copies`), since
/// a repeat of the same payload can decode its own list. A payload with no
/// list (the header-only own block) or a different count gets the copy, as
/// before; so does every caller with the flag off.
pub fn find_or_take_sealed(sealed_hash: B256, transactions: usize) -> Option<SealedBlock<Block>> {
    if !take_sealed_enabled() || transactions == 0 {
        return find_sealed(sealed_hash);
    }
    let mut store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    let at = store.iter().position(|(hash, _)| *hash == sealed_hash)?;
    if store[at].1.body().transactions.len() != transactions {
        return Some(store[at].1.clone());
    }
    store.remove(at).map(|(_, block)| block)
}

/// Whether `N42_ENGINE_TAKE_SEALED=1` is set; see [`find_or_take_sealed`].
pub fn take_sealed_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_ENGINE_TAKE_SEALED").is_ok_and(|v| v == "1"))
}

/// Serialises every test that files builds: the stores are process-global and
/// bounded by [`KEEP`], so concurrent tests would evict each other's builds.
#[cfg(test)]
pub(crate) static STORE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use n42_tx_types::{BlockBody, N42TxEnvelope};
    use reth_execution_types::BlockExecutionOutput;
    use std::time::{Duration, Instant};

    /// Serialises the store's tests and starts each on an empty store: a
    /// build a test left sealed and never finished would otherwise hold a
    /// slot for the next test (`make_room` keeps finishing builds).
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        let guard = STORE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        store().0.lock().unwrap_or_else(|p| p.into_inner()).clear();
        guard
    }

    fn header(tag: u8, number: u64) -> Header {
        Header {
            number,
            parent_hash: B256::repeat_byte(tag),
            state_root: B256::repeat_byte(tag.wrapping_add(1)),
            receipts_root: B256::repeat_byte(tag.wrapping_add(2)),
            gas_used: 1_000 + u64::from(tag),
            transactions_root: B256::repeat_byte(tag.wrapping_add(3)),
            ..Default::default()
        }
    }

    fn built(header: &Header) -> BuiltExecution {
        let block = Block {
            header: header.clone(),
            body: BlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: Some(Vec::new().into()) },
        };
        BuiltExecution {
            block: Arc::new(RecoveredBlock::new_sealed(SealedBlock::seal_slow(block), Vec::new())),
            execution_output: Arc::new(BlockExecutionOutput { result: Default::default(), state: Default::default() }),
            hashed_state: Arc::new(HashedPostState::default()),
            trie_updates: Arc::new(TrieUpdates::default()),
        }
    }

    fn find_by(h: &Header) -> Option<(B256, BuiltExecution)> {
        find(h.parent_hash, h.number, h.state_root, h.receipts_root, h.gas_used, None)
    }

    #[test]
    fn a_finished_build_is_found_only_by_all_the_fields_a_seal_cannot_change() {
        let _guard = lock();
        let h = header(0x11, 501);
        let execution = built(&h);
        let hash = execution.block.hash();
        remember(hash, execution);
        assert_eq!(stage_of(hash), Some(Stage::Complete));
        assert_eq!(find_by(&h).map(|(found, _)| found), Some(hash));

        let off = |f: &dyn Fn(&mut Header)| {
            let mut other = h.clone();
            f(&mut other);
            find_by(&other)
        };
        assert!(off(&|o| o.parent_hash = B256::repeat_byte(0xEE)).is_none(), "parent");
        assert!(off(&|o| o.number += 1).is_none(), "number");
        assert!(off(&|o| o.state_root = B256::repeat_byte(0xEE)).is_none(), "state root");
        assert!(off(&|o| o.receipts_root = B256::repeat_byte(0xEE)).is_none(), "receipts root");
        assert!(off(&|o| o.gas_used += 1).is_none(), "gas");
    }

    #[test]
    fn the_transactions_root_tells_siblings_with_the_same_parent_results_apart() {
        let _guard = lock();
        let a = header(0x12, 502);
        let b = Header { transactions_root: B256::repeat_byte(0x99), ..a.clone() };
        let (ea, eb) = (built(&a), built(&b));
        let (ha, hb) = (ea.block.hash(), eb.block.hash());
        assert_ne!(ha, hb);
        remember(ha, ea);
        remember(hb, eb);
        let by_root = |root| find(a.parent_hash, 502, a.state_root, a.receipts_root, a.gas_used, root).map(|(h, _)| h);
        assert_eq!(by_root(Some(a.transactions_root)), Some(ha));
        assert_eq!(by_root(Some(b.transactions_root)), Some(hb));
        assert_eq!(by_root(Some(B256::repeat_byte(0x55))), None);
        // Without a root the newest of the siblings answers.
        assert_eq!(by_root(None), Some(hb));
    }

    /// The eviction moved off the store's lock leaves the store the inline
    /// eviction left -- the same hashes and stages in the same order -- over
    /// a long run of puts mixing finished and finishing builds and repeats,
    /// and hands out exactly the entries the inline one dropped.
    #[test]
    fn an_evicted_entry_is_dropped_off_the_lock_and_the_store_is_the_same() {
        use alloy_primitives::U256;
        let block = built(&header(0x31, 1)).block;
        let entry = |stage: Stage| Entry { stage, block: Arc::clone(&block), execution: None, shards: None };
        let mut inline: VecDeque<(B256, Entry)> = VecDeque::new();
        let mut moved: VecDeque<(B256, Entry)> = VecDeque::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut evicted_total = 0usize;
        for n in 0..400u64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            // Some hashes come back (a re-put), most are new.
            let hash = B256::from(U256::from(if seed.is_multiple_of(5) { seed % 7 } else { 1_000 + n }));
            let stage = match seed % 4 {
                0 => Stage::Sealed,
                1 => Stage::StateReady,
                _ => Stage::Complete,
            };
            let before: usize = inline.len();
            let replaced = inline.iter().filter(|(h, _)| *h == hash).count();
            inline.retain(|(h, _)| *h != hash);
            make_room(&mut inline);
            let dropped = before - inline.len();
            inline.push_back((hash, entry(stage)));
            let evicted = put_into(&mut moved, hash, entry(stage));
            assert_eq!(evicted.len(), dropped, "put {n}: as many entries leave ({replaced} replaced)");
            evicted_total += evicted.len();
            free_off_path(evicted);
            let keys = |store: &VecDeque<(B256, Entry)>| store.iter().map(|(h, e)| (*h, e.stage)).collect::<Vec<_>>();
            assert_eq!(keys(&inline), keys(&moved), "put {n}");
        }
        assert!(evicted_total > 0);
    }

    #[test]
    fn the_store_keeps_only_the_last_few_builds() {
        let _guard = lock();
        let hashes: Vec<B256> = (0..=KEEP as u8)
            .map(|i| {
                let execution = built(&header(0x20 + i, 510 + u64::from(i)));
                let hash = execution.block.hash();
                remember(hash, execution);
                hash
            })
            .collect();
        assert_eq!(stage_of(hashes[0]), None, "the oldest is evicted");
        for hash in &hashes[1..] {
            assert_eq!(stage_of(*hash), Some(Stage::Complete));
        }
        // Filing the same hash again replaces it instead of taking a second slot.
        remember(hashes[3], built(&header(0x23, 513)));
        assert_eq!(stage_of(hashes[1]), Some(Stage::Complete));
    }

    #[test]
    fn a_pending_build_advances_through_its_stages() {
        let _guard = lock();
        let h = header(0x30, 520);
        let execution = built(&h);
        let hash = execution.block.hash();
        remember_pending(hash, execution.block.clone());
        assert_eq!(stage_of(hash), Some(Stage::Sealed));
        // Sealed already: no execution to give, and no waiting for one.
        assert!(wait_for(hash, Stage::Sealed).is_none());
        // The kept block is known without waiting, with no execution yet.
        let (kept_hash, block, exec) = find_kept_sealed(h.parent_hash, 520, h.state_root, h.receipts_root, h.gas_used, None)
            .expect("filed before the seal is handed out");
        assert_eq!(kept_hash, hash);
        assert_eq!(block.hash(), hash);
        assert!(exec.is_none());

        state_ready(hash, execution.clone());
        assert_eq!(stage_of(hash), Some(Stage::StateReady));
        assert!(wait_for(hash, Stage::StateReady).is_some());
        assert!(matches!(wait_for_state(hash), Some(ParentState::Full(_))));
        assert!(find_at(h.parent_hash, 520, h.state_root, h.receipts_root, h.gas_used, None, Stage::StateReady).is_some());

        complete(hash, execution);
        assert_eq!(stage_of(hash), Some(Stage::Complete));
        assert!(find_by(&h).is_some());
        assert!(Stage::Complete > Stage::StateReady && Stage::StateReady > Stage::Sealed, "stages are ordered");
    }

    #[test]
    fn a_waiter_is_woken_by_the_stage_it_waits_for() {
        let _guard = lock();
        let h = header(0x31, 521);
        let execution = built(&h);
        let hash = execution.block.hash();
        remember_pending(hash, execution.block.clone());
        // Ordered by the test, not by the clock: the old form measured the
        // waiter's own elapsed time against the main thread's 100 ms sleep,
        // and a waiter thread scheduled 10+ ms late on a loaded machine read
        // under 90 ms. What it asserts is the same: the waiter returned with
        // the block (a deadline returns `None`), and only after the stage was
        // reached (`completed` is set before `complete` runs, and nothing
        // else can move the build to `Complete`).
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let seen = std::sync::Arc::clone(&completed);
        let waiter = std::thread::spawn(move || {
            let _ = ready_tx.send(());
            let found = wait_for(hash, Stage::Complete).is_some();
            (found, seen.load(std::sync::atomic::Ordering::SeqCst))
        });
        ready_rx.recv().expect("the waiter started");
        // Not needed for the assertion; it gives the waiter time to block,
        // so the test exercises the wake-up rather than the first look.
        std::thread::sleep(Duration::from_millis(50));
        completed.store(true, std::sync::atomic::Ordering::SeqCst);
        complete(hash, execution);
        let (found, after_complete) = waiter.join().unwrap();
        assert!(found, "woke on the stage, not the deadline");
        assert!(after_complete, "returned only once the stage was reached");
    }

    #[test]
    fn a_failed_finish_releases_its_waiters_at_once() {
        let _guard = lock();
        let h = header(0x32, 522);
        let execution = built(&h);
        let hash = execution.block.hash();
        remember_pending(hash, execution.block.clone());
        let waiter = std::thread::spawn(move || {
            let at = Instant::now();
            (wait_for(hash, Stage::Complete).is_none(), at.elapsed())
        });
        std::thread::sleep(Duration::from_millis(100));
        fail(hash);
        let (none, waited) = waiter.join().unwrap();
        assert!(none);
        assert!(waited < WAIT, "released by the failure, not the deadline: {waited:?}");
        assert_eq!(stage_of(hash), None);
        assert!(wait_for_state(hash).is_none());
    }

    /// loop320 FASb, node 1 at the tenure handover: own blocks 1024 and 1025
    /// sealed, a given-up build ahead on the old parent filed finished, 1024
    /// completed and taken by its own import, then 1026 and 1027 sealed while
    /// 1025 was still finishing. The FIFO bound evicted 1025, its completion
    /// was dropped, and its own import found nothing.
    #[test]
    fn a_build_still_finishing_is_not_evicted_for_a_newer_one() {
        let _guard = lock();
        let own: Vec<Header> = (0..4u8).map(|i| header(0x90 + i * 4, 1024 + u64::from(i))).collect();
        let hash = |h: &Header| built(h).block.hash();
        remember_pending(hash(&own[0]), built(&own[0]).block);
        remember_pending(hash(&own[1]), built(&own[1]).block);
        let stale = header(0xB0, 1021);
        remember(hash(&stale), built(&stale));
        complete(hash(&own[0]), built(&own[0]));
        take(own[0].parent_hash, own[0].number, own[0].state_root, own[0].receipts_root, own[0].gas_used, None)
            .expect("1024 taken by its own import");
        remember_pending(hash(&own[2]), built(&own[2]).block);
        remember_pending(hash(&own[3]), built(&own[3]).block);

        assert_eq!(stage_of(hash(&own[1])), Some(Stage::Sealed), "1025 is still finishing and stays");
        assert_eq!(stage_of(hash(&stale)), None, "the finished stale build made the room");
        complete(hash(&own[1]), built(&own[1]));
        assert_eq!(find_by(&own[1]).map(|(found, _)| found), Some(hash(&own[1])), "its own import finds it");
        for h in &own[2..] {
            assert_eq!(stage_of(hash(h)), Some(Stage::Sealed));
            fail(hash(h));
        }
        fail(hash(&own[1]));
    }

    #[test]
    fn finishing_builds_are_bounded_too() {
        let _guard = lock();
        let heads: Vec<Header> = (0..=KEEP_FINISHING as u8).map(|i| header(0xC0 + i * 4, 1100 + u64::from(i))).collect();
        let hashes: Vec<B256> = heads
            .iter()
            .map(|h| {
                let block = built(h).block;
                let hash = block.hash();
                remember_pending(hash, block);
                hash
            })
            .collect();
        assert_eq!(stage_of(hashes[0]), None, "past the hard bound the oldest goes");
        for hash in &hashes[1..] {
            assert_eq!(stage_of(*hash), Some(Stage::Sealed));
            fail(*hash);
        }
    }

    #[test]
    fn an_advance_for_a_build_not_in_the_store_is_dropped() {
        let _guard = lock();
        let h = header(0x33, 523);
        let execution = built(&h);
        let hash = execution.block.hash();
        state_ready(hash, execution.clone());
        complete(hash, execution);
        assert_eq!(stage_of(hash), None, "an evicted build is not re-filed over a live one");
    }

    #[test]
    fn a_waiter_for_a_build_never_filed_returns_at_once() {
        let _guard = lock();
        let at = Instant::now();
        assert!(wait_for(B256::repeat_byte(0xFA), Stage::Complete).is_none());
        assert!(wait_for_state(B256::repeat_byte(0xFA)).is_none());
        assert!(at.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn shards_are_served_before_the_bundle_and_dropped_when_it_arrives() {
        let _guard = lock();
        let h = header(0x34, 524);
        let execution = built(&h);
        let hash = execution.block.hash();
        let parent = || ShardedParent {
            residual: execution.execution_output.clone(),
            shards: Arc::new(crate::output_shards::OutputShards::new(alloy_primitives::Address::ZERO, 4, 2).freeze()),
        };
        // Shards for a build that is not filed are ignored.
        shards_ready(B256::repeat_byte(0xFB), parent());

        remember_pending(hash, execution.block.clone());
        shards_ready(hash, parent());
        match wait_for_state(hash) {
            Some(ParentState::Sharded(sharded)) => assert_eq!(sharded.shards.shard_count(), 2),
            other => panic!("expected the shard set, got {other:?}"),
        }
        state_ready(hash, execution.clone());
        assert!(matches!(wait_for_state(hash), Some(ParentState::Full(_))), "the bundle supersedes the shards");
        // Shards filed after the state is ready do not take its place.
        shards_ready(hash, parent());
        assert!(matches!(wait_for_state(hash), Some(ParentState::Full(_))));
    }

    #[test]
    fn a_taken_build_leaves_the_store_but_stays_findable_as_kept() {
        let _guard = lock();
        let h = header(0x40, 530);
        let execution = built(&h);
        let hash = execution.block.hash();
        remember(hash, execution);
        let (taken, _) = take(h.parent_hash, 530, h.state_root, h.receipts_root, h.gas_used, None).expect("taken");
        assert_eq!(taken, hash);
        assert_eq!(stage_of(hash), None);
        assert!(find_by(&h).is_none(), "gone from the store");
        assert!(take(h.parent_hash, 530, h.state_root, h.receipts_root, h.gas_used, None).is_none(), "taken once");
        let (kept, _) = find_kept(h.parent_hash, 530, h.state_root, h.receipts_root, h.gas_used, None).expect("kept");
        assert_eq!(kept, hash);
        assert!(find_kept_at(h.parent_hash, 530, h.state_root, h.receipts_root, h.gas_used, None, Stage::StateReady).is_some());
        let (sealed_hash, block, exec) =
            find_kept_sealed(h.parent_hash, 530, h.state_root, h.receipts_root, h.gas_used, None).expect("kept sealed");
        assert_eq!(sealed_hash, hash);
        assert_eq!(block.hash(), hash);
        assert!(exec.is_some());
        // A caller that gave the transactions root still has to match it.
        assert!(find_kept(h.parent_hash, 530, h.state_root, h.receipts_root, h.gas_used, Some(B256::repeat_byte(0x01))).is_none());
        assert!(wait_for(hash, Stage::Complete).is_some(), "the handed list answers a waiter");
        assert!(matches!(wait_for_state(hash), Some(ParentState::Full(_))));
    }

    #[test]
    fn the_handed_list_is_bounded_too() {
        let _guard = lock();
        let heads: Vec<Header> = (0..=KEEP as u8).map(|i| header(0x50 + i * 4, 540 + u64::from(i))).collect();
        for h in &heads {
            let execution = built(h);
            remember(execution.block.hash(), execution);
            take(h.parent_hash, h.number, h.state_root, h.receipts_root, h.gas_used, None).expect("taken");
        }
        let kept = |h: &Header| find_kept(h.parent_hash, h.number, h.state_root, h.receipts_root, h.gas_used, None);
        // The oldest handed build fell off, and nothing is filed in the store, so the lookup answers None at once.
        assert!(kept(&heads[0]).is_none());
        for h in &heads[1..] {
            assert!(kept(h).is_some());
        }
    }

    #[test]
    fn find_gives_up_after_the_deadline_on_a_build_that_never_completes() {
        let _guard = lock();
        let h = header(0x60, 550);
        let execution = built(&h);
        remember_pending(execution.block.hash(), execution.block.clone());
        let at = Instant::now();
        assert!(find_by(&h).is_none());
        assert!(at.elapsed() >= WAIT - Duration::from_millis(50), "waited for the finish: {:?}", at.elapsed());
    }

    fn sealed_block(tag: u8, transactions: usize) -> SealedBlock<Block> {
        let txs: Vec<N42TxEnvelope> = (0..transactions)
            .map(|nonce| {
                let tx = alloy_consensus::TxLegacy { nonce: nonce as u64, ..Default::default() };
                N42TxEnvelope::Eth(reth_ethereum_primitives::TransactionSigned::new_unhashed(
                    reth_ethereum_primitives::Transaction::Legacy(tx),
                    alloy_primitives::Signature::test_signature(),
                ))
            })
            .collect();
        let block = Block {
            header: Header { number: u64::from(tag), extra_data: vec![tag].into(), ..Default::default() },
            body: BlockBody { transactions: txs, ommers: Vec::new(), withdrawals: None },
        };
        SealedBlock::seal_slow(block)
    }

    #[test]
    fn a_sealed_block_is_kept_for_the_engines_own_new_payload() {
        let _guard = lock();
        let block = sealed_block(0x71, 2);
        let hash = block.hash();
        assert!(find_sealed(hash).is_none());
        assert!(!sealed_here_with_transactions(hash));
        remember_sealed(hash, block);
        assert!(sealed_here_with_transactions(hash));
        // find leaves it, take removes it: a payload converted twice finds it the first time only.
        assert_eq!(find_sealed(hash).map(|b| b.body().transactions.len()), Some(2));
        assert_eq!(find_sealed(hash).map(|b| b.hash()), Some(hash));
        assert_eq!(take_sealed(hash).map(|b| b.hash()), Some(hash));
        assert!(take_sealed(hash).is_none());
        assert!(find_sealed(hash).is_none());
        // The hint outlives the block, so a header-only payload is still recognised.
        assert!(sealed_here_with_transactions(hash));
    }

    #[test]
    fn an_empty_sealed_block_is_not_a_header_only_hint() {
        let _guard = lock();
        let block = sealed_block(0x72, 0);
        let hash = block.hash();
        remember_sealed(hash, block);
        assert!(!sealed_here_with_transactions(hash));
    }

    #[test]
    fn find_or_take_sealed_copies_when_the_flag_is_off() {
        let _guard = lock();
        // The flag is read from the environment once; these tests never set it.
        assert!(!take_sealed_enabled());
        let block = sealed_block(0x73, 3);
        let hash = block.hash();
        remember_sealed(hash, block);
        assert!(find_or_take_sealed(hash, 3).is_some());
        assert!(find_or_take_sealed(hash, 3).is_some(), "copied, not moved");
        assert!(find_or_take_sealed(hash, 0).is_some());
        assert!(find_or_take_sealed(B256::repeat_byte(0xFC), 3).is_none());
    }

    #[test]
    fn the_sealed_store_is_bounded_and_refiling_replaces() {
        let _guard = lock();
        let blocks: Vec<_> = (0..=KEEP as u8).map(|i| sealed_block(0x80 + i, 1)).collect();
        let hashes: Vec<B256> = blocks.iter().map(|b| b.hash()).collect();
        for block in blocks.iter().cloned() {
            remember_sealed(block.hash(), block);
        }
        assert!(find_sealed(hashes[0]).is_none(), "the oldest was retired");
        assert!(sealed_here_with_transactions(hashes[0]), "its hint was not");
        for hash in &hashes[1..] {
            assert!(find_sealed(*hash).is_some());
        }
        remember_sealed(hashes[1], blocks[1].clone());
        assert!(find_sealed(hashes[2]).is_some(), "re-filing took no extra slot");
    }
}
