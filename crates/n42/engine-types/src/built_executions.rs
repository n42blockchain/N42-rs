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
const DEFAULT_KEEP: usize = 3;

/// Parses `N42_BUILT_KEEP`: an unsigned number in `3..=16`, else the default
/// (with one warning for a value that is set but invalid).
fn built_keep_from(value: Option<&str>) -> usize {
    let Some(raw) = value else { return DEFAULT_KEEP };
    match raw.trim().parse::<usize>() {
        Ok(n) if (3..=16).contains(&n) => n,
        _ => {
            tracing::warn!(target: "n42.built_executions", value = raw, default = DEFAULT_KEEP, "N42_BUILT_KEEP must be an integer in 3..=16; using the default");
            DEFAULT_KEEP
        }
    }
}

/// How many own built executions the stores keep (`N42_BUILT_KEEP`, `3..=16`,
/// default 3), read once.
///
/// Why it is tunable: under pipeline depth 2 with `N42_CHECK_BEFORE_SLOT=1`
/// and `N42_FAR_AHEAD_BLOCKS=2` the validators' import of an own block arrives
/// 280-400 ms after its seal, 3-4 builds later (loop351 D2S12F2P45T64), so the
/// entry was already evicted and 1115 of 1156 own blocks were re-executed
/// through the direct import (136 ms) instead of the hand-off (48 ms).
/// What an entry costs: one full 200k-transaction bundle with its hashed state
/// and trie updates, freed on the `n42-built-free` thread.
fn keep() -> usize {
    static KEEP: OnceLock<usize> = OnceLock::new();
    *KEEP.get_or_init(|| built_keep_from(std::env::var("N42_BUILT_KEEP").ok().as_deref()))
}

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
    /// Consensus sealed this build ([`pin_sealed`]) and its hand-off has not
    /// taken it yet ([`handed_off`]): never evicted for a newer build. See
    /// [`make_room_into`] for when a pin is let go.
    pinned: bool,
    /// The hand-off has already taken this build ([`handed_off`]): a sealed
    /// header arriving later must not pin it again, nothing would release it.
    handed_off: bool,
}

/// At most this many pinned builds; past it the oldest pin is let go (with a
/// WARN), so a pin nothing ever releases cannot grow the store without bound
/// while the canonical notifications that release pins lag.
fn max_pinned() -> usize {
    4 * keep()
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
    STORE.get_or_init(|| (Mutex::new(VecDeque::with_capacity(keep())), Condvar::new()))
}

/// The store's hard bound: only builds still finishing behind their seal may
/// take it past [`keep`].
fn keep_finishing() -> usize {
    2 * keep()
}

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
    let mut entry = entry;
    while let Some(at) = store.iter().position(|(hash, _)| *hash == built_hash) {
        if let Some((_, old)) = store.remove(at) {
            entry.pinned |= old.pinned;
            entry.handed_off |= old.handed_off;
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
    free_boxed_off_path(Box::new(evicted));
}

/// Whatever left one of the stores, dropped on the `n42-built-free` thread
/// (inline if that thread cannot be had): an evicted sealed block or handed
/// build may be the last holder of a 200k-transaction body, whose free was
/// 5-16 ms of the own-block hand-off's `clone_ms` when it ran there (loop351
/// af, `moved_body=true` blocks).
pub(crate) fn free_boxed_off_path(evicted: Box<dyn Send>) {
    static FREE: OnceLock<Option<Mutex<std::sync::mpsc::SyncSender<Box<dyn Send>>>>> = OnceLock::new();
    let sender = FREE.get_or_init(|| {
        let (send, receive) = std::sync::mpsc::sync_channel::<Box<dyn Send>>(2);
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
        Some(sender) => try_queue_free(&sender.lock().unwrap_or_else(|p| p.into_inner()), evicted),
        None => Some(evicted),
    };
    drop(unsent);
}

// Retired bundles are still large while queued. Keep at most two waiting;
// if the worker falls behind, free outside the stores' locks on the caller.
fn try_queue_free(sender: &std::sync::mpsc::SyncSender<Box<dyn Send>>, value: Box<dyn Send>) -> Option<Box<dyn Send>> {
    match sender.try_send(value) {
        Ok(()) => None,
        Err(std::sync::mpsc::TrySendError::Full(value) | std::sync::mpsc::TrySendError::Disconnected(value)) => Some(value),
    }
}

/// Frees a slot for one more build. A finished build goes first, oldest
/// first; a build still finishing behind its seal is evicted only past
/// [`keep_finishing`]. Its advances are dropped once it has left the store
/// ([`advance`]), so evicting it loses the block for its own import
/// ("the execution layer no longer holds own block"). loop320 FASb: with the
/// fields published at the seal three own builds were finishing at once at
/// the tenure handover, a given-up build ahead on the old parent had been
/// filed finished beside them, and the oldest finishing build was evicted
/// for the newest. Keeping a finishing entry costs nothing its finish does
/// not hold anyway.
///
/// A pinned build (sealed by consensus, not yet handed off: [`pin_sealed`])
/// is never evicted here, and the bound counts unpinned builds only. Without
/// that, a run of small blocks sealed faster than their imports arrive
/// evicted a sealed own build before its hand-off, and every validator key's
/// import of it then failed: the block was never imported and the chain
/// stopped at it (loop351 stage aj, block 2081: 2082-2084 sealed within
/// ~100 ms behind it). A pin is let go once the canonical chain reaches its
/// number without a hand-off ([`release_passed_pins`]), or, past
/// [`max_pinned`], the oldest first; both say so at WARN. A build whose
/// hand-off already happened is never pinned ([`pin_sealed`]): in loop351
/// stage ak the late pin came from empty blocks, whose hand-off lands before
/// the next build request (which carries the sealed header) arrives, and
/// every such pin was only let go by the chain passing it, with a WARN.
#[cfg(test)]
fn make_room(store: &mut VecDeque<(B256, Entry)>) {
    let mut evicted = Vec::new();
    make_room_into(store, &mut evicted);
}

/// [`make_room`], the evicted entries handed to `evicted` rather than dropped.
fn make_room_into(store: &mut VecDeque<(B256, Entry)>, evicted: &mut Vec<Entry>) {
    release_passed_pins(store, crate::canonical_head::number());
    while store.iter().filter(|(_, entry)| entry.pinned).count() >= max_pinned() {
        let Some((hash, entry)) = store.iter_mut().find(|(_, entry)| entry.pinned) else { break };
        entry.pinned = false;
        tracing::warn!(
            target: "n42.built_executions",
            number = entry.block.header().number,
            built_hash = %hash,
            max_pinned = max_pinned(),
            "a sealed own build was never handed off and too many are pinned; its pin is let go"
        );
    }
    let unpinned = |store: &VecDeque<(B256, Entry)>| store.iter().filter(|(_, entry)| !entry.pinned).count();
    while unpinned(store) >= keep() {
        let removed = if let Some(at) = store.iter().position(|(_, entry)| !entry.pinned && entry.stage == Stage::Complete) {
            store.remove(at)
        } else if unpinned(store) >= keep_finishing() {
            store.iter().position(|(_, entry)| !entry.pinned).and_then(|at| store.remove(at))
        } else {
            break;
        };
        if let Some((_, entry)) = removed {
            evicted.push(entry);
        }
    }
}

/// Lets go the pins of builds at or below `canonical`: the chain has a block
/// at that height, and if it were this build its hand-off would have
/// released the pin. Each is said once at WARN; the build then counts
/// against [`keep`] like any other.
fn release_passed_pins(store: &mut VecDeque<(B256, Entry)>, canonical: u64) {
    for (hash, entry) in store.iter_mut() {
        if entry.pinned && entry.block.header().number <= canonical {
            entry.pinned = false;
            tracing::warn!(
                target: "n42.built_executions",
                number = entry.block.header().number,
                canonical,
                built_hash = %hash,
                "the chain passed a sealed own build that was never handed off; its pin is let go"
            );
        }
    }
}

/// [`release_passed_pins`] on the store, for a caller that knows the chain
/// reached `canonical` (and for tests, which cannot move the process-wide
/// canonical head the store reads by itself).
pub fn release_pins_through(canonical: u64) {
    let (store, _) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    release_passed_pins(&mut store, canonical);
}

/// Pins the kept build that consensus sealed under this header's fields
/// (parent, number, roots, gas, transactions root -- what a seal does not
/// change): it stays in the store, whatever comes after it, until its
/// hand-off ([`handed_off`]) or until the chain passes its number. Called
/// when a sealed header naming one of this layer's builds arrives. Returns
/// whether a build was pinned. A build already handed off ([`handed_off`])
/// is skipped: with empty blocks the hand-off of block N lands before the
/// build request for N+1 brings the sealed header (loop351 stage ak), and a
/// pin placed then would never be released.
pub fn pin_sealed(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, transactions_root: Option<B256>) -> bool {
    let (store, _) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    if number <= crate::canonical_head::number() {
        return false;
    }
    match store
        .iter_mut()
        .rev()
        .find(|(_, entry)| !entry.handed_off && matches_block(&entry.block, parent, number, state_root, receipts_root, gas_used, transactions_root))
    {
        Some((_, entry)) => {
            entry.pinned = true;
            true
        }
        None => false,
    }
}

/// The build's hand-off has taken it: its pin (if any) is released and it
/// counts against [`keep`] again. It is remembered as handed off, so a later
/// [`pin_sealed`] for the same build is a no-op.
pub fn handed_off(built_hash: B256) {
    let (store, _) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, entry)) = store.iter_mut().find(|(hash, _)| *hash == built_hash) {
        entry.pinned = false;
        entry.handed_off = true;
    }
}

/// Whether `built_hash` is kept and pinned.
pub fn is_pinned(built_hash: B256) -> bool {
    store_get(built_hash).is_some_and(|entry| entry.pinned)
}

/// Remembers a finished build under the hash the builder gave it.
pub fn remember(built_hash: B256, execution: BuiltExecution) {
    put(built_hash, Entry { stage: Stage::Complete, block: execution.block.clone(), execution: Some(execution), shards: None, pinned: false, handed_off: false });
}

/// A block sealed before its finish: known from here on, waited for by
/// whoever needs its state or its execution.
pub fn remember_pending(built_hash: B256, block: Arc<RecoveredBlock<Block>>) {
    put(built_hash, Entry { stage: Stage::Sealed, block, execution: None, shards: None, pinned: false, handed_off: false });
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

/// Builds whose execution fields are published (the QMDB root filed, the
/// receipts root and gas known) and when: what an answer to the block's import
/// needs, which comes before the merged post-state map `Complete` carries
/// (`docs/DELTA_LOG_DESIGN.md` 1). Bounded; the oldest goes first.
fn answerable_table() -> &'static Mutex<VecDeque<(B256, std::time::Instant)>> {
    static TABLE: OnceLock<Mutex<VecDeque<(B256, std::time::Instant)>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(VecDeque::with_capacity(4 * keep())))
}

/// The build's fields are published: its import can be answered before its
/// merged map lands.
pub fn answerable(built_hash: B256) {
    {
        let mut table = answerable_table().lock().unwrap_or_else(|p| p.into_inner());
        table.retain(|(hash, _)| *hash != built_hash);
        while table.len() >= 4 * keep() {
            table.pop_front();
        }
        table.push_back((built_hash, std::time::Instant::now()));
    }
    // A waiter checks the table under the store's lock: taking it here
    // before the notify means none can miss this wake-up.
    let (store, advanced) = store();
    drop(store.lock().unwrap_or_else(|p| p.into_inner()));
    advanced.notify_all();
}

/// When the build's fields were published ([`answerable`]), if they were.
pub fn answerable_at(built_hash: B256) -> Option<std::time::Instant> {
    let table = answerable_table().lock().unwrap_or_else(|p| p.into_inner());
    table.iter().rev().find(|(hash, _)| *hash == built_hash).map(|(_, at)| *at)
}

/// Parses `N42_STATE_READY_WITHOUT_MERGE`: on only for `1`.
pub fn state_ready_without_merge_from(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// `N42_STATE_READY_WITHOUT_MERGE=1` (default off, read once): an own block's
/// header-only import is answered once the build's fields are published
/// ([`find_answerable`]), without waiting for the merged post-state map;
/// the merge runs behind the answer unchanged, and the executed insert goes
/// to the engine when the map lands (docs/DELTA_LOG_DESIGN.md stage 1).
/// Takes effect only with `N42_ANSWER_AT_INSERT=1`, whose deferred
/// `newPayload` carries the insert's outcome.
pub fn state_ready_without_merge() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let on = state_ready_without_merge_from(std::env::var("N42_STATE_READY_WITHOUT_MERGE").ok().as_deref());
        tracing::info!(target: "n42.built_executions", state_ready_without_merge = on, "N42_STATE_READY_WITHOUT_MERGE");
        on
    })
}

/// The kept build matching these fields once its import can be answered:
/// its fields published ([`answerable`]) or `Complete`, waited for up to
/// [`WAIT`]. Gives its builder hash and its block; the build stays in the
/// store for the insert that follows when its map lands.
pub fn find_answerable(
    parent: B256,
    number: u64,
    state_root: B256,
    receipts_root: B256,
    gas_used: u64,
    transactions_root: Option<B256>,
) -> Option<(B256, Arc<RecoveredBlock<Block>>)> {
    let (store, advanced) = store();
    let deadline = std::time::Instant::now() + WAIT;
    let mut guard = store.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        let found = guard
            .iter()
            .rev()
            .find(|(_, entry)| matches_block(&entry.block, parent, number, state_root, receipts_root, gas_used, transactions_root))
            .map(|(hash, entry)| (*hash, entry.stage, Arc::clone(&entry.block)));
        match found {
            Some((hash, stage, block)) if stage == Stage::Complete || answerable_at(hash).is_some() => {
                return Some((hash, block))
            }
            Some(_) => {}
            None => {
                drop(guard);
                let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
                return handed
                    .iter()
                    .rev()
                    .find(|(_, built)| matches_block(&built.block, parent, number, state_root, receipts_root, gas_used, transactions_root))
                    .map(|(hash, built)| (*hash, Arc::clone(&built.block)));
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
            // `N42_MERGE_ELIDE`: an output handed out with a thin bundle keeps
            // its shard set, the next build's read of it ([`wait_for_state`]).
            if !n42_sharded_output::is_elided(&*execution.execution_output) {
                entry.shards = None;
            }
            entry.execution = Some(execution);
        }
        // Evicted (a finish that ran longer than `keep()` builds), or never
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
/// first: the post-state the next build opens on. An output handed out with a
/// thin bundle (`N42_MERGE_ELIDE`) is given as its shard set after
/// `StateReady` too: the only entries that keep one past it.
pub fn wait_for_state(built_hash: B256) -> Option<ParentState> {
    let (store, advanced) = store();
    let deadline = std::time::Instant::now() + WAIT;
    let mut guard = store.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        match guard.iter().find(|(hash, _)| *hash == built_hash) {
            Some((_, entry)) if entry.stage >= Stage::StateReady => {
                if let Some(shards) = &entry.shards {
                    return Some(ParentState::Sharded(shards.clone()));
                }
                return entry.execution.clone().map(ParentState::Full);
            }
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
    let mut evicted = Vec::new();
    while let Some(at) = handed.iter().position(|(hash, _)| *hash == taken.0) {
        evicted.extend(handed.remove(at));
    }
    while handed.len() >= keep() {
        evicted.extend(handed.pop_front());
    }
    handed.push_back(taken.clone());
    drop(handed);
    if !evicted.is_empty() {
        free_boxed_off_path(Box::new(evicted));
    }
    Some(taken)
}

/// Builds [`take`] handed to the engine, still findable by [`find_kept`].
fn handed() -> &'static Mutex<VecDeque<(B256, BuiltExecution)>> {
    static HANDED: OnceLock<Mutex<VecDeque<(B256, BuiltExecution)>>> = OnceLock::new();
    HANDED.get_or_init(|| Mutex::new(VecDeque::with_capacity(keep())))
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
    find_kept_sealed_with(parent, number, state_root, receipts_root, gas_used, transactions_root, |hash, block, execution| {
        (hash, Arc::clone(block), execution.cloned())
    })
}

/// [`find_kept_sealed`] keeping no reference to the block: the builder hash,
/// a copy of the block's header and of its withdrawals (a few hundred bytes).
/// For a caller that only asks whether a header is one of this layer's
/// builds -- every follower key's request on a shared layer asks it, as the
/// own-block hand-off is about to move the block's body, which a reference
/// held by such a lookup at that moment would make it copy instead.
pub fn find_kept_sealed_header(
    parent: B256,
    number: u64,
    state_root: B256,
    receipts_root: B256,
    gas_used: u64,
    transactions_root: Option<B256>,
) -> Option<(B256, alloy_consensus::Header, Option<Vec<alloy_eips::eip4895::Withdrawal>>)> {
    find_kept_sealed_with(parent, number, state_root, receipts_root, gas_used, transactions_root, |hash, block, _| {
        (hash, block.header().clone(), block.body().withdrawals.as_ref().map(|w| w.to_vec()))
    })
}

/// The kept build matching these fields, `found` applied to it under the
/// stores' lock (it must be cheap).
fn find_kept_sealed_with<R>(
    parent: B256,
    number: u64,
    state_root: B256,
    receipts_root: B256,
    gas_used: u64,
    transactions_root: Option<B256>,
    found: impl FnOnce(B256, &Arc<RecoveredBlock<Block>>, Option<&BuiltExecution>) -> R,
) -> Option<R> {
    {
        let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
        if let Some((hash, built)) = handed.iter().rev().find(|(_, built)| matches_build(built, parent, number, state_root, receipts_root, gas_used, transactions_root)) {
            return Some(found(*hash, &built.block, Some(built)));
        }
    }
    let (store, _) = store();
    let store = store.lock().unwrap_or_else(|p| p.into_inner());
    store
        .iter()
        .rev()
        .find(|(_, entry)| matches_block(&entry.block, parent, number, state_root, receipts_root, gas_used, transactions_root))
        .map(|(hash, entry)| found(*hash, &entry.block, entry.execution.as_ref()))
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
fn sealed_store() -> &'static Mutex<VecDeque<(B256, SealedKept)>> {
    static STORE: OnceLock<Mutex<VecDeque<(B256, SealedKept)>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(VecDeque::with_capacity(keep())))
}

/// A sealed block in the store: its own copy, or the executed block handed
/// to the engine, shared (`N42_HANDOFF_NO_CLONE`).
#[derive(Debug)]
enum SealedKept {
    Owned(SealedBlock<Block>),
    Shared(Arc<RecoveredBlock<Block>>),
}

impl SealedKept {
    fn block(&self) -> &SealedBlock<Block> {
        match self {
            Self::Owned(block) => block,
            Self::Shared(recovered) => recovered.sealed_block(),
        }
    }

    /// The block by value: moved when this is its only holder, else copied.
    fn into_block(self) -> SealedBlock<Block> {
        match self {
            Self::Owned(block) => block,
            Self::Shared(recovered) => {
                Arc::try_unwrap(recovered).map_or_else(|shared| shared.sealed_block().clone(), RecoveredBlock::into_sealed_block)
            }
        }
    }
}

/// Parses `N42_HANDOFF_NO_CLONE`: on only for `1`.
fn handoff_no_clone_from(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// Whether the own-block hand-off shares its executed block with the sealed
/// store instead of copying the body for it (`N42_HANDOFF_NO_CLONE=1`,
/// default off).
///
/// The hand-off copies the build's body once for the engine's insert -- the
/// build is still held by the handed store ([`take`] keeps it for the build
/// on the sealed block), so `Arc::try_unwrap` fails and the body is cloned --
/// and once more for [`remember_sealed`]. The first copy is unavoidable while
/// the handed store holds the build (the insert needs a block under the
/// sealed header, and the body sits by value in the block); the second is
/// not: the store can keep the very `Arc` the insert carries. Readers of the
/// store copy out of it as before ([`find_sealed`]); a take moves the block
/// only once the engine has dropped its copy.
pub fn handoff_no_clone_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| handoff_no_clone_from(std::env::var("N42_HANDOFF_NO_CLONE").ok().as_deref()))
}

/// Keeps the sealed block under its sealed hash.
pub fn remember_sealed(sealed_hash: B256, block: SealedBlock<Block>) {
    let transactions = block.body().transactions.len();
    keep_sealed(sealed_hash, transactions, SealedKept::Owned(block));
}

/// [`remember_sealed`] sharing the executed block handed to the engine
/// (`N42_HANDOFF_NO_CLONE`): no copy of the body.
pub fn remember_sealed_shared(sealed_hash: B256, block: Arc<RecoveredBlock<Block>>) {
    let transactions = block.body().transactions.len();
    keep_sealed(sealed_hash, transactions, SealedKept::Shared(block));
}

/// Parses `N42_HANDOFF_MOVE_BODY`: on only for `1`.
fn handoff_move_body_from(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// Whether the own-block hand-off moves the build's body under the sealed
/// header instead of copying it (`N42_HANDOFF_MOVE_BODY=1`, default off).
///
/// The hand-off needs the block under the header consensus sealed, and the
/// body sits by value in a `RecoveredBlock`, so it can only be moved when the
/// hand-off holds the block's last `Arc`. With the switch off the stores keep
/// theirs (the build store entry and its execution, the handed list, a
/// shared sealed block) and the 200k-transaction body and senders are cloned:
/// `clone_ms` 36-38 ms on every slow hand-off (loop351 stage j). With it on,
/// [`reseal_moving`] takes those `Arc`s out under the stores' locks, moves the
/// body and senders under the sealed header, and puts the one new `Arc` back
/// in every slot that held the build: the build hash then aliases the sealed
/// block, so readers by the build's hash or by its fields find the same block
/// (its header is the sealed one; every field they match on or compare is one
/// a seal does not change). A holder outside the stores (a build on the
/// sealed block reading it on a thread, a payload not yet dropped) makes the
/// move fail; the body is then cloned as before and the hand-off line says
/// `moved_body=false`.
pub fn handoff_move_body_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| handoff_move_body_from(std::env::var("N42_HANDOFF_MOVE_BODY").ok().as_deref()))
}

/// The block under `sealed`, made by moving `block`'s body and senders when
/// the stores' references to it are the only others (`Ok`), every store slot
/// that held `block` then holding the returned `Arc`; `Err(block)` when a
/// holder outside the stores keeps it alive, every slot left as it was.
///
/// A block already under the sealed hash (a second hand-off of the same
/// block, which found the alias) is returned as it is.
pub fn reseal_moving(
    built_hash: B256,
    block: Arc<RecoveredBlock<Block>>,
    sealed: reth_primitives_traits::SealedHeader,
) -> Result<Arc<RecoveredBlock<Block>>, Arc<RecoveredBlock<Block>>> {
    if block.hash() == sealed.hash() {
        return Ok(block);
    }
    // Lock order store -> handed -> sealed store; no other function holds
    // two of these at once.
    let (store, advanced) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    let mut handed = handed().lock().unwrap_or_else(|p| p.into_inner());
    let mut sealed_kept = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    let mut slots: Vec<&mut Arc<RecoveredBlock<Block>>> = Vec::new();
    for (hash, entry) in store.iter_mut() {
        if *hash != built_hash {
            continue;
        }
        if Arc::ptr_eq(&entry.block, &block) {
            slots.push(&mut entry.block);
        }
        if let Some(execution) = entry.execution.as_mut()
            && Arc::ptr_eq(&execution.block, &block)
        {
            slots.push(&mut execution.block);
        }
    }
    for (hash, built) in handed.iter_mut() {
        if *hash == built_hash && Arc::ptr_eq(&built.block, &block) {
            slots.push(&mut built.block);
        }
    }
    for (_, kept) in sealed_kept.iter_mut() {
        if let SealedKept::Shared(shared) = kept
            && Arc::ptr_eq(shared, &block)
        {
            slots.push(shared);
        }
    }
    // A stand-in while the block is out: cheap, and never seen outside the
    // locks held here.
    let stand_in = Arc::new(RecoveredBlock::new_sealed(SealedBlock::seal_slow(Block::default()), Vec::new()));
    for slot in &mut slots {
        drop(std::mem::replace(&mut **slot, Arc::clone(&stand_in)));
    }
    let result = match Arc::try_unwrap(block) {
        Ok(owned) => {
            let (built_block, senders) = owned.split_sealed();
            let body = built_block.split_sealed_header_body().1;
            Ok(Arc::new(RecoveredBlock::new_sealed(SealedBlock::from_sealed_parts(sealed, body), senders)))
        }
        Err(shared) => Err(shared),
    };
    let back = match &result {
        Ok(moved) | Err(moved) => moved,
    };
    for slot in slots {
        *slot = Arc::clone(back);
    }
    drop(sealed_kept);
    drop(handed);
    drop(store);
    advanced.notify_all();
    result
}

/// The block kept for the build `built_hash`, in the build store or on the
/// handed list: after a [`reseal_moving`], the sealed block (the alias from
/// the build hash).
pub fn kept_block(built_hash: B256) -> Option<Arc<RecoveredBlock<Block>>> {
    if let Some(entry) = store_get(built_hash) {
        return Some(entry.block);
    }
    let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
    handed.iter().rev().find(|(hash, _)| *hash == built_hash).map(|(_, built)| Arc::clone(&built.block))
}

/// Sealed hashes the store must not retire yet ([`hold_sealed`]); one entry
/// per hold, so two holds of one hash need two releases.
fn sealed_held() -> &'static Mutex<Vec<B256>> {
    static HELD: OnceLock<Mutex<Vec<B256>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(Vec::new()))
}

/// Keeps the sealed block under `sealed_hash` (once remembered) out of the
/// store's eviction until the returned guard is dropped.
///
/// `N42_STATE_READY_WITHOUT_MERGE` answers an own block before its insert and
/// sends its header-only `newPayload` only once the merge lands, 50-90 ms
/// later, while the next blocks are remembered behind it: with the default
/// bound of three the block was retired before the engine converted its
/// payload (loop351 stage cl, block 891: the conversion fell back to the
/// payload, the deferred pass failed, the failure latched and every later own
/// block was executed again). The hold spans that pass.
pub fn hold_sealed(sealed_hash: B256) -> SealedHold {
    sealed_held().lock().unwrap_or_else(|p| p.into_inner()).push(sealed_hash);
    SealedHold(sealed_hash)
}

/// A hold on a kept sealed block ([`hold_sealed`]), let go on drop.
#[derive(Debug)]
pub struct SealedHold(B256);

impl Drop for SealedHold {
    fn drop(&mut self) {
        let mut held = sealed_held().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(at) = held.iter().position(|hash| *hash == self.0) {
            held.swap_remove(at);
        }
    }
}

fn keep_sealed(sealed_hash: B256, transactions: usize, block: SealedKept) {
    {
        let mut hints = sealed_hints().lock().unwrap_or_else(|p| p.into_inner());
        hints.retain(|(hash, _)| *hash != sealed_hash);
        while hints.len() >= SEALED_HINTS {
            hints.pop_front();
        }
        hints.push_back((sealed_hash, transactions));
    }
    let mut store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    let mut evicted = Vec::new();
    while let Some(at) = store.iter().position(|(hash, _)| *hash == sealed_hash) {
        evicted.extend(store.remove(at));
    }
    while store.len() >= keep() {
        // The oldest block no deferred `newPayload` still needs
        // ([`hold_sealed`]); when every kept block is held the store grows
        // past its bound until a hold is let go.
        let held = sealed_held().lock().unwrap_or_else(|p| p.into_inner());
        let Some(at) = store.iter().position(|(hash, _)| !held.contains(hash)) else { break };
        drop(held);
        evicted.extend(store.remove(at));
    }
    store.push_back((sealed_hash, block));
    drop(store);
    if !evicted.is_empty() {
        free_boxed_off_path(Box::new(evicted));
    }
}

/// How many sealed hashes [`sealed_here_with_transactions`] remembers: the
/// sealed blocks themselves are retired after [`keep`], their hashes and
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
    store.remove(at).map(|(_, block)| block.into_block())
}

/// The sealed block under this hash, left in the store: the engine converts
/// a header-only own-block payload more than once on some paths (a sibling
/// re-proposed after a TC was converted, then executed with the *empty*
/// transaction list the payload carries: loop147-150), and every conversion
/// must find the body. The store's bound (`keep()`) retires it.
pub fn find_sealed(sealed_hash: B256) -> Option<SealedBlock<Block>> {
    let store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    store.iter().find(|(hash, _)| *hash == sealed_hash).map(|(_, block)| block.block().clone())
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
    if store[at].1.block().body().transactions.len() != transactions {
        return Some(store[at].1.block().clone());
    }
    store.remove(at).map(|(_, block)| block.into_block())
}

/// Whether `N42_ENGINE_TAKE_SEALED=1` is set; see [`find_or_take_sealed`].
pub fn take_sealed_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_ENGINE_TAKE_SEALED").is_ok_and(|v| v == "1"))
}

/// Serialises every test that files builds: the stores are process-global and
/// bounded by [`keep`], so concurrent tests would evict each other's builds.
#[cfg(test)]
pub(crate) static STORE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    #[test]
    fn a_held_sealed_block_outlives_the_bound() {
        let _guard = super::STORE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let block = |n: u64| {
            let mut b = super::Block::default();
            b.header.number = n;
            reth_primitives_traits::SealedBlock::seal_slow(b)
        };
        let first = block(9_100);
        let first_hash = first.hash();
        let hold = super::hold_sealed(first_hash);
        super::remember_sealed(first_hash, first);
        for n in 9_101..9_101 + super::keep() as u64 + 2 {
            let b = block(n);
            super::remember_sealed(b.hash(), b);
        }
        assert!(super::find_sealed(first_hash).is_some(), "held: not retired");
        drop(hold);
        for n in 9_200..9_200 + super::keep() as u64 {
            let b = block(n);
            super::remember_sealed(b.hash(), b);
        }
        assert!(super::find_sealed(first_hash).is_none(), "released: retired by the bound");
    }

    #[test]
    fn saturated_or_disconnected_free_worker_returns_ownership_without_waiting() {
        struct CountDrop(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for CountDrop {
            fn drop(&mut self) { self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
        }
        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        assert!(try_queue_free(&send, Box::new(CountDrop(drops.clone()))).is_none());
        let unsent = try_queue_free(&send, Box::new(CountDrop(drops.clone())));
        assert!(unsent.is_some());
        drop(unsent);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(recv.recv().unwrap());
        drop(recv);
        drop(try_queue_free(&send, Box::new(CountDrop(drops.clone()))));
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn built_keep_parses_and_bounds() {
        assert_eq!(built_keep_from(None), 3);
        assert_eq!(built_keep_from(Some("8")), 8);
        assert_eq!(built_keep_from(Some("16")), 16);
        assert_eq!(built_keep_from(Some("2")), 3);
        assert_eq!(built_keep_from(Some("17")), 3);
        assert_eq!(built_keep_from(Some("x")), 3);
    }

    #[test]
    fn handoff_no_clone_is_on_only_for_one() {
        assert!(handoff_no_clone_from(Some("1")));
        for off in [None, Some(""), Some("0"), Some("true")] {
            assert!(!handoff_no_clone_from(off), "{off:?}");
        }
    }

    #[test]
    fn handoff_move_body_is_on_only_for_one() {
        assert!(handoff_move_body_from(Some("1")));
        for off in [None, Some(""), Some("0"), Some("true")] {
            assert!(!handoff_move_body_from(off), "{off:?}");
        }
    }

    fn sealed_of(built: &Header) -> reth_primitives_traits::SealedHeader {
        reth_primitives_traits::SealedHeader::seal_slow(Header { extra_data: b"sealed".as_slice().into(), ..built.clone() })
    }

    /// A handed build whose block is moved under the sealed header: the
    /// hand-off was the last holder outside the stores, so nothing is cloned;
    /// the sealed block is found under the sealed hash and, through the
    /// alias, under the build hash and by its fields.
    #[test]
    fn a_handed_build_is_resealed_by_move_and_found_both_ways() {
        let _guard = lock();
        let h = header(0x61, 610);
        let execution = built(&h);
        let built_hash = execution.block.hash();
        remember(built_hash, execution);
        let (hash, taken) = take(h.parent_hash, 610, h.state_root, h.receipts_root, h.gas_used, None).expect("taken");
        assert_eq!(hash, built_hash);
        let sealed = sealed_of(&h);
        let sealed_hash = sealed.hash();
        let moved = reseal_moving(built_hash, taken.block, sealed).expect("the stores were the only other holders");
        assert_eq!(moved.hash(), sealed_hash);
        assert_eq!(moved.body().transactions.len(), 0);
        remember_sealed_shared(sealed_hash, Arc::clone(&moved));
        assert_eq!(find_sealed(sealed_hash).map(|block| block.hash()), Some(sealed_hash));
        let aliased = kept_block(built_hash).expect("the build hash aliases the sealed block");
        assert!(Arc::ptr_eq(&aliased, &moved));
        let (kept_hash, by_fields, execution) =
            find_kept_sealed(h.parent_hash, 610, h.state_root, h.receipts_root, h.gas_used, None).expect("by fields");
        assert_eq!(kept_hash, built_hash);
        assert!(Arc::ptr_eq(&by_fields, &moved));
        assert!(execution.is_some_and(|execution| Arc::ptr_eq(&execution.block, &moved)));
        assert!(wait_for(built_hash, Stage::Complete).is_some_and(|execution| execution.block.hash() == sealed_hash));
    }

    /// A build kept in the store (a header-only import that leaves it for the
    /// build on seal) is resealed in the store's entry, its block and its
    /// execution both.
    #[test]
    fn a_stored_build_is_resealed_in_both_of_its_slots() {
        let _guard = lock();
        let h = header(0x62, 620);
        let execution = built(&h);
        let built_hash = execution.block.hash();
        remember(built_hash, execution);
        let (_, found) = find(h.parent_hash, 620, h.state_root, h.receipts_root, h.gas_used, None).expect("found");
        let sealed = sealed_of(&h);
        let moved = reseal_moving(built_hash, found.block, sealed.clone()).expect("moved");
        let entry = store_get(built_hash).expect("still stored");
        assert!(Arc::ptr_eq(&entry.block, &moved));
        assert!(entry.execution.is_some_and(|execution| Arc::ptr_eq(&execution.block, &moved)));
    }

    /// A holder outside the stores keeps the block: nothing moves, every slot
    /// keeps the build as it was, and the caller gets the block back to copy.
    #[test]
    fn a_block_held_elsewhere_is_not_moved() {
        let _guard = lock();
        let h = header(0x63, 630);
        let execution = built(&h);
        let built_hash = execution.block.hash();
        remember(built_hash, execution);
        let (_, taken) = take(h.parent_hash, 630, h.state_root, h.receipts_root, h.gas_used, None).expect("taken");
        let elsewhere = Arc::clone(&taken.block);
        let back = reseal_moving(built_hash, taken.block, sealed_of(&h)).expect_err("held elsewhere");
        assert!(Arc::ptr_eq(&back, &elsewhere));
        assert_eq!(back.hash(), built_hash);
        assert!(kept_block(built_hash).is_some_and(|kept| Arc::ptr_eq(&kept, &elsewhere)));
    }

    /// A second hand-off of the same block finds the alias, already under the
    /// sealed hash: returned as it is, without a panic or a copy.
    #[test]
    fn a_second_handoff_of_a_resealed_block_returns_it() {
        let _guard = lock();
        let h = header(0x64, 640);
        let execution = built(&h);
        let built_hash = execution.block.hash();
        remember(built_hash, execution);
        let (_, taken) = take(h.parent_hash, 640, h.state_root, h.receipts_root, h.gas_used, None).expect("taken");
        let sealed = sealed_of(&h);
        let moved = reseal_moving(built_hash, taken.block, sealed.clone()).expect("moved");
        let (_, again) =
            find_kept(h.parent_hash, 640, h.state_root, h.receipts_root, h.gas_used, None).expect("found by the alias");
        let second = reseal_moving(built_hash, again.block, sealed.clone()).expect("already sealed");
        assert!(Arc::ptr_eq(&second, &moved));
        assert_eq!(second.hash(), sealed.hash());
    }

    /// A shared sealed block is found by copy while the engine holds it and
    /// moved out by a take once it does not.
    #[test]
    fn a_shared_sealed_block_is_found_and_taken() {
        let _guard = lock();
        let header = Header { number: 777, ..Default::default() };
        let sealed = SealedBlock::<Block>::seal_slow(alloy_consensus::Block::new(header, BlockBody::default()));
        let hash = sealed.hash();
        let shared = Arc::new(RecoveredBlock::new_sealed(sealed, Vec::new()));
        remember_sealed_shared(hash, Arc::clone(&shared));
        assert_eq!(find_sealed(hash).map(|block| block.hash()), Some(hash));
        drop(shared);
        assert_eq!(take_sealed(hash).map(|block| block.hash()), Some(hash));
        assert!(find_sealed(hash).is_none());
    }

    /// A sealed block evicted from the store is freed off the caller's
    /// path: the caller's own reference stays the only one it sees, and the
    /// evicted block is gone once the free thread has run.
    #[test]
    fn an_evicted_sealed_block_is_freed_off_the_path() {
        let _guard = lock();
        let first = Arc::new(RecoveredBlock::new_sealed(
            SealedBlock::<Block>::seal_slow(alloy_consensus::Block::new(Header { number: 880, ..Default::default() }, BlockBody::default())),
            Vec::new(),
        ));
        let gone = Arc::downgrade(&first);
        remember_sealed_shared(first.hash(), first);
        for number in 881..881 + keep() as u64 {
            let next = SealedBlock::<Block>::seal_slow(alloy_consensus::Block::new(Header { number, ..Default::default() }, BlockBody::default()));
            let hash = next.hash();
            remember_sealed_shared(hash, Arc::new(RecoveredBlock::new_sealed(next, Vec::new())));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while gone.upgrade().is_some() {
            assert!(Instant::now() < deadline, "the evicted block was never freed");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

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

    /// T11 of docs/DEFERRED_DEPTH_2_DESIGN.md: at depth 2 two blocks on
    /// *different* parents of one grandparent carry the same four fields (the
    /// grandparent's result); the store's identity includes the parent, so
    /// each is found under its own and never under the other's.
    #[test]
    fn at_depth_two_cousins_with_the_same_fields_are_kept_apart() {
        let _guard = lock();
        let a = header(0x13, 503);
        let b = Header { parent_hash: B256::repeat_byte(0x9a), ..a.clone() };
        assert_eq!((a.state_root, a.receipts_root, a.gas_used), (b.state_root, b.receipts_root, b.gas_used));
        let (ea, eb) = (built(&a), built(&b));
        let (ha, hb) = (ea.block.hash(), eb.block.hash());
        assert_ne!(ha, hb);
        remember(ha, ea);
        remember(hb, eb);
        assert_eq!(find_by(&a).map(|(h, _)| h), Some(ha));
        assert_eq!(find_by(&b).map(|(h, _)| h), Some(hb));
        let by_parent = |parent| find(parent, 503, a.state_root, a.receipts_root, a.gas_used, Some(a.transactions_root)).map(|(h, _)| h);
        assert_eq!(by_parent(a.parent_hash), Some(ha));
        assert_eq!(by_parent(b.parent_hash), Some(hb));
    }

    /// The eviction moved off the store's lock leaves the store the inline
    /// eviction left -- the same hashes and stages in the same order -- over
    /// a long run of puts mixing finished and finishing builds and repeats,
    /// and hands out exactly the entries the inline one dropped.
    #[test]
    fn an_evicted_entry_is_dropped_off_the_lock_and_the_store_is_the_same() {
        use alloy_primitives::U256;
        let block = built(&header(0x31, 1)).block;
        let entry = |stage: Stage| Entry { stage, block: Arc::clone(&block), execution: None, shards: None, pinned: false, handed_off: false };
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
        let hashes: Vec<B256> = (0..=keep() as u8)
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
    fn an_answer_is_found_at_the_fields_before_the_merge_completes() {
        let _guard = lock();
        let h = header(0x3A, 525);
        let execution = built(&h);
        let hash = execution.block.hash();
        remember_pending(hash, execution.block.clone());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (p, sr, rr, gas) = (h.parent_hash, h.state_root, h.receipts_root, h.gas_used);
        let waiter = std::thread::spawn(move || {
            let _ = ready_tx.send(());
            let found = find_answerable(p, 525, sr, rr, gas, None);
            (found.map(|(hash, _)| hash), stage_of(hash))
        });
        ready_rx.recv().expect("the waiter started");
        std::thread::sleep(Duration::from_millis(30));
        assert!(answerable_at(hash).is_none());
        // The fields published: the answer goes, the merge has not landed.
        answerable(hash);
        let (found, stage_then) = waiter.join().unwrap();
        assert_eq!(found, Some(hash), "found at the fields, not at the deadline");
        assert_eq!(stage_then, Some(Stage::Sealed), "answered before Complete");
        assert!(answerable_at(hash).is_some());
        // Still in the store for the insert that follows the map.
        assert_eq!(stage_of(hash), Some(Stage::Sealed));
        complete(hash, execution.clone());
        let (taken, insert) = take(p, 525, sr, rr, gas, None).expect("the insert takes the completed build");
        assert_eq!(taken, hash);
        assert!(Arc::ptr_eq(&insert.execution_output, &execution.execution_output), "the same map the merge filed");
        assert!(state_ready_without_merge_from(Some("1")));
        assert!(!state_ready_without_merge_from(None) && !state_ready_without_merge_from(Some("0")));
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

    /// loop351 stage aj: a full build sealed by consensus, then three small
    /// builds sealed behind it before its import arrives. Unpinned, the third
    /// evicted it (keep 3) and its hand-off found nothing; pinned, its
    /// hand-off still finds it, and once handed off it counts against the
    /// bound again.
    #[test]
    fn a_sealed_build_is_kept_until_its_hand_off_however_many_follow() {
        let _guard = lock();
        let first = header(0xD0, 2_000_081);
        let first_hash = built(&first).block.hash();
        remember_pending(first_hash, built(&first).block);
        complete(first_hash, built(&first));
        assert!(pin_sealed(first.parent_hash, first.number, first.state_root, first.receipts_root, first.gas_used, Some(first.transactions_root)));
        let small: Vec<Header> = (1..=3u8).map(|i| header(0xD0 + i * 4, 2_000_081 + u64::from(i))).collect();
        for h in &small {
            let execution = built(h);
            let hash = execution.block.hash();
            remember_pending(hash, execution.block.clone());
            complete(hash, execution);
        }
        for h in &small {
            let execution = built(h);
            remember(execution.block.hash(), execution);
        }
        assert!(is_pinned(first_hash));
        let (found, _) = find_by(&first).expect("the hand-off still finds the sealed build");
        assert_eq!(found, first_hash);
        handed_off(first_hash);
        assert!(!is_pinned(first_hash));
        let next = header(0xF0, 2_000_085);
        remember(built(&next).block.hash(), built(&next));
        assert_eq!(stage_of(first_hash), None, "handed off, it is the oldest finished build and goes");
    }

    /// A pinned build the chain passes without a hand-off (consensus sealed a
    /// sibling's height, a view changed) is let go and evicted like any other.
    #[test]
    fn a_pin_is_let_go_when_the_chain_passes_it() {
        let _guard = lock();
        let stuck = header(0xE0, 3_000_010);
        let stuck_hash = built(&stuck).block.hash();
        remember(stuck_hash, built(&stuck));
        assert!(pin_sealed(stuck.parent_hash, stuck.number, stuck.state_root, stuck.receipts_root, stuck.gas_used, Some(stuck.transactions_root)));
        release_pins_through(3_000_009);
        assert!(is_pinned(stuck_hash), "the chain is below it");
        release_pins_through(3_000_010);
        assert!(!is_pinned(stuck_hash), "the chain reached it");
        for i in 1..=keep() as u8 {
            let h = header(0xE0 + i * 4, 3_000_010 + u64::from(i));
            remember(built(&h).block.hash(), built(&h));
        }
        assert_eq!(stage_of(stuck_hash), None, "released, it is evicted");
    }

    /// Two-ahead's orphan (`N42_BUILD_AHEAD_GATE=seal`): block N and the
    /// build on it, N+1, both sealed and pinned, and N is never proposed; the
    /// height is built again on the same parent. The replacement and its child
    /// are found by their own fields and never as the orphans (the identity
    /// includes the parent and the roots), and once the chain passes N+1 both
    /// orphans' pins go and they are evicted like any other build.
    #[test]
    fn an_orphaned_two_ahead_pair_is_released_and_the_replacement_is_found() {
        let _guard = lock();
        let orphan = header(0x50, 5_000_010);
        let orphan_hash = built(&orphan).block.hash();
        remember(orphan_hash, built(&orphan));
        assert!(pin_sealed(orphan.parent_hash, orphan.number, orphan.state_root, orphan.receipts_root, orphan.gas_used, Some(orphan.transactions_root)));
        let child = Header { parent_hash: orphan_hash, ..header(0x54, 5_000_011) };
        let child_hash = built(&child).block.hash();
        remember(child_hash, built(&child));
        assert!(pin_sealed(child.parent_hash, child.number, child.state_root, child.receipts_root, child.gas_used, Some(child.transactions_root)));
        // The replacement: the same parent and height, other transactions.
        let replacement = Header { parent_hash: orphan.parent_hash, ..header(0x58, 5_000_010) };
        let replacement_hash = built(&replacement).block.hash();
        remember(replacement_hash, built(&replacement));
        assert_eq!(find_by(&replacement).map(|(h, _)| h), Some(replacement_hash));
        assert_eq!(find_by(&orphan).map(|(h, _)| h), Some(orphan_hash), "kept apart, not confused");
        // A build on the replacement with the orphan child's fields finds nothing.
        let on_replacement = Header { parent_hash: replacement_hash, ..child.clone() };
        assert!(find_by(&on_replacement).is_none());
        handed_off(replacement_hash);
        // The chain commits the replacement and its own child: both pins go.
        release_pins_through(5_000_011);
        assert!(!is_pinned(orphan_hash) && !is_pinned(child_hash));
        for i in 1..=keep() as u8 {
            let h = header(0x60 + i * 4, 5_000_011 + u64::from(i));
            remember(built(&h).block.hash(), built(&h));
        }
        assert_eq!(stage_of(orphan_hash), None, "released, the orphan is evicted");
        assert_eq!(stage_of(child_hash), None, "released, the orphan's child is evicted");
    }

    /// A seal header arriving after the hand-off (empty blocks) pins nothing.
    #[test]
    fn a_pin_after_the_hand_off_is_a_no_op() {
        let _guard = lock();
        let h = header(0xC0, 4_500_010);
        let hash = built(&h).block.hash();
        remember(hash, built(&h));
        handed_off(hash);
        assert!(!pin_sealed(h.parent_hash, h.number, h.state_root, h.receipts_root, h.gas_used, Some(h.transactions_root)));
        assert!(!is_pinned(hash));
    }

    /// Pins are bounded: past `max_pinned` the oldest pin is let go.
    #[test]
    fn pins_are_bounded() {
        let _guard = lock();
        let heads: Vec<Header> = (0..=max_pinned() as u8).map(|i| header(0x10 + i * 4, 4_000_000 + u64::from(i))).collect();
        for h in &heads {
            remember(built(h).block.hash(), built(h));
            assert!(pin_sealed(h.parent_hash, h.number, h.state_root, h.receipts_root, h.gas_used, Some(h.transactions_root)));
        }
        let extra = header(0xFC, 4_000_100);
        remember(built(&extra).block.hash(), built(&extra));
        let pinned = heads.iter().filter(|h| is_pinned(built(h).block.hash())).count();
        assert!(pinned < max_pinned(), "{pinned} pins kept");
        assert!(!is_pinned(built(&heads[0]).block.hash()), "the oldest pin went first");
    }

    #[test]
    fn finishing_builds_are_bounded_too() {
        let _guard = lock();
        let heads: Vec<Header> = (0..=keep_finishing() as u8).map(|i| header(0xC0 + i * 4, 1100 + u64::from(i))).collect();
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
        let heads: Vec<Header> = (0..=keep() as u8).map(|i| header(0x50 + i * 4, 540 + u64::from(i))).collect();
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
        let blocks: Vec<_> = (0..=keep() as u8).map(|i| sealed_block(0x80 + i, 1)).collect();
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
