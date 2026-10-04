// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One import per block per execution layer, however many validator keys
//! bring the block to it (`N42_IMPORT_ONCE=1`, off by default).
//!
//! Several validator keys may share one execution layer: each key's validator
//! hands every block to it on the raw payload channel (`payload_serve`), and
//! that channel sits in front of reth's own per-hash dedupe. Without this
//! registry k keys on one execution layer mean k executions, k QMDB root jobs
//! and k hashed-state builds of every block, and the leader's own build is
//! reused by the first request only.
//!
//! The registry is keyed by block hash. The first request for a hash becomes
//! its [`Owner`] and does the work exactly as before; it says when the block
//! is checked ([`Owner::checked`]) and what the final status is
//! ([`Owner::done`]). Every later request for the hash, from any connection,
//! becomes a [`Waiter`]: it does no work, and is answered CHECKED as soon as
//! the owner's check is done and then with the owner's final status. An owner
//! that ends without a final status -- its connection died, its road refused
//! the block, the engine failed -- resets the cell when it is dropped, and
//! one waiter takes the work over with its own request.
//!
//! Bound: the registry keeps the last [`DEFAULT_CAP`] hashes in arrival
//! order. A new hash evicts the oldest entry that is finished or vacant; an
//! entry still being worked on is evicted only past twice the cap. At a block
//! every 0.3-1 s that is tens of seconds of blocks -- far past persistence --
//! and a block that is never committed (a sibling at its height won) leaves
//! the same way. An evicted cell lives on for whoever still holds it; only a
//! request arriving after the eviction misses it and does the work again,
//! which is today's behaviour.

use alloy_primitives::B256;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// How many hashes the registry keeps by default.
pub const DEFAULT_CAP: usize = 64;

/// `N42_IMPORT_ONCE=1`, read once.
pub fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_IMPORT_ONCE").is_ok_and(|v| v == "1"))
}

/// The process's registry when `N42_IMPORT_ONCE=1`; `None` otherwise, and then
/// the raw payload channel serves every request exactly as before.
pub fn global() -> Option<Arc<Registry>> {
    static REGISTRY: std::sync::OnceLock<Arc<Registry>> = std::sync::OnceLock::new();
    enabled().then(|| Arc::clone(REGISTRY.get_or_init(|| Arc::new(Registry::new(DEFAULT_CAP)))))
}

/// The combination this registry refuses at start-up: a held execution
/// (`N42_VOTE_BEFORE_SLOT`, `request::HOLD_EXECUTION`) is released by the one
/// validator that sent it, and with several keys on one execution layer the
/// keys' slots and drops disagree. `HELD_EXECUTIONS` keeps one release per
/// hash, so the shared work would wait on one key's byte and every other
/// key's release would be lost.
pub fn check_startup() -> Result<(), String> {
    refuse_held(enabled(), std::env::var("N42_VOTE_BEFORE_SLOT").is_ok_and(|v| v == "1"))
}

/// [`check_startup`] on given switches.
fn refuse_held(once: bool, held: bool) -> Result<(), String> {
    if once && held {
        return Err("N42_IMPORT_ONCE=1 cannot be combined with N42_VOTE_BEFORE_SLOT=1: a held execution is \
                    released by one validator, and the registry shares that execution with every key on this \
                    execution layer; turn one of them off"
            .to_owned());
    }
    Ok(())
}

/// A cell's state, published to every requester of the hash.
#[derive(Debug, Clone, Default)]
struct State {
    /// The requester doing the work, by token; `None` when nobody is.
    owner: Option<u64>,
    /// The owner's check is done: a CHECKED frame may go out.
    checked: bool,
    /// The final payload status, encoded (`raw_engine::encode_payload_status`).
    done: Option<Arc<Vec<u8>>>,
    /// Whether `done` answers requests that arrive later as well. A status
    /// that may change (SYNCING, ACCEPTED) answers the requesters waiting now
    /// and nobody after them: the next request does the work again.
    retain: bool,
}

impl State {
    fn finished(&self) -> bool {
        self.done.is_some()
    }

    /// Nobody is working on it and no later request may be answered from it.
    fn claimable(&self) -> bool {
        (self.owner.is_none() && !self.finished()) || (self.finished() && !self.retain)
    }
}

/// One block hash's entry.
#[derive(Debug)]
pub struct Cell {
    hash: B256,
    state: watch::Sender<State>,
    /// Requests for this hash, the first included.
    requests: AtomicU32,
    /// Requests answered from the registry without doing any work.
    served: AtomicU32,
}

impl Cell {
    fn new(hash: B256, owner: u64) -> Self {
        let (state, _) = watch::channel(State { owner: Some(owner), ..Default::default() });
        Self { hash, state, requests: AtomicU32::new(1), served: AtomicU32::new(0) }
    }

    /// The block hash this cell is for.
    pub const fn hash(&self) -> B256 {
        self.hash
    }

    /// Takes the cell if it is claimable; the old final status, if any, is
    /// cleared so this owner's own is the one waiters get.
    fn try_claim(&self, token: u64) -> bool {
        self.state.send_if_modified(|state| {
            if state.claimable() {
                *state = State { owner: Some(token), ..Default::default() };
                true
            } else {
                false
            }
        })
    }
}

/// What a fleet leg reads to prove one import per block per execution layer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Requests for this block so far (this cell), the owner's included.
    pub requests: u32,
    /// Of those, answered from the registry with no work.
    pub served: u32,
    /// Since start: imports started (owners, first or taking over).
    pub imports: u64,
    /// Since start: distinct blocks registered.
    pub blocks: u64,
    /// Since start: imports started by a waiter after its owner ended without
    /// a final status.
    pub takeovers: u64,
    /// Since start: requests answered from the registry.
    pub served_total: u64,
}

/// The registry of one execution layer.
#[derive(Debug)]
pub struct Registry {
    entries: Mutex<VecDeque<Arc<Cell>>>,
    cap: usize,
    next_token: AtomicU64,
    imports: AtomicU64,
    blocks: AtomicU64,
    takeovers: AtomicU64,
    served: AtomicU64,
}

/// A request's place in the registry.
#[derive(Debug)]
pub enum Claim {
    /// Do the work, and report its progress on the owner.
    Owner(Owner),
    /// Wait for another request's work.
    Waiter(Waiter),
}

impl Registry {
    /// A registry keeping `cap` hashes (at least one).
    pub fn new(cap: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(cap.max(1) + 1)),
            cap: cap.max(1),
            next_token: AtomicU64::new(1),
            imports: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            takeovers: AtomicU64::new(0),
            served: AtomicU64::new(0),
        }
    }

    /// Registers a request for `hash`. The first request (and the first after
    /// the cell was reset, or after a final status that is not retained)
    /// becomes the owner; every other one a waiter.
    pub fn claim(self: &Arc<Self>, hash: B256) -> Claim {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cell) = entries.iter().rev().find(|cell| cell.hash == hash).cloned() {
            drop(entries);
            cell.requests.fetch_add(1, Ordering::Relaxed);
            if cell.try_claim(token) {
                self.imports.fetch_add(1, Ordering::Relaxed);
                return Claim::Owner(Owner { cell, registry: Arc::clone(self), token });
            }
            let rx = cell.state.subscribe();
            return Claim::Waiter(Waiter { cell, registry: Arc::clone(self), rx, seen_checked: false });
        }
        Self::make_room(&mut entries, self.cap);
        let cell = Arc::new(Cell::new(hash, token));
        entries.push_back(Arc::clone(&cell));
        drop(entries);
        self.blocks.fetch_add(1, Ordering::Relaxed);
        self.imports.fetch_add(1, Ordering::Relaxed);
        Claim::Owner(Owner { cell, registry: Arc::clone(self), token })
    }

    /// Frees one slot: the oldest finished or vacant entry, or past twice the
    /// cap the oldest entry whatever it is.
    fn make_room(entries: &mut VecDeque<Arc<Cell>>, cap: usize) {
        while entries.len() >= cap {
            let idle = entries.iter().position(|cell| {
                let state = cell.state.borrow();
                state.finished() || state.owner.is_none()
            });
            match idle {
                Some(at) => {
                    entries.remove(at);
                }
                None if entries.len() >= 2 * cap => {
                    entries.pop_front();
                }
                None => break,
            }
        }
    }

    /// How many hashes are registered.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Whether no hash is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The counts for `cell` and since start.
    fn counts(&self, cell: &Cell) -> Counts {
        Counts {
            requests: cell.requests.load(Ordering::Relaxed),
            served: cell.served.load(Ordering::Relaxed),
            imports: self.imports.load(Ordering::Relaxed),
            blocks: self.blocks.load(Ordering::Relaxed),
            takeovers: self.takeovers.load(Ordering::Relaxed),
            served_total: self.served.load(Ordering::Relaxed),
        }
    }
}

/// The request doing a hash's work. Dropped without [`Owner::done`], it
/// resets the cell and a waiter takes the work over.
#[derive(Debug)]
pub struct Owner {
    cell: Arc<Cell>,
    registry: Arc<Registry>,
    token: u64,
}

impl Owner {
    /// The block hash being worked on.
    pub fn hash(&self) -> B256 {
        self.cell.hash
    }

    /// The block is checked: waiters may send their CHECKED frames.
    pub fn checked(&self) {
        let token = self.token;
        self.cell.state.send_if_modified(|state| {
            if state.owner == Some(token) && !state.checked && !state.finished() {
                state.checked = true;
                true
            } else {
                false
            }
        });
    }

    /// The final status, encoded. `retain` says whether requests arriving
    /// later are answered with it too (a VALID or INVALID verdict) or do the
    /// work again (a status that may change).
    pub fn done(&self, encoded_status: Vec<u8>, retain: bool) {
        let token = self.token;
        let encoded = Arc::new(encoded_status);
        self.cell.state.send_if_modified(|state| {
            if state.owner == Some(token) && !state.finished() {
                state.done = Some(encoded);
                state.retain = retain;
                true
            } else {
                false
            }
        });
    }

    /// The counts for this block and since start, for the block's line.
    pub fn counts(&self) -> Counts {
        self.registry.counts(&self.cell)
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let token = self.token;
        self.cell.state.send_if_modified(|state| {
            if state.owner == Some(token) && !state.finished() {
                state.owner = None;
                state.checked = false;
                true
            } else {
                false
            }
        });
    }
}

/// What a waiter learns next.
#[derive(Debug)]
pub enum Event {
    /// The owner's check is done (said once per waiter).
    Checked,
    /// The final status, encoded.
    Done(Arc<Vec<u8>>),
    /// The owner ended without a final status and this waiter owns the work.
    TakeOver(Owner),
}

/// A request waiting on another request's work.
#[derive(Debug)]
pub struct Waiter {
    cell: Arc<Cell>,
    registry: Arc<Registry>,
    rx: watch::Receiver<State>,
    seen_checked: bool,
}

impl Waiter {
    /// The block hash waited for.
    pub fn hash(&self) -> B256 {
        self.cell.hash
    }

    /// The next thing this waiter has to act on.
    pub async fn next(&mut self) -> Event {
        loop {
            let (done, checked, vacant) = {
                let state = self.rx.borrow_and_update();
                (state.done.clone(), state.checked, state.owner.is_none() && !state.finished())
            };
            if let Some(done) = done {
                self.cell.served.fetch_add(1, Ordering::Relaxed);
                self.registry.served.fetch_add(1, Ordering::Relaxed);
                return Event::Done(done);
            }
            if checked && !self.seen_checked {
                self.seen_checked = true;
                return Event::Checked;
            }
            if vacant && let Some(owner) = self.take_over() {
                return Event::TakeOver(owner);
            }
            if self.rx.changed().await.is_err() {
                // The cell's sender lives as long as the cell, which this
                // waiter holds; should it ever be gone, the work is this
                // request's own.
                return Event::TakeOver(self.force_take_over());
            }
        }
    }

    fn take_over(&self) -> Option<Owner> {
        let token = self.registry.next_token.fetch_add(1, Ordering::Relaxed);
        self.cell.try_claim(token).then(|| self.owner(token))
    }

    fn force_take_over(&self) -> Owner {
        let token = self.registry.next_token.fetch_add(1, Ordering::Relaxed);
        self.cell.state.send_modify(|state| *state = State { owner: Some(token), ..Default::default() });
        self.owner(token)
    }

    fn owner(&self, token: u64) -> Owner {
        self.registry.imports.fetch_add(1, Ordering::Relaxed);
        self.registry.takeovers.fetch_add(1, Ordering::Relaxed);
        Owner { cell: Arc::clone(&self.cell), registry: Arc::clone(&self.registry), token }
    }
}

#[cfg(test)]
#[path = "import_once_tests.rs"]
mod tests;
