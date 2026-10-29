// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An own block's revert set, completed after its import was answered
//! (`N42_ANSWER_BEFORE_REVERTS=1`).
//!
//! The leader's merge of a 200,000-transfer block is the account map (~37 ms)
//! and then the revert set (~50 ms), and the import of the block is answered
//! only once both are done (loop351 af: `seal_to_state_ready` 152 ms, the
//! merge 91 of it). Nothing on the answer's road reads the reverts: the next
//! build reads the post-state, the engine's in-memory overlay reads the
//! bundle's accounts, the QMDB root is computed before the merge. Only
//! persistence (the changesets), the in-memory changeset reads and the
//! canonical notification's outcome do.
//!
//! With the switch the build hands its execution out with the block's own
//! reverts only (the executor's few) and registers the output here; the
//! revert set is merged beside it and filled in when done. Every consumer of
//! the reverts asks [`resolve`] (or [`complete_in_place`]) first, which waits
//! for the fill, so what it reads is the bundle the switch-off merge leaves.
//! An output is known by its address: the registry keeps the output alive
//! while its entry exists, so the address is not reused, and drops the entry
//! once nobody else holds the output.

use std::any::Any;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

pub use revm_database::states::reverts::Reverts;
use revm_database::BundleState;

/// How long a consumer waits for a fill: a stall guard, not a budget (the
/// revert merge is ~50 ms).
const WAIT: Duration = Duration::from_secs(30);

/// Whether the leader's builds answer before their revert set is merged
/// (`N42_ANSWER_BEFORE_REVERTS=1`, default off), read and logged once.
pub fn answer_before_reverts() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let on = n42_env::flag("N42_ANSWER_BEFORE_REVERTS", false);
        tracing::info!(target: "n42.deferred_reverts", answer_before_reverts = on, "N42_ANSWER_BEFORE_REVERTS");
        on
    })
}

/// Whether [`register`] frees the outputs it evicts after the registry lock
/// is released, on a thread of its own (`N42_REGISTER_FREE_OFFLOCK=1`,
/// default off), read and logged once. Off, the eviction drops them under
/// the lock on the registering thread -- the merger, between the merge's end
/// and `StateReady`, where the last holder of an older block's output frees
/// its ~185k-account bundle.
pub fn register_free_offlock() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let on = n42_env::flag("N42_REGISTER_FREE_OFFLOCK", false);
        tracing::info!(target: "n42.deferred_reverts", register_free_offlock = on, "N42_REGISTER_FREE_OFFLOCK");
        on
    })
}

/// Drops evicted entries on a thread of their own (`n42-reverts-free`); the
/// caller drops them (outside the lock) when that thread is two behind or
/// cannot be had. Nothing reads an entry once it left the registry.
fn free_off_path(evicted: Vec<Entry>) {
    if evicted.is_empty() {
        return;
    }
    static FREE: OnceLock<Option<Mutex<std::sync::mpsc::SyncSender<Vec<Entry>>>>> = OnceLock::new();
    let sender = FREE.get_or_init(|| {
        let (send, receive) = std::sync::mpsc::sync_channel::<Vec<Entry>>(2);
        std::thread::Builder::new()
            .name("n42-reverts-free".into())
            .spawn(move || {
                while let Ok(entries) = receive.recv() {
                    drop(entries);
                }
            })
            .ok()
            .map(|_| Mutex::new(send))
    });
    let unsent = match sender {
        Some(sender) => match sender.lock().unwrap_or_else(std::sync::PoisonError::into_inner).try_send(evicted) {
            Ok(()) => None,
            Err(
                std::sync::mpsc::TrySendError::Full(evicted) | std::sync::mpsc::TrySendError::Disconnected(evicted),
            ) => Some(evicted),
        },
        None => Some(evicted),
    };
    drop(unsent);
}

/// A fill's state.
#[derive(Debug, Default)]
enum Fill {
    #[default]
    Pending,
    Filled(Arc<Reverts>, usize),
    /// The merge ended without a fill (a panic): consumers fail at once.
    Failed,
}

#[derive(Debug, Default)]
struct Slot {
    fill: Mutex<Fill>,
    done: Condvar,
}

impl Slot {
    fn set(&self, fill: Fill) {
        *self.fill.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = fill;
        self.done.notify_all();
    }
}

struct Entry {
    key: usize,
    keep: Arc<dyn Any + Send + Sync>,
    slot: Arc<Slot>,
}

fn registry() -> &'static Mutex<Vec<Entry>> {
    static REGISTRY: OnceLock<Mutex<Vec<Entry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn key_of<T>(output: *const T) -> usize {
    output.cast::<()>() as usize
}

/// The promise of an output's revert set, given by [`register`]: filled with
/// [`LateReverts::fill`]; dropped unfilled, the consumers fail instead of
/// waiting out [`WAIT`].
#[derive(Debug)]
pub struct LateReverts {
    slot: Arc<Slot>,
    filled: bool,
}

impl LateReverts {
    /// The output's complete revert set and its size (`reverts_size`).
    pub fn fill(mut self, reverts: Reverts, size: usize) {
        self.slot.set(Fill::Filled(Arc::new(reverts), size));
        self.filled = true;
    }
}

impl Drop for LateReverts {
    fn drop(&mut self) {
        if !self.filled {
            tracing::error!(target: "n42.deferred_reverts", "a block's late revert set was never filled; its consumers fail");
            self.slot.set(Fill::Failed);
        }
    }
}

/// Registers `output` (an execution handed out with its block's own
/// reverts only) as owed its complete revert set. Entries whose output
/// nobody else holds any more are dropped here.
pub fn register<T: Send + Sync + 'static>(output: &Arc<T>) -> LateReverts {
    register_timed(output).0
}

/// What one [`register`] cost, us: the wait for the registry lock, the time
/// it was held, and the part of that spent dropping the entries whose output
/// nobody else held (the last holder frees the output there).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegisterTiming {
    /// Waiting for the registry lock.
    pub wait_us: u64,
    /// The lock held: the eviction and the insert.
    pub lock_us: u64,
    /// The eviction under the lock: with the free of what it evicted, unless
    /// `N42_REGISTER_FREE_OFFLOCK` moves that free off the lock.
    pub free_us: u64,
    /// The entries evicted.
    pub evicted: usize,
}

/// [`register`], timed.
pub fn register_timed<T: Send + Sync + 'static>(output: &Arc<T>) -> (LateReverts, RegisterTiming) {
    let slot = Arc::new(Slot::default());
    let keep: Arc<dyn Any + Send + Sync> = output.clone();
    let asked = std::time::Instant::now();
    let mut entries = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let locked = std::time::Instant::now();
    let before = entries.len();
    // Off the lock: the evicted entries are only moved out under it, and
    // dropped (with the outputs they last held) once it is released.
    let mut out = Vec::new();
    if register_free_offlock() {
        out = entries.extract_if(.., |entry| Arc::strong_count(&entry.keep) <= 1).collect();
    } else {
        entries.retain(|entry| Arc::strong_count(&entry.keep) > 1);
    }
    let evicted = before - entries.len();
    let freed = std::time::Instant::now();
    entries.push(Entry { key: key_of(Arc::as_ptr(output)), keep, slot: Arc::clone(&slot) });
    drop(entries);
    let released = std::time::Instant::now();
    free_off_path(out);
    let us = |from: std::time::Instant, to: std::time::Instant| to.duration_since(from).as_micros() as u64;
    let timing = RegisterTiming {
        wait_us: us(asked, locked),
        lock_us: us(locked, released),
        free_us: us(locked, freed),
        evicted,
    };
    (LateReverts { slot, filled: false }, timing)
}

/// Why a registered output's revert set could not be had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unfilled {
    /// The merge ended without filling it.
    Failed,
    /// Not filled within the wait.
    TimedOut,
}

impl std::fmt::Display for Unfilled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed => f.write_str("the block's late revert set failed"),
            Self::TimedOut => f.write_str("the block's late revert set was not filled in time"),
        }
    }
}

impl std::error::Error for Unfilled {}

/// Whether anything is registered at all (consumers skip the lookup
/// otherwise).
fn any_registered() -> bool {
    !registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty()
}

/// The complete revert set (and its size) of `output` when it was handed
/// out without it, waiting for the fill; `Ok(None)` when its bundle is
/// complete as it stands.
pub fn resolve<T>(output: &T) -> Result<Option<(Arc<Reverts>, usize)>, Unfilled> {
    if !any_registered() {
        return Ok(None);
    }
    let key = key_of(std::ptr::from_ref(output));
    let slot = {
        let entries = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match entries.iter().find(|entry| entry.key == key) {
            Some(entry) => Arc::clone(&entry.slot),
            None => return Ok(None),
        }
    };
    let fill = slot.fill.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (fill, _) = slot
        .done
        .wait_timeout_while(fill, WAIT, |fill| matches!(fill, Fill::Pending))
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match &*fill {
        Fill::Filled(reverts, size) => Ok(Some((Arc::clone(reverts), *size))),
        Fill::Failed => Err(Unfilled::Failed),
        Fill::Pending => Err(Unfilled::TimedOut),
    }
}

/// `bundle` -- a copy of `output`'s bundle -- with `output`'s complete
/// revert set put in, when it was handed out without it.
pub fn complete_in_place<T>(output: &T, bundle: &mut BundleState) -> Result<(), Unfilled> {
    if let Some((reverts, size)) = resolve(output)? {
        bundle.reverts = (*reverts).clone();
        bundle.reverts_size = size;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some_reverts(n: usize) -> Reverts {
        let mut reverts = Reverts::default();
        reverts.push(
            (0..n)
                .map(|i| {
                    (
                        alloy_primitives::Address::with_last_byte(i as u8),
                        revm_database::AccountRevert::default(),
                    )
                })
                .collect(),
        );
        reverts
    }

    #[test]
    fn a_consumer_waits_for_the_fill_and_an_unregistered_output_is_complete() {
        let output = Arc::new(BundleState::default());
        let other = Arc::new(BundleState::default());
        assert_eq!(resolve(&*output), Ok(None));
        let late = register(&output);
        let waiter = {
            let output = Arc::clone(&output);
            std::thread::spawn(move || resolve(&*output))
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished(), "the consumer waits for the fill");
        late.fill(some_reverts(3), 3);
        let (reverts, size) = waiter.join().expect("joined").expect("filled").expect("registered");
        assert_eq!((reverts.len(), reverts[0].len(), size), (1, 3, 3));
        assert_eq!(resolve(&*other), Ok(None), "another output is complete as it stands");
        let mut bundle = BundleState::default();
        complete_in_place(&*output, &mut bundle).expect("filled");
        assert_eq!((bundle.reverts.len(), bundle.reverts_size), (1, 3));
    }

    #[test]
    fn an_unfilled_promise_fails_its_consumers_at_once_and_entries_go_with_their_output() {
        let output = Arc::new(BundleState::default());
        drop(register(&output));
        assert_eq!(resolve(&*output), Err(Unfilled::Failed));
        // Once only the registry holds the output, the next registration drops it.
        let key = key_of(Arc::as_ptr(&output));
        drop(output);
        let next = Arc::new(BundleState::default());
        register(&next).fill(Reverts::default(), 0);
        let entries = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(entries.iter().all(|entry| entry.key != key || Arc::strong_count(&entry.keep) > 1));
    }
}
