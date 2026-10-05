// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ingest's own tokio runtime (`N42_INGEST_RUNTIME=1`), and recovery
//! slots taken on the blocking side.
//!
//! `docs/SHARED_EXECUTION_SCOPE.md` 10.2: with the ingest on the execution
//! layer's main runtime, ~56 of 64 connections sat waiting at the recovery
//! semaphore while 2.5 of its 12 permits did work. A permit released on a
//! blocking thread is granted to a waiting connection task, and that task
//! then waits 2-4 ms for a main-runtime worker to poll it -- behind the
//! canonical pruner's synchronous work, 128 connection and admitter tasks,
//! and gate reads blocked on the queue's lock -- before it can hand the
//! permit to a blocking thread. Raising the permits from 12 to 24 left the
//! frame rate where it was.
//!
//! With the switch on, the listener, every connection's read loop, its gate,
//! decode and reply, its admitter, the gate's watcher and the 5 s report run
//! on a runtime of their own (`n42-ingest` threads, `N42_INGEST_RUNTIME_WORKERS`
//! async workers, 8 by default: 64 connections at 7,000 frames a second are
//! ~3.2 cores of decode and ~0.5 of reads and replies). The recovery (the
//! attested-frame check, or the per-transaction verification) runs on that
//! runtime's blocking pool and takes its slot *there*, from a counting
//! semaphore a blocking thread waits on ([`BlockingSlots`]): a connection
//! task never holds or awaits a permit, so no permit is ever parked on a task
//! that has not been polled yet. The pool's thread bound is the slot count
//! (plus two), so the waiting is mostly tokio's own queue of blocking tasks,
//! which a thread finishing a frame takes from directly.
//!
//! What stays on the main runtime: the engine API and RPC, the network, the
//! payload builder's tasks, the queue's 5 ms inbox drainer
//! (`N42_TX_QUEUE_DRAINER`), the pool's new-transaction feed into the queue,
//! the canonical-head watcher the gate's lag allowance reads, the canonical
//! pruner unless `N42_QUEUE_PRUNE_THREAD=1` moves it to its own thread, and
//! the vote road unless `N42_ROAD_RUNTIME=1` gives it its own runtime.
//!
//! A runtime that cannot be built leaves the ingest where it was, with a
//! warning, and the semaphore on the async side as before.

use std::sync::{Arc, OnceLock};

use parking_lot::{Condvar, Mutex};
use tracing::{info, warn};

/// Whether the ingest runs on its own runtime (`N42_INGEST_RUNTIME=1`, off by
/// default).
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_INGEST_RUNTIME").is_ok_and(|v| v == "1"))
}

/// Async workers of the ingest's runtime: `N42_INGEST_RUNTIME_WORKERS`, 8 by
/// default, clamped to 1..=64.
pub(crate) fn workers() -> usize {
    std::env::var("N42_INGEST_RUNTIME_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 64)
}

/// The blocking pool's thread bound for `slots` recovery slots: the slots
/// plus two, so a frame's recovery never waits for a thread while a slot is
/// free, and 512 (tokio's default) when the slots are unbounded.
pub(crate) const fn blocking_threads(slots: Option<usize>) -> usize {
    match slots {
        Some(slots) => slots + 2,
        None => 512,
    }
}

/// A runtime of `workers` async workers named `n42-ingest` whose blocking
/// pool is bounded for `slots` recovery slots.
pub(crate) fn build(workers: usize, slots: Option<usize>) -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(blocking_threads(slots))
        .thread_name("n42-ingest")
        .enable_all()
        .build()
}

/// The ingest's runtime, built on first use; `None` when the switch is off
/// or the runtime could not be built (said once, as a warning).
///
/// Held in a static and never dropped: dropping a runtime from inside
/// another runtime's context panics, and this one lives as long as the
/// process.
pub fn handle() -> Option<tokio::runtime::Handle> {
    static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    if !enabled() {
        return None;
    }
    RUNTIME
        .get_or_init(|| {
            let workers = workers();
            let slots = crate::recovery_slot_count();
            match build(workers, slots) {
                Ok(runtime) => {
                    info!(
                        target: "n42.tx_ingest",
                        workers,
                        slots,
                        blocking_threads = blocking_threads(slots),
                        "transaction ingest on its own runtime, recovery slots taken on the blocking side"
                    );
                    Some(runtime)
                }
                Err(err) => {
                    warn!(
                        target: "n42.tx_ingest",
                        %err,
                        "N42_INGEST_RUNTIME=1 but its runtime could not be built; the ingest stays on the main runtime"
                    );
                    None
                }
            }
        })
        .as_ref()
        .map(|runtime| runtime.handle().clone())
}

/// A counting semaphore a blocking thread waits on: the recovery slots
/// under `N42_INGEST_RUNTIME=1`. Released by the holder's own thread when
/// its guard drops, and handed to the next waiter by the kernel's wake of a
/// parked thread, not by an async task's poll.
#[derive(Debug)]
pub(crate) struct BlockingSlots {
    free: Mutex<usize>,
    released: Condvar,
}

impl BlockingSlots {
    /// `permits` slots; `None` is unbounded (every acquire succeeds at once).
    pub(crate) fn new(permits: Option<usize>) -> Arc<Self> {
        Arc::new(Self { free: Mutex::new(permits.unwrap_or(usize::MAX)), released: Condvar::new() })
    }

    /// Waits on the calling (blocking) thread for a slot.
    pub(crate) fn acquire(self: &Arc<Self>) -> BlockingSlot {
        let mut free = self.free.lock();
        while *free == 0 {
            self.released.wait(&mut free);
        }
        *free -= 1;
        BlockingSlot { slots: Arc::clone(self) }
    }

    /// Slots free right now; for the tests.
    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        *self.free.lock()
    }
}

/// One held slot; dropping it frees the slot and wakes one waiter.
#[derive(Debug)]
pub(crate) struct BlockingSlot {
    slots: Arc<BlockingSlots>,
}

impl Drop for BlockingSlot {
    fn drop(&mut self) {
        let mut free = self.slots.free.lock();
        *free = free.saturating_add(1);
        drop(free);
        self.slots.released.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn unset(name: &str) -> bool {
        std::env::var_os(name).is_none()
    }

    #[test]
    fn the_ingest_runtime_is_off_unless_asked_for() {
        if unset("N42_INGEST_RUNTIME") {
            assert!(!enabled());
            assert!(handle().is_none(), "the ingest stays on the main runtime");
        }
        if unset("N42_INGEST_RUNTIME_WORKERS") {
            assert_eq!(workers(), 8);
        }
        assert_eq!(blocking_threads(Some(12)), 14);
        assert_eq!(blocking_threads(None), 512);
    }

    /// No more than the permits run at once, every acquire is served, and
    /// every slot is back at the end.
    #[test]
    fn blocking_slots_bound_the_holders_and_come_back() {
        let slots = BlockingSlots::new(Some(3));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (slots, running, peak) = (Arc::clone(&slots), Arc::clone(&running), Arc::clone(&peak));
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        let _slot = slots.acquire();
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::yield_now();
                        running.fetch_sub(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("a holder panicked");
        }
        assert!(peak.load(Ordering::SeqCst) <= 3);
        assert_eq!(slots.available(), 3);
        let unbounded = BlockingSlots::new(None);
        let held: Vec<_> = (0..100).map(|_| unbounded.acquire()).collect();
        drop(held);
        assert_eq!(unbounded.available(), usize::MAX);
    }
}
