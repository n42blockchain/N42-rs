// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The entry-file compaction's schedule (`docs/QMDB_COMPACTION_DESIGN.md` 3.4-3.5, stage 3):
//! when it may run, how far back, and which punches wait for the read view.
//!
//! A round, on its own thread (`n42-qmdb-entcompact`, niced like the log's fold) and never on
//! the import path:
//!
//! 1. the horizon is the slot count of the newest logged block at or below
//!    `min(database persisted, logged) - N42_QMDB_COMPACT_RETAIN` blocks, so a restart -- which
//!    stands at the database's head or above -- never meets a group that records a kill its
//!    checkpoint does not hold, and the forest clamps it further to its undo records;
//! 2. under the forest's lock, `compact_twigs` rewrites up to the round's budget of twigs with no
//!    `fsync`; the file is synced outside the lock;
//! 3. the read view takes the moved keys' new locations (`QmdbReadView::retarget`);
//! 4. a round's freed ranges wait until the view says no journal can name them
//!    (`moved_unreachable`), then go to `punch` under the lock, oldest first.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Condvar, Mutex, PoisonError,
    },
};

use n42_twig_core::entry_store::FileRange;

use crate::read_view::Retargeted;

/// The schedule's knobs, read once from the environment.
#[derive(Debug, Clone, Copy)]
pub struct EntryCompactConfig {
    /// `N42_QMDB_COMPACT=1` (default off): a file-mode node runs the
    /// compaction thread.
    pub enabled: bool,
    /// `N42_QMDB_COMPACT_DEAD_FRAC` (default 0.5): the dead share a twig
    /// needs to be rewritten.
    pub dead_fraction: f64,
    /// `N42_QMDB_COMPACT_TWIGS_PER_BLOCK` (default 4): the rewrite budget per
    /// block the database persisted since the last round.
    pub twigs_per_block: usize,
    /// `N42_QMDB_COMPACT_RETAIN` (default 256): blocks below the persisted
    /// head a twig's records must lie (section 3.4 (a)).
    pub retain: u64,
}

impl EntryCompactConfig {
    /// The most twigs one round rewrites, whatever the blocks since.
    pub const MAX_TWIGS_PER_ROUND: usize = 64;

    /// From the environment.
    pub fn from_env() -> Self {
        fn var<T: std::str::FromStr>(name: &str) -> Option<T> {
            std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
        }
        Self {
            enabled: std::env::var("N42_QMDB_COMPACT").is_ok_and(|v| v.trim() == "1"),
            dead_fraction: var::<f64>("N42_QMDB_COMPACT_DEAD_FRAC").filter(|f| (0.0..=1.0).contains(f)).unwrap_or(0.5),
            twigs_per_block: var("N42_QMDB_COMPACT_TWIGS_PER_BLOCK").unwrap_or(4),
            retain: var("N42_QMDB_COMPACT_RETAIN").unwrap_or(256),
        }
    }
}

/// A round's freed ranges, waiting for the read view to let go of them.
#[derive(Debug)]
pub(crate) struct PendingPunch {
    /// The view's retarget of the round's moves; `None` when no valid view
    /// held anything to move.
    pub(crate) moved: Option<Retargeted>,
    pub(crate) freed: Vec<(usize, FileRange)>,
}

/// What one round did ([`crate::node_state::QmdbNodeState::compact_entries_round`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntryCompactRound {
    /// The horizon used, in slots; `None` when no logged block was deep enough.
    pub horizon: Option<u64>,
    /// Twigs rewritten.
    pub twigs: usize,
    /// Bytes appended to `entries.relocated`.
    pub bytes_written: u64,
    /// Live keys moved (the read view's retargets).
    pub moves: usize,
    /// Ranges punched this round (earlier rounds' freed ranges).
    pub punched_ranges: usize,
    /// Their bytes.
    pub punched_bytes: u64,
    /// Ranges still waiting for the read view.
    pub waiting: usize,
}

/// The schedule's shared state, one per node state.
#[derive(Debug)]
pub(crate) struct EntryCompaction {
    config: Mutex<EntryCompactConfig>,
    /// `(block, slot count after it)` of the blocks logged, ascending, at
    /// most [`Self::LOGGED_KEPT`].
    logged: Mutex<VecDeque<(u64, u64)>>,
    /// The highest block the database persisted, `u64::MAX` for none yet.
    persisted: AtomicU64,
    /// Persisted blocks not yet budgeted by a round.
    unbudgeted: AtomicU64,
    pub(crate) pending: Mutex<VecDeque<PendingPunch>>,
    /// Wakes the thread: set when the database persisted.
    wake: (Mutex<bool>, Condvar),
    /// Totals: rounds, twigs, bytes written, bytes punched.
    pub(crate) rounds: AtomicU64,
    pub(crate) twigs: AtomicU64,
    pub(crate) written: AtomicU64,
    pub(crate) punched: AtomicU64,
    pub(crate) thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl EntryCompaction {
    const LOGGED_KEPT: usize = 16_384;

    pub(crate) const fn new(config: EntryCompactConfig) -> Self {
        Self {
            config: Mutex::new(config),
            logged: Mutex::new(VecDeque::new()),
            persisted: AtomicU64::new(u64::MAX),
            unbudgeted: AtomicU64::new(0),
            pending: Mutex::new(VecDeque::new()),
            wake: (Mutex::new(false), Condvar::new()),
            rounds: AtomicU64::new(0),
            twigs: AtomicU64::new(0),
            written: AtomicU64::new(0),
            punched: AtomicU64::new(0),
            thread: Mutex::new(None),
        }
    }

    /// The knobs in force.
    pub(crate) fn config(&self) -> EntryCompactConfig {
        *self.config.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the knobs (tests; a running thread reads them each round).
    pub(crate) fn set_config(&self, config: EntryCompactConfig) {
        *self.config.lock().unwrap_or_else(PoisonError::into_inner) = config;
    }

    /// The delta log now holds block `number`, after which the tree holds
    /// `slots` slots. A block at or above `number` noted before (a fork
    /// that lost) is forgotten.
    pub(crate) fn note_logged(&self, number: u64, slots: u64) {
        let mut logged = self.logged.lock().unwrap_or_else(PoisonError::into_inner);
        while logged.back().is_some_and(|(at, _)| *at >= number) {
            logged.pop_back();
        }
        logged.push_back((number, slots));
        while logged.len() > Self::LOGGED_KEPT {
            logged.pop_front();
        }
    }

    /// The database persisted up to block `number` (`blocks` of them in this
    /// batch); wakes the thread.
    pub(crate) fn note_persisted(&self, number: u64, blocks: u64) {
        let previous = self.persisted.load(Ordering::Relaxed);
        if previous == u64::MAX || number > previous {
            self.persisted.store(number, Ordering::Relaxed);
        }
        self.unbudgeted.fetch_add(blocks, Ordering::Relaxed);
        let (flag, wake) = &self.wake;
        *flag.lock().unwrap_or_else(PoisonError::into_inner) = true;
        wake.notify_one();
    }

    /// The horizon in slots (step 1 of the module documentation), if a
    /// logged block is deep enough.
    pub(crate) fn horizon(&self) -> Option<u64> {
        let persisted = self.persisted.load(Ordering::Relaxed);
        if persisted == u64::MAX {
            return None;
        }
        let logged = self.logged.lock().unwrap_or_else(PoisonError::into_inner);
        let newest_logged = logged.back()?.0;
        let deepest = persisted.min(newest_logged).checked_sub(self.config().retain)?;
        let at = logged.partition_point(|(number, _)| *number <= deepest);
        at.checked_sub(1).map(|i| logged[i].1)
    }

    /// The twigs this round may rewrite: the budget of the blocks persisted
    /// since the last round, at least one block's.
    pub(crate) fn take_budget(&self) -> usize {
        let blocks = self.unbudgeted.swap(0, Ordering::Relaxed).max(1);
        (blocks as usize).saturating_mul(self.config().twigs_per_block).min(EntryCompactConfig::MAX_TWIGS_PER_ROUND)
    }

    /// Waits up to `timeout` for a wake; whether one came.
    pub(crate) fn wait(&self, timeout: std::time::Duration) -> bool {
        let (flag, wake) = &self.wake;
        let guard = flag.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut guard, _) = wake.wait_timeout_while(guard, timeout, |woken| !*woken).unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(retain: u64) -> EntryCompactConfig {
        EntryCompactConfig { enabled: true, dead_fraction: 0.5, twigs_per_block: 4, retain }
    }

    #[test]
    fn the_horizon_is_the_newest_logged_block_deep_enough_below_both_heads() {
        let schedule = EntryCompaction::new(config(10));
        assert_eq!(schedule.horizon(), None, "nothing persisted");
        for n in 1..=40 {
            schedule.note_logged(n, n * 100);
        }
        schedule.note_persisted(25, 25);
        assert_eq!(schedule.horizon(), Some(1500), "persisted 25 - 10");
        schedule.note_persisted(60, 1);
        assert_eq!(schedule.horizon(), Some(3000), "logged 40 - 10");
        // A fork at 35 replaces 35..=40.
        schedule.note_logged(35, 9_999);
        assert_eq!(schedule.horizon(), Some(2500), "logged 35 - 10");
        assert_eq!(schedule.take_budget(), EntryCompactConfig::MAX_TWIGS_PER_ROUND.min(26 * 4));
        assert_eq!(schedule.take_budget(), 4, "at least one block's");
        let shallow = EntryCompaction::new(config(100));
        shallow.note_logged(5, 10);
        shallow.note_persisted(5, 1);
        assert_eq!(shallow.horizon(), None);
    }
}
