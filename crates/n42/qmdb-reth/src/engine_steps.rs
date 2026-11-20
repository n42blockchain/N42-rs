// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What reth's engine thread did for each block this node hands it, timed on
//! that thread.
//!
//! The engine tree runs on one OS thread (`engine`), and under load it was the
//! serial server of the leader's chain (~30 ms of CPU a full own block,
//! `docs/PLAN_6M_2026_11.md`). Two of its calls reach N42 code:
//! [`N42TreeValidator`](crate::N42TreeValidator)'s executed-insert hook (the
//! tree accepted an own block inserted as executed) and its payload
//! conversion (a `newPayload` whose block the tree already holds converts the
//! payload only to throw the block away). Both are recorded here under the
//! block's hash, with when they started and how long they took in wall time
//! and in the thread's own CPU time, so the hand-off can print, per block,
//! how long each message waited in the engine's queue and how long it worked.
//!
//! The record is a small ring (the last [`KEEP`] blocks), written once per
//! call on the engine thread under a mutex nobody holds for long; a reader
//! takes its block's entry out.
//!
//! [`wait_accepted`] also lets the own-block hand-off learn that the tree
//! accepted its executed insert (`N42_SKIP_OWN_NEW_PAYLOAD`): the hook is
//! called by the tree only for an insert it keeps -- not for one dropped as
//! outdated or already known.

use alloy_primitives::B256;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Blocks remembered.
pub const KEEP: usize = 64;

/// How the payload's block was produced by the conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConvertRoad {
    /// Not recorded (the conversion did not reach the sealed store).
    #[default]
    Unknown,
    /// The kept sealed block was moved out of the store: no copy.
    Taken,
    /// The kept block is shared with the engine's own copy (the executed
    /// insert's), so the conversion copied it.
    CopiedShared,
    /// The kept block was the store's own and was copied (the payload's
    /// count differs, or `N42_ENGINE_TAKE_SEALED` is off).
    CopiedOwned,
    /// No kept block: the payload was decoded.
    Decoded,
}

impl ConvertRoad {
    /// The word the log line prints.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Taken => "taken",
            Self::CopiedShared => "copied_shared",
            Self::CopiedOwned => "copied_owned",
            Self::Decoded => "decoded",
        }
    }
}

/// One block's engine-thread record.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineSteps {
    /// The executed-insert hook ran (the tree accepted the insert).
    pub accepted_at: Option<Instant>,
    /// The hook's wall time, microseconds.
    pub insert_hook_us: u64,
    /// The hook's thread CPU time, microseconds.
    pub insert_hook_cpu_us: u64,
    /// When the `newPayload` conversion started.
    pub convert_at: Option<Instant>,
    /// When it returned.
    pub convert_done_at: Option<Instant>,
    /// Its wall time, microseconds.
    pub convert_us: u64,
    /// Its thread CPU time, microseconds.
    pub convert_cpu_us: u64,
    /// How it produced the block.
    pub convert_road: ConvertRoad,
    /// The sealed store's lock wait, microseconds.
    pub convert_lock_us: u64,
    /// The copy (or decode) of the block, microseconds.
    pub convert_copy_us: u64,
    /// Transactions in the converted block.
    pub convert_txs: usize,
}

struct Ring {
    entries: Mutex<VecDeque<(B256, EngineSteps)>>,
    accepted: Condvar,
}

fn ring() -> &'static Ring {
    static RING: OnceLock<Ring> = OnceLock::new();
    RING.get_or_init(|| Ring { entries: Mutex::new(VecDeque::with_capacity(KEEP)), accepted: Condvar::new() })
}

fn update(hash: B256, f: impl FnOnce(&mut EngineSteps)) {
    let ring = ring();
    let mut entries = ring.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, steps)) = entries.iter_mut().rev().find(|(h, _)| *h == hash) {
        f(steps);
        return;
    }
    if entries.len() >= KEEP {
        entries.pop_front();
    }
    let mut steps = EngineSteps::default();
    f(&mut steps);
    entries.push_back((hash, steps));
}

/// This thread's CPU time so far, microseconds (0 where it cannot be read).
pub fn thread_cpu_us() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec; the clock id is a constant.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000).saturating_add(ts.tv_nsec as u64 / 1_000)
}

/// A span on the current thread: wall clock and thread CPU time.
#[derive(Debug, Clone, Copy)]
pub struct Span {
    at: Instant,
    cpu_us: u64,
}

impl Span {
    /// Starts now.
    pub fn start() -> Self {
        Self { at: Instant::now(), cpu_us: thread_cpu_us() }
    }

    /// When it started.
    pub const fn at(&self) -> Instant {
        self.at
    }

    /// `(wall us, cpu us)` since the start.
    pub fn elapsed(&self) -> (u64, u64) {
        (self.at.elapsed().as_micros() as u64, thread_cpu_us().saturating_sub(self.cpu_us))
    }
}

/// The tree accepted `hash` as an executed block: its hook started at
/// `span`. Wakes [`wait_accepted`].
pub fn note_accepted(hash: B256, span: Span) {
    let (wall, cpu) = span.elapsed();
    update(hash, |steps| {
        steps.accepted_at = Some(span.at());
        steps.insert_hook_us = wall;
        steps.insert_hook_cpu_us = cpu;
    });
    ring().accepted.notify_all();
}

/// The engine's conversion of `hash`'s payload, started at `span`, has
/// returned.
pub fn note_converted(hash: B256, span: Span) {
    let (wall, cpu) = span.elapsed();
    update(hash, |steps| {
        steps.convert_at = Some(span.at());
        steps.convert_done_at = Some(Instant::now());
        steps.convert_us = wall;
        steps.convert_cpu_us = cpu;
    });
}

/// How the conversion of `hash`'s payload produced its block (recorded by
/// the payload validator, inside the span [`note_converted`] closes).
pub fn note_convert_road(hash: B256, road: ConvertRoad, lock_us: u64, copy_us: u64, txs: usize) {
    update(hash, |steps| {
        steps.convert_road = road;
        steps.convert_lock_us = lock_us;
        steps.convert_copy_us = copy_us;
        steps.convert_txs = txs;
    });
}

/// `hash`'s record, taken out of the ring.
pub fn take(hash: B256) -> Option<EngineSteps> {
    let mut entries = ring().entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let at = entries.iter().rposition(|(h, _)| *h == hash)?;
    entries.remove(at).map(|(_, steps)| steps)
}

/// When the tree accepted `hash` as an executed block, waiting at most
/// `bound` for it. Blocking: call it off the async runtime.
pub fn wait_accepted(hash: B256, bound: Duration) -> Option<Instant> {
    let ring = ring();
    let deadline = Instant::now() + bound;
    let mut entries = ring.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        if let Some(at) = entries.iter().rev().find(|(h, _)| *h == hash).and_then(|(_, steps)| steps.accepted_at) {
            return Some(at);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        entries = ring
            .accepted
            .wait_timeout(entries, left)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring is process-wide: these tests take turns.
    static TURN: Mutex<()> = Mutex::new(());

    #[test]
    fn an_accepted_insert_is_seen_and_one_never_accepted_times_out() {
        let _turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let hash = B256::with_last_byte(0xA1);
        let waiter = std::thread::spawn(move || wait_accepted(hash, Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(20));
        note_accepted(hash, Span::start());
        assert!(waiter.join().expect("waiter").is_some(), "woken by the hook");
        let never = B256::with_last_byte(0xA2);
        let at = Instant::now();
        assert_eq!(wait_accepted(never, Duration::from_millis(30)), None);
        assert!(at.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn one_blocks_steps_are_kept_together_and_taken_once() {
        let _turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let hash = B256::with_last_byte(0xB1);
        note_accepted(hash, Span::start());
        note_convert_road(hash, ConvertRoad::CopiedShared, 3, 14_000, 200_000);
        note_converted(hash, Span::start());
        let steps = take(hash).expect("recorded");
        assert!(steps.accepted_at.is_some() && steps.convert_at.is_some() && steps.convert_done_at.is_some());
        assert_eq!((steps.convert_road, steps.convert_copy_us, steps.convert_txs), (ConvertRoad::CopiedShared, 14_000, 200_000));
        assert!(take(hash).is_none(), "taken once");
    }

    #[test]
    fn the_ring_keeps_the_last_blocks() {
        let _turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for i in 0..(KEEP as u64 + 8) {
            note_accepted(B256::left_padding_from(&(0xC000_0000 + i).to_be_bytes()), Span::start());
        }
        assert!(take(B256::left_padding_from(&0xC000_0000u64.to_be_bytes())).is_none(), "the oldest is gone");
        assert!(take(B256::left_padding_from(&(0xC000_0000 + KEEP as u64 + 7).to_be_bytes())).is_some());
    }
}
