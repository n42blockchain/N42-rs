// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! What happens to a leader's block between its seal and its child's start,
//! as instants this process can see: the chain header and the answer written
//! to the validator, the child's build request arriving, the child's build
//! entering `build_on_own` and starting, and the first import request for the
//! block by any key (at E=1 the leader key's, right after its proposal).
//!
//! The marks are kept for the last few block numbers and read by the child's
//! phases line as `prev_seal_to_*_us`, so the seal-to-next-build road is on
//! the line that already carries the build's own timers, without a line of
//! its own. Observability only: nothing reads a mark to decide anything.

use std::sync::Mutex;
use std::time::Instant;

/// A point on the road from a block's seal to its child's build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// The block sealed (the early-seal hook ran).
    Sealed = 0,
    /// The chain header frame written to the validator that asked to chain.
    HeaderSent = 1,
    /// The block's answer (compact or whole) written to the validator.
    AnswerSent = 2,
    /// The first byte of the child's build request read.
    ChildRequest = 3,
    /// The child's build entered `build_on_own`.
    ChildEntered = 4,
    /// The child's build started (`default_n42_payload`'s first line).
    ChildStarted = 5,
    /// The first import request for the block by header (any key).
    FirstImport = 6,
}

const MARKS: usize = 7;
/// Block numbers remembered: a child's line is written ~100 ms after its
/// parent's seal, a handful of blocks at the bench's pacing.
const KEPT: usize = 32;

#[derive(Debug, Clone, Copy)]
struct Entry {
    number: u64,
    at: [Option<Instant>; MARKS],
}

static TABLE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// Records `mark` for block `number` at `at`; the first record of a mark
/// stands (a second request for the same block does not move it).
pub fn note_at(number: u64, mark: Mark, at: Instant) {
    let Ok(mut table) = TABLE.lock() else {
        return;
    };
    let slot = mark as usize;
    if let Some(entry) = table.iter_mut().find(|entry| entry.number == number) {
        if entry.at[slot].is_none() {
            entry.at[slot] = Some(at);
        }
        return;
    }
    let mut entry = Entry { number, at: [None; MARKS] };
    entry.at[slot] = Some(at);
    if table.len() < KEPT {
        table.push(entry);
    } else if let Some(oldest) = table.iter_mut().min_by_key(|entry| entry.number) {
        // The lowest number goes: a late mark for an old block is dropped
        // rather than evicting a recent one.
        if oldest.number < number {
            *oldest = entry;
        }
    }
}

/// [`note_at`] now.
pub fn note(number: u64, mark: Mark) {
    note_at(number, mark, Instant::now());
}

/// Microseconds from block `number`'s seal to `mark`, 0 when either is not
/// recorded (or the mark came first).
pub fn since_seal_us(number: u64, mark: Mark) -> u64 {
    let Ok(table) = TABLE.lock() else {
        return 0;
    };
    table
        .iter()
        .find(|entry| entry.number == number)
        .and_then(|entry| Some(entry.at[mark as usize]?.saturating_duration_since(entry.at[Mark::Sealed as usize]?)))
        .map_or(0, |gap| gap.as_micros() as u64)
}

/// The road from block `number`'s seal, microseconds, in [`Mark`] order
/// after `Sealed` (0 where a mark is missing).
pub fn road_us(number: u64) -> [u64; MARKS - 1] {
    let mut out = [0u64; MARKS - 1];
    for (k, mark) in [
        Mark::HeaderSent,
        Mark::AnswerSent,
        Mark::ChildRequest,
        Mark::ChildEntered,
        Mark::ChildStarted,
        Mark::FirstImport,
    ]
    .into_iter()
    .enumerate()
    {
        out[k] = since_seal_us(number, mark);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // One test for the table, which is the process's: two would race each
    // other's evictions. Its numbers are far above any block another test
    // seals, so those are what an eviction takes first.
    #[test]
    fn marks_read_from_the_seal_the_first_record_stands_and_old_blocks_age_out() {
        let number = 9_000_000_001;
        let sealed = Instant::now();
        note_at(number, Mark::Sealed, sealed);
        note_at(number, Mark::ChildStarted, sealed + Duration::from_micros(9_400));
        note_at(number, Mark::ChildStarted, sealed + Duration::from_micros(20_000));
        note_at(number, Mark::HeaderSent, sealed + Duration::from_micros(1_900));
        assert_eq!(since_seal_us(number, Mark::ChildStarted), 9_400);
        assert_eq!(since_seal_us(number, Mark::HeaderSent), 1_900);
        assert_eq!(since_seal_us(number, Mark::AnswerSent), 0, "not recorded");
        assert_eq!(since_seal_us(number + 1, Mark::HeaderSent), 0, "no such block");
        let road = road_us(number);
        assert_eq!(road[0], 1_900);
        assert_eq!(road[4], 9_400);

        let base = 9_100_000_000;
        let now = Instant::now();
        note_at(base, Mark::ChildRequest, now);
        note_at(base, Mark::Sealed, now + Duration::from_millis(1));
        assert_eq!(since_seal_us(base, Mark::ChildRequest), 0, "a mark before the seal");
        for k in 1..=(2 * KEPT as u64) {
            note_at(base + k, Mark::Sealed, now);
        }
        assert_eq!(since_seal_us(base, Mark::Sealed), 0);
        let table = TABLE.lock().map(|t| t.iter().any(|e| e.number == base)).unwrap_or(true);
        assert!(!table, "the oldest block was evicted");
    }
}
