// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Who occupies the QMDB forest's lock and its tree, block by block.
//!
//! The `forest lock waited` / `forest lock held` WARN lines only name waits
//! and holds over 20 ms, so the sum per block of everything under the lock
//! (and of the tree's leases) could not be read from a log. This keeps a
//! running sum per label -- holds, hold time, waits, wait time -- and logs it
//! every [`LOG_EVERY`] with the canonical blocks that passed meanwhile, so
//! the occupancy per block of each holder is one division away.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::info;

/// How often the running sums are logged.
const LOG_EVERY: Duration = Duration::from_secs(10);

/// A take that waited at least this long counts as a wait.
const WAIT_COUNTED: Duration = Duration::from_micros(100);

/// One label's sums since the last line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LabelSums {
    /// Times the lock (or the tree, for `tree_lease`) was held.
    pub holds: u64,
    /// Time held, microseconds.
    pub hold_us: u64,
    /// Times a taker found it busy and waited.
    pub waits: u64,
    /// Time waited, microseconds.
    pub wait_us: u64,
}

#[derive(Debug)]
struct Table {
    labels: Vec<(&'static str, LabelSums)>,
    since: Instant,
    canonical_at: u64,
}

/// The running sums per label ([`crate::node_state::QmdbNodeState`] keeps one).
#[derive(Debug)]
pub struct Occupancy {
    table: Mutex<Table>,
}

impl Default for Occupancy {
    fn default() -> Self {
        Self { table: Mutex::new(Table { labels: Vec::new(), since: Instant::now(), canonical_at: 0 }) }
    }
}

impl Occupancy {
    fn with<T>(&self, f: impl FnOnce(&mut Table) -> T) -> T {
        let mut table = self.table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut table)
    }

    fn entry<'a>(table: &'a mut Table, label: &'static str) -> &'a mut LabelSums {
        let at = match table.labels.iter().position(|(name, _)| *name == label) {
            Some(at) => at,
            None => {
                table.labels.push((label, LabelSums::default()));
                table.labels.len() - 1
            }
        };
        &mut table.labels[at].1
    }

    /// A hold of `held` by `label`.
    pub fn hold(&self, label: &'static str, held: Duration) {
        self.with(|table| {
            let sums = Self::entry(table, label);
            sums.holds += 1;
            sums.hold_us += held.as_micros() as u64;
        });
    }

    /// A wait of `waited` by `label`: counted as a wait from
    /// [`WAIT_COUNTED`] (an uncontended take costs nanoseconds), its time
    /// added either way.
    pub fn wait(&self, label: &'static str, waited: Duration) {
        if waited.is_zero() {
            return;
        }
        self.with(|table| {
            let sums = Self::entry(table, label);
            sums.waits += u64::from(waited >= WAIT_COUNTED);
            sums.wait_us += waited.as_micros() as u64;
        });
    }

    /// The sums since the last line, by label.
    pub fn snapshot(&self) -> Vec<(&'static str, LabelSums)> {
        self.with(|table| table.labels.clone())
    }

    /// Logs the sums and starts new ones when [`LOG_EVERY`] has passed;
    /// `canonical` is the canonical head's number now.
    pub fn maybe_log(&self, canonical: u64) {
        let taken = self.with(|table| {
            if table.since.elapsed() < LOG_EVERY {
                return None;
            }
            let window = table.since.elapsed();
            let blocks = canonical.saturating_sub(table.canonical_at);
            table.since = Instant::now();
            table.canonical_at = canonical;
            Some((std::mem::take(&mut table.labels), window, blocks))
        });
        let Some((labels, window, blocks)) = taken else { return };
        let per = blocks.max(1) as f64 * 1000.0;
        let mut labels = labels;
        labels.sort_by_key(|(_, sums)| std::cmp::Reverse(sums.hold_us + sums.wait_us));
        let line = labels
            .iter()
            .map(|(label, s)| {
                format!(
                    "{label}:{}/{:.2}ms/{}/{:.2}ms",
                    s.holds,
                    s.hold_us as f64 / per,
                    s.waits,
                    s.wait_us as f64 / per,
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        info!(
            target: "n42.qmdb",
            window_ms = window.as_millis() as u64,
            blocks,
            per_block = %line,
            "forest occupancy (label:holds/hold-ms-per-block/waits/wait-ms-per-block)",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_by_label_and_skips_empty_waits() {
        let occ = Occupancy::default();
        occ.hold("a", Duration::from_micros(300));
        occ.hold("a", Duration::from_micros(200));
        occ.wait("a", Duration::ZERO);
        occ.wait("b", Duration::from_micros(150));
        occ.wait("b", Duration::from_micros(20));
        let snap = occ.snapshot();
        assert_eq!(snap[0], ("a", LabelSums { holds: 2, hold_us: 500, waits: 0, wait_us: 0 }));
        assert_eq!(snap[1], ("b", LabelSums { holds: 0, hold_us: 0, waits: 1, wait_us: 170 }));
    }
}
