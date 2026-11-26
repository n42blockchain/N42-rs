// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Anchored import for the range catch-up (sync standard §3.3-§3.4, W7).
//!
//! A block pulled by range is executed only once it is *authenticated*: its
//! hash lies on the parent-hash chain below a verified anchor -- a block hash
//! named by a commit-domain QC that verified against the validator set of its
//! exact view (`ConsensusEngine::verify_sync_anchor_qc`), harvested from the
//! headers of the pulled blocks themselves or from a live commit. Pulled
//! blocks wait in an [`AnchorBuffer`] that is contiguous and parent-linked
//! (the service screens each block before it is pushed), so an anchor on one
//! buffered block authenticates every buffered block below it. The blocks
//! above the highest anchor are the *unanchored tail*: never executed by the
//! sync importer, and bounded by [`MAX_TAIL_BLOCKS`] and [`MAX_TAIL_BYTES`].
//!
//! `N42_SYNC_ANCHOR` ([`SyncAnchorMode`]) selects the rule: `enforce` (the
//! default), `observe` (import as before and log what `enforce` would have
//! held or refused) or `off`.

use alloy_primitives::B256;
use std::collections::VecDeque;

/// The environment variable that selects the [`SyncAnchorMode`] (gov5's name).
pub const SYNC_ANCHOR_ENV: &str = "N42_SYNC_ANCHOR";

/// Unanchored blocks the sync importer holds at most (sync standard §3.4.6).
pub const MAX_TAIL_BLOCKS: usize = 64;

/// Bytes of unanchored blocks the sync importer holds at most (§3.4.6).
pub const MAX_TAIL_BYTES: usize = 512 << 20;

/// Anchored hashes kept while the block they name has not been pulled yet.
const MAX_PENDING_ANCHORS: usize = 256;

/// How the range catch-up treats blocks no verified anchor covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAnchorMode {
    /// No anchor bookkeeping: the catch-up as it was before the rule.
    Off,
    /// Import as `Off` does, and log every block `Enforce` would have held
    /// unexecuted or every pull it would have ended.
    Observe,
    /// Execute only authenticated blocks, in order; hold the unanchored tail.
    Enforce,
}

impl SyncAnchorMode {
    /// Reads a value of [`SYNC_ANCHOR_ENV`]: unset or empty is `Enforce`;
    /// `None` for a value that names no mode.
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            None | Some("" | "enforce" | "on" | "1" | "true") => Some(Self::Enforce),
            Some("observe" | "log") => Some(Self::Observe),
            Some("off" | "0" | "false") => Some(Self::Off),
            Some(_) => None,
        }
    }

    /// The mode the environment selects. A value that names no mode is
    /// refused loudly and the default (`Enforce`) kept: a typo must not turn
    /// the rule off.
    pub fn from_env() -> Self {
        let raw = std::env::var(SYNC_ANCHOR_ENV).ok();
        Self::parse(raw.as_deref()).unwrap_or_else(|| {
            tracing::warn!(
                target: "n42.h2.node",
                value = ?raw,
                "{SYNC_ANCHOR_ENV} names no mode (enforce|observe|off); enforcing"
            );
            Self::Enforce
        })
    }
}

/// One block in an [`AnchorBuffer`].
#[derive(Debug)]
pub(crate) struct Buffered<T> {
    pub(crate) number: u64,
    pub(crate) hash: B256,
    /// What the block counts against [`MAX_TAIL_BYTES`].
    pub(crate) bytes: usize,
    pub(crate) item: T,
}

/// Pulled blocks waiting for authentication, in ascending order, contiguous
/// and parent-linked (the caller screens every block before it pushes it).
pub(crate) struct AnchorBuffer<T> {
    blocks: VecDeque<Buffered<T>>,
    bytes: usize,
    /// The highest buffered (or already released) number an anchor covers.
    authenticated_to: Option<u64>,
    /// Anchored hashes whose block is not in the buffer (yet).
    pending: VecDeque<B256>,
}

impl<T> Default for AnchorBuffer<T> {
    fn default() -> Self {
        Self { blocks: VecDeque::new(), bytes: 0, authenticated_to: None, pending: VecDeque::new() }
    }
}

impl<T> std::fmt::Debug for AnchorBuffer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorBuffer")
            .field("from", &self.blocks.front().map(|b| b.number))
            .field("to", &self.blocks.back().map(|b| b.number))
            .field("bytes", &self.bytes)
            .field("authenticated_to", &self.authenticated_to)
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl<T> AnchorBuffer<T> {
    /// Records a verified anchor. A buffered block it names authenticates
    /// itself and every buffered block below it: its number is returned. An
    /// anchor naming a block not buffered is kept for the block's arrival.
    pub(crate) fn anchor(&mut self, hash: B256) -> Option<u64> {
        if let Some(number) = self.blocks.iter().find(|b| b.hash == hash).map(|b| b.number) {
            self.authenticated_to = Some(self.authenticated_to.map_or(number, |to| to.max(number)));
            return Some(number);
        }
        if !self.pending.contains(&hash) {
            if self.pending.len() >= MAX_PENDING_ANCHORS {
                self.pending.pop_front();
            }
            self.pending.push_back(hash);
        }
        None
    }

    /// Buffers a screened block on top. Whether an anchor recorded before
    /// it arrived names it.
    pub(crate) fn push(&mut self, block: Buffered<T>) -> bool {
        let anchored = if let Some(at) = self.pending.iter().position(|h| *h == block.hash) {
            self.pending.remove(at);
            self.authenticated_to = Some(self.authenticated_to.map_or(block.number, |to| to.max(block.number)));
            true
        } else {
            false
        };
        self.bytes += block.bytes;
        self.blocks.push_back(block);
        anchored
    }

    /// The lowest buffered block, when an anchor covers it.
    pub(crate) fn pop_ready(&mut self) -> Option<Buffered<T>> {
        let to = self.authenticated_to?;
        if self.blocks.front()?.number > to {
            return None;
        }
        let block = self.blocks.pop_front()?;
        self.bytes -= block.bytes;
        Some(block)
    }

    /// The unanchored tail: blocks and bytes above the highest anchor.
    pub(crate) fn tail(&self) -> (usize, usize) {
        let to = self.authenticated_to;
        self.blocks
            .iter()
            .filter(|b| to.is_none_or(|to| b.number > to))
            .fold((0, 0), |(n, bytes), b| (n + 1, bytes + b.bytes))
    }

    /// Whether the unanchored tail is past [`MAX_TAIL_BLOCKS`] or
    /// [`MAX_TAIL_BYTES`].
    pub(crate) fn tail_over_bound(&self) -> bool {
        let (blocks, bytes) = self.tail();
        blocks > MAX_TAIL_BLOCKS || bytes > MAX_TAIL_BYTES
    }

    /// The highest buffered block no anchor covers, `(number, hash)`: what a
    /// `commit_qc/1` request asks to have certified.
    pub(crate) fn unanchored_top(&self) -> Option<(u64, B256)> {
        let top = self.blocks.back()?;
        self.authenticated_to.is_none_or(|to| top.number > to).then_some((top.number, top.hash))
    }

    /// The highest number an anchor covers, buffered or released.
    pub(crate) const fn authenticated_to(&self) -> Option<u64> {
        self.authenticated_to
    }

    /// Blocks buffered.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Drops every buffered block: how many there were.
    pub(crate) fn clear(&mut self) -> usize {
        let dropped = self.blocks.len();
        self.blocks.clear();
        self.bytes = 0;
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(number: u64) -> Buffered<()> {
        Buffered { number, hash: B256::with_last_byte(number as u8), bytes: 10, item: () }
    }

    #[test]
    fn the_mode_defaults_to_enforce_and_a_typo_is_not_off() {
        assert_eq!(SyncAnchorMode::parse(None), Some(SyncAnchorMode::Enforce));
        assert_eq!(SyncAnchorMode::parse(Some("")), Some(SyncAnchorMode::Enforce));
        assert_eq!(SyncAnchorMode::parse(Some(" Observe ")), Some(SyncAnchorMode::Observe));
        assert_eq!(SyncAnchorMode::parse(Some("off")), Some(SyncAnchorMode::Off));
        assert_eq!(SyncAnchorMode::parse(Some("enforce")), Some(SyncAnchorMode::Enforce));
        assert_eq!(SyncAnchorMode::parse(Some("of")), None);
    }

    #[test]
    fn an_anchor_releases_its_block_and_everything_below_it_in_order() {
        let mut buffer = AnchorBuffer::default();
        for n in 1..=4 {
            assert!(!buffer.push(block(n)));
        }
        assert!(buffer.pop_ready().is_none(), "nothing anchored");
        assert_eq!(buffer.tail(), (4, 40));
        assert_eq!(buffer.anchor(B256::with_last_byte(2)), Some(2));
        assert_eq!(buffer.pop_ready().map(|b| b.number), Some(1));
        assert_eq!(buffer.pop_ready().map(|b| b.number), Some(2));
        assert!(buffer.pop_ready().is_none(), "3 and 4 are the tail");
        assert_eq!(buffer.tail(), (2, 20));
        // An older anchor does not move the mark back.
        buffer.anchor(B256::with_last_byte(1));
        assert_eq!(buffer.authenticated_to(), Some(2));
    }

    #[test]
    fn an_anchor_for_a_block_not_yet_pulled_authenticates_it_on_arrival() {
        let mut buffer = AnchorBuffer::default();
        assert!(!buffer.push(block(1)));
        assert_eq!(buffer.anchor(B256::with_last_byte(2)), None);
        assert!(buffer.push(block(2)), "the anchor waited for it");
        assert_eq!(buffer.pop_ready().map(|b| b.number), Some(1));
        assert_eq!(buffer.pop_ready().map(|b| b.number), Some(2));
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn the_tail_is_bounded_by_blocks_and_by_bytes() {
        let mut buffer = AnchorBuffer::default();
        for n in 1..=MAX_TAIL_BLOCKS as u64 {
            buffer.push(block(n));
        }
        assert!(!buffer.tail_over_bound());
        buffer.push(block(MAX_TAIL_BLOCKS as u64 + 1));
        assert!(buffer.tail_over_bound());
        assert_eq!(buffer.clear(), MAX_TAIL_BLOCKS + 1);
        assert_eq!(buffer.tail(), (0, 0));

        buffer.push(Buffered { number: 1, hash: B256::with_last_byte(1), bytes: MAX_TAIL_BYTES + 1, item: () });
        assert!(buffer.tail_over_bound(), "one block past the byte bound");
        buffer.anchor(B256::with_last_byte(1));
        assert!(!buffer.tail_over_bound(), "anchored, it is not tail");
    }
}
