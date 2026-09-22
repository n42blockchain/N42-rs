// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The highest block number this node has seen committed.
//!
//! One number, written by the node's canonical-state subscriber and read by
//! the payload builder, so a build can tell whether the height it is
//! building was decided while it was being set up.
//!
//! That happens once or twice a leg at a tenure handover: reth's payload
//! service starts a job for a height, consensus commits somebody else's
//! block at it, and the build then runs on a parent the chain has moved
//! past. Its candidates are the queue's, and the queue was pruned by the
//! blocks that parent does not have, so every lane looks gapped and the
//! block comes out empty (loop210: `par_txs=0 par_groups=384
//! par_skipped=163000 gas=0`, once or twice a leg, its payload never
//! proposed). Nothing about that says the node is starving, and the lines
//! that would otherwise say so now say `superseded` instead.

use std::sync::atomic::{AtomicU64, Ordering};

static HEAD: AtomicU64 = AtomicU64::new(0);

/// Records a block the chain has committed. Only the highest is kept.
pub fn saw(number: u64) {
    HEAD.fetch_max(number, Ordering::Relaxed);
}

/// The highest committed block number seen, 0 before the first.
pub fn number() -> u64 {
    HEAD.load(Ordering::Relaxed)
}

/// Whether a block at `number` was already decided by the chain: the
/// payload a build is making for that height is for a height somebody has
/// committed, so nothing will ask for it.
pub fn already_decided(number: u64) -> bool {
    number <= HEAD.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_head_only_rises_and_says_what_is_decided() {
        saw(10);
        saw(4);
        assert_eq!(number(), 10);
        assert!(already_decided(10));
        assert!(already_decided(3));
        assert!(!already_decided(11));
    }
}
