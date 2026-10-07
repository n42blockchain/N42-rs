// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deferred execution at depth `D` (`docs/DEFERRED_DEPTH_2_DESIGN.md`
//! section 1): which block's execution result a header carries, and the vote
//! rule over it.
//!
//! Let `result(B)` be what executing block `B` on its parent's post-state
//! produces (state root, receipts root, logs bloom, gas used). Under deferred
//! execution the header of block `N >= 1` carries `result(A_D(N))`, where
//! `A_D(N)` is the ancestor of `N` at distance `D` **on N's own chain, by
//! hash** (`A_1` = the parent, `A_2` = the parent's parent), and `A_D(N)` is
//! genesis whenever `N <= D`. `result(genesis)` is the genesis header's own
//! four fields.
//!
//! | block | D = 1 | D = 2 |
//! | --- | --- | --- |
//! | 1 | `result(0)` | `result(0)` |
//! | 2 | `result(1)` | `result(0)` |
//! | 3 | `result(2)` | `result(1)` |
//! | N | `result(N-1)` | `result(N-2)` |
//!
//! Blocks `1..=D` all carry the genesis result, so the expected fields of a
//! block whose parent is numbered below `D` are the parent's own header
//! fields (genesis carries itself; blocks `1..D` carry genesis's): no lookup.
//! Every later block's expected fields are this node's recorded result under
//! the ancestor's hash. There is no canonical lookup and no number arithmetic:
//! a block built on a sibling chain carries that chain's ancestor's result.
//!
//! Nothing here reads reth types; the execution layer
//! (`n42-engine-types`' `HotStuffConsensus`) supplies the lookups.

use alloy_primitives::B256;

/// The deepest depth the rule is defined for: the grandparent needs only the
/// parent header's `parent_hash`; a third level would need parent links in
/// the result registry.
pub const MAX_DEPTH: u64 = 2;

/// What the rule needs to know about a block's parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentLink {
    /// The parent's number.
    pub number: u64,
    /// The parent's hash.
    pub hash: B256,
    /// The parent's own parent hash (its header's `parent_hash`).
    pub parent_hash: B256,
}

/// Where the expected execution fields of a child of a given parent come
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultSource {
    /// The parent header's own four fields: the child is at most `D` blocks
    /// from genesis, so it carries the genesis result, which the parent's
    /// header carries too (it *is* genesis, or it is one of blocks `1..D`).
    ParentHeader,
    /// This node's recorded result for the block with this hash.
    Recorded(B256),
}

/// A depth the rule is not defined for (0, or above [`MAX_DEPTH`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("deferred execution depth {0} is not defined (1..={MAX_DEPTH})")]
pub struct UnsupportedDepth(pub u64);

/// The hash of the ancestor whose result a child of `parent` carries at
/// `depth`, on the child's own chain.
pub const fn ancestor_hash(parent: &ParentLink, depth: u64) -> Result<B256, UnsupportedDepth> {
    match depth {
        1 => Ok(parent.hash),
        2 => Ok(parent.parent_hash),
        other => Err(UnsupportedDepth(other)),
    }
}

/// Where the expected fields of a child of `parent` come from at `depth`.
pub const fn result_source(parent: &ParentLink, depth: u64) -> Result<ResultSource, UnsupportedDepth> {
    let hash = match ancestor_hash(parent, depth) {
        Ok(hash) => hash,
        Err(err) => return Err(err),
    };
    // The child is `parent.number + 1`; it carries the genesis result when
    // that is at most `depth`, i.e. when the parent is numbered below it.
    if parent.number < depth {
        Ok(ResultSource::ParentHeader)
    } else {
        Ok(ResultSource::Recorded(hash))
    }
}

/// The number of the block whose result a block numbered `number` carries
/// at `depth`: `number - depth`, floored at genesis. For logs and tests;
/// the rule itself goes by hash.
pub const fn carried_number(number: u64, depth: u64) -> u64 {
    number.saturating_sub(depth)
}

/// The block a commit of block `number` certifies at `depth`: its result is
/// in that block's header, and the quorum on that block checked it. `None`
/// when that would be below block 1 (genesis is certified by definition).
/// Depth 0 means the commit is of a block before deferred execution, whose
/// votes were import-gated: it certifies itself.
pub const fn certified_number(number: u64, depth: u64) -> Option<u64> {
    if depth == 0 {
        return Some(number);
    }
    match number.checked_sub(depth) {
        Some(0) | None => None,
        Some(certified) => Some(certified),
    }
}

/// Why a header fails the vote rule's comparison.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CarriedError<F: core::fmt::Debug> {
    /// The rule is not defined at this depth.
    #[error(transparent)]
    Depth(#[from] UnsupportedDepth),
    /// This node holds no result for the ancestor.
    #[error("deferred execution: the result of {0} is not known here")]
    AncestorUnknown(B256),
    /// The header's fields are not this node's result for the ancestor.
    #[error("deferred execution: header carries {got:?} for {ancestor}, this node executed {expected:?}")]
    Mismatch {
        /// The ancestor (the parent header's hash when the source is the
        /// parent header).
        ancestor: B256,
        /// What the header carries.
        got: F,
        /// What this node holds.
        expected: F,
    },
}

/// The fields a child of `parent` must carry at `depth`: the parent
/// header's own (`parent_fields`) at the chain start, else `recorded(ancestor)`.
pub fn expected_fields<F: Copy + core::fmt::Debug>(
    parent: &ParentLink,
    depth: u64,
    parent_fields: F,
    recorded: impl FnOnce(&B256) -> Option<F>,
) -> Result<F, CarriedError<F>> {
    match result_source(parent, depth)? {
        ResultSource::ParentHeader => Ok(parent_fields),
        ResultSource::Recorded(hash) => recorded(&hash).ok_or(CarriedError::AncestorUnknown(hash)),
    }
}

/// The vote rule's comparison (design section 1.4, item 3): the header's four
/// fields equal this node's result for the depth-`D` ancestor. Items 1, 2 and
/// 4 (the proposal, the body, includability on the *parent's* output) are
/// checked elsewhere and do not depend on the depth.
pub fn check_carried<F: Copy + PartialEq + core::fmt::Debug>(
    got: F,
    parent: &ParentLink,
    depth: u64,
    parent_fields: F,
    recorded: impl FnOnce(&B256) -> Option<F>,
) -> Result<(), CarriedError<F>> {
    let expected = expected_fields(parent, depth, parent_fields, recorded)?;
    if got == expected {
        return Ok(());
    }
    let ancestor = match result_source(parent, depth)? {
        ResultSource::ParentHeader => parent.hash,
        ResultSource::Recorded(hash) => hash,
    };
    Err(CarriedError::Mismatch { ancestor, got, expected })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A block of a test chain: its hash, parent hash, number, its own
    /// result, and the fields its header carries.
    #[derive(Debug, Clone, Copy)]
    struct Block {
        hash: B256,
        parent: B256,
        number: u64,
        own: u64,
        carried: u64,
    }

    impl Block {
        const fn link(&self) -> ParentLink {
            ParentLink { number: self.number, hash: self.hash, parent_hash: self.parent }
        }
    }

    fn h(tag: u8, n: u64) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        B256::from(bytes)
    }

    /// Builds `len` blocks on `base` at `depth`, each result distinct
    /// (`tag * 1000 + number`), the carried fields by the rule, the recorded
    /// results in `registry`.
    fn extend(chain: &mut Vec<Block>, tag: u8, len: u64, depth: u64, registry: &mut HashMap<B256, u64>) {
        for _ in 0..len {
            let parent = *chain.last().expect("a base");
            let number = parent.number + 1;
            let carried = expected_fields(&parent.link(), depth, parent.carried, |hash| registry.get(hash).copied())
                .expect("the ancestor's result is recorded");
            let block = Block { hash: h(tag, number), parent: parent.hash, number, own: u64::from(tag) * 1000 + number, carried };
            registry.insert(block.hash, block.own);
            chain.push(block);
        }
    }

    fn genesis(registry: &mut HashMap<B256, u64>) -> Vec<Block> {
        let genesis = Block { hash: h(0, 0), parent: B256::ZERO, number: 0, own: 7, carried: 7 };
        registry.insert(genesis.hash, genesis.own);
        vec![genesis]
    }

    #[test]
    fn the_table_of_section_one() {
        for depth in 1..=MAX_DEPTH {
            let mut registry = HashMap::new();
            let mut chain = genesis(&mut registry);
            extend(&mut chain, 1, 8, depth, &mut registry);
            for block in &chain[1..] {
                // Blocks 1..=D carry the genesis result; every later one the
                // result of the block D behind it.
                let source = chain[carried_number(block.number, depth) as usize];
                assert_eq!(block.carried, source.own, "block {} at depth {depth}", block.number);
                if block.number <= depth {
                    assert_eq!(block.carried, chain[0].own);
                }
            }
            // Every result after genesis appears in exactly one header.
            for block in &chain[1..chain.len() - depth as usize] {
                let carriers = chain.iter().filter(|b| b.number > 0 && b.carried == block.own).count();
                assert_eq!(carriers, 1, "result({}) at depth {depth}", block.number);
            }
        }
    }

    #[test]
    fn the_chain_start_needs_no_lookup() {
        let link = |number: u64| ParentLink { number, hash: h(9, number), parent_hash: h(9, number.wrapping_sub(1)) };
        // D=1: only genesis as the parent; D=2: genesis and block 1.
        assert_eq!(result_source(&link(0), 1), Ok(ResultSource::ParentHeader));
        assert_eq!(result_source(&link(1), 1), Ok(ResultSource::Recorded(h(9, 1))));
        assert_eq!(result_source(&link(0), 2), Ok(ResultSource::ParentHeader));
        assert_eq!(result_source(&link(1), 2), Ok(ResultSource::ParentHeader));
        assert_eq!(result_source(&link(2), 2), Ok(ResultSource::Recorded(h(9, 1))));
        // Nothing recorded at all: the start still checks.
        let none = |_: &B256| None::<u64>;
        assert_eq!(check_carried(5, &link(1), 2, 5, none), Ok(()));
        assert_eq!(check_carried(5, &link(2), 2, 5, none), Err(CarriedError::AncestorUnknown(h(9, 1))));
    }

    #[test]
    fn a_depth_outside_the_rule_is_refused() {
        let link = ParentLink { number: 5, hash: h(1, 5), parent_hash: h(1, 4) };
        for depth in [0, 3, 64] {
            assert_eq!(result_source(&link, depth), Err(UnsupportedDepth(depth)));
            assert_eq!(check_carried(1u64, &link, depth, 1, |_| Some(1)), Err(CarriedError::Depth(UnsupportedDepth(depth))));
        }
    }

    /// The vote rule at depth 2 accepts the grandparent's result and refuses
    /// the parent's (the depth-1 value) and the great-grandparent's; at depth
    /// 1 the same headers are judged the other way. Both in one test is the
    /// mixed-fleet refusal: a depth-1 member never accepts a depth-2 header
    /// once results differ.
    #[test]
    fn each_depth_refuses_the_others_header() {
        let mut registry = HashMap::new();
        let mut chain = genesis(&mut registry);
        extend(&mut chain, 1, 6, 2, &mut registry);
        let recorded = |hash: &B256| registry.get(hash).copied();
        let n = chain[5];
        let parent = chain[4];
        for (got, d2, d1) in [
            (chain[3].own, true, false), // result(N-2)
            (chain[4].own, false, true), // result(N-1)
            (chain[2].own, false, false), // result(N-3)
        ] {
            assert_eq!(check_carried(got, &parent.link(), 2, parent.carried, recorded).is_ok(), d2);
            assert_eq!(check_carried(got, &parent.link(), 1, parent.carried, recorded).is_ok(), d1);
        }
        assert_eq!(n.carried, chain[3].own);
        match check_carried(chain[4].own, &parent.link(), 2, parent.carried, recorded) {
            Err(CarriedError::Mismatch { ancestor, got, expected }) => {
                assert_eq!((ancestor, got, expected), (chain[3].hash, chain[4].own, chain[3].own));
            }
            other => panic!("expected a mismatch naming the grandparent, got {other:?}"),
        }
    }

    /// N-1 dropped by a view change: block 4 and its sibling 4' both build on
    /// 3 and both carry result(2); 5 on 4 and 5' on 4' both carry result(3)
    /// (equal fields, different parents); 6 on 5' carries result(4'), never
    /// result(4). The result is of N's own chain's grandparent, by hash.
    #[test]
    fn a_sibling_fork_carries_its_own_chains_grandparent() {
        let mut registry = HashMap::new();
        let mut chain = genesis(&mut registry);
        extend(&mut chain, 1, 5, 2, &mut registry); // 0..=5 on branch 1
        let mut sibling = chain[..4].to_vec(); // 0..=3
        extend(&mut sibling, 2, 3, 2, &mut registry); // 4', 5', 6' on branch 2
        let (four, five) = (chain[4], chain[5]);
        let (four_s, five_s, six_s) = (sibling[4], sibling[5], sibling[6]);
        assert_ne!(four.hash, four_s.hash);
        assert_ne!(four.own, four_s.own, "the siblings executed different bodies");
        assert_eq!(four.carried, chain[2].own);
        assert_eq!(four_s.carried, chain[2].own, "4 and 4' carry result(2)");
        assert_eq!(five.carried, chain[3].own);
        assert_eq!(five_s.carried, chain[3].own, "5 and 5' carry result(3)");
        assert_ne!(five.parent, five_s.parent, "with different parents");
        assert_eq!(six_s.carried, four_s.own, "6 on 5' carries result(4')");
        assert_ne!(six_s.carried, four.own);
        // A follower that executed both branches judges each by its own chain.
        let recorded = |hash: &B256| registry.get(hash).copied();
        assert!(check_carried(six_s.carried, &five_s.link(), 2, five_s.carried, recorded).is_ok());
        assert!(check_carried(four.own, &five_s.link(), 2, five_s.carried, recorded).is_err());
        let six_on_five = expected_fields(&five.link(), 2, five.carried, recorded).expect("recorded");
        assert_eq!(six_on_five, four.own, "a child of 5 would carry result(4)");
    }

    #[test]
    fn a_commit_certifies_the_block_depth_behind_it() {
        assert_eq!(certified_number(8, 0), Some(8));
        assert_eq!(certified_number(8, 1), Some(7));
        assert_eq!(certified_number(8, 2), Some(6));
        // Blocks 1..=D carry the genesis result: their commits certify
        // nothing beyond genesis.
        assert_eq!(certified_number(1, 1), None);
        assert_eq!(certified_number(2, 1), Some(1));
        assert_eq!(certified_number(1, 2), None);
        assert_eq!(certified_number(2, 2), None);
        assert_eq!(certified_number(3, 2), Some(1));
        assert_eq!(carried_number(1, 2), 0);
        assert_eq!(carried_number(7, 2), 5);
    }
}
