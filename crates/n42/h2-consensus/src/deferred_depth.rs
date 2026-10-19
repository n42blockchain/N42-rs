// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deferred execution at depth `D` (`docs/DEFERRED_DEPTH_2_DESIGN.md`
//! section 1, `docs/DEPTH3_DESIGN.md`): which block's execution result a
//! header carries, and the vote rule over it.
//!
//! Let `result(B)` be what executing block `B` on its parent's post-state
//! produces (state root, receipts root, logs bloom, gas used). Under deferred
//! execution the header of block `N >= 1` carries `result(A_D(N))`, where
//! `A_D(N)` is the ancestor of `N` at distance `D` **on N's own chain, by
//! hash** (`A_1` = the parent, `A_2` = the parent's parent, `A_3` = the
//! parent's parent's parent), and `A_D(N)` is genesis whenever `N <= D`.
//! `result(genesis)` is the genesis header's own four fields.
//!
//! | block | D = 1 | D = 2 | D = 3 |
//! | --- | --- | --- | --- |
//! | 1 | `result(0)` | `result(0)` | `result(0)` |
//! | 2 | `result(1)` | `result(0)` | `result(0)` |
//! | 3 | `result(2)` | `result(1)` | `result(0)` |
//! | 4 | `result(3)` | `result(2)` | `result(1)` |
//! | N | `result(N-1)` | `result(N-2)` | `result(N-3)` |
//!
//! Blocks `1..=D` all carry the genesis result, so the expected fields of a
//! block whose parent is numbered below `D` are the parent's own header
//! fields (genesis carries itself; blocks `1..D` carry genesis's): no lookup.
//! Every later block's expected fields are this node's recorded result under
//! the ancestor's hash. There is no canonical lookup and no number arithmetic:
//! a block built on a sibling chain carries that chain's ancestor's result.
//!
//! The parent header names the parent and the grandparent; at depth 3 the
//! great-grandparent is named by no header in hand, so it is found through a
//! *lineage*: a lookup from a block hash to that block's parent hash, which
//! the caller supplies (the executed-fields registry's parent links). A
//! lineage miss is an error ([`AncestorError::LineageUnknown`]), never a
//! fallback to a nearer ancestor. Depths 1 and 2 never consult it.
//!
//! Nothing here reads reth types; the execution layer
//! (`n42-engine-types`' `HotStuffConsensus`) supplies the lookups.

use alloy_primitives::B256;

/// The deepest depth the rule is defined for. Depth 1 and 2 need only the
/// parent header; depth 3 needs one step of lineage beyond it.
pub const MAX_DEPTH: u64 = 3;

/// The environment variable that opts a process in to *run* depth 3
/// (`N42_DEFERRED_DEPTH3=1`, `docs/DEPTH3_DESIGN.md` section 4); the same
/// variable `reth_chainspec::qmdb` reads for the start-up check. The rule is
/// defined to [`MAX_DEPTH`] either way; this gates the wiring and the
/// capacities sized for depth 3.
pub const DEPTH3_ENV: &str = "N42_DEFERRED_DEPTH3";

/// Whether a value of [`DEPTH3_ENV`] opts in: exactly `1`.
pub fn depth3_opted_in_from(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim() == "1")
}

/// [`DEPTH3_ENV`], read once.
pub fn depth3_opted_in() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| depth3_opted_in_from(std::env::var(DEPTH3_ENV).ok().as_deref()))
}

/// The deepest depth this process runs: [`MAX_DEPTH`] with [`DEPTH3_ENV`],
/// else 2.
pub fn run_max_depth() -> u64 {
    if depth3_opted_in() { MAX_DEPTH } else { 2 }
}

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

/// Why the ancestor a child of a parent carries cannot be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AncestorError {
    /// The rule is not defined at this depth.
    #[error(transparent)]
    Depth(#[from] UnsupportedDepth),
    /// The lineage holds no parent for this block hash, so the ancestor
    /// beyond it cannot be named here.
    #[error("deferred execution: the parent of {0} is not known here")]
    LineageUnknown(B256),
}

/// A lineage that knows no parent: what a caller passes at depth 1 or 2,
/// where the rule never consults it.
pub const fn no_lineage(_: &B256) -> Option<B256> {
    None
}

/// Whether the rule is defined at `depth`.
pub const fn check_depth(depth: u64) -> Result<(), UnsupportedDepth> {
    if depth >= 1 && depth <= MAX_DEPTH {
        Ok(())
    } else {
        Err(UnsupportedDepth(depth))
    }
}

/// The hash of the ancestor whose result a child of `parent` carries at
/// `depth`, on the child's own chain: the parent at depth 1, its parent at
/// depth 2 (both from the parent link alone), and from depth 3 on the
/// lineage walked from the grandparent, one step per further level.
///
/// The hash is named whether or not the child is near enough to genesis to
/// carry the genesis result ([`carries_genesis`]); callers that only need
/// the expected fields go through [`result_source`], which asks the lineage
/// nothing at the chain start.
pub fn ancestor_hash(
    parent: &ParentLink,
    depth: u64,
    mut lineage: impl FnMut(&B256) -> Option<B256>,
) -> Result<B256, AncestorError> {
    check_depth(depth)?;
    if depth == 1 {
        return Ok(parent.hash);
    }
    let mut hash = parent.parent_hash;
    for _ in 2..depth {
        hash = lineage(&hash).ok_or(AncestorError::LineageUnknown(hash))?;
    }
    Ok(hash)
}

/// Whether a child of `parent` carries the genesis result at `depth` (the
/// child is numbered at most `depth`, i.e. the parent below it), in which
/// case its expected fields are the parent header's own.
pub const fn carries_genesis(parent: &ParentLink, depth: u64) -> Result<bool, UnsupportedDepth> {
    match check_depth(depth) {
        Ok(()) => Ok(parent.number < depth),
        Err(err) => Err(err),
    }
}

/// Where the expected fields of a child of `parent` come from at `depth`.
/// The lineage is consulted only past the chain start and only at depth 3.
pub fn result_source(
    parent: &ParentLink,
    depth: u64,
    lineage: impl FnMut(&B256) -> Option<B256>,
) -> Result<ResultSource, AncestorError> {
    if carries_genesis(parent, depth)? {
        return Ok(ResultSource::ParentHeader);
    }
    Ok(ResultSource::Recorded(ancestor_hash(parent, depth, lineage)?))
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
    /// The lineage holds no parent for this hash: the ancestor cannot be
    /// named (depth 3 and above).
    #[error("deferred execution: the parent of {0} is not known here")]
    LineageUnknown(B256),
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

impl<F: core::fmt::Debug> From<AncestorError> for CarriedError<F> {
    fn from(err: AncestorError) -> Self {
        match err {
            AncestorError::Depth(depth) => Self::Depth(depth),
            AncestorError::LineageUnknown(hash) => Self::LineageUnknown(hash),
        }
    }
}

/// The fields a child of `parent` must carry at `depth`, with the source
/// they came from: the parent header's own (`parent_fields`) at the chain
/// start, else `recorded(ancestor)`.
fn expected_with_source<F: Copy + core::fmt::Debug>(
    parent: &ParentLink,
    depth: u64,
    parent_fields: F,
    lineage: impl FnMut(&B256) -> Option<B256>,
    recorded: impl FnOnce(&B256) -> Option<F>,
) -> Result<(F, ResultSource), CarriedError<F>> {
    match result_source(parent, depth, lineage)? {
        ResultSource::ParentHeader => Ok((parent_fields, ResultSource::ParentHeader)),
        ResultSource::Recorded(hash) => recorded(&hash)
            .map(|fields| (fields, ResultSource::Recorded(hash)))
            .ok_or(CarriedError::AncestorUnknown(hash)),
    }
}

/// The fields a child of `parent` must carry at `depth`: the parent
/// header's own (`parent_fields`) at the chain start, else
/// `recorded(ancestor)`, the ancestor named through `lineage` at depth 3.
pub fn expected_fields<F: Copy + core::fmt::Debug>(
    parent: &ParentLink,
    depth: u64,
    parent_fields: F,
    lineage: impl FnMut(&B256) -> Option<B256>,
    recorded: impl FnOnce(&B256) -> Option<F>,
) -> Result<F, CarriedError<F>> {
    expected_with_source(parent, depth, parent_fields, lineage, recorded).map(|(fields, _)| fields)
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
    lineage: impl FnMut(&B256) -> Option<B256>,
    recorded: impl FnOnce(&B256) -> Option<F>,
) -> Result<(), CarriedError<F>> {
    let (expected, source) = expected_with_source(parent, depth, parent_fields, lineage, recorded)?;
    if got == expected {
        return Ok(());
    }
    let ancestor = match source {
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

    /// What a node records: each block's result, and each block's parent
    /// (the lineage depth 3 walks).
    #[derive(Debug, Default)]
    struct Registry {
        results: HashMap<B256, u64>,
        parents: HashMap<B256, B256>,
    }

    impl Registry {
        fn record(&mut self, block: &Block) {
            self.results.insert(block.hash, block.own);
            self.parents.insert(block.hash, block.parent);
        }

        fn result(&self, hash: &B256) -> Option<u64> {
            self.results.get(hash).copied()
        }

        fn parent(&self, hash: &B256) -> Option<B256> {
            self.parents.get(hash).copied()
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
    /// results and parent links in `registry`.
    fn extend(chain: &mut Vec<Block>, tag: u8, len: u64, depth: u64, registry: &mut Registry) {
        for _ in 0..len {
            let parent = *chain.last().expect("a base");
            let number = parent.number + 1;
            let carried = expected_fields(&parent.link(), depth, parent.carried, |hash| registry.parent(hash), |hash| registry.result(hash))
                .expect("the ancestor's result is recorded");
            let block = Block { hash: h(tag, number), parent: parent.hash, number, own: u64::from(tag) * 1000 + number, carried };
            registry.record(&block);
            chain.push(block);
        }
    }

    fn genesis(registry: &mut Registry) -> Vec<Block> {
        let genesis = Block { hash: h(0, 0), parent: B256::ZERO, number: 0, own: 7, carried: 7 };
        registry.results.insert(genesis.hash, genesis.own);
        vec![genesis]
    }

    #[test]
    fn the_table_of_section_one() {
        for depth in 1..=MAX_DEPTH {
            let mut registry = Registry::default();
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

    /// Depths 1 and 2 name their ancestor from the parent link alone: the
    /// lineage is never asked, so a caller passing [`no_lineage`] behaves as
    /// before the lineage existed.
    #[test]
    fn depths_one_and_two_never_ask_the_lineage() {
        let link = ParentLink { number: 5, hash: h(1, 5), parent_hash: h(1, 4) };
        let asked = |_: &B256| -> Option<B256> { panic!("depth 1 and 2 never walk the lineage") };
        assert_eq!(ancestor_hash(&link, 1, asked), Ok(h(1, 5)));
        assert_eq!(ancestor_hash(&link, 2, asked), Ok(h(1, 4)));
        assert_eq!(result_source(&link, 1, asked), Ok(ResultSource::Recorded(h(1, 5))));
        assert_eq!(result_source(&link, 2, asked), Ok(ResultSource::Recorded(h(1, 4))));
        assert_eq!(ancestor_hash(&link, 2, no_lineage), Ok(h(1, 4)));
    }

    /// A five-block lineage (genesis, 1..=4) and a child of block 4: the
    /// ancestor at depth 1, 2 and 3 is block 4, 3 and 2; the expected fields
    /// are those blocks' results; and with the one link depth 3 walks
    /// missing, depth 3 is an error naming it while depths 1 and 2 still
    /// answer.
    #[test]
    fn the_depth_three_ancestor_on_a_five_block_lineage() {
        let mut registry = Registry::default();
        let mut chain = genesis(&mut registry);
        extend(&mut chain, 1, 4, 3, &mut registry);
        let parent = chain[4].link();
        for (depth, ancestor) in [(1u64, 4usize), (2, 3), (3, 2)] {
            assert_eq!(ancestor_hash(&parent, depth, |hash| registry.parent(hash)), Ok(chain[ancestor].hash), "depth {depth}");
            assert_eq!(
                expected_fields(&parent, depth, chain[4].carried, |hash| registry.parent(hash), |hash| registry.result(hash)),
                Ok(chain[ancestor].own),
                "depth {depth}"
            );
        }
        // The headers themselves: block 4 carries result(1), 3 the genesis's.
        assert_eq!(chain[4].carried, chain[1].own);
        assert_eq!(chain[3].carried, chain[0].own);
        // Without the grandparent's parent link depth 3 cannot name block 2.
        registry.parents.remove(&chain[3].hash);
        assert_eq!(ancestor_hash(&parent, 3, |hash| registry.parent(hash)), Err(AncestorError::LineageUnknown(chain[3].hash)));
        assert_eq!(
            check_carried(chain[2].own, &parent, 3, chain[4].carried, |hash| registry.parent(hash), |hash| registry.result(hash)),
            Err(CarriedError::LineageUnknown(chain[3].hash))
        );
        assert_eq!(ancestor_hash(&parent, 2, |hash| registry.parent(hash)), Ok(chain[3].hash));
        assert_eq!(ancestor_hash(&parent, 1, |hash| registry.parent(hash)), Ok(chain[4].hash));
        // A missing result (lineage present) is the ancestor unknown.
        registry.parents.insert(chain[3].hash, chain[2].hash);
        registry.results.remove(&chain[2].hash);
        assert_eq!(
            check_carried(chain[2].own, &parent, 3, chain[4].carried, |hash| registry.parent(hash), |hash| registry.result(hash)),
            Err(CarriedError::AncestorUnknown(chain[2].hash))
        );
    }

    #[test]
    fn the_chain_start_needs_no_lookup() {
        let link = |number: u64| ParentLink { number, hash: h(9, number), parent_hash: h(9, number.wrapping_sub(1)) };
        // D=1: only genesis as the parent; D=2: genesis and block 1; D=3:
        // genesis, 1 and 2 -- none of them asks the lineage.
        assert_eq!(result_source(&link(0), 1, no_lineage), Ok(ResultSource::ParentHeader));
        assert_eq!(result_source(&link(1), 1, no_lineage), Ok(ResultSource::Recorded(h(9, 1))));
        assert_eq!(result_source(&link(0), 2, no_lineage), Ok(ResultSource::ParentHeader));
        assert_eq!(result_source(&link(1), 2, no_lineage), Ok(ResultSource::ParentHeader));
        assert_eq!(result_source(&link(2), 2, no_lineage), Ok(ResultSource::Recorded(h(9, 1))));
        for number in 0..3 {
            assert_eq!(result_source(&link(number), 3, no_lineage), Ok(ResultSource::ParentHeader));
            assert_eq!(carries_genesis(&link(number), 3), Ok(true));
        }
        assert_eq!(carries_genesis(&link(3), 3), Ok(false));
        assert_eq!(result_source(&link(3), 3, no_lineage), Err(AncestorError::LineageUnknown(h(9, 2))));
        assert_eq!(result_source(&link(3), 3, |hash| (*hash == h(9, 2)).then(|| h(9, 1))), Ok(ResultSource::Recorded(h(9, 1))));
        // Nothing recorded at all: the start still checks.
        let none = |_: &B256| None::<u64>;
        assert_eq!(check_carried(5, &link(1), 2, 5, no_lineage, none), Ok(()));
        assert_eq!(check_carried(5, &link(2), 2, 5, no_lineage, none), Err(CarriedError::AncestorUnknown(h(9, 1))));
        assert_eq!(check_carried(5, &link(2), 3, 5, no_lineage, none), Ok(()));
    }

    #[test]
    fn a_depth_outside_the_rule_is_refused() {
        let link = ParentLink { number: 5, hash: h(1, 5), parent_hash: h(1, 4) };
        for depth in [0, MAX_DEPTH + 1, 64] {
            assert_eq!(check_depth(depth), Err(UnsupportedDepth(depth)));
            assert_eq!(result_source(&link, depth, |_| Some(B256::ZERO)), Err(AncestorError::Depth(UnsupportedDepth(depth))));
            assert_eq!(ancestor_hash(&link, depth, |_| Some(B256::ZERO)), Err(AncestorError::Depth(UnsupportedDepth(depth))));
            assert_eq!(carries_genesis(&link, depth), Err(UnsupportedDepth(depth)));
            assert_eq!(
                check_carried(1u64, &link, depth, 1, |_| Some(B256::ZERO), |_| Some(1)),
                Err(CarriedError::Depth(UnsupportedDepth(depth)))
            );
        }
        for depth in 1..=MAX_DEPTH {
            assert_eq!(check_depth(depth), Ok(()));
        }
    }

    /// The vote rule at depth 2 accepts the grandparent's result and refuses
    /// the parent's (the depth-1 value) and the great-grandparent's; at depth
    /// 1 the same headers are judged the other way, and at depth 3 only the
    /// great-grandparent's passes. All in one test is the mixed-fleet
    /// refusal: a member of one depth never accepts another depth's header
    /// once results differ.
    #[test]
    fn each_depth_refuses_the_others_header() {
        let mut registry = Registry::default();
        let mut chain = genesis(&mut registry);
        extend(&mut chain, 1, 6, 2, &mut registry);
        let lineage = |hash: &B256| registry.parent(hash);
        let recorded = |hash: &B256| registry.result(hash);
        let n = chain[5];
        let parent = chain[4];
        for (got, d3, d2, d1) in [
            (chain[3].own, false, true, false), // result(N-2)
            (chain[4].own, false, false, true), // result(N-1)
            (chain[2].own, true, false, false), // result(N-3)
        ] {
            assert_eq!(check_carried(got, &parent.link(), 3, parent.carried, lineage, recorded).is_ok(), d3);
            assert_eq!(check_carried(got, &parent.link(), 2, parent.carried, lineage, recorded).is_ok(), d2);
            assert_eq!(check_carried(got, &parent.link(), 1, parent.carried, lineage, recorded).is_ok(), d1);
        }
        assert_eq!(n.carried, chain[3].own);
        match check_carried(chain[4].own, &parent.link(), 2, parent.carried, lineage, recorded) {
            Err(CarriedError::Mismatch { ancestor, got, expected }) => {
                assert_eq!((ancestor, got, expected), (chain[3].hash, chain[4].own, chain[3].own));
            }
            other => panic!("expected a mismatch naming the grandparent, got {other:?}"),
        }
        // At depth 3 a header carrying the depth-2 value is refused, naming
        // the great-grandparent -- never silently judged as depth 2.
        match check_carried(chain[3].own, &parent.link(), 3, parent.carried, lineage, recorded) {
            Err(CarriedError::Mismatch { ancestor, got, expected }) => {
                assert_eq!((ancestor, got, expected), (chain[2].hash, chain[3].own, chain[2].own));
            }
            other => panic!("expected a mismatch naming the great-grandparent, got {other:?}"),
        }
    }

    /// N-1 dropped by a view change: block 4 and its sibling 4' both build on
    /// 3 and both carry result(2); 5 on 4 and 5' on 4' both carry result(3)
    /// (equal fields, different parents); 6 on 5' carries result(4'), never
    /// result(4). The result is of N's own chain's grandparent, by hash.
    #[test]
    fn a_sibling_fork_carries_its_own_chains_grandparent() {
        let mut registry = Registry::default();
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
        let recorded = |hash: &B256| registry.result(hash);
        assert!(check_carried(six_s.carried, &five_s.link(), 2, five_s.carried, no_lineage, recorded).is_ok());
        assert!(check_carried(four.own, &five_s.link(), 2, five_s.carried, no_lineage, recorded).is_err());
        let six_on_five = expected_fields(&five.link(), 2, five.carried, no_lineage, recorded).expect("recorded");
        assert_eq!(six_on_five, four.own, "a child of 5 would carry result(4)");
    }

    /// The same fork at depth 3: 3 is the last common block, so 5 and 5'
    /// carry result(2), 6 and 6' carry result(3), and 7' on 6' carries
    /// result(4') -- through the lineage of its own branch, never result(4).
    #[test]
    fn a_sibling_fork_at_depth_three_follows_its_own_lineage() {
        let mut registry = Registry::default();
        let mut chain = genesis(&mut registry);
        extend(&mut chain, 1, 6, 3, &mut registry); // 0..=6 on branch 1
        let mut sibling = chain[..4].to_vec(); // 0..=3
        extend(&mut sibling, 2, 4, 3, &mut registry); // 4'..=7' on branch 2
        assert_eq!(chain[5].carried, chain[2].own);
        assert_eq!(sibling[5].carried, chain[2].own, "5 and 5' carry result(2)");
        assert_eq!(chain[6].carried, chain[3].own);
        assert_eq!(sibling[6].carried, chain[3].own, "6 and 6' carry result(3)");
        assert_eq!(sibling[7].carried, sibling[4].own, "7' carries result(4')");
        let lineage = |hash: &B256| registry.parent(hash);
        let recorded = |hash: &B256| registry.result(hash);
        let six_s = sibling[6];
        assert!(check_carried(sibling[4].own, &six_s.link(), 3, six_s.carried, lineage, recorded).is_ok());
        assert!(check_carried(chain[4].own, &six_s.link(), 3, six_s.carried, lineage, recorded).is_err());
        let seven_on_six = expected_fields(&chain[6].link(), 3, chain[6].carried, lineage, recorded).expect("recorded");
        assert_eq!(seven_on_six, chain[4].own, "a child of 6 would carry result(4)");
    }

    #[test]
    fn a_commit_certifies_the_block_depth_behind_it() {
        assert_eq!(certified_number(8, 0), Some(8));
        assert_eq!(certified_number(8, 1), Some(7));
        assert_eq!(certified_number(8, 2), Some(6));
        assert_eq!(certified_number(8, 3), Some(5));
        // Blocks 1..=D carry the genesis result: their commits certify
        // nothing beyond genesis.
        assert_eq!(certified_number(1, 1), None);
        assert_eq!(certified_number(2, 1), Some(1));
        assert_eq!(certified_number(1, 2), None);
        assert_eq!(certified_number(2, 2), None);
        assert_eq!(certified_number(3, 2), Some(1));
        assert_eq!(certified_number(3, 3), None);
        assert_eq!(certified_number(4, 3), Some(1));
        assert_eq!(carried_number(1, 2), 0);
        assert_eq!(carried_number(7, 2), 5);
        assert_eq!(carried_number(2, 3), 0);
        assert_eq!(carried_number(7, 3), 4);
    }
}
