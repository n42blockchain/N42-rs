// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The QMDB trees a node holds while blocks are still contested.
//!
//! [`super::QmdbState`] is one tree with a linear history — right for a chain
//! whose blocks arrive already decided. An execution client's engine tree is
//! not that: it validates blocks *before* consensus settles them, and two
//! proposals for the same height can both be valid at once. Each has to be
//! committed against the tree as it stood after their common parent, which is
//! why this keys trees by block hash rather than height.
//!
//! Every block gets its own tree because a QMDB root is a function of the
//! append history, not just the state — see the crate docs. Sharing one tree
//! and reverting on a fork is what gov5 does with undo records; until this port
//! has those, a per-block copy is the correct-first version of the same thing,
//! and the window of retained trees is bounded so it stays a window.

use std::collections::HashMap;
use std::sync::Arc;

use alloy_primitives::{Address, B256};
use n42_twig_core::qmdb_compat::{
    gov5_account_key, gov5_storage_key, QmdbCompatTree, QmdbProof, QmdbSnapshot,
};
use serde::{Deserialize, Serialize};

use crate::{BlockChanges, StateError};

/// How many blocks behind the canonical head a tree is kept.
///
/// A committed HotStuff-2 block never reverts, so this only has to cover the
/// unfinalised tip plus sibling proposals at the same heights.
pub const DEFAULT_RETAIN_DEPTH: u64 = 64;

/// A block's tree, computed but not yet filed under its hash.
///
/// A block producer does not know its block's hash until the header — state
/// root included — is sealed, so computing the root and recording the tree
/// have to be two steps. Validation knows the hash up front and does both at
/// once with [`QmdbForest::apply`].
#[derive(Debug, Clone)]
pub struct PreparedBlock {
    /// The root the block's header must carry.
    pub root: B256,
    tree: QmdbCompatTree,
}

impl PreparedBlock {
    /// The root the block's header must carry.
    pub const fn root(&self) -> B256 {
        self.root
    }
}

/// Everything needed to rebuild the canonical head's tree after a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForestSnapshot {
    /// Layout version, so a future change to the tree encoding is detected
    /// rather than misread.
    pub version: u32,
    /// The block the tree stands at.
    pub head_number: u64,
    /// Its hash.
    pub head_hash: B256,
    /// The tree.
    pub tree: QmdbSnapshot,
}

impl ForestSnapshot {
    /// The layout this crate writes.
    pub const VERSION: u32 = 1;
}

/// Trees for recent blocks, keyed by block hash.
#[derive(Debug)]
pub struct QmdbForest {
    trees: HashMap<B256, Arc<QmdbCompatTree>>,
    numbers: HashMap<B256, u64>,
    head: (u64, B256),
    retain_depth: u64,
}

impl QmdbForest {
    /// A forest whose only tree is the genesis state.
    ///
    /// The root of that tree is what a QMDB chain's genesis header carries as
    /// its state root: gov5 seeds the forest from the alloc at init and writes
    /// the resulting root into the header, and a node that computed the
    /// Merkle-Patricia root of the same alloc would disagree with it about the
    /// genesis hash before the first block.
    pub fn genesis(genesis_hash: B256, alloc: &BlockChanges) -> Result<Self, StateError> {
        let mut tree = QmdbCompatTree::new();
        tree.apply_sorted_ops(alloc.operations())?;
        Ok(Self::at(0, genesis_hash, tree))
    }

    /// A forest restored from a snapshot of its canonical head.
    pub fn from_snapshot(snapshot: &ForestSnapshot) -> Result<Self, StateError> {
        if snapshot.version != ForestSnapshot::VERSION {
            return Err(StateError::SnapshotVersion {
                found: snapshot.version,
                expected: ForestSnapshot::VERSION,
            });
        }
        let tree = QmdbCompatTree::from_snapshot(&snapshot.tree)
            .map_err(|error| StateError::Snapshot(error.to_string()))?;
        Ok(Self::at(snapshot.head_number, snapshot.head_hash, tree))
    }

    fn at(number: u64, hash: B256, tree: QmdbCompatTree) -> Self {
        let mut forest = Self {
            trees: HashMap::new(),
            numbers: HashMap::new(),
            head: (number, hash),
            retain_depth: DEFAULT_RETAIN_DEPTH,
        };
        forest.trees.insert(hash, Arc::new(tree));
        forest.numbers.insert(hash, number);
        forest
    }

    /// Sets how many blocks behind the head trees are kept.
    pub const fn with_retain_depth(mut self, depth: u64) -> Self {
        self.retain_depth = depth;
        self
    }

    /// The canonical head, as `(number, hash)`.
    pub const fn head(&self) -> (u64, B256) {
        self.head
    }

    /// Whether a tree is held for `block_hash`.
    pub fn contains(&self, block_hash: &B256) -> bool {
        self.trees.contains_key(block_hash)
    }

    /// The state root after `block_hash`, if its tree is held.
    pub fn root_of(&self, block_hash: &B256) -> Option<B256> {
        self.trees.get(block_hash).map(|tree| B256::from(tree.root()))
    }

    /// The state root at the canonical head.
    pub fn root(&self) -> B256 {
        self.root_of(&self.head.1).unwrap_or_default()
    }

    /// How many trees are held.
    pub fn len(&self) -> usize {
        self.trees.len()
    }

    /// Whether no trees are held — never true for a constructed forest.
    pub fn is_empty(&self) -> bool {
        self.trees.is_empty()
    }

    /// Computes the tree and root a block would have on top of `parent`.
    ///
    /// Nothing is recorded: the caller seals its header with the root, learns
    /// the block hash, and files the tree with [`Self::insert`].
    pub fn compute(&self, parent: B256, changes: &BlockChanges) -> Result<PreparedBlock, StateError> {
        let base = self
            .trees
            .get(&parent)
            .ok_or(StateError::UnknownParent(parent))?;
        // A per-block copy. See the module docs for why this is the correct
        // first version rather than an oversight.
        let mut tree = (**base).clone();
        let root = tree.apply_sorted_ops(changes.operations())?;
        Ok(PreparedBlock {
            root: B256::from(root),
            tree,
        })
    }

    /// Files a computed tree under the block it belongs to.
    ///
    /// Idempotent: a block already held is left as it is. The same block reaches
    /// a producer twice — once when it builds it, once when its own execution
    /// layer validates it — and both arrive at the same tree.
    pub fn insert(&mut self, block_hash: B256, number: u64, prepared: PreparedBlock) {
        if self.trees.contains_key(&block_hash) {
            return;
        }
        self.trees.insert(block_hash, Arc::new(prepared.tree));
        self.numbers.insert(block_hash, number);
    }

    /// Computes and files a block's tree in one step, for a block whose hash
    /// is already known. Returns the root.
    ///
    /// Idempotent by hash, like [`Self::insert`].
    pub fn apply(
        &mut self,
        parent: B256,
        block_hash: B256,
        number: u64,
        changes: &BlockChanges,
    ) -> Result<B256, StateError> {
        if let Some(root) = self.root_of(&block_hash) {
            return Ok(root);
        }
        let prepared = self.compute(parent, changes)?;
        let root = prepared.root;
        self.insert(block_hash, number, prepared);
        Ok(root)
    }

    /// Advances the canonical head and drops trees that have fallen out of the
    /// retention window.
    ///
    /// The head must already be held: a block becomes canonical only after it
    /// was validated, and validation is what files its tree.
    pub fn set_canonical(&mut self, block_hash: B256) -> Result<(), StateError> {
        let number = *self
            .numbers
            .get(&block_hash)
            .ok_or(StateError::UnknownBlock(block_hash))?;
        self.head = (number, block_hash);
        let cutoff = number.saturating_sub(self.retain_depth);
        let stale: Vec<B256> = self
            .numbers
            .iter()
            .filter(|(hash, n)| **n < cutoff && **hash != block_hash)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in stale {
            self.trees.remove(&hash);
            self.numbers.remove(&hash);
        }
        Ok(())
    }

    /// A snapshot of the canonical head, enough to restore this forest.
    ///
    /// Only the head: every other tree is either an ancestor a restarted node
    /// no longer needs, or a sibling that lost.
    pub fn snapshot(&self) -> ForestSnapshot {
        let tree = self
            .trees
            .get(&self.head.1)
            .map(|tree| tree.snapshot())
            .unwrap_or_else(|| QmdbCompatTree::new().snapshot());
        ForestSnapshot {
            version: ForestSnapshot::VERSION,
            head_number: self.head.0,
            head_hash: self.head.1,
            tree,
        }
    }

    /// Proves an account at the canonical head.
    pub fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.trees
            .get(&self.head.1)?
            .prove(&gov5_account_key(&address.0 .0))
    }

    /// Proves a storage slot at the canonical head.
    pub fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.trees
            .get(&self.head.1)?
            .prove(&gov5_storage_key(&address.0 .0, &slot.0))
    }
}

/// Something that can prove state against a root it also reports.
///
/// The root and the proof have to come from the same tree, or a verifier
/// checks one against the other and learns nothing. Implemented for both the
/// linear [`super::QmdbState`] and the [`QmdbForest`] a live node keeps.
pub trait StateProofProvider: Send + Sync {
    /// The state root proofs are anchored to.
    fn state_root(&self) -> B256;
    /// Proves an account's leaf, if it has one.
    fn prove_account(&self, address: Address) -> Option<QmdbProof>;
    /// Proves a storage slot's leaf, if it has one.
    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof>;
}

impl StateProofProvider for std::sync::Mutex<QmdbForest> {
    fn state_root(&self) -> B256 {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .root()
    }

    fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_account(address)
    }

    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_storage(address, slot)
    }
}

impl StateProofProvider for std::sync::Mutex<super::QmdbState> {
    fn state_root(&self) -> B256 {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .root()
    }

    fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_account(address)
    }

    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_storage(address, slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountState;
    use alloy_primitives::U256;

    fn changes(byte: u8) -> BlockChanges {
        let mut changes = BlockChanges::new();
        changes.set_account(
            Address::with_last_byte(byte),
            AccountState {
                nonce: byte as u64,
                balance: U256::from(byte),
                code_hash: B256::ZERO,
            },
        );
        changes
    }

    const GENESIS: B256 = B256::repeat_byte(0xA0);

    #[test]
    fn two_siblings_are_both_computed_against_their_parent() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let a = B256::repeat_byte(0x0A);
        let b = B256::repeat_byte(0x0B);
        let root_a = forest.apply(GENESIS, a, 1, &changes(1)).unwrap();
        let root_b = forest.apply(GENESIS, b, 1, &changes(2)).unwrap();

        // Neither sibling saw the other. A linear tree would have applied B on
        // top of A and forked from every node that only ever saw B.
        let mut only_b = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        assert_eq!(only_b.apply(GENESIS, b, 1, &changes(2)).unwrap(), root_b);
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn a_block_filed_twice_keeps_its_first_tree() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let a = B256::repeat_byte(0x0A);
        let first = forest.apply(GENESIS, a, 1, &changes(1)).unwrap();
        // The producer's copy and the validator's copy of the same block.
        let again = forest.apply(GENESIS, a, 1, &changes(1)).unwrap();
        assert_eq!(first, again);
        assert_eq!(forest.len(), 2);
    }

    #[test]
    fn compute_then_insert_matches_apply() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let prepared = forest.compute(GENESIS, &changes(1)).unwrap();
        let a = B256::repeat_byte(0x0A);
        forest.insert(a, 1, prepared.clone());

        let mut direct = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        assert_eq!(direct.apply(GENESIS, a, 1, &changes(1)).unwrap(), prepared.root);
        assert_eq!(forest.root_of(&a), Some(prepared.root));
    }

    #[test]
    fn an_unknown_parent_is_refused() {
        let forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        match forest.compute(B256::repeat_byte(0xEE), &changes(1)) {
            Err(StateError::UnknownParent(_)) => {}
            other => panic!("expected an unknown parent, got {other:?}"),
        }
    }

    #[test]
    fn old_trees_fall_out_of_the_window_but_the_head_never_does() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new())
            .unwrap()
            .with_retain_depth(2);
        let mut parent = GENESIS;
        for n in 1..=5u8 {
            let hash = B256::repeat_byte(n);
            forest.apply(parent, hash, n as u64, &changes(n)).unwrap();
            forest.set_canonical(hash).unwrap();
            parent = hash;
        }
        assert_eq!(forest.head(), (5, B256::repeat_byte(5)));
        assert!(forest.contains(&B256::repeat_byte(5)));
        assert!(forest.contains(&B256::repeat_byte(3)));
        assert!(!forest.contains(&B256::repeat_byte(1)), "block 1 is past the window");
        assert!(!forest.contains(&GENESIS));
    }

    #[test]
    fn a_snapshot_restores_the_head_tree_exactly() {
        let mut forest = QmdbForest::genesis(GENESIS, &changes(9)).unwrap();
        let a = B256::repeat_byte(0x0A);
        let root = forest.apply(GENESIS, a, 1, &changes(1)).unwrap();
        forest.set_canonical(a).unwrap();

        let restored = QmdbForest::from_snapshot(&forest.snapshot()).unwrap();
        assert_eq!(restored.head(), (1, a));
        assert_eq!(restored.root(), root);

        // And the restored tree continues the append history, not just the
        // state: the next block's root agrees with the original.
        let b = B256::repeat_byte(0x0B);
        let mut restored = restored;
        assert_eq!(
            restored.apply(a, b, 2, &changes(2)).unwrap(),
            forest.apply(a, b, 2, &changes(2)).unwrap(),
        );
    }

    #[test]
    fn a_snapshot_from_another_layout_is_refused() {
        let forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let mut snapshot = forest.snapshot();
        snapshot.version += 1;
        assert!(matches!(
            QmdbForest::from_snapshot(&snapshot),
            Err(StateError::SnapshotVersion { .. })
        ));
    }
}
