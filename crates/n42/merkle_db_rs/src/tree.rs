use std::{collections::HashMap, marker::PhantomData};
use std::collections::HashSet;

use tree_hash::Hash256;

use crate::{error::Error, utils::{tree_height, zero_tree_root}, Value};

use typenum::Unsigned;

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Tree<T: Value> {
    Leaf(T),
    Node {
        left: Hash256,
        right: Hash256,
    },
    Zero(usize),
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct VecTree<T: Value, N: Unsigned> {
    root: Hash256,
    kv: HashMap<Hash256, Tree<T>>,
    vec_len: u64,
    height: usize, // The fixed height of the tree based on capacity N
    _phantom: PhantomData<N>,
}

impl<T: Value, N: Unsigned> VecTree<T, N> {
    pub fn try_new(vec_len: u64) -> Result<Self, Error> {
        if vec_len as usize > N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len,
                limit: N::to_u64(),
            });
        }

        let height = tree_height(N::to_usize());
        let root = zero_tree_root(height);

        let mut kv = HashMap::from([(root, Tree::Zero(height))]);

        // SSZ Compatibility: If T::default() collides with Zero(0), we must ensure
        // the Leaf(Default) node exists in the map.
        // This allows `get` to return a reference to it when traversing implicit zero branches.
        let default_val = T::default();
        if default_val.tree_hash_root() == zero_tree_root(0) {
            kv.insert(zero_tree_root(0), Tree::Leaf(default_val));
        }

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            _phantom: PhantomData,
        })
    }

    /// Creates a new VecTree from an existing Vec, building the Merkle tree.
    pub fn from_vec(elements: Vec<T>) -> Result<Self, Error> {
        let vec_len = elements.len() as u64;

        // 1. Capacity Guard
        if vec_len > N::to_u64() {
            return Err(Error::VecLenTooLarge {
                vec_len,
                limit: N::to_u64(),
            });
        }

        let height = tree_height(N::to_usize());
        let mut kv = HashMap::new();

        // 2. Recursive Builder
        fn build_recursive<T: Value>(
            elements: &[T],
            height: usize,
            kv: &mut HashMap<Hash256, Tree<T>>,
        ) -> Hash256 {
            // CASE A: The current branch is empty (Padding/Sparse)
            if elements.is_empty() {
                let root = zero_tree_root(height);

                if height == 0 {
                    // Special Handling for Height 0 (The Leaf Level)
                    // We check for collision just like in `try_new`.
                    let default_val = T::default();
                    if default_val.tree_hash_root() == root {
                        kv.insert(root, Tree::Leaf(default_val));
                    } else {
                        kv.insert(root, Tree::Zero(0));
                    }
                } else {
                    // Internal nodes that are empty are stored as Zero subtrees
                    kv.insert(root, Tree::Zero(height));
                }
                return root;
            }

            // CASE B: The branch has data and we've reached a Leaf
            if height == 0 {
                // Elements is guaranteed to have the value because CASE A was skipped
                let leaf_val = elements[0].clone();
                let root = leaf_val.tree_hash_root();
                kv.insert(root, Tree::Leaf(leaf_val));
                return root;
            }

            // CASE C: Internal Node with data (Split and Hash)
            let capacity_at_height = 1usize << (height - 1);
            let (left_slice, right_slice) = if elements.len() <= capacity_at_height {
                (elements, &[][..])
            } else {
                elements.split_at(capacity_at_height)
            };

            let left = build_recursive(left_slice, height - 1, kv);
            let right = build_recursive(right_slice, height - 1, kv);

            // Compute parent hash: SHA256(left || right)
            let mut hasher = Sha256::new();
            hasher.update(left.as_slice());
            hasher.update(right.as_slice());
            let root = Hash256::from_slice(&hasher.finalize());

            kv.insert(root, Tree::Node { left, right });
            root
        }

        let root = build_recursive(&elements, height, &mut kv);

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            _phantom: PhantomData,
        })
    }

    /// Convenience wrapper for `diff_restore` with an empty memory map.
    pub fn restore<F>(
        root: Hash256,
        vec_len: u64,
        db_get: F,
    ) -> Result<Self, Error>
    where
        F: Fn(&Hash256) -> Option<Tree<T>>,
    {
        let empty_map = HashMap::new();
        Self::diff_restore(root, vec_len, &empty_map, db_get)
    }

    /// Restores a `VecTree` from a backing Key-Value store, with an in-memory optimization.
    pub fn diff_restore<F>(
        root: Hash256,
        vec_len: u64,
        existing_kv: &HashMap<Hash256, Tree<T>>,
        db_get: F,
    ) -> Result<Self, Error>
    where
        F: Fn(&Hash256) -> Option<Tree<T>>,
    {
        if vec_len as usize > N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len,
                limit: N::to_u64(),
            });
        }

        let height = tree_height(N::to_usize());
        let mut kv = HashMap::new();
        let mut stack = vec![(root, height)];

        // Pre-insert Leaf(Default) if collision happens.
        let default_val = T::default();
        if default_val.tree_hash_root() == zero_tree_root(0) {
            kv.insert(zero_tree_root(0), Tree::Leaf(default_val.clone()));
        }

        while let Some((current_hash, current_height)) = stack.pop() {
            // Optimization: If hash matches zero root, we usually don't need to check DB/Map
            // UNLESS it's a collision case at height 0.
            if current_hash == zero_tree_root(current_height) {
                if current_height == 0 && default_val.tree_hash_root() == zero_tree_root(0) {
                    // Collision: ensure Leaf(Default) is present (pre-inserted above).
                    kv.insert(current_hash, Tree::Leaf(T::default()));
                } else {
                    kv.insert(current_hash, Tree::Zero(current_height));
                }
                continue;
            }

            if kv.contains_key(&current_hash) {
                continue;
            }

            // --- OPTIMIZATION START ---
            // Check in-memory map first. If found, use it and skip DB.
            let node_opt = existing_kv.get(&current_hash).cloned();

            let node = match node_opt {
                Some(n) => n,
                None => {
                    // Not in memory, fetch from DB
                    match db_get(&current_hash) {
                        Some(n) => n,
                        None => {
                            // Implicit zero node handling
                            if current_hash == zero_tree_root(current_height) {
                                if current_height == 0 && default_val.tree_hash_root() == zero_tree_root(0) {
                                    Tree::Leaf(T::default())
                                } else {
                                    Tree::Zero(current_height)
                                }
                            } else {
                                return Err(Error::InconsistentTreeMissingNode {
                                    height: current_height,
                                    hash: current_hash,
                                });
                            }
                        }
                    }
                }
            };
            // --- OPTIMIZATION END ---

            match &node {
                Tree::Node { left, right } => {
                    if current_height == 0 {
                        return Err(Error::InconsistentTreeLeafAtNonZeroHeight {
                            height: 0,
                            hash: current_hash,
                        });
                    }
                    stack.push((*right, current_height - 1));
                    stack.push((*left, current_height - 1));
                }
                Tree::Leaf(_) => {
                    if current_height != 0 {
                        return Err(Error::InconsistentTreeLeafAtNonZeroHeight {
                            height: current_height,
                            hash: current_hash,
                        });
                    }
                }
                Tree::Zero(h) => {
                    if *h != current_height {
                         return Err(Error::InconsistentTreeZeroHeightMismatch {
                            expected: current_height,
                            found: *h,
                            hash: current_hash,
                        });
                    }
                }
            }
            kv.insert(current_hash, node);
        }

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            _phantom: PhantomData,
        })
    }


    pub fn save<F, E>(&self, mut db_put: F) -> Result<(), E>
    where
        F: FnMut(&Hash256, &Tree<T>) -> Result<(), E>,
    {
        for (hash, node) in &self.kv {
            if let Tree::Zero(h) = node {
                if *hash == zero_tree_root(*h) {
                    continue;
                }
            }
            db_put(hash, node)?;
        }
        Ok(())
    }

    /// Saves the `VecTree` nodes to a backing Key-Value store, with differential optimization.
    ///
    /// This performs a traversal from the root. If a key already exists in the DB (checked via `db_contains`),
    /// it skips saving that key AND its children. This is highly efficient for incremental updates.
    ///
    /// **Important:** You must separately save `self.root` and `self.len()` in your database
    /// metadata so you have the entry points to call `restore` later.
    ///
    /// # Generic Parameters
    /// * `F`: The closure for writing to the DB.
    /// * `C`: The closure for checking if a key exists in the DB.
    /// * `E`: A custom error type that your database might return.
    pub fn diff_save<F, C, E>(&self, mut db_put: F, mut db_contains: C) -> Result<(), E>
    where
        F: FnMut(&Hash256, &Tree<T>) -> Result<(), E>,
        C: FnMut(&Hash256) -> bool,
    {
        let mut visited = HashSet::new();
        let mut stack = vec![self.root];

        while let Some(hash) = stack.pop() {
            if !visited.insert(hash) {
                continue;
            }

            if db_contains(&hash) {
                continue;
            }

            if let Some(node) = self.kv.get(&hash) {
                if let Tree::Zero(h) = node {
                    if hash == zero_tree_root(*h) {
                        continue;
                    }
                }

                db_put(&hash, node)?;

                if let Tree::Node { left, right } = node {
                    stack.push(*right);
                    stack.push(*left);
                }
            }
        }
        Ok(())
    }

    pub fn root(self: &Self) -> Hash256 {
        self.root
    }

    pub fn ssz_root(self: &Self) -> Hash256 {
        let left_bytes: &[u8; 32] = self.root.as_ref();

        let mut chunk = [0u8; 32];
        chunk[..8].copy_from_slice(&self.vec_len.to_le_bytes());
        let right_bytes = chunk;

        let mut hasher = Sha256::new();
        hasher.update(left_bytes);
        hasher.update(&right_bytes);

        Hash256::from_slice(&hasher.finalize())
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len() {
            return None;
        }

        let height = self.height;
        let mut current_hash = self.root;

        for h in (0..height).rev() {
            let node = self.kv.get(&current_hash);
            match node {
                Some(Tree::Node { left, right }) => {
                    let bit = (index >> h) & 1;
                    current_hash = if bit == 0 { *left } else { *right };
                }
                Some(Tree::Zero(_)) | None => {
                    // Check if this is a valid "Zero" node (explicit or implicit)
                    let is_zero_node = match node {
                        Some(Tree::Zero(_)) => true,
                        None => current_hash == zero_tree_root(h + 1),
                        _ => false,
                    };

                    if is_zero_node {
                        // FIX: Collision Handling Logic
                        // If we hit an empty subtree (Zero node), it usually means "empty".
                        // BUT, if T::default() has the same hash as an empty leaf (ZeroHash),
                        // then "empty" effectively means "filled with default values".
                        //
                        // We check if `kv` has a Leaf stored at `zero_tree_root(0)`.
                        // `try_new` and `restore` guarantee this Leaf exists if collision is true.
                        if let Some(Tree::Leaf(val)) = self.kv.get(&zero_tree_root(0)) {
                            return Some(val);
                        }

                        // If no leaf found there, it's truly empty (non-collision type).
                        return None;
                    }

                    // If it's None and NOT a zero root, the tree is corrupted.
                    panic!("Inconsistent tree: missing node for hash {:?} at height {}", current_hash, h + 1);
                }
                Some(Tree::Leaf(_)) => {
                    panic!("Inconsistent tree: found Leaf node at height {}", h + 1);
                }
            }
        }

        match self.kv.get(&current_hash) {
            Some(Tree::Leaf(value)) => Some(value),
            Some(Tree::Zero(0)) => {
                // Explicit zero node at leaf level -> Empty.
                None
            }
            None => {
                if current_hash == zero_tree_root(0) {
                    // Implicit zero leaf.
                    // Check for collision leaf again (handle implicit leaf case)
                    if let Some(Tree::Leaf(val)) = self.kv.get(&zero_tree_root(0)) {
                        return Some(val);
                    }
                    None
                } else {
                    panic!("Inconsistent tree: missing node for leaf hash {:?}", current_hash);
                }
            }
            Some(Tree::Node { .. }) | Some(Tree::Zero(_)) => {
                panic!("Inconsistent tree: found non-Leaf node at height 0");
            }
        }
    }

    pub fn set(&mut self, index: usize, value: T) -> Result<(), Error> {
        if index >= self.len() {
            return Err(Error::OutOfBoundsUpdate {
                index: index as u64,
                len: self.vec_len,
            });
        }

        let _ = self.update_leaf(index, Some(value));
        Ok(())
    }

    pub fn push(&mut self, value: T) -> Result<(), Error>
    where T: Clone
    {
        let index = self.len();
        if index >= N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len: self.vec_len + 1, // The length it would be
                limit: N::to_u64(),
            });
        }

        // Update the tree *before* incrementing length.
        // `update_leaf` has no bounds check, so this is safe.
        let _ = self.update_leaf(index, Some(value));

        // Now, commit the length change
        self.vec_len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T>
    where
        T: Default + Clone,
    {
        if self.is_empty() {
            return None;
        }

        self.vec_len -= 1;
        let index = self.len();

        let default_val = T::default();
        let default_hash = default_val.tree_hash_root();
        let zero_hash = zero_tree_root(0);

        // LOGIC FIX:
        // If Hash(Default) == Hash(Zero) (e.g. u64):
        //    We MUST insert Leaf(Default) to keep the DB entry "Active" for other indices.
        // If Hash(Default) != Hash(Zero) (e.g. complex struct):
        //    We MUST insert Zero(0) (None) to ensure the padding hash is correct.
        let old_value_opt = if default_hash == zero_hash {
             self.update_leaf(index, Some(default_val))
        } else {
             self.update_leaf(index, None)
        };

        Some(old_value_opt.unwrap_or_default())
    }

    /// Tries to pop a value from the end of the `VecTree`.
    ///
    /// This is a "strict" version of `pop` that does **not** require `T: Default`.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` if a leaf with a value was popped.
    /// * `Ok(None)` if the `VecTree` was already empty (i.e., `len() == 0`).
    /// * `Err(Error::PoppedEmptySlot)` if the `VecTree` was *not* empty,
    ///   but the leaf being popped was already a `Zero` node (an empty slot).
    ///   This is the "zero case" – `pop()` would have returned `Some(T::default())`.
    pub fn try_pop(&mut self) -> Result<Option<T>, Error>
    where T: Clone
    {
        if self.is_empty() {
            return Ok(None);
        }

        self.vec_len -= 1;
        let index = self.len();

        let old_value_opt = self.update_leaf(index, None);

        match old_value_opt {
            Some(value) => Ok(Some(value)),
            None => Err(Error::PoppedEmptySlot { index: index as u64 }),
        }
    }

    /// Internal function to update a leaf and rebuild the tree path.
    /// This function is the core logic for `set`, `push`, and `pop`.
    /// It has NO bounds checks and will panic on internal tree corruption.
    /// It returns the *old* value that was at that leaf.
    fn update_leaf(&mut self, index: usize, new_value: Option<T>) -> Option<T>
    where T: Clone
    {
        let height = self.height;
        let mut siblings: Vec<Hash256> = Vec::with_capacity(height);
        let mut current_hash = self.root;

        for h in (1..=height).rev() {
            let (left_hash, right_hash) = match self.kv.get(&current_hash) {
                Some(Tree::Node { left, right }) => (*left, *right),
                Some(Tree::Zero(h_zero)) => {
                    if *h_zero != h { panic!("Inconsistent tree height"); }
                    (zero_tree_root(h - 1), zero_tree_root(h - 1))
                }
                Some(Tree::Leaf(_)) => panic!("Found Leaf at height {}", h),
                None => {
                    if current_hash != zero_tree_root(h) { panic!("Missing node"); }
                    (zero_tree_root(h - 1), zero_tree_root(h - 1))
                }
            };

            let bit = (index >> (h - 1)) & 1;
            if bit == 0 {
                siblings.push(right_hash);
                current_hash = left_hash;
            } else {
                siblings.push(left_hash);
                current_hash = right_hash;
            }
        }

        let old_value = match self.kv.get(&current_hash) {
            Some(Tree::Leaf(val)) => Some(val.clone()),
            Some(Tree::Zero(0)) | None => None,
            _ => panic!("Invalid leaf state"),
        };

        let mut new_node_hash;
        if let Some(ref value) = new_value {
            // Standard SSZ: Hash is directly from the value.
            new_node_hash = value.tree_hash_root();
            self.kv.insert(new_node_hash, Tree::Leaf(value.clone()));
        } else {
            // Restoring to Zero / Default
            new_node_hash = zero_tree_root(0);

            // If we are explicitly setting None, we check for collision again here?
            // No, update_leaf is low-level. If caller passed None, they WANT Zero.
            // But we must respect the collision rule: if Zero(0) and Leaf(Default) collide,
            // we should technically store Leaf(Default) to be safe...
            // BUT: pop() handles that logic. If pop() wanted Leaf(Default), it passed Some(Default).
            // If pop() passed None, it means Hash(Default) != Hash(Zero), so Zero is safe.
            self.kv.insert(new_node_hash, Tree::Zero(0));
        }

        for h in 0..height {
            let sibling_hash = siblings.pop().unwrap();
            let (left_hash, right_hash) = if (index >> h) & 1 == 0 {
                (new_node_hash, sibling_hash)
            } else {
                (sibling_hash, new_node_hash)
            };

            let mut hasher = Sha256::new();
            let left_bytes: &[u8; 32] = left_hash.as_ref();
            let right_bytes: &[u8; 32] = right_hash.as_ref();
            hasher.update(left_bytes);
            hasher.update(right_bytes);
            new_node_hash = Hash256::from_slice(&hasher.finalize());

            let current_height = h + 1;
            if new_node_hash == zero_tree_root(current_height) {
                self.kv.insert(new_node_hash, Tree::Zero(current_height));
            } else {
                self.kv.insert(new_node_hash, Tree::Node { left: left_hash, right: right_hash });
            }
        }

        self.root = new_node_hash;
        old_value
    }


    pub fn clear(&mut self) {
        self.vec_len = 0;
        self.root = zero_tree_root(self.height);
        self.kv.clear();
        // Add back the single root node representing the empty tree.
        self.kv.insert(self.root, Tree::Zero(self.height));
    }

    pub fn len(&self) -> usize {
        self.vec_len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> VecTreeIter<T, N> {
        VecTreeIter { tree: self, index: 0 }
    }
}

pub struct VecTreeIter<'a, T: Value, N: Unsigned> {
    tree: &'a VecTree<T, N>,
    index: usize,
}

// If there are holes in the leaves, this iterator will return early, on the first Zero value
impl<'a, T: Value, N: Unsigned> Iterator for VecTreeIter<'a, T, N> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.tree.len() {
            return None;
        }

        let item = self.tree.get(self.index)?;
        self.index += 1;
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::tree_height;
    use tree_hash::TreeHash;
    use typenum::{U1, U16, U8}; // Import some type numbers

    // Note: `u64` implements `Value` via the blanket impl in `lib.rs`
    // because `ssz` provides `Encode`, `Decode`, and `TreeHash` for `u64`.

    #[test]
    fn test_new_empty() {
        let tree = VecTree::<u64, U8>::try_new(0).unwrap();
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());

        // Height of 0 elements is 0
        let height_n = tree_height(U8::to_usize()); // tree_height(8) = 3
        assert_eq!(tree.height, height_n);
        // Root is zero root of height N
        assert_eq!(tree.root, zero_tree_root(height_n));

        // Check final SSZ root
        let chunk = [0u8; 32]; // vec_len = 0
        let mut h = Sha256::new();
        let binding = zero_tree_root(height_n);
        let zero_root_bytes: &[u8; 32] = binding.as_ref();
        h.update(zero_root_bytes);
        h.update(&chunk);
        let expected_root: Hash256 = Hash256::from_slice(&h.finalize());

        assert_eq!(tree.ssz_root(), expected_root);
    }

    #[test]
    fn test_new_vec_len_1() {
        let mut tree = VecTree::<u64, U1>::try_new(1).unwrap();
        assert_eq!(tree.len(), 1);

        let height_n = tree_height(U1::to_usize()); // tree_height(1) = 0
        assert_eq!(height_n, 0);
        assert_eq!(tree.height, height_n);
        assert_eq!(tree.root, zero_tree_root(height_n));

        // Get from zero tree
        assert_eq!(tree.get(0), Some(&u64::default()));

        // Set and Get
        tree.set(0, 42u64).unwrap();
        assert_eq!(tree.get(0), Some(&42u64));

        // Root should be leaf hash
        assert_eq!(tree.root, 42u64.tree_hash_root());

        // OOB
        assert_eq!(tree.get(1), None);
        assert!(tree.set(1, 99u64).is_err());
    }

    #[test]
    fn test_new_with_length() {
        let vec_len = 5;
        let tree = VecTree::<u64, U8>::try_new(vec_len).unwrap();
        assert_eq!(tree.len(), 5);
        assert!(!tree.is_empty());

        let height_n = tree_height(U8::to_usize()); // tree_height(8) = 3
        assert_eq!(tree.height, height_n);
        assert_eq!(tree.root, zero_tree_root(height_n));
    }

    #[test]
    fn test_new_too_large() {
        // Try to create a tree with len 9, but limit is 8
        let res = VecTree::<u64, U8>::try_new(9);
        assert!(res.is_err());

        match res.err().unwrap() {
            Error::VecLenTooLarge { vec_len, limit } => {
                assert_eq!(vec_len, 9);
                assert_eq!(limit, 8);
            }
            _ => panic!("Wrong error type"), // Adjusted for non-exhaustive enum
        }
    }

    #[test]
    fn test_get_on_zero_tree() {
        let tree = VecTree::<u64, U16>::try_new(10).unwrap();
        assert_eq!(tree.len(), 10);

        let height_n = tree_height(U16::to_usize()); // tree_height(16) = 4
        assert_eq!(tree.height, height_n);

        assert_eq!(tree.get(0), Some(&u64::default()));
        assert_eq!(tree.get(5), Some(&u64::default()));
        assert_eq!(tree.get(9), Some(&u64::default()));

        // OOB get should also be None
        assert_eq!(tree.get(10), None);
        assert_eq!(tree.get(99), None);
    }

    #[test]
    fn test_set_and_get_simple() {
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();

        let height_n = tree_height(U8::to_usize()); // tree_height(8) = 3
        assert_eq!(tree.height, height_n);
        let zero_root = zero_tree_root(height_n);
        assert_eq!(tree.root, zero_root);

        // Set value at index 3
        tree.set(3, 100u64).unwrap();

        // Root should have changed
        assert_ne!(tree.root, zero_root);

        // Get back the value
        assert_eq!(tree.get(3), Some(&100u64));

        assert_eq!(tree.get(0), Some(&u64::default()));
        assert_eq!(tree.get(2), Some(&u64::default()));
        assert_eq!(tree.get(4), Some(&u64::default()));
        assert_eq!(tree.get(7), Some(&u64::default()));
    }

    #[test]
    fn test_overwrite_value() {
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();

        // Set initial value
        tree.set(5, 100u64).unwrap();
        assert_eq!(tree.get(5), Some(&100u64));
        let root1 = tree.root;
        let ssz_root1 = tree.ssz_root();

        // Set new value at same index
        tree.set(5, 200u64).unwrap();
        assert_eq!(tree.get(5), Some(&200u64));
        let root2 = tree.root;
        let ssz_root2 = tree.ssz_root();

        // Roots should be different
        assert_ne!(root1, root2);
        assert_ne!(ssz_root1, ssz_root2);
    }

    #[test]
    fn test_set_multiple_values_non_power_of_2() {
        let mut tree = VecTree::<u64, U8>::try_new(5).unwrap();

        // Set values at boundaries and middle
        tree.set(0, 10u64).unwrap();
        tree.set(4, 50u64).unwrap();
        tree.set(2, 30u64).unwrap();

        // Check all values
        assert_eq!(tree.get(0), Some(&10u64));
        assert_eq!(tree.get(1), Some(&u64::default()));
        assert_eq!(tree.get(2), Some(&30u64));
        assert_eq!(tree.get(3), Some(&u64::default()));
        assert_eq!(tree.get(4), Some(&50u64));

        // Check OOB
        assert_eq!(tree.get(5), None);
    }

    #[test]
    fn test_set_out_of_bounds() {
        let mut tree = VecTree::<u64, U8>::try_new(5).unwrap();

        // Set at len is OOB (valid indices are 0..=4)
        let res = tree.set(5, 100u64);
        assert!(res.is_err());
        match res.err().unwrap() {
            Error::OutOfBoundsUpdate { index, len } => {
                assert_eq!(index, 5);
                assert_eq!(len, 5);
            }
            _ => panic!("Wrong error type"), // Adjusted for non-exhaustive enum
        }

        // Set way OOB
        let res_way_oob = tree.set(99, 100u64);
        assert!(res_way_oob.is_err());
    }

    #[test]
    fn test_final_ssz_root_mixin() {
        let mut tree1 = VecTree::<u64, U8>::try_new(4).unwrap();
        tree1.set(1, 123u64).unwrap();
        let ssz_root1 = tree1.ssz_root();

        // Create another tree with same content but different vec_len
        let mut tree2 = VecTree::<u64, U8>::try_new(5).unwrap();
        tree2.set(1, 123u64).unwrap();
        let ssz_root2 = tree2.ssz_root();

        // The Merkle roots (tree.root) should be IDENTICAL
        // because both have N=U8 (height=3) and the same content.
        assert_eq!(tree1.root, tree2.root);

        // The final SSZ roots MUST be different because vec_len is mixed in
        assert_ne!(ssz_root1, ssz_root2);

        // Create a third tree with same content and same vec_len
        let mut tree3 = VecTree::<u64, U8>::try_new(4).unwrap();
        tree3.set(1, 123u64).unwrap();
        let ssz_root3 = tree3.ssz_root();

        // These should be identical
        assert_eq!(tree1.root, tree3.root);
        assert_eq!(ssz_root1, ssz_root3);
    }

    #[test]
    fn test_push_simple() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        assert_eq!(tree.len(), 0);

        tree.push(10u64).unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get(0), Some(&10u64));

        tree.push(20u64).unwrap();
        assert_eq!(tree.len(), 2);
        assert_eq!(tree.get(0), Some(&10u64));
        assert_eq!(tree.get(1), Some(&20u64));
    }

    #[test]
    fn test_push_to_capacity() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        let capacity = U8::to_usize();

        for i in 0..capacity {
            assert!(tree.push(i as u64).is_ok());
        }

        assert_eq!(tree.len(), capacity);

        // Now, try to push one more
        let res = tree.push(99u64);
        assert!(res.is_err());
        match res.err().unwrap() {
            Error::VecLenTooLarge { vec_len, limit } => {
                assert_eq!(vec_len, (capacity + 1) as u64);
                assert_eq!(limit, capacity as u64);
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_pop_simple() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10u64).unwrap();
        tree.push(20u64).unwrap();
        assert_eq!(tree.len(), 2);

        let popped = tree.pop();
        assert_eq!(popped, Some(20u64));
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get(0), Some(&10u64));
        assert_eq!(tree.get(1), None); // Index 1 is now OOB

        let popped2 = tree.pop();
        assert_eq!(popped2, Some(10u64));
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
        assert_eq!(tree.get(0), None); // Index 0 is now OOB
    }

    #[test]
    fn test_pop_empty() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        assert!(tree.is_empty());

        let popped = tree.pop();
        assert_eq!(popped, None);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_push_pop_interleaved() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();

        tree.push(10).unwrap(); // len 1
        tree.push(20).unwrap(); // len 2

        let val1 = tree.pop(); // pops 20, len 1
        assert_eq!(val1, Some(20));
        assert_eq!(tree.len(), 1);

        tree.push(30).unwrap(); // len 2
        assert_eq!(tree.len(), 2);
        assert_eq!(tree.get(0), Some(&10));
        assert_eq!(tree.get(1), Some(&30));

        let val2 = tree.pop(); // pops 30, len 1
        assert_eq!(val2, Some(30));
        let val3 = tree.pop(); // pops 10, len 0
        assert_eq!(val3, Some(10));
        let val4 = tree.pop(); // pops None, len 0
        assert_eq!(val4, None);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_pop_restores_zero_root() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        let height_n = tree_height(U8::to_usize());
        let zero_root = zero_tree_root(height_n);

        assert_eq!(tree.root, zero_root);

        // Push a value, root changes
        tree.push(12345u64).unwrap();
        assert_ne!(tree.root, zero_root);
        assert_eq!(tree.len(), 1);

        // Pop the value, root should be restored
        let val = tree.pop();
        assert_eq!(val, Some(12345u64));
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.root, zero_root);
    }

    #[test]
    fn test_try_pop_simple() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10u64).unwrap();
        tree.push(20u64).unwrap();
        assert_eq!(tree.len(), 2);

        // Pop 20 (works)
        let popped = tree.try_pop().unwrap();
        assert_eq!(popped, Some(20u64));
        assert_eq!(tree.len(), 1);

        // Pop 10 (works)
        let popped2 = tree.try_pop().unwrap();
        assert_eq!(popped2, Some(10u64));
        assert_eq!(tree.len(), 0);

        // Pop empty (works)
        let popped3 = tree.try_pop().unwrap();
        assert_eq!(popped3, None);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_try_pop_on_zero_slot() {
        // Create a tree with len=3, but push a default value at [1]
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10u64).unwrap();
        tree.push(u64::default()).unwrap(); // This creates a Zero(0) leaf at [1]
        tree.push(30u64).unwrap();
        assert_eq!(tree.len(), 3);
        assert_eq!(tree.get(1), Some(&u64::default()));

        // Pop 30 (works)
        let res1 = tree.try_pop().unwrap();
        assert_eq!(res1, Some(30u64));
        assert_eq!(tree.len(), 2);

        // Pop default() at [1] (this is the "Zero situation")
        let res2 = tree.try_pop();
        assert!(res2.is_err());
        match res2.err().unwrap() {
            Error::PoppedEmptySlot { index } => {
                assert_eq!(index, 1);
            }
            _ => panic!("Wrong error type"),
        }
        assert_eq!(tree.len(), 1); // Length still decremented

        // Pop 10 (works)
        let res3 = tree.try_pop().unwrap();
        assert_eq!(res3, Some(10u64));
        assert_eq!(tree.len(), 0);

        // Pop empty (works)
        let res4 = tree.try_pop().unwrap();
        assert_eq!(res4, None);
    }

    #[test]
    fn test_clear() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10u64).unwrap();
        tree.push(20u64).unwrap();
        tree.push(30u64).unwrap();

        assert_eq!(tree.len(), 3);
        assert!(!tree.is_empty());

        let height_n = tree_height(U8::to_usize());
        let zero_root = zero_tree_root(height_n);
        assert_ne!(tree.root, zero_root); // Tree is not empty

        tree.clear();

        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
        assert_eq!(tree.root, zero_root); // Root is restored
        assert_eq!(tree.get(0), None); // All elements are gone
    }

    #[test]
    fn vec_tree_iter_simple() {
        use typenum::U16;

        let mut tree = VecTree::<u64, U16>::try_new(4).unwrap();

        tree.set(0, 10).unwrap();
        tree.set(1, 20).unwrap();
        tree.set(2, 30).unwrap();
        tree.set(3, 40).unwrap();

        let collected: Vec<_> = tree.iter().cloned().collect();
        assert_eq!(collected, vec![10, 20, 30, 40]);
    }

    #[test]
    fn vec_tree_iter_empty() {
        use typenum::U16;

        let tree = VecTree::<u64, U16>::try_new(0).unwrap();
        assert_eq!(tree.iter().next(), None);
    }

    #[test]
    fn test_save_restore_zeros() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(0u64).unwrap(); // Leaf(0)

        let mut db = HashMap::new();
        tree.save(|h, n| { db.insert(*h, n.clone()); Ok::<(),()>(()) }).unwrap();

        let restored = VecTree::<u64, U8>::restore(tree.root, tree.len() as u64, |h| db.get(h).cloned()).unwrap();
        assert_eq!(restored.get(0), Some(&0u64));
    }

    #[test]
    fn test_restore_from_db() {
        // 1. Create a tree and populate it
        let mut original_tree = VecTree::<u64, U8>::try_new(0).unwrap();
        original_tree.push(10u64).unwrap();
        original_tree.push(20u64).unwrap();
        // Index 2 is empty (Default/Zero)
        // Since u64::default() == 0, and Hash(0) == ZeroHash, this is stored as Leaf(0)
        original_tree.push(u64::default()).unwrap();
        original_tree.push(40u64).unwrap();

        let root = original_tree.root; // Internal root
        let vec_len = original_tree.vec_len;

        // 2. Simulate a DB
        let db = &original_tree.kv;
        // db_get closure mimics fetching from DB
        let db_get = |h: &Hash256| db.get(h).cloned();

        // 3. Restore
        let restored_tree = VecTree::<u64, U8>::restore(root, vec_len, db_get).unwrap();

        // 4. Verify
        assert_eq!(restored_tree.len(), 4);
        assert_eq!(restored_tree.root, root);

        // Check contents
        assert_eq!(restored_tree.get(0), Some(&10u64));
        assert_eq!(restored_tree.get(1), Some(&20u64));

        // Crucial check: Since Hash(Default) collides with ZeroHash for u64,
        // restore() logic infers Leaf(Default).
        assert_eq!(restored_tree.get(2), Some(&0u64));

        assert_eq!(restored_tree.get(3), Some(&40u64));

        // Ensure iterators work
        let vals: Vec<u64> = restored_tree.iter().cloned().collect();
        assert_eq!(vals, vec![10, 20, 0, 40]);
    }

    #[test]
    fn test_save_and_restore_round_trip() {
        let mut original = VecTree::<u64, U8>::try_new(0).unwrap();
        original.push(1u64).unwrap();
        original.push(2u64).unwrap();
        original.push(0u64).unwrap(); // Explicit zero

        // Create a simulated DB
        let mut db: HashMap<Hash256, Tree<u64>> = HashMap::new();

        // Save using the new save method
        original.save(|hash, node| {
            db.insert(*hash, node.clone());
            Ok::<(), ()>(())
        }).unwrap();

        // Restore using the restore method
        let restored = VecTree::<u64, U8>::restore(
            original.root,
            original.vec_len,
            |h| db.get(h).cloned()
        ).unwrap();

        assert_eq!(original.root, restored.root);
        assert_eq!(original.len(), restored.len());
        assert_eq!(original.get(0), restored.get(0));
        assert_eq!(original.get(1), restored.get(1));
        assert_eq!(original.get(2), restored.get(2)); // Check zero handling
    }

        #[test]
    fn test_diff_save_full_overlap() {
        // Scenario: Tree is fully persisted. diff_save should write nothing.
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10).unwrap();
        tree.push(20).unwrap();

        let mut db = HashMap::new();
        // Initial full save
        tree.save(|h, n| { db.insert(*h, n.clone()); Ok::<(),()>(()) }).unwrap();

        // Count writes for the second save
        let mut write_count = 0;
        tree.diff_save(
            |_h, _n| { write_count += 1; Ok::<(),()>(()) },
            |h| db.contains_key(h)
        ).unwrap();

        assert_eq!(write_count, 0, "diff_save should write nothing if DB contains all nodes");
    }

    #[test]
    fn test_diff_save_no_overlap() {
        // Scenario: DB is empty. diff_save should write everything (like full save).
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10).unwrap();

        let mut write_count = 0;
        tree.diff_save(
            |_h, _n| { write_count += 1; Ok::<(),()>(()) },
            |_h| false // DB contains nothing
        ).unwrap();

        // Should write Leaf(10) and path to root
        assert!(write_count > 0);
    }

    #[test]
    fn test_complex_diff_workflow() {
        // 1. Setup Base Tree: [10, 20, 30, 40]
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10).unwrap();
        tree.push(20).unwrap();
        tree.push(30).unwrap();
        tree.push(40).unwrap();

        let mut db_base = HashMap::new();
        tree.save(|h, n| { db_base.insert(*h, n.clone()); Ok::<(),()>(()) }).unwrap();

        // 2. Modify Tree: Update index 2 (30 -> 300)
        tree.set(2, 300).unwrap();

        // 3. Diff Save to a "Patch" DB
        let mut db_patch = HashMap::new();
        let mut writes = 0;
        tree.diff_save(
            |h, n| {
                db_patch.insert(*h, n.clone());
                writes += 1;
                Ok::<(),()>(())
            },
            |h| db_base.contains_key(h)
        ).unwrap();

        // 4. Verify Patch
        assert!(writes > 0);
        let leaf_10_hash = 10u64.tree_hash_root();
        assert!(!db_patch.contains_key(&leaf_10_hash), "Unmodified leaf should not be in patch");

        // 5. Diff Restore
        let existing_kv = db_base.clone();

        let restored = VecTree::<u64, U8>::diff_restore(
            tree.root,
            tree.vec_len,
            &existing_kv,
            |h| db_patch.get(h).cloned()
        ).unwrap();

        assert_eq!(restored.get(0), Some(&10));
        assert_eq!(restored.get(2), Some(&300));
        assert_eq!(restored.root, tree.root);
    }

    #[test]
    fn test_from_vec_basic() {
        // CASE: Standard initialization with data
        let elements = vec![10u64, 20u64, 30u64];
        let tree = VecTree::<u64, U8>::from_vec(elements).expect("Should create tree");

        assert_eq!(tree.vec_len, 3);
        assert_eq!(tree.height, 3); // log2(8)
        assert!(tree.kv.contains_key(&tree.root));
    }

    #[test]
    fn test_from_vec_full_capacity() {
        // CASE: Filling exactly to N
        let elements = vec![1u64; 8];
        let tree = VecTree::<u64, U8>::from_vec(elements).expect("Should support full capacity");
        assert_eq!(tree.vec_len, 8);
    }

    #[test]
    fn test_from_vec_overflow() {
        // CASE: Safety check for length > N
        let elements = vec![1u64; 9];
        let result = VecTree::<u64, U8>::from_vec(elements);
        assert!(result.is_err(), "Should error when vec length exceeds typenum capacity");
    }

    #[test]
    fn test_empty_vec_is_zero_root() {
        // CASE: Empty vector must match precomputed zero_tree_root
        let tree = VecTree::<u64, U8>::from_vec(vec![]).unwrap();
        let expected_root = zero_tree_root(3); // Height of U8 is 3
        assert_eq!(tree.root, expected_root, "Empty tree must have zero_tree_root(height)");
    }

    #[test]
    fn test_sparse_optimization() {
        // CASE: Only 1 element. Indices 4-7 should be a Zero(2) node
        let elements = vec![99u64];
        let tree = VecTree::<u64, U8>::from_vec(elements).unwrap();

        let zero_h2 = zero_tree_root(2);
        assert!(tree.kv.contains_key(&zero_h2), "Tree should utilize Zero(2) for the empty right half");
    }

    #[test]
    fn test_ssz_default_collision() {
        // CASE: SSZ Compatibility check
        // If 0u64's hash matches zero_tree_root(0), it must be explicitly in the map
        let elements = vec![0u64];
        let tree = VecTree::<u64, U8>::from_vec(elements).unwrap();

        let leaf_root = 0u64.tree_hash_root();
        assert!(tree.kv.contains_key(&leaf_root), "Leaf(0) must exist in KV store for SSZ compatibility");
    }
}
