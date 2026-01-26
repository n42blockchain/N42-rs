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
    /// For collision types (where T::default() hashes to zero_tree_root(0)),
    /// stores the default value to return when reading uninitialized positions.
    /// None for non-collision types.
    default_for_collision: Option<T>,
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

        let kv = HashMap::from([(root, Tree::Zero(height))]);

        // SSZ Collision Handling: Store default separately for collision types
        let default_val = T::default();
        let default_for_collision = if default_val.tree_hash_root() == zero_tree_root(0) {
            Some(default_val)
        } else {
            None
        };

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            default_for_collision,
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
                    // Leaf level - store Zero node for empty positions
                    kv.insert(root, Tree::Zero(0));
                } else {
                    // Internal nodes that are empty are stored as Zero subtrees
                    kv.insert(root, Tree::Zero(height));
                }
                return root;
            }

            // CASE B: The branch has data and we've reached a Leaf
            if height == 0 {
                // Elements slice is non-empty (CASE A would have handled empty), extract the value
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

        // SSZ Collision Handling: Store default separately for collision types
        let default_val = T::default();
        let default_for_collision = if default_val.tree_hash_root() == zero_tree_root(0) {
            Some(default_val)
        } else {
            None
        };

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            default_for_collision,
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

        while let Some((current_hash, current_height)) = stack.pop() {
            // Optimization: If hash matches zero root, store Zero node directly
            if current_hash == zero_tree_root(current_height) {
                kv.insert(current_hash, Tree::Zero(current_height));
                continue;
            }

            if kv.contains_key(&current_hash) {
                continue;
            }

            // Try in-memory cache first, then fall back to database lookup
            let node_opt = existing_kv.get(&current_hash).cloned();

            let node = match node_opt {
                Some(n) => n,
                None => {
                    // Cache miss, fetch from database
                    match db_get(&current_hash) {
                        Some(n) => n,
                        None => {
                            // Node not in DB - check if it's an implicit zero node
                            if current_hash == zero_tree_root(current_height) {
                                Tree::Zero(current_height)
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

        // SSZ Collision Handling: Store default separately for collision types
        let default_val = T::default();
        let default_for_collision = if default_val.tree_hash_root() == zero_tree_root(0) {
            Some(default_val)
        } else {
            None
        };

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            default_for_collision,
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
                        // Collision Handling: Return default for collision types, None otherwise
                        return self.default_for_collision.as_ref();
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
            Some(Tree::Zero(0)) | None => {
                // Zero node or implicit zero at leaf level
                if current_hash == zero_tree_root(0) {
                    // Return collision default if it exists, None otherwise
                    return self.default_for_collision.as_ref();
                }
                if let None = self.kv.get(&current_hash) {
                    panic!("Inconsistent tree: missing node for leaf hash {:?}", current_hash);
                }
                None
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
                vec_len: self.vec_len + 1, // The new length after push would exceed capacity
                limit: N::to_u64(),
            });
        }

        // Update the tree structure before incrementing length.
        // This ordering is safe because update_leaf() has no bounds checks.
        let _ = self.update_leaf(index, Some(value));

        // Commit the length change after tree update succeeds
        self.vec_len += 1;
        Ok(())
    }

    /// Pushes multiple values at once, computing shared ancestor hashes only once.
    pub fn push_batch(&mut self, values: &[T]) -> Result<(), Error>
    where T: Clone
    {
        if values.is_empty() {
            return Ok(());
        }

        let start = self.len();
        let new_len = start + values.len();

        if new_len > N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len: new_len as u64,
                limit: N::to_u64(),
            });
        }

        // Insert leaves, collect hashes in order
        let mut hashes: Vec<Hash256> = values.iter().map(|v| {
            let h = v.tree_hash_root();
            self.kv.insert(h, Tree::Leaf(v.clone()));
            h
        }).collect();

        let mut level_start = start;

        // Build up level by level
        for level in 0..self.height {
            let parent_start = level_start >> 1;
            let parent_end = (level_start + hashes.len() - 1) >> 1;

            let mut parent_hashes = Vec::with_capacity(parent_end - parent_start + 1);

            for parent_idx in parent_start..=parent_end {
                let left_idx = parent_idx << 1;
                let right_idx = left_idx + 1;

                let left = self.batch_get_hash(&hashes, level_start, left_idx, level);
                let right = self.batch_get_hash(&hashes, level_start, right_idx, level);

                let mut hasher = Sha256::new();
                hasher.update(left.as_ref() as &[u8; 32]);
                hasher.update(right.as_ref() as &[u8; 32]);
                let parent = Hash256::from_slice(&hasher.finalize());

                if parent == zero_tree_root(level + 1) {
                    self.kv.insert(parent, Tree::Zero(level + 1));
                } else {
                    self.kv.insert(parent, Tree::Node { left, right });
                }
                parent_hashes.push(parent);
            }

            hashes = parent_hashes;
            level_start = parent_start;
        }

        self.root = hashes[0];
        self.vec_len = new_len as u64;
        Ok(())
    }

    fn batch_get_hash(&self, hashes: &[Hash256], level_start: usize, idx: usize, level: usize) -> Hash256 {
        if idx >= level_start && idx < level_start + hashes.len() {
            hashes[idx - level_start]
        } else {
            self.get_hash_at_level(idx, level)
        }
    }

    fn get_hash_at_level(&self, index: usize, level: usize) -> Hash256 {
        let mut hash = self.root;
        for h in (level + 1..=self.height).rev() {
            match self.kv.get(&hash) {
                Some(Tree::Node { left, right }) => {
                    hash = if (index >> (h - 1 - level)) & 1 == 0 { *left } else { *right };
                }
                _ => return zero_tree_root(level),
            }
        }
        hash
    }

pub fn update_indices<F>(&mut self, indices: &HashSet<usize>, mut f: F) -> Result<(), Error>
    where
        F: FnMut(usize, &mut T),
        T: Clone + Default + PartialEq, // PartialEq required to detect unchanged values and skip hashing
    {
        if indices.is_empty() {
            return Ok(());
        }

        // 1. Pre-validation for Atomicity
        for &idx in indices {
            if idx >= self.len() {
                return Err(Error::OutOfBoundsUpdate {
                    index: idx as u64,
                    len: self.vec_len,
                });
            }
        }

        let mut updated_hashes: HashMap<usize, Hash256> = HashMap::new();
        let default_val = T::default();

        // 2. Leaf Update Phase with Value Comparison
        for &idx in indices {
            let old_val = self.get(idx).cloned().unwrap_or_else(|| default_val.clone());
            let mut new_val = old_val.clone();
            
            f(idx, &mut new_val);

            // Optimization: If the value didn't change, avoid the expensive tree_hash_root()
            if old_val == new_val {
                continue;
            }

            // Only hash if a change occurred
            let new_hash = new_val.tree_hash_root();

            // Always store as Leaf since we have an actual value from the closure.
            // This matches the behavior of update_leaf() when called with Some(value).
            // The Zero(0) optimization is only for explicit removals (None), which
            // update_indices doesn't support - it always produces a value.
            self.kv.insert(new_hash, Tree::Leaf(new_val));

            updated_hashes.insert(idx, new_hash);
        }

        // If no values actually changed, early exit
        if updated_hashes.is_empty() {
            return Ok(());
        }

        // 3. Bubble Up Phase
        for h in 0..self.height {
            let mut next_level_updates = HashMap::new();
            let target_zero_hash = zero_tree_root(h + 1);

            for (&idx, _) in &updated_hashes {
                let parent_idx = idx >> 1;
                if next_level_updates.contains_key(&parent_idx) {
                    continue;
                }

                let left_idx = parent_idx << 1;
                let right_idx = left_idx + 1;

                let left = updated_hashes.get(&left_idx).cloned()
                    .unwrap_or_else(|| self.get_hash_at_level(left_idx, h));
                
                let right = updated_hashes.get(&right_idx).cloned()
                    .unwrap_or_else(|| self.get_hash_at_level(right_idx, h));

                let mut hasher = Sha256::new();
                hasher.update(left.as_slice());
                hasher.update(right.as_slice());
                let parent_hash = Hash256::from_slice(&hasher.finalize());

                if parent_hash == target_zero_hash {
                    self.kv.insert(parent_hash, Tree::Zero(h + 1));
                } else {
                    self.kv.insert(parent_hash, Tree::Node { left, right });
                }

                next_level_updates.insert(parent_idx, parent_hash);
            }
            updated_hashes = next_level_updates;
        }

        if let Some(&new_root) = updated_hashes.get(&0) {
            self.root = new_root;
        }

        Ok(())
    }

    /// Removes and returns the last element from the `VecTree`.
    ///
    /// This method always succeeds when the tree is non-empty, treating uninitialized
    /// positions (holes) as containing `T::default()` values. This is SSZ-compatible
    /// behavior where vectors are conceptually "filled" with defaults up to their capacity.
    ///
    /// # Returns
    ///
    /// * `Some(value)` - The value at the last position (or `T::default()` if it was a hole)
    /// * `None` - If the tree is empty (`len() == 0`)
    ///
    /// # When to Use
    ///
    /// Use `pop()` when `T` implements `Default` and you want SSZ-compatible semantics
    /// where holes are treated as default values. For types without `Default`, use
    /// `try_pop()` instead, which can distinguish between actual values and holes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_db_rs::tree::VecTree;
    /// # use typenum::U8;
    /// let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
    /// tree.push(42).unwrap();
    ///
    /// // Popping an actual value
    /// assert_eq!(tree.pop(), Some(42));
    ///
    /// // Popping when empty returns None
    /// assert_eq!(tree.pop(), None);
    /// ```
    pub fn pop(&mut self) -> Option<T>
    where
        T: Default + Clone,
    {
        if self.is_empty() {
            return None;
        }

        self.vec_len -= 1;
        let index = self.len();

        let old_value_opt = self.update_leaf(index, None);

        Some(old_value_opt.unwrap_or_default())
    }

    /// Tries to pop a value from the end of the `VecTree`, distinguishing holes from values.
    ///
    /// Unlike `pop()`, this method can **fail** when encountering an uninitialized position
    /// (a hole). This is useful for types that don't implement `Default`, where there's no
    /// sensible default value to return for holes.
    ///
    /// # Semantic Difference from `pop()`
    ///
    /// - **`pop()`**: Treats holes as `T::default()`, always succeeds (requires `T: Default`)
    /// - **`try_pop()`**: Fails on holes with `PoppedEmptySlot` error (no `T: Default` needed)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - Successfully popped an actual value
    /// * `Ok(None)` - The tree was already empty (`len() == 0`)
    /// * `Err(Error::PoppedEmptySlot)` - The position was a hole (uninitialized)
    ///
    /// # When to Use
    ///
    /// Use `try_pop()` when:
    /// - `T` does not implement `Default`
    /// - You need to distinguish between actual values and holes
    /// - You want strict validation that you're not popping uninitialized data
    ///
    /// For types with `Default` where holes should be treated as defaults, use `pop()` instead.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_db_rs::tree::VecTree;
    /// # use typenum::U8;
    /// let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
    /// tree.push(42).unwrap();
    ///
    /// // Popping an actual value succeeds
    /// assert_eq!(tree.try_pop(), Ok(Some(42)));
    ///
    /// // Popping when empty returns Ok(None)
    /// assert_eq!(tree.try_pop(), Ok(None));
    /// ```
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
            // Store the value as a leaf, hash computed from the value itself
            new_node_hash = value.tree_hash_root();
            self.kv.insert(new_node_hash, Tree::Leaf(value.clone()));
        } else {
            // Restore to empty state
            new_node_hash = zero_tree_root(0);

            // Collision handling: Preserve default value for collision types
            // For collision types, store Tree::Leaf(default) so get() returns the default
            // For non-collision types, store Tree::Zero(0) so get() returns None
            if let Some(ref default_val) = self.default_for_collision {
                self.kv.insert(new_node_hash, Tree::Leaf(default_val.clone()));
            } else {
                self.kv.insert(new_node_hash, Tree::Zero(0));
            }
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

    /// Removes all key-value pairs from the internal map that are not reachable from the current root, returns the number of pairs removed.
    pub fn prune(&mut self) -> usize {
        let initial_size = self.kv.len();

        let mut reachable = HashSet::new();
        let mut stack = vec![self.root];

        // 1. Standard Reachability Traversal
        while let Some(current_hash) = stack.pop() {
            if !reachable.insert(current_hash) {
                continue;
            }
            if let Some(tree_node) = self.kv.get(&current_hash) {
                match tree_node {
                    Tree::Node { left, right } => {
                        stack.push(*left);
                        stack.push(*right);
                    }
                    _ => {} // Leaf and Zero are terminal
                }
            }
        }

        // 2. Retain only reachable nodes
        self.kv.retain(|hash, _| reachable.contains(hash));

        // 3. Return the count of removed items
        initial_size - self.kv.len()
    }
}

pub struct VecTreeIter<'a, T: Value, N: Unsigned> {
    tree: &'a VecTree<T, N>,
    index: usize,
}

// Note: For collision types, holes return defaults. For non-collision types, iteration stops at the first hole.
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
        // Create a tree with len=3, explicitly pushing default value at [1]
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        tree.push(10u64).unwrap();
        tree.push(u64::default()).unwrap(); // This stores Tree::Leaf(0), not a hole
        tree.push(30u64).unwrap();
        assert_eq!(tree.len(), 3);
        assert_eq!(tree.get(1), Some(&u64::default()));

        // Pop 30 (works)
        let res1 = tree.try_pop().unwrap();
        assert_eq!(res1, Some(30u64));
        assert_eq!(tree.len(), 2);

        // Pop default() at [1] - explicitly pushed value should succeed
        let res2 = tree.try_pop().unwrap();
        assert_eq!(res2, Some(u64::default()));
        assert_eq!(tree.len(), 1);

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

    #[test]
fn test_prune_after_set_updates() {
    use typenum::U4; // Small tree for easier tracking

    // 1. Initialize a tree with 4 elements
    // Map will contain: 1 root + 2 internal nodes + 4 leaves
    let mut tree: VecTree<u64, U4> = VecTree::from_vec(vec![10, 20, 30, 40])
        .expect("Failed to create tree");

    let removed = tree.prune();
    assert_eq!(removed, 0, "Freshly built tree should have no orphans");

    let initial_size = tree.kv.len();
    let old_root = tree.root;

    // 2. Update one element
    // This creates a new leaf and new internal nodes leading to the root.
    // The old leaf (10) and its old parent nodes become "orphans".
    tree.set(0, 99).expect("Set failed");

    let size_after_set = tree.kv.len();
    assert!(size_after_set > initial_size, "Map should grow as orphans are left behind");
    assert_ne!(tree.root, old_root, "Root must change after update");

    // 3. Prune the tree
    let removed = tree.prune();
    assert!(removed > 0, "Prune should return the count of removed orphans");

    // 4. Verification
    let final_size = tree.kv.len();

    assert!(
        final_size < size_after_set,
        "Prune should reclaim memory by removing orphaned nodes"
    );

    assert!(
        final_size == initial_size,
        "Prune should shrink the tree to the minimal size(initial_size here since vec_len does not change)"
    );

    assert!(
        !tree.kv.contains_key(&old_root),
        "The old root should be removed"
    );

    assert!(
        tree.kv.contains_key(&tree.root),
        "The new root must be preserved"
    );

    // Verify the un-updated parts are still reachable and preserved
    // The hash for '20' (index 1), '30' (index 2), and '40' (index 3) should still exist.
    let leaf_val_20_hash = 20u64.tree_hash_root();
    assert!(
        tree.kv.contains_key(&leaf_val_20_hash),
        "Unchanged siblings must be preserved"
    );

    assert_eq!(tree.prune(), 0, "Second prune should find nothing to remove");
}

    #[test]
    fn test_prune_preserves_full_tree() {
        // Tree with 3 elements should keep all its nodes after pruning
        let mut tree: VecTree<u64, U8> = VecTree::from_vec(vec![1, 2, 3])
            .expect("Failed to create tree");
        let size_before = tree.kv.len();

        let removed = tree.prune();
        assert_eq!(removed, 0, "Freshly built tree should have no orphans");

        assert_eq!(tree.kv.len(), size_before, "No nodes should be removed from a healthy tree");
    }

    #[test]
    fn test_prune_with_zero_collision() {
        // Create an empty tree
        let mut tree: VecTree<u64, U8> = VecTree::try_new(0).expect("Failed to create empty tree");

        let removed = tree.prune();
        assert_eq!(removed, 0, "Freshly built tree should have no orphans");

        assert!(tree.kv.contains_key(&tree.root), "Root must remain");

        // For collision types, verify that default_for_collision is preserved
        let zero_leaf_hash = zero_tree_root(0);
        if 0u64.tree_hash_root() == zero_leaf_hash {
            assert_eq!(tree.default_for_collision, Some(0u64),
                "Collision default should be preserved after prune");
        }
    }

    #[test]
    fn test_single_push_time_capacity_100000() {
        use std::time::Instant;
        use typenum::U131072; // 2^17 = 131072, smallest power of 2 >= 100000

        // Create a tree with capacity ~100000
        let mut tree = VecTree::<u64, U131072>::try_new(0).unwrap();

        // Measure single push time
        let start = Instant::now();
        tree.push(42u64).unwrap();
        let elapsed = start.elapsed();

        println!("\n========== Single Push Performance Test ==========");
        println!("Tree capacity: 131072 (2^17)");
        println!("Tree height: {}", tree.height);
        println!("Single push time: {:?}", elapsed);
        println!("==================================================\n");

        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_push_batch_basic() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();

        tree.push_batch(&[10, 20, 30]).unwrap();

        assert_eq!(tree.len(), 3);
        assert_eq!(tree.get(0), Some(&10));
        assert_eq!(tree.get(1), Some(&20));
        assert_eq!(tree.get(2), Some(&30));
    }

    #[test]
    fn test_push_batch_empty() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();
        let empty: &[u64] = &[];

        tree.push_batch(empty).unwrap();

        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn test_push_batch_single() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();

        tree.push_batch(&[42]).unwrap();

        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get(0), Some(&42));
    }

    #[test]
    fn test_push_batch_to_capacity() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();

        tree.push_batch(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        assert_eq!(tree.len(), 8);
        for i in 0..8 {
            assert_eq!(tree.get(i), Some(&((i + 1) as u64)));
        }
    }

    #[test]
    fn test_push_batch_overflow() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();

        let result = tree.push_batch(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);

        assert!(result.is_err());
    }

    #[test]
    fn test_push_batch_after_push() {
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();

        tree.push(10).unwrap();
        tree.push(20).unwrap();
        tree.push_batch(&[30, 40, 50]).unwrap();

        assert_eq!(tree.len(), 5);
        assert_eq!(tree.get(0), Some(&10));
        assert_eq!(tree.get(1), Some(&20));
        assert_eq!(tree.get(2), Some(&30));
        assert_eq!(tree.get(3), Some(&40));
        assert_eq!(tree.get(4), Some(&50));
    }

    #[test]
    fn test_push_batch_root_matches_individual_push() {
        // Verify batch produces same root as individual pushes
        let mut tree_batch = VecTree::<u64, U16>::try_new(0).unwrap();
        let mut tree_individual = VecTree::<u64, U16>::try_new(0).unwrap();

        let values: Vec<u64> = (0..10).collect();

        tree_batch.push_batch(&values).unwrap();
        for v in &values {
            tree_individual.push(*v).unwrap();
        }

        assert_eq!(tree_batch.root(), tree_individual.root());
        assert_eq!(tree_batch.ssz_root(), tree_individual.ssz_root());
    }

    #[test]
    fn test_push_batch_perf_comparison() {
        use std::time::Instant;
        use typenum::U131072;

        const BATCH_SIZE: usize = 100;
        let values: Vec<u64> = (0..BATCH_SIZE as u64).collect();

        // Individual pushes
        let mut tree1 = VecTree::<u64, U131072>::try_new(0).unwrap();
        let start1 = Instant::now();
        for v in &values {
            tree1.push(*v).unwrap();
        }
        let elapsed_individual = start1.elapsed();

        // Batch push
        let mut tree2 = VecTree::<u64, U131072>::try_new(0).unwrap();
        let start2 = Instant::now();
        tree2.push_batch(&values).unwrap();
        let elapsed_batch = start2.elapsed();

        // Verify correctness
        assert_eq!(tree1.root(), tree2.root());

        let speedup = elapsed_individual.as_nanos() as f64 / elapsed_batch.as_nanos() as f64;

        println!("\n========== Batch Push Performance Test ==========");
        println!("Batch size: {}", BATCH_SIZE);
        println!("Individual pushes: {:?}", elapsed_individual);
        println!("Batch push:        {:?}", elapsed_batch);
        println!("Speedup:           {:.2}x", speedup);
        println!("=================================================\n");
    }

#[test]
    fn test_update_with_index_and_mutation() {
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();
        let mut set = HashSet::new();
        set.insert(1);
        set.insert(3);
        set.insert(5);

        // Closure now uses both the index and the mutable reference
        tree.update_indices(&set, |idx, val| {
            *val = (idx * 10) as u64;
        }).unwrap();

        assert_eq!(tree.get(1), Some(&10u64));
        assert_eq!(tree.get(3), Some(&30u64));
        assert_eq!(tree.get(5), Some(&50u64));
        assert_eq!(tree.get(0), Some(&0u64)); // Unchanged
    }

    #[test]
    fn test_update_indices_shared_parent_bubble() {
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();

        // Indices 0 and 1 share a direct parent at height 1
        let mut indices = HashSet::new();
        indices.insert(0);
        indices.insert(1);

        tree.update_indices(&indices, |_idx, val| {
            *val = 100;
        }).unwrap();

        assert_eq!(tree.get(0), Some(&100u64));
        assert_eq!(tree.get(1), Some(&100u64));

        // Verify the internal node structure was updated in the KV store
        let root_node = tree.kv.get(&tree.root()).unwrap();
        if let Tree::Node { left, .. } = root_node {
            // "left" is the hash of the subtree containing index 0 and 1
            assert!(tree.kv.contains_key(left), "Intermediate node missing from KV store");
        } else {
            panic!("Root should be a Node");
        }
    }

    #[test]
    fn test_update_indices_collision_u64_recovery() {
        // u64 is a collision type: hash(0) == zero_root(0)
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();
        let mut set = HashSet::new();
        set.insert(0);

        // 1. Change to non-zero
        tree.update_indices(&set, |_, v| *v = 42).unwrap();
        assert_ne!(tree.root(), zero_tree_root(3));

        // 2. Change back to zero (the collision value)
        tree.update_indices(&set, |_, v| *v = 0).unwrap();

        assert_eq!(tree.get(0), Some(&0u64));
        // Tree should mathematically converge back to the empty root
        assert_eq!(tree.root(), zero_tree_root(3));

        // Critical: Check internal storage.
        // For collision types, the zero_root(0) MUST be stored as a Leaf.
        assert!(matches!(tree.kv.get(&zero_tree_root(0)), Some(Tree::Leaf(_))));
    }

    #[test]
    fn test_update_indices_atomicity_and_oob() {
        let mut tree = VecTree::<u64, U8>::try_new(4).unwrap();
        let root_before = tree.root();

        let mut set = HashSet::new();
        set.insert(1);
        set.insert(99); // Out of bounds index

        // This should fail during the pre-validation step
        let result = tree.update_indices(&set, |_, v| *v = 1000);

        assert!(result.is_err());
        // Verify tree state remains untouched
        assert_eq!(tree.root(), root_before);
        assert_eq!(tree.get(1), Some(&0u64));
    }

    #[test]
    fn test_update_indices_consistency_vs_set() {
        let mut tree_batch = VecTree::<u64, U8>::try_new(8).unwrap();
        let mut tree_single = VecTree::<u64, U8>::try_new(8).unwrap();

        let indices = vec![0, 2, 4, 6];
        let mut set = HashSet::new();

        for &i in &indices {
            set.insert(i);
            tree_single.set(i, (i + 1) as u64).unwrap();
        }

        // Apply same updates via batch
        tree_batch.update_indices(&set, |idx, val| {
            *val = (idx + 1) as u64;
        }).unwrap();

        assert_eq!(tree_batch.root(), tree_single.root(), "Batch update produced different root than sequential set()");
    }

    #[test]
    fn test_update_indices_always_stores_leaf() {
        // Verify that update_indices always stores Tree::Leaf, never Tree::Zero(0)
        // for actual values produced by the closure, even for default values
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();
        let mut set = HashSet::new();
        set.insert(0);
        set.insert(1);

        // Update to non-default values
        tree.update_indices(&set, |idx, val| {
            *val = (idx + 10) as u64;
        }).unwrap();

        // Check that leaves are stored as Leaf nodes
        let hash_10 = 10u64.tree_hash_root();
        let hash_11 = 11u64.tree_hash_root();
        assert!(matches!(tree.kv.get(&hash_10), Some(Tree::Leaf(v)) if *v == 10));
        assert!(matches!(tree.kv.get(&hash_11), Some(Tree::Leaf(v)) if *v == 11));

        // Update back to default (0) - even for collision types, should store Leaf
        tree.update_indices(&set, |_, val| {
            *val = 0;
        }).unwrap();

        // For u64 collision type, zero_tree_root(0) should map to Tree::Leaf(0)
        let zero_hash = zero_tree_root(0);
        assert!(matches!(tree.kv.get(&zero_hash), Some(Tree::Leaf(v)) if *v == 0),
            "update_indices must store Tree::Leaf even for default values");
    }

    // ==================== Collision Mechanism Coverage Tests ====================

    #[test]
    fn test_collision_get_implicit_zeros() {
        // Core collision test: Reading uninitialized positions should return Some(&0) for u64
        let tree = VecTree::<u64, U8>::try_new(8).unwrap();

        // All positions should return Some(&0) even though nothing was set
        for i in 0..8 {
            assert_eq!(tree.get(i), Some(&0u64),
                "Collision type should return default for uninitialized position {}", i);
        }

        // Verify the collision default is set
        assert_eq!(tree.default_for_collision, Some(0u64),
            "Collision default must be set for implicit zero reads");
    }

    #[test]
    fn test_collision_pop_with_holes() {
        // Test popping holes on collision types returns defaults correctly
        let mut tree = VecTree::<u64, U8>::try_new(3).unwrap();

        // Set only middle element
        tree.set(1, 42).unwrap();

        // Pop position 2 (a hole) - should return default (0)
        assert_eq!(tree.pop(), Some(0u64));
        assert_eq!(tree.len(), 2);

        // Pop position 1 (actual value) - should return 42
        assert_eq!(tree.pop(), Some(42u64));
        assert_eq!(tree.len(), 1);

        // Pop position 0 (a hole) - should return default (0)
        assert_eq!(tree.pop(), Some(0u64));
        assert_eq!(tree.len(), 0);

        // Verify collision default still exists after all pops
        assert_eq!(tree.default_for_collision, Some(0u64),
            "Collision default must survive pop operations");
    }

    #[test]
    fn test_collision_explicit_default_vs_hole() {
        // Test that explicitly setting default value vs hole are indistinguishable
        let mut tree1 = VecTree::<u64, U8>::try_new(2).unwrap();
        let tree2 = VecTree::<u64, U8>::try_new(2).unwrap();

        // tree1: explicitly set to default
        tree1.set(0, 0).unwrap();
        tree1.set(1, 0).unwrap();

        // tree2: leave as holes (implicit defaults)
        // Nothing set

        // Both should have the same root (SSZ semantics)
        assert_eq!(tree1.root(), tree2.root(),
            "Explicit defaults and holes should produce same merkle root");

        // Both should read the same
        assert_eq!(tree1.get(0), Some(&0u64));
        assert_eq!(tree2.get(0), Some(&0u64));
        assert_eq!(tree1.get(1), Some(&0u64));
        assert_eq!(tree2.get(1), Some(&0u64));
    }

    #[test]
    fn test_collision_restore_preserves_collision_leaf() {
        // Test that restore() correctly rebuilds collision leaf
        let mut original = VecTree::<u64, U8>::try_new(4).unwrap();
        original.set(2, 100).unwrap();

        // Create a database (HashMap) to save to
        let mut db = HashMap::new();
        original.save(|hash, tree| {
            db.insert(*hash, tree.clone());
            Ok::<(), ()>(())
        }).unwrap();

        // Restore from the database
        let restored = VecTree::<u64, U8>::restore(
            original.root(),
            original.len() as u64,
            |hash| db.get(hash).cloned()
        ).unwrap();

        // Verify collision default is set
        assert_eq!(restored.default_for_collision, Some(0u64),
            "Restored tree must have collision default set");

        // Verify we can read implicit zeros
        assert_eq!(restored.get(0), Some(&0u64));
        assert_eq!(restored.get(1), Some(&0u64));
        assert_eq!(restored.get(2), Some(&100u64));
        assert_eq!(restored.get(3), Some(&0u64));
    }

    #[test]
    fn test_collision_clear_reinitializes_correctly() {
        // Test that clear() returns tree to initial state
        let mut tree = VecTree::<u64, U8>::try_new(4).unwrap();
        tree.push(10).unwrap();
        tree.push(20).unwrap();

        tree.clear();

        // After clear, tree is empty and back to initial state
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.root(), zero_tree_root(tree.height));

        // Should be able to use the tree normally after clear
        tree.push(30).unwrap();
        assert_eq!(tree.get(0), Some(&30u64));
    }

    #[test]
    fn test_collision_mixed_operations_sparse_tree() {
        // Complex scenario: mix of sets, gets, pops, pushes on sparse tree
        let mut tree = VecTree::<u64, U8>::try_new(7).unwrap();

        // Set sparse values
        tree.set(2, 22).unwrap();
        tree.set(5, 55).unwrap();
        tree.set(6, 66).unwrap();

        // Read holes (should return defaults)
        assert_eq!(tree.get(0), Some(&0u64));
        assert_eq!(tree.get(1), Some(&0u64));
        assert_eq!(tree.get(3), Some(&0u64));
        assert_eq!(tree.get(4), Some(&0u64));

        // Read actual values
        assert_eq!(tree.get(2), Some(&22u64));
        assert_eq!(tree.get(5), Some(&55u64));
        assert_eq!(tree.get(6), Some(&66u64));

        // Overwrite a position with default
        tree.set(5, 0).unwrap();
        assert_eq!(tree.get(5), Some(&0u64));

        // Push to extend length (now length is 8)
        tree.push(77).unwrap();
        assert_eq!(tree.get(7), Some(&77u64));

        // Pop back
        assert_eq!(tree.pop(), Some(77u64));

        // Verify collision default still intact
        assert_eq!(tree.default_for_collision, Some(0u64));
    }

    #[test]
    fn test_collision_prune_after_multiple_ops() {
        // Verify collision leaf survives prune after various operations
        let mut tree = VecTree::<u64, U8>::try_new(4).unwrap();

        // Multiple operations
        tree.push(10).unwrap();
        tree.push(20).unwrap();
        tree.pop();
        tree.push(30).unwrap();
        tree.set(0, 0).unwrap(); // Set to default

        tree.prune();

        // Collision default must still be set
        assert_eq!(tree.default_for_collision, Some(0u64),
            "Collision default must be preserved");

        // Should still be able to read defaults
        assert_eq!(tree.get(0), Some(&0u64));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_height_zero_tree_collision() {
        // Tree with capacity 1 (height 0) - edge case
        use typenum::U1;
        let mut tree = VecTree::<u64, U1>::try_new(1).unwrap();

        // The root IS the leaf for height 0
        assert_eq!(tree.height, 0);

        // Should have collision default set
        assert_eq!(tree.default_for_collision, Some(0u64));

        // Get should work
        assert_eq!(tree.get(0), Some(&0u64));

        // Set and get
        tree.set(0, 99).unwrap();
        assert_eq!(tree.get(0), Some(&99u64));
    }

    #[test]
    fn test_update_indices_height_zero() {
        use typenum::U1;
        let mut tree = VecTree::<u64, U1>::try_new(1).unwrap();

        let mut indices = HashSet::new();
        indices.insert(0);

        tree.update_indices(&indices, |_, val| {
            *val = 42;
        }).unwrap();

        assert_eq!(tree.get(0), Some(&42u64));
        // Root should be updated directly
        assert_eq!(tree.root(), 42u64.tree_hash_root());
    }

    #[test]
    fn test_update_indices_all_indices() {
        // Update every single index in the tree
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();

        let indices: HashSet<usize> = (0..8).collect();
        tree.update_indices(&indices, |idx, val| {
            *val = (idx * 10) as u64;
        }).unwrap();

        // Verify all values
        for i in 0..8 {
            assert_eq!(tree.get(i), Some(&((i * 10) as u64)));
        }
    }

    #[test]
    fn test_update_indices_interleaved_with_set() {
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();

        // First update_indices
        let mut indices = HashSet::new();
        indices.insert(0);
        indices.insert(2);
        tree.update_indices(&indices, |idx, val| {
            *val = idx as u64;
        }).unwrap();

        // Then manual set
        tree.set(1, 100).unwrap();
        tree.set(3, 300).unwrap();

        // Another update_indices
        let mut indices2 = HashSet::new();
        indices2.insert(0);
        indices2.insert(1);
        tree.update_indices(&indices2, |_, val| {
            *val += 1000;
        }).unwrap();

        // Verify final state
        assert_eq!(tree.get(0), Some(&1000u64)); // 0 + 1000
        assert_eq!(tree.get(1), Some(&1100u64)); // 100 + 1000
        assert_eq!(tree.get(2), Some(&2u64));    // unchanged
        assert_eq!(tree.get(3), Some(&300u64));  // unchanged
    }

    #[test]
    fn test_update_indices_empty_to_default() {
        // Update indices to explicitly set defaults (collision edge case)
        let mut tree = VecTree::<u64, U8>::try_new(8).unwrap();

        let indices: HashSet<usize> = (0..4).collect();
        tree.update_indices(&indices, |_, val| {
            *val = 0;
        }).unwrap();

        // Verify all positions read as default
        for i in 0..4 {
            assert_eq!(tree.get(i), Some(&0u64));
        }

        // Tree root should equal zero_tree_root (SSZ: defaults hash to empty tree)
        assert_eq!(tree.root(), zero_tree_root(3));
    }

    #[test]
    fn test_collision_multiple_pops_sparse() {
        // Pop multiple times from sparse tree with collision type
        let mut tree = VecTree::<u64, U8>::try_new(5).unwrap();

        // Only set position 2
        tree.set(2, 42).unwrap();

        // Pop 4 (hole) -> default
        assert_eq!(tree.pop(), Some(0u64));
        assert_eq!(tree.len(), 4);

        // Pop 3 (hole) -> default
        assert_eq!(tree.pop(), Some(0u64));
        assert_eq!(tree.len(), 3);

        // Pop 2 (value) -> 42
        assert_eq!(tree.pop(), Some(42u64));
        assert_eq!(tree.len(), 2);

        // Pop 1 (hole) -> default
        assert_eq!(tree.pop(), Some(0u64));
        assert_eq!(tree.len(), 1);

        // Pop 0 (hole) -> default
        assert_eq!(tree.pop(), Some(0u64));
        assert_eq!(tree.len(), 0);

        // Verify collision default still exists
        assert_eq!(tree.default_for_collision, Some(0u64));
    }

    #[test]
    fn test_try_pop_preserves_values() {
        // Verify try_pop works correctly with actual values
        let mut tree = VecTree::<u64, U8>::try_new(0).unwrap();

        // Push actual values
        tree.push(10).unwrap();
        tree.push(20).unwrap();
        tree.push(30).unwrap();

        // Pop them back
        assert_eq!(tree.try_pop(), Ok(Some(30)));
        assert_eq!(tree.try_pop(), Ok(Some(20)));
        assert_eq!(tree.try_pop(), Ok(Some(10)));
        assert_eq!(tree.try_pop(), Ok(None));
    }

    #[test]
    fn test_from_vec_collision_type() {
        // Test from_vec with collision type includes collision leaf
        let elements = vec![10u64, 0, 20, 0, 30];
        let tree = VecTree::<u64, U8>::from_vec(elements).unwrap();

        // Verify values
        assert_eq!(tree.get(0), Some(&10u64));
        assert_eq!(tree.get(1), Some(&0u64));
        assert_eq!(tree.get(2), Some(&20u64));
        assert_eq!(tree.get(3), Some(&0u64));
        assert_eq!(tree.get(4), Some(&30u64));

        // Verify collision default is set
        assert_eq!(tree.default_for_collision, Some(0u64));

        // Reading beyond length returns None (bounds check)
        assert_eq!(tree.len(), 5);
        assert_eq!(tree.get(5), None);
        assert_eq!(tree.get(6), None);
        assert_eq!(tree.get(7), None);
    }

}
