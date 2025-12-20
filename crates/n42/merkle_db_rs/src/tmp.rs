// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

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
