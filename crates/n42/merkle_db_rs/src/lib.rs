// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

use ssz::{Decode, Encode};
use tree_hash::TreeHash;

pub mod error;
pub mod tree;
pub mod utils;

#[cfg(feature = "debug")]
pub trait Value:
    Encode + Decode + TreeHash + PartialEq + Clone + Default + std::fmt::Debug
{
}

#[cfg(feature = "debug")]
impl<T> Value for T where
    T: Encode + Decode + TreeHash + PartialEq + Clone + Default + std::fmt::Debug
{
}

#[cfg(not(feature = "debug"))]
pub trait Value: Encode + Decode + TreeHash + PartialEq + Clone + Default {}

#[cfg(not(feature = "debug"))]
impl<T> Value for T where T: Encode + Decode + TreeHash + PartialEq + Clone + Default {}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
