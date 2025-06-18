//! The `Slot` and `Epoch` types are defined as new types over u64 to enforce type-safety between
//! the two types.
//!
//! `Slot` and `Epoch` have implementations which permit conversion, comparison and math operations
//! between each and `u64`, however specifically not between each other.
//!
//! All math operations on `Slot` and `Epoch` are saturating, they never wrap.
//!
//! It would be easy to define `PartialOrd` and other traits generically across all types which
//! implement `Into<u64>`, however this would allow operations between `Slots` and `Epochs` which
//! may lead to programming errors which are not detected by the compiler.

use crate::safe_aitrh::{SafeArith, Result, ArithError};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use std::fmt;
use std::hash::Hash;
use alloy_primitives::private::arbitrary;


#[derive(
    arbitrary::Arbitrary, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Slot(#[serde(with = "serde_utils::quoted_u64")] u64);

#[derive(
    arbitrary::Arbitrary, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Epoch(#[serde(with = "serde_utils::quoted_u64")] u64);

macro_rules! impl_from_into_u64 {
    ($main: ident) => {
        impl From<u64> for $main {
            fn from(n: u64) -> $main {
                $main(n)
            }
        }

        impl From<$main> for u64 {
            fn from(from: $main) -> u64 {
                from.0
            }
        }

        impl $main {
            pub fn as_u64(&self) -> u64 {
                self.0
            }
        }
    };
}

macro_rules! impl_from_into_usize {
    ($main: ident) => {
        impl From<usize> for $main {
            fn from(n: usize) -> $main {
                $main(n as u64)
            }
        }

        impl From<$main> for usize {
            fn from(from: $main) -> usize {
                from.0 as usize
            }
        }

        impl $main {
            pub fn as_usize(&self) -> usize {
                self.0 as usize
            }
        }
    };
}

macro_rules! impl_safe_arith {
    ($type: ident, $rhs_ty: ident) => {
        impl SafeArith<$rhs_ty> for $type {
            const ZERO: Self = $type::new(0);
            const ONE: Self = $type::new(1);

            fn safe_add(&self, other: $rhs_ty) -> Result<Self> {
                self.0
                    .checked_add(other.into())
                    .map(Self::new)
                    .ok_or(ArithError::Overflow)
            }

            fn safe_sub(&self, other: $rhs_ty) -> Result<Self> {
                self.0
                    .checked_sub(other.into())
                    .map(Self::new)
                    .ok_or(ArithError::Overflow)
            }

            fn safe_div(&self, other: $rhs_ty) -> Result<Self> {
                self.0
                    .checked_div(other.into())
                    .map(Self::new)
                    .ok_or(ArithError::DivisionByZero)
            }

            fn safe_rem(&self, other: $rhs_ty) -> Result<Self> {
                self.0
                    .checked_rem(other.into())
                    .map(Self::new)
                    .ok_or(ArithError::DivisionByZero)
            }
        }
    };
}

macro_rules! impl_debug {
    ($type: ident) => {
        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($type), self.0)
            }
        }
    };
}

macro_rules! impl_ssz {
    ($type: ident) => {
        impl Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                <u64 as Encode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <u64 as Encode>::ssz_fixed_len()
            }

            fn ssz_bytes_len(&self) -> usize {
                0_u64.ssz_bytes_len()
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                self.0.ssz_append(buf)
            }
        }

        impl Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                <u64 as Decode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <u64 as Decode>::ssz_fixed_len()
            }

            fn from_ssz_bytes(bytes: &[u8]) -> core::result::Result<Self, DecodeError> {
                Ok($type(u64::from_ssz_bytes(bytes)?))
            }
        }

        impl tree_hash::TreeHash for $type {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::Basic
            }

            fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
                self.0.tree_hash_packed_encoding()
            }

            fn tree_hash_packing_factor() -> usize {
                32usize.wrapping_div(8)
            }

            fn tree_hash_root(&self) -> tree_hash::Hash256 {
                tree_hash::Hash256::from_slice(&int_to_fixed_bytes32(self.0))
            }
        }

        // impl SignedRoot for $type {}
    };
}

macro_rules! impl_common {
    ($type: ident) => {
        impl_from_into_u64!($type);
        impl_from_into_usize!($type);
        impl_safe_arith!($type, $type);
        impl_safe_arith!($type, u64);
        impl_debug!($type);
        impl_ssz!($type);
    };
}


impl_common!(Slot);
impl_common!(Epoch);

impl Slot {
    pub const fn new(slot: u64) -> Slot {
        Slot(slot)
    }

    pub fn epoch(self, slots_per_epoch: u64) -> Epoch {
        Epoch::new(self.0)
            .safe_div(slots_per_epoch)
            .expect("slots_per_epoch is not 0")
    }
}

impl Epoch {
    pub const fn new(epoch: u64) -> Epoch {
        Epoch(epoch)
    }
}

/// Returns `int` as little-endian bytes with a length of 32.
pub fn int_to_fixed_bytes32(int: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    let int_bytes = int.to_le_bytes();
    bytes[0..int_bytes.len()].copy_from_slice(&int_bytes);
    bytes
}
