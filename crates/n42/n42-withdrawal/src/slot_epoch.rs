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


#[cfg(feature = "legacy-arith")]
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, Sub, SubAssign};

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

macro_rules! impl_safe_arith {
    ($type: ident, $rhs_ty: ident) => {
        impl SafeArith<$rhs_ty> for $type {
            const ZERO: Self = $type::new(0);
            const ONE: Self = $type::new(1);

            fn safe_div(&self, other: $rhs_ty) -> Result<Self> {
                self.0
                    .checked_div(other.into())
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

macro_rules! impl_common {
    ($type: ident) => {
        impl_safe_arith!($type, $type);
        impl_safe_arith!($type, u64);
        impl_debug!($type);
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


