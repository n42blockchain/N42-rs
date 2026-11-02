// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! n42 primitives

mod snapshot;
pub use snapshot::APosConfig;
pub use snapshot::Snapshot;
pub use snapshot::Tally;
pub use snapshot::Vote;

mod validator;
pub use validator::*;

/// Beacon-chain types and the beacon state transition.
pub mod beacon;
/// Database codecs for the beacon types.
pub mod db_codec;
pub use beacon::*;

mod activation_queue;
/// Overflow-checked arithmetic.
pub mod safe_arith;
pub use safe_arith::{ArithError, SafeArith, SafeArithIter};

mod committee_cache;
pub use committee_cache::CommitteeCache;

mod attestation_duty;
mod beacon_committee;
/// The swap-or-not committee shuffle.
pub mod shuffle_list;

#[cfg(test)]
mod test_util;

/// 256-bit hash.
pub type Hash256 = alloy_primitives::B256;
/// Slot number.
pub type Slot = u64;
/// Index of a committee within a slot.
pub type CommitteeIndex = u64;
