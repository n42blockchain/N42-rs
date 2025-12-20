// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! n42 primitives

mod snapshot;
pub use snapshot::APosConfig;
pub use snapshot::Snapshot;

mod validator;
pub use validator::*;

mod beacon;
pub use beacon::*;
//pub use beacon::{BeaconState, BeaconBlock, BeaconStateChangeset, BeaconBlockChangeset, VoluntaryExit, VoluntaryExitWithSig, Epoch};

mod activation_queue;
mod safe_aitrh;

mod committee_cache;
pub use committee_cache::CommitteeCache;

mod attestation_duty;
mod beacon_committee;
mod shuffle_list;

pub type Hash256 = alloy_primitives::B256;
pub type Slot = u64;
pub type CommitteeIndex = u64;
