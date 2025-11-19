//! n42 primitives

mod snapshot;
pub use snapshot::Snapshot;
pub use snapshot::APosConfig;

mod validator;
pub use validator::*;

mod beacon;
pub use beacon::*;
//pub use beacon::{BeaconState, BeaconBlock, BeaconStateChangeset, BeaconBlockChangeset, VoluntaryExit, VoluntaryExitWithSig, Epoch};

mod safe_aitrh;
mod activation_queue;
mod committee_cache;
mod shuffle_list;
mod beacon_committee;
mod attestation_duty;

pub type Hash256 = alloy_primitives::B256;
pub type Slot = u64;
pub type CommitteeIndex = u64;

pub const N42_MIN_BASE_FEE: u64 = 0x5f5e100; // 0.1 Gwei
