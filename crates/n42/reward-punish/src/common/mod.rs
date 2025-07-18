mod single_pass;
mod epoch_processing_summary;
pub mod progressive_balance_cache;
mod balance;
pub mod participation_flags;
mod per_slot_processing;
mod per_epoch_processing;
pub mod sync_committee;
pub mod epoch_cache;
mod fixed_bytes;

pub type Hash256 = fixed_bytes::Hash256;
pub type Uint256 = fixed_bytes::Uint256;
pub type Address = fixed_bytes::Address;

pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;
pub const TIMELY_SOURCE_WEIGHT: u64 = 14;
pub const TIMELY_TARGET_WEIGHT: u64 = 26;
pub const TIMELY_HEAD_WEIGHT: u64 = 14;
pub const TIMELY_ALL_WEIGHT: u64 = 64;
pub const NUM_FLAG_INDICES: usize = 1;
pub const WEIGHT_DENOMINATOR: u64 = 64;
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;

pub const PARTICIPATION_FLAG_WEIGHTS: [u64; NUM_FLAG_INDICES] = [
    // TIMELY_SOURCE_WEIGHT,
    // TIMELY_TARGET_WEIGHT,
    // TIMELY_HEAD_WEIGHT,
    TIMELY_ALL_WEIGHT,
];