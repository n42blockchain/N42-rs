#![allow(elided_lifetimes_in_paths)]
#![allow(missing_docs)]

#[macro_use]
pub mod macros;
pub mod withdrawal;
pub mod per_block_processing;
pub mod error;
pub mod beacon_state;
pub mod crypto;
pub mod pending_partial_withdrawal;
pub mod safe_aitrh;
pub mod validators;
pub mod chain_spec;
pub mod payload;
pub mod fork_name;
pub mod slot_epoch;
pub mod exit_cache;
pub mod beacon_block_body;
pub mod verify_deposit;
pub mod signature;
pub mod verify_exit;
pub mod slashing;
pub mod signature_set;

// pub type Hash256 = alloy_primitives::B256;
pub use tree_hash::Hash256;
pub type H256 = tree_hash::Hash256;
pub type Address = alloy_primitives::Address;
pub type CommitteeIndex = u64;
