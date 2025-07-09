// mod reward;
mod reward_and_penalties;
mod per_epoch_processing;
mod validator_statuses;
mod base;
mod errors;
mod arith;
mod slashings;
mod spec;
mod beaconstate;
mod slot_epoch_macros;
mod slot_epoch;
mod pending_attestation;
mod attestation_data;
mod signing_data;
mod slot_data;
mod relative_epoch;
mod beacon_committee;
mod committee_cache;

pub use tree_hash::Hash256;
pub use ssz_types::{typenum, typenum::Unsigned, BitList, BitVector, FixedVector, VariableList};
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
