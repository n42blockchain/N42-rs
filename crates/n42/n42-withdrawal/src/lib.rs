pub mod models;
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

pub type Hash256 = alloy_primitives::B256;



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
