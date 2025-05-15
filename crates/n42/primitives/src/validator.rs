use serde::{Deserialize, Serialize};
use alloy_primitives::Address;
#[derive(Serialize, Debug, Deserialize)]
pub struct Validator {
    pub index: u64,
    pub balance: u64,
    pub is_active: bool,
    pub is_slashed: bool,
    pub is_withdrawal_allowed: bool,
}
#[derive(Serialize, Debug, Deserialize)]
pub struct  ValidatorBeforeTx{
    pub address: Address,
    pub info: Option<Validator>,
}
#[derive(Debug)]
pub struct ValidatorChangeset{
    pub validators: Vec<(Address,Option<Validator>)>,
}