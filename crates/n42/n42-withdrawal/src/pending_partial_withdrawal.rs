// use crate::test_utils::TestRandom;
use crate::slot_epoch::Epoch;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;
use alloy_primitives::{
    private::{
        arbitrary,
        serde::{Deserialize, Serialize}, }, };

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct PendingPartialWithdrawal {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}