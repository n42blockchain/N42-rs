use alloy_primitives::{Address, private::arbitrary, };
use tree_hash_derive::TreeHash;
pub use milhouse::{interface::Interface, List, Vector};
use std::fmt::Debug;
use std::hash::Hash;
use serde::{Deserialize, Serialize};
use ssz_types::VariableList;
use ssz_derive::{Decode, Encode};
use crate::beacon_state::EthSpec;
use crate::slot_epoch::Epoch;
use crate::Hash256;

pub type Withdrawals<E> = VariableList<Withdrawal, <E as EthSpec>::MaxWithdrawalsPerPayload>;

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Withdrawal {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::address_hex")]
    pub address: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

/// Casper FFG checkpoint, used in attestations.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Hash256,
}