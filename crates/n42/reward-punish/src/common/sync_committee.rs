use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use tree_hash_derive::TreeHash;
// use n42_withdrawals::beacon_state::EthSpec;
use crate::spec::EthSpec;
use n42_withdrawals::crypto::PublicKeyBytes;

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, arbitrary::Arbitrary,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
pub struct SyncCommittee<E: EthSpec> {
    pub pubkeys: FixedVector<PublicKeyBytes, E::SyncCommitteeSize>,
    pub aggregate_pubkey: PublicKeyBytes,
}