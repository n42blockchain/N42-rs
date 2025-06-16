use std::fmt::Debug;
use std::hash::Hash;
use alloy_primitives::private::arbitrary;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use test_random_derive::TestRandom;
use crate::Hash256;
use crate::withdrawal::EthSpec;
use crate::beacon_state::Error;

pub trait AbstractExecPayload<E: EthSpec>:
ExecPayload<E>
+ Sized
+ From<ExecutionPayload<E>>
+ TryFrom<ExecutionPayloadHeader<E>>
{
    type Ref<'a>: ExecPayload<E>
    + Copy;
}

/// A trait representing behavior of an `ExecutionPayload` that either has a full list of transactions
/// or a transaction hash in it's place.
pub trait ExecPayload<E: EthSpec>: Debug + Clone + PartialEq + Hash + TreeHash + Send {
    fn withdrawals_root(&self) -> Result<Hash256, Error>;

}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            // TestRandom,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec")
    ),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    map_into(FullPayload, BlindedPayload),
    map_ref_into(ExecutionPayloadHeader)
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayload<E: EthSpec> {

}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            // TestRandom,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec")
    ),
    ref_attributes(
        derive(PartialEq, TreeHash, Debug),
        tree_hash(enum_behaviour = "transparent")
    ),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    map_ref_into(ExecutionPayloadHeader)
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct ExecutionPayloadHeader<E: EthSpec> {

}