use std::fmt::Debug;
use std::hash::Hash;
use tree_hash::TreeHash;
use crate::Hash256;
use crate::beacon_state::{Error, EthSpec};
use std::marker::PhantomData;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;
use ssz_derive::{Decode, Encode};
use std::borrow::Cow;
use serde::de::DeserializeOwned;
use ssz::{Decode, Encode};


/// `ExecPayload` functionality the requires ownership.
pub trait OwnedExecPayload<E: EthSpec>:
ExecPayload<E>
+ Default
+ Serialize
+ DeserializeOwned
+ Encode
+ Decode
+ for<'a> arbitrary::Arbitrary<'a>
+ 'static
{
}

pub trait AbstractExecPayload<E: EthSpec>:
ExecPayload<E>
+ Sized
+ From<ExecutionPayload<E>>
+ TryFrom<ExecutionPayloadHeader<E>>
{
    type Ref<'a>: ExecPayload<E>
    + Copy
    // + From<&'a Self::Bellatrix>
    // + From<&'a Self::Capella>
    // + From<&'a Self::Deneb>
    + From<&'a Self::Electra>
    + From<&'a Self::Fulu>;

    // type Bellatrix: OwnedExecPayload<E>
    // + Into<Self>
    // + for<'a> From<Cow<'a, ExecutionPayloadBellatrix<E>>>
    // + TryFrom<ExecutionPayloadHeaderBellatrix<E>>;
    // type Capella: OwnedExecPayload<E>
    // + Into<Self>
    // + for<'a> From<Cow<'a, ExecutionPayloadCapella<E>>>
    // + TryFrom<ExecutionPayloadHeaderCapella<E>>;
    // type Deneb: OwnedExecPayload<E>
    // + Into<Self>
    // + for<'a> From<Cow<'a, ExecutionPayloadDeneb<E>>>
    // + TryFrom<ExecutionPayloadHeaderDeneb<E>>;
    type Electra: OwnedExecPayload<E>
    + Into<Self>
    + for<'a> From<Cow<'a, ExecutionPayloadElectra<E>>>
    + TryFrom<ExecutionPayloadHeaderElectra<E>>;
    type Fulu: OwnedExecPayload<E>
    + Into<Self>
    + for<'a> From<Cow<'a, ExecutionPayloadFulu<E>>>
    + TryFrom<ExecutionPayloadHeaderFulu<E>>;
}

/// A trait representing behavior of an `ExecutionPayload` that either has a full list of transactions
/// or a transaction hash in it's place.
pub trait ExecPayload<E: EthSpec>: Debug + Clone + PartialEq + Hash + TreeHash + Send {
    fn withdrawals_root(&self) -> Result<Hash256, Error>;

}

#[superstruct(
    variants(Electra, Fulu),
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
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec")
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
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
    #[tree_hash(skip_hashing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

#[superstruct(
    variants(Electra, Fulu),
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
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
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
    #[tree_hash(skip_hashing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

// #[superstruct(
//     variants(Electra, Fulu),
//     variant_attributes(
//         derive(
//             Debug,
//             Clone,
//             Serialize,
//             Deserialize,
//             Encode,
//             Decode,
//             TreeHash,
//             Derivative,
//             arbitrary::Arbitrary,
//         ),
//         derivative(PartialEq, Hash(bound = "E: EthSpec")),
//         serde(bound = "E: EthSpec", deny_unknown_fields),
//         arbitrary(bound = "E: EthSpec"),
//         ssz(struct_behaviour = "transparent"),
//     ),
//     ref_attributes(
//         derive(Debug, Derivative, TreeHash),
//         derivative(PartialEq, Hash(bound = "E: EthSpec")),
//         tree_hash(enum_behaviour = "transparent"),
//     ),
//     map_into(ExecutionPayload),
//     map_ref_into(ExecutionPayloadRef),
//     cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
//     partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
// )]
// #[derive(Debug, Clone, Serialize, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary)]
// #[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
// #[serde(bound = "E: EthSpec")]
// #[arbitrary(bound = "E: EthSpec")]
// #[tree_hash(enum_behaviour = "transparent")]
pub struct FullPayload<E: EthSpec> {
    _phantom: PhantomData<E>,
}