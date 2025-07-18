use std::hash::{Hash, Hasher};
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use ssz_types::{BitList, BitVector};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;
use serde::{Deserialize, Serialize};

use crate::spec::EthSpec;
use crate::attestation_data::AttestationData;



#[derive(Debug, PartialEq)]
pub enum Error {
    SszTypesError(ssz_types::Error),
    AlreadySigned(usize),
    IncorrectStateVariant,
    InvalidCommitteeLength,
    InvalidCommitteeIndex,
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Self {
        Error::SszTypesError(e)
    }
}
#[superstruct(
    variants(Base, Electra),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Decode,
            Encode,
            Derivative,
            // arbitrary::Arbitrary,
            TreeHash,
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        // arbitrary(bound = "E: EthSpec"),
    ),
    ref_attributes(derive(TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(
    Debug,
    Clone,
    Serialize,
    TreeHash,
    Encode,
    Derivative,
    Deserialize,
    // arbitrary::Arbitrary,
    PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
// #[arbitrary(bound = "E: EthSpec")]
pub struct Attestation<E: EthSpec> {
    #[superstruct(only(Base), partial_getter(rename = "aggregation_bits_base"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerSlot>,
    pub data: AttestationData,

    // pub signature: AggregateSignature,
    #[superstruct(only(Electra))]
    pub committee_bits: BitVector<E::MaxCommitteesPerSlot>,
}

impl<E: EthSpec> Hash for Attestation<E> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        match self {
            Attestation::Base(att) => att.hash(state),
            Attestation::Electra(att) => att.hash(state),
        }
    }
}