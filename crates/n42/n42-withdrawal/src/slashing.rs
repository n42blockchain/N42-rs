use std::slice::Iter;
use superstruct::superstruct;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use derivative::Derivative;
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;
use crate::beacon_state::EthSpec;
use crate::crypto::fake_crypto_implementations::AggregateSignature;
use crate::signature::AttestationData;


#[derive(Debug, PartialEq, Clone)]
pub enum Error {

}

#[superstruct(
    variants(Electra),
    variant_attributes(
        derive(
            Derivative, Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, arbitrary::Arbitrary
        ),
        derivative(PartialEq, Eq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec"),
        arbitrary(bound = "E: EthSpec")
    ),
    ref_attributes(derive(Debug))
)]
#[derive(
    Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct AttesterSlashing<E: EthSpec> {
    #[superstruct(flatten)]
    pub attestation_1: IndexedAttestation<E>,
    #[superstruct(flatten)]
    pub attestation_2: IndexedAttestation<E>,
}

impl<'a, E: EthSpec> AttesterSlashingRef<'a, E> {
    pub fn attestation_1(&self) -> IndexedAttestationRef<'a, E> {
        match self {
            AttesterSlashingRef::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_1)
            }
        }
    }

    pub fn attestation_2(&self) -> IndexedAttestationRef<'a, E> {
        match self {
            AttesterSlashingRef::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_2)
            }
        }
    }
}

/// Details an attestation that can be slashable.
/// To be included in an `AttesterSlashing`.
#[superstruct(
    variants(Electra),
    variant_attributes(
        derive(
            Debug, Clone, Serialize, Deserialize, Decode, Encode, Derivative, arbitrary::Arbitrary, TreeHash,
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
    )
)]
#[derive(
    Debug, Clone, Serialize, TreeHash, Encode, Derivative, Deserialize, arbitrary::Arbitrary, PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct IndexedAttestation<E: EthSpec> {
    pub data: AttestationData,
    pub signature: AggregateSignature,
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: VariableList<u64, E::MaxValidatorsPerSlot>,
}

impl<E: EthSpec> IndexedAttestationRef<'_, E> {
    pub fn attesting_indices_len(&self) -> usize {
        match self {
            IndexedAttestationRef::Electra(att) => att.attesting_indices.len(),
        }
    }

    pub fn attesting_indices_iter(&self) -> Iter<'_, u64> {
        match self {
            IndexedAttestationRef::Electra(att) => att.attesting_indices.iter(),
        }
    }
}