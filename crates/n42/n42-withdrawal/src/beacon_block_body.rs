use std::iter;
use derivative::Derivative;
use superstruct::superstruct;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use metastruct::metastruct;
use ssz_types::{BitList, BitVector, VariableList};
use crate::{Hash256, Address};
use crate::payload::{AbstractExecPayload, FullPayload};
use crate::beacon_state::{Error, EthSpec};
use crate::chain_spec::ChainSpec;
use crate::crypto::{PublicKeyBytes, SignatureBytes, BlsSignature as Signature};
use crate::crypto::fake_crypto_implementations::AggregateSignature;
use crate::fork_name::ForkName;
use crate::signature::{AttestationData, ProposerSlashing, SyncAggregate, SignedBlsToExecutionChange, InconsistentFork};
use crate::slashing::{AttesterSlashingElectra, AttesterSlashingRef};
use crate::slot_epoch::Slot;
use crate::withdrawal::{Deposit, SignedRoot, SignedVoluntaryExit};

#[superstruct(
    variants(Electra),
    variant_attributes(
        derive(
            Debug, Clone, Serialize, Deserialize, Decode, Encode, Derivative, arbitrary::Arbitrary, TreeHash,
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
    ),
    ref_attributes(derive(TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(
    Debug, Clone, Serialize, TreeHash, Encode, Derivative, Deserialize, arbitrary::Arbitrary, PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct Attestation<E: EthSpec> {
    pub data: AttestationData,
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerSlot>,
    #[superstruct(only(Electra))]
    pub committee_bits: BitVector<E::MaxCommitteesPerSlot>,
    pub signature: AggregateSignature,

}

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
#[superstruct(
    variants(Electra, Fulu),
    variant_attributes(
        derive( Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Derivative, arbitrary::Arbitrary),
        derivative(PartialEq, Hash(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")),
        serde(
            bound = "E: EthSpec, Payload: AbstractExecPayload<E>",
            deny_unknown_fields
        ),
        arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
    ),
    specific_variant_attributes(
        Electra(metastruct(mappings(beacon_block_body_electra_fields(groups(fields))))),
        Fulu(metastruct(mappings(beacon_block_body_fulu_fields(groups(fields)))))
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative, arbitrary::Arbitrary)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
pub struct BeaconBlockBody<E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    pub randao_reveal: Signature,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Electra,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Fulu,

    #[superstruct(only(Electra))]
    pub execution_requests: ExecutionRequests<E>,
    pub deposits: VariableList<Deposit, E::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, E::MaxVoluntaryExits>,
    pub proposer_slashings: VariableList<ProposerSlashing, E::MaxProposerSlashings>,
    #[superstruct(only(Electra), partial_getter(rename = "attester_slashings_electra"))]
    pub attester_slashings: VariableList<AttesterSlashingElectra<E>, E::MaxAttesterSlashingsElectra>,
    #[superstruct(only(Electra), partial_getter(rename = "attestations_electra"))]
    pub attestations: VariableList<AttestationElectra<E>, E::MaxAttestationsElectra>,
    #[superstruct(only(Electra))]
    pub sync_aggregate: SyncAggregate<E>,
    #[superstruct(only(Electra))]
    pub bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, E::MaxBlsToExecutionChanges>,
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBodyRef<'a, E, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'a>, Error> {
        match self {
            Self::Electra(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Fulu(body) => Ok(Payload::Ref::from(&body.execution_payload)),
        }
    }

    pub fn attester_slashings_len(&self) -> usize {
        match self {
            Self::Electra(body) => body.attester_slashings.len(),
            Self::Fulu(_body) => 0
        }
    }

    pub fn attestations_len(&self) -> usize {
        match self {
            Self::Electra(body) => body.attestations.len(),
            Self::Fulu(_) => 0
        }
    }

    pub fn attester_slashings(&self) -> Box<dyn Iterator<Item = AttesterSlashingRef<'a, E>> + 'a> {
        match self {
            // Self::Electra(body) => Box::new(
            //     body.attester_slashings
            //         .iter()
            //         .map(AttesterSlashingRef::Electra),
            // ),
            Self::Electra(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Electra),
            ),
            Self::Fulu(_body) => Box::new(iter::empty())

        }
    }

    pub fn attestations(&self) -> Box<dyn Iterator<Item = AttestationRef<'a, E>> + 'a> {
        match self {
            Self::Electra(body) => Box::new(body.attestations.iter().map(AttestationRef::Electra)),
            Self::Fulu(_body) => Box::new(iter::empty()),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub type DepositRequests<E> =
    VariableList<DepositRequest, <E as EthSpec>::MaxDepositRequestsPerPayload>;
pub type WithdrawalRequests<E> =
    VariableList<WithdrawalRequest, <E as EthSpec>::MaxWithdrawalRequestsPerPayload>;
pub type ConsolidationRequests<E> =
    VariableList<ConsolidationRequest, <E as EthSpec>::MaxConsolidationRequestsPerPayload>;

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct DepositRequest {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: SignatureBytes,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct WithdrawalRequest {
    #[serde(with = "serde_utils::address_hex")]
    pub source_address: Address,
    pub validator_pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: PublicKeyBytes,
    pub target_pubkey: PublicKeyBytes,
}

#[derive(
    arbitrary::Arbitrary, Debug, Derivative, Default, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct ExecutionRequests<E: EthSpec> {
    pub deposits: DepositRequests<E>,
    pub withdrawals: WithdrawalRequests<E>,
    pub consolidations: ConsolidationRequests<E>,
}

////////////////////////////////////////////////////////////////////////////////////////////////////

/// A `BeaconBlock` and a signature from its proposer.
#[superstruct(
    variants(Electra, Fulu),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Derivative, arbitrary::Arbitrary),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
        arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
    ),
    map_into(BeaconBlock),
    map_ref_into(BeaconBlockRef),
    map_ref_mut_into(BeaconBlockRefMut)
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct SignedBeaconBlock<E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    #[superstruct(only(Electra), partial_getter(rename = "message_electra"))]
    pub message: BeaconBlockElectra<E, Payload>,
    #[superstruct(only(Fulu), partial_getter(rename = "message_fulu"))]
    pub message: BeaconBlockFulu<E, Payload>,
    pub signature: Signature,
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> SignedBeaconBlock<E, Payload> {
    /// Accessor for the block's `message` field as a ref.
    pub fn message<'a>(&'a self) -> BeaconBlockRef<'a, E, Payload> {
        map_signed_beacon_block_ref_into_beacon_block_ref!(
            &'a _,
            self.to_ref(),
            |inner, cons| cons(&inner.message)
        )
    }
    /// Convenience accessor for the block's slot.
    pub fn slot(&self) -> Slot {
        self.message().slot()
    }
    /// Convenience accessor for the block's parent root.
    pub fn parent_root(&self) -> Hash256 {
        self.message().parent_root()
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        self.message().fork_name(spec)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

/// A block of the `BeaconChain`.
#[superstruct(
    variants(Electra, Fulu),
    variant_attributes(
        derive(
            Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Derivative, arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")),
        serde(
            bound = "E: EthSpec, Payload: AbstractExecPayload<E>",
            deny_unknown_fields
        ),
        arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
    ),
    ref_attributes(
        derive(Debug, PartialEq, TreeHash),
        tree_hash(enum_behaviour = "transparent")
    ),
    map_ref_into(BeaconBlockBodyRef, BeaconBlock),
    map_ref_mut_into(BeaconBlockBodyRefMut)
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconBlock<E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    #[superstruct(getter(copy))]
    pub slot: Slot,
    #[superstruct(only(Electra), partial_getter(rename = "body_electra"))]
    pub body: BeaconBlockBodyElectra<E, Payload>,
    #[superstruct(only(Fulu), partial_getter(rename = "body_fulu"))]
    pub body: BeaconBlockBodyFulu<E, Payload>,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[superstruct(getter(copy))]
    pub parent_root: Hash256,
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> SignedRoot for BeaconBlock<E, Payload> {}
impl<E: EthSpec, Payload: AbstractExecPayload<E>> SignedRoot for BeaconBlockRef<'_, E, Payload> {}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockRef<'a, E, Payload> {
    /// Convenience accessor for the `body` as a `BeaconBlockBodyRef`.
    pub fn body(&self) -> BeaconBlockBodyRef<'a, E, Payload> {
        map_beacon_block_ref_into_beacon_block_body_ref!(&'a _, *self, |block, cons| cons(
            &block.body
        ))
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_slot::<E>(self.slot());
        let object_fork = self.fork_name_unchecked();

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            BeaconBlockRef::Electra { .. } => ForkName::Electra,
            BeaconBlockRef::Fulu { .. } => ForkName::Fulu,
        }
    }
}