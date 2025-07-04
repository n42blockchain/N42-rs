use derivative::Derivative;
use superstruct::superstruct;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use metastruct::metastruct;
use ssz_types::VariableList;
use crate::{Hash256, Address};
use crate::payload::{AbstractExecPayload, FullPayload};
use crate::beacon_state::{Error, EthSpec};
use crate::crypto::{PublicKeyBytes, SignatureBytes};

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
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Electra,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Fulu,

    #[superstruct(only(Electra))]
    pub execution_requests: ExecutionRequests<E>,
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBodyRef<'a, E, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'a>, Error> {
        match self {
            Self::Electra(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Fulu(body) => Ok(Payload::Ref::from(&body.execution_payload)),
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
    #[superstruct(only(Electra), partial_getter(rename = "body_electra"))]
    pub body: BeaconBlockBodyElectra<E, Payload>,
    #[superstruct(only(Fulu), partial_getter(rename = "body_fulu"))]
    pub body: BeaconBlockBodyFulu<E, Payload>,
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockRef<'a, E, Payload> {
    /// Convenience accessor for the `body` as a `BeaconBlockBodyRef`.
    pub fn body(&self) -> BeaconBlockBodyRef<'a, E, Payload> {
        map_beacon_block_ref_into_beacon_block_body_ref!(&'a _, *self, |block, cons| cons(
            &block.body
        ))
    }
}