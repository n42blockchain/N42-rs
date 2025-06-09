use std::fmt::Debug;
use alloy_primitives::private::arbitrary;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use milhouse::List;
use superstruct::superstruct;
use crate::pending_partial_withdrawal::PendingPartialWithdrawal;
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use metastruct::metastruct;
use ssz_types::typenum::Unsigned;
use compare_fields_derive::CompareFields;
use test_random_derive::TestRandom;
use crate::validators::Validator;
use crate::fork_name::ForkName;
use crate::slot_epoch::{Epoch, Slot};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    NonExecutionAddressWithdrawalCredential,
    BalancesOutOfBounds(usize),
    UnknownValidator(usize),
}

#[superstruct(
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            Derivative,
            Debug,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            CompareFields,
            arbitrary::Arbitrary,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
        derivative(Clone),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    map_ref_mut_into(BeaconStateRef)
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, arbitrary::Arbitrary)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconState<E>
where
    E: EthSpec,
{

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub slot: Slot,
    #[compare_fields(as_iter)]
    #[test_random(default)]
    pub validators: List<Validator, E::ValidatorRegistryLimit>,
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    #[compare_fields(as_iter)]
    #[test_random(default)]
    pub balances: List<u64, E::ValidatorRegistryLimit>,

    // Capella
    #[superstruct(only(Capella, Deneb, Electra, Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Capella, Deneb, Electra, Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_validator_index: u64,

    #[compare_fields(as_iter)]
    #[test_random(default)]
    #[superstruct(only(Electra, Fulu))]
    pub pending_partial_withdrawals: List<PendingPartialWithdrawal, E::PendingPartialWithdrawalsLimit>,

}

impl<E: EthSpec> BeaconState<E> {
    /// The epoch corresponding to `self.slot()`.
    pub fn current_epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Does not check if `self` is consistent with the fork dictated by `self.slot()`.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            BeaconState::Base { .. } => ForkName::Base,
            BeaconState::Altair { .. } => ForkName::Altair,
            BeaconState::Bellatrix { .. } => ForkName::Bellatrix,
            BeaconState::Capella { .. } => ForkName::Capella,
            BeaconState::Deneb { .. } => ForkName::Deneb,
            BeaconState::Electra { .. } => ForkName::Electra,
            BeaconState::Fulu { .. } => ForkName::Fulu,
        }
    }

    /// Safe indexer for the `validators` list.
    pub fn get_validator(&self, validator_index: usize) -> Result<&Validator, Error> {
        self.validators()
            .get(validator_index)
            .ok_or(Error::UnknownValidator(validator_index))
    }

    /// Get the balance of a single validator.
    pub fn get_balance(&self, validator_index: usize) -> Result<u64, Error> {
        self.balances()
            .get(validator_index)
            .ok_or(Error::BalancesOutOfBounds(validator_index))
            .copied()
    }
}

/// Represents the "Beacon Chain" component of Ethereum 2.0. Allows import of blocks and block
/// operations and chooses a canonical head.
pub struct BeaconChain<T: BeaconChainTypes> {

}

pub trait BeaconChainTypes: Send + Sync + 'static {
    type EthSpec: EthSpec;
}

pub trait EthSpec:
'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq + for<'a> arbitrary::Arbitrary<'a>
{
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingPartialWithdrawalsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;


    fn max_withdrawals_per_payload() -> usize {
        Self::MaxWithdrawalsPerPayload::to_usize()
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_epoch() -> u64 {
        Self::SlotsPerEpoch::to_u64()
    }
}
