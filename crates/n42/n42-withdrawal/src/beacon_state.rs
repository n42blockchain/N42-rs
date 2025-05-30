use alloy_primitives::private::arbitrary;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use milhouse::List;
use superstruct::superstruct;
use crate::models::{Epoch, EthSpec, PendingPartialWithdrawal, Validator};
use crate::error::Error;
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

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
            // TestRandom, CompareFields,
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
            crate::models::BeaconState::Base { .. } => ForkName::Base,
            crate::models::BeaconState::Altair { .. } => ForkName::Altair,
            crate::models::BeaconState::Bellatrix { .. } => ForkName::Bellatrix,
            crate::models::BeaconState::Capella { .. } => ForkName::Capella,
            crate::models::BeaconState::Deneb { .. } => ForkName::Deneb,
            crate::models::BeaconState::Electra { .. } => ForkName::Electra,
            crate::models::BeaconState::Fulu { .. } => ForkName::Fulu,
        }
    }

    /// Safe indexer for the `validators` list.
    pub fn get_validator(&self, validator_index: usize) -> std::result::Result<&Validator, Error> {
        self.validators()
            .get(validator_index)
            .ok_or(Error::UnknownValidator(validator_index))
    }

    /// Get the balance of a single validator.
    pub fn get_balance(&self, validator_index: usize) -> std::result::Result<u64, Error> {
        self.balances()
            .get(validator_index)
            .ok_or(Error::BalancesOutOfBounds(validator_index))
            .copied()
    }
}