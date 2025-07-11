use std::fmt::Debug;
use arbitrary;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::Unsigned;
use crate::slot_epoch::Epoch;
use crate::beaconstate::BeaconState;


fn option_wrapper<F, T>(f: F) -> Option<T>
where
    F: Fn() -> Option<T>,
{
    f()
}

#[derive(PartialEq, Debug, Clone)]
pub struct Spec {
    pub min_epochs_to_inactivity_penalty: u64,
    pub effective_balance_increment: u64,
    pub inactivity_penalty_quotient: u64,
    pub base_rewards_per_epoch:u64,
    pub proposer_reward_quotient: u64,
    pub base_reward_factor: u64,
    pub slots_per_epoch: u64,
    pub slots_per_big_epoch: u64,
    pub proportional_slashing_multiplier: u64,
    pub proportional_slashing_multiplier_bellatrix: u64,
    pub proportional_slashing_multiplier_altair: u64,
}

impl Spec {
    pub fn mainnet() -> Self {

        Self{
            min_epochs_to_inactivity_penalty: 4,
            effective_balance_increment: option_wrapper(|| {
                u64::checked_pow(2, 0)?.checked_mul(u64::checked_pow(10, 9)?)
            })
                .expect("calculation does not overflow"),
            inactivity_penalty_quotient: u64::checked_pow(2, 26).expect("pow does not overflow"),
            base_rewards_per_epoch: 2,
            proposer_reward_quotient: 4,
            base_reward_factor: 1/2,
            slots_per_epoch: 64,
            slots_per_big_epoch: 10800,
            proportional_slashing_multiplier: 1,
            proportional_slashing_multiplier_bellatrix: 3,
            proportional_slashing_multiplier_altair: 2,

        }
    }


    /// For a given `BeaconState`, return the proportional slashing multiplier associated with its variant.
    pub fn proportional_slashing_multiplier_for_state<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> u64 {
        let fork_name = state.fork_name_unchecked();
        if fork_name >= ForkName::Bellatrix {
            self.proportional_slashing_multiplier_bellatrix
        } else if fork_name >= ForkName::Altair {
            self.proportional_slashing_multiplier_altair
        } else {
            self.proportional_slashing_multiplier
        }
    }

    // /// Returns the name of the fork pertaining to `self`.
    // ///
    // /// Does not check if `self` is consistent with the fork dictated by `self.slot()`.
    // pub fn fork_name_unchecked(&self) -> ForkName {
    //     match self {
    //         BeaconState::Base { .. } => ForkName::Base,
    //         BeaconState::Altair { .. } => ForkName::Altair,
    //         BeaconState::Bellatrix { .. } => ForkName::Bellatrix,
    //         BeaconState::Capella { .. } => ForkName::Capella,
    //         BeaconState::Deneb { .. } => ForkName::Deneb,
    //         BeaconState::Electra { .. } => ForkName::Electra,
    //         BeaconState::Fulu { .. } => ForkName::Fulu,
    //     }
    // }
}



pub trait EthSpec:
    'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq + for<'a> arbitrary::Arbitrary<'a>
{
    type MaxValidatorsPerCommittee: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type GenesisEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type EpochsPerSlashingsVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxPendingAttestations: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;


    fn genesis_epoch() -> Epoch {
        Epoch::new(Self::GenesisEpoch::to_u64())
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_epoch() -> u64 {
        Self::SlotsPerEpoch::to_u64()
    }

}
#[derive(
    Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
// #[serde(try_from = "String")]
// #[serde(into = "String")]
#[ssz(enum_behaviour = "tag")]
pub enum ForkName {
    Base,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
}
//
// impl ForkName {
//     pub fn list_all() -> Vec<ForkName> {
//         vec![
//             ForkName::Base,
//             ForkName::Altair,
//             ForkName::Bellatrix,
//             ForkName::Capella,
//             ForkName::Deneb,
//             ForkName::Electra,
//             ForkName::Fulu,
//         ]
//     }
//
// }

