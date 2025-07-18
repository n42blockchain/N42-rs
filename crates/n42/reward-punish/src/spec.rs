use std::fmt::Debug;
use arbitrary;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::Unsigned;
use crate::slot_epoch::Epoch;
use crate::beaconstate::BeaconState;
use crate::beaconstate::Error;
use crate::arith::SafeArith;
use crate::slot_epoch::Slot;
use crate::fork_name::ForkName;


/// Each of the BLS signature domains.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Domain {
    BlsToExecutionChange,
    BeaconProposer,
    BeaconAttester,
    Randao,
    Deposit,
    VoluntaryExit,
    SelectionProof,
    AggregateAndProof,
    SyncCommittee,
    ContributionAndProof,
    SyncCommitteeSelectionProof,
    // ApplicationMask(ApplicationDomain),
}



fn option_wrapper<F, T>(f: F) -> Option<T>
where
    F: Fn() -> Option<T>,
{
    f()
}

#[derive(PartialEq, Debug, Clone)]
pub struct Spec {

    pub genesis_slot: Slot,

    /// The Altair fork epoch is optional, with `None` representing "Altair never happens".
    pub altair_fork_epoch: Option<Epoch>,



    pub min_epochs_to_inactivity_penalty: u64,
    pub effective_balance_increment: u64,
    pub inactivity_penalty_quotient: u64,
    pub inactivity_score_bias: u64,
    pub min_inactivity_epoch: u64,
    pub multiple_reward_for_inactivity_penalty: u64,
    pub inactivity_score_recovery_rate: u64,
    pub max_inactivity_score: u64,
    pub base_rewards_per_epoch:u64,


    pub proposer_reward_quotient: u64,
    pub base_reward_factor: u64,
    pub slots_per_epoch: u64,
    pub slots_per_big_epoch: u64,
    pub max_work_epoch: u64,
    pub proportional_slashing_multiplier: u64,
    pub proportional_slashing_multiplier_bellatrix: u64,
    pub proportional_slashing_multiplier_altair: u64,
    pub min_seed_lookahead: Epoch,
    pub max_seed_lookahead: Epoch,
    pub max_committees_per_slot: usize,
    pub target_committee_size: usize,
    pub shuffle_round_count: u8,

    pub min_per_epoch_churn_limit: u64,
    pub churn_limit_quotient: u64,




    pub inactivity_penalty_quotient_bellatrix: u64,
    pub inactivity_penalty_quotient_altair: u64,

    /*
    * Signature domains
    */
    pub(crate) domain_beacon_proposer: u32,
    pub(crate) domain_beacon_attester: u32,
    pub(crate) domain_randao: u32,
    pub(crate) domain_deposit: u32,
    pub(crate) domain_voluntary_exit: u32,
    pub(crate) domain_selection_proof: u32,
    pub(crate) domain_aggregate_and_proof: u32,

    pub(crate) domain_sync_committee: u32,
    pub(crate) domain_sync_committee_selection_proof: u32,
    pub(crate) domain_contribution_and_proof: u32,


    /*
    * Capella params
    */
    pub(crate) domain_bls_to_execution_change: u32,


    /*
    * Fulu hard fork params
    */

    /// The Fulu fork epoch is optional, with `None` representing "Fulu never happens".
    pub fulu_fork_epoch: Option<Epoch>,
    pub electra_fork_epoch: Option<Epoch>,


}

impl Spec {
    pub fn mainnet() -> Self {

        Self{

            genesis_slot: Slot::new(0),
            altair_fork_epoch: Some(Epoch::new(74240)),

            min_epochs_to_inactivity_penalty: 4,
            effective_balance_increment: option_wrapper(|| {
                u64::checked_pow(2, 0)?.checked_mul(u64::checked_pow(10, 9)?)
            })
                .expect("calculation does not overflow"),
            inactivity_penalty_quotient: u64::checked_pow(2, 26).expect("pow does not overflow"),
            inactivity_score_bias: 1,
            min_inactivity_epoch: 1350,
            multiple_reward_for_inactivity_penalty: 3,
            inactivity_score_recovery_rate: 48,
            max_inactivity_score: 6750,
            base_rewards_per_epoch: 1,
            proposer_reward_quotient: 4,
            base_reward_factor: 2,
            slots_per_epoch: 32,
            slots_per_big_epoch: 10800,
            max_work_epoch: 5,
            proportional_slashing_multiplier: 1,
            proportional_slashing_multiplier_bellatrix: 3,
            proportional_slashing_multiplier_altair: 2,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            max_committees_per_slot: 64,
            target_committee_size: 128,
            shuffle_round_count: 90,



            inactivity_penalty_quotient_bellatrix: u64::checked_pow(2, 24)
                .expect("pow does not overflow"),
            inactivity_penalty_quotient_altair: option_wrapper(|| {
                u64::checked_pow(2, 24)?.checked_mul(3)
            })
                .expect("calculation does not overflow"),


            /*
             * Signature domains
             */
            min_per_epoch_churn_limit: 4,
            churn_limit_quotient: 32,
            domain_beacon_proposer: 0,
            domain_beacon_attester: 1,
            domain_randao: 2,
            domain_deposit: 3,
            domain_voluntary_exit: 4,
            domain_selection_proof: 5,
            domain_aggregate_and_proof: 6,

            domain_sync_committee: 7,
            domain_sync_committee_selection_proof: 8,
            domain_contribution_and_proof: 9,

            /*
             * Capella params
             */
            domain_bls_to_execution_change: 10,


            /*
             * Fulu hard fork params
             */
            fulu_fork_epoch: None,


            electra_fork_epoch: Some(Epoch::new(1337856)),
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


    /// Get the domain number, unmodified by the fork.
    ///
    /// Spec v0.12.1
    pub fn get_domain_constant(&self, domain: Domain) -> u32 {
        match domain {
            Domain::BeaconProposer => self.domain_beacon_proposer,
            Domain::BeaconAttester => self.domain_beacon_attester,
            Domain::Randao => self.domain_randao,
            Domain::Deposit => self.domain_deposit,
            Domain::VoluntaryExit => self.domain_voluntary_exit,
            Domain::SelectionProof => self.domain_selection_proof,
            Domain::AggregateAndProof => self.domain_aggregate_and_proof,
            Domain::SyncCommittee => self.domain_sync_committee,
            Domain::ContributionAndProof => self.domain_contribution_and_proof,
            Domain::SyncCommitteeSelectionProof => self.domain_sync_committee_selection_proof,
            // Domain::ApplicationMask(application_domain) => application_domain.get_domain_constant(),
            Domain::BlsToExecutionChange => self.domain_bls_to_execution_change,
        }
    }


    pub fn inactivity_penalty_quotient_for_fork(&self, fork_name: ForkName) -> u64 {
        if fork_name >= ForkName::Bellatrix {
            self.inactivity_penalty_quotient_bellatrix
        } else if fork_name >= ForkName::Altair {
            self.inactivity_penalty_quotient_altair
        } else {
            self.inactivity_penalty_quotient
        }
    }

    /// Returns the name of the fork which is active at `epoch`.
    pub fn fork_name_at_epoch(&self, epoch: Epoch) -> ForkName {
        match self.fulu_fork_epoch {
            Some(fork_epoch) if epoch >= fork_epoch => ForkName::Fulu,
            _ => match self.electra_fork_epoch {
                Some(fork_epoch) if epoch >= fork_epoch => ForkName::Electra,
            //     _ => match self.deneb_fork_epoch {
            //         Some(fork_epoch) if epoch >= fork_epoch => ForkName::Deneb,
            //         _ => match self.capella_fork_epoch {
            //             Some(fork_epoch) if epoch >= fork_epoch => ForkName::Capella,
            //             _ => match self.bellatrix_fork_epoch {
            //                 Some(fork_epoch) if epoch >= fork_epoch => ForkName::Bellatrix,
                            _ => match self.altair_fork_epoch {
                                Some(fork_epoch) if epoch >= fork_epoch => ForkName::Altair,
                                _ => ForkName::Base,
                            },
                        },
                    // },
                // },
            // },
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

    type SyncCommitteeSize: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxValidatorsPerCommittee: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type GenesisEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type EpochsPerSlashingsVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxPendingAttestations: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxValidatorsPerSlot: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type MaxCommitteesPerSlot: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type EpochsPerHistoricalVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;


    fn genesis_epoch() -> Epoch {
        Epoch::new(Self::GenesisEpoch::to_u64())
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_epoch() -> u64 {
        Self::SlotsPerEpoch::to_u64()
    }


    fn get_committee_count_per_slot_with(
        active_validator_count: usize,
        max_committees_per_slot: usize,
        target_committee_size: usize,
    ) -> Result<usize, Error> {
        let slots_per_epoch = Self::SlotsPerEpoch::to_usize();

        Ok(std::cmp::max(
            1,
            std::cmp::min(
                max_committees_per_slot,
                active_validator_count
                    .safe_div(slots_per_epoch)?
                    .safe_div(target_committee_size)?,
            ),
        ))
    }


    /// Return the number of committees per slot.
    ///
    /// Note: the number of committees per slot is constant in each epoch, and depends only on
    /// the `active_validator_count` during the slot's epoch.
    ///
    /// Spec v0.12.1
    fn get_committee_count_per_slot(
        active_validator_count: usize,
        spec: &Spec,
    ) -> Result<usize, Error> {
        Self::get_committee_count_per_slot_with(
            active_validator_count,
            spec.max_committees_per_slot,
            spec.target_committee_size,
        )
    }

}
// #[derive(
//     Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash,
// )]
// // #[serde(try_from = "String")]
// // #[serde(into = "String")]
// #[ssz(enum_behaviour = "tag")]
// pub enum ForkName {
//     Base,
//     Altair,
//     Bellatrix,
//     Capella,
//     Deneb,
//     Electra,
//     Fulu,
// }
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

