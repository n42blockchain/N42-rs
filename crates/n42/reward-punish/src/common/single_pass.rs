use std::cmp::min;
use integer_sqrt::IntegerSquareRoot;
use crate::beaconstate::BeaconState;
use crate::spec::{EthSpec,Spec};
use crate::common::epoch_processing_summary::ParticipationEpochSummary;
use crate::errors::EpochProcessingError as Error;

use crate::slot_epoch::Epoch;
use crate::beaconstate::Checkpoint;
use crate::fork_name::ForkName;
use crate::common::participation_flags::ParticipationFlags;
use crate::arith::SafeArith;
use crate::common::progressive_balance_cache::ProgressiveBalancesCache;
use crate::beaconstate::Error as BeaconStateError;
use crate::per_epoch_processing::Delta;
use milhouse::Cow;
use itertools::izip;

use crate::common::NUM_FLAG_INDICES;
use crate::common::{PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_WEIGHT,
                    TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT,WEIGHT_DENOMINATOR,
                    TIMELY_HEAD_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX};


pub struct SinglePassConfig {
    pub inactivity_updates: bool,
    pub rewards_and_penalties: bool,
    pub registry_updates: bool,
    pub slashings: bool,
    pub pending_deposits: bool,
    pub pending_consolidations: bool,
    pub effective_balance_updates: bool,
}

impl Default for SinglePassConfig {
    fn default() -> SinglePassConfig {
        Self::enable_all()
    }
}

impl SinglePassConfig {
    pub fn enable_all() -> SinglePassConfig {
        Self {
            inactivity_updates: true,
            rewards_and_penalties: true,
            registry_updates: true,
            slashings: true,
            pending_deposits: true,
            pending_consolidations: true,
            effective_balance_updates: true,
        }
    }

    pub fn disable_all() -> SinglePassConfig {
        SinglePassConfig {
            inactivity_updates: false,
            rewards_and_penalties: false,
            registry_updates: false,
            slashings: false,
            pending_deposits: false,
            pending_consolidations: false,
            effective_balance_updates: false,
        }
    }
}




/// Values from the state that are immutable throughout epoch processing.
pub struct StateContext {
    current_epoch: Epoch,
    next_epoch: Epoch,
    finalized_checkpoint: Checkpoint,
    is_in_inactivity_leak: bool,
    total_active_balance: u64,
    churn_limit: u64,
    fork_name: ForkName,
}


struct RewardsAndPenaltiesContext {
    unslashed_participating_increments_array: [u64; NUM_FLAG_INDICES],
    active_increments: u64,
}

impl RewardsAndPenaltiesContext {
    fn new(
        progressive_balances: &ProgressiveBalancesCache,
        state_ctxt: &StateContext,
        spec: &Spec,
    ) -> Result<Self, Error> {
        let mut unslashed_participating_increments_array = [0; NUM_FLAG_INDICES];
        for flag_index in 0..NUM_FLAG_INDICES {
            let unslashed_participating_balance =
                progressive_balances.previous_epoch_flag_attesting_balance(flag_index)?;
            let unslashed_participating_increments =
                unslashed_participating_balance.safe_div(spec.effective_balance_increment)?;

            *unslashed_participating_increments_array
                .get_mut(flag_index)
                .ok_or(Error::InvalidFlagIndex(flag_index))? = unslashed_participating_increments;
        }
        let active_increments = state_ctxt
            .total_active_balance
            .safe_div(spec.effective_balance_increment)?;

        Ok(Self {
            unslashed_participating_increments_array,
            active_increments,
        })
    }

    fn get_unslashed_participating_increments(&self, flag_index: usize) -> Result<u64, Error> {
        self.unslashed_participating_increments_array
            .get(flag_index)
            .copied()
            .ok_or(Error::InvalidFlagIndex(flag_index))
    }
}


#[derive(Debug, PartialEq, Clone)]
pub struct ValidatorInfo {
    pub index: usize,
    pub effective_balance: u64,
    pub base_reward: u64,
    pub is_eligible: bool,
    pub is_slashed: bool,
    pub is_active_current_epoch: bool,
    pub is_active_previous_epoch: bool,
    // Used for determining rewards.
    pub previous_epoch_participation: ParticipationFlags,
    // Used for updating the progressive balances cache for next epoch.
    pub current_epoch_participation: ParticipationFlags,
}

impl ValidatorInfo {
    #[inline]
    pub fn is_unslashed_participating_index(&self, flag_index: usize) -> Result<bool, Error> {
        Ok(self.is_active_previous_epoch
            && !self.is_slashed
            && self
            .previous_epoch_participation
            .has_flag(flag_index)
            .map_err(|_| Error::InvalidFlagIndex(flag_index))?)
    }
}




pub fn process_epoch_single_pass<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &Spec,
    conf: SinglePassConfig,
) -> Result<ParticipationEpochSummary<E>, Error> {
    let current_epoch = state.current_epoch();
    let previous_epoch = state.previous_epoch();
    let next_epoch = state.next_epoch()?;
    let is_in_inactivity_leak = state.is_in_inactivity_leak(previous_epoch, spec)?;
    let total_active_balance = state.get_total_active_balance()?;
    let total_effective_balance = state.compute_total_effective_balance()?;

    let churn_limit = state.get_validator_churn_limit(spec)?;
    // let activation_churn_limit = state.get_activation_churn_limit(spec)?;
    let finalized_checkpoint = state.finalized_checkpoint();
    let fork_name = state.fork_name_unchecked();


    let state_ctxt = &StateContext {
        current_epoch,
        next_epoch,
        finalized_checkpoint,
        is_in_inactivity_leak,
        total_active_balance,
        churn_limit,
        fork_name,
    };

    // Split the state into several disjoint mutable borrows.
    let (
        validators,
        balances,
        previous_epoch_participation,
        current_epoch_participation,
        inactivity_scores,
        progressive_balances,
        exit_cache,
        epoch_cache,
    ) = state.mutable_validator_fields()?;





    let num_validators = validators.len();

    // Take a snapshot of the validators and participation before mutating. This is used for
    // informational purposes (e.g. by the validator monitor).
    let summary = ParticipationEpochSummary::new(
        validators.clone(),
        previous_epoch_participation.clone(),
        current_epoch_participation.clone(),
        previous_epoch,
        current_epoch,
    );

    // Compute shared values required for different parts of epoch processing.
    let rewards_ctxt = &RewardsAndPenaltiesContext::new(progressive_balances, state_ctxt, spec)?;
    // Iterate over the validators and related fields in one pass.
    let mut validators_iter = validators.iter_cow();
    let mut balances_iter = balances.iter_cow();

    let mut inactivity_scores_iter = inactivity_scores.iter_cow();


    for (index, &previous_epoch_participation, &current_epoch_participation) in izip!(
        0..num_validators,
        previous_epoch_participation.iter(),
        current_epoch_participation.iter(),
    ) {
        let (_, mut validator) = validators_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;
        let (_, mut balance) = balances_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;
        let (_, mut inactivity_score) = inactivity_scores_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;

        let is_active_current_epoch = validator.is_active_at(current_epoch);
        let is_active_previous_epoch = validator.is_active_at(previous_epoch);
        let is_eligible = is_active_previous_epoch
            || (validator.slashed && previous_epoch.safe_add(1)? < validator.withdrawable_epoch);

        let base_reward_m = if is_eligible {
            epoch_cache.get_base_reward(index)?
        } else {
            0
        };
        let base_reward = base_reward_m.safe_mul(spec.base_reward_factor)?
                                                    .safe_div(total_effective_balance.integer_sqrt())?
                                                    .safe_div(spec.base_rewards_per_epoch)?;

        let validator_info = &ValidatorInfo {
            index,
            effective_balance: validator.effective_balance,
            base_reward,
            is_eligible,
            is_slashed: validator.slashed,
            is_active_current_epoch,
            is_active_previous_epoch,
            previous_epoch_participation,
            current_epoch_participation,
        };


        if current_epoch != E::genesis_epoch() {
            // `process_inactivity_updates`
            if conf.inactivity_updates {
                process_single_inactivity_update(
                    &mut inactivity_score,
                    validator_info,
                    state_ctxt,
                    spec,
                )?;
            }

            // `process_rewards_and_penalties`
            if conf.rewards_and_penalties {
                process_single_reward_and_penalty(
                    &mut balance,
                    &inactivity_score,
                    validator_info,
                    rewards_ctxt,
                    state_ctxt,
                    spec,
                )?;
            }
        }


        // Ok(())

    }
    Ok(summary)

}

fn process_single_reward_and_penalty(
        balance: &mut Cow<'_, u64>,
        inactivity_score: &u64,
        validator_info: &ValidatorInfo,
        rewards_ctxt: &RewardsAndPenaltiesContext,
        state_ctxt: &StateContext,
        spec: &Spec,
    ) -> Result<(), Error> {
        if !validator_info.is_eligible {
            return Ok(());
        }

        let mut delta = Delta::default();
        for flag_index in 0..NUM_FLAG_INDICES {
            get_flag_index_delta(
                &mut delta,
                validator_info,
                flag_index,
                rewards_ctxt,
                state_ctxt,
            )?;
        }
        get_inactivity_penalty_delta(
            &mut delta,
            validator_info,
            inactivity_score,
            state_ctxt,
            spec,
        )?;

        if delta.rewards != 0 || delta.penalties != 0 {
            let balance = balance.make_mut()?;
            balance.safe_add_assign(delta.rewards)?;
            *balance = balance.saturating_sub(delta.penalties);
        }

        Ok(())
    }




    /// Get the weight for a `flag_index` from the constant list of all weights.
    fn get_flag_weight(flag_index: usize) -> Result<u64, Error> {
        PARTICIPATION_FLAG_WEIGHTS
            .get(flag_index)
            .copied()
            .ok_or(Error::InvalidFlagIndex(flag_index))
    }

    fn get_flag_index_delta(
        delta: &mut Delta,
        validator_info: &ValidatorInfo,
        flag_index: usize,
        rewards_ctxt: &RewardsAndPenaltiesContext,
        state_ctxt: &StateContext,
    ) -> Result<(), Error> {
        let base_reward = validator_info.base_reward;
        let weight = get_flag_weight(flag_index)?;
        // let unslashed_participating_increments =
        //     rewards_ctxt.get_unslashed_participating_increments(flag_index)?;

        // if validator_info.is_unslashed_participating_index(flag_index)? {
        //     if !state_ctxt.is_in_inactivity_leak {
                let reward_numerator = base_reward
                    .safe_mul(weight)?;
                    // .safe_mul(unslashed_participating_increments)?;
                delta.reward(
                    reward_numerator.safe_div(WEIGHT_DENOMINATOR
                        // rewards_ctxt
                            // .active_increments
                            // .safe_mul(WEIGHT_DENOMINATOR)?,
                    )?,
                )?;
            // }
            // } else if flag_index != TIMELY_HEAD_FLAG_INDEX {
            //     delta.penalize(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?)?;
        // }
        Ok(())
    }

    fn get_inactivity_penalty_delta(
        delta: &mut Delta,
        validator_info: &ValidatorInfo,
        inactivity_score: &u64,
        state_ctxt: &StateContext,
        spec: &Spec,
    ) -> Result<(), Error> {

        // if !validator_info.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {

            if *inactivity_score > spec.min_inactivity_epoch {
                let base_reward = validator_info.base_reward;
                let pealty_for_reawrd = base_reward
                                        .safe_mul(spec.multiple_reward_for_inactivity_penalty)?;
                delta.penalize(pealty_for_reawrd)?;

                // let penalty_numerator = validator_info
                //     .effective_balance;
                //     // .safe_mul(*inactivity_score)?;
                // let penalty_denominator = spec
                //     .inactivity_score_bias
                //     .safe_mul(spec.inactivity_penalty_quotient_for_fork(state_ctxt.fork_name))?;
                // delta.penalize(penalty_numerator.safe_div(penalty_denominator)?)?;

            }

        // }

        // if state_ctxt.is_in_inactivity_leak && !validator_info.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
        //     let penalty_numerator = validator_info.effective_balance.safe_mul(*inactivity_score)?;
        //     let penalty = penalty_numerator.safe_div(spec.inactivity_penalty_quotient_altair)?;
        //     delta.penalize(penalty)?;
        // }
        Ok(())
    }




fn process_single_inactivity_update(
    inactivity_score: &mut Cow<'_, u64>,
    validator_info: &ValidatorInfo,
    state_ctxt: &StateContext,
    spec: &Spec,
) -> Result<(), Error> {
    if !validator_info.is_eligible {
        return Ok(());
    }

    // Increase inactivity score of inactive validators
    if validator_info.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
        // Avoid mutating when the inactivity score is 0 and can't go any lower -- the common
        // case.
        if **inactivity_score < spec.inactivity_score_recovery_rate {
            *inactivity_score.make_mut()? = 0;
            return Ok(());
        }
        inactivity_score.make_mut()?.safe_sub_assign(spec.inactivity_score_recovery_rate)?;
    } else {

        if **inactivity_score < spec.max_inactivity_score {
            inactivity_score
                .make_mut()?
                .safe_add_assign(spec.inactivity_score_bias)?;
        }else { *inactivity_score.make_mut()? = spec.max_inactivity_score; }

    }


    // // Decrease the score of all validators for forgiveness when not during a leak
    // if !state_ctxt.is_in_inactivity_leak {
    //     let deduction = min(spec.inactivity_score_recovery_rate, **inactivity_score);
    //     inactivity_score.make_mut()?.safe_sub_assign(deduction)?;
    // }



    Ok(())
}




