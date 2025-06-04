use tree_hash::TreeHash;
use crate::models::{EthSpec, Withdrawals, Withdrawal};
use crate::beacon_state::{BeaconState,};
use crate::chain_spec::ChainSpec;
use crate::error::{BlockProcessingError, Error as BeaconStateError};
use crate::payload::{AbstractExecPayload, ExecPayload};
use crate::safe_aitrh::{SafeArith, SafeArithIter};


/// Compute the next batch of withdrawals which should be included in a block.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-get_expected_withdrawals
pub fn get_expected_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(Withdrawals<E>, Option<usize>), BlockProcessingError> {
    let epoch = state.current_epoch();
    let mut withdrawal_index = state.next_withdrawal_index()?;
    let mut validator_index = state.next_withdrawal_validator_index()?;
    let mut withdrawals = Vec::<Withdrawal>::with_capacity(E::max_withdrawals_per_payload());
    let fork_name = state.fork_name_unchecked();

    // [New in Electra:EIP7251]
    // Consume pending partial withdrawals
    let processed_partial_withdrawals_count =
        if let Ok(pending_partial_withdrawals) = state.pending_partial_withdrawals() {
            let mut processed_partial_withdrawals_count = 0;
            for withdrawal in pending_partial_withdrawals.iter() {
                if withdrawal.withdrawable_epoch > epoch
                    || withdrawals.len() == spec.max_pending_partials_per_withdrawals_sweep as usize
                {
                    break;
                }

                let validator = state.get_validator(withdrawal.validator_index as usize)?;

                let has_sufficient_effective_balance =
                    validator.effective_balance >= spec.min_activation_balance;
                let total_withdrawn = withdrawals
                    .iter()
                    .filter_map(|w| {
                        (w.validator_index == withdrawal.validator_index).then_some(w.amount)
                    })
                    .safe_sum()?;
                let balance = state
                    .get_balance(withdrawal.validator_index as usize)?
                    .safe_sub(total_withdrawn)?;
                let has_excess_balance = balance > spec.min_activation_balance;

                if validator.exit_epoch == spec.far_future_epoch
                    && has_sufficient_effective_balance
                    && has_excess_balance
                {
                    let withdrawable_balance = std::cmp::min(
                        balance.safe_sub(spec.min_activation_balance)?,
                        withdrawal.amount,
                    );
                    withdrawals.push(Withdrawal {
                        index: withdrawal_index,
                        validator_index: withdrawal.validator_index,
                        address: validator
                            .get_execution_withdrawal_address(spec)
                            .ok_or(BeaconStateError::NonExecutionAddressWithdrawalCredential)?,
                        amount: withdrawable_balance,
                    });
                    withdrawal_index.safe_add_assign(1)?;
                }
                processed_partial_withdrawals_count.safe_add_assign(1)?;
            }
            Some(processed_partial_withdrawals_count)
        } else {
            None
        };

    let bound = std::cmp::min(
        state.validators().len() as u64,
        spec.max_validators_per_withdrawals_sweep,
    );
    for _ in 0..bound {
        let validator = state.get_validator(validator_index as usize)?;
        let partially_withdrawn_balance = withdrawals
            .iter()
            .filter_map(|withdrawal| {
                (withdrawal.validator_index == validator_index).then_some(withdrawal.amount)
            })
            .safe_sum()?;
        let balance = state
            .balances()
            .get(validator_index as usize)
            .ok_or(BeaconStateError::BalancesOutOfBounds(
                validator_index as usize,
            ))?
            .safe_sub(partially_withdrawn_balance)?;
        if validator.is_fully_withdrawable_validator(balance, epoch, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance,
            });
            withdrawal_index.safe_add_assign(1)?;
        } else if validator.is_partially_withdrawable_validator(balance, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance.safe_sub(validator.get_max_effective_balance(spec, fork_name))?,
            });
            withdrawal_index.safe_add_assign(1)?;
        }
        if withdrawals.len() == E::max_withdrawals_per_payload() {
            break;
        }
        validator_index = validator_index
            .safe_add(1)?
            .safe_rem(state.validators().len() as u64)?;
    }

    Ok((withdrawals.into(), processed_partial_withdrawals_count))
}

/// Apply withdrawals to the state.
pub fn process_withdrawals<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    payload: Payload::Ref<'_>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    if state.fork_name_unchecked().capella_enabled() {
        let (expected_withdrawals, processed_partial_withdrawals_count) =
            get_expected_withdrawals(state, spec)?;
        let expected_root = expected_withdrawals.tree_hash_root();
        let withdrawals_root = payload.withdrawals_root()?;

        if expected_root != withdrawals_root {
            return Err(BlockProcessingError::WithdrawalsRootMismatch {
                expected: expected_root,
                found: withdrawals_root,
            });
        }

        for withdrawal in expected_withdrawals.iter() {
            decrease_balance(
                state,
                withdrawal.validator_index as usize,
                withdrawal.amount,
            )?;
        }

        // Update pending partial withdrawals [New in Electra:EIP7251]
        if let Some(processed_partial_withdrawals_count) = processed_partial_withdrawals_count {
            state
                .pending_partial_withdrawals_mut()?
                .pop_front(processed_partial_withdrawals_count)?;
        }

        // Update the next withdrawal index if this block contained withdrawals
        if let Some(latest_withdrawal) = expected_withdrawals.last() {
            *state.next_withdrawal_index_mut()? = latest_withdrawal.index.safe_add(1)?;

            // Update the next validator index to start the next withdrawal sweep
            if expected_withdrawals.len() == E::max_withdrawals_per_payload() {
                // Next sweep starts after the latest withdrawal's validator index
                let next_validator_index = latest_withdrawal
                    .validator_index
                    .safe_add(1)?
                    .safe_rem(state.validators().len() as u64)?;
                *state.next_withdrawal_validator_index_mut()? = next_validator_index;
            }
        }

        // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        if expected_withdrawals.len() != E::max_withdrawals_per_payload() {
            let next_validator_index = state
                .next_withdrawal_validator_index()?
                .safe_add(spec.max_validators_per_withdrawals_sweep)?
                .safe_rem(state.validators().len() as u64)?;
            *state.next_withdrawal_validator_index_mut()? = next_validator_index;
        }

        Ok(())
    } else {
        // these shouldn't even be encountered but they're here for completeness
        Ok(())
    }
}

pub fn decrease_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    decrease_balance_directly(state.get_balance_mut(index)?, delta)
}

pub fn decrease_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    *balance = balance.saturating_sub(delta);
    Ok(())
}