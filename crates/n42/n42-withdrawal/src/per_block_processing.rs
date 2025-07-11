use ssz_types::FixedVector;
use ssz_types::typenum::{Unsigned, U33};
use tree_hash::TreeHash;
use crate::beacon_block_body::{BeaconBlockBodyRef, SignedBeaconBlock, WithdrawalRequest};
use crate::withdrawal::{Withdrawals, Withdrawal, VerifySignatures, Deposit, DepositData, SignedVoluntaryExit, PendingDeposit, BlockSignatureStrategy};
use crate::beacon_state::{BeaconState, Error as BeaconStateError, EthSpec};
use crate::chain_spec::ChainSpec;
use crate::error::{BlockProcessingError, EpochProcessingError as Error, IntoWithIndex};
use crate::fork_name::ForkName;
use crate::payload::{AbstractExecPayload, ExecPayload};
use crate::pending_partial_withdrawal::PendingPartialWithdrawal;
use crate::safe_aitrh::{SafeArith, SafeArithIter};
use crate::validators::Validator;
use crate::Hash256;
use crate::signature::{BlockSignatureVerifier, ConsensusContext};
use crate::verify_deposit::{get_existing_validator_index, is_valid_deposit_signature, verify_deposit_merkle_proof};
use crate::verify_exit::{get_pubkey_from_state, verify_exit};
use std::borrow::Cow;
use rayon::prelude::*;


/// Performs a validator registry update, if required.
///
/// NOTE: unchanged in Altair
pub fn process_registry_updates<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Process activation eligibility and ejections.
    // Collect eligible and exiting validators (we need to avoid mutating the state while iterating).
    // We assume it's safe to re-order the change in eligibility and `initiate_validator_exit`.
    // Rest assured exiting validators will still be exited in the same order as in the spec.
    let current_epoch = state.current_epoch();
    let is_ejectable = |validator: &Validator| {
        validator.is_active_at(current_epoch)
            && validator.effective_balance <= spec.ejection_balance
    };
    let fork_name = state.fork_name_unchecked();
    let indices_to_update: Vec<_> = state
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| {
            validator.is_eligible_for_activation_queue(spec, fork_name) || is_ejectable(validator)
        })
        .map(|(idx, _)| idx)
        .collect();

    for index in indices_to_update {
        let validator = state.get_validator_mut(index)?;
        if validator.is_eligible_for_activation_queue(spec, fork_name) {
            validator.activation_eligibility_epoch = current_epoch.safe_add(1)?;
        }
        if is_ejectable(validator) {
            initiate_validator_exit(state, index, spec)?;
        }
    }

    // Queue validators eligible for activation and not dequeued for activation prior to finalized epoch
    // Dequeue validators for activation up to churn limit
    let churn_limit = state.get_activation_churn_limit(spec)? as usize;

    let epoch_cache = state.epoch_cache();
    let activation_queue = epoch_cache
        .activation_queue()?
        .get_validators_eligible_for_activation(state.finalized_checkpoint().epoch, churn_limit);

    let delayed_activation_epoch = state.compute_activation_exit_epoch(current_epoch, spec)?;
    for index in activation_queue {
        state.get_validator_mut(index)?.activation_epoch = delayed_activation_epoch;
    }

    Ok(())
}

/// Updates the state for a new block, whilst validating that the block is valid, optionally
/// checking the block proposer signature.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// If `block_root` is `Some`, this root is used for verification of the proposer's signature. If it
/// is `None` the signing root is computed from scratch. This parameter only exists to avoid
/// re-calculating the root when it is already known. Note `block_root` should be equal to the
/// tree hash root of the block, NOT the signing root of the block. This function takes
/// care of mixing in the domain.
pub fn per_block_processing<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    signed_block: &SignedBeaconBlock<E, Payload>,
    block_signature_strategy: BlockSignatureStrategy,
    // verify_block_root: VerifyBlockRoot,
    ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let block = signed_block.message();

    // // Verify that the `SignedBeaconBlock` instantiation matches the fork at `signed_block.slot()`.
    // signed_block
    //     .fork_name(spec)
    //     .map_err(BlockProcessingError::InconsistentBlockFork)?;
    //
    // // Verify that the `BeaconState` instantiation matches the fork at `state.slot()`.
    // state
    //     .fork_name(spec)
    //     .map_err(BlockProcessingError::InconsistentStateFork)?;
    //
    // // Build epoch cache if it hasn't already been built, or if it is no longer valid
    // initialize_epoch_cache(state, spec)?;
    // initialize_progressive_balances_cache(state, spec)?;
    // state.build_slashings_cache()?;
    //
    let verify_signatures = match block_signature_strategy {
        BlockSignatureStrategy::VerifyBulk => {
            // Verify all signatures in the block at once.
            block_verify!(
                BlockSignatureVerifier::verify_entire_block(
                    state,
                    |i| get_pubkey_from_state(state, i),
                    |pk_bytes| pk_bytes.decompress().ok().map(Cow::Owned),
                    signed_block,
                    ctxt,
                    spec
                )
                .is_ok(),
                BlockProcessingError::BulkSignatureVerificationFailed
            );
            VerifySignatures::False
        }
        BlockSignatureStrategy::VerifyIndividual => VerifySignatures::True,
        BlockSignatureStrategy::NoVerification => VerifySignatures::False,
        BlockSignatureStrategy::VerifyRandao => VerifySignatures::False,
    };
    //
    // let proposer_index = process_block_header(
    //     state,
    //     block.temporary_block_header(),
    //     verify_block_root,
    //     ctxt,
    //     spec,
    // )?;
    //
    // if verify_signatures.is_true() {
    //     verify_block_signature(state, signed_block, ctxt, spec)?;
    // }
    //
    // let verify_randao = if let BlockSignatureStrategy::VerifyRandao = block_signature_strategy {
    //     VerifySignatures::True
    // } else {
    //     verify_signatures
    // };
    // Ensure the current and previous epoch committee caches are built.
    // state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    // state.build_committee_cache(RelativeEpoch::Current, spec)?;

    // The call to the `process_execution_payload` must happen before the call to the
    // `process_randao` as the former depends on the `randao_mix` computed with the reveal of the
    // previous block.
    // if is_execution_enabled(state, block.body()) {
        let body = block.body();
        process_withdrawals::<E, Payload>(state, body.execution_payload()?, spec)?;
        // process_execution_payload::<E, Payload>(state, body, spec)?; evm交易
    // }

    // process_randao(state, block, verify_randao, ctxt, spec)?;
    // process_eth1_data(state, block.body().eth1_data())?;
    // process_operations(state, block.body(), verify_signatures, ctxt, spec)?;
    process_operations(state, block.body(), verify_signatures, spec)?;

    // if let Ok(sync_aggregate) = block.body().sync_aggregate() {
    //     process_sync_aggregate(
    //         state,
    //         sync_aggregate,
    //         proposer_index,
    //         verify_signatures,
    //         spec,
    //     )?;
    // }
    //
    // if is_progressive_balances_enabled(state) {
    //     update_progressive_balances_metrics(state.progressive_balances_cache())?;
    // }

    Ok(())
}

pub fn process_operations<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    block_body: BeaconBlockBodyRef<E, Payload>,
    verify_signatures: VerifySignatures,
    // ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // process_proposer_slashings(
    //     state,
    //     block_body.proposer_slashings(),
    //     verify_signatures,
    //     ctxt,
    //     spec,
    // )?;
    // process_attester_slashings(
    //     state,
    //     block_body.attester_slashings(),
    //     verify_signatures,
    //     ctxt,
    //     spec,
    // )?;
    // process_attestations(state, block_body, verify_signatures, ctxt, spec)?;
    process_deposits(state, block_body.deposits(), spec)?;
    process_exits(state, block_body.voluntary_exits(), verify_signatures, spec)?;

    // if let Ok(bls_to_execution_changes) = block_body.bls_to_execution_changes() {
    //     process_bls_to_execution_changes(state, bls_to_execution_changes, verify_signatures, spec)?;
    // }

    // if state.fork_name_unchecked().electra_enabled() {
        state.update_pubkey_cache()?;
        // process_deposit_requests(state, &block_body.execution_requests()?.deposits, spec)?;存款请求
        process_withdrawal_requests(state, &block_body.execution_requests()?.withdrawals, spec)?;
        // process_consolidation_requests( 合并请求
        //     state,
        //     &block_body.execution_requests()?.consolidations,
        //     spec,
        // )?;
    // }

    Ok(())
}

/// Validates each `Deposit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
pub fn process_deposits<E: EthSpec>(
    state: &mut BeaconState<E>,
    deposits: &[Deposit],
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // [Modified in Electra:EIP6110]
    // Disable former deposit mechanism once all prior deposits are processed
    let deposit_requests_start_index = state.deposit_requests_start_index().unwrap_or(u64::MAX);
    let eth1_deposit_index_limit = std::cmp::min(
        deposit_requests_start_index,
        state.eth1_data().deposit_count,
    );

    if state.eth1_deposit_index() < eth1_deposit_index_limit {
        let expected_deposit_len = std::cmp::min(
            E::MaxDeposits::to_u64(),
            eth1_deposit_index_limit.safe_sub(state.eth1_deposit_index())?,
        );
        block_verify!(
            deposits.len() as u64 == expected_deposit_len,
            BlockProcessingError::DepositCountInvalid {
                expected: expected_deposit_len as usize,
                found: deposits.len(),
            }
        );
    } else {
        block_verify!(
            deposits.len() as u64 == 0,
            BlockProcessingError::DepositCountInvalid {
                expected: 0,
                found: deposits.len(),
            }
        );
    }

    // Verify merkle proofs in parallel.
    deposits
        .par_iter()
        .enumerate()
        .try_for_each(|(i, deposit)| {
            verify_deposit_merkle_proof(
                state,
                deposit,
                state.eth1_deposit_index().safe_add(i as u64)?,
                spec,
            )
                .map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    for deposit in deposits {
        apply_deposit(state, deposit.data.clone(), None, true, spec)?;
    }

    Ok(())
}

/// Process a single deposit, verifying its merkle proof if provided.
pub fn apply_deposit<E: EthSpec>(
    state: &mut BeaconState<E>,
    deposit_data: DepositData,
    proof: Option<FixedVector<Hash256, U33>>,
    increment_eth1_deposit_index: bool,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let deposit_index = state.eth1_deposit_index() as usize;
    if let Some(proof) = proof {
        let deposit = Deposit {
            proof,
            data: deposit_data.clone(),
        };
        verify_deposit_merkle_proof(state, &deposit, state.eth1_deposit_index(), spec)
            .map_err(|e| e.into_with_index(deposit_index))?;
    }

    if increment_eth1_deposit_index {
        state.eth1_deposit_index_mut().safe_add_assign(1)?;
    }

    // Get an `Option<u64>` where `u64` is the validator index if this deposit public key
    // already exists in the beacon_state.
    let validator_index = get_existing_validator_index(state, &deposit_data.pubkey)
        .map_err(|e| e.into_with_index(deposit_index))?;

    let amount = deposit_data.amount;

    if let Some(index) = validator_index {
        // [Modified in Electra:EIP7251]
        if let Ok(pending_deposits) = state.pending_deposits_mut() {
            pending_deposits.push(PendingDeposit {
                pubkey: deposit_data.pubkey,
                withdrawal_credentials: deposit_data.withdrawal_credentials,
                amount,
                signature: deposit_data.signature,
                slot: spec.genesis_slot, // Use `genesis_slot` to distinguish from a pending deposit request
            })?;
        } else {
            // Update the existing validator balance.
            increase_balance(state, index as usize, amount)?;
        }
    }
    // New validator
    else {
        // The signature should be checked for new validators. Return early for a bad
        // signature.
        if is_valid_deposit_signature(&deposit_data, spec).is_err() {
            return Ok(());
        }

        state.add_validator_to_registry(
            deposit_data.pubkey,
            deposit_data.withdrawal_credentials,
            if state.fork_name_unchecked() >= ForkName::Electra {
                0
            } else {
                amount
            },
            spec,
        )?;

        // [New in Electra:EIP7251]
        if let Ok(pending_deposits) = state.pending_deposits_mut() {
            pending_deposits.push(PendingDeposit {
                pubkey: deposit_data.pubkey,
                withdrawal_credentials: deposit_data.withdrawal_credentials,
                amount,
                signature: deposit_data.signature,
                slot: spec.genesis_slot, // Use `genesis_slot` to distinguish from a pending deposit request
            })?;
        }
    }

    Ok(())
}

/// Validates each `Exit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
pub fn process_exits<E: EthSpec>(
    state: &mut BeaconState<E>,
    voluntary_exits: &[SignedVoluntaryExit],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify and apply each exit in series. We iterate in series because higher-index exits may
    // become invalid due to the application of lower-index ones.
    for (i, exit) in voluntary_exits.iter().enumerate() {
        verify_exit(state, None, exit, verify_signatures, spec)
            .map_err(|e| e.into_with_index(i))?;

        initiate_validator_exit(state, exit.message.validator_index as usize, spec)?;
    }
    Ok(())
}

// Make sure to build the pubkey cache before calling this function
pub fn process_withdrawal_requests<E: EthSpec>(
    state: &mut BeaconState<E>,
    requests: &[WithdrawalRequest],
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    for request in requests {
        let amount = request.amount;
        let is_full_exit_request = amount == spec.full_exit_request_amount;

        // If partial withdrawal queue is full, only full exits are processed
        if state.pending_partial_withdrawals()?.len() == E::pending_partial_withdrawals_limit()
            && !is_full_exit_request
        {
            continue;
        }

        // Verify pubkey exists
        let Some(validator_index) = state.pubkey_cache().get(&request.validator_pubkey) else {
            continue;
        };

        let validator = state.get_validator(validator_index)?;
        // Verify withdrawal credentials
        let has_correct_credential = validator.has_execution_withdrawal_credential(spec);
        let is_correct_source_address = validator
            .get_execution_withdrawal_address(spec)
            .map(|addr| addr == request.source_address)
            .unwrap_or(false);

        if !(has_correct_credential && is_correct_source_address) {
            continue;
        }

        // Verify the validator is active
        if !validator.is_active_at(state.current_epoch()) {
            continue;
        }

        // Verify exit has not been initiated
        if validator.exit_epoch != spec.far_future_epoch {
            continue;
        }

        // Verify the validator has been active long enough
        if state.current_epoch()
            < validator
            .activation_epoch
            .safe_add(spec.shard_committee_period)?
        {
            continue;
        }

        let pending_balance_to_withdraw = state.get_pending_balance_to_withdraw(validator_index)?;
        if is_full_exit_request {
            // Only exit validator if it has no pending withdrawals in the queue
            if pending_balance_to_withdraw == 0 {
                initiate_validator_exit(state, validator_index, spec)?
            }
            continue;
        }

        let balance = state.get_balance(validator_index)?;
        let has_sufficient_effective_balance =
            validator.effective_balance >= spec.min_activation_balance;
        let has_excess_balance = balance
            > spec
            .min_activation_balance
            .safe_add(pending_balance_to_withdraw)?;

        // Only allow partial withdrawals with compounding withdrawal credentials
        if validator.has_compounding_withdrawal_credential(spec)
            && has_sufficient_effective_balance
            && has_excess_balance
        {
            let to_withdraw = std::cmp::min(
                balance
                    .safe_sub(spec.min_activation_balance)?
                    .safe_sub(pending_balance_to_withdraw)?,
                amount,
            );
            let exit_queue_epoch = state.compute_exit_epoch_and_update_churn(to_withdraw, spec)?;
            let withdrawable_epoch =
                exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
            state
                .pending_partial_withdrawals_mut()?
                .push(PendingPartialWithdrawal {
                    validator_index: validator_index as u64,
                    amount: to_withdraw,
                    withdrawable_epoch,
                })?;
        }
    }
    Ok(())
}

/// Initiate the exit of the validator of the given `index`.
pub fn initiate_validator_exit<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    let validator = state.get_validator_cow(index)?;// 只读

    // Return if the validator already initiated exit
    if validator.exit_epoch != spec.far_future_epoch {
        return Ok(());
    }

    // Ensure the exit cache is built.第一次时调用，把已退出验证者加入缓存
    state.build_exit_cache(spec)?;

    // Compute exit queue epoch 用余额和churn计算
    let effective_balance = state.get_effective_balance(index)?;
    let exit_queue_epoch = state.compute_exit_epoch_and_update_churn(effective_balance, spec)?;

    let validator = state.get_validator_mut(index)?;
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch =
        exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;

    state
        .exit_cache_mut()
        .record_validator_exit(exit_queue_epoch)?;

    Ok(())
}

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

        // Update the next withdrawal index if this block contained withdrawals 有处理提现，最后提现id加1
        if let Some(latest_withdrawal) = expected_withdrawals.last() {
            *state.next_withdrawal_index_mut()? = latest_withdrawal.index.safe_add(1)?;

            // Update the next validator index to start the next withdrawal sweep
            // 提现数等于最大payload值，下次扫描起点是本次末尾验证者id加1
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
        //  这一段validator提现都处理完成，下次扫描起点是上次起始索引加一大段，提现数小于payload最大值
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

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    increase_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    balance.safe_add_assign(delta)?;
    Ok(())
}