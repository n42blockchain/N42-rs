use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use ssz_derive::{Encode, Decode};
use ssz::{Encode, Decode};
//use tree_hash_derive::TreeHash;
use integer_sqrt::IntegerSquareRoot;
use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals}, eip7002::WithdrawalRequest, eip7685::Requests
};
use serde::{Deserialize, Serialize};
use alloy_primitives::{FixedBytes, Sealable};
use alloy_primitives::{Address, Bytes, keccak256, BlockHash, B256, Log};
use alloy_sol_types::{SolEnum, SolEvent, sol};
use tracing::{trace, debug, error, info, warn};

use std::collections::{HashMap, BTreeMap};
use crate::{activation_queue::ActivationQueue, beacon_committee::BeaconCommittee, committee_cache::get_active_validator_indices, Hash256, Slot, Validator};
use crate::safe_aitrh::SafeArith;
use crate::safe_aitrh::SafeArithIter;
use std::sync::Arc;
use crate::committee_cache::CommitteeCache;
use ethereum_hashing::hash;

pub const SLOTS_PER_EPOCH: u64 = 5;
const REWARD_AMOUNT: u64 = 1;

// EthSpec
pub const max_withdrawals_per_payload: usize = 16;
pub const pending_partial_withdrawals_limit: usize = 16; // ?
pub const MaxDeposits: u64 = 16;
pub const genesis_epoch : u64 = 0;

// chain_spec
pub const max_pending_partials_per_withdrawals_sweep: u64 = 16; // ?
pub const min_activation_balance: u64 = 32000000000;
pub const ejection_balance: u64 = 16000000000;
pub const far_future_epoch: u64 = u64::max_value();
pub const max_validators_per_withdrawals_sweep: u64 = 16384;
pub const max_effective_balance: u64 = 32000000000; //?
pub const full_exit_request_amount: u64 = 0;
pub const shard_committee_period: u64 = 1; //?
pub const compounding_withdrawal_prefix_byte: u8 = 0x02;
pub const eth1_address_withdrawal_prefix_byte: u8 = 0x01;
pub const max_seed_lookahead: u64 = 4;
pub const max_per_epoch_activation_exit_churn_limit:u64 = 256000000000;
pub const min_per_epoch_churn_limit_electra:u64 = 128000000000;
pub const churn_limit_quotient:u64 = 32;
pub const effective_balance_increment:u64 = 1000000000;
pub const base_rewards_per_epoch:u64 = 4;
pub const base_reward_factor:u64 = 64;
pub const min_epochs_to_inactivity_penalty :u64 = 4;
pub const inactivity_penalty_quotient:u64 = 67108864; //?
pub const proposer_reward_quotient:u64 = 4;
pub const min_per_epoch_churn_limit:u64 = 4;
pub const max_committees_per_slot: usize = 4;
pub const target_committee_size: usize = 4;
pub const min_seed_lookahead: u64 = 1;
pub const shuffle_round_count: u8 = 10;

pub const min_validator_withdrawability_delay: u64 = 1;

pub const CACHED_EPOCHS: usize = 3;

macro_rules! verify {
    ($condition: expr, $result: expr) => {
        if !$condition {
            //return Err(eyre::eyre!("BlockOperationError {$result}"));
            return Err(eyre::eyre!($result));
        }
    };
}

/// Solidity-style struct for the DepositEvent
sol! {
    #[derive(Debug)]
    event DepositEvent (
        bytes pubkey,
        bytes withdrawal_credentials,
        bytes amount,
        bytes signature,
        bytes index,
    );
}


pub type Epoch = u64;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct VoluntaryExit {
    pub epoch: Epoch,
    pub validator_index: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct VoluntaryExitWithSig {
    pub voluntary_exit: VoluntaryExit,
    pub signature: Bytes,
}

pub struct BeaconStateChangeset{
    pub beaconstates:Vec<(BlockHash,BeaconState)>,
}

pub struct BeaconBlockChangeset{
    pub beaconblocks:Vec<(BlockHash,BeaconBlock)>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct BeaconState {
    pub slot: u64,
    pub eth1_deposit_index: u64,
    pub validators: Vec<Validator>,
    pub balances: Vec<Gwei>,

    pub next_withdrawal_index: u64,
    pub next_withdrawal_validator_index: u64,
    pub pending_partial_withdrawals: Vec<PendingPartialWithdrawal>,
    pub earliest_exit_epoch: Epoch,
    pub exit_balance_to_consume: u64,

    pub eth1_data: Eth1Data,

    //pub total_active_balance: Option<TotalActiveBalance>,

    pub committee_caches: Vec<CommitteeCache>,
}

/*
#[derive(Debug, Clone, Hash, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct TotalActiveBalance(Epoch, u64);
*/

impl Sealable for BeaconState {
    fn hash_slow(&self) -> B256 {
        let out = self.as_ssz_bytes();
        keccak256(&out)
    }
}

pub type Gwei = u64;

// mock
pub type BLSPubkey = FixedBytes<48>;
pub type BLSSignature = FixedBytes<96>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct BeaconBlock {
    pub eth1_block_hash: BlockHash,
    pub parent_hash: BlockHash,
    pub state_root: B256,
    pub body: BeaconBlockBody,
}

impl Sealable for BeaconBlock {
    fn hash_slow(&self) -> B256 {
        let out = self.as_ssz_bytes();
        keccak256(&out)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct BeaconBlockBody {
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub voluntary_exits: Vec<VoluntaryExitWithSig>,
    pub execution_requests: ExecutionRequestsV4,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionRequests {
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<WithdrawalRequest>,
    pub consolidations: Vec<ConsolidationRequest>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct DepositRequest {
    pub pubkey: Bytes,
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: Bytes,
    pub index: u64,
}

/*
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: Bytes,
    pub amount: u64,
}
*/

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: Bytes,
    pub target_pubkey: Bytes,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Attestation {
    pub pubkey: BLSPubkey,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Deposit {
    pub proof: Vec<B256>,
    pub data: DepositData,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct DepositData {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: B256,
    pub amount: Gwei,
    pub signature: BLSSignature,
}

pub fn parse_deposit_log(log: &Log) -> Option<DepositEvent> {
    let deposit_event_sig = b"DepositEvent(bytes,bytes,bytes,bytes,bytes)";
    let deposit_topic: B256 = keccak256(deposit_event_sig).into();
    debug!(target: "consensus-client", ?deposit_topic, "parse_deposit_log");
    if let Some(&topic) = log.topics().get(0) {
        if topic == deposit_topic {
            match DepositEvent::decode_log(&log) {
                Ok(v) => Some(v.data),
                Err(err) => {
                    error!(target: "consensus-client", ?err, "parse_deposit_log failed");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    }
}

impl BeaconState {
    pub fn new() -> Self {
        Self {
            committee_caches: vec![Default::default(); 3],
            ..Default::default()
        }
    }

    pub fn state_transition(old_beacon_state: &BeaconState, beacon_block: &BeaconBlock) -> eyre::Result<Self> {
        debug!(target: "consensus-client", ?old_beacon_state, ?beacon_block, "state_transition");
        let mut new_beacon_state = old_beacon_state.clone();
        new_beacon_state.slot += 1;
        if (new_beacon_state.slot) % SLOTS_PER_EPOCH == 0 {
            new_beacon_state.process_epoch()?;
        }
        new_beacon_state.process_block(&beacon_block)?;

        Ok(new_beacon_state)
    }

    pub fn process_epoch(&mut self) -> eyre::Result<()> {
        // workaround empty validators
        let epoch = self.current_epoch();
        let active_validator_indices = get_active_validator_indices(&self.validators, epoch);
        if !active_validator_indices.is_empty() {
            self.build_all_committee_caches()?;
        }

        let validator_statuses = ValidatorStatuses::new(self)?;
        self.process_rewards_and_penalties(&validator_statuses)?;
        self.process_registry_updates()?;

        Ok(())
    }

    pub fn process_registry_updates(&mut self) -> eyre::Result<()> {
        // Process activation eligibility and ejections.
        // Collect eligible and exiting validators (we need to avoid mutating the state while iterating).
        // We assume it's safe to re-order the change in eligibility and `initiate_validator_exit`.
        // Rest assured exiting validators will still be exited in the same order as in the spec.
        let current_epoch = self.current_epoch();
        let is_ejectable = |validator: &Validator| {
            validator.is_active_at(current_epoch)
                && validator.effective_balance <= ejection_balance
        };
        //let fork_name = state.fork_name_unchecked();
        let indices_to_update: Vec<_> = self
            .validators
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.is_eligible_for_activation_queue() || is_ejectable(validator)
            })
            .map(|(idx, _)| idx)
            .collect();

        for index in indices_to_update {
            let validator = self.get_validator_mut(index)?;
            if validator.is_eligible_for_activation_queue() {
                validator.activation_eligibility_epoch = current_epoch.safe_add(1)?;
            }
            if is_ejectable(validator) {
                self.initiate_validator_exit(index)?;
            }
        }

        // Queue validators eligible for activation and not dequeued for activation prior to finalized epoch
        // Dequeue validators for activation up to churn limit
        let churn_limit = self.get_activation_churn_limit()? as usize;

        let next_epoch = self.next_epoch()?;
        let mut full_activation_queue = ActivationQueue::default();

        for (index, validator) in self.validators.iter().enumerate() {

            // Add to speculative activation queue.
            full_activation_queue
                .add_if_could_be_eligible_for_activation(index, validator, next_epoch);
        }

        //let epoch_cache = state.epoch_cache();
        let activation_queue =
            full_activation_queue
            .get_validators_eligible_for_activation(current_epoch, churn_limit);
            //.get_validators_eligible_for_activation(state.finalized_checkpoint().epoch, churn_limit);

        let delayed_activation_epoch = self.compute_activation_exit_epoch(current_epoch)?;
        for index in activation_queue {
            self.get_validator_mut(index)?.activation_epoch = delayed_activation_epoch;
        }

        Ok(())
    }

    pub fn process_block(&mut self, beacon_block: &BeaconBlock) -> eyre::Result<()> {
        self.process_operations(&beacon_block.body)?;
        Ok(())
    }

    pub fn process_operations(&mut self, beacon_block_body: &BeaconBlockBody) -> eyre::Result<()> {
        //self.process_deposit(&beacon_block_body.deposits)?;
        //self.process_attestation(&beacon_block_body.attestations)?;
        //self.process_voluntary_exit(&beacon_block_body.voluntary_exits)?;

        let deposits: Vec<Deposit> = beacon_block_body.execution_requests.deposits.clone().iter().map(|deposit_request| {
            Deposit {
                proof: Default::default(),
                data: DepositData {
                    pubkey: deposit_request.pubkey,
                    withdrawal_credentials: deposit_request.withdrawal_credentials,
                    amount: deposit_request.amount,
                    signature: deposit_request.signature,
                }
            }

        }).collect();
        self.process_deposits(&deposits)?;
        self.process_exits(&beacon_block_body.voluntary_exits)?;
        self.process_withdrawal_requests(&beacon_block_body.execution_requests.withdrawals)?;

        Ok(())
    }

    pub fn process_withdrawal_requests(&mut self, requests: &[WithdrawalRequest]) -> eyre::Result<()> {
        for request in requests {
            let amount = request.amount;
            let is_full_exit_request = amount == full_exit_request_amount;

            // If partial withdrawal queue is full, only full exits are processed
            if self.pending_partial_withdrawals.len() == pending_partial_withdrawals_limit
                && !is_full_exit_request
            {
                continue;
            }

            // Verify pubkey exists
            let Some(validator_index) = self.get_validator_index_from_pubkey(&request.validator_pubkey) else {
                continue;
            };

            let validator = self.get_validator(validator_index)?;
            // Verify withdrawal credentials
            let has_correct_credential = validator.has_execution_withdrawal_credential();
            let is_correct_source_address = validator
                .get_execution_withdrawal_address()
                .map(|addr| addr == request.source_address)
                .unwrap_or(false);

            if !(has_correct_credential && is_correct_source_address) {
                continue;
            }

            // Verify the validator is active
            if !validator.is_active_at(self.current_epoch()) {
                continue;
            }

            // Verify exit has not been initiated
            if validator.exit_epoch != far_future_epoch {
                continue;
            }

            // Verify the validator has been active long enough
            if self.current_epoch()
                < validator
                .activation_epoch
                .safe_add(shard_committee_period)?
            {
                continue;
            }

            let pending_balance_to_withdraw = self.get_pending_balance_to_withdraw(validator_index)?;
            if is_full_exit_request {
                // Only exit validator if it has no pending withdrawals in the queue
                if pending_balance_to_withdraw == 0 {
                    self.initiate_validator_exit(validator_index)?
                }
                continue;
            }

            let balance = self.get_balance(validator_index)?;
            let has_sufficient_effective_balance =
                validator.effective_balance >= min_activation_balance;
            let has_excess_balance = balance
                > 
                min_activation_balance
                .safe_add(pending_balance_to_withdraw)?;

            // Only allow partial withdrawals with compounding withdrawal credentials
            if validator.has_compounding_withdrawal_credential()
                && has_sufficient_effective_balance
                && has_excess_balance
            {
                let to_withdraw = std::cmp::min(
                    balance
                        .safe_sub(min_activation_balance)?
                        .safe_sub(pending_balance_to_withdraw)?,
                    amount,
                );
                let exit_queue_epoch = self.compute_exit_epoch_and_update_churn(to_withdraw)?;
                let withdrawable_epoch =
                    exit_queue_epoch.safe_add(min_validator_withdrawability_delay)?;
                self
                    //.pending_partial_withdrawals_mut()?
                    .pending_partial_withdrawals
                    .push(PendingPartialWithdrawal {
                        validator_index: validator_index as u64,
                        amount: to_withdraw,
                        withdrawable_epoch,
                    });
            }
        }
        Ok(())
    }

    pub fn process_deposit(&mut self, deposits: &Vec<Deposit>) -> eyre::Result<()> {
        // TODO: check deposits against eth1 block and beacon state
        // TODO: update state
        for deposit in deposits {
            let _ = self.process_one_deposit(deposit);
        }
        Ok(())
    }

    pub fn process_one_deposit(&mut self, deposit: &Deposit) -> eyre::Result<()> {
        let mut updated = false;
        for (index, validator) in self.validators.iter_mut().enumerate() {
            if validator.pubkey == deposit.data.pubkey {
                validator.effective_balance += deposit.data.amount;
                self.balances[index] += deposit.data.amount;
                updated = true;
            }
        }

        if !updated {
            let validator = Validator {
                pubkey: deposit.data.pubkey.clone(),
                withdrawal_credentials: deposit.data.withdrawal_credentials,
                effective_balance: deposit.data.amount,
                activation_epoch: self.slot / SLOTS_PER_EPOCH + 1,
                ..Default::default()
            };
            self.validators.push(validator);
            self.balances.push(deposit.data.amount);
        }

        Ok(())
    }

    pub fn process_attestation(&mut self, attestations: &Vec<Attestation>) -> eyre::Result<()> {
        // TODO: check attestations against beacon state
        // TODO: update state
        for attestation in attestations {
            let _ = self.process_one_attestation(attestation);
        }

        Ok(())
    }

    pub fn process_one_attestation(&mut self, attestation: &Attestation) -> eyre::Result<()> {
        let epoch = self.current_epoch();
        for (index, validator) in self.validators.iter_mut().enumerate() {
            if validator.pubkey == attestation.pubkey && epoch >= validator.activation_epoch && (validator.exit_epoch == 0 || epoch < validator.exit_epoch) {
                validator.effective_balance += REWARD_AMOUNT;
                self.balances[index] += REWARD_AMOUNT;
                break;
            }
        }

        Ok(())
    }

    pub fn process_voluntary_exit(&mut self, voluntary_exits: &Vec<VoluntaryExitWithSig>) -> eyre::Result<()> {
        // TODO: check voluntary exits against beacon state
        // TODO: update state
        for voluntary_exit in voluntary_exits {
            let _ = self.process_one_voluntary_exit(voluntary_exit);
        }
        Ok(())
    }

    pub fn process_one_voluntary_exit(&mut self, voluntary_exit: &VoluntaryExitWithSig) -> eyre::Result<()> {
        let voluntary_exit = &voluntary_exit.voluntary_exit;
        let validator_index: usize = voluntary_exit.validator_index as usize;
        if validator_index >= self.validators.len() {
            return Ok(());
        }
        if self.validators[validator_index].withdrawable_epoch == 0 {
            let exit_epoch = voluntary_exit.epoch;
            self.validators[validator_index].exit_epoch = exit_epoch;
            self.validators[validator_index].withdrawable_epoch = exit_epoch + 1;
        }

        Ok(())
    }

    pub fn valid_validators(&self) -> Vec<Validator> {
        let mut validators = self.validators.clone();
        validators.retain(|validator| {
            let epoch = self.current_epoch();
            epoch >= validator.activation_epoch && (validator.exit_epoch == 0 || epoch < validator.exit_epoch)
        });
        validators
    }

    pub fn get_expected_withdrawals(&self) -> eyre::Result<(Vec<Withdrawal>, Option<usize>)> {
        debug!(target: "consensus-client", "get_expected_withdrawals");
        let epoch = self.current_epoch();
        let mut withdrawal_index = self.next_withdrawal_index;
        let mut validator_index = self.next_withdrawal_validator_index;
        let mut withdrawals = Vec::<Withdrawal>::with_capacity(max_withdrawals_per_payload);

        let mut processed_partial_withdrawals_count = 0;

            for withdrawal in self.pending_partial_withdrawals.iter() {
                if withdrawal.withdrawable_epoch > epoch
                    || withdrawals.len() == max_pending_partials_per_withdrawals_sweep as usize
                {
                    break;
                }

                let validator = self.get_validator(withdrawal.validator_index as usize)?;

                let has_sufficient_effective_balance =
                    validator.effective_balance >= min_activation_balance;
                let total_withdrawn = withdrawals
                    .iter()
                    .filter_map(|w| {
                        (w.validator_index == withdrawal.validator_index).then_some(w.amount)
                    })
                    .safe_sum()?;
                let balance = self
                    .get_balance(withdrawal.validator_index as usize)?
                    .safe_sub(total_withdrawn)?;
                let has_excess_balance = balance > min_activation_balance;

                if validator.exit_epoch == far_future_epoch
                    && has_sufficient_effective_balance
                    && has_excess_balance
                {
                    let withdrawable_balance = std::cmp::min(
                        balance.safe_sub(min_activation_balance)?,
                        withdrawal.amount,
                    );
                    withdrawals.push(Withdrawal {
                        index: withdrawal_index,
                        validator_index: withdrawal.validator_index,
                        address: validator
                            .get_execution_withdrawal_address()
                            .ok_or(eyre::eyre!("NonExecutionAddressWithdrawalCredential"))?,
                        amount: withdrawable_balance,
                    });
                    withdrawal_index.safe_add_assign(1)?;
                }
                processed_partial_withdrawals_count.safe_add_assign(1)?;
            }

    let bound = std::cmp::min(
        self.validators.len() as u64,
        max_validators_per_withdrawals_sweep,
    );
    debug!(target: "consensus-client", ?bound, "get_expected_withdrawals");
    for _ in 0..bound {
        let validator = self.get_validator(validator_index as usize)?;
        let partially_withdrawn_balance = withdrawals
            .iter()
            .filter_map(|withdrawal| {
                (withdrawal.validator_index == validator_index).then_some(withdrawal.amount)
            })
            .safe_sum()?;
        let balance = self.get_balance(validator_index as usize)?
            .safe_sub(partially_withdrawn_balance)?;
        if validator.is_fully_withdrawable_validator(balance, epoch) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address()
                    //.ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                    .ok_or(eyre::eyre!("WithdrawalCredentialsInvalid"))?,
                amount: balance,
            });
            withdrawal_index.safe_add_assign(1)?;
        } else if validator.is_partially_withdrawable_validator(balance) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address()
                    //.ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                    .ok_or(eyre::eyre!("WithdrawalCredentialsInvalid"))?,
                //amount: balance.safe_sub(validator.get_max_effective_balance(spec, fork_name))?,
                amount: balance.safe_sub(max_effective_balance)?,
            });
            withdrawal_index.safe_add_assign(1)?;
        }
        if withdrawals.len() == max_withdrawals_per_payload {
            break;
        }
        validator_index = validator_index
            .safe_add(1)?
            .safe_rem(self.validators.len() as u64)?;
    }

    debug!(target: "consensus-client", ?withdrawals, processed_partial_withdrawals_count, "get_expected_withdrawals");
    Ok((withdrawals, Some(processed_partial_withdrawals_count)))
    }

    pub fn process_withdrawals(&mut self) -> eyre::Result<(Vec<Withdrawal>, Option<usize>)> {
        let (expected_withdrawals, processed_partial_withdrawals_count) =
            self.get_expected_withdrawals()?;

        // TODO: check expected_withdrawals hash root against execution payload withdrawals root

        for withdrawal in expected_withdrawals.iter() {
            decrease_balance(
                self,
                withdrawal.validator_index as usize,
                withdrawal.amount,
            )?;
        }

        // Update pending partial withdrawals [New in Electra:EIP7251]
        if let Some(processed_partial_withdrawals_count) = processed_partial_withdrawals_count.clone() {
            self
                //.pending_partial_withdrawals_mut()?
                //.pop_front(processed_partial_withdrawals_count)?;
                .pending_partial_withdrawals
                .drain(0..processed_partial_withdrawals_count);
        }

        // Update the next withdrawal index if this block contained withdrawals
        if let Some(latest_withdrawal) = expected_withdrawals.last() {
            //*state.next_withdrawal_index_mut()? = latest_withdrawal.index.safe_add(1)?;
            self.next_withdrawal_index = latest_withdrawal.index.safe_add(1)?;

            // Update the next validator index to start the next withdrawal sweep
            if expected_withdrawals.len() == max_withdrawals_per_payload {
                // Next sweep starts after the latest withdrawal's validator index
                let next_validator_index = latest_withdrawal
                    .validator_index
                    .safe_add(1)?
                    .safe_rem(self.validators.len() as u64)?;
                self.next_withdrawal_validator_index = next_validator_index;
            }
        }

        // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        if expected_withdrawals.len() != max_withdrawals_per_payload && !self.validators.is_empty() {
            let next_validator_index = self
                .next_withdrawal_validator_index
                .safe_add(max_validators_per_withdrawals_sweep)?
                .safe_rem(self.validators.len() as u64)?;
            self.next_withdrawal_validator_index = next_validator_index;
        }

        Ok((expected_withdrawals, processed_partial_withdrawals_count))
    }

    pub fn current_epoch(&self) -> Epoch {
        self.slot / SLOTS_PER_EPOCH
    }

    pub fn next_epoch(&self) -> eyre::Result<Epoch> {
        Ok(self.current_epoch().safe_add(1)?)
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    pub fn previous_epoch(&self) -> Epoch {
        let current_epoch = self.current_epoch();
        if let Ok(prev_epoch) = current_epoch.safe_sub(1) {
            prev_epoch
        } else {
            current_epoch
        }
    }

    /// Safe indexer for the `validators` list.
    pub fn get_validator(&self, validator_index: usize) -> eyre::Result<&Validator> {
        self.validators
            .get(validator_index)
            .ok_or(eyre::eyre!(format!("UnknownValidator, {validator_index}")))
    }

    /// Safe mutator for the `validators` list.
    pub fn get_validator_mut(&mut self, validator_index: usize) -> eyre::Result<&mut Validator> {
        self.validators
            .get_mut(validator_index)
            .ok_or(eyre::eyre!(format!("UnknownValidator, {validator_index}")))
    }

    pub fn get_balance(&self, validator_index: usize) -> eyre::Result<u64> {
        self.balances
            .get(validator_index)
            .ok_or(eyre::eyre!(format!("UnknownValidator, {validator_index}")))
            .copied()
    }

    /// Get a mutable reference to the balance of a single validator.
    pub fn get_balance_mut(&mut self, validator_index: usize) -> eyre::Result<&mut u64> {
        self.balances
            .get_mut(validator_index)
            .ok_or(eyre::eyre!(format!("BalancesOutOfBounds, {validator_index}")))
    }

    pub fn get_pending_balance_to_withdraw(&self, validator_index: usize) -> eyre::Result<u64> {
        let mut pending_balance = 0;
        for withdrawal in self
            .pending_partial_withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.validator_index as usize == validator_index)
        {
            pending_balance.safe_add_assign(withdrawal.amount)?;
        }
        Ok(pending_balance)
    }

    pub fn compute_activation_exit_epoch(
        &self,
        epoch: Epoch,
    ) -> eyre::Result<Epoch> {
        Ok(epoch.safe_add(1)?.safe_add(max_seed_lookahead)?)
    }

    pub fn compute_exit_epoch_and_update_churn(
        &mut self,
        exit_balance: u64,
    ) -> eyre::Result<Epoch> {
        let mut earliest_exit_epoch = std::cmp::max(
            self.earliest_exit_epoch,
            self.compute_activation_exit_epoch(self.current_epoch())?,
        );

        let per_epoch_churn = self.get_activation_exit_churn_limit()?;
        // New epoch for exits
        let mut exit_balance_to_consume = if self.earliest_exit_epoch < earliest_exit_epoch {
            per_epoch_churn
        } else {
            self.exit_balance_to_consume
        };

        // Exit doesn't fit in the current earliest epoch
        if exit_balance > exit_balance_to_consume {
            let balance_to_process = exit_balance.safe_sub(exit_balance_to_consume)?;
            let additional_epochs = balance_to_process
                .safe_sub(1)?
                .safe_div(per_epoch_churn)?
                .safe_add(1)?;
            earliest_exit_epoch.safe_add_assign(additional_epochs)?;
            exit_balance_to_consume
                .safe_add_assign(additional_epochs.safe_mul(per_epoch_churn)?)?;
        }
                // Consume the balance and update state variables
                self.exit_balance_to_consume =
                    exit_balance_to_consume.safe_sub(exit_balance)?;
                self.earliest_exit_epoch = earliest_exit_epoch;
                Ok(self.earliest_exit_epoch)
    }

    pub fn get_validator_index_from_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.validators.iter().position(|validator| validator.pubkey == *pubkey)
    }

    /// Return the effective balance for a validator with the given `validator_index`.
    pub fn get_effective_balance(&self, validator_index: usize) -> eyre::Result<u64> {
        self.get_validator(validator_index)
            .map(|v| v.effective_balance)
    }

    /// Initiate the exit of the validator of the given `index`.
    pub fn initiate_validator_exit(
        &mut self,
        index: usize,
    ) -> eyre::Result<()> {
        let validator = self.get_validator(index)?;

        // Return if the validator already initiated exit
        if validator.exit_epoch != far_future_epoch {
            return Ok(());
        }

        // Ensure the exit cache is built.
        //state.build_exit_cache(spec)?;

        // Compute exit queue epoch
        let effective_balance = self.get_effective_balance(index)?;
        let exit_queue_epoch = self.compute_exit_epoch_and_update_churn(effective_balance)?;

        let validator = self.get_validator_mut(index)?;
        validator.exit_epoch = exit_queue_epoch;
        validator.withdrawable_epoch =
            exit_queue_epoch.safe_add(min_validator_withdrawability_delay)?;

        /*
        state
            .exit_cache_mut()
            .record_validator_exit(exit_queue_epoch)?;
        */

        Ok(())
    }

    /// Return the churn limit for the current epoch dedicated to activations and exits.
    pub fn get_activation_exit_churn_limit(&self) -> eyre::Result<u64> {
        Ok(std::cmp::min(
            max_per_epoch_activation_exit_churn_limit,
            self.get_balance_churn_limit()?,
        ))
    }

    /// Return the churn limit for the current epoch.
    pub fn get_balance_churn_limit(&self) -> eyre::Result<u64> {
        let total_active_balance = self.get_total_active_balance()?;
        let churn = std::cmp::max(
            min_per_epoch_churn_limit_electra,
            total_active_balance.safe_div(churn_limit_quotient)?,
        );

        Ok(churn.safe_sub(churn.safe_rem(effective_balance_increment)?)?)
    }

    /// Implementation of `get_total_active_balance`, matching the spec.
    ///
    /// Requires the total active balance cache to be initialised, which is initialised whenever
    /// the current committee cache is.
    ///
    /// Returns minimum `EFFECTIVE_BALANCE_INCREMENT`, to avoid div by 0.
    pub fn get_total_active_balance(&self) -> eyre::Result<u64> {
        self.compute_total_active_balance_slow()
        // self.get_total_active_balance_at_epoch(self.current_epoch())
    }

    /// Get the cached total active balance while checking that it is for the correct `epoch`.
    pub fn get_total_active_balance_at_epoch(&self, epoch: Epoch) -> eyre::Result<u64> {
        todo!()
        /*
        let TotalActiveBalance(initialized_epoch, balance) = self
            .total_active_balance.clone()
            .ok_or(eyre::eyre!("TotalActiveBalanceCacheUninitialized"))?;

        if initialized_epoch == epoch {
            Ok(balance)
        } else {
            Err(eyre::eyre!(format!("TotalActiveBalanceCacheInconsistent , initialized_epoch={initialized_epoch}, current_epoch={epoch}")))
        }
        */
    }

/// Validates each `Exit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
pub fn process_exits(
    self: &mut Self,
    voluntary_exits: &[VoluntaryExitWithSig],
) -> eyre::Result<()> {
    // Verify and apply each exit in series. We iterate in series because higher-index exits may
    // become invalid due to the application of lower-index ones.
    for (i, exit) in voluntary_exits.iter().enumerate() {
        self.verify_exit(None, exit)
            .map_err(|e| eyre::eyre!("verify_exit error {e}, index {i}"))?;

        self.initiate_validator_exit(exit.voluntary_exit.validator_index as usize)?;
    }
    Ok(())
}

/// Indicates if an `Exit` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Exit` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.12.1
pub fn verify_exit(
    self: &mut Self,
    current_epoch: Option<Epoch>,
    signed_exit: &VoluntaryExitWithSig,
    //verify_signatures: VerifySignatures,
) -> eyre::Result<()> {
    let current_epoch = current_epoch.unwrap_or(self.current_epoch());
    let exit = &signed_exit.voluntary_exit;

    let validator = self
        .validators
        .get(exit.validator_index as usize)
        .ok_or_else(|| eyre::eyre!(format!("ExitInvalid::ValidatorUnknown({}", exit.validator_index)))?;

    // Verify the validator is active.
    verify!(
        validator.is_active_at(current_epoch),
        format!("ExitInvalid::NotActive({})", exit.validator_index)
    );

    // Verify that the validator has not yet exited.
    verify!(
        validator.exit_epoch == far_future_epoch,
        format!("ExitInvalid::AlreadyExited({})", exit.validator_index)
    );

    // Exits must specify an epoch when they become valid; they are not valid before then.
    verify!(
        current_epoch >= exit.epoch,
        /*
        ExitInvalid::FutureEpoch {
            state: current_epoch,
            exit: exit.epoch
        }
        */
        format!("ExitInvalid::FutureEpoch(state: {}, exit {})", current_epoch, exit.epoch)
    );

    // Verify the validator has been active long enough.
    let earliest_exit_epoch = validator
        .activation_epoch
        .safe_add(shard_committee_period)?;
    verify!(
        current_epoch >= earliest_exit_epoch,
        /*
        ExitInvalid::TooYoungToExit {
            current_epoch,
            earliest_exit_epoch,
        }
        */
        format!("ExitInvalid::TooYoungToExit (current_epoch: {}, earliest_exit_epoch {})", current_epoch, earliest_exit_epoch)
    );

    /*
    if verify_signatures.is_true() {
        verify!(
            exit_signature_set(
                self,
                |i| get_pubkey_from_state(self, i),
                signed_exit,
            )?
            .verify(),
            ExitInvalid::BadSignature
        );
    }
    */

    // [New in Electra:EIP7251]
    // Only exit validator if it has no pending withdrawals in the queue
    if let Ok(pending_balance_to_withdraw) =
        self.get_pending_balance_to_withdraw(exit.validator_index as usize)
    {
        verify!(
            pending_balance_to_withdraw == 0,
            format!("ExitInvalid::PendingWithdrawalInQueue({})", exit.validator_index)
        );
    }

    Ok(())
}

/// Validates each `Deposit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
pub fn process_deposits(
    self: &mut Self,
    deposits: &[Deposit],
) -> eyre::Result<()> {
    debug!(target: "consensus-client", deposists_length=?deposits.len(), "process_deposits");

    /*
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
    */

    // Update the state in series.
    for deposit in deposits {
        self.apply_deposit(deposit.data.clone(), None, true)?;
    }

    Ok(())
}

/// Process a single deposit, verifying its merkle proof if provided.
pub fn apply_deposit(
    self: &mut Self,
    deposit_data: DepositData,
    //proof: Option<FixedVector<Hash256, U33>>,
    proof: Option<u8>, // for compile
    increment_eth1_deposit_index: bool,
) -> eyre::Result<()> {
    let deposit_index = self.eth1_deposit_index as usize;
    /*
    if let Some(proof) = proof {
        let deposit = Deposit {
            proof,
            data: deposit_data.clone(),
        };
        verify_deposit_merkle_proof(state, &deposit, state.eth1_deposit_index(), spec)
            .map_err(|e| e.into_with_index(deposit_index))?;
    }
    */

    if increment_eth1_deposit_index {
        self.eth1_deposit_index.safe_add_assign(1)?;
    }

    // Get an `Option<u64>` where `u64` is the validator index if this deposit public key
    // already exists in the beacon_state.
    let validator_index = self.get_validator_index_from_pubkey(&deposit_data.pubkey);

    let amount = deposit_data.amount;

    if let Some(index) = validator_index {
        /*
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
        */
        increase_balance(self, index as usize, amount)?;
    }
    // New validator
    else {
        // The signature should be checked for new validators. Return early for a bad
        // signature.
        /*
        if is_valid_deposit_signature(&deposit_data, spec).is_err() {
            return Ok(());
        }
        */

        self.add_validator_to_registry(
            deposit_data.pubkey,
            deposit_data.withdrawal_credentials,
            /*
            if state.fork_name_unchecked() >= ForkName::Electra {
                0
            } else {
                amount
            },
            */
                amount,
        )?;

        /*
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
        */
    }

    Ok(())
}

    /// Add a validator to the registry and return the validator index that was allocated for it.
    pub fn add_validator_to_registry(
        &mut self,
        //pubkey: PublicKeyBytes,
        pubkey: BLSPubkey,
        withdrawal_credentials: B256,
        amount: u64,
        //spec: &ChainSpec,
    ) -> eyre::Result<usize> {
        let index = self.validators.len();
        //let fork_name = self.fork_name_unchecked();
        self.validators.push(Validator::from_deposit(
            pubkey,
            withdrawal_credentials,
            amount,
            //fork_name,
        ));
        self.balances.push(amount);

        // Altair or later initializations.
        /*
        if let Ok(previous_epoch_participation) = self.previous_epoch_participation_mut() {
            previous_epoch_participation.push(ParticipationFlags::default())?;
        }
        if let Ok(current_epoch_participation) = self.current_epoch_participation_mut() {
            current_epoch_participation.push(ParticipationFlags::default())?;
        }
        if let Ok(inactivity_scores) = self.inactivity_scores_mut() {
            inactivity_scores.push(0)?;
        }
        */

        // Keep the pubkey cache up to date if it was up to date prior to this call.
        //
        // Doing this here while we know the pubkey and index is marginally quicker than doing it in
        // a call to `update_pubkey_cache` later because we don't need to index into the validators
        // tree again.
        /*
        let pubkey_cache = self.pubkey_cache_mut();
        if pubkey_cache.len() == index {
            let success = pubkey_cache.insert(pubkey, index);
            if !success {
                return Err(Error::PubkeyCacheInconsistent);
            }
        }
        */

        Ok(index)
    }

    /// Apply attester and proposer rewards.
    pub fn process_rewards_and_penalties(
        self: &mut Self,
        validator_statuses: &ValidatorStatuses,
        //spec: &Spec,
    ) -> eyre::Result<()> {
        debug!(target: "consensus-client", ?validator_statuses, "process_rewards_and_penalties");
        if self.current_epoch() == genesis_epoch {
            return Ok(());
        }

        // Guard against an out-of-bounds during the validator balance update.
        if validator_statuses.statuses.len() != self.balances.len()
            || validator_statuses.statuses.len() != self.validators.len()
        {
            return Err(eyre::eyre!("ValidatorStatusesInconsistent"));
        }

        let deltas = self.get_attestation_deltas_all(
            validator_statuses,
            ProposerRewardCalculation::Include,
        )?;
        debug!(target: "consensus-client", ?deltas, "process_rewards_and_penalties");

        // Apply the deltas, erroring on overflow above but not on overflow below (saturating at 0
        // instead).
        for (i, delta) in deltas.into_iter().enumerate() {
            let combined_delta = delta.flatten()?;
            increase_balance(self, i, combined_delta.rewards)?;
            decrease_balance(self, i, combined_delta.penalties)?;
        }

        Ok(())
    }

    /// Apply rewards for participation in attestations during the previous epoch.
    pub fn get_attestation_deltas_all(
        self: &Self,
        validator_statuses: &ValidatorStatuses,
        proposer_reward: ProposerRewardCalculation,
        //spec: &Spec,
    ) -> eyre::Result<Vec<AttestationDelta>> {
        self.get_attestation_deltas(validator_statuses, proposer_reward)
    }

    /// Apply rewards for participation in attestations during the previous epoch.
    /// If `maybe_validators_subset` specified, only the deltas for the specified validator subset is
    /// returned, otherwise deltas for all validators are returned.
    ///
    /// Returns a vec of validator indices to `AttestationDelta`.
    fn get_attestation_deltas(
        self: &Self,
        validator_statuses: &ValidatorStatuses,
        proposer_reward: ProposerRewardCalculation,
        // maybe_validators_subset: Option<&Vec<usize>>,
        //spec: &Spec,
    ) -> eyre::Result<Vec<AttestationDelta>> {
        /*
        let finality_delay = state
            .previous_epoch()
            .safe_sub(state.finalized_checkpoint().epoch)?
            .as_u64();
        */
        let finality_delay = 0;

        let mut deltas = vec![AttestationDelta::default(); self.validators.len()];

        let total_balances = &validator_statuses.total_balances;
        let sqrt_total_active_balance = SqrtTotalActiveBalance::new(total_balances.current_epoch());

        // // Ignore validator if a subset is specified and validator is not in the subset
        // let include_validator_delta = |idx| match maybe_validators_subset.as_ref() {
        //     None => true,
        //     Some(validators_subset) if validators_subset.contains(&idx) => true,
        //     Some(_) => false,
        // };

        for (index, validator) in validator_statuses.statuses.iter().enumerate() {
            // Ignore ineligible validators. All sub-functions of the spec do this except for
            // `get_inclusion_delay_deltas`. It's safe to do so here because any validator that is in
            // the unslashed indices of the matching source attestations is active, and therefore
            // eligible.
            if !validator.is_eligible {
                continue;
            }

            let base_reward = get_base_reward(
                validator.current_epoch_effective_balance,
                sqrt_total_active_balance,
            )?;

            debug!(target: "consensus-client", ?base_reward, "get_attestation_deltas");
            
            // let (inclusion_delay_delta, proposer_delta) =
            //     get_inclusion_delay_delta(validator, base_reward, spec)?;

            // if include_validator_delta(index) {
                let all_delta =
                    get_all_delta(validator, base_reward, total_balances, finality_delay)?;
                // let target_delta =
                //     get_target_delta(validator, base_reward, total_balances, finality_delay, spec)?;
                // let head_delta =
                //     get_head_delta(validator, base_reward, total_balances, finality_delay, spec)?;
                let inactivity_penalty_delta =
                    get_inactivity_penalty_delta(validator, base_reward, finality_delay)?;

                let delta = deltas
                    .get_mut(index)
                    //.ok_or(Error::DeltaOutOfBounds(index))?;
                    .ok_or(eyre::eyre!(format!("DeltaOutOfBounds, {index}")))?;
                delta.all_delta.combine(all_delta)?;
                // delta.target_delta.combine(target_delta)?;
                // delta.head_delta.combine(head_delta)?;
                // delta.inclusion_delay_delta.combine(inclusion_delay_delta)?;
                delta
                    .inactivity_penalty_delta
                    .combine(inactivity_penalty_delta)?;
            // }

            // if let ProposerRewardCalculation::Include = proposer_reward {
            //     if let Some((proposer_index, proposer_delta)) = proposer_delta {
            //         if include_validator_delta(proposer_index) {
            //             deltas
            //                 .get_mut(proposer_index)
            //                 .ok_or(Error::ValidatorStatusesInconsistent)?
            //                 .inclusion_delay_delta
            //                 .combine(proposer_delta)?;
            //         }
            //     }
            // }
        }

        Ok(deltas)
    }

    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the current epoch committee cache, and will error if it isn't initialized.
    pub fn get_validator_churn_limit(&self, /* spec: &ChainSpec */) -> eyre::Result<u64> {
        /*
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            (self
                .committee_cache(RelativeEpoch::Current)?
                .active_validator_count() as u64)
                .safe_div(spec.churn_limit_quotient)?,
        ))
        */
        Ok(min_per_epoch_churn_limit)
    }

    pub fn get_activation_churn_limit(&self) -> eyre::Result<u64> {
        self.get_validator_churn_limit()
    }

    /// Passing `previous_epoch` to this function rather than computing it internally provides
    /// a tangible speed improvement in state processing.
    pub fn is_eligible_validator(
        &self,
        previous_epoch: Epoch,
        val: &Validator,
    ) -> eyre::Result<bool> {
        Ok(val.is_active_at(previous_epoch)
            //|| (val.slashed && previous_epoch.safe_add(Epoch::new(1))? < val.withdrawable_epoch))
            || (val.slashed && previous_epoch.safe_add(1)? < val.withdrawable_epoch))
    }

    /// Compute the total active balance cache from scratch.
    ///
    /// This method should rarely be invoked because single-pass epoch processing keeps the total
    /// active balance cache up to date.
    pub fn compute_total_active_balance_slow(&self) -> eyre::Result<u64> {
        let current_epoch = self.current_epoch();

        let mut total_active_balance = 0;

        for validator in &self.validators {
            if validator.is_active_at(current_epoch) {
                total_active_balance.safe_add_assign(validator.effective_balance)?;
            }
        }
        Ok(std::cmp::max(
            total_active_balance,
            effective_balance_increment,
        ))
    }

    pub fn get_seed(
        &self,
        epoch: Epoch,
    ) -> eyre::Result<Hash256> {
        let mut preimage = epoch.to_le_bytes();
        Ok(Hash256::from_slice(&hash(&preimage)))
    }

    /// Build all committee caches, if they need to be built.
    pub fn build_all_committee_caches(&mut self,) -> eyre::Result<()> {
        //self.build_committee_cache(RelativeEpoch::Previous)?;
        self.build_committee_cache(RelativeEpoch::Current)?;
        //self.build_committee_cache(RelativeEpoch::Next)?;
        Ok(())
    }

    /// Build a committee cache, unless it is has already been built.
    pub fn build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        //spec: &ChainSpec,
    ) -> eyre::Result<()> {
        let i = Self::committee_cache_index(relative_epoch);
        let is_initialized = self
            .committee_cache_at_index(i)?
            .is_initialized_at(relative_epoch.into_epoch(self.current_epoch()));

        if !is_initialized {
            //self.force_build_committee_cache(relative_epoch, spec)?;
            self.force_build_committee_cache(relative_epoch)?;
        }

        /*
        if self.total_active_balance().is_none() && relative_epoch == RelativeEpoch::Current {
            self.build_total_active_balance_cache(spec)?;
        }
        */
        Ok(())
    }

    /// Get the committee cache at a given index.
    fn committee_cache_at_index(&self, index: usize) -> eyre::Result<&CommitteeCache> {
        self.committee_caches
            .get(index)
            .ok_or(eyre::eyre!(format!("Error::CommitteeCachesOutOfBounds, {index}")))
    }

    /// Get a mutable reference to the committee cache at a given index.
    fn committee_cache_at_index_mut(
        &mut self,
        index: usize,
    ) -> eyre::Result<&mut CommitteeCache> {
        self.committee_caches
            .get_mut(index)
            .ok_or(eyre::eyre!(format!("Error::CommitteeCachesOutOfBounds, {index}")))
    }

    pub(crate) fn committee_cache_index(relative_epoch: RelativeEpoch) -> usize {
        match relative_epoch {
            RelativeEpoch::Previous => 0,
            RelativeEpoch::Current => 1,
            RelativeEpoch::Next => 2,
        }
    }

    /// Always builds the requested committee cache, even if it is already initialized.
    pub fn force_build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        //spec: &ChainSpec,
    ) -> eyre::Result<()> {
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let i = Self::committee_cache_index(relative_epoch);

        //*self.committee_cache_at_index_mut(i)? = self.initialize_committee_cache(epoch, spec)?;
        *self.committee_cache_at_index_mut(i)? = self.initialize_committee_cache(epoch)?;
        Ok(())
    }

    /// Initializes a new committee cache for the given `epoch`, regardless of whether one already
    /// exists. Returns the committee cache without attaching it to `self`.
    ///
    /// To build a cache and store it on `self`, use `Self::build_committee_cache`.
    pub fn initialize_committee_cache(
        &self,
        epoch: Epoch,
        //spec: &ChainSpec,
    ) -> eyre::Result<CommitteeCache> {
        //CommitteeCache::initialized(self, epoch, spec)
        CommitteeCache::initialized(self, epoch)
    }

    /// Get all of the Beacon committees at a given relative epoch.
    ///
    /// Utilises the committee cache.
    ///
    /// Spec v0.12.1
    pub fn get_beacon_committees_at_epoch(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> eyre::Result<Vec<BeaconCommittee<'_>>> {
        // workaround empty validators
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let active_validator_indices = get_active_validator_indices(&self.validators, epoch);
        if active_validator_indices.is_empty() {
            return Ok(Vec::new());
        }

        let cache = self.committee_cache(relative_epoch)?;
        cache.get_all_beacon_committees()
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    pub fn committee_cache(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> eyre::Result<&CommitteeCache> {
        let i = Self::committee_cache_index(relative_epoch);
        let cache = self.committee_cache_at_index(i)?;
        debug!(target: "consensus-client", ?i, ?cache, "committee_cache");

        if cache.is_initialized_at(relative_epoch.into_epoch(self.current_epoch())) {
            Ok(cache)
        } else {
            Err(eyre::eyre!(format!("Error::CommitteeCacheUninitialized, relative_epoch: {relative_epoch:?}")))
        }
    }

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct PendingPartialWithdrawal {
    pub validator_index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance(
    state: &mut BeaconState,
    index: usize,
    delta: u64,
) -> eyre::Result<()> {
    increase_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance_directly(balance: &mut u64, delta: u64) -> eyre::Result<()> {
    balance.safe_add_assign(delta)?;
    Ok(())
}

pub fn decrease_balance(
    state: &mut BeaconState,
    index: usize,
    delta: u64,
) -> eyre::Result<()> {
    decrease_balance_directly(state.get_balance_mut(index)?, delta)
}

pub fn decrease_balance_directly(balance: &mut u64, delta: u64) -> eyre::Result<()> {
    *balance = balance.saturating_sub(delta);
    Ok(())
}

pub fn is_compounding_withdrawal_credential(
    withdrawal_credentials: B256,
) -> bool {
    withdrawal_credentials
        .as_slice()
        .first()
        .map(|prefix_byte| *prefix_byte == compounding_withdrawal_prefix_byte)
        .unwrap_or(false)
}

#[derive(Debug, PartialEq, Clone)]
pub enum ExitInvalid {
    /// The specified validator is not active.
    NotActive(u64),
    /// The specified validator is not in the state's validator registry.
    ValidatorUnknown(u64),
    /// The specified validator has a non-maximum exit epoch.
    AlreadyExited(u64),
    /// The specified validator has already initiated exit.
    AlreadyInitiatedExit(u64),
    /// The exit is for a future epoch.
    FutureEpoch {
        state: Epoch,
        exit: Epoch,
    },
    /// The validator has not been active for long enough.
    TooYoungToExit {
        current_epoch: Epoch,
        earliest_exit_epoch: Epoch,
    },
    /// The exit signature was not signed by the validator.
    BadSignature,
    /// There was an error whilst attempting to get a set of signatures. The signatures may have
    /// been invalid or an internal error occurred.
    //SignatureSetError(SignatureSetError),
    PendingWithdrawalInQueue(u64),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Eth1Data {
    pub deposit_root: B256,
    pub deposit_count: u64,
    pub block_hash: B256,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ValidatorStatuses {
    /// Information about each individual validator from the state's validator registry.
    pub statuses: Vec<ValidatorStatus>,
    /// Summed balances for various sets of validators.
    pub total_balances: TotalBalances,
}

impl ValidatorStatuses {
    /// Initializes a new instance, determining:
    ///
    /// - Active validators
    /// - Total balances for the current and previous epochs.
    ///
    /// Spec v0.12.1
    pub fn new(
        state: &BeaconState,
        //spec: &ChainSpec,
    ) -> eyre::Result<Self> {
        // TODO: get validator status from rpc
        let mut statuses = Vec::with_capacity(state.validators.len());
        let mut total_balances = TotalBalances::new();

        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        for validator in state.validators.iter() {
            let effective_balance = validator.effective_balance;
            let mut status = ValidatorStatus {
                is_slashed: validator.slashed,
                is_eligible: state.is_eligible_validator(previous_epoch, validator)?,
                is_withdrawable_in_current_epoch: validator.is_withdrawable_at(current_epoch),
                current_epoch_effective_balance: effective_balance,

                //
                is_previous_epoch_attester: true,

                ..ValidatorStatus::default()
            };

            if validator.is_active_at(current_epoch) {
                status.is_active_in_current_epoch = true;
                total_balances
                    .current_epoch
                    .safe_add_assign(effective_balance)?;
            }

            if validator.is_active_at(previous_epoch) {
                status.is_active_in_previous_epoch = true;
                total_balances
                    .previous_epoch
                    .safe_add_assign(effective_balance)?;
            }

            statuses.push(status);
        }

        Ok(Self {
            statuses,
            total_balances,
        })
    }

}

#[derive(Debug)]
pub enum ProposerRewardCalculation {
    Include,
    Exclude,
}

/// Combination of several deltas for different components of an attestation reward.
///
/// Exists only for compatibility with EF rewards tests.
#[derive(Default, Clone, Debug)]
pub struct AttestationDelta {
    // pub source_delta: Delta,
    // pub target_delta: Delta,
    // pub head_delta: Delta,
    // pub inclusion_delay_delta: Delta,
    pub all_delta: Delta,
    pub inactivity_penalty_delta: Delta,
}

impl AttestationDelta {
    /// Flatten into a single delta.
    pub fn flatten(self) -> eyre::Result<Delta> {
        let AttestationDelta {
            // source_delta,
            // target_delta,
            // head_delta,
            // inclusion_delay_delta,
            all_delta,
            inactivity_penalty_delta,
        } = self;
        let mut result = Delta::default();
        for delta in [
            // source_delta,
            // target_delta,
            // head_delta,
            // inclusion_delay_delta,
            all_delta,
            inactivity_penalty_delta,
        ] {
            result.combine(delta)?;
        }
        Ok(result)
    }
}

/// Used to track the changes to a validator's balance.
#[derive(Default, Clone, Debug)]
pub struct Delta {
    pub rewards: u64,
    pub penalties: u64,
}

impl Delta {
    /// Reward the validator with the `reward`.
    pub fn reward(&mut self, reward: u64) -> eyre::Result<()> {
        self.rewards = self.rewards.safe_add(reward)?;
        Ok(())
    }

    /// Penalize the validator with the `penalty`.
    pub fn penalize(&mut self, penalty: u64) -> eyre::Result<()> {
        self.penalties = self.penalties.safe_add(penalty)?;
        Ok(())
    }

    /// Combine two deltas.
    pub fn combine(&mut self, other: Delta) -> eyre::Result<()> {
        self.reward(other.rewards)?;
        self.penalize(other.penalties)
    }
}

#[derive(Copy, Clone)]
pub struct SqrtTotalActiveBalance(u64);

impl SqrtTotalActiveBalance {
    pub fn new(total_active_balance: u64) -> Self {
        Self(total_active_balance.integer_sqrt())
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Returns the base reward for some validator.
pub fn get_base_reward(
    validator_effective_balance: u64,
    sqrt_total_active_balance: SqrtTotalActiveBalance,
) -> eyre::Result<u64> {
    Ok(validator_effective_balance
        .safe_mul(base_reward_factor)?
        .safe_div(sqrt_total_active_balance.as_u64())?
        .safe_div(base_rewards_per_epoch)?)
}

fn get_all_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    total_balances: &TotalBalances,
    finality_delay: u64,
) -> eyre::Result<Delta> {
    get_attestation_component_delta(
        validator.is_previous_epoch_attester && !validator.is_slashed,
        total_balances.previous_epoch_attesters(),
        total_balances,
        base_reward,
        finality_delay,
        //spec,
    )
}

pub fn get_inactivity_penalty_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    finality_delay: u64,
    //spec: &Spec,
) -> eyre::Result<Delta> {
    let mut delta = Delta::default();

    // Inactivity penalty
    if finality_delay > min_epochs_to_inactivity_penalty {
        // If validator is performing optimally this cancels all rewards for a neutral balance
        delta.penalize(
            base_rewards_per_epoch
                .safe_mul(base_reward)?
                .safe_sub(get_proposer_reward(base_reward)?)?,
        )?;

        // Additionally, all validators whose FFG target didn't match are penalized extra
        // This condition is equivalent to this condition from the spec:
        // `index not in get_unslashed_attesting_indices(state, matching_target_attestations)`
        if validator.is_slashed || !validator.is_previous_epoch_attester {
            delta.penalize(
                validator
                    .current_epoch_effective_balance
                    .safe_mul(finality_delay)?
                    .safe_div(inactivity_penalty_quotient)?,
            )?;
        }
    }

    Ok(delta)
}

/// Sets the boolean `var` on `self` to be true if it is true on `other`. Otherwise leaves `self`
/// as is.
macro_rules! set_self_if_other_is_true {
    ($self_: ident, $other: ident, $var: ident) => {
        if $other.$var {
            $self_.$var = true;
        }
    };
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ValidatorStatus {
    /// True if the validator has been slashed, ever.
    pub is_slashed: bool,
    /// True if the validator is eligible.
    pub is_eligible: bool,
    // /// True if the validator can withdraw in the current epoch.
    // pub is_withdrawable_in_current_epoch: bool,
    /// True if the validator was active in the state's _current_ epoch.
    pub is_active_in_current_epoch: bool,
    /// True if the validator was active in the state's _previous_ epoch.
    pub is_active_in_previous_epoch: bool,
    /// The validator's effective balance in the _current_ epoch.
    pub current_epoch_effective_balance: u64,

    /// True if the validator had an attestation included in the _current_ epoch.
    pub is_current_epoch_attester: bool,
    // /// True if the validator's beacon block root attestation for the first slot of the _current_
    // /// epoch matches the block root known to the state.
    // pub is_current_epoch_target_attester: bool,
    /// True if the validator had an attestation included in the _previous_ epoch.
    pub is_previous_epoch_attester: bool,
    // /// True if the validator's beacon block root attestation for the first slot of the _previous_
    // /// epoch matches the block root known to the state.
    // pub is_previous_epoch_target_attester: bool,
    // /// True if the validator's beacon block root attestation in the _previous_ epoch at the
    // /// attestation's slot (`attestation_data.slot`) matches the block root known to the state.
    // pub is_previous_epoch_head_attester: bool,

    // Information used to reward the block producer of this validators earliest-included
    // attestation.
    // pub inclusion_info: Option<InclusionInfo>,
    /// True if the validator can withdraw in the current epoch.
    pub is_withdrawable_in_current_epoch: bool,
}

impl ValidatorStatus {
    /// Accepts some `other` `ValidatorStatus` and updates `self` if required.
    ///
    /// Will never set one of the `bool` fields to `false`, it will only set it to `true` if other
    /// contains a `true` field.
    ///
    /// Note: does not update the winning root info, this is done manually.
    pub fn update(&mut self, other: &Self) {
        // Update all the bool fields, only updating `self` if `other` is true (never setting
        // `self` to false).
        set_self_if_other_is_true!(self, other, is_slashed);
        set_self_if_other_is_true!(self, other, is_eligible);
        // set_self_if_other_is_true!(self, other, is_withdrawable_in_current_epoch);
        set_self_if_other_is_true!(self, other, is_active_in_current_epoch);
        set_self_if_other_is_true!(self, other, is_active_in_previous_epoch);
        set_self_if_other_is_true!(self, other, is_current_epoch_attester);
        // set_self_if_other_is_true!(self, other, is_current_epoch_target_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_attester);
        // set_self_if_other_is_true!(self, other, is_previous_epoch_target_attester);
        // set_self_if_other_is_true!(self, other, is_previous_epoch_head_attester);

        // if let Some(other_info) = other.inclusion_info {
        //     if let Some(self_info) = self.inclusion_info.as_mut() {
        //         self_info.update(&other_info);
        //     } else {
        //         self.inclusion_info = other.inclusion_info;
        //     }
        // }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct TotalBalances {
    /// The effective balance increment from the spec.
    effective_balance_increment: u64,
    /// The total effective balance of all active validators during the _current_ epoch.
    current_epoch: u64,
    /// The total effective balance of all active validators during the _previous_ epoch.
    previous_epoch: u64,
    /// The total effective balance of all validators who attested during the _current_ epoch.
    current_epoch_attesters: u64,
    // / The total effective balance of all validators who attested during the _current_ epoch and
    // / agreed with the state about the beacon block at the first slot of the _current_ epoch.
    // current_epoch_target_attesters: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch.
    previous_epoch_attesters: u64,
    // / The total effective balance of all validators who attested during the _previous_ epoch and
    // / agreed with the state about the beacon block at the first slot of the _previous_ epoch.
    // previous_epoch_target_attesters: u64,
    // / The total effective balance of all validators who attested during the _previous_ epoch and
    // / agreed with the state about the beacon block at the time of attestation.
    // previous_epoch_head_attesters: u64,
}

// Generate a safe accessor for a balance in `TotalBalances`, as per spec `get_total_balance`.
macro_rules! balance_accessor {
    ($field_name:ident) => {
        pub fn $field_name(&self) -> u64 {
            std::cmp::max(self.effective_balance_increment, self.$field_name)
        }
    };
}

impl TotalBalances {
    pub fn new() -> Self {
        Self {
            effective_balance_increment: effective_balance_increment,
            current_epoch: 0,
            previous_epoch: 0,
            current_epoch_attesters: 0,
            // current_epoch_target_attesters: 0,
            previous_epoch_attesters: 0,
            // previous_epoch_target_attesters: 0,
            // previous_epoch_head_attesters: 0,
        }
    }

    balance_accessor!(current_epoch);
    balance_accessor!(previous_epoch);
    // balance_accessor!(current_epoch_attesters);
    // balance_accessor!(current_epoch_target_attesters);
    balance_accessor!(previous_epoch_attesters);
    // balance_accessor!(previous_epoch_target_attesters);
    // balance_accessor!(previous_epoch_head_attesters);
}

pub fn get_attestation_component_delta(
    index_in_unslashed_attesting_indices: bool,
    attesting_balance: u64,
    total_balances: &TotalBalances,
    base_reward: u64,
    finality_delay: u64,
    //spec: &Spec,
) -> eyre::Result<Delta> {
    let mut delta = Delta::default();

    let total_balance = total_balances.current_epoch();

    if index_in_unslashed_attesting_indices {
        if finality_delay > min_epochs_to_inactivity_penalty {
            // Since full base reward will be canceled out by inactivity penalty deltas,
            // optimal participation receives full base reward compensation here.
            delta.reward(base_reward)?;
        } else {
            let reward_numerator = base_reward
                .safe_mul(attesting_balance.safe_div(effective_balance_increment)?)?;
            delta.reward(
                reward_numerator
                    .safe_div(total_balance.safe_div(effective_balance_increment)?)?,
            )?;
        }
    } else {
        delta.penalize(base_reward)?;
    }

    Ok(delta)
}

/// Compute the reward awarded to a proposer for including an attestation from a validator.
///
/// The `base_reward` param should be the `base_reward` of the attesting validator.
fn get_proposer_reward(base_reward: u64) -> eyre::Result<u64> {
    Ok(base_reward.safe_div(proposer_reward_quotient)?)
}

/// Defines the epochs relative to some epoch. Most useful when referring to the committees prior
/// to and following some epoch.
///
/// Spec v0.12.1
#[derive(Debug, PartialEq, Clone, Copy, arbitrary::Arbitrary)]
pub enum RelativeEpoch {
    /// The prior epoch.
    Previous,
    /// The current epoch.
    Current,
    /// The next epoch.
    Next,
}

impl RelativeEpoch {
    /// Returns the `epoch` that `self` refers to, with respect to the `base` epoch.
    ///
    /// Spec v0.12.1
    pub fn into_epoch(self, base: Epoch) -> Epoch {
        match self {
            // Due to saturating nature of epoch, check for current first.
            RelativeEpoch::Current => base,
            RelativeEpoch::Previous => base.saturating_sub(1u64),
            RelativeEpoch::Next => base.saturating_add(1u64),
        }
    }
}

