use reth_primitives::{Block, Header, SealedBlock};

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals}, eip7685::Requests,
};
use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolEnum, SolEvent, sol};
use serde::{Deserialize, Serialize};
use alloy_primitives::Sealable;
use alloy_rlp::{Encodable, Decodable, RlpEncodable,  RlpDecodable};
use std::collections::{HashMap, BTreeMap};
use alloy_primitives::{keccak256, BlockHash, B256, Log};
use n42_primitives::{Epoch, VoluntaryExit, VoluntaryExitWithSig};
use crate::storage::{Storage};
use crate::safe_aitrh::SafeArith;
use crate::safe_aitrh::SafeArithIter;
use tracing::{trace, debug, error, info, warn};

const INMEMORY_BEACON_STATES: u32 = 256;

const STAKING_AMOUNT: u64 = 32000000000;

const REWARD_AMOUNT: u64 = 1;
const SLOTS_PER_EPOCH: u64 = 32;

// EthSpec
const max_withdrawals_per_payload: usize = 16;
const pending_partial_withdrawals_limit: usize = 16; // ?

// chain_spec
const max_pending_partials_per_withdrawals_sweep: u64 = 16; // ?
const min_activation_balance: u64 = 32000000000;
const far_future_epoch: u64 = u64::max_value();
const max_validators_per_withdrawals_sweep: u64 = 16384;
const max_effective_balance: u64 = 32000000000; //?
const full_exit_request_amount: u64 = 32000000000; //?
const shard_committee_period: u64 = 1; //?
const compounding_withdrawal_prefix_byte: u8 = 0x02;
const eth1_address_withdrawal_prefix_byte: u8 = 0x01;
const max_seed_lookahead: u64 = 4;
const max_per_epoch_activation_exit_churn_limit:u64 = 256000000000;
const min_per_epoch_churn_limit_electra:u64 = 128000000000;
const churn_limit_quotient:u64 = 32;
const effective_balance_increment:u64 = 1000000000;

const min_validator_withdrawability_delay: u64 = 1;

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

#[derive(Debug)]
pub struct Beacon {
    storage: Storage,
}

impl Beacon {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
        }
    }

    pub fn gen_beacon_block(&mut self, old_beacon_state: Option<BeaconState>, parent_hash: BlockHash, deposits: &Vec<Deposit>, attestations: &Vec<Attestation>, voluntary_exits: &Vec<VoluntaryExitWithSig>, execution_requests: &Option<Requests>, eth1_sealed_block: &SealedBlock) -> eyre::Result<BeaconBlock> {
        let mut beacon_block = BeaconBlock {
            parent_hash,
            eth1_block_hash: eth1_sealed_block.hash_slow(),
            body: BeaconBlockBody {
                deposits: deposits.clone(),
                attestations: attestations.clone(),
                voluntary_exits: voluntary_exits.clone(),
                execution_requests: parse_execution_requests(execution_requests),
            },
            ..Default::default()
        };
        let beacon_state = self.state_transition(old_beacon_state, &beacon_block)?;
        beacon_block.state_root = beacon_state.hash_slow();
        Ok(beacon_block)
    }

    pub fn state_transition(&mut self, old_beacon_state: Option<BeaconState>, beacon_block: &BeaconBlock) -> eyre::Result<BeaconState> {
        debug!(target: "consensus-client", ?beacon_block, "state_transition");
        let beacon_state = if old_beacon_state.is_none() {
            self.storage.get_beacon_state_by_beacon_hash(beacon_block.parent_hash)?
        } else {
            old_beacon_state.unwrap()
        };
        let new_beacon_state = BeaconState::state_transition(&beacon_state, beacon_block)?;
        self.storage.save_beacon_state_by_beacon_hash(beacon_block.hash_slow(), new_beacon_state.clone())?;
        debug!(target: "consensus-client", ?new_beacon_state, "state_transition");

        Ok(new_beacon_state)
    }

    pub fn gen_withdrawals(&mut self, eth1_block_hash: BlockHash) -> eyre::Result<(Option<Vec<Withdrawal>>, BeaconState)> {
        let beacon_block_hash = self.storage.get_beacon_block_hash_by_eth1_hash(eth1_block_hash)?;
        debug!(target: "consensus-client", ?beacon_block_hash, "gen_withdrawals");
        let mut beacon_state = self.storage.get_beacon_state_by_beacon_hash(beacon_block_hash)?;

        /*
        let mut withdrawals = Vec::new();
        if (beacon_state.slot + 1) % SLOTS_PER_EPOCH == 0 {
            for (index, validator) in beacon_state.validators.iter_mut().enumerate() {
                let epoch = beacon_state.slot / SLOTS_PER_EPOCH;
                if epoch >= validator.activation_epoch && (validator.exit_epoch == 0 || epoch < validator.exit_epoch) {
                    if beacon_state.balances[index] > STAKING_AMOUNT {
                        let extra = beacon_state.balances[index] - STAKING_AMOUNT;
                        withdrawals.push(
                            Withdrawal {
                                address: get_address(&validator.withdrawal_credentials),
                                amount: extra,
                                ..Default::default()
                            }
                        );
                        validator.effective_balance = STAKING_AMOUNT;
                        beacon_state.balances[index]= STAKING_AMOUNT;
                    }
                } else if epoch == validator.withdrawable_epoch {
                    withdrawals.push(
                        Withdrawal {
                            address: get_address(&validator.withdrawal_credentials),
                            amount: beacon_state.balances[index],
                            ..Default::default()
                        }
                    );
                    validator.effective_balance = 0;
                    beacon_state.balances[index]= 0;
                }
            }
        }
        Ok((Some(withdrawals), beacon_state))
        */

        let (expected_withdrawals, processed_partial_withdrawals_count) =
        beacon_state.process_withdrawals()?;
        Ok((Some(expected_withdrawals), beacon_state))

    }

    pub fn is_valid_voluntary_exit(&mut self, eth1_block_hash: BlockHash, voluntary_exit: &VoluntaryExit, signature: &Bytes) -> eyre::Result<bool> {
        let beacon_block_hash = self.storage.get_beacon_block_hash_by_eth1_hash(eth1_block_hash)?;
        let beacon_state = self.storage.get_beacon_state_by_beacon_hash(beacon_block_hash)?;
        if let Some(validator) = beacon_state.validators.get(voluntary_exit.validator_index as usize) {
            if voluntary_exit.epoch > validator.activation_epoch && validator.exit_epoch == 0 {
                // TODO: check signature

                return Ok(true)
            }
        }

        Ok(false)
    }
}

fn get_address(withdrawal_credentials: &B256) -> Address {
    assert_eq!(withdrawal_credentials.as_slice()[0], 0x01);
    Address::from_slice(&withdrawal_credentials.as_slice()[12..])
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
#[rlp(trailing)]
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

    pub total_active_balance: Option<TotalActiveBalance>,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct TotalActiveBalance(Epoch, u64);

impl Sealable for BeaconState {
    fn hash_slow(&self) -> B256 {
        let mut out = Vec::new();
        self.encode(&mut out);
        keccak256(&out)
    }
}

type Gwei = u64;

// mock
type BLSPubkey = Bytes;
type BLSSignature = Bytes;

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct Validator {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: B256,  // Commitment to pubkey for withdrawals
    pub effective_balance: Gwei,  // Balance at stake
    pub slashed: bool,

    // Status epochs
    pub activation_eligibility_epoch: Epoch,  // When criteria for activation were met
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,  // When validator can withdraw funds
}

impl Validator {
    pub fn is_partially_withdrawable_validator(
        &self,
        balance: u64,
    ) -> bool {
        self.effective_balance == max_effective_balance
            && balance > max_effective_balance
    }

    pub fn is_fully_withdrawable_validator(
        &self,
        balance: u64,
        epoch: Epoch,
    ) -> bool {
        self.withdrawable_epoch <= epoch && balance > 0
    }

    pub fn get_execution_withdrawal_address(&self) -> Option<Address> {
        self.withdrawal_credentials
            .as_slice()
            .get(12..)
            .map(Address::from_slice)
    }

    /// Check if ``validator`` has an 0x02 prefixed "compounding" withdrawal credential.
    pub fn has_compounding_withdrawal_credential(&self) -> bool {
        is_compounding_withdrawal_credential(self.withdrawal_credentials)
    }

    pub fn has_execution_withdrawal_credential(&self) -> bool {
        self.has_compounding_withdrawal_credential()
            || self.has_eth1_withdrawal_credential()
    }

    /// Returns `true` if the validator has eth1 withdrawal credential.
    pub fn has_eth1_withdrawal_credential(&self) -> bool {
        self.withdrawal_credentials
            .as_slice()
            .first()
            .map(|byte| *byte == eth1_address_withdrawal_prefix_byte)
            .unwrap_or(false)
    }

    /// Returns `true` if the validator is considered active at some epoch.
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct BeaconBlock {
    pub eth1_block_hash: BlockHash,
    pub parent_hash: BlockHash,
    pub state_root: B256,
    pub body: BeaconBlockBody,
}

impl Sealable for BeaconBlock {
    fn hash_slow(&self) -> B256 {
        let mut out = Vec::new();
        self.encode(&mut out);
        keccak256(&out)
    }
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct BeaconBlockBody {
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub voluntary_exits: Vec<VoluntaryExitWithSig>,
    pub execution_requests: ExecutionRequests,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct ExecutionRequests {
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<WithdrawalRequest>,
    pub consolidations: Vec<ConsolidationRequest>,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct DepositRequest {
    pub pubkey: Bytes,
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: Bytes,
    pub index: u64,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: Bytes,
    pub amount: u64,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: Bytes,
    pub target_pubkey: Bytes,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct Attestation {
    pub pubkey: Bytes,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct Deposit {
    pub proof: Vec<B256>,
    pub data: DepositData,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
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
    pub fn state_transition(old_beacon_state: &BeaconState, beacon_block: &BeaconBlock) -> eyre::Result<Self> {
        debug!(target: "consensus-client", ?old_beacon_state, ?beacon_block, "state_transition");
        let mut new_beacon_state = old_beacon_state.clone();
        if (new_beacon_state.slot + 1) % SLOTS_PER_EPOCH == 0 {
            new_beacon_state.process_epoch()?;
        }
        new_beacon_state.slot += 1;
        new_beacon_state.process_block(&beacon_block)?;

        Ok(new_beacon_state)
    }

    pub fn process_epoch(&self) -> eyre::Result<()> {
        self.process_rewards_and_penalties()?;
        self.process_registry_updates()?;
        Ok(())
    }

    pub fn process_rewards_and_penalties(&self) -> eyre::Result<()> {
        Ok(())
    }

    pub fn process_registry_updates(&self) -> eyre::Result<()> {
        Ok(())
    }

    pub fn process_block(&mut self, beacon_block: &BeaconBlock) -> eyre::Result<()> {
        self.process_operations(&beacon_block.body)?;
        Ok(())
    }

    pub fn process_operations(&mut self, beacon_block_body: &BeaconBlockBody) -> eyre::Result<()> {
        self.process_deposit(&beacon_block_body.deposits)?;
        self.process_attestation(&beacon_block_body.attestations)?;
        self.process_voluntary_exit(&beacon_block_body.voluntary_exits)?;

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
        if expected_withdrawals.len() != max_withdrawals_per_payload {
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

    pub fn get_validator_index_from_pubkey(&self, pubkey: &Bytes) -> Option<usize> {
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
        self.get_total_active_balance_at_epoch(self.current_epoch())
    }

    /// Get the cached total active balance while checking that it is for the correct `epoch`.
    pub fn get_total_active_balance_at_epoch(&self, epoch: Epoch) -> eyre::Result<u64> {
        let TotalActiveBalance(initialized_epoch, balance) = self
            .total_active_balance.clone()
            .ok_or(eyre::eyre!("TotalActiveBalanceCacheUninitialized"))?;

        if initialized_epoch == epoch {
            Ok(balance)
        } else {
            Err(eyre::eyre!(format!("TotalActiveBalanceCacheInconsistent , initialized_epoch={initialized_epoch}, current_epoch={epoch}")))
        }
    }

}

#[derive(Debug, Clone, Hash, Default, PartialEq, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct PendingPartialWithdrawal {
    pub validator_index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
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

fn parse_execution_requests(requests: &Option<Requests>) -> ExecutionRequests {
    todo!()
}
