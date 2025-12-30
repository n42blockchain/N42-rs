// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals},
    eip7002::WithdrawalRequest,
    eip7685::Requests,
};
use alloy_primitives::{keccak256, Address, BlockHash, Bytes, Log, B256};
use alloy_primitives::{FixedBytes, Sealable};
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use alloy_sol_types::{sol, SolEnum, SolEvent};
use blst::min_pk::PublicKey;
use blst::min_pk::SecretKey;
use blst::min_pk::{AggregateSignature, Signature};
use hex::FromHex;
use integer_sqrt::IntegerSquareRoot;
use once_cell::sync::Lazy;
use schnellru::LruMap;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::BTreeSet;
use std::sync::RwLock;
use tracing::{debug, error, info, trace, warn};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::committee_cache::CommitteeCache;
use crate::safe_arith::SafeArith;
use crate::safe_arith::SafeArithIter;
use crate::{
    activation_queue::ActivationQueue, beacon_committee::BeaconCommittee, CommitteeIndex, Hash256,
    Slot, Validator,
};
use derivative::Derivative;
use ethereum_hashing::hash;
use merkle_db_rs::tree::VecTree;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use typenum::U100000;

// ========== Performance Optimization: Public Key Cache ==========
// Cache parsed BLS public keys to avoid repeated parsing overhead
// Key: validator pubkey bytes, Value: parsed PublicKey
const PUBKEY_CACHE_SIZE: u32 = 10000;
static PUBKEY_CACHE: Lazy<RwLock<LruMap<FixedBytes<48>, PublicKey>>> =
    Lazy::new(|| RwLock::new(LruMap::new(schnellru::ByLength::new(PUBKEY_CACHE_SIZE))));

/// Get or parse a public key with caching
fn get_cached_pubkey(pubkey_bytes: &FixedBytes<48>) -> eyre::Result<PublicKey> {
    // Try cache read first
    if let Ok(cache) = PUBKEY_CACHE.read() {
        if let Some(pk) = cache.peek(pubkey_bytes) {
            return Ok(pk.clone());
        }
    }

    // Parse public key
    let pk = PublicKey::from_bytes(pubkey_bytes.as_slice())
        .map_err(|e| eyre::eyre!("PublicKey::from_bytes error {e:?}"))?;

    // Cache it
    if let Ok(mut cache) = PUBKEY_CACHE.write() {
        cache.insert(*pubkey_bytes, pk.clone());
    }

    Ok(pk)
}

// ========== Performance Optimization: Shuffle Cache ==========
// Cache committee shuffle results to avoid repeated computation
const SHUFFLE_CACHE_SIZE: u32 = 8;
pub static SHUFFLE_CACHE: Lazy<RwLock<LruMap<(u64, B256), Vec<usize>>>> =
    Lazy::new(|| RwLock::new(LruMap::new(schnellru::ByLength::new(SHUFFLE_CACHE_SIZE))));

pub const SLOTS_PER_EPOCH: u64 = 32;

pub const DOMAIN_CONSTANT_BEACON_ATTESTER: u32 = 1;

// EthSpec
pub const max_withdrawals_per_payload: usize = 16;
pub const pending_partial_withdrawals_limit: usize = 16; // ?
pub const MaxDeposits: u64 = 16;
pub const genesis_epoch: u64 = 0;

#[derive(Debug, Default)]
pub struct ChainSpec {
    pub max_pending_partials_per_withdrawals_sweep: u64,
    pub min_activation_balance: u64,
    pub ejection_balance: u64,
    pub far_future_epoch: u64,
    pub max_validators_per_withdrawals_sweep: u64,
    pub max_effective_balance: u64,
    pub full_exit_request_amount: u64,
    pub shard_committee_period: u64, //?
    pub compounding_withdrawal_prefix_byte: u8,
    pub eth1_address_withdrawal_prefix_byte: u8,
    pub max_seed_lookahead: u64,
    pub max_per_epoch_activation_exit_churn_limit: u64,
    pub min_per_epoch_churn_limit_electra: u64,
    pub churn_limit_quotient: u64,
    pub effective_balance_increment: u64,
    pub base_rewards_per_epoch: u64,
    pub base_reward_factor: u64,
    pub min_epochs_to_inactivity_penalty: u64,
    pub inactivity_penalty_quotient: u64, //?
    pub proposer_reward_quotient: u64,
    pub min_per_epoch_churn_limit: u64,
    pub max_committees_per_slot: usize,
    pub target_committee_size: usize,
    pub min_seed_lookahead: u64,
    pub shuffle_round_count: u8,

    pub inactivity_score_bias: u64,
    pub inactivity_score_recovery_rate: u64,
    pub max_inactivity_score: u64,
    pub trigger_punish_inactivity_score: u64,
    pub multiple_reward_for_inactivity_penalty: u64,

    pub min_validator_withdrawability_delay: u64,
}

pub fn beacon_chain_spec() -> ChainSpec {
    ChainSpec {
        max_pending_partials_per_withdrawals_sweep: 16,
        min_activation_balance: 32000000000,
        ejection_balance: 16000000000,
        far_future_epoch: u64::max_value(),
        max_validators_per_withdrawals_sweep: 16384,
        max_effective_balance: 32000000000,
        full_exit_request_amount: 0,
        shard_committee_period: 1,
        compounding_withdrawal_prefix_byte: 0x02,
        eth1_address_withdrawal_prefix_byte: 0x01,
        max_seed_lookahead: 4,
        max_per_epoch_activation_exit_churn_limit: 256000000000,
        min_per_epoch_churn_limit_electra: 128000000000,
        churn_limit_quotient: 32,
        effective_balance_increment: 1000000000,
        base_rewards_per_epoch: 1,
        base_reward_factor: 1,
        min_epochs_to_inactivity_penalty: 4,
        inactivity_penalty_quotient: 67108864,
        proposer_reward_quotient: 4,
        min_per_epoch_churn_limit: 4,
        max_committees_per_slot: 4,
        target_committee_size: 4,
        min_seed_lookahead: 1,
        shuffle_round_count: 10,

        inactivity_score_bias: 1,
        inactivity_score_recovery_rate: 48,
        max_inactivity_score: 8100,
        trigger_punish_inactivity_score: 2700,
        multiple_reward_for_inactivity_penalty: 3,

        min_validator_withdrawability_delay: 1,
    }
}

/*
pub const inactivity_score_bias: u64 = 1;
pub const inactivity_score_recovery_rate: u64 = 5;
pub const max_inactivity_score: u64 = 15;
pub const trigger_punish_inactivity_score: u64 = 15;
pub const multiple_reward_for_inactivity_penalty: u64 = 3;

pub const min_validator_withdrawability_delay: u64 = 1;
*/

pub const CACHED_EPOCHS: usize = 3;

// lighthouse: consensus/types/src/chain_spec.rs, get_deposit_domain()
// genesis_fork_version: [0, 0, 0, 0]
const DOMAIN_DEPOSIT: [u8; 32] =
    hex_literal::hex!("03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9");

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

pub fn epoch_to_block_number(epoch: Epoch) -> u64 {
    epoch.saturating_mul(SLOTS_PER_EPOCH)
}

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

pub struct BeaconStateChangeset {
    pub beaconstates: Vec<(BlockHash, BeaconState)>,
}

pub struct BeaconBlockChangeset {
    pub beaconblocks: Vec<(BlockHash, BeaconBlock)>,
}

#[derive(Derivative, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[derivative(Debug)]
pub struct BeaconState {
    pub slot: u64,
    pub eth1_deposit_index: u64,
    //pub validators: Vec<Validator>,
    pub validators: Hash256,
    pub validators_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug = "ignore")]
    pub validators_store: VecTree<Validator, U100000>,

    //pub balances: Vec<Gwei>,
    pub balances: Hash256,
    pub balances_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug = "ignore")]
    pub balances_store: VecTree<Gwei, U100000>,

    //pub inactivity_scores: Vec<u64>,
    pub inactivity_scores: Hash256,
    pub inactivity_scores_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug = "ignore")]
    pub inactivity_scores_store: VecTree<u64, U100000>,

    pub randao_mix: B256,

    pub next_withdrawal_index: u64,
    pub next_withdrawal_validator_index: u64,
    pub pending_partial_withdrawals: Vec<PendingPartialWithdrawal>,
    pub earliest_exit_epoch: Epoch,
    pub exit_balance_to_consume: u64,

    //pub total_active_balance: Option<TotalActiveBalance>,

    //pub committee_caches: Vec<CommitteeCache>,
    pub epoch_attester_indexes: Hash256,
    pub epoch_attester_indexes_len: u64,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug = "ignore")]
    pub epoch_attester_indexes_store: VecTree<u64, U100000>,

    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[derivative(Debug = "ignore")]
    pub epoch_attester_indexes_set: BTreeSet<u64>,
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
    pub slot: Slot,
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
pub struct BlockVerifyResultAggregate {
    pub validator_indexes: BTreeSet<u64>,
    pub block_aggregate_signature: Option<FixedBytes<96>>,
}

pub fn agg_sig_to_fixed(sig: &AggregateSignature) -> FixedBytes<96> {
    FixedBytes::from(sig.to_signature().to_bytes())
}

pub fn fixed_to_agg_sig(bytes: &FixedBytes<96>) -> eyre::Result<AggregateSignature> {
    Ok(AggregateSignature::from_signature(
        &Signature::from_bytes(bytes.as_ref())
            .map_err(|e| eyre::eyre!("Signature::from_bytes error: {e:?}"))?,
    ))
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
    pub validator_indexes: BTreeSet<u64>,
    pub data: AttestationData,
    pub block_aggregate_signature: Option<FixedBytes<96>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationData {
    pub slot: Slot,
    pub committee_index: CommitteeIndex,
    pub receipts_root: B256,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Deposit {
    pub proof: Vec<B256>,
    pub data: DepositData,
}

/// Used by deposit data signing and verifying, do not modify field data types
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct DepositData {
    pub pubkey: FixedBytes<48>,
    #[serde(rename = "withdrawal_credentials")]
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: FixedBytes<96>,
}

impl DepositData {
    pub fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }

    /// Generate the signature for a given DepositData details.
    pub fn create_signature(
        &self,
        secret_key: &SecretKey,
        // spec: &ChainSpec
    ) -> FixedBytes<96> {
        //let domain = spec.get_deposit_domain();

        debug!("domain: 0x{}", hex::encode(DOMAIN_DEPOSIT));

        let msg = self
            .as_deposit_message()
            .signing_root(FixedBytes::from_slice(&DOMAIN_DEPOSIT));
        debug!("signing_root: 0x{}", hex::encode(msg));
        //SignatureBytes::from(secret_key.sign(msg))
        FixedBytes(
            secret_key
                .sign(
                    msg.as_ref(),
                    alloy_rpc_types_beacon::constants::BLS_DST_SIG,
                    &[],
                )
                .to_bytes(),
        )
    }

    pub fn verify_signature(&self) -> bool {
        let signature = match Signature::from_bytes(self.signature.as_ref()) {
            Ok(v) => v,
            _ => return false,
        };

        let pubkey = match PublicKey::from_bytes(self.pubkey.as_ref()) {
            Ok(v) => v,
            _ => return false,
        };

        let msg = self
            .as_deposit_message()
            .signing_root(FixedBytes::from_slice(&DOMAIN_DEPOSIT));
        let err = signature.verify(
            true,
            msg.as_ref(),
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &[],
            &pubkey,
            true,
        );
        err == blst::BLST_ERROR::BLST_SUCCESS
    }
}

#[derive(TreeHash, Serialize, Deserialize)]
pub struct DepositMessage {
    pub pubkey: FixedBytes<48>,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

impl SignedRoot for DepositMessage {}

//arbitrary::Arbitrary,
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SigningData {
    pub object_root: B256,
    pub domain: B256,
}

pub trait SignedRoot: tree_hash::TreeHash {
    fn signing_root(&self, domain: Hash256) -> Hash256 {
        SigningData {
            object_root: self.tree_hash_root(),
            domain,
        }
        .tree_hash_root()
    }
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
        let validators_len = 0;
        let validators_store = VecTree::try_new(validators_len).unwrap();
        let inactivity_scores_len = 0;
        let inactivity_scores_store = VecTree::try_new(inactivity_scores_len).unwrap();
        let balances_len = 0;
        let balances_store = VecTree::try_new(balances_len).unwrap();
        let epoch_attester_indexes_len = 0;
        let epoch_attester_indexes_store = VecTree::try_new(epoch_attester_indexes_len).unwrap();
        Self {
            //committee_caches: vec![Default::default(); 3],
            validators: validators_store.root(),
            validators_store,
            validators_len,
            inactivity_scores: inactivity_scores_store.root(),
            inactivity_scores_store,
            inactivity_scores_len,
            balances: balances_store.root(),
            balances_store,
            balances_len,
            epoch_attester_indexes: epoch_attester_indexes_store.root(),
            epoch_attester_indexes_store,
            epoch_attester_indexes_len,
            ..Default::default()
        }
    }

    pub fn state_transition(
        old_beacon_state: &BeaconState,
        beacon_block: &BeaconBlock,
    ) -> eyre::Result<Self> {
        debug!(target: "consensus-client", ?old_beacon_state, ?beacon_block, "state_transition");
        let spec = beacon_chain_spec();
        let mut new_beacon_state = old_beacon_state.clone();
        new_beacon_state.slot += 1;
        if (new_beacon_state.slot) % SLOTS_PER_EPOCH == 0 {
            new_beacon_state.process_epoch(&spec)?;
        }
        new_beacon_state.process_block(&beacon_block, &spec)?;

        Ok(new_beacon_state)
    }

    pub fn process_epoch(&mut self, spec: &ChainSpec) -> eyre::Result<()> {
        // PERF: Batch collect updates to minimize tree operations
        // Phase 1: Collect effective balance updates
        let num_validators = self.balances_store.len();
        let mut validator_updates: Vec<(usize, Validator)> =
            Vec::with_capacity(num_validators / 10);

        for index in 0..num_validators {
            let balance = self
                .balances_store
                .get(index)
                .ok_or(eyre::eyre!("BalanceNotfound"))?
                .min(&spec.max_effective_balance);
            let new_effective_balance =
                round_to_nearest(*balance, spec.effective_balance_increment);
            let validator = self
                .validators_store
                .get(index)
                .ok_or(eyre::eyre!("ValidatorNotfound"))?;

            if new_effective_balance != validator.effective_balance {
                let mut updated_validator = validator.clone();
                updated_validator.effective_balance = new_effective_balance;
                validator_updates.push((index, updated_validator));
            }
        }

        // Apply validator updates in batch
        for (index, validator) in validator_updates {
            self.validators_store.set(index, validator)?;
        }

        // Phase 2: Collect inactivity score updates
        let epoch = self.previous_epoch();
        let active_validator_indices = self.get_active_validator_indices(epoch);
        let mut score_updates: Vec<(usize, u64)> =
            Vec::with_capacity(active_validator_indices.len());

        for validator_index in active_validator_indices {
            let is_active = self
                .epoch_attester_indexes_set
                .contains(&(validator_index as u64));
            let current_score = self
                .inactivity_scores_store
                .get(validator_index)
                .ok_or(eyre::eyre!("InactivityScoreNotfound"))?;

            let new_score = if is_active {
                current_score.saturating_sub(spec.inactivity_score_recovery_rate)
            } else if *current_score < spec.max_inactivity_score {
                current_score.saturating_add(spec.inactivity_score_bias)
            } else {
                *current_score
            };

            if new_score != *current_score {
                score_updates.push((validator_index, new_score));
            }
        }

        // Apply inactivity score updates in batch
        for (index, score) in score_updates {
            self.inactivity_scores_store.set(index, score)?;
        }

        let validator_statuses = ValidatorStatuses::new(self, spec)?;

        self.epoch_attester_indexes_store.clear();
        self.epoch_attester_indexes_set.clear();

        self.process_rewards_and_penalties(&validator_statuses, spec)?;
        self.process_registry_updates(spec)?;

        Ok(())
    }

    pub fn process_registry_updates(&mut self, spec: &ChainSpec) -> eyre::Result<()> {
        // Process activation eligibility and ejections.
        // Collect eligible and exiting validators (we need to avoid mutating the state while iterating).
        // We assume it's safe to re-order the change in eligibility and `initiate_validator_exit`.
        // Rest assured exiting validators will still be exited in the same order as in the spec.
        let current_epoch = self.current_epoch();
        let is_ejectable = |validator: &Validator| {
            validator.is_active_at(current_epoch)
                && validator.effective_balance <= spec.ejection_balance
        };
        //let fork_name = state.fork_name_unchecked();
        let indices_to_update: Vec<_> = self
            .validators_store
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.is_eligible_for_activation_queue(spec) || is_ejectable(validator)
            })
            .map(|(idx, _)| idx)
            .collect();

        for index in indices_to_update {
            /*
            let validator = self.get_validator_mut(index)?;
            if validator.is_eligible_for_activation_queue(spec) {
                validator.activation_eligibility_epoch = current_epoch.safe_add(1)?;
            }
            if is_ejectable(validator) {
                self.initiate_validator_exit(index, spec)?;
            }
            */
            let mut validator = self
                .validators_store
                .get(index)
                .ok_or(eyre::eyre!("ValidatorNotfound"))?
                .clone();
            if validator.is_eligible_for_activation_queue(spec) {
                validator.activation_eligibility_epoch = current_epoch.safe_add(1)?;
                self.validators_store.set(index, validator.clone())?;
            }
            if is_ejectable(&validator) {
                self.initiate_validator_exit(index, spec)?;
            }
        }

        // Queue validators eligible for activation and not dequeued for activation prior to finalized epoch
        // Dequeue validators for activation up to churn limit
        let churn_limit = self.get_activation_churn_limit(spec)? as usize;

        let next_epoch = self.next_epoch()?;
        let mut full_activation_queue = ActivationQueue::default();

        for (index, validator) in self.validators_store.iter().enumerate() {
            // Add to speculative activation queue.
            full_activation_queue
                .add_if_could_be_eligible_for_activation(index, validator, next_epoch, spec);
        }

        //let epoch_cache = state.epoch_cache();
        let activation_queue = full_activation_queue
            .get_validators_eligible_for_activation(current_epoch, churn_limit);
        //.get_validators_eligible_for_activation(state.finalized_checkpoint().epoch, churn_limit);

        let delayed_activation_epoch = self.compute_activation_exit_epoch(current_epoch, spec)?;
        for index in activation_queue {
            //self.get_validator_mut(index)?.activation_epoch = delayed_activation_epoch;
            let mut validator = self
                .validators_store
                .get(index)
                .ok_or(eyre::eyre!("ValidatorNotfound"))?
                .clone();
            validator.activation_epoch = delayed_activation_epoch;
            self.validators_store.set(index, validator)?;
        }

        Ok(())
    }

    pub fn process_block(
        &mut self,
        beacon_block: &BeaconBlock,
        spec: &ChainSpec,
    ) -> eyre::Result<()> {
        self.process_randao(&beacon_block.body, spec)?;
        self.process_operations(&beacon_block.body, spec)?;
        Ok(())
    }

    pub fn process_randao(
        &mut self,
        beacon_block_body: &BeaconBlockBody,
        _spec: &ChainSpec,
    ) -> eyre::Result<()> {
        // PERF: Use batch verification for better throughput
        self.verify_attestations_batch(&beacon_block_body.attestations)?;

        // Update randao mix
        let mut mix = self.randao_mix;
        for attestation in &beacon_block_body.attestations {
            if let Some(sig) = attestation.block_aggregate_signature {
                mix = mix ^ keccak256(sig);
            }
        }

        self.randao_mix = mix;

        Ok(())
    }

    pub fn process_operations(
        &mut self,
        beacon_block_body: &BeaconBlockBody,
        spec: &ChainSpec,
    ) -> eyre::Result<()> {
        //self.process_deposit(&beacon_block_body.deposits)?;
        self.process_attestation(&beacon_block_body.attestations)?;
        //self.process_voluntary_exit(&beacon_block_body.voluntary_exits)?;

        let deposits: Vec<Deposit> = beacon_block_body
            .execution_requests
            .deposits
            .clone()
            .iter()
            .map(|deposit_request| Deposit {
                proof: Default::default(),
                data: DepositData {
                    pubkey: deposit_request.pubkey,
                    withdrawal_credentials: deposit_request.withdrawal_credentials,
                    amount: deposit_request.amount,
                    signature: deposit_request.signature,
                },
            })
            .collect();
        self.process_deposits(&deposits, spec)?;
        self.process_exits(&beacon_block_body.voluntary_exits, spec)?;
        self.process_withdrawal_requests(&beacon_block_body.execution_requests.withdrawals, spec)?;

        Ok(())
    }

    pub fn process_withdrawal_requests(
        &mut self,
        requests: &[WithdrawalRequest],
        spec: &ChainSpec,
    ) -> eyre::Result<()> {
        for request in requests {
            let amount = request.amount;
            let is_full_exit_request = amount == spec.full_exit_request_amount;

            // If partial withdrawal queue is full, only full exits are processed
            if self.pending_partial_withdrawals.len() == pending_partial_withdrawals_limit
                && !is_full_exit_request
            {
                continue;
            }

            // Verify pubkey exists
            let Some(validator_index) =
                self.get_validator_index_from_pubkey(&request.validator_pubkey)
            else {
                continue;
            };

            let validator = self.get_validator(validator_index)?;
            // Verify withdrawal credentials
            let has_correct_credential = validator.has_execution_withdrawal_credential(spec);
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
            if validator.exit_epoch != spec.far_future_epoch {
                continue;
            }

            // Verify the validator has been active long enough
            if self.current_epoch()
                < validator
                    .activation_epoch
                    .safe_add(spec.shard_committee_period)?
            {
                continue;
            }

            let pending_balance_to_withdraw =
                self.get_pending_balance_to_withdraw(validator_index)?;
            if is_full_exit_request {
                // Only exit validator if it has no pending withdrawals in the queue
                if pending_balance_to_withdraw == 0 {
                    self.initiate_validator_exit(validator_index, spec)?
                }
                continue;
            }

            let balance = self.get_balance(validator_index)?;
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
                let exit_queue_epoch =
                    self.compute_exit_epoch_and_update_churn(to_withdraw, spec)?;
                let withdrawable_epoch =
                    exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
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

    pub fn process_attestation(&mut self, attestations: &Vec<Attestation>) -> eyre::Result<()> {
        for attestation in attestations {
            let _ = self.process_one_attestation(attestation)?;
        }

        Ok(())
    }

    pub fn process_one_attestation(&mut self, attestation: &Attestation) -> eyre::Result<()> {
        self.verify_aggregate_signature(&attestation)?;
        //self.epoch_attester_indexes.extend(attestation.validator_indexes.iter());
        for validator_index in attestation.validator_indexes.iter() {
            self.epoch_attester_indexes_store.push(*validator_index)?;
        }

        Ok(())
    }

    /// Verify aggregate signature with public key caching for better performance
    pub fn verify_aggregate_signature(&self, attestation: &Attestation) -> eyre::Result<()> {
        let sig = match attestation.block_aggregate_signature {
            Some(ref v) => v,
            None => {
                return Err(eyre::eyre!("aggregate signature is empty"));
            }
        };
        let sig = fixed_to_agg_sig(sig)?;

        // PERF: Pre-allocate with capacity and use cached public keys
        let mut pubkeys = Vec::with_capacity(attestation.validator_indexes.len());
        for validator_index in &attestation.validator_indexes {
            let validator = self.get_validator(*validator_index as usize)?;
            // Use cached public key to avoid repeated parsing
            let pk = get_cached_pubkey(&validator.pubkey)?;
            pubkeys.push(pk);
        }
        let pubkeys_refs: Vec<&PublicKey> = pubkeys.iter().collect();

        // Use JSON encoding for signature verification
        let bytes: Vec<u8> = serde_json::to_vec(&attestation.data)?;
        let bytes_slice: &[u8] = &bytes;

        let aggregate_sig_verify_result = sig.to_signature().fast_aggregate_verify(
            true,
            bytes_slice,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &pubkeys_refs.as_slice(),
        );
        debug!(target: "consensus-client", slot=?attestation.data.slot, pubkeys_len=?pubkeys.len(), ?aggregate_sig_verify_result);

        if aggregate_sig_verify_result == blst::BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(eyre::eyre!("failed: {aggregate_sig_verify_result:?}"))
        }
    }

    /// Batch verify multiple attestations for improved throughput
    /// This is more efficient than verifying each attestation individually
    /// when processing a block with multiple attestations
    pub fn verify_attestations_batch(&self, attestations: &[Attestation]) -> eyre::Result<()> {
        if attestations.is_empty() {
            return Ok(());
        }

        // For small batches, just verify individually (batch overhead not worth it)
        if attestations.len() < 4 {
            for attestation in attestations {
                self.verify_aggregate_signature(attestation)?;
            }
            return Ok(());
        }

        // PERF: Batch verification - collect all data first
        let mut all_signatures = Vec::with_capacity(attestations.len());
        let mut all_pubkeys: Vec<Vec<PublicKey>> = Vec::with_capacity(attestations.len());
        let mut all_messages: Vec<Vec<u8>> = Vec::with_capacity(attestations.len());

        for attestation in attestations {
            let sig = match attestation.block_aggregate_signature {
                Some(ref v) => v,
                None => {
                    return Err(eyre::eyre!("aggregate signature is empty"));
                }
            };
            let sig = fixed_to_agg_sig(sig)?;
            all_signatures.push(sig.to_signature());

            // Collect public keys with caching
            let mut pubkeys = Vec::with_capacity(attestation.validator_indexes.len());
            for validator_index in &attestation.validator_indexes {
                let validator = self.get_validator(*validator_index as usize)?;
                let pk = get_cached_pubkey(&validator.pubkey)?;
                pubkeys.push(pk);
            }
            all_pubkeys.push(pubkeys);

            // Use JSON encoding
            all_messages.push(serde_json::to_vec(&attestation.data)?);
        }

        // Verify each attestation's aggregate signature
        // Note: blst doesn't have a multi-message batch verify in the same sense,
        // but we've already optimized with caching. For true batch verification,
        // we'd need signatures on the same message.
        for (i, (sig, (pubkeys, msg))) in all_signatures
            .iter()
            .zip(all_pubkeys.iter().zip(all_messages.iter()))
            .enumerate()
        {
            let pubkeys_refs: Vec<&PublicKey> = pubkeys.iter().collect();
            let result = sig.fast_aggregate_verify(
                true,
                msg.as_slice(),
                alloy_rpc_types_beacon::constants::BLS_DST_SIG,
                &pubkeys_refs.as_slice(),
            );

            if result != blst::BLST_ERROR::BLST_SUCCESS {
                return Err(eyre::eyre!(
                    "Batch verification failed at attestation {}: {:?}",
                    i,
                    result
                ));
            }
        }

        debug!(target: "consensus-client", "Batch verified {} attestations successfully", attestations.len());
        Ok(())
    }

    pub fn get_expected_withdrawals(
        &self,
        spec: &ChainSpec,
    ) -> eyre::Result<(Vec<Withdrawal>, Option<usize>)> {
        debug!(target: "consensus-client", "get_expected_withdrawals");
        let epoch = self.current_epoch();
        let mut withdrawal_index = self.next_withdrawal_index;
        let mut validator_index = self.next_withdrawal_validator_index;
        let mut withdrawals = Vec::<Withdrawal>::with_capacity(max_withdrawals_per_payload);

        let mut processed_partial_withdrawals_count = 0;

        for withdrawal in self.pending_partial_withdrawals.iter() {
            if withdrawal.withdrawable_epoch > epoch
                || withdrawals.len() == spec.max_pending_partials_per_withdrawals_sweep as usize
            {
                break;
            }

            let validator = self.get_validator(withdrawal.validator_index as usize)?;

            let has_sufficient_effective_balance =
                validator.effective_balance >= spec.min_activation_balance;
            let total_withdrawn = withdrawals
                .iter()
                .filter_map(|w| {
                    (w.validator_index == withdrawal.validator_index).then_some(w.amount)
                })
                .safe_sum()?;
            let balance = self
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
                        .get_execution_withdrawal_address()
                        .ok_or(eyre::eyre!("NonExecutionAddressWithdrawalCredential"))?,
                    amount: withdrawable_balance,
                });
                withdrawal_index.safe_add_assign(1)?;
            }
            processed_partial_withdrawals_count.safe_add_assign(1)?;
        }

        let bound = std::cmp::min(
            self.validators_store.len() as u64,
            spec.max_validators_per_withdrawals_sweep,
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
            let balance = self
                .get_balance(validator_index as usize)?
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
            } else if validator.is_partially_withdrawable_validator(balance, spec) {
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address: validator
                        .get_execution_withdrawal_address()
                        //.ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                        .ok_or(eyre::eyre!("WithdrawalCredentialsInvalid"))?,
                    //amount: balance.safe_sub(validator.get_max_effective_balance(spec, fork_name))?,
                    amount: balance.safe_sub(spec.max_effective_balance)?,
                });
                withdrawal_index.safe_add_assign(1)?;
            }
            if withdrawals.len() == max_withdrawals_per_payload {
                break;
            }
            validator_index = validator_index
                .safe_add(1)?
                .safe_rem(self.validators_store.len() as u64)?;
        }

        //debug!(target: "consensus-client", ?withdrawals, processed_partial_withdrawals_count, "get_expected_withdrawals");
        Ok((withdrawals, Some(processed_partial_withdrawals_count)))
    }

    pub fn process_withdrawals(&mut self) -> eyre::Result<(Vec<Withdrawal>, Option<usize>)> {
        let spec = beacon_chain_spec();
        let (expected_withdrawals, processed_partial_withdrawals_count) =
            self.get_expected_withdrawals(&spec)?;

        // TODO: check expected_withdrawals hash root against execution payload withdrawals root

        for withdrawal in expected_withdrawals.iter() {
            decrease_balance(self, withdrawal.validator_index as usize, withdrawal.amount)?;
        }

        // Update pending partial withdrawals [New in Electra:EIP7251]
        if let Some(processed_partial_withdrawals_count) =
            processed_partial_withdrawals_count.clone()
        {
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
                    .safe_rem(self.validators_store.len() as u64)?;
                self.next_withdrawal_validator_index = next_validator_index;
            }
        }

        // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        if expected_withdrawals.len() != max_withdrawals_per_payload
            && !self.validators_store.is_empty()
        {
            let next_validator_index = self
                .next_withdrawal_validator_index
                .safe_add(spec.max_validators_per_withdrawals_sweep)?
                .safe_rem(self.validators_store.len() as u64)?;
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
        self.validators_store
            .get(validator_index)
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
    }

    /*
    /// Safe mutator for the `validators` list.
    pub fn get_validator_mut(&mut self, validator_index: usize) -> eyre::Result<&mut Validator> {
        self.validators
            .get_mut(validator_index)
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
    }
    */

    pub fn get_balance(&self, validator_index: usize) -> eyre::Result<u64> {
        self.balances_store
            .get(validator_index)
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
            .copied()
    }

    /*
    /// Get a mutable reference to the balance of a single validator.
    pub fn get_balance_mut(&mut self, validator_index: usize) -> eyre::Result<&mut u64> {
        self.balances
            .get_mut(validator_index)
            .ok_or(eyre::eyre!("BalancesOutOfBounds, {validator_index}"))
    }
    */

    pub fn get_inactivity_score(&self, validator_index: usize) -> eyre::Result<u64> {
        self.inactivity_scores_store
            .get(validator_index)
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
            .copied()
    }

    /*
    /// Get a mutable reference to the inactivity_score of a single validator.
    pub fn get_inactivity_score_mut(&mut self, validator_index: usize) -> eyre::Result<&mut u64> {
        self.inactivity_scores
            .get_mut(validator_index)
            .ok_or(eyre::eyre!("InactivityScoreOutOfBounds, {validator_index}"))
    }
    */

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
        spec: &ChainSpec,
    ) -> eyre::Result<Epoch> {
        Ok(epoch.safe_add(1)?.safe_add(spec.max_seed_lookahead)?)
    }

    pub fn compute_exit_epoch_and_update_churn(
        &mut self,
        exit_balance: u64,
        spec: &ChainSpec,
    ) -> eyre::Result<Epoch> {
        let mut earliest_exit_epoch = std::cmp::max(
            self.earliest_exit_epoch,
            self.compute_activation_exit_epoch(self.current_epoch(), spec)?,
        );

        let per_epoch_churn = self.get_activation_exit_churn_limit(spec)?;
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
        self.exit_balance_to_consume = exit_balance_to_consume.safe_sub(exit_balance)?;
        self.earliest_exit_epoch = earliest_exit_epoch;
        Ok(self.earliest_exit_epoch)
    }

    pub fn get_validator_index_from_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.validators_store
            .iter()
            .position(|validator| validator.pubkey == *pubkey)
    }

    /// Return the effective balance for a validator with the given `validator_index`.
    pub fn get_effective_balance(&self, validator_index: usize) -> eyre::Result<u64> {
        self.get_validator(validator_index)
            .map(|v| v.effective_balance)
    }

    /// Initiate the exit of the validator of the given `index`.
    pub fn initiate_validator_exit(&mut self, index: usize, spec: &ChainSpec) -> eyre::Result<()> {
        let validator = self.get_validator(index)?;

        // Return if the validator already initiated exit
        if validator.exit_epoch != spec.far_future_epoch {
            return Ok(());
        }

        // Ensure the exit cache is built.
        //state.build_exit_cache(spec)?;

        // Compute exit queue epoch
        let effective_balance = self.get_effective_balance(index)?;
        let exit_queue_epoch = self.compute_exit_epoch_and_update_churn(effective_balance, spec)?;

        /*
        let validator = self.get_validator_mut(index)?;
        validator.exit_epoch = exit_queue_epoch;
        validator.withdrawable_epoch =
            exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
        */
        let mut validator = self
            .validators_store
            .get(index)
            .ok_or(eyre::eyre!("ValidatorNotfound"))?
            .clone();
        validator.exit_epoch = exit_queue_epoch;
        validator.withdrawable_epoch =
            exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
        self.validators_store.set(index, validator)?;

        /*
        state
            .exit_cache_mut()
            .record_validator_exit(exit_queue_epoch)?;
        */

        Ok(())
    }

    /// Return the churn limit for the current epoch dedicated to activations and exits.
    pub fn get_activation_exit_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        Ok(std::cmp::min(
            spec.max_per_epoch_activation_exit_churn_limit,
            self.get_balance_churn_limit(spec)?,
        ))
    }

    /// Return the churn limit for the current epoch.
    pub fn get_balance_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        let total_active_balance = self.get_total_active_balance(spec)?;
        let churn = std::cmp::max(
            spec.min_per_epoch_churn_limit_electra,
            total_active_balance.safe_div(spec.churn_limit_quotient)?,
        );

        Ok(churn.safe_sub(churn.safe_rem(spec.effective_balance_increment)?)?)
    }

    /// Implementation of `get_total_active_balance`, matching the spec.
    ///
    /// Requires the total active balance cache to be initialised, which is initialised whenever
    /// the current committee cache is.
    ///
    /// Returns minimum `EFFECTIVE_BALANCE_INCREMENT`, to avoid div by 0.
    pub fn get_total_active_balance(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        self.compute_total_active_balance_slow(spec)
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
            Err(eyre::eyre!("TotalActiveBalanceCacheInconsistent , initialized_epoch={initialized_epoch}, current_epoch={epoch}"))
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
        spec: &ChainSpec,
    ) -> eyre::Result<()> {
        // Verify and apply each exit in series. We iterate in series because higher-index exits may
        // become invalid due to the application of lower-index ones.
        for (i, exit) in voluntary_exits.iter().enumerate() {
            self.verify_exit(None, exit, spec)
                .map_err(|e| eyre::eyre!("verify_exit error {e}, index {i}"))?;

            self.initiate_validator_exit(exit.voluntary_exit.validator_index as usize, spec)?;
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
        spec: &ChainSpec,
    ) -> eyre::Result<()> {
        let current_epoch = current_epoch.unwrap_or(self.current_epoch());
        let exit = &signed_exit.voluntary_exit;

        let validator = self
            .validators_store
            .get(exit.validator_index as usize)
            .ok_or_else(|| eyre::eyre!("ExitInvalid::ValidatorUnknown({}", exit.validator_index))?;

        // Verify the validator is active.
        verify!(
            validator.is_active_at(current_epoch),
            format!("ExitInvalid::NotActive({})", exit.validator_index)
        );

        // Verify that the validator has not yet exited.
        verify!(
            validator.exit_epoch == spec.far_future_epoch,
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
            format!(
                "ExitInvalid::FutureEpoch(state: {}, exit {})",
                current_epoch, exit.epoch
            )
        );

        // Verify the validator has been active long enough.
        let earliest_exit_epoch = validator
            .activation_epoch
            .safe_add(spec.shard_committee_period)?;
        verify!(
            current_epoch >= earliest_exit_epoch,
            /*
            ExitInvalid::TooYoungToExit {
                current_epoch,
                earliest_exit_epoch,
            }
            */
            format!(
                "ExitInvalid::TooYoungToExit (current_epoch: {}, earliest_exit_epoch {})",
                current_epoch, earliest_exit_epoch
            )
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
                format!(
                    "ExitInvalid::PendingWithdrawalInQueue({})",
                    exit.validator_index
                )
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
        spec: &ChainSpec,
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
            self.apply_deposit(deposit.data.clone(), None, true, spec)?;
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
        spec: &ChainSpec,
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
                spec,
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
        spec: &ChainSpec,
    ) -> eyre::Result<usize> {
        let index = self.validators_store.len();
        //let fork_name = self.fork_name_unchecked();
        self.validators_store.push(Validator::from_deposit(
            pubkey,
            withdrawal_credentials,
            amount,
            //fork_name,
            spec,
        ))?;
        self.balances_store.push(amount)?;
        self.inactivity_scores_store.push(0)?;

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
        spec: &ChainSpec,
    ) -> eyre::Result<()> {
        //debug!(target: "consensus-client", slot=?self.slot, ?validator_statuses, "process_rewards_and_penalties");
        if self.current_epoch() == genesis_epoch {
            return Ok(());
        }

        // Guard against an out-of-bounds during the validator balance update.
        if validator_statuses.statuses.len() != self.balances_store.len()
            || validator_statuses.statuses.len() != self.validators_store.len()
        {
            return Err(eyre::eyre!("ValidatorStatusesInconsistent"));
        }

        let deltas = self.get_attestation_deltas_all(
            validator_statuses,
            ProposerRewardCalculation::Include,
            spec,
        )?;
        //debug!(target: "consensus-client", ?deltas, "process_rewards_and_penalties");

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
        spec: &ChainSpec,
    ) -> eyre::Result<Vec<AttestationDelta>> {
        self.get_attestation_deltas(validator_statuses, proposer_reward, spec)
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
        spec: &ChainSpec,
    ) -> eyre::Result<Vec<AttestationDelta>> {
        /*
        let finality_delay = state
            .previous_epoch()
            .safe_sub(state.finalized_checkpoint().epoch)?
            .as_u64();
        */
        let finality_delay = 0;

        let mut deltas = vec![AttestationDelta::default(); self.validators_store.len()];

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
                spec,
            )?;

            //debug!(target: "consensus-client", ?base_reward, "get_attestation_deltas");

            // let (inclusion_delay_delta, proposer_delta) =
            //     get_inclusion_delay_delta(validator, base_reward, spec)?;

            // if include_validator_delta(index) {
            let all_delta =
                get_all_delta(validator, base_reward, total_balances, finality_delay, spec)?;
            // let target_delta =
            //     get_target_delta(validator, base_reward, total_balances, finality_delay, spec)?;
            // let head_delta =
            //     get_head_delta(validator, base_reward, total_balances, finality_delay, spec)?;
            /*
            let inactivity_penalty_delta =
                get_inactivity_penalty_delta(validator, base_reward, finality_delay)?;
            */

            let delta = deltas
                .get_mut(index)
                //.ok_or(Error::DeltaOutOfBounds(index))?;
                .ok_or(eyre::eyre!("DeltaOutOfBounds, {index}"))?;
            delta.all_delta.combine(all_delta)?;
            // delta.target_delta.combine(target_delta)?;
            // delta.head_delta.combine(head_delta)?;
            // delta.inclusion_delay_delta.combine(inclusion_delay_delta)?;
            /*
            delta
                .inactivity_penalty_delta
                .combine(inactivity_penalty_delta)?;
            */
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
            //debug!(target: "consensus-client", ?index, ?delta, "get_attestation_deltas");
        }

        Ok(deltas)
    }

    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the current epoch committee cache, and will error if it isn't initialized.
    pub fn get_validator_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        /*
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            (self
                .committee_cache(RelativeEpoch::Current)?
                .active_validator_count() as u64)
                .safe_div(spec.churn_limit_quotient)?,
        ))
        */
        Ok(spec.min_per_epoch_churn_limit)
    }

    pub fn get_activation_churn_limit(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        self.get_validator_churn_limit(spec)
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
    pub fn compute_total_active_balance_slow(&self, spec: &ChainSpec) -> eyre::Result<u64> {
        let current_epoch = self.current_epoch();

        let mut total_active_balance = 0;

        for validator in self.validators_store.iter() {
            if validator.is_active_at(current_epoch) {
                total_active_balance.safe_add_assign(validator.effective_balance)?;
            }
        }
        Ok(std::cmp::max(
            total_active_balance,
            spec.effective_balance_increment,
        ))
    }

    pub fn get_seed(&self, epoch: Epoch, domain_constant: u32) -> eyre::Result<Hash256> {
        let mix = self.randao_mix;

        let domain_bytes = domain_constant.to_le_bytes();
        let epoch_bytes = epoch.to_le_bytes();

        const NUM_DOMAIN_BYTES: usize = 4;
        const NUM_EPOCH_BYTES: usize = 8;
        const MIX_OFFSET: usize = NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES;
        const NUM_MIX_BYTES: usize = 32;

        let mut preimage = [0; NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES + NUM_MIX_BYTES];
        preimage[0..NUM_DOMAIN_BYTES].copy_from_slice(&domain_bytes);
        preimage[NUM_DOMAIN_BYTES..MIX_OFFSET].copy_from_slice(&epoch_bytes);
        preimage[MIX_OFFSET..].copy_from_slice(mix.as_slice());

        Ok(Hash256::from_slice(&hash(&preimage)))
    }

    /*
        /// Build all committee caches, if they need to be built.
        pub fn build_all_committee_caches(&mut self,
            spec: &ChainSpec,
            ) -> eyre::Result<()> {
            //self.build_committee_cache(RelativeEpoch::Previous)?;
            self.build_committee_cache(RelativeEpoch::Current, spec)?;
            //self.build_committee_cache(RelativeEpoch::Next)?;
            Ok(())
        }

        /// Build a committee cache, unless it is has already been built.
        pub fn build_committee_cache(
            &mut self,
            relative_epoch: RelativeEpoch,
            spec: &ChainSpec,
        ) -> eyre::Result<()> {
            let i = Self::committee_cache_index(relative_epoch);
            let is_initialized = self
                .committee_cache_at_index(i)?
                .is_initialized_at(relative_epoch.into_epoch(self.current_epoch()));

            if !is_initialized {
                self.force_build_committee_cache(relative_epoch, spec)?;
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
                .ok_or(eyre::eyre!("Error::CommitteeCachesOutOfBounds, {index}"))
        }

        /// Get a mutable reference to the committee cache at a given index.
        fn committee_cache_at_index_mut(
            &mut self,
            index: usize,
        ) -> eyre::Result<&mut CommitteeCache> {
            self.committee_caches
                .get_mut(index)
                .ok_or(eyre::eyre!("Error::CommitteeCachesOutOfBounds, {index}"))
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
            spec: &ChainSpec,
        ) -> eyre::Result<()> {
            let epoch = relative_epoch.into_epoch(self.current_epoch());
            let i = Self::committee_cache_index(relative_epoch);

            *self.committee_cache_at_index_mut(i)? = self.initialize_committee_cache(epoch, spec)?;
            Ok(())
        }

        /// Initializes a new committee cache for the given `epoch`, regardless of whether one already
        /// exists. Returns the committee cache without attaching it to `self`.
        ///
        /// To build a cache and store it on `self`, use `Self::build_committee_cache`.
        pub fn initialize_committee_cache(
            &self,
            epoch: Epoch,
            spec: &ChainSpec,
        ) -> eyre::Result<CommitteeCache> {
            CommitteeCache::initialized(self, epoch, spec)
        }
    */

    pub fn has_active_validators(&self, relative_epoch: RelativeEpoch) -> bool {
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let active_validator_indices = self.get_active_validator_indices(epoch);

        !active_validator_indices.is_empty()
    }

    pub fn get_active_validator_indices(&self, epoch: Epoch) -> Vec<usize> {
        let mut active = Vec::with_capacity(self.validators_store.len());
        for (index, validator) in self.validators_store.iter().enumerate() {
            if validator.is_active_at(epoch) {
                active.push(index)
            }
        }

        active
    }

    /*
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
            if !self.has_active_validators(RelativeEpoch::Current) {
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
                Err(eyre::eyre!("Error::CommitteeCacheUninitialized, relative_epoch: {relative_epoch:?}"))
            }
        }
    */
    pub fn gen_committee_cache(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> eyre::Result<CommitteeCache> {
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let spec = beacon_chain_spec();
        CommitteeCache::initialized(self, epoch, &spec)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct PendingPartialWithdrawal {
    pub validator_index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance(state: &mut BeaconState, index: usize, delta: u64) -> eyre::Result<()> {
    //increase_balance_directly(state.get_balance_mut(index)?, delta)
    let balance = state
        .balances_store
        .get(index)
        .ok_or(eyre::eyre!("BalanceNotfound"))?;
    Ok(state
        .balances_store
        .set(index, balance.saturating_add(delta))?)
}

/*
/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance_directly(balance: &mut u64, delta: u64) -> eyre::Result<()> {
    balance.safe_add_assign(delta)?;
    Ok(())
}
*/

pub fn decrease_balance(state: &mut BeaconState, index: usize, delta: u64) -> eyre::Result<()> {
    //decrease_balance_directly(state.get_balance_mut(index)?, delta)
    let balance = state
        .balances_store
        .get(index)
        .ok_or(eyre::eyre!("BalanceNotfound"))?;
    Ok(state
        .balances_store
        .set(index, balance.saturating_sub(delta))?)
}

/*
pub fn decrease_balance_directly(balance: &mut u64, delta: u64) -> eyre::Result<()> {
    *balance = balance.saturating_sub(delta);
    Ok(())
}
*/

pub fn is_compounding_withdrawal_credential(
    withdrawal_credentials: B256,
    spec: &ChainSpec,
) -> bool {
    withdrawal_credentials
        .as_slice()
        .first()
        .map(|prefix_byte| *prefix_byte == spec.compounding_withdrawal_prefix_byte)
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
    FutureEpoch { state: Epoch, exit: Epoch },
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
    pub fn new(state: &BeaconState, spec: &ChainSpec) -> eyre::Result<Self> {
        let mut statuses = Vec::with_capacity(state.validators_store.len());
        let mut total_balances = TotalBalances::new(spec);

        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        for (validator_index, validator) in state.validators_store.iter().enumerate() {
            let effective_balance = validator.effective_balance;
            let inactivity_score = state.get_inactivity_score(validator_index)?;
            let is_punishable = inactivity_score >= spec.trigger_punish_inactivity_score;
            let mut status = ValidatorStatus {
                is_slashed: validator.slashed,
                is_eligible: state.is_eligible_validator(previous_epoch, validator)?,
                is_withdrawable_in_current_epoch: validator.is_withdrawable_at(current_epoch),
                current_epoch_effective_balance: effective_balance,

                //
                is_previous_epoch_attester: state
                    .epoch_attester_indexes_set
                    .contains(&(validator_index as u64)),
                is_punishable,

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
    spec: &ChainSpec,
) -> eyre::Result<u64> {
    Ok(validator_effective_balance
        .safe_mul(spec.base_reward_factor)?
        .safe_div(sqrt_total_active_balance.as_u64())?
        .safe_div(spec.base_rewards_per_epoch)?)
}

fn get_all_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    total_balances: &TotalBalances,
    finality_delay: u64,
    spec: &ChainSpec,
) -> eyre::Result<Delta> {
    get_attestation_component_delta_n42(base_reward, validator.is_punishable, spec)
}

pub fn get_attestation_component_delta_n42(
    base_reward: u64,
    is_punishable: bool,
    spec: &ChainSpec,
) -> eyre::Result<Delta> {
    let mut delta = Delta::default();

    delta.reward(base_reward)?;
    if is_punishable {
        delta.penalize(base_reward * spec.multiple_reward_for_inactivity_penalty)?;
    }

    Ok(delta)
}

pub fn get_inactivity_penalty_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    finality_delay: u64,
    spec: &ChainSpec,
) -> eyre::Result<Delta> {
    let mut delta = Delta::default();

    debug!(?finality_delay, "get_inactivity_penalty_delta");
    // Inactivity penalty
    if finality_delay > spec.min_epochs_to_inactivity_penalty {
        // If validator is performing optimally this cancels all rewards for a neutral balance
        delta.penalize(
            spec.base_rewards_per_epoch
                .safe_mul(base_reward)?
                .safe_sub(get_proposer_reward(base_reward, spec)?)?,
        )?;

        // Additionally, all validators whose FFG target didn't match are penalized extra
        // This condition is equivalent to this condition from the spec:
        // `index not in get_unslashed_attesting_indices(state, matching_target_attestations)`
        if validator.is_slashed || !validator.is_previous_epoch_attester {
            delta.penalize(
                validator
                    .current_epoch_effective_balance
                    .safe_mul(finality_delay)?
                    .safe_div(spec.inactivity_penalty_quotient)?,
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

    pub is_punishable: bool,
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
    pub fn new(spec: &ChainSpec) -> Self {
        Self {
            effective_balance_increment: spec.effective_balance_increment,
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

/// Compute the reward awarded to a proposer for including an attestation from a validator.
///
/// The `base_reward` param should be the `base_reward` of the attesting validator.
fn get_proposer_reward(base_reward: u64, spec: &ChainSpec) -> eyre::Result<u64> {
    Ok(base_reward.safe_div(spec.proposer_reward_quotient)?)
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

pub fn round_down(n: u64, step: u64) -> u64 {
    n - (n % step)
}

fn round_to_nearest(n: u64, step: u64) -> u64 {
    ((n + step / 2) / step) * step
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn test_round_down() {
        assert_eq!(round_down(10, 3), 9);
        assert_eq!(round_down(9, 3), 9);
        assert_eq!(round_down(8, 3), 6);
        assert_eq!(round_down(0, 3), 0);
        assert_eq!(round_down(100, 10), 100);
        assert_eq!(round_down(105, 10), 100);
    }

    #[test]
    fn test_round_to_nearest() {
        assert_eq!(round_to_nearest(10, 3), 9);
        assert_eq!(round_to_nearest(11, 3), 12);
        assert_eq!(round_to_nearest(5, 3), 6);
        assert_eq!(round_to_nearest(4, 3), 3);
    }

    #[test]
    fn test_beacon_chain_spec_defaults() {
        let spec = beacon_chain_spec();
        assert_eq!(spec.min_activation_balance, 32000000000);
        assert_eq!(spec.ejection_balance, 16000000000);
        assert_eq!(spec.max_effective_balance, 32000000000);
        assert_eq!(spec.effective_balance_increment, 1000000000);
        assert_eq!(spec.max_committees_per_slot, 4);
        assert_eq!(spec.target_committee_size, 4);
    }

    #[test]
    fn test_relative_epoch_into_epoch() {
        let base_epoch: u64 = 10;

        assert_eq!(RelativeEpoch::Current.into_epoch(base_epoch), 10);
        assert_eq!(RelativeEpoch::Previous.into_epoch(base_epoch), 9);
        assert_eq!(RelativeEpoch::Next.into_epoch(base_epoch), 11);

        // Test edge case with epoch 0
        assert_eq!(RelativeEpoch::Previous.into_epoch(0), 0); // saturating_sub
        assert_eq!(RelativeEpoch::Current.into_epoch(0), 0);
        assert_eq!(RelativeEpoch::Next.into_epoch(0), 1);
    }

    #[test]
    fn test_total_balances() {
        let spec = beacon_chain_spec();
        let balances = TotalBalances::new(&spec);

        // Should return effective_balance_increment as minimum
        assert_eq!(balances.current_epoch(), spec.effective_balance_increment);
        assert_eq!(balances.previous_epoch(), spec.effective_balance_increment);
        assert_eq!(
            balances.previous_epoch_attesters(),
            spec.effective_balance_increment
        );
    }

    #[test]
    fn test_validator_status_default() {
        let status = ValidatorStatus::default();
        assert!(!status.is_slashed);
        assert!(!status.is_eligible);
        assert!(!status.is_active_in_current_epoch);
        assert!(!status.is_active_in_previous_epoch);
        assert!(!status.is_current_epoch_attester);
        assert!(!status.is_previous_epoch_attester);
    }

    #[test]
    fn test_validator_status_update() {
        let mut status1 = ValidatorStatus::default();
        let mut status2 = ValidatorStatus::default();

        status2.is_slashed = true;
        status2.is_eligible = true;
        status2.is_active_in_current_epoch = true;

        status1.update(&status2);

        assert!(status1.is_slashed);
        assert!(status1.is_eligible);
        assert!(status1.is_active_in_current_epoch);
        assert!(!status1.is_previous_epoch_attester); // Should remain false
    }

    #[test]
    fn test_slots_per_epoch_constant() {
        assert_eq!(SLOTS_PER_EPOCH, 32);
    }

    #[test]
    fn test_domain_constant() {
        assert_eq!(DOMAIN_CONSTANT_BEACON_ATTESTER, 1);
    }

    #[test]
    fn test_cached_epochs_constant() {
        assert_eq!(CACHED_EPOCHS, 3);
    }

    #[test]
    fn test_pubkey_cache_operations() {
        // Clear cache first
        if let Ok(mut cache) = PUBKEY_CACHE.write() {
            cache.clear();
        }

        // Generate a valid test pubkey (48 bytes)
        let pubkey_bytes = FixedBytes::<48>::ZERO;

        // This should fail because zero bytes is not a valid public key
        // but it tests the cache mechanism
        let result = get_cached_pubkey(&pubkey_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_shuffle_cache_initialization() {
        // Verify the cache is properly initialized
        let cache_result = SHUFFLE_CACHE.read();
        assert!(cache_result.is_ok());
    }

    #[test]
    fn test_beacon_state_new() {
        let state = BeaconState::new();
        assert_eq!(state.validators_len, 0);
        assert_eq!(state.balances_len, 0);
        assert_eq!(state.slot, 0);
    }

    #[test]
    fn test_beacon_block_default() {
        let block = BeaconBlock::default();
        assert_eq!(block.slot, 0);
        assert_eq!(block.eth1_block_hash, B256::ZERO);
        assert_eq!(block.parent_hash, B256::ZERO);
        assert_eq!(block.state_root, B256::ZERO);
    }

    #[test]
    fn test_attestation_data_default() {
        let data = AttestationData::default();
        assert_eq!(data.slot, 0);
        assert_eq!(data.committee_index, 0);
        assert_eq!(data.receipts_root, B256::ZERO);
    }

    #[test]
    fn test_deposit_data_default() {
        let data = DepositData::default();
        assert_eq!(data.pubkey, BLSPubkey::default());
        assert_eq!(data.amount, 0);
    }

    #[test]
    fn test_voluntary_exit_default() {
        let exit = VoluntaryExit::default();
        assert_eq!(exit.epoch, 0);
        assert_eq!(exit.validator_index, 0);
    }

    #[test]
    fn test_epoch_to_block_number() {
        assert_eq!(epoch_to_block_number(0), 0);
        assert_eq!(epoch_to_block_number(1), 32);
        assert_eq!(epoch_to_block_number(2), 64);
        assert_eq!(epoch_to_block_number(10), 320);
    }

    #[test]
    fn test_voluntary_exit_with_sig_default() {
        let exit_with_sig = VoluntaryExitWithSig::default();
        assert_eq!(exit_with_sig.voluntary_exit.epoch, 0);
        assert_eq!(exit_with_sig.voluntary_exit.validator_index, 0);
    }

    #[test]
    fn test_attestation_default() {
        let attestation = Attestation::default();
        assert!(attestation.validator_indexes.is_empty());
        assert_eq!(attestation.data.slot, 0);
        assert!(attestation.block_aggregate_signature.is_none());
    }

    #[test]
    fn test_beacon_block_body_default() {
        let body = BeaconBlockBody::default();
        assert!(body.deposits.is_empty());
        assert!(body.voluntary_exits.is_empty());
    }

    #[test]
    fn test_beacon_block_hash_slow() {
        let block = BeaconBlock::default();
        let hash = block.hash_slow();
        // Hash should be deterministic for same input
        let hash2 = block.hash_slow();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_attestation_signature_roundtrip() {
        use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};

        // Generate a test keypair
        let ikm = [1u8; 32]; // Use fixed seed for reproducibility
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();

        // Create test attestation data
        let attestation_data = AttestationData {
            slot: 12345,
            committee_index: 0,
            receipts_root: B256::from([0xab; 32]),
        };

        // Sign using JSON serialization (same as mobile-sdk client)
        let bytes: Vec<u8> = serde_json::to_vec(&attestation_data).unwrap();
        let sig = sk.sign(&bytes, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[]);

        // Verify the signature directly (same as miner.rs verification)
        let err = sig.verify(
            true,
            &bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &[],
            &pk,
            true,
        );
        assert_eq!(
            err,
            blst::BLST_ERROR::BLST_SUCCESS,
            "Single signature verification failed"
        );

        // Create attestation with aggregate signature (same as beacon.rs verification)
        let agg_sig = AggregateSignature::from_signature(&sig);
        let attestation = Attestation {
            validator_indexes: [0].into_iter().collect(),
            data: attestation_data.clone(),
            block_aggregate_signature: Some(agg_sig_to_fixed(&agg_sig)),
        };

        // Verify using fast_aggregate_verify (same as verify_aggregate_signature)
        let sig_bytes = attestation.block_aggregate_signature.as_ref().unwrap();
        let agg_sig_restored = fixed_to_agg_sig(sig_bytes).unwrap();
        let pubkeys = vec![pk];
        let pubkeys_refs: Vec<&PublicKey> = pubkeys.iter().collect();

        let result = agg_sig_restored.to_signature().fast_aggregate_verify(
            true,
            &bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &pubkeys_refs,
        );
        assert_eq!(
            result,
            blst::BLST_ERROR::BLST_SUCCESS,
            "Aggregate signature verification failed"
        );
    }

    #[test]
    fn test_attestation_signature_multiple_validators() {
        use blst::min_pk::{AggregateSignature, PublicKey, SecretKey};

        // Generate multiple keypairs
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();
        for i in 0..3 {
            let ikm = [i + 1; 32];
            let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            secret_keys.push(sk);
            public_keys.push(pk);
        }

        // Create test attestation data
        let attestation_data = AttestationData {
            slot: 67890,
            committee_index: 1,
            receipts_root: B256::from([0xcd; 32]),
        };

        // Sign with each validator and aggregate using JSON serialization
        let bytes: Vec<u8> = serde_json::to_vec(&attestation_data).unwrap();
        let mut agg_sig: Option<AggregateSignature> = None;

        for sk in &secret_keys {
            let sig = sk.sign(&bytes, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[]);
            match agg_sig.as_mut() {
                Some(agg) => {
                    agg.add_signature(&sig, false).unwrap();
                }
                None => {
                    agg_sig = Some(AggregateSignature::from_signature(&sig));
                }
            }
        }

        // Verify aggregate signature
        let agg_sig = agg_sig.unwrap();
        let pubkeys_refs: Vec<&PublicKey> = public_keys.iter().collect();

        let result = agg_sig.to_signature().fast_aggregate_verify(
            true,
            &bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &pubkeys_refs,
        );
        assert_eq!(
            result,
            blst::BLST_ERROR::BLST_SUCCESS,
            "Multi-validator aggregate signature verification failed"
        );
    }

    #[test]
    fn test_attestation_signature_json_vs_ssz_mismatch() {
        use blst::min_pk::SecretKey;
        use ssz::Encode;

        // Generate a test keypair
        let ikm = [42u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();

        // Create test attestation data
        let attestation_data = AttestationData {
            slot: 100,
            committee_index: 2,
            receipts_root: B256::from([0xef; 32]),
        };

        // Sign using JSON serialization (the correct one now)
        let json_bytes: Vec<u8> = serde_json::to_vec(&attestation_data).unwrap();
        let sig = sk.sign(
            &json_bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &[],
        );

        // Try to verify using SSZ serialization (should fail)
        let ssz_bytes: Vec<u8> = attestation_data.as_ssz_bytes();
        let err = sig.verify(
            true,
            &ssz_bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &[],
            &pk,
            true,
        );
        assert_ne!(
            err,
            blst::BLST_ERROR::BLST_SUCCESS,
            "Verification should fail when using different serialization"
        );

        // Verify using JSON serialization (should succeed)
        let err = sig.verify(
            true,
            &json_bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &[],
            &pk,
            true,
        );
        assert_eq!(
            err,
            blst::BLST_ERROR::BLST_SUCCESS,
            "Verification should succeed with matching serialization"
        );
    }
}
