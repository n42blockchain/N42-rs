// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_eips::{eip4895::Withdrawal, eip7002::WithdrawalRequest};
use alloy_primitives::{keccak256, Address, BlockHash, Bytes, Log, B256};
use alloy_primitives::{FixedBytes, Sealable};
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use alloy_sol_types::{sol, SolEvent};
use blst::min_pk::PublicKey;
use blst::min_pk::SecretKey;
use blst::min_pk::{AggregateSignature, Signature};
use integer_sqrt::IntegerSquareRoot;
use once_cell::sync::Lazy;
use schnellru::LruMap;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::collections::BTreeSet;
use std::sync::RwLock;
use tracing::{debug, error};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::committee_cache::CommitteeCache;
use crate::safe_arith::SafeArith;
use crate::safe_arith::SafeArithIter;
use crate::{activation_queue::ActivationQueue, CommitteeIndex, Hash256, Slot, Validator};
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
                .get(index)?
                .ok_or(eyre::eyre!("BalanceNotfound"))?
                .min(&spec.max_effective_balance);
            let new_effective_balance =
                round_to_nearest(*balance, spec.effective_balance_increment);
            let validator = self
                .validators_store
                .get(index)?
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
                .get(validator_index)?
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
                .get(index)?
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
                .get(index)?
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
            .get(validator_index)?
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
            .get(validator_index)?
            .copied()
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
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
            .get(validator_index)?
            .copied()
            .ok_or(eyre::eyre!("UnknownValidator, {validator_index}"))
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
            .get(index)?
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
            .get(exit.validator_index as usize)?
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
        .get(index)?
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
        .get(index)?
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

#[cfg(test)]
mod state_basics {
    use super::*;
    use crate::test_util::{active_validator, state_with_validators};

    fn spec() -> ChainSpec {
        beacon_chain_spec()
    }

    #[test]
    fn epoch_accessors_follow_the_slot() {
        let mut s = BeaconState::new();
        assert_eq!((s.current_epoch(), s.previous_epoch()), (0, 0));
        s.slot = 31;
        assert_eq!(s.current_epoch(), 0);
        s.slot = 32;
        assert_eq!((s.current_epoch(), s.previous_epoch()), (1, 0));
        s.slot = 64;
        assert_eq!(s.current_epoch(), 2);
        assert_eq!(s.previous_epoch(), 1);
        assert_eq!(s.next_epoch().unwrap(), 3);
    }

    #[test]
    fn indexers_report_unknown_validators() {
        let s = state_with_validators(2, 0);
        assert!(s.get_validator(1).is_ok());
        assert_eq!(s.get_balance(1).unwrap(), 32_000_000_000);
        assert_eq!(s.get_inactivity_score(0).unwrap(), 0);
        assert_eq!(s.get_effective_balance(0).unwrap(), 32_000_000_000);

        for err in [
            s.get_validator(2).map(|_| ()).unwrap_err(),
            s.get_balance(2).map(|_| ()).unwrap_err(),
            s.get_inactivity_score(2).map(|_| ()).unwrap_err(),
            s.get_effective_balance(2).map(|_| ()).unwrap_err(),
        ] {
            assert!(err.to_string().contains("UnknownValidator"), "{err}");
        }
    }

    #[test]
    fn pubkey_lookup_finds_the_right_index() {
        let s = state_with_validators(5, 0);
        assert_eq!(s.get_validator_index_from_pubkey(&crate::test_util::pubkey(3)), Some(3));
        assert_eq!(s.get_validator_index_from_pubkey(&BLSPubkey::repeat_byte(0xff)), None);
    }

    #[test]
    fn pending_balance_sums_only_the_requested_validator() {
        let mut s = state_with_validators(3, 0);
        for (v, amount) in [(1u64, 5u64), (2, 7), (1, 11)] {
            s.pending_partial_withdrawals.push(PendingPartialWithdrawal {
                validator_index: v,
                amount,
                withdrawable_epoch: 0,
            });
        }
        assert_eq!(s.get_pending_balance_to_withdraw(1).unwrap(), 16);
        assert_eq!(s.get_pending_balance_to_withdraw(2).unwrap(), 7);
        assert_eq!(s.get_pending_balance_to_withdraw(0).unwrap(), 0);

        s.pending_partial_withdrawals.push(PendingPartialWithdrawal {
            validator_index: 1,
            amount: u64::MAX,
            withdrawable_epoch: 0,
        });
        assert!(s.get_pending_balance_to_withdraw(1).is_err());
    }

    #[test]
    fn activation_exit_epoch_adds_lookahead_and_checks_overflow() {
        let s = BeaconState::new();
        let spec = spec();
        // epoch + 1 + max_seed_lookahead (4)
        assert_eq!(s.compute_activation_exit_epoch(3, &spec).unwrap(), 8);
        assert!(s.compute_activation_exit_epoch(u64::MAX, &spec).is_err());
        assert!(s.compute_activation_exit_epoch(u64::MAX - 1, &spec).is_err());
    }

    #[test]
    fn total_active_balance_counts_only_active_validators() {
        let spec = spec();
        let mut s = state_with_validators(3, 0);
        assert_eq!(s.compute_total_active_balance_slow(&spec).unwrap(), 96_000_000_000);
        assert_eq!(s.get_total_active_balance(&spec).unwrap(), 96_000_000_000);

        let mut exited = active_validator(0, &spec);
        exited.exit_epoch = 0;
        s.validators_store.set(0, exited).unwrap();
        assert_eq!(s.get_total_active_balance(&spec).unwrap(), 64_000_000_000);

        // An empty registry is floored at one effective balance increment (no div by zero).
        assert_eq!(
            BeaconState::new().get_total_active_balance(&spec).unwrap(),
            spec.effective_balance_increment
        );
    }

    #[test]
    fn churn_limits_scale_with_total_active_balance() {
        let spec = spec();
        // 4 validators: total/32 = 4 ETH is below the 128 ETH floor.
        let small = state_with_validators(4, 0);
        assert_eq!(small.get_balance_churn_limit(&spec).unwrap(), 128_000_000_000);
        assert_eq!(small.get_activation_exit_churn_limit(&spec).unwrap(), 128_000_000_000);

        // 100 validators with a lowered floor: total/32 = 100 ETH wins over the floor, and the
        // activation/exit variant is capped by max_per_epoch_activation_exit_churn_limit.
        let mut low_floor = beacon_chain_spec();
        low_floor.min_per_epoch_churn_limit_electra = 1_000_000_000;
        let big = state_with_validators(100, 0);
        assert_eq!(big.get_balance_churn_limit(&low_floor).unwrap(), 100_000_000_000);
        assert_eq!(big.get_activation_exit_churn_limit(&low_floor).unwrap(), 100_000_000_000);
        low_floor.max_per_epoch_activation_exit_churn_limit = 50_000_000_000;
        assert_eq!(big.get_activation_exit_churn_limit(&low_floor).unwrap(), 50_000_000_000);

        // The result is rounded down to a multiple of the effective balance increment.
        let mut odd = beacon_chain_spec();
        odd.churn_limit_quotient = 7;
        let s = state_with_validators(100, 0);
        // 3.2e12 / 7 = 457_142_857_142 -> 457_000_000_000
        assert_eq!(s.get_balance_churn_limit(&odd).unwrap(), 457_000_000_000);

        // The registry-update churn limit is the configured minimum.
        assert_eq!(small.get_validator_churn_limit(&spec).unwrap(), 4);
        assert_eq!(small.get_activation_churn_limit(&spec).unwrap(), 4);
    }

    #[test]
    fn exit_queue_consumes_churn_and_spills_into_later_epochs() {
        let spec = spec();
        let mut s = state_with_validators(4, 0);

        // Fresh queue: exits start at current + 1 + lookahead = 5 with a full 128 ETH of churn.
        assert_eq!(s.compute_exit_epoch_and_update_churn(32_000_000_000, &spec).unwrap(), 5);
        assert_eq!(s.earliest_exit_epoch, 5);
        assert_eq!(s.exit_balance_to_consume, 96_000_000_000);

        // Same epoch keeps consuming the remaining churn.
        assert_eq!(s.compute_exit_epoch_and_update_churn(32_000_000_000, &spec).unwrap(), 5);
        assert_eq!(s.exit_balance_to_consume, 64_000_000_000);

        // 300 ETH on a fresh queue needs two more epochs of churn beyond the first.
        let mut t = state_with_validators(4, 0);
        assert_eq!(t.compute_exit_epoch_and_update_churn(300_000_000_000, &spec).unwrap(), 7);
        assert_eq!(t.earliest_exit_epoch, 7);
        assert_eq!(t.exit_balance_to_consume, 84_000_000_000);
    }

    #[test]
    fn initiate_validator_exit_sets_epochs_once() {
        let spec = spec();
        let mut s = state_with_validators(4, 0);
        s.initiate_validator_exit(0, &spec).unwrap();
        let v = s.get_validator(0).unwrap().clone();
        assert_eq!(v.exit_epoch, 5);
        assert_eq!(v.withdrawable_epoch, 6);
        let (queue_epoch, to_consume) = (s.earliest_exit_epoch, s.exit_balance_to_consume);

        // A second call is a no-op: it must not consume more churn.
        s.initiate_validator_exit(0, &spec).unwrap();
        assert_eq!(s.get_validator(0).unwrap(), &v);
        assert_eq!((s.earliest_exit_epoch, s.exit_balance_to_consume), (queue_epoch, to_consume));

        assert!(s.initiate_validator_exit(9, &spec).is_err());
    }

    #[test]
    fn seed_is_the_hash_of_domain_epoch_and_mix() {
        let mut s = BeaconState::new();
        s.randao_mix = B256::repeat_byte(0x5a);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&7u32.to_le_bytes());
        preimage.extend_from_slice(&9u64.to_le_bytes());
        preimage.extend_from_slice(s.randao_mix.as_slice());
        let expected = Hash256::from_slice(&hash(&preimage));
        assert_eq!(s.get_seed(9, 7).unwrap(), expected);
        assert_ne!(s.get_seed(10, 7).unwrap(), expected);
        assert_ne!(s.get_seed(9, 8).unwrap(), expected);
        s.randao_mix = B256::ZERO;
        assert_ne!(s.get_seed(9, 7).unwrap(), expected);
    }

    #[test]
    fn active_indices_and_relative_epochs() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);
        let mut late = active_validator(1, &spec);
        late.activation_epoch = 3;
        s.validators_store.set(1, late).unwrap();
        let mut gone = active_validator(2, &spec);
        gone.exit_epoch = 2;
        s.validators_store.set(2, gone).unwrap();

        // current epoch is 2.
        assert_eq!(s.get_active_validator_indices(1), vec![0, 2, 3]);
        assert_eq!(s.get_active_validator_indices(2), vec![0, 3]);
        assert_eq!(s.get_active_validator_indices(3), vec![0, 1, 3]);
        assert!(s.has_active_validators(RelativeEpoch::Current));

        assert!(!BeaconState::new().has_active_validators(RelativeEpoch::Current));
    }

    #[test]
    fn gen_committee_cache_matches_direct_construction() {
        let s = state_with_validators(128, 32);
        for rel in [RelativeEpoch::Previous, RelativeEpoch::Current, RelativeEpoch::Next] {
            let epoch = rel.into_epoch(s.current_epoch());
            let via_state = s.gen_committee_cache(rel).unwrap();
            let direct = CommitteeCache::initialized(&s, epoch, &spec()).unwrap();
            assert_eq!(via_state, direct);
            assert!(via_state.is_initialized_at(epoch));
        }
        assert!(BeaconState::new().gen_committee_cache(RelativeEpoch::Current).is_err());
    }

    #[test]
    fn balance_helpers_saturate_and_reject_unknown_index() {
        let mut s = state_with_validators(2, 0);
        increase_balance(&mut s, 0, 5).unwrap();
        assert_eq!(s.get_balance(0).unwrap(), 32_000_000_005);
        decrease_balance(&mut s, 0, 10).unwrap();
        assert_eq!(s.get_balance(0).unwrap(), 31_999_999_995);

        // Decreasing below zero floors at zero.
        decrease_balance(&mut s, 1, u64::MAX).unwrap();
        assert_eq!(s.get_balance(1).unwrap(), 0);
        // Increasing past u64::MAX saturates.
        increase_balance(&mut s, 1, u64::MAX).unwrap();
        increase_balance(&mut s, 1, 1).unwrap();
        assert_eq!(s.get_balance(1).unwrap(), u64::MAX);

        assert!(increase_balance(&mut s, 2, 1).unwrap_err().to_string().contains("BalanceNotfound"));
        assert!(decrease_balance(&mut s, 2, 1).unwrap_err().to_string().contains("BalanceNotfound"));
    }

    #[test]
    fn compounding_credential_detection_uses_the_prefix_byte() {
        let spec = spec();
        let mut c = [0u8; 32];
        c[0] = 0x02;
        assert!(is_compounding_withdrawal_credential(B256::from(c), &spec));
        c[0] = 0x01;
        assert!(!is_compounding_withdrawal_credential(B256::from(c), &spec));
        c[0] = 0x00;
        assert!(!is_compounding_withdrawal_credential(B256::from(c), &spec));
    }

    #[test]
    fn base_reward_formula() {
        let mut spec = spec();
        let sqrt = SqrtTotalActiveBalance::new(1_000_000_000_000_000_000);
        assert_eq!(sqrt.as_u64(), 1_000_000_000);
        assert_eq!(get_base_reward(32_000_000_000, sqrt, &spec).unwrap(), 32);

        spec.base_reward_factor = 3;
        spec.base_rewards_per_epoch = 2;
        assert_eq!(get_base_reward(32_000_000_000, sqrt, &spec).unwrap(), 48);

        // Zero divisors are errors, not panics.
        assert!(get_base_reward(1, SqrtTotalActiveBalance::new(0), &spec).is_err());
        spec.base_rewards_per_epoch = 0;
        assert!(get_base_reward(1, sqrt, &spec).is_err());
        // Multiplication overflow is an error.
        spec.base_rewards_per_epoch = 1;
        spec.base_reward_factor = u64::MAX;
        assert!(get_base_reward(2, sqrt, &spec).is_err());
    }

    #[test]
    fn delta_arithmetic_and_flatten() {
        let mut d = Delta::default();
        d.reward(10).unwrap();
        d.penalize(4).unwrap();
        d.combine(Delta { rewards: 5, penalties: 1 }).unwrap();
        assert_eq!((d.rewards, d.penalties), (15, 5));

        assert!(d.reward(u64::MAX).is_err());
        assert!(d.penalize(u64::MAX).is_err());
        assert!(d.combine(Delta { rewards: u64::MAX, penalties: 0 }).is_err());

        let flat = AttestationDelta {
            all_delta: Delta { rewards: 3, penalties: 1 },
            inactivity_penalty_delta: Delta { rewards: 2, penalties: 8 },
        }
        .flatten()
        .unwrap();
        assert_eq!((flat.rewards, flat.penalties), (5, 9));

        let overflow = AttestationDelta {
            all_delta: Delta { rewards: u64::MAX, penalties: 0 },
            inactivity_penalty_delta: Delta { rewards: 1, penalties: 0 },
        };
        assert!(overflow.flatten().is_err());
    }

    #[test]
    fn attestation_component_delta_penalises_only_punishable_validators() {
        let spec = spec();
        let ok = get_attestation_component_delta_n42(1000, false, &spec).unwrap();
        assert_eq!((ok.rewards, ok.penalties), (1000, 0));
        let bad = get_attestation_component_delta_n42(1000, true, &spec).unwrap();
        assert_eq!((bad.rewards, bad.penalties), (1000, 3000));
    }

    #[test]
    fn inactivity_penalty_applies_after_the_grace_period() {
        let spec = spec();
        let attester = ValidatorStatus {
            is_previous_epoch_attester: true,
            current_epoch_effective_balance: 32_000_000_000,
            ..ValidatorStatus::default()
        };
        // Within min_epochs_to_inactivity_penalty (4): nothing.
        let d = get_inactivity_penalty_delta(&attester, 1000, 4, &spec).unwrap();
        assert_eq!((d.rewards, d.penalties), (0, 0));

        // Beyond it: base_rewards_per_epoch * base_reward - proposer reward (base/4) = 750.
        let d = get_inactivity_penalty_delta(&attester, 1000, 10, &spec).unwrap();
        assert_eq!(d.penalties, 750);

        // Non-attesters and slashed validators also pay effective_balance * delay / quotient.
        let extra = 32_000_000_000u64 * 10 / 67_108_864;
        let absent = ValidatorStatus { is_previous_epoch_attester: false, ..attester };
        assert_eq!(get_inactivity_penalty_delta(&absent, 1000, 10, &spec).unwrap().penalties, 750 + extra);
        let slashed = ValidatorStatus { is_slashed: true, ..attester };
        assert_eq!(get_inactivity_penalty_delta(&slashed, 1000, 10, &spec).unwrap().penalties, 750 + extra);
    }

    #[test]
    fn eligibility_includes_slashed_validators_until_withdrawable() {
        let spec = spec();
        let s = BeaconState::new();
        let active = active_validator(0, &spec);
        assert!(s.is_eligible_validator(5, &active).unwrap());

        let mut exited = active_validator(1, &spec);
        exited.exit_epoch = 3;
        exited.withdrawable_epoch = 10;
        assert!(!s.is_eligible_validator(5, &exited).unwrap());
        exited.slashed = true;
        // previous_epoch + 1 < withdrawable_epoch
        assert!(s.is_eligible_validator(5, &exited).unwrap());
        assert!(!s.is_eligible_validator(9, &exited).unwrap());
        assert!(s.is_eligible_validator(u64::MAX, &exited).is_err());
    }

    #[test]
    fn validator_statuses_summarise_the_registry() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);
        s.epoch_attester_indexes_set.insert(1);
        s.inactivity_scores_store.set(2, 2700).unwrap();
        let mut exited = active_validator(3, &spec);
        exited.exit_epoch = 1;
        s.validators_store.set(3, exited).unwrap();

        let vs = ValidatorStatuses::new(&s, &spec).unwrap();
        assert_eq!(vs.statuses.len(), 4);
        assert!(vs.statuses[1].is_previous_epoch_attester);
        assert!(!vs.statuses[0].is_previous_epoch_attester);
        assert!(vs.statuses[2].is_punishable);
        assert!(!vs.statuses[1].is_punishable);
        assert!(!vs.statuses[3].is_active_in_current_epoch);
        assert!(!vs.statuses[3].is_active_in_previous_epoch);
        assert!(vs.statuses[0].is_active_in_current_epoch && vs.statuses[0].is_active_in_previous_epoch);
        assert_eq!(vs.statuses[0].current_epoch_effective_balance, 32_000_000_000);
        // Three validators remain active.
        assert_eq!(vs.total_balances.current_epoch(), 96_000_000_000);
        assert_eq!(vs.total_balances.previous_epoch(), 96_000_000_000);

        // A registry without its inactivity scores is inconsistent.
        let mut broken = state_with_validators(2, 0);
        broken.inactivity_scores_store.clear();
        assert!(ValidatorStatuses::new(&broken, &spec).is_err());
    }

    #[test]
    fn rewards_and_penalties_are_skipped_in_the_genesis_epoch() {
        let spec = spec();
        let mut s = state_with_validators(4, 0);
        let vs = ValidatorStatuses::new(&s, &spec).unwrap();
        s.process_rewards_and_penalties(&vs, &spec).unwrap();
        for i in 0..4 {
            assert_eq!(s.get_balance(i).unwrap(), 32_000_000_000);
        }
    }

    #[test]
    fn rewards_pay_base_reward_and_punish_inactive_validators() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);
        s.inactivity_scores_store.set(2, 2700).unwrap();
        let vs = ValidatorStatuses::new(&s, &spec).unwrap();
        s.process_rewards_and_penalties(&vs, &spec).unwrap();

        // sqrt(4 * 32e9) = 357_770; base reward = 32e9 / 357_770.
        let base = 32_000_000_000u64 / 357_770;
        assert_eq!(base, 89_442);
        assert_eq!(s.get_balance(0).unwrap(), 32_000_000_000 + base);
        assert_eq!(s.get_balance(1).unwrap(), 32_000_000_000 + base);
        // Punishable: reward base, then lose 3 * base.
        assert_eq!(s.get_balance(2).unwrap(), 32_000_000_000 + base - 3 * base);
    }

    #[test]
    fn rewards_reject_statuses_that_do_not_match_the_registry() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);
        let mut vs = ValidatorStatuses::new(&s, &spec).unwrap();
        vs.statuses.pop();
        let err = s.process_rewards_and_penalties(&vs, &spec).unwrap_err();
        assert!(err.to_string().contains("ValidatorStatusesInconsistent"));
    }

    #[test]
    fn ineligible_validators_get_no_delta() {
        let spec = spec();
        let s = state_with_validators(2, 64);
        let mut vs = ValidatorStatuses::new(&s, &spec).unwrap();
        vs.statuses[0].is_eligible = false;
        let deltas = s
            .get_attestation_deltas_all(&vs, ProposerRewardCalculation::Exclude, &spec)
            .unwrap();
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas[0].clone().flatten().unwrap().rewards, 0);
        assert!(deltas[1].clone().flatten().unwrap().rewards > 0);
    }

    #[test]
    fn total_balances_never_drop_below_one_increment() {
        let spec = spec();
        let tb = TotalBalances::new(&spec);
        assert_eq!(tb.current_epoch(), 1_000_000_000);
        let vs = ValidatorStatuses::new(&BeaconState::new(), &spec).unwrap();
        assert!(vs.statuses.is_empty());
        assert_eq!(vs.total_balances.previous_epoch_attesters(), 1_000_000_000);
    }

    #[test]
    fn validator_status_update_never_clears_flags() {
        let mut a = ValidatorStatus { is_slashed: true, ..ValidatorStatus::default() };
        let b = ValidatorStatus {
            is_previous_epoch_attester: true,
            is_current_epoch_attester: true,
            is_active_in_previous_epoch: true,
            ..ValidatorStatus::default()
        };
        a.update(&b);
        assert!(a.is_slashed, "update must not clear an already-set flag");
        assert!(a.is_previous_epoch_attester && a.is_current_epoch_attester);
        assert!(a.is_active_in_previous_epoch);
        assert!(!a.is_eligible);
    }
}

#[cfg(test)]
mod deposits_and_exits {
    use super::*;
    use crate::test_util::{active_validator, eth1_credentials, pubkey, secret_key, state_with_validators};
    use alloy_primitives::LogData;

    fn spec() -> ChainSpec {
        beacon_chain_spec()
    }

    fn signed_deposit(i: usize, amount: u64) -> DepositData {
        let mut d = DepositData {
            pubkey: pubkey(i),
            withdrawal_credentials: eth1_credentials(i as u8 + 1),
            amount,
            signature: FixedBytes::ZERO,
        };
        d.signature = d.create_signature(&secret_key(i));
        d
    }

    #[test]
    fn deposit_signature_verifies_only_for_the_signed_content() {
        let d = signed_deposit(0, 32_000_000_000);
        assert!(d.verify_signature());

        let mut tampered = d.clone();
        tampered.amount += 1;
        assert!(!tampered.verify_signature());

        let mut other_creds = d.clone();
        other_creds.withdrawal_credentials = eth1_credentials(0x77);
        assert!(!other_creds.verify_signature());

        // A signature made by a different key does not verify for this pubkey.
        let mut wrong_key = d.clone();
        wrong_key.signature = d.create_signature(&secret_key(1));
        assert!(!wrong_key.verify_signature());
    }

    #[test]
    fn deposit_verification_rejects_unparseable_inputs() {
        let d = signed_deposit(0, 32_000_000_000);
        let mut bad_sig = d.clone();
        bad_sig.signature = FixedBytes::ZERO;
        assert!(!bad_sig.verify_signature());
        let mut bad_pk = d;
        bad_pk.pubkey = FixedBytes::ZERO;
        assert!(!bad_pk.verify_signature());
    }

    #[test]
    fn deposit_message_mirrors_the_deposit_and_signs_over_the_domain() {
        let d = signed_deposit(2, 5);
        let m = d.as_deposit_message();
        assert_eq!((m.pubkey, m.withdrawal_credentials, m.amount), (d.pubkey, d.withdrawal_credentials, 5));

        let domain = Hash256::repeat_byte(3);
        let expected = SigningData { object_root: m.tree_hash_root(), domain }.tree_hash_root();
        assert_eq!(m.signing_root(domain), expected);
        assert_ne!(m.signing_root(Hash256::repeat_byte(4)), expected);

        // The amount is a quoted decimal string in JSON, as the deposit tooling expects.
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["amount"], serde_json::json!("5"));
    }

    fn deposit_log(topic: B256, data: Bytes) -> Log {
        Log {
            address: Address::ZERO,
            data: LogData::new(vec![topic], data).unwrap(),
        }
    }

    #[test]
    fn deposit_log_parsing() {
        let ev = DepositEvent {
            pubkey: Bytes::from(vec![1u8; 48]),
            withdrawal_credentials: Bytes::from(vec![2u8; 32]),
            amount: Bytes::from(vec![3u8; 8]),
            signature: Bytes::from(vec![4u8; 96]),
            index: Bytes::from(vec![5u8; 8]),
        };
        let log = Log { address: Address::repeat_byte(1), data: ev.encode_log_data() };
        let parsed = parse_deposit_log(&log).unwrap();
        assert_eq!(parsed.pubkey, ev.pubkey);
        assert_eq!(parsed.withdrawal_credentials, ev.withdrawal_credentials);
        assert_eq!(parsed.amount, ev.amount);
        assert_eq!(parsed.signature, ev.signature);
        assert_eq!(parsed.index, ev.index);

        // Unknown topic, no topics, and a right topic with undecodable data all yield None.
        let topic = keccak256(b"DepositEvent(bytes,bytes,bytes,bytes,bytes)");
        assert!(parse_deposit_log(&deposit_log(B256::repeat_byte(9), Bytes::new())).is_none());
        assert!(parse_deposit_log(&Log { address: Address::ZERO, data: LogData::new(vec![], Bytes::new()).unwrap() }).is_none());
        assert!(parse_deposit_log(&deposit_log(topic, Bytes::from(vec![1, 2, 3]))).is_none());
    }

    #[test]
    fn add_validator_to_registry_appends_to_all_three_stores() {
        let spec = spec();
        let mut s = state_with_validators(2, 0);
        let idx = s.add_validator_to_registry(pubkey(9), eth1_credentials(9), 32_500_000_000, &spec).unwrap();
        assert_eq!(idx, 2);
        assert_eq!(s.validators_store.len(), 3);
        assert_eq!(s.balances_store.len(), 3);
        assert_eq!(s.inactivity_scores_store.len(), 3);
        assert_eq!(s.get_balance(2).unwrap(), 32_500_000_000);
        assert_eq!(s.get_inactivity_score(2).unwrap(), 0);

        let v = s.get_validator(2).unwrap();
        // Effective balance is rounded down to the increment and capped at the maximum.
        assert_eq!(v.effective_balance, 32_000_000_000);
        assert_eq!(v.activation_epoch, spec.far_future_epoch);
        assert_eq!(v.activation_eligibility_epoch, spec.far_future_epoch);
        assert_eq!(v.exit_epoch, spec.far_future_epoch);

        let idx = s.add_validator_to_registry(pubkey(10), eth1_credentials(1), 20_700_000_000, &spec).unwrap();
        assert_eq!(s.get_validator(idx).unwrap().effective_balance, 20_000_000_000);
    }

    #[test]
    fn apply_deposit_creates_or_tops_up() {
        let spec = spec();
        let mut s = state_with_validators(2, 0);

        // New pubkey: validator is created and the deposit index advances.
        s.apply_deposit(signed_deposit(5, 32_000_000_000), None, true, &spec).unwrap();
        assert_eq!(s.validators_store.len(), 3);
        assert_eq!(s.eth1_deposit_index, 1);
        assert_eq!(s.get_balance(2).unwrap(), 32_000_000_000);

        // Existing pubkey: balance is increased, the registry does not grow.
        s.apply_deposit(signed_deposit(1, 7), None, true, &spec).unwrap();
        assert_eq!(s.validators_store.len(), 3);
        assert_eq!(s.get_balance(1).unwrap(), 32_000_000_007);
        assert_eq!(s.eth1_deposit_index, 2);

        // The deposit index is only advanced when asked to.
        s.apply_deposit(signed_deposit(1, 1), None, false, &spec).unwrap();
        assert_eq!(s.eth1_deposit_index, 2);
    }

    #[test]
    fn process_deposits_applies_each_deposit_in_order() {
        let spec = spec();
        let mut s = BeaconState::new();
        let deposits: Vec<Deposit> = (0..3)
            .map(|i| Deposit { proof: vec![], data: signed_deposit(i, 32_000_000_000) })
            .chain(std::iter::once(Deposit { proof: vec![], data: signed_deposit(0, 1_000_000_000) }))
            .collect();
        s.process_deposits(&deposits, &spec).unwrap();
        assert_eq!(s.validators_store.len(), 3);
        assert_eq!(s.eth1_deposit_index, 4);
        assert_eq!(s.get_balance(0).unwrap(), 33_000_000_000);
        assert_eq!(s.get_validator(1).unwrap().pubkey, pubkey(1));
    }

    fn exit(validator_index: u64, epoch: Epoch) -> VoluntaryExitWithSig {
        VoluntaryExitWithSig {
            voluntary_exit: VoluntaryExit { epoch, validator_index },
            signature: Bytes::new(),
        }
    }

    #[test]
    fn verify_exit_accepts_a_mature_active_validator() {
        let spec = spec();
        // Epoch 2, shard_committee_period 1, activation epoch 0.
        let mut s = state_with_validators(2, 64);
        s.verify_exit(None, &exit(0, 2), &spec).unwrap();
        // Explicit epoch overrides the state's own.
        s.verify_exit(Some(5), &exit(0, 5), &spec).unwrap();
    }

    #[test]
    fn verify_exit_rejects_each_invalid_case() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);

        let err = s.verify_exit(None, &exit(9, 0), &spec).unwrap_err().to_string();
        assert!(err.contains("ValidatorUnknown"), "{err}");

        // Not active: activation is in the future.
        let mut inactive = active_validator(1, &spec);
        inactive.activation_epoch = 10;
        s.validators_store.set(1, inactive).unwrap();
        let err = s.verify_exit(None, &exit(1, 0), &spec).unwrap_err().to_string();
        assert!(err.contains("NotActive(1)"), "{err}");

        // Active, but an exit has already been scheduled.
        let mut exiting = active_validator(2, &spec);
        exiting.exit_epoch = 100;
        s.validators_store.set(2, exiting).unwrap();
        let err = s.verify_exit(None, &exit(2, 0), &spec).unwrap_err().to_string();
        assert!(err.contains("AlreadyExited(2)"), "{err}");

        // The exit names an epoch that has not arrived.
        let err = s.verify_exit(None, &exit(0, 3), &spec).unwrap_err().to_string();
        assert!(err.contains("FutureEpoch"), "{err}");

        // Too young: needs activation_epoch + shard_committee_period.
        let mut young = state_with_validators(1, 0);
        let err = young.verify_exit(None, &exit(0, 0), &spec).unwrap_err().to_string();
        assert!(err.contains("TooYoungToExit"), "{err}");

        // Pending partial withdrawals block a voluntary exit.
        s.pending_partial_withdrawals.push(PendingPartialWithdrawal {
            validator_index: 3,
            amount: 1,
            withdrawable_epoch: 0,
        });
        let err = s.verify_exit(None, &exit(3, 0), &spec).unwrap_err().to_string();
        assert!(err.contains("PendingWithdrawalInQueue(3)"), "{err}");
    }

    #[test]
    fn process_exits_schedules_exits_and_reports_the_failing_index() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);
        s.process_exits(&[exit(0, 2), exit(1, 2)], &spec).unwrap();
        assert_eq!(s.get_validator(0).unwrap().exit_epoch, 2 + 1 + 4);
        assert_eq!(s.get_validator(1).unwrap().exit_epoch, 7);
        assert_eq!(s.get_validator(2).unwrap().exit_epoch, spec.far_future_epoch);

        // The same validator cannot exit twice; the error names the offending position.
        let err = s.process_exits(&[exit(2, 2), exit(0, 2)], &spec).unwrap_err().to_string();
        assert!(err.contains("index 1"), "{err}");
        // Earlier exits in the batch were already applied.
        assert_ne!(s.get_validator(2).unwrap().exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn exit_invalid_variants_compare_by_value() {
        assert_eq!(ExitInvalid::NotActive(1), ExitInvalid::NotActive(1));
        assert_ne!(
            ExitInvalid::FutureEpoch { state: 1, exit: 2 },
            ExitInvalid::FutureEpoch { state: 1, exit: 3 }
        );
    }
}

#[cfg(test)]
mod attestations_and_withdrawals {
    use super::*;
    use crate::test_util::{active_validator, eth1_credentials, pubkey, secret_key, state_with_validators};

    fn spec() -> ChainSpec {
        beacon_chain_spec()
    }

    fn data(slot: u64) -> AttestationData {
        AttestationData { slot, committee_index: 0, receipts_root: B256::repeat_byte(slot as u8) }
    }

    /// An attestation signed by `indices` over the JSON encoding of `data`.
    fn attestation(indices: &[u64], data: AttestationData) -> Attestation {
        let msg = serde_json::to_vec(&data).unwrap();
        let mut agg: Option<AggregateSignature> = None;
        for &i in indices {
            let sig = secret_key(i as usize).sign(&msg, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[]);
            match agg.as_mut() {
                Some(a) => a.add_signature(&sig, true).unwrap(),
                None => agg = Some(AggregateSignature::from_signature(&sig)),
            }
        }
        Attestation {
            validator_indexes: indices.iter().copied().collect(),
            data,
            block_aggregate_signature: agg.map(|a| agg_sig_to_fixed(&a)),
        }
    }

    #[test]
    fn aggregate_signature_roundtrips_and_rejects_garbage() {
        let a = attestation(&[0], data(1));
        let bytes = a.block_aggregate_signature.unwrap();
        let sig = fixed_to_agg_sig(&bytes).unwrap();
        assert_eq!(agg_sig_to_fixed(&sig), bytes);
        assert!(fixed_to_agg_sig(&FixedBytes::<96>::repeat_byte(0xff)).is_err());
    }

    #[test]
    fn pubkey_cache_parses_once_and_rejects_invalid_keys() {
        let pk = pubkey(40);
        let first = get_cached_pubkey(&pk).unwrap();
        let second = get_cached_pubkey(&pk).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(first.to_bytes().as_slice(), pk.as_slice());
        assert!(get_cached_pubkey(&FixedBytes::<48>::repeat_byte(0xff)).is_err());
    }

    #[test]
    fn verify_aggregate_signature_accepts_valid_and_rejects_bad_attestations() {
        let s = state_with_validators(4, 0);
        s.verify_aggregate_signature(&attestation(&[0, 1, 2], data(5))).unwrap();

        // Missing signature.
        let mut missing = attestation(&[0], data(5));
        missing.block_aggregate_signature = None;
        let err = s.verify_aggregate_signature(&missing).unwrap_err().to_string();
        assert!(err.contains("aggregate signature is empty"), "{err}");

        // Signature over different data.
        let mut forged = attestation(&[0, 1], data(5));
        forged.data = data(6);
        let err = s.verify_aggregate_signature(&forged).unwrap_err().to_string();
        assert!(err.contains("failed"), "{err}");

        // Claimed signers differ from actual signers.
        let mut wrong_set = attestation(&[0, 1], data(5));
        wrong_set.validator_indexes = [0u64, 2].into_iter().collect();
        assert!(s.verify_aggregate_signature(&wrong_set).is_err());

        // Unknown validator index.
        let mut unknown = attestation(&[0], data(5));
        unknown.validator_indexes.insert(77);
        assert!(s.verify_aggregate_signature(&unknown).unwrap_err().to_string().contains("UnknownValidator"));

        // Undecodable signature bytes.
        let mut garbage = attestation(&[0], data(5));
        garbage.block_aggregate_signature = Some(FixedBytes::<96>::repeat_byte(0xff));
        assert!(s.verify_aggregate_signature(&garbage).is_err());
    }

    #[test]
    fn verify_aggregate_signature_rejects_a_validator_with_an_invalid_pubkey() {
        let mut s = state_with_validators(2, 0);
        let mut v = active_validator(0, &spec());
        v.pubkey = FixedBytes::<48>::repeat_byte(0xff);
        s.validators_store.set(0, v).unwrap();
        let err = s.verify_aggregate_signature(&attestation(&[0], data(1))).unwrap_err().to_string();
        assert!(err.contains("PublicKey::from_bytes"), "{err}");
    }

    #[test]
    fn batch_verification_paths() {
        let s = state_with_validators(6, 0);
        // Empty and small batches.
        s.verify_attestations_batch(&[]).unwrap();
        s.verify_attestations_batch(&[attestation(&[0], data(1)), attestation(&[1, 2], data(2))]).unwrap();
        let mut small_bad = vec![attestation(&[0], data(1)), attestation(&[1], data(2))];
        small_bad[1].data = data(3);
        assert!(s.verify_attestations_batch(&small_bad).is_err());

        // Four or more takes the batch path.
        let good: Vec<Attestation> = (0..5).map(|i| attestation(&[i], data(10 + i))).collect();
        s.verify_attestations_batch(&good).unwrap();

        let mut bad = good.clone();
        bad[2].data = data(99);
        let err = s.verify_attestations_batch(&bad).unwrap_err().to_string();
        assert!(err.contains("Batch verification failed at attestation 2"), "{err}");

        let mut missing = good.clone();
        missing[3].block_aggregate_signature = None;
        assert!(s.verify_attestations_batch(&missing).unwrap_err().to_string().contains("empty"));

        let mut unknown = good.clone();
        unknown[0].validator_indexes.insert(500);
        assert!(s.verify_attestations_batch(&unknown).is_err());

        let mut garbage = good;
        garbage[1].block_aggregate_signature = Some(FixedBytes::<96>::repeat_byte(0xff));
        assert!(s.verify_attestations_batch(&garbage).is_err());
    }

    #[test]
    fn process_randao_xors_signature_hashes_into_the_mix() {
        let spec = spec();
        let mut s = state_with_validators(3, 0);
        s.randao_mix = B256::repeat_byte(0x11);
        let a = attestation(&[0], data(1));
        let b = attestation(&[1, 2], data(2));
        let expected = B256::repeat_byte(0x11)
            ^ keccak256(a.block_aggregate_signature.unwrap())
            ^ keccak256(b.block_aggregate_signature.unwrap());

        let body = BeaconBlockBody { attestations: vec![a.clone(), b], ..Default::default() };
        s.process_randao(&body, &spec).unwrap();
        assert_eq!(s.randao_mix, expected);

        // No attestations: the mix is unchanged.
        let before = s.randao_mix;
        s.process_randao(&BeaconBlockBody::default(), &spec).unwrap();
        assert_eq!(s.randao_mix, before);

        // An invalid attestation aborts before the mix is touched.
        let mut bad = a;
        bad.data = data(9);
        let body = BeaconBlockBody { attestations: vec![bad], ..Default::default() };
        assert!(s.process_randao(&body, &spec).is_err());
        assert_eq!(s.randao_mix, before);
    }

    #[test]
    fn process_attestation_records_attesters_only_for_valid_signatures() {
        let mut s = state_with_validators(4, 0);
        s.process_attestation(&vec![attestation(&[0, 2], data(1)), attestation(&[3], data(2))]).unwrap();
        assert_eq!(s.epoch_attester_indexes_store.len(), 3);
        let recorded: Vec<u64> = s.epoch_attester_indexes_store.iter().copied().collect();
        assert_eq!(recorded, vec![0, 2, 3]);

        let mut bad = attestation(&[1], data(3));
        bad.data = data(4);
        assert!(s.process_one_attestation(&bad).is_err());
        assert_eq!(s.epoch_attester_indexes_store.len(), 3);
    }

    fn pending(validator_index: u64, amount: u64, withdrawable_epoch: Epoch) -> PendingPartialWithdrawal {
        PendingPartialWithdrawal { validator_index, amount, withdrawable_epoch }
    }

    fn request(i: usize, amount: u64) -> WithdrawalRequest {
        WithdrawalRequest {
            source_address: Address::repeat_byte(i as u8 + 1),
            validator_pubkey: pubkey(i),
            amount,
        }
    }

    fn compounding(i: usize) -> Validator {
        let mut v = active_validator(i, &spec());
        let mut c = [0u8; 32];
        c[0] = 0x02;
        c[12..].fill(i as u8 + 1);
        v.withdrawal_credentials = B256::from(c);
        v
    }

    #[test]
    fn full_exit_request_exits_a_mature_validator() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);
        s.process_withdrawal_requests(&[request(1, 0)], &spec).unwrap();
        assert_eq!(s.get_validator(1).unwrap().exit_epoch, 7);
        assert_eq!(s.get_validator(0).unwrap().exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn withdrawal_requests_that_fail_validation_are_skipped() {
        let spec = spec();
        let far = spec.far_future_epoch;
        let mut s = state_with_validators(6, 64);

        // 1: wrong source address.
        let mut wrong_addr = request(1, 0);
        wrong_addr.source_address = Address::repeat_byte(0xee);
        // 2: unknown pubkey.
        let mut unknown = request(2, 0);
        unknown.validator_pubkey = FixedBytes::repeat_byte(0xab);
        // 3: no execution credential prefix.
        let mut no_cred = active_validator(3, &spec);
        no_cred.withdrawal_credentials = B256::ZERO;
        s.validators_store.set(3, no_cred).unwrap();
        // 4: not yet activated.
        let mut inactive = active_validator(4, &spec);
        inactive.activation_epoch = 50;
        s.validators_store.set(4, inactive).unwrap();
        // 5: exit already scheduled.
        let mut exiting = active_validator(5, &spec);
        exiting.exit_epoch = 100;
        s.validators_store.set(5, exiting).unwrap();

        s.process_withdrawal_requests(
            &[wrong_addr, unknown, request(3, 0), request(4, 0), request(5, 0)],
            &spec,
        )
        .unwrap();
        assert_eq!(s.get_validator(1).unwrap().exit_epoch, far);
        assert_eq!(s.get_validator(3).unwrap().exit_epoch, far);
        assert_eq!(s.get_validator(4).unwrap().exit_epoch, far);
        assert_eq!(s.get_validator(5).unwrap().exit_epoch, 100);
        assert!(s.pending_partial_withdrawals.is_empty());
    }

    #[test]
    fn withdrawal_request_for_a_too_young_validator_is_skipped() {
        let spec = spec();
        // Epoch 0 < activation 0 + shard_committee_period 1.
        let mut s = state_with_validators(2, 0);
        s.process_withdrawal_requests(&[request(0, 0)], &spec).unwrap();
        assert_eq!(s.get_validator(0).unwrap().exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn full_exit_is_blocked_by_a_pending_partial_withdrawal() {
        let spec = spec();
        let mut s = state_with_validators(2, 64);
        s.pending_partial_withdrawals.push(pending(0, 5, 100));
        s.process_withdrawal_requests(&[request(0, 0)], &spec).unwrap();
        assert_eq!(s.get_validator(0).unwrap().exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn partial_withdrawal_requires_compounding_credentials() {
        let spec = spec();
        let mut s = state_with_validators(2, 64);
        s.balances_store.set(0, 40_000_000_000).unwrap();
        s.process_withdrawal_requests(&[request(0, 5_000_000_000)], &spec).unwrap();
        assert!(s.pending_partial_withdrawals.is_empty());
    }

    #[test]
    fn partial_withdrawals_queue_up_to_the_excess_balance() {
        let spec = spec();
        let mut s = state_with_validators(2, 64);
        s.validators_store.set(0, compounding(0)).unwrap();
        s.balances_store.set(0, 40_000_000_000).unwrap();

        s.process_withdrawal_requests(&[request(0, 5_000_000_000)], &spec).unwrap();
        assert_eq!(s.pending_partial_withdrawals, vec![pending(0, 5_000_000_000, 8)]);
        assert_eq!(s.earliest_exit_epoch, 7);
        assert_eq!(s.exit_balance_to_consume, 128_000_000_000 - 5_000_000_000);

        // Only the 3 ETH not already pending can still be withdrawn.
        s.process_withdrawal_requests(&[request(0, 100_000_000_000)], &spec).unwrap();
        assert_eq!(s.pending_partial_withdrawals.len(), 2);
        assert_eq!(s.pending_partial_withdrawals[1].amount, 3_000_000_000);

        // Nothing excess is left, so a further request is ignored.
        s.process_withdrawal_requests(&[request(0, 1)], &spec).unwrap();
        assert_eq!(s.pending_partial_withdrawals.len(), 2);
    }

    #[test]
    fn a_full_partial_queue_only_admits_full_exits() {
        let spec = spec();
        let mut s = state_with_validators(3, 64);
        s.validators_store.set(0, compounding(0)).unwrap();
        s.balances_store.set(0, 40_000_000_000).unwrap();
        for _ in 0..pending_partial_withdrawals_limit {
            s.pending_partial_withdrawals.push(pending(2, 1, 100));
        }

        s.process_withdrawal_requests(&[request(0, 1_000_000_000), request(1, 0)], &spec).unwrap();
        assert_eq!(s.pending_partial_withdrawals.len(), pending_partial_withdrawals_limit);
        assert_eq!(s.get_validator(1).unwrap().exit_epoch, 7);
        assert_eq!(s.get_validator(0).unwrap().exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn expected_withdrawals_cover_full_and_sweep_partial_cases() {
        let spec = spec();
        let mut s = state_with_validators(4, 64);
        // Validator 1: fully withdrawable (withdrawable epoch passed, balance > 0).
        let mut done = active_validator(1, &spec);
        done.exit_epoch = 1;
        done.withdrawable_epoch = 1;
        s.validators_store.set(1, done).unwrap();
        // Validator 2: effective balance at max and 1 ETH of excess.
        s.balances_store.set(2, 33_000_000_000).unwrap();
        // Validator 3: fully withdrawable but zero balance, so skipped.
        let mut empty = active_validator(3, &spec);
        empty.withdrawable_epoch = 0;
        s.validators_store.set(3, empty).unwrap();
        s.balances_store.set(3, 0).unwrap();

        let (w, processed) = s.get_expected_withdrawals(&spec).unwrap();
        assert_eq!(processed, Some(0));
        assert_eq!(w.len(), 2);
        assert_eq!((w[0].index, w[0].validator_index, w[0].amount), (0, 1, 32_000_000_000));
        assert_eq!(w[0].address, Address::repeat_byte(2));
        assert_eq!((w[1].index, w[1].validator_index, w[1].amount), (1, 2, 1_000_000_000));
        assert_eq!(w[1].address, Address::repeat_byte(3));
    }

    #[test]
    fn expected_withdrawals_start_at_the_stored_indices() {
        let spec = spec();
        let mut s = state_with_validators(3, 64);
        s.balances_store.set(0, 33_000_000_000).unwrap();
        s.balances_store.set(2, 34_000_000_000).unwrap();
        s.next_withdrawal_index = 10;
        s.next_withdrawal_validator_index = 2;
        let (w, _) = s.get_expected_withdrawals(&spec).unwrap();
        // The sweep starts at validator 2 and wraps around to validator 0.
        assert_eq!(w.iter().map(|x| (x.index, x.validator_index)).collect::<Vec<_>>(), vec![(10, 2), (11, 0)]);

        s.next_withdrawal_validator_index = 3;
        assert!(s.get_expected_withdrawals(&spec).is_err());
    }

    #[test]
    fn expected_withdrawals_include_ripe_pending_partials() {
        let spec = spec();
        let mut s = state_with_validators(3, 64);
        s.balances_store.set(0, 40_000_000_000).unwrap();
        s.pending_partial_withdrawals = vec![
            pending(0, 5_000_000_000, 2),
            // Not yet withdrawable: processing stops here.
            pending(0, 1, 3),
        ];
        let (w, processed) = s.get_expected_withdrawals(&spec).unwrap();
        assert_eq!(processed, Some(1));
        // The pending 5 ETH, then the sweep pays the 3 ETH still above the 32 ETH cap.
        assert_eq!(w.len(), 2);
        assert_eq!((w[0].index, w[0].validator_index, w[0].amount), (0, 0, 5_000_000_000));
        assert_eq!((w[1].index, w[1].validator_index, w[1].amount), (1, 0, 3_000_000_000));

        // A partial for a validator with no excess balance is consumed without paying out.
        s.balances_store.set(0, 32_000_000_000).unwrap();
        let (w, processed) = s.get_expected_withdrawals(&spec).unwrap();
        assert!(w.is_empty());
        assert_eq!(processed, Some(1));

        // A pending entry naming a missing validator is an error.
        s.pending_partial_withdrawals = vec![pending(99, 1, 0)];
        assert!(s.get_expected_withdrawals(&spec).is_err());
    }

    #[test]
    fn expected_withdrawals_are_capped_per_payload() {
        let spec = spec();
        let mut s = state_with_validators(20, 64);
        for i in 0..20 {
            let mut v = active_validator(i, &spec);
            v.withdrawable_epoch = 0;
            s.validators_store.set(i, v).unwrap();
        }
        let (w, _) = s.get_expected_withdrawals(&spec).unwrap();
        assert_eq!(w.len(), max_withdrawals_per_payload);
        assert_eq!(w.last().unwrap().validator_index, 15);
    }

    #[test]
    fn process_withdrawals_debits_balances_and_advances_the_sweep() {
        let spec = spec();
        let mut s = state_with_validators(20, 64);
        for i in 0..20 {
            let mut v = active_validator(i, &spec);
            v.withdrawable_epoch = 0;
            s.validators_store.set(i, v).unwrap();
        }
        s.pending_partial_withdrawals.push(pending(0, 1, 3));

        let (w, processed) = s.process_withdrawals().unwrap();
        assert_eq!(w.len(), 16);
        assert_eq!(processed, Some(0));
        for i in 0..16 {
            assert_eq!(s.get_balance(i).unwrap(), 0);
        }
        assert_eq!(s.get_balance(16).unwrap(), 32_000_000_000);
        assert_eq!(s.next_withdrawal_index, 16);
        // A full payload resumes after the last paid validator.
        assert_eq!(s.next_withdrawal_validator_index, 16);
        assert_eq!(s.pending_partial_withdrawals.len(), 1);

        // Next block: the remaining four are paid, a short payload advances the sweep by the
        // sweep size modulo the registry length.
        let (w, _) = s.process_withdrawals().unwrap();
        assert_eq!(w.len(), 4);
        assert_eq!(s.next_withdrawal_index, 20);
        assert_eq!(s.next_withdrawal_validator_index, (16 + 16384) % 20);
    }

    #[test]
    fn process_withdrawals_drains_processed_partials_and_handles_empty_registries() {
        let mut s = state_with_validators(5, 64);
        s.balances_store.set(0, 40_000_000_000).unwrap();
        s.pending_partial_withdrawals = vec![pending(0, 2_000_000_000, 1), pending(0, 1, 9)];
        let (w, processed) = s.process_withdrawals().unwrap();
        // 2 ETH pending payout plus the 6 ETH the sweep finds above the cap afterwards.
        assert_eq!((w.len(), processed), (2, Some(1)));
        assert_eq!((w[0].amount, w[1].amount), (2_000_000_000, 6_000_000_000));
        assert_eq!(s.get_balance(0).unwrap(), 32_000_000_000);
        assert_eq!(s.pending_partial_withdrawals, vec![pending(0, 1, 9)]);
        assert_eq!(s.next_withdrawal_index, 2);
        // 16384 % 5 == 4
        assert_eq!(s.next_withdrawal_validator_index, 4);

        let mut empty = BeaconState::new();
        let (w, processed) = empty.process_withdrawals().unwrap();
        assert!(w.is_empty());
        assert_eq!(processed, Some(0));
        assert_eq!(empty.next_withdrawal_validator_index, 0);
    }

    #[test]
    fn process_operations_applies_deposits_exits_and_withdrawal_requests() {
        use alloy_eips::eip6110::DepositRequest as ElDepositRequest;
        let spec = spec();
        let mut s = state_with_validators(3, 64);
        let body = BeaconBlockBody {
            attestations: vec![attestation(&[0], data(1))],
            deposits: vec![],
            voluntary_exits: vec![VoluntaryExitWithSig {
                voluntary_exit: VoluntaryExit { epoch: 2, validator_index: 1 },
                signature: Bytes::new(),
            }],
            execution_requests: ExecutionRequestsV4 {
                deposits: vec![ElDepositRequest {
                    pubkey: pubkey(30),
                    withdrawal_credentials: eth1_credentials(30),
                    amount: 32_000_000_000,
                    signature: FixedBytes::ZERO,
                    index: 0,
                }],
                withdrawals: vec![request(2, 0)],
                consolidations: vec![],
            },
        };
        s.process_operations(&body, &spec).unwrap();

        assert_eq!(s.epoch_attester_indexes_store.len(), 1);
        assert_eq!(s.validators_store.len(), 4);
        assert_eq!(s.get_validator(3).unwrap().pubkey, pubkey(30));
        assert_eq!(s.eth1_deposit_index, 1);
        assert_ne!(s.get_validator(1).unwrap().exit_epoch, spec.far_future_epoch);
        assert_ne!(s.get_validator(2).unwrap().exit_epoch, spec.far_future_epoch);
        assert_eq!(s.get_validator(0).unwrap().exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn process_operations_propagates_an_invalid_exit() {
        let spec = spec();
        let mut s = state_with_validators(2, 64);
        let body = BeaconBlockBody {
            voluntary_exits: vec![VoluntaryExitWithSig {
                voluntary_exit: VoluntaryExit { epoch: 50, validator_index: 0 },
                signature: Bytes::new(),
            }],
            ..Default::default()
        };
        assert!(s.process_operations(&body, &spec).unwrap_err().to_string().contains("FutureEpoch"));
    }
}

#[cfg(test)]
mod epoch_processing {
    use super::*;
    use crate::test_util::{active_validator, eth1_credentials, pubkey, state_with_validators};
    use ssz::Decode;

    fn spec() -> ChainSpec {
        beacon_chain_spec()
    }

    #[test]
    fn rounding_helpers() {
        assert_eq!(round_to_nearest(31_400_000_000, 1_000_000_000), 31_000_000_000);
        assert_eq!(round_to_nearest(31_500_000_000, 1_000_000_000), 32_000_000_000);
        assert_eq!(round_to_nearest(0, 1_000_000_000), 0);
        assert_eq!(round_down(31_999_999_999, 1_000_000_000), 31_000_000_000);
    }

    #[test]
    fn epoch_processing_rounds_effective_balances_and_ejects_low_validators() {
        let spec = spec();
        let mut s = state_with_validators(5, 0);
        s.balances_store.set(0, 31_400_000_000).unwrap();
        s.balances_store.set(1, 31_500_000_000).unwrap();
        // Balances above the cap are clamped to the maximum effective balance.
        s.balances_store.set(2, 45_000_000_000).unwrap();
        s.balances_store.set(3, 20_499_999_999).unwrap();
        s.balances_store.set(4, 15_600_000_000).unwrap();

        s.process_epoch(&spec).unwrap();

        let eff: Vec<u64> = (0..5).map(|i| s.get_effective_balance(i).unwrap()).collect();
        assert_eq!(
            eff,
            vec![31_000_000_000, 32_000_000_000, 32_000_000_000, 20_000_000_000, 16_000_000_000]
        );
        // Only the validator at the ejection balance is queued to exit.
        for i in 0..4 {
            assert_eq!(s.get_validator(i).unwrap().exit_epoch, spec.far_future_epoch, "validator {i}");
        }
        assert_eq!(s.get_validator(4).unwrap().exit_epoch, 5);
    }

    #[test]
    fn epoch_processing_updates_inactivity_scores() {
        let spec = spec();
        let mut s = state_with_validators(4, 0);
        for (i, score) in [(0usize, 100u64), (1, 0), (2, 8100), (3, 10)] {
            s.inactivity_scores_store.set(i, score).unwrap();
        }
        s.epoch_attester_indexes_set.insert(0);
        s.epoch_attester_indexes_set.insert(3);
        s.epoch_attester_indexes_store.push(0).unwrap();
        s.epoch_attester_indexes_store.push(3).unwrap();

        s.process_epoch(&spec).unwrap();

        // Attesters recover by 48 (floored at zero); absentees gain 1 until the 8100 cap.
        assert_eq!(s.get_inactivity_score(0).unwrap(), 52);
        assert_eq!(s.get_inactivity_score(1).unwrap(), 1);
        assert_eq!(s.get_inactivity_score(2).unwrap(), 8100);
        assert_eq!(s.get_inactivity_score(3).unwrap(), 0);
        // The attester records are consumed by the epoch.
        assert!(s.epoch_attester_indexes_set.is_empty());
        assert!(s.epoch_attester_indexes_store.is_empty());
    }

    #[test]
    fn epoch_processing_pays_rewards_after_genesis() {
        let spec = spec();
        let mut s = state_with_validators(4, 32);
        // One more absent epoch pushes validator 1 over the punishment threshold.
        s.inactivity_scores_store.set(1, 2699).unwrap();
        s.process_epoch(&spec).unwrap();

        let base = 32_000_000_000u64 / 357_770;
        assert_eq!(s.get_balance(0).unwrap(), 32_000_000_000 + base);
        assert_eq!(s.get_inactivity_score(1).unwrap(), 2700);
        assert_eq!(s.get_balance(1).unwrap(), 32_000_000_000 + base - 3 * base);
    }

    #[test]
    fn epoch_processing_reports_a_corrupt_registry() {
        let spec = spec();
        let mut s = state_with_validators(2, 0);
        s.validators_store.clear();
        assert!(s.process_epoch(&spec).is_err());

        let mut t = state_with_validators(2, 0);
        t.inactivity_scores_store.clear();
        assert!(t.process_epoch(&spec).is_err());
    }

    fn fresh_deposit(i: usize) -> Validator {
        Validator::from_deposit(pubkey(i), eth1_credentials(1), 32_000_000_000, &spec())
    }

    #[test]
    fn registry_updates_queue_then_activate_new_validators() {
        let spec = spec();
        let mut s = state_with_validators(2, 64);
        s.validators_store.push(fresh_deposit(2)).unwrap();
        s.balances_store.push(32_000_000_000).unwrap();
        s.inactivity_scores_store.push(0).unwrap();

        // Epoch 2: the validator becomes eligible for the queue, one epoch later.
        s.process_registry_updates(&spec).unwrap();
        let v = s.get_validator(2).unwrap().clone();
        assert_eq!(v.activation_eligibility_epoch, 3);
        assert_eq!(v.activation_epoch, spec.far_future_epoch);

        // Epoch 3: eligibility epoch has been reached, activation is delayed by the lookahead.
        s.slot = 96;
        s.process_registry_updates(&spec).unwrap();
        assert_eq!(s.get_validator(2).unwrap().activation_epoch, 3 + 1 + 4);
    }

    #[test]
    fn registry_updates_respect_the_activation_churn_limit() {
        let spec = spec();
        let mut s = state_with_validators(1, 64);
        for i in 1..=6 {
            let mut v = fresh_deposit(i);
            v.activation_eligibility_epoch = 1;
            s.validators_store.push(v).unwrap();
            s.balances_store.push(32_000_000_000).unwrap();
            s.inactivity_scores_store.push(0).unwrap();
        }
        s.process_registry_updates(&spec).unwrap();

        let activated: Vec<usize> = (1..=6)
            .filter(|&i| s.get_validator(i).unwrap().activation_epoch != spec.far_future_epoch)
            .collect();
        // min_per_epoch_churn_limit is 4; lowest indices go first.
        assert_eq!(activated, vec![1, 2, 3, 4]);
        assert_eq!(s.get_validator(1).unwrap().activation_epoch, 2 + 1 + 4);

        // Validators whose eligibility epoch is still in the future wait.
        let mut waiting = state_with_validators(1, 64);
        let mut v = fresh_deposit(1);
        v.activation_eligibility_epoch = 3;
        waiting.validators_store.push(v).unwrap();
        waiting.balances_store.push(32_000_000_000).unwrap();
        waiting.inactivity_scores_store.push(0).unwrap();
        waiting.process_registry_updates(&spec).unwrap();
        assert_eq!(waiting.get_validator(1).unwrap().activation_epoch, spec.far_future_epoch);
    }

    #[test]
    fn registry_updates_eject_active_validators_with_low_effective_balance() {
        let spec = spec();
        let mut s = state_with_validators(3, 64);
        let mut weak = active_validator(1, &spec);
        weak.effective_balance = 16_000_000_000;
        s.validators_store.set(1, weak).unwrap();
        s.process_registry_updates(&spec).unwrap();
        assert_eq!(s.get_validator(1).unwrap().exit_epoch, 2 + 1 + 4);
        assert_eq!(s.get_validator(0).unwrap().exit_epoch, spec.far_future_epoch);
    }

    #[test]
    fn state_transition_advances_the_slot_without_mutating_the_input() {
        let old = state_with_validators(4, 5);
        let new = BeaconState::state_transition(&old, &BeaconBlock::default()).unwrap();
        assert_eq!(new.slot, 6);
        assert_eq!(old.slot, 5);
        assert_eq!(new.validators_store.len(), 4);
    }

    #[test]
    fn state_transition_runs_epoch_processing_on_epoch_boundaries() {
        let mut old = state_with_validators(4, 31);
        old.balances_store.set(0, 31_400_000_000).unwrap();
        let new = BeaconState::state_transition(&old, &BeaconBlock::default()).unwrap();
        assert_eq!(new.slot, 32);
        assert_eq!(new.get_effective_balance(0).unwrap(), 31_000_000_000);
        assert_eq!(new.get_inactivity_score(0).unwrap(), 1);
        // The input state still has its original values.
        assert_eq!(old.get_effective_balance(0).unwrap(), 32_000_000_000);
        assert_eq!(old.get_inactivity_score(0).unwrap(), 0);

        // Not on a boundary: no epoch processing.
        let mid = state_with_validators(4, 10);
        let after = BeaconState::state_transition(&mid, &BeaconBlock::default()).unwrap();
        assert_eq!(after.get_inactivity_score(0).unwrap(), 0);

        // An empty registry survives an epoch boundary.
        let empty = BeaconState { slot: 31, ..BeaconState::new() };
        assert_eq!(BeaconState::state_transition(&empty, &BeaconBlock::default()).unwrap().slot, 32);
    }

    #[test]
    fn state_transition_applies_the_block_body() {
        use alloy_eips::eip6110::DepositRequest as ElDepositRequest;
        let old = state_with_validators(2, 3);
        let block = BeaconBlock {
            slot: 4,
            body: BeaconBlockBody {
                execution_requests: ExecutionRequestsV4 {
                    deposits: vec![ElDepositRequest {
                        pubkey: pubkey(20),
                        withdrawal_credentials: eth1_credentials(1),
                        amount: 32_000_000_000,
                        signature: FixedBytes::ZERO,
                        index: 0,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let new = BeaconState::state_transition(&old, &block).unwrap();
        assert_eq!(new.validators_store.len(), 3);
        assert_eq!(old.validators_store.len(), 2);
    }

    #[test]
    fn state_transition_rejects_blocks_with_bad_attestations() {
        let old = state_with_validators(2, 3);
        let mut bad = Attestation::default();
        bad.validator_indexes.insert(0);
        bad.block_aggregate_signature = Some(FixedBytes::<96>::repeat_byte(0xff));
        let block = BeaconBlock {
            body: BeaconBlockBody { attestations: vec![bad], ..Default::default() },
            ..Default::default()
        };
        assert!(BeaconState::state_transition(&old, &block).is_err());
    }

    #[test]
    fn state_hash_covers_persisted_fields() {
        let mut a = state_with_validators(2, 1);
        let h = a.hash_slow();
        assert_eq!(h, a.hash_slow());
        assert_eq!(h, keccak256(a.as_ssz_bytes()));
        a.slot = 2;
        assert_ne!(a.hash_slow(), h);
    }

    #[test]
    fn state_ssz_and_json_keep_roots_but_not_the_in_memory_stores() {
        let mut s = state_with_validators(3, 7);
        s.randao_mix = B256::repeat_byte(4);
        s.next_withdrawal_index = 9;
        s.pending_partial_withdrawals.push(PendingPartialWithdrawal {
            validator_index: 1,
            amount: 2,
            withdrawable_epoch: 3,
        });
        let back = BeaconState::from_ssz_bytes(&s.as_ssz_bytes()).unwrap();
        assert_eq!(back.slot, 7);
        assert_eq!(back.randao_mix, B256::repeat_byte(4));
        assert_eq!(back.next_withdrawal_index, 9);
        assert_eq!(back.pending_partial_withdrawals, s.pending_partial_withdrawals);
        assert_eq!(back.validators_len, s.validators_len);
        assert_eq!(back.validators, s.validators);
        assert_eq!(back.validators_store.len(), 0);

        let json = serde_json::to_string(&s).unwrap();
        let from_json: BeaconState = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json.slot, 7);
        assert_eq!(from_json.balances, s.balances);
    }

    fn sample_block() -> BeaconBlock {
        let spec = spec();
        let mut att = Attestation::default();
        att.validator_indexes.extend([1u64, 5]);
        att.data = AttestationData { slot: 3, committee_index: 1, receipts_root: B256::repeat_byte(2) };
        att.block_aggregate_signature = Some(FixedBytes::<96>::repeat_byte(7));
        BeaconBlock {
            slot: 12,
            eth1_block_hash: B256::repeat_byte(1),
            parent_hash: B256::repeat_byte(2),
            state_root: B256::repeat_byte(3),
            body: BeaconBlockBody {
                attestations: vec![att],
                deposits: vec![Deposit {
                    proof: vec![B256::repeat_byte(9)],
                    data: DepositData {
                        pubkey: pubkey(1),
                        withdrawal_credentials: eth1_credentials(1),
                        amount: spec.min_activation_balance,
                        signature: FixedBytes::repeat_byte(5),
                    },
                }],
                voluntary_exits: vec![VoluntaryExitWithSig {
                    voluntary_exit: VoluntaryExit { epoch: 4, validator_index: 2 },
                    signature: Bytes::from(vec![1, 2, 3]),
                }],
                execution_requests: ExecutionRequestsV4::default(),
            },
        }
    }

    #[test]
    fn block_ssz_json_and_hash_roundtrip() {
        let block = sample_block();
        let bytes = block.as_ssz_bytes();
        assert_eq!(BeaconBlock::from_ssz_bytes(&bytes).unwrap(), block);
        assert!(BeaconBlock::from_ssz_bytes(&bytes[..bytes.len() - 3]).is_err());

        let json = serde_json::to_string(&block).unwrap();
        assert_eq!(serde_json::from_str::<BeaconBlock>(&json).unwrap(), block);

        assert_eq!(block.hash_slow(), keccak256(&bytes));
        let mut other = block.clone();
        other.body.voluntary_exits[0].voluntary_exit.epoch = 5;
        assert_ne!(other.hash_slow(), block.hash_slow());
    }

    #[test]
    fn auxiliary_types_roundtrip_through_ssz() {
        let agg = BlockVerifyResultAggregate {
            validator_indexes: [3u64, 1, 2].into_iter().collect(),
            block_aggregate_signature: Some(FixedBytes::repeat_byte(8)),
        };
        assert_eq!(BlockVerifyResultAggregate::from_ssz_bytes(&agg.as_ssz_bytes()).unwrap(), agg);

        let reqs = ExecutionRequests {
            deposits: vec![DepositRequest {
                pubkey: Bytes::from(vec![1; 48]),
                withdrawal_credentials: B256::repeat_byte(2),
                amount: 3,
                signature: Bytes::from(vec![4; 96]),
                index: 5,
            }],
            withdrawals: vec![],
            consolidations: vec![ConsolidationRequest {
                source_address: Address::repeat_byte(6),
                source_pubkey: Bytes::from(vec![7; 48]),
                target_pubkey: Bytes::from(vec![8; 48]),
            }],
        };
        assert_eq!(ExecutionRequests::from_ssz_bytes(&reqs.as_ssz_bytes()).unwrap(), reqs);

        let eth1 = Eth1Data { deposit_root: B256::repeat_byte(1), deposit_count: 2, block_hash: B256::repeat_byte(3) };
        assert_eq!(Eth1Data::from_ssz_bytes(&eth1.as_ssz_bytes()).unwrap(), eth1);

        let signing = SigningData { object_root: B256::repeat_byte(1), domain: B256::repeat_byte(2) };
        assert_eq!(SigningData::from_ssz_bytes(&signing.as_ssz_bytes()).unwrap(), signing);
    }
}
