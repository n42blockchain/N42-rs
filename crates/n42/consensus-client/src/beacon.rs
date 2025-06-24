use reth_primitives::{Block, Header, SealedBlock};

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals},
};
use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolEnum, SolEvent, sol};
use serde::{Deserialize, Serialize};
use alloy_primitives::Sealable;
use alloy_rlp::{Encodable, RlpEncodable,  RlpDecodable};
use std::collections::{HashMap, BTreeMap};
use alloy_primitives::{keccak256, BlockHash, B256, Log};
use crate::storage::{Storage};
use tracing::{trace, debug, error, info, warn};

const INMEMORY_BEACON_STATES: u32 = 256;

const STAKING_AMOUNT: u64 = 32000000000;
const REWARD_AMOUNT: u64 = 1;
const SLOTS_PER_EPOCH: u64 = 32;

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

    pub fn gen_beacon_block(&mut self, parent_hash: BlockHash, deposits: &Vec<Deposit>, attestations: &Vec<Attestation>, voluntary_exits: &Vec<VoluntaryExit>, eth1_sealed_block: &SealedBlock) -> eyre::Result<BeaconBlock> {
        let mut beacon_block = BeaconBlock {
            parent_hash,
            eth1_block_hash: eth1_sealed_block.hash_slow(),
            body: BeaconBlockBody {
                deposits: deposits.clone(),
                attestations: attestations.clone(),
                voluntary_exits: voluntary_exits.clone(),
            },
            ..Default::default()
        };
        let beacon_state = self.state_transition(&beacon_block)?;
        beacon_block.state_root = beacon_state.hash_slow();
        Ok(beacon_block)
    }

    pub fn state_transition(&mut self, beacon_block: &BeaconBlock) -> eyre::Result<BeaconState> {
        debug!(target: "consensus-client", ?beacon_block, "state_transition");
        let beacon_state = self.storage.get_beacon_state_by_beacon_hash(beacon_block.parent_hash)?;
        let new_beacon_state = BeaconState::state_transition(&beacon_state, beacon_block)?;
        self.storage.save_beacon_state_by_beacon_hash(beacon_block.hash_slow(), new_beacon_state.clone())?;
        debug!(target: "consensus-client", ?new_beacon_state, "state_transition");

        Ok(new_beacon_state)
    }

    pub fn gen_withdrawals(&mut self, eth1_block_hash: BlockHash) -> Option<Vec<Withdrawal>> {
        let mut withdrawals = Vec::new();
        let beacon_block_hash = self.storage.get_beacon_block_hash_by_eth1_hash(eth1_block_hash).unwrap();
        debug!(target: "consensus-client", ?beacon_block_hash, "gen_withdrawals");
        let mut beacon_state = self.storage.get_beacon_state_by_beacon_hash(beacon_block_hash).unwrap();

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

        self.storage.save_beacon_state_by_beacon_hash(beacon_block_hash, beacon_state).unwrap();

        Some(withdrawals)
    }
}

fn get_address(withdrawal_credentials: &B256) -> Address {
    assert_eq!(withdrawal_credentials.as_slice()[0], 0x01);
    Address::from_slice(&withdrawal_credentials.as_slice()[12..])
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct BeaconState {
    slot: u64,
    eth1_deposit_index: u64,
    validators: Vec<Validator>,
    balances: Vec<Gwei>,
}

impl Sealable for BeaconState {
    fn hash_slow(&self) -> B256 {
        let mut out = Vec::new();
        self.encode(&mut out);
        keccak256(&out)
    }
}

type Gwei = u64;
type Epoch = u64;

// mock
type BLSPubkey = Bytes;
type BLSSignature = Bytes;

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct Validator {
    pubkey: BLSPubkey,
    withdrawal_credentials: B256,  // Commitment to pubkey for withdrawals
    effective_balance: Gwei,  // Balance at stake
    slashed: bool,

    // Status epochs
    activation_eligibility_epoch: Epoch,  // When criteria for activation were met
    activation_epoch: Epoch,
    exit_epoch: Epoch,
    withdrawable_epoch: Epoch,  // When validator can withdraw funds
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
    pub voluntary_exits: Vec<VoluntaryExit>,
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

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct VoluntaryExit {
    pub epoch: Epoch,
    pub validator_index: u64,
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
        for (index, validator) in self.validators.iter_mut().enumerate() {
            if validator.pubkey == attestation.pubkey {
                validator.effective_balance += REWARD_AMOUNT;
                self.balances[index] += REWARD_AMOUNT;
                break;
            }
        }

        Ok(())
    }

    pub fn process_voluntary_exit(&mut self, voluntary_exits: &Vec<VoluntaryExit>) -> eyre::Result<()> {
        // TODO: check voluntary exits against beacon state
        // TODO: update state
        for voluntary_exit in voluntary_exits {
            let _ = self.process_one_voluntary_exit(voluntary_exit);
        }
        Ok(())
    }

    pub fn process_one_voluntary_exit(&mut self, voluntary_exit: &VoluntaryExit) -> eyre::Result<()> {
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

}
