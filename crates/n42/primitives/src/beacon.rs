use reth_primitives::{Block, Header, SealedBlock};
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, BTreeMap};
use alloy_primitives::{BlockHash, B256};
use crate::Validator;

const INMEMORY_BEACON_STATES: u32 = 256;

const SLOTS_PER_EPOCH: u64 = 32;

#[derive(Debug)]
pub struct Beacon {
    beacon_states: schnellru::LruMap<Eth1BlockHash, BeaconState>,
}

impl Beacon {
    pub fn new() -> Self {
        Beacon {
            beacon_states: schnellru::LruMap::new(schnellru::ByLength::new(INMEMORY_BEACON_STATES)),
        }
    }

    pub fn gen_beacon_block(&self, eth1_sealed_block: &SealedBlock) -> eyre::Result<BeaconBlock> {
        Ok(Default::default())
    }

    pub fn state_transition(&mut self, parent_eth1_block_hash: Eth1BlockHash, beacon_block: &BeaconBlock) -> eyre::Result<()> {
        let beacon_state = self.beacon_states.get(&parent_eth1_block_hash).unwrap();
        let new_beacon_state = BeaconState::state_transition(beacon_state, beacon_block)?;
        self.beacon_states.insert(Eth1BlockHash(beacon_block.eth1_block_hash), new_beacon_state);

        Ok(())
    }
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct BeaconState {
    slot: u64,
    eth1_deposit_index: u64,
    validators: BTreeMap<usize, Validator>,
    balances: BTreeMap<usize, Gwei>,
}

#[derive(Serialize,Deserialize,Debug,PartialEq)]
pub struct  BeaconStateBeforeBlock{
    pub address: BlockHash,
    pub info: Option<BeaconState>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq)]
pub struct Eth1BlockHash(pub BlockHash);

type Gwei = u64;
type Epoch = u64;

// mock
type BLSPubkey = u64;
type BLSSignature = u64;

// #[derive(Debug, Clone, Hash, Default)]
// pub struct Validator {
//     pubkey: BLSPubkey,
//     withdrawal_credentials: B256,  // Commitment to pubkey for withdrawals
//     effective_balance: Gwei,  // Balance at stake
//     slashed: bool,

//     // Status epochs
//     activation_eligibility_epoch: Epoch,  // When criteria for activation were met
//     activation_epoch: Epoch,
//     exit_epoch: Epoch,
//     withdrawable_epoch: Epoch,  // When validator can withdraw funds
// }

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct BeaconBlock {
    pub eth1_block_hash: BlockHash,
    pub state_root: B256,
    pub body: BeaconBlockBody,
}

#[derive(Debug,Serialize,Deserialize,PartialEq)]
pub struct  BeaconBlockBeforeBlock{
    pub address: BlockHash,
    pub info: Option<BeaconBlock>,
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct BeaconBlockBody {
    attestations: Vec<Attestation>,
    deposits: Vec<Deposit>,
    voluntary_exits: Vec<VoluntaryExit>,
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct Attestation {}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct Deposit {
    proof: Vec<B256>,
    data: DepositData,
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct DepositData {
    pubkey: BLSPubkey,
    withdrawal_credentials: B256,
    amount: Gwei,
    signature: BLSSignature,
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct VoluntaryExit {
    epoch: Epoch,
    validator_index: u64,
}

impl BeaconState {
    pub fn state_transition(old_beacon_state: &BeaconState, beacon_block: &BeaconBlock) -> eyre::Result<Self> {
        let mut new_beacon_state = old_beacon_state.clone();
        if (new_beacon_state.slot + 1) % SLOTS_PER_EPOCH == 0 {
            new_beacon_state.process_epoch()?;
        }
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

    pub fn process_block(&self, beacon_block: &BeaconBlock) -> eyre::Result<()> {
        self.process_operations(&beacon_block.body)?;
        Ok(())
    }

    pub fn process_operations(&self, beacon_block_body: &BeaconBlockBody) -> eyre::Result<()> {
        self.process_deposit(beacon_block_body)?;
        self.process_attestation(beacon_block_body)?;
        self.process_voluntary_exit(beacon_block_body)?;

        Ok(())
    }

    pub fn process_deposit(&self, beacon_block_body: &BeaconBlockBody) -> eyre::Result<()> {
        // TODO: check deposits against eth1 block and beacon state
        // TODO: update state
        Ok(())
    }

    pub fn process_attestation(&self, beacon_block_body: &BeaconBlockBody) -> eyre::Result<()> {
        // TODO: check attestations against beacon state
        // TODO: update state
        Ok(())
    }

    pub fn process_voluntary_exit(&self, beacon_block_body: &BeaconBlockBody) -> eyre::Result<()> {
        // TODO: check voluntary exits against beacon state
        // TODO: update state
        Ok(())
    }

}
