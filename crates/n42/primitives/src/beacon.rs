use alloy_primitives::Bytes;
use alloy_rlp::{RlpEncodable,  RlpDecodable};
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, BTreeMap};
use alloy_primitives::{BlockHash, B256};
use crate::Validator;

pub type Epoch = u64;

#[derive(Debug, Clone, Hash, Default, PartialEq, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct VoluntaryExit {
    pub epoch: Epoch,
    pub validator_index: u64,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
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

// TODO

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct BeaconState {
    pub slot: u64,
    pub eth1_deposit_index: u64,
    pub validators: BTreeMap<usize, Validator>,
    pub balances: BTreeMap<usize, Gwei>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq)]
pub struct Eth1BlockHash(pub BlockHash);

type Gwei = u64;

// mock
type BLSPubkey = u64;
type BLSSignature = u64;

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct BeaconBlock {
    pub eth1_block_hash: BlockHash,
    pub state_root: B256,
    pub body: BeaconBlockBody,
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct BeaconBlockBody {
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub voluntary_exits: Vec<VoluntaryExit>,
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct Attestation {}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct Deposit {
    pub proof: Vec<B256>,
    pub data: DepositData,
}

#[derive(Debug, Clone, Hash, Default,Serialize,Deserialize,PartialEq)]
pub struct DepositData {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: B256,
    pub amount: Gwei,
    pub signature: BLSSignature,
}
