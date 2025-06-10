use std::collections::BTreeMap;

use alloy_primitives::{BlockHash, B256};

#[derive(Debug, Clone, Hash, Default)]
pub struct BeaconState {
    eth1_deposit_index: u64,
    validators: BTreeMap<usize, Validator>,
    balances: BTreeMap<usize, Gwei>,
}

#[derive(Debug, Clone, Hash, Default)]
pub struct Eth1BlockHash(BlockHash);

type Gwei = u64;
type Epoch = u64;

// mock
type BLSPubkey = u64;
type BLSSignature = u64;

#[derive(Debug, Clone, Hash, Default)]
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

#[derive(Debug, Clone, Hash, Default)]
pub struct BeaconBlock {
    eth1_block_hash: BlockHash,
    state_root: B256,
    body: BeaconBlockBody,
}

#[derive(Debug, Clone, Hash, Default)]
pub struct BeaconBlockBody {
    attestations: Vec<Attestation>,
    deposits: Vec<Deposit>,
    voluntary_exits: Vec<VoluntaryExit>,
}

#[derive(Debug, Clone, Hash, Default)]
pub struct Attestation {}

#[derive(Debug, Clone, Hash, Default)]
pub struct Deposit {
    proof: Vec<B256>,
    data: DepositData,
}

#[derive(Debug, Clone, Hash, Default)]
pub struct DepositData {
    pubkey: BLSPubkey,
    withdrawal_credentials: B256,
    amount: Gwei,
    signature: BLSSignature,
}

#[derive(Debug, Clone, Hash, Default)]
pub struct VoluntaryExit {
    epoch: Epoch,
    validator_index: u64,
}
