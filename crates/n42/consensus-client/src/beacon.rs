use reth_chainspec::EthereumHardforks;
use reth_provider::{BlockIdReader, BlockReader, ChainSpecProvider, BeaconProvider, BeaconProviderWriter};
use alloy_primitives::Sealable;
use reth_primitives::{Block, Header, SealedBlock};

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals},
};
use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolEnum, SolEvent, sol};
use serde::{Deserialize, Serialize};
use alloy_rlp::{Encodable, Decodable, RlpEncodable,  RlpDecodable};
use std::collections::{HashMap, BTreeMap};
use alloy_primitives::{keccak256, BlockHash, B256, Log};
use n42_primitives::{Epoch, VoluntaryExit, VoluntaryExitWithSig, BeaconState, Validator, BeaconBlock, BeaconBlockBody, Attestation, Deposit, DepositData, SLOTS_PER_EPOCH, };
use tracing::{trace, debug, error, info, warn};

const INMEMORY_BEACON_STATES: u32 = 256;

const STAKING_AMOUNT: u64 = 32000000000;

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
pub struct Beacon<Provider> {
    provider: Provider,
}

impl<Provider> Beacon<Provider>
where
    Provider:
        BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static + Clone,
{
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
        }
    }

    pub fn gen_beacon_block(&mut self, old_beacon_state: Option<BeaconState>, parent_hash: BlockHash, deposits: &Vec<Deposit>, attestations: &Vec<Attestation>, voluntary_exits: &Vec<VoluntaryExitWithSig>, eth1_sealed_block: &SealedBlock) -> eyre::Result<BeaconBlock> {
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
        let beacon_state = self.state_transition(old_beacon_state, &beacon_block)?;
        beacon_block.state_root = beacon_state.hash_slow();
        Ok(beacon_block)
    }

    pub fn state_transition(&mut self, old_beacon_state: Option<BeaconState>, beacon_block: &BeaconBlock) -> eyre::Result<BeaconState> {
        debug!(target: "consensus-client", ?beacon_block, "state_transition");
        let beacon_state = if old_beacon_state.is_none() {
            self.provider.get_beacon_state_by_hash(&beacon_block.parent_hash)?.unwrap()
        } else {
            old_beacon_state.unwrap()
        };
        let new_beacon_state = BeaconState::state_transition(&beacon_state, beacon_block)?;
        self.provider.save_beacon_state_by_hash(&beacon_block.hash_slow(), new_beacon_state.clone())?;
        debug!(target: "consensus-client", ?new_beacon_state, "state_transition");

        Ok(new_beacon_state)
    }

    pub fn gen_withdrawals(&mut self, eth1_block_hash: BlockHash) -> eyre::Result<(Option<Vec<Withdrawal>>, BeaconState)> {
        let mut withdrawals = Vec::new();
        let beacon_block_hash = self.provider.get_beacon_block_hash_by_eth1_hash(&eth1_block_hash)?.unwrap();
        debug!(target: "consensus-client", ?beacon_block_hash, "gen_withdrawals");
        let mut beacon_state = self.provider.get_beacon_state_by_hash(&beacon_block_hash)?.unwrap();

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
    }

    pub fn is_valid_voluntary_exit(&mut self, eth1_block_hash: BlockHash, voluntary_exit: &VoluntaryExit, signature: &Bytes) -> eyre::Result<bool> {
        let beacon_block_hash = self.provider.get_beacon_block_hash_by_eth1_hash(&eth1_block_hash)?.unwrap();
        let beacon_state = self.provider.get_beacon_state_by_hash(&beacon_block_hash)?.unwrap();
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
