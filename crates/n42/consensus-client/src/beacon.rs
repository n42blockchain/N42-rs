use reth_primitives_traits::AlloyBlockHeader;
use blst::min_pk::PublicKey;
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use reth_chainspec::EthereumHardforks;
use reth_provider::{BlockIdReader, BlockReader, ChainSpecProvider, BeaconProvider, BeaconProviderWriter};
use alloy_primitives::Sealable;
use reth_primitives::{Block, Header, SealedBlock};

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals}, eip7685::Requests,
};
use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use alloy_rlp::{Encodable, Decodable, RlpEncodable,  RlpDecodable};
use std::collections::{HashMap, BTreeMap};
use alloy_primitives::{keccak256, BlockHash, B256, Log};
use n42_primitives::{Attestation, BeaconBlock, BeaconBlockBody, BeaconState, BlockVerifyResultAggregate, CommitteeIndex, Deposit, DepositData, Epoch, ExecutionRequests, Validator, VoluntaryExit, VoluntaryExitWithSig, SLOTS_PER_EPOCH };
use tracing::{trace, debug, error, info, warn};

const INMEMORY_BEACON_STATES: u32 = 256;

const STAKING_AMOUNT: u64 = 32000000000;

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

    pub fn gen_beacon_block(&mut self, old_beacon_state: Option<BeaconState>, parent_hash: BlockHash, deposits: &Vec<Deposit>, attestations: &Vec<Attestation>, voluntary_exits: &Vec<VoluntaryExitWithSig>, execution_requests: &Option<Requests>, eth1_sealed_block: &SealedBlock) -> eyre::Result<BeaconBlock> {
        let mut beacon_block = BeaconBlock {
            parent_hash,
            eth1_block_hash: eth1_sealed_block.hash_slow(),
            body: BeaconBlockBody {
                deposits: deposits.clone(),
                attestations: attestations.clone(),
                voluntary_exits: voluntary_exits.clone(),
                execution_requests: parse_execution_requests(execution_requests)?,
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
        let beacon_block_with_root = BeaconBlock { state_root: new_beacon_state.hash_slow(), ..beacon_block.clone() };
        let beacon_block_hash = beacon_block_with_root.hash_slow();
        self.provider.save_beacon_state_by_hash(&beacon_block_hash, new_beacon_state.clone())?;
        debug!(target: "consensus-client", ?beacon_block_hash, ?new_beacon_state, "state_transition");

        Ok(new_beacon_state)
    }

    pub fn gen_withdrawals(&mut self, eth1_block_hash: BlockHash) -> eyre::Result<(Option<Vec<Withdrawal>>, BeaconState)> {
        debug!(target: "consensus-client", ?eth1_block_hash, "gen_withdrawals");
        let beacon_block_hash = self.provider.get_beacon_block_hash_by_eth1_hash(&eth1_block_hash)?.unwrap();
        debug!(target: "consensus-client", ?beacon_block_hash, "gen_withdrawals");
        let mut beacon_state = self.provider.get_beacon_state_by_hash(&beacon_block_hash)?.unwrap();
        debug!(target: "consensus-client", ?beacon_state, "gen_withdrawals");

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
        let beacon_block_hash = self.provider.get_beacon_block_hash_by_eth1_hash(&eth1_block_hash)?.unwrap();
        let beacon_state = self.provider.get_beacon_state_by_hash(&beacon_block_hash)?.unwrap();
        if let Some(validator) = beacon_state.validators.get(voluntary_exit.validator_index as usize) {
            if voluntary_exit.epoch > validator.activation_epoch && !validator.is_exited_set() {
                // TODO: check signature

                return Ok(true)
            }
        }

        Ok(false)
    }

    fn get_beacon_state_from_block_hash(&self, block_hash: B256) -> eyre::Result<BeaconState> {
        let beacon_block = self.provider.get_beacon_block_by_eth1_hash(&block_hash)?.ok_or(eyre::eyre!("beacon block not found, block_hash={:?}", block_hash))?;
        let beacon_block_hash = beacon_block.hash_slow();

        let beacon_state = self.provider.get_beacon_state_by_hash(&beacon_block_hash)?.ok_or(eyre::eyre!("beacon state not found, beacon_block_hash={:?}", beacon_block_hash))?;

        Ok(beacon_state)
    }

    pub fn get_validator_index_from_beacon_state(&self, block_hash: B256, pubkey: PublicKey) -> eyre::Result<Option<u64>> {
        let beacon_state = self.get_beacon_state_from_block_hash(block_hash)?;

        for (i, validator) in beacon_state.validators.into_iter().enumerate() {
            if pubkey == PublicKey::from_bytes(&validator.pubkey.as_slice()).unwrap() {
                return Ok(Some(i as u64));
            }
        }

        Ok(None)
    }

    pub fn get_validator_pubkey_from_beacon_state(&self, block_hash: B256, validator_index: u64) -> eyre::Result<Option<PublicKey>> {
        let beacon_state = self.get_beacon_state_from_block_hash(block_hash)?;

        let validator = beacon_state.get_validator(validator_index as usize)?;
        let pubkey = PublicKey::from_bytes(validator.pubkey.as_ref()).unwrap();
        Ok(Some(pubkey))
    }
}

fn get_address(withdrawal_credentials: &B256) -> Address {
    assert_eq!(withdrawal_credentials.as_slice()[0], 0x01);
    Address::from_slice(&withdrawal_credentials.as_slice()[12..])
}

fn parse_execution_requests(requests: &Option<Requests>) -> eyre::Result<ExecutionRequestsV4> {
    Ok(requests.clone().unwrap_or_default().try_into()?)
}
