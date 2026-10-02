// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::Sealable;
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use blst::min_pk::{PublicKey, Signature};
use merkle_db_rs::tree::{Tree, VecTree};
use reth_chainspec::EthereumHardforks;
use n42_tx_types::Block;
use reth_primitives_traits::Header;
// reth-primitives (deleted in reth 2.4.1) supplied this default type argument.
type SealedBlock<B = Block> = reth_primitives_traits::SealedBlock<B>;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{
    BeaconProvider, BeaconProviderWriter, BlockIdReader, BlockReader, ChainSpecProvider,
};

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals},
    eip7685::Requests,
};
use alloy_primitives::{keccak256, BlockHash, Log, B256};
use alloy_primitives::{Address, Bytes};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use n42_primitives::{
    Attestation, BeaconBlock, BeaconBlockBody, BeaconState, BlockVerifyResultAggregate,
    CommitteeIndex, Deposit, DepositData, Epoch, ExecutionRequests, Validator,
    VoluntaryExitWithSig, SLOTS_PER_EPOCH,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct Beacon<Provider> {
    provider: Provider,
}

impl<Provider> Beacon<Provider>
where
    Provider: BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static
        + Clone,
{
    pub fn new(provider: Provider) -> Self {
        Self { provider }
    }

    pub fn gen_beacon_block(
        &mut self,
        old_beacon_state: BeaconState,
        parent_hash: BlockHash,
        attestations: &Vec<Attestation>,
        execution_requests: &Option<Requests>,
        eth1_sealed_block: &SealedBlock,
    ) -> eyre::Result<BeaconBlock> {
        let mut execution_requests = parse_execution_requests(execution_requests)?;

        execution_requests.deposits.retain(|deposit|
            {
                let deposit_data = DepositData {
                    pubkey: deposit.pubkey,
                    withdrawal_credentials: deposit.withdrawal_credentials,
                    signature: deposit.signature,
                    amount: deposit.amount,
                };

                let deposit_data_verify_result = deposit_data.verify_signature();
                debug!(target: "consensus-client", pubkey=?deposit_data.pubkey, ?deposit_data_verify_result, "gen_beacon_block");
                deposit_data_verify_result
            }
        );

        let mut beacon_block = BeaconBlock {
            slot: old_beacon_state.slot + 1,
            parent_hash,
            eth1_block_hash: eth1_sealed_block.hash_slow(),
            body: BeaconBlockBody {
                deposits: Default::default(),
                attestations: attestations.clone(),
                voluntary_exits: Default::default(),
                execution_requests,
            },
            ..Default::default()
        };
        let beacon_state = self.state_transition(Some(old_beacon_state), &beacon_block)?;
        beacon_block.state_root = beacon_state.hash_slow();
        Ok(beacon_block)
    }

    pub fn state_transition(
        &mut self,
        old_beacon_state: Option<BeaconState>,
        beacon_block: &BeaconBlock,
    ) -> eyre::Result<BeaconState> {
        debug!(target: "consensus-client", ?beacon_block, "state_transition");
        let beacon_state = match old_beacon_state {
            Some(v) => v,
            None => self
                .provider
                .get_beacon_state_by_hash(&beacon_block.parent_hash)?
                .ok_or(eyre::eyre!(
                    "beacon_state not found by hash, {:?}",
                    beacon_block.parent_hash
                ))?,
        };
        let new_beacon_state = BeaconState::state_transition(&beacon_state, beacon_block)?;
        let beacon_block_with_root = BeaconBlock {
            state_root: new_beacon_state.hash_slow(),
            ..beacon_block.clone()
        };
        let beacon_block_hash = beacon_block_with_root.hash_slow();
        self.provider
            .save_beacon_state_by_hash(&beacon_block_hash, new_beacon_state.clone())?;
        debug!(target: "consensus-client", ?beacon_block_hash, ?new_beacon_state, "state_transition");

        Ok(new_beacon_state)
    }

    pub fn gen_withdrawals(
        &mut self,
        eth1_block_hash: BlockHash,
    ) -> eyre::Result<(Option<Vec<Withdrawal>>, BeaconState)> {
        debug!(target: "consensus-client", ?eth1_block_hash, "gen_withdrawals");
        let beacon_block_hash = self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_block_hash)?
            .ok_or(eyre::eyre!(
                "beacon block hash not found, eth1_block_hash={:?}",
                eth1_block_hash
            ))?;

        debug!(target: "consensus-client", ?beacon_block_hash, "gen_withdrawals");
        let mut beacon_state = self
            .provider
            .get_beacon_state_by_hash(&beacon_block_hash)?
            .ok_or(eyre::eyre!(
                "beacon_state not found by hash, beacon_block_hash={:?}",
                beacon_block_hash
            ))?;
        debug!(target: "consensus-client", ?beacon_state, "gen_withdrawals");

        let (expected_withdrawals, processed_partial_withdrawals_count) =
            beacon_state.process_withdrawals()?;
        Ok((Some(expected_withdrawals), beacon_state))
    }

    /// Get validator index from beacon state by pubkey
    pub fn get_validator_index_from_beacon_state(
        &self,
        block_hash: BlockHash,
        pubkey: blst::min_pk::PublicKey,
    ) -> eyre::Result<Option<u64>> {
        let beacon_block_hash = self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&block_hash)?
            .ok_or(eyre::eyre!(
                "beacon_block_hash not found by eth1_hash, {:?}",
                block_hash
            ))?;
        let beacon_state = self
            .provider
            .get_beacon_state_by_hash(&beacon_block_hash)?
            .ok_or(eyre::eyre!(
                "beacon_state not found by hash, {:?}",
                beacon_block_hash
            ))?;

        // Search for validator by pubkey using validators_store
        let pubkey_bytes: [u8; 48] = pubkey.to_bytes();
        for (index, validator) in beacon_state.validators_store.iter().enumerate() {
            if validator.pubkey.0 == pubkey_bytes {
                return Ok(Some(index as u64));
            }
        }
        Ok(None)
    }
}

fn parse_execution_requests(requests: &Option<Requests>) -> eyre::Result<ExecutionRequestsV4> {
    Ok(requests.clone().unwrap_or_default().try_into()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip7685::Requests;

    #[test]
    fn test_parse_execution_requests_none() {
        let result = parse_execution_requests(&None);
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert!(requests.deposits.is_empty());
        assert!(requests.withdrawals.is_empty());
        assert!(requests.consolidations.is_empty());
    }

    #[test]
    fn test_parse_execution_requests_empty() {
        let requests = Some(Requests::default());
        let result = parse_execution_requests(&requests);
        assert!(result.is_ok());
    }
}

/// `Beacon` against a real (temporary, in-process) provider: the beacon
/// tables are written and read through reth's `BlockchainProvider`, so what
/// is tested is the round trip, not a mock of it.
#[cfg(test)]
mod provider_tests {
    use super::*;
    use reth_provider::providers::BlockchainProvider;
    use reth_provider::test_utils::{
        create_test_provider_factory, MockNodeTypesWithDB,
    };

    type TestProvider = BlockchainProvider<MockNodeTypesWithDB>;

    fn provider() -> TestProvider {
        let factory = create_test_provider_factory();
        // The tests only touch the beacon tables, so the in-memory chain tip is
        // a stand-in header rather than an inserted genesis block.
        let tip = reth_primitives_traits::SealedHeader::new(Header::default(), B256::ZERO);
        BlockchainProvider::with_latest(factory, tip).expect("provider")
    }

    fn sealed() -> SealedBlock {
        SealedBlock::seal_slow(Block::default())
    }

    fn real_pubkey(seed: u8) -> blst::min_pk::PublicKey {
        blst::min_pk::SecretKey::key_gen(&[seed; 32], &[]).unwrap().sk_to_pk()
    }

    fn state_with_validators(keys: &[blst::min_pk::PublicKey]) -> BeaconState {
        let mut state = BeaconState::new();
        for key in keys {
            state
                .validators_store
                .push(Validator { pubkey: alloy_primitives::FixedBytes(key.to_bytes()), ..Default::default() })
                .expect("push validator");
            state.balances_store.push(32_000_000_000).expect("push balance");
            state.inactivity_scores_store.push(0).expect("push score");
        }
        state.validators = state.validators_store.root();
        state.validators_len = state.validators_store.len() as u64;
        state.balances = state.balances_store.root();
        state.balances_len = state.balances_store.len() as u64;
        state.inactivity_scores = state.inactivity_scores_store.root();
        state.inactivity_scores_len = state.inactivity_scores_store.len() as u64;
        state
    }

    /// Records `state` as the beacon state of the eth1 block `eth1`, returning
    /// the beacon block hash it was filed under.
    fn file_state(provider: &TestProvider, eth1: B256, state: BeaconState) -> B256 {
        let beacon_hash = B256::repeat_byte(0xB0);
        provider.save_beacon_block_hash_by_eth1_hash(&eth1, beacon_hash).unwrap();
        provider.save_beacon_state_by_hash(&beacon_hash, state).unwrap();
        beacon_hash
    }

    #[test]
    fn withdrawals_for_an_unknown_eth1_block_are_an_error() {
        let mut beacon = Beacon::new(provider());
        let err = beacon.gen_withdrawals(B256::repeat_byte(1)).unwrap_err();
        assert!(err.to_string().contains("beacon block hash not found"), "{err}");
    }

    #[test]
    fn withdrawals_need_the_beacon_state_behind_the_mapping() {
        let provider = provider();
        provider.save_beacon_block_hash_by_eth1_hash(&B256::repeat_byte(1), B256::repeat_byte(2)).unwrap();
        let mut beacon = Beacon::new(provider);
        let err = beacon.gen_withdrawals(B256::repeat_byte(1)).unwrap_err();
        assert!(err.to_string().contains("beacon_state not found"), "{err}");
    }

    #[test]
    fn a_chain_without_validators_has_no_withdrawals_and_returns_the_stored_state() {
        let provider = provider();
        let eth1 = B256::repeat_byte(1);
        let mut stored = BeaconState::new();
        stored.slot = 41;
        file_state(&provider, eth1, stored);
        let mut beacon = Beacon::new(provider);
        let (withdrawals, state) = beacon.gen_withdrawals(eth1).expect("withdrawals");
        assert_eq!(withdrawals, Some(Vec::new()));
        assert_eq!(state.slot, 41);
    }

    #[test]
    fn a_state_transition_without_a_parent_state_names_the_missing_hash() {
        let mut beacon = Beacon::new(provider());
        let block = BeaconBlock { slot: 1, parent_hash: B256::repeat_byte(9), ..Default::default() };
        let err = beacon.state_transition(None, &block).unwrap_err();
        assert!(err.to_string().contains("beacon_state not found by hash"), "{err}");
    }

    #[test]
    fn a_state_transition_advances_the_slot_and_stores_the_new_state() {
        let provider = provider();
        let mut beacon = Beacon::new(provider.clone());
        let block = BeaconBlock { slot: 1, ..Default::default() };
        let new_state = beacon.state_transition(Some(BeaconState::new()), &block).expect("transitions");
        assert_eq!(new_state.slot, 1);

        // Filed under the hash of the block carrying the resulting state root.
        let with_root = BeaconBlock { state_root: new_state.hash_slow(), ..block };
        let stored = provider
            .get_beacon_state_by_hash(&with_root.hash_slow())
            .unwrap()
            .expect("the new state was saved");
        assert_eq!(stored.slot, 1);
        assert_eq!(stored.hash_slow(), new_state.hash_slow());
    }

    #[test]
    fn a_state_transition_can_start_from_the_parent_stored_in_the_provider() {
        let provider = provider();
        let parent_hash = B256::repeat_byte(0xAA);
        let mut parent = BeaconState::new();
        parent.slot = 5;
        provider.save_beacon_state_by_hash(&parent_hash, parent).unwrap();
        let mut beacon = Beacon::new(provider);
        let block = BeaconBlock { slot: 6, parent_hash, ..Default::default() };
        let new_state = beacon.state_transition(None, &block).expect("transitions");
        assert_eq!(new_state.slot, 6);
    }

    #[test]
    fn a_generated_beacon_block_extends_the_state_and_names_its_eth1_block() {
        let provider = provider();
        let mut beacon = Beacon::new(provider.clone());
        let mut old = BeaconState::new();
        old.slot = 2;
        let eth1 = sealed();
        let parent = B256::repeat_byte(0x42);

        let block = beacon
            .gen_beacon_block(old.clone(), parent, &Vec::new(), &None, &eth1)
            .expect("generates");
        assert_eq!(block.slot, 3);
        assert_eq!(block.parent_hash, parent);
        assert_eq!(block.eth1_block_hash, eth1.hash());
        assert!(block.body.attestations.is_empty());
        assert!(block.body.execution_requests.deposits.is_empty());

        // The state root commits to the state the block leads to, which was saved.
        let expected = BeaconState::state_transition(&old, &block).expect("same transition");
        assert_eq!(block.state_root, expected.hash_slow());
        let stored = provider
            .get_beacon_state_by_hash(&block.hash_slow())
            .unwrap()
            .expect("the resulting state is stored under the block's hash");
        assert_eq!(stored.slot, 3);

        // Deterministic: the same inputs give the same block.
        let again = beacon.gen_beacon_block(old, parent, &Vec::new(), &None, &eth1).unwrap();
        assert_eq!(again.hash_slow(), block.hash_slow());
    }

    #[test]
    fn a_deposit_with_a_bad_signature_is_dropped_from_the_generated_block() {
        use alloy_eips::eip7685::Requests;
        // One 192-byte deposit request: pubkey 48 | credentials 32 | amount 8 | signature 96 | index 8.
        let mut deposit = Vec::new();
        deposit.extend_from_slice(&[7u8; 48]);
        deposit.extend_from_slice(&[0u8; 32]);
        deposit.extend_from_slice(&32_000_000_000u64.to_le_bytes());
        deposit.extend_from_slice(&[9u8; 96]);
        deposit.extend_from_slice(&0u64.to_le_bytes());
        let mut requests = Requests::default();
        requests.push_request_with_type(0x00, deposit);

        let parsed = parse_execution_requests(&Some(requests.clone())).expect("parses");
        assert_eq!(parsed.deposits.len(), 1, "the request is well formed");

        let mut beacon = Beacon::new(provider());
        let block = beacon
            .gen_beacon_block(BeaconState::new(), B256::ZERO, &Vec::new(), &Some(requests), &sealed())
            .expect("generates");
        assert!(block.body.execution_requests.deposits.is_empty(), "an unverifiable deposit is not included");
    }

    #[test]
    fn a_malformed_request_list_is_an_error() {
        use alloy_eips::eip7685::Requests;
        let mut requests = Requests::default();
        requests.push_request_with_type(0x00, vec![1, 2, 3]);
        assert!(parse_execution_requests(&Some(requests)).is_err());
    }

    #[test]
    fn a_validator_is_found_by_pubkey_in_the_state_of_an_eth1_block() {
        let provider = provider();
        let eth1 = B256::repeat_byte(1);
        file_state(&provider, eth1, state_with_validators(&[real_pubkey(1), real_pubkey(2)]));
        let beacon = Beacon::new(provider);
        assert_eq!(beacon.get_validator_index_from_beacon_state(eth1, real_pubkey(1)).unwrap(), Some(0));
        assert_eq!(beacon.get_validator_index_from_beacon_state(eth1, real_pubkey(2)).unwrap(), Some(1));
        assert_eq!(beacon.get_validator_index_from_beacon_state(eth1, real_pubkey(3)).unwrap(), None);
    }

    #[test]
    fn the_validator_lookup_reports_a_missing_mapping_and_a_missing_state() {
        let provider = provider();
        let beacon = Beacon::new(provider.clone());
        let pk = real_pubkey(3);
        let err = beacon.get_validator_index_from_beacon_state(B256::repeat_byte(1), pk).unwrap_err();
        assert!(err.to_string().contains("beacon_block_hash not found"), "{err}");

        provider.save_beacon_block_hash_by_eth1_hash(&B256::repeat_byte(1), B256::repeat_byte(2)).unwrap();
        let err = beacon.get_validator_index_from_beacon_state(B256::repeat_byte(1), pk).unwrap_err();
        assert!(err.to_string().contains("beacon_state not found"), "{err}");
    }
}
