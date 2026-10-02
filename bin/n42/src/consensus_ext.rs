// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::Address;
use alloy_primitives::{Sealable, B256};
use alloy_rpc_types::BlockId;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{
    core::{RpcResult, SubscriptionResult},
    proc_macros::rpc,
    types::{
        error::{INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
        ErrorObject,
    },
    PendingSubscriptionSink, SubscriptionMessage,
};
use n42_clique::{BlockVerifyResult, UnverifiedBlock};
use n42_primitives::{
    beacon_chain_spec, epoch_to_block_number, AttestationData, BLSPubkey, BeaconBlock, BeaconState,
    Snapshot, ValidatorInfo,
};
use pubsub_mem::{subscribe, RouterMsg};
use reth_consensus::{ConsensusError, FullConsensus};
use n42_tx_types::N42Primitives as EthPrimitives;
use reth_node_core::primitives::AlloyBlockHeader;
use reth_provider::{BeaconProvider, BlockIdReader, BlockReader, HeaderProvider};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::debug;

/// trait interface for a custom rpc namespace: `consensus`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "consensusExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "consensusExt"))]
pub trait ConsensusExtApi {
    /// Propose in the clique consensus.
    #[method(name = "propose")]
    fn propose(&self, address: Address, auth: bool) -> RpcResult<()>;

    /// Discard in the clique consensus.
    #[method(name = "discard")]
    fn discard(&self, address: Address) -> RpcResult<()>;

    /// GetSnapshot in the clique consensus.
    #[method(name = "get_snapshot")]
    fn get_snapshot(&self, number: u64) -> RpcResult<Snapshot>;

    /// Proposals in the clique consensus.
    #[method(name = "proposals")]
    fn proposals(&self) -> RpcResult<HashMap<Address, bool>>;
}

/// The type that implements the `consensus` rpc namespace trait
pub struct ConsensusExt<Cons, Provider> {
    pub consensus: Cons,
    pub provider: Provider,
}

impl<Cons, Provider> ConsensusExtApiServer for ConsensusExt<Cons, Provider>
where
    Cons: FullConsensus<EthPrimitives> + Clone + Unpin + 'static,
    Provider: HeaderProvider + Clone + Send + Sync + 'static,
{
    fn propose(&self, address: Address, auth: bool) -> RpcResult<()> {
        Ok(self.consensus.propose(address, auth).unwrap_or_default())
    }

    fn discard(&self, address: Address) -> RpcResult<()> {
        Ok(self.consensus.discard(address).unwrap_or_default())
    }

    fn get_snapshot(&self, number: u64) -> RpcResult<Snapshot> {
        let hash = self
            .provider
            .header_by_number(number)
            .unwrap_or_default()
            .unwrap_or_default()
            .hash_slow();
        self.consensus.snapshot(number, hash, None).map_err(|err| {
            ErrorObject::owned(INVALID_PARAMS_CODE, err.to_string(), Option::<()>::None)
        })
    }

    fn proposals(&self) -> RpcResult<HashMap<Address, bool>> {
        Ok(self.consensus.proposals().unwrap_or_default())
    }
}

/// trait interface for a custom rpc namespace: `consensusBeaconExt`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "consensusBeaconExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "consensusBeaconExt"))]
pub trait ConsensusBeaconExtApi {
    #[subscription(name = "subscribeToVerificationRequest", item = String)]
    fn subscribe_to_verification_request(&self, pubkey: BLSPubkey) -> SubscriptionResult;

    #[method(name = "submitVerification")]
    fn submit_verification(
        &self,
        pubkey: String,
        signature: String,
        attestation_data: AttestationData,
        block_hash: B256,
    ) -> RpcResult<()>;

    /// get_beacon_block_hash_by_eth1_hash
    #[method(name = "get_beacon_block_hash_by_eth1_hash")]
    fn get_beacon_block_hash_by_eth1_hash(&self, eth1_hash: B256) -> RpcResult<Option<B256>>;

    /// get_beacon_block_by_hash
    #[method(name = "get_beacon_block_by_hash")]
    fn get_beacon_block_by_hash(&self, beacon_block_hash: B256) -> RpcResult<Option<BeaconBlock>>;

    /// get_beacon_block_by_number
    #[method(name = "get_beacon_block_by_number")]
    fn get_beacon_block_by_number(&self, block_id: BlockId) -> RpcResult<Option<BeaconBlock>>;

    /// get_beacon_state_by_beacon_block_hash
    #[method(name = "get_beacon_state_by_beacon_block_hash")]
    fn get_beacon_state_by_beacon_block_hash(
        &self,
        beacon_block_hash: B256,
    ) -> RpcResult<Option<BeaconState>>;

    /// get_beacon_state_by_number
    #[method(name = "get_beacon_state_by_number")]
    fn get_beacon_state_by_number(&self, state_id: BlockId) -> RpcResult<Option<BeaconState>>;

    /// get_beacon_validator_by_pubkey
    #[method(name = "get_beacon_validator_by_pubkey")]
    fn get_beacon_validator_by_pubkey(&self, pubkey: BLSPubkey)
        -> RpcResult<Option<ValidatorInfo>>;

    /// get_total_effective_balance
    #[method(name = "get_total_effective_balance")]
    fn get_total_effective_balance(&self) -> RpcResult<u64>;
}

/// The type that implements the `consensusBeaconRpc` rpc namespace trait
pub struct ConsensusBeaconExt<Cons, Provider> {
    pub consensus: Cons,
    pub provider: Provider,
    pub verification_tx: mpsc::Sender<BlockVerifyResult>,
    pub router_tx: mpsc::Sender<RouterMsg<UnverifiedBlock>>,
}

impl<Cons, Provider> ConsensusBeaconExtApiServer for ConsensusBeaconExt<Cons, Provider>
where
    Cons: FullConsensus<EthPrimitives> + Clone + Unpin + 'static,
    Provider: HeaderProvider + BeaconProvider + BlockIdReader + BlockReader + Clone + 'static,
{
    fn subscribe_to_verification_request(
        &self,
        pending: PendingSubscriptionSink,
        pubkey: BLSPubkey,
    ) -> SubscriptionResult {
        let router_tx_clone = self.router_tx.clone();

        tokio::spawn(async move {
            let (_id, mut rx) = match subscribe(router_tx_clone, hex::encode(&pubkey)).await {
                Ok(v) => v,
                Err(err) => {
                    debug!(target: "reth::cli", ?pubkey, ?err, "subscribe_to_verification_request failed");
                    return;
                }
            };
            debug!(target: "reth::cli", ?pubkey, "subscribe_to_verification_request New client subscribed");
            if let Ok(sink) = pending.accept().await {
                let subscription_id = sink.subscription_id();
                while let Some(event) = rx.recv().await {
                    let data_to_be_verified = event.payload;
                    debug!(target: "reth::cli", ?pubkey, "start broadcasting, block number {:?}", data_to_be_verified.blockbody.header().number());
                    if sink.is_closed() {
                        debug!(target: "reth::cli", ?subscription_id, "subscribe_to_verification_request client disconnected");
                        break;
                    }
                    let message = SubscriptionMessage::new(
                        "subscribeToVerificationRequest",
                        subscription_id.clone(),
                        &data_to_be_verified,
                    )
                    .unwrap();
                    if let Err(e) = sink.send(message).await {
                        debug!(target: "reth::cli", ?subscription_id, ?e, "subscribe_to_verification_request Error sending to client");
                        break;
                    }
                    debug!(target: "reth::cli", ?pubkey, "finish broadcasting, block number {:?}", data_to_be_verified.blockbody.header().number());
                }
            }
        });
        Ok(())
    }

    fn submit_verification(
        &self,
        pubkey: String,
        signature: String,
        attestation_data: AttestationData,
        block_hash: B256,
    ) -> RpcResult<()> {
        debug!(target: "reth::cli", ?pubkey, "received verification from rpc, slot={:?}", attestation_data.slot);
        let v = BlockVerifyResult {
            pubkey,
            signature,
            attestation_data,
            block_hash,
        };
        let _ = self.verification_tx.try_send(v);
        Ok(())
    }

    fn get_beacon_block_hash_by_eth1_hash(&self, eth1_hash: B256) -> RpcResult<Option<B256>> {
        self.provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_block_by_hash(&self, beacon_block_hash: B256) -> RpcResult<Option<BeaconBlock>> {
        self.provider
            .get_beacon_block_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_block_by_number(&self, block_id: BlockId) -> RpcResult<Option<BeaconBlock>> {
        let eth1_hash = match self.provider.block_hash_for_id(block_id).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        let beacon_block_hash = match self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_hash)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        self.provider
            .get_beacon_block_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_state_by_beacon_block_hash(
        &self,
        beacon_block_hash: B256,
    ) -> RpcResult<Option<BeaconState>> {
        self.provider
            .get_beacon_state_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_state_by_number(&self, block_id: BlockId) -> RpcResult<Option<BeaconState>> {
        let eth1_hash = match self.provider.block_hash_for_id(block_id).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        let beacon_block_hash = match self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_hash)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        self.provider
            .get_beacon_state_by_hash(&beacon_block_hash)
            .map_err(|e| ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>))
    }

    fn get_beacon_validator_by_pubkey(
        &self,
        pubkey: BLSPubkey,
    ) -> RpcResult<Option<ValidatorInfo>> {
        let beacon_state = match self.get_beacon_state_by_number(BlockId::latest())? {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };
        let validator_index = match beacon_state.get_validator_index_from_pubkey(&pubkey) {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };
        let validator = beacon_state.get_validator(validator_index).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })?;
        let balance_in_beacon = beacon_state.get_balance(validator_index).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })?;
        let effective_balance = beacon_state
            .get_effective_balance(validator_index)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })?;
        let inactivity_score = beacon_state
            .get_inactivity_score(validator_index)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })?;
        let activation_block_number = epoch_to_block_number(validator.activation_epoch);
        let activation_timestamp = match self
            .provider
            .header_by_number(activation_block_number)
            .map_err(|e| {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
            })? {
            Some(v) => v.timestamp(),
            None => 0,
        };
        let exit_block_number = epoch_to_block_number(validator.exit_epoch);
        let exit_timestamp =
            match self
                .provider
                .header_by_number(exit_block_number)
                .map_err(|e| {
                    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
                })? {
                Some(v) => v.timestamp(),
                None => 0,
            };

        let validator_info = ValidatorInfo {
            activation_timestamp,
            exit_timestamp,
            balance_in_beacon,
            effective_balance,
            inactivity_score,
        };
        Ok(Some(validator_info))
    }

    fn get_total_effective_balance(&self) -> RpcResult<u64> {
        let beacon_state = match self.get_beacon_state_by_number(BlockId::latest())? {
            Some(v) => v,
            None => {
                return Err(ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    format!("beacon state not found"),
                    None::<()>,
                ));
            }
        };
        let spec = beacon_chain_spec();
        let total_active_balance = beacon_state.get_total_active_balance(&spec).map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, format!("{e:?}"), None::<()>)
        })?;

        Ok(total_active_balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::server::ServerBuilder;
    use reth_consensus::noop::NoopConsensus;
    use reth_provider::test_utils::NoopProvider;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_propose_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::propose(&client, Address::random(), true)
            .await
            .unwrap();
        assert_eq!(result, ());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_discard_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::discard(&client, Address::random())
            .await
            .unwrap();
        assert_eq!(result, ());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_get_snapshot_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::get_snapshot(&client, 0)
            .await
            .unwrap();
        assert_eq!(result, Snapshot::default());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_proposals_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::proposals(&client).await.unwrap();
        assert_eq!(result, HashMap::default());
    }

    use alloy_consensus::Header;
    use n42_primitives::Validator;
    use reth_provider::providers::BlockchainProvider;
    use reth_provider::test_utils::{create_test_provider_factory, MockNodeTypesWithDB};
    use reth_provider::BeaconProviderWriter;

    type TestProvider = BlockchainProvider<MockNodeTypesWithDB>;

    const TIP: B256 = B256::repeat_byte(0x77);

    fn provider() -> TestProvider {
        let factory = create_test_provider_factory();
        let tip = reth_primitives_traits::SealedHeader::new(Header::default(), TIP);
        BlockchainProvider::with_latest(factory, tip).expect("provider")
    }

    fn beacon_ext(
        provider: TestProvider,
    ) -> (
        ConsensusBeaconExt<NoopConsensus, TestProvider>,
        mpsc::Receiver<BlockVerifyResult>,
    ) {
        let (verification_tx, verification_rx) = mpsc::channel(2);
        let (router_tx, _router_rx) = mpsc::channel(2);
        (
            ConsensusBeaconExt { consensus: NoopConsensus::default(), provider, verification_tx, router_tx },
            verification_rx,
        )
    }

    fn state_with_validator(pubkey: BLSPubkey, effective_balance: u64) -> BeaconState {
        let mut state = BeaconState::new();
        state
            .validators_store
            .push(Validator {
                pubkey,
                effective_balance,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                ..Default::default()
            })
            .unwrap();
        state.balances_store.push(effective_balance + 5).unwrap();
        state.inactivity_scores_store.push(3).unwrap();
        state.validators = state.validators_store.root();
        state.validators_len = 1;
        state.balances = state.balances_store.root();
        state.balances_len = 1;
        state.inactivity_scores = state.inactivity_scores_store.root();
        state.inactivity_scores_len = 1;
        state
    }

    /// Files `state` under the beacon block that the latest eth1 block maps to.
    fn file_latest_state(provider: &TestProvider, state: BeaconState) -> B256 {
        let beacon_hash = B256::repeat_byte(0xB1);
        provider.save_beacon_block_hash_by_eth1_hash(&TIP, beacon_hash).unwrap();
        provider.save_beacon_state_by_hash(&beacon_hash, state).unwrap();
        beacon_hash
    }

    #[test]
    fn submit_verification_forwards_the_result_to_the_miner_channel() {
        let (ext, mut rx) = beacon_ext(provider());
        let hash = B256::repeat_byte(5);
        ext.submit_verification("pk".into(), "sig".into(), AttestationData::default(), hash).unwrap();
        let got = rx.try_recv().expect("forwarded");
        assert_eq!(got.pubkey, "pk");
        assert_eq!(got.signature, "sig");
        assert_eq!(got.block_hash, hash);
    }

    #[test]
    fn submit_verification_with_a_full_channel_still_answers_ok() {
        let (ext, mut rx) = beacon_ext(provider());
        for _ in 0..4 {
            ext.submit_verification("pk".into(), "sig".into(), AttestationData::default(), B256::ZERO)
                .expect("a full channel drops the result, not the call");
        }
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        assert_eq!(n, 2, "only the channel's capacity is delivered");
    }

    #[test]
    fn beacon_block_and_state_lookups_by_hash_return_what_was_stored() {
        let provider = provider();
        let (ext, _rx) = beacon_ext(provider.clone());
        let hash = B256::repeat_byte(0xA1);
        assert_eq!(ext.get_beacon_block_by_hash(hash).unwrap(), None);
        assert_eq!(ext.get_beacon_state_by_beacon_block_hash(hash).unwrap(), None);
        assert_eq!(ext.get_beacon_block_hash_by_eth1_hash(hash).unwrap(), None);

        let block = BeaconBlock { slot: 9, ..Default::default() };
        provider.save_beacon_block_by_hash(&hash, block.clone()).unwrap();
        let mut state = BeaconState::new();
        state.slot = 12;
        provider.save_beacon_state_by_hash(&hash, state).unwrap();
        provider.save_beacon_block_hash_by_eth1_hash(&hash, B256::repeat_byte(0xA2)).unwrap();

        assert_eq!(ext.get_beacon_block_by_hash(hash).unwrap(), Some(block));
        assert_eq!(ext.get_beacon_state_by_beacon_block_hash(hash).unwrap().unwrap().slot, 12);
        assert_eq!(ext.get_beacon_block_hash_by_eth1_hash(hash).unwrap(), Some(B256::repeat_byte(0xA2)));
    }

    #[test]
    fn lookups_by_number_walk_eth1_hash_to_beacon_hash_to_the_object() {
        let provider = provider();
        let (ext, _rx) = beacon_ext(provider.clone());
        let id = BlockId::latest();
        // No mapping filed yet: both lookups stop at the first missing link.
        assert_eq!(ext.get_beacon_block_by_number(id).unwrap(), None);
        assert_eq!(ext.get_beacon_state_by_number(id).unwrap(), None);

        let block_hash = file_latest_state(&provider, BeaconState::new());
        // A mapping without a stored block still answers None for the block.
        assert_eq!(ext.get_beacon_block_by_number(id).unwrap(), None);
        provider.save_beacon_block_by_hash(&block_hash, BeaconBlock { slot: 4, ..Default::default() }).unwrap();
        assert_eq!(ext.get_beacon_block_by_number(id).unwrap().unwrap().slot, 4);
        assert!(ext.get_beacon_state_by_number(id).unwrap().is_some());
    }

    #[test]
    fn an_unknown_block_number_has_no_beacon_object() {
        let (ext, _rx) = beacon_ext(provider());
        let id = BlockId::number(123_456);
        assert_eq!(ext.get_beacon_block_by_number(id).unwrap(), None);
        assert_eq!(ext.get_beacon_state_by_number(id).unwrap(), None);
    }

    #[test]
    fn a_validator_is_reported_with_its_balances_and_zero_timestamps_without_headers() {
        let provider = provider();
        let pubkey = BLSPubkey::repeat_byte(0x42);
        file_latest_state(&provider, state_with_validator(pubkey, 32_000_000_000));
        let (ext, _rx) = beacon_ext(provider);
        let info = ext.get_beacon_validator_by_pubkey(pubkey).unwrap().expect("known validator");
        assert_eq!(info.effective_balance, 32_000_000_000);
        assert_eq!(info.balance_in_beacon, 32_000_000_005);
        assert_eq!(info.inactivity_score, 3);
        assert_eq!(info.activation_timestamp, 0);
        assert_eq!(info.exit_timestamp, 0);
        assert_eq!(ext.get_beacon_validator_by_pubkey(BLSPubkey::repeat_byte(1)).unwrap(), None);
    }

    #[test]
    fn a_validator_lookup_without_a_state_is_none() {
        let (ext, _rx) = beacon_ext(provider());
        assert_eq!(ext.get_beacon_validator_by_pubkey(BLSPubkey::repeat_byte(1)).unwrap(), None);
    }

    #[test]
    fn the_total_effective_balance_needs_a_state_and_sums_active_validators() {
        let provider = provider();
        let (ext, _rx) = beacon_ext(provider.clone());
        let err = ext.get_total_effective_balance().unwrap_err();
        assert_eq!(err.code(), INTERNAL_ERROR_CODE);
        assert!(err.message().contains("beacon state not found"), "{err}");

        file_latest_state(&provider, state_with_validator(BLSPubkey::repeat_byte(2), 32_000_000_000));
        assert_eq!(ext.get_total_effective_balance().unwrap(), 32_000_000_000);
    }

    #[test]
    fn get_snapshot_of_an_unknown_block_goes_through_the_consensus_engine() {
        let ext = ConsensusExt { consensus: NoopConsensus::default(), provider: provider() };
        // The noop engine answers every snapshot request with the default one.
        assert_eq!(ext.get_snapshot(5).unwrap(), Snapshot::default());
        assert!(ext.proposals().unwrap().is_empty());
        ext.propose(Address::repeat_byte(1), true).unwrap();
        ext.discard(Address::repeat_byte(1)).unwrap();
    }

    async fn start_server() -> std::net::SocketAddr {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let consensus = NoopConsensus::default();
        let provider = NoopProvider::default();
        let api = ConsensusExt {
            consensus,
            provider,
        };
        let server_handle = server.start(api.into_rpc());

        tokio::spawn(server_handle.stopped());

        addr
    }
}
