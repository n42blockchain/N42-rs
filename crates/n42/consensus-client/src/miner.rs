//! Contains the implementation of the mining mode for the local engine.

use reth_beacon_consensus::BeaconConsensusEngineHandle;
use reth_node_types::NodeTypesWithEngine;
use reth_consensus::Consensus;
use std::sync::Arc;
use reth_node_api::{FullNodeComponents,  FullNodeTypes};
use alloy_primitives::{TxHash, B256, U128, U256, BlockNumber};
use alloy_rpc_types_engine::{CancunPayloadFields, ExecutionPayloadSidecar, ForkchoiceState, PayloadStatus};
use eyre::OptionExt;
use futures_util::{stream::Fuse, StreamExt};
use reth_beacon_consensus::{BeaconEngineMessage, ForkchoiceStatus};
use reth_chainspec::EthereumHardforks;
use reth_engine_primitives::{EngineApiMessageVersion, EngineTypes};
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{
    BuiltPayload, PayloadAttributesBuilder, PayloadBuilder, PayloadKind, PayloadTypes,
};
use reth_provider::{TdProvider, BlockReader, ChainSpecProvider};
use reth_rpc_types_compat::engine::payload::block_to_payload;
use reth_transaction_pool::TransactionPool;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, UNIX_EPOCH},
    thread,
    hash::Hash,
};
use reth_eth_wire_types::NewBlock;
use reth_network::NetworkHandle;
use reth_network_api::NetworkEvent;
use reth_tokio_util::EventStream;
use tokio::{
    sync::{mpsc::UnboundedSender, oneshot},
    time::{Interval, sleep},
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info};

/// A mining mode for the local dev engine.
#[derive(Debug)]
pub enum MiningMode {
    /// In this mode a block is built as soon as
    /// a valid transaction reaches the pool.
    Instant(Fuse<ReceiverStream<TxHash>>),
    /// In this mode a block is built at a fixed interval.
    Interval(Interval),
    NoMining,
}

impl MiningMode {
    /// Constructor for a [`MiningMode::Instant`]
    pub fn instant<Pool: TransactionPool>(pool: Pool) -> Self {
        let rx = pool.pending_transactions_listener();
        Self::Instant(ReceiverStream::new(rx).fuse())
    }

    /// Constructor for a [`MiningMode::Interval`]
    pub fn interval(duration: Duration) -> Self {
        let start = tokio::time::Instant::now() + duration;
        Self::Interval(tokio::time::interval_at(start, duration))
    }
}

impl Future for MiningMode {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this {
            Self::Instant(rx) => {
                // drain all transactions notifications
                if let Poll::Ready(Some(_)) = rx.poll_next_unpin(cx) {
                    return Poll::Ready(())
                }
                Poll::Pending
            }
            Self::Interval(interval) => {
                if interval.poll_tick(cx).is_ready() {
                    return Poll::Ready(())
                }
                Poll::Pending
            }
            Self::NoMining => {
                Poll::Pending
            }
        }
    }
}

/// Local miner advancing the chain/
#[derive(Debug)]
pub struct N42Miner<EngineT: EngineTypes, Provider, B, Network> {
    /// Provider to read the current tip of the chain.
    provider: Provider,
    /// The payload attribute builder for the engine
    payload_attributes_builder: B,

    /// beacon engine handle
    beacon_engine_handle: BeaconConsensusEngineHandle<EngineT>,
    /// The mining mode for the engine
    mode: MiningMode,
    /// The payload builder for the engine
    payload_builder: PayloadBuilderHandle<EngineT>,
    /// Timestamp for the next block.
    safe_block_hash: B256,
    /// full network  for announce block
    network: Network,
    new_block_event_stream: EventStream<NewBlock>,
    network_event_stream: EventStream<NetworkEvent>,
    consensus: Arc<dyn Consensus>,
}

impl<EngineT, Provider, B, Network> N42Miner<EngineT, Provider, B, Network>
where
    EngineT: EngineTypes,
    Provider: TdProvider + BlockReader + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
    B: PayloadAttributesBuilder<<EngineT as PayloadTypes>::PayloadAttributes>,
    Network: reth_network_api::FullNetwork,
{
    /// Spawns a new [`N42Miner`] with the given parameters.
    pub fn spawn_new(
        provider: Provider,
        payload_attributes_builder: B,
        beacon_engine_handle: BeaconConsensusEngineHandle<EngineT>,
        mode: MiningMode,
        payload_builder: PayloadBuilderHandle<EngineT>,
        network: Network,
        consensus: Arc<dyn Consensus>,
    ) {
        let latest_header =
            provider.sealed_header(provider.best_block_number().unwrap()).unwrap().unwrap();
        let latest_td = consensus.total_difficulty(latest_header.hash_slow());

        let new_block_event_stream = network.subscribe_block();
        let network_event_stream = network.event_listener();
        let miner = Self {
            provider,
            payload_attributes_builder,
            beacon_engine_handle,
            mode,
            payload_builder,
            safe_block_hash: latest_header.hash(),
            network,
            new_block_event_stream,
            network_event_stream,
            consensus,
        };

        // Spawn the miner
        tokio::spawn(miner.run());
    }

    /// Runs the [`N42Miner`] in a loop, polling the miner and building payloads.
    async fn run(mut self) {
        if let Ok(all_peers) = self.network.get_all_peers().await {
            info!(target: "consensus-client", "all_peers={:?}", all_peers);
                /*
            all_peers.iter().for_each(|peer|
                if self.max_td < peer.status.total_difficulty {
                    self.max_td = peer.status.total_difficulty;
                    self.max_td_hash = peer.status.blockhash;
                }
            );
                */
            //info!(target: "consensus-client", max_td=?self.max_td, max_td_hash=?self.max_td_hash);
        }
        if let fetch_client = self.network.fetch_client().await {
        }
        let mut fcu_interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                // Wait for the interval or the pool to receive a transaction
                _ = &mut self.mode => {
                    if let Err(e) = self.advance().await {
                        error!(target: "consensus-client", "Error advancing the chain: {:?}", e);
                    }
                }
                new_block_event = &mut self.new_block_event_stream.next() => {
                    info!(target: "consensus-client", "new_block_event={:?}", new_block_event);
                    if let Some(new_block) = new_block_event {
                        let (max_td, _) = self.max_td_and_hash();
                        info!(target: "consensus-client", ?max_td, new_block_td=?U256::from(new_block.td));
                        if max_td < U256::from(new_block.td) {
                            match self.insert_block(&new_block).await {
                                Ok(_) => {
                                }
                                Err(e) => {
                                    error!(target: "consensus-client", "Error validating and inserting the block: {:?}", e);
                                }
                            }
                        }
                    }
                }
                network_event = &mut self.network_event_stream.next() => {
                    info!(target: "consensus-client", "network_event={:?}", network_event);
                    if let Some(network_event) = network_event {
                        match network_event {
                            NetworkEvent::SessionEstablished {status, ..} => {
                                /*
                                if self.max_td < status.total_difficulty {
                                    self.max_td = status.total_difficulty;
                                    self.max_td_hash = status.blockhash;
                                }
                                */
                            },
                            _ => { },
                        }
                    }
                }
            }
        }
    }

    /// Returns current forkchoice state.
    fn forkchoice_state(&self) -> ForkchoiceState {
        let (_, max_td_hash) = self.max_td_and_hash();
        ForkchoiceState {
            head_block_hash: max_td_hash,
            safe_block_hash: self.safe_block_hash,
            finalized_block_hash: self.safe_block_hash,
        }
    }

    /// Sends a FCU to the engine.
    async fn update_forkchoice_state(&self) -> eyre::Result<ForkchoiceStatus> {
        let res = self.beacon_engine_handle.fork_choice_updated(
            self.forkchoice_state(),
            None,
            EngineApiMessageVersion::default(),
        ).await?;

        Ok(res.payload_status.status.into())
    }

    /// Generates payload attributes for a new block, passes them to FCU and inserts built payload
    /// through newPayload.
    async fn advance(&mut self) -> eyre::Result<()> {
        let header =
            self.provider.sealed_header(self.provider.best_block_number().unwrap()).unwrap().unwrap();
        let interval = match self.mode {
            MiningMode::Interval(ref v) => {
                info!(?v, "advance interval value");
                v.period().as_secs()
            }
            _ => 1,
        };
        info!(target: "consensus-client", interval, "advance");
        let now =
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("cannot be earlier than UNIX_EPOCH")
                .as_secs();
        let timestamp = std::cmp::max(
            header.timestamp + interval as u64,
            now,
        );
        if timestamp > now {
            sleep(Duration::from_secs(timestamp - now)).await;
        }
        info!(target: "consensus-client", timestamp, "advance: PayloadAttributes timestamp");

        let mut res = self.beacon_engine_handle.fork_choice_updated(
                self.forkchoice_state(),
                Some(self.payload_attributes_builder.build(timestamp)),
                EngineApiMessageVersion::default(),
            ).await?;
        if !res.payload_status.is_valid() {
            eyre::bail!("Error advancing the chain: fork_choice_updated with PayloadAttributes status is not valid: {:?}", res);
        }
        let payload_id = res.payload_id.ok_or_eyre("No payload id")?;

        let payload = match self
            .payload_builder
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
        {
            Some(Ok(payload)) => payload,
            Some(Err(err)) => {
                eyre::bail!("Failed to resolve payload: {}", err);
            }
            None => {
                eyre::bail!("No payload");
            }
        };

        let block = payload.block();
        let max_td = self.consensus.total_difficulty(block.header.hash());
        info!(target: "consensus-client", ?max_td, "advance: new_block hash {:?}", block.header.hash());

        match self.beacon_engine_handle.fork_choice_updated(
            self.forkchoice_state_with_head(block.hash()),
            None,
            EngineApiMessageVersion::default(),
        ).await {
            Ok(v) => {
                info!(target: "consensus-client", "forkchoice(block hash) status {:?}", v);
            }
            Err(e) => {
                error!(target: "consensus-client", "Error updating fork choice(block hash): {:?}", e);
            }
        }


        self.network.announce_block(NewBlock{block: block.clone().unseal(), td: max_td.to::<U128>()}, block.hash());

        Ok(())
    }

    fn forkchoice_state_with_head(&self, head_block_hash: B256) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash,
            safe_block_hash: self.safe_block_hash,
            finalized_block_hash: self.safe_block_hash,
        }
    }

    async fn insert_block(&mut self, new_block: &NewBlock) -> eyre::Result<()> {
        let block = new_block.clone().block.seal_slow();
        info!(target: "consensus-client", "new_block hash {:?}", block.header.hash());

        let cancun_fields =
            self.provider.chain_spec().is_cancun_active_at_timestamp(block.timestamp).then(|| {
                CancunPayloadFields {
                    parent_beacon_block_root: block.parent_beacon_block_root.unwrap(),
                    versioned_hashes: block.blob_versioned_hashes().into_iter().copied().collect(),
                }
            });

        let res = self.beacon_engine_handle.new_payload(
            block_to_payload(block.clone()),
            cancun_fields
                .map(ExecutionPayloadSidecar::v3)
                .unwrap_or_else(ExecutionPayloadSidecar::none),
        ).await?;
        info!(target: "consensus-client", "new_payload res={:?}", res);
        if res.is_invalid() {
            eyre::bail!("new block is invalid: {}", res);
        }

        match self.beacon_engine_handle.fork_choice_updated(
            self.forkchoice_state_with_head(block.hash()),
            None,
            EngineApiMessageVersion::default(),
        ).await {
            Ok(v) => {
                info!(target: "consensus-client", "forkchoice(block hash) status {:?}", v);
            }
            Err(e) => {
                error!(target: "consensus-client", "Error updating fork choice(block hash): {:?}", e);
            }
        }

        Ok(())
    }

    fn max_td_and_hash(&self) -> (U256, B256) {
        let header =
            self.provider.sealed_header(self.provider.best_block_number().unwrap()).unwrap().unwrap();
        let td = self.consensus.total_difficulty(header.hash_slow());
        info!(hash=?header.hash(), ?td, header.number, header.timestamp, "max_td_and_hash");
        (td, header.hash())
    }
}
