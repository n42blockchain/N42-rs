//! Contains the implementation of the mining mode for the local engine.

use reth_beacon_consensus::{
    BeaconConsensusEngineHandle,
};
use reth_node_types::NodeTypesWithEngine;
use reth_node_api::{FullNodeComponents,  FullNodeTypes};
use alloy_primitives::{TxHash, B256, U128, U256};
use alloy_rpc_types_engine::{CancunPayloadFields, ExecutionPayloadSidecar, ForkchoiceState};
use eyre::OptionExt;
use futures_util::{stream::Fuse, StreamExt};
use reth_beacon_consensus::{BeaconEngineMessage, ForkchoiceStatus};
use reth_chainspec::EthereumHardforks;
use reth_engine_primitives::{EngineApiMessageVersion, EngineTypes};
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{
    BuiltPayload, PayloadAttributesBuilder, PayloadBuilder, PayloadKind, PayloadTypes,
};
use reth_provider::{BlockReader, ChainSpecProvider};
use reth_rpc_types_compat::engine::payload::block_to_payload;
use reth_transaction_pool::TransactionPool;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, UNIX_EPOCH},
};
use reth_eth_wire_types::NewBlock;
use reth_network::NetworkHandle;
use reth_network_api::NetworkEvent;
use reth_tokio_util::EventStream;
use tokio::{
    sync::{mpsc::UnboundedSender, oneshot},
    time::Interval,
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
    last_timestamp: u64,
    /// Stores latest mined blocks.
    last_block_hashes: Vec<B256>,
    /// full network  for announce block
    network: Network,
    new_block_event_stream: EventStream<NewBlock>,
    network_event_stream: EventStream<NetworkEvent>,
}

impl<EngineT, Provider, B, Network> N42Miner<EngineT, Provider, B, Network>
where
    EngineT: EngineTypes,
    Provider: BlockReader + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
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
    ) {
        let latest_header =
            provider.sealed_header(provider.best_block_number().unwrap()).unwrap().unwrap();

        let new_block_event_stream = network.subscribe_block();
        let network_event_stream = network.event_listener();
        let miner = Self {
            provider,
            payload_attributes_builder,
            beacon_engine_handle,
            mode,
            payload_builder,
            last_timestamp: latest_header.timestamp,
            last_block_hashes: vec![latest_header.hash()],
            network,
            new_block_event_stream,
            network_event_stream,
        };

        // Spawn the miner
        tokio::spawn(miner.run());
    }

    /// Runs the [`N42Miner`] in a loop, polling the miner and building payloads.
    async fn run(mut self) {
        if let all_peers = self.network.get_all_peers().await {
            info!(target: "consensus-client", "all_peers={:?}", all_peers);
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
                        if let Err(e) = self.insert_block(new_block).await {
                            error!(target: "consensus-client", "Error validating and inserting the block: {:?}", e);
                        }
                    }
                }
                network_event = &mut self.network_event_stream.next() => {
                    info!(target: "consensus-client", "network_event={:?}", network_event);
                }
            }
        }
    }

    /// Returns current forkchoice state.
    fn forkchoice_state(&self) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: *self.last_block_hashes.last().expect("at least 1 block exists"),
            safe_block_hash: *self
                .last_block_hashes
                .get(self.last_block_hashes.len().saturating_sub(32))
                .expect("at least 1 block exists"),
            finalized_block_hash: *self
                .last_block_hashes
                .get(self.last_block_hashes.len().saturating_sub(64))
                .expect("at least 1 block exists"),
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
        let timestamp = std::cmp::max(
            self.last_timestamp + 1,
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("cannot be earlier than UNIX_EPOCH")
                .as_secs(),
        );

        let res = self.beacon_engine_handle.fork_choice_updated(
            self.forkchoice_state(),
            Some(self.payload_attributes_builder.build(timestamp)),
            EngineApiMessageVersion::default(),
        ).await?;
        if !res.payload_status.is_valid() {
            eyre::bail!("Invalid payload status")
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

        let cancun_fields =
            self.provider.chain_spec().is_cancun_active_at_timestamp(block.timestamp).then(|| {
                CancunPayloadFields {
                    parent_beacon_block_root: block.parent_beacon_block_root.unwrap(),
                    versioned_hashes: block.blob_versioned_hashes().into_iter().copied().collect(),
                }
            });

        let res = self.beacon_engine_handle.new_payload(
            block_to_payload(payload.block().clone()),
            cancun_fields
                .map(ExecutionPayloadSidecar::v3)
                .unwrap_or_else(ExecutionPayloadSidecar::none),
        ).await?;
        if !res.is_valid() {
            eyre::bail!("Invalid payload")
        }

        self.last_timestamp = timestamp;
        self.last_block_hashes.push(block.hash());
        // ensure we keep at most 64 blocks
        if self.last_block_hashes.len() > 64 {
            self.last_block_hashes =
                self.last_block_hashes.split_off(self.last_block_hashes.len() - 64);
        }

        //announce block
        //todo td
        self.network.announce_block(NewBlock{block: block.clone().unseal(), td: U128::MAX}, block.hash());

        Ok(())
    }

    fn forkchoice_state_with_head(&self, head_block_hash: B256) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash,
            safe_block_hash: *self
                .last_block_hashes
                .get(self.last_block_hashes.len().saturating_sub(32))
                .expect("at least 1 block exists"),
            finalized_block_hash: *self
                .last_block_hashes
                .get(self.last_block_hashes.len().saturating_sub(64))
                .expect("at least 1 block exists"),
        }
    }

    async fn insert_block(&mut self, new_block: NewBlock) -> eyre::Result<()> {
        let block = new_block.clone().block.seal_slow();
        info!(target: "consensus-client", "new_block hash {:?}", block.header.hash());

        match self.beacon_engine_handle.fork_choice_updated(
            self.forkchoice_state_with_head(block.parent_hash),
            None,
            EngineApiMessageVersion::default(),
        ).await {
            Ok(v) => {
                info!(target: "consensus-client", "forkchoice status {:?}", v);
            }
            Err(e) => {
                error!(target: "consensus-client", "Error updating fork choice: {:?}", e);
            }
        }

        let block = new_block.clone().block.seal_slow();
        let cancun_fields =
            self.provider.chain_spec().is_cancun_active_at_timestamp(block.timestamp).then(|| {
                CancunPayloadFields {
                    parent_beacon_block_root: block.parent_beacon_block_root.unwrap(),
                    versioned_hashes: block.blob_versioned_hashes().into_iter().copied().collect(),
                }
            });

        let res = self.beacon_engine_handle.new_payload(
            block_to_payload(block),
            cancun_fields
                .map(ExecutionPayloadSidecar::v3)
                .unwrap_or_else(ExecutionPayloadSidecar::none),
        ).await?;
        info!(target: "consensus-client", "new_payload res={:?}", res);

        Ok(())
    }
}
