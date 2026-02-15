// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client for connecting to APoS Miner node.
//!
//! Receives UnverifiedBlocks from the miner and submits
//! aggregated attestations back.

use crate::{GatewayConfig, ValidatorRegistry};
use alloy_primitives::B256;
use n42_clique::UnverifiedBlock;
use n42_primitives::{AttestationData, BLSPubkey, CommitteeIndex};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Message from miner to gateway
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MinerToGateway {
    /// New block to distribute to validators
    NewBlock {
        block: UnverifiedBlock,
        target_pubkeys: Vec<BLSPubkey>,
    },
    /// Miner requests gateway's registered pubkeys
    PubkeyRequest,
}

/// Message from gateway to miner
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GatewayToMiner {
    /// Register pubkeys managed by this gateway
    RegisterPubkeys(Vec<BLSPubkey>),
    /// Submit a partial aggregate attestation
    PartialAggregate {
        committee_index: CommitteeIndex,
        aggregate_signature: Vec<u8>,
        pubkeys: Vec<Vec<u8>>,
        validator_indices: Vec<u64>,
        attestation_data: AttestationData,
        block_hash: B256,
    },
}

/// Client connection to the APoS Miner.
pub struct MinerClient {
    config: GatewayConfig,
    registry: Arc<RwLock<ValidatorRegistry>>,
    /// Channel to forward received blocks for local distribution
    block_tx: mpsc::Sender<(UnverifiedBlock, Vec<BLSPubkey>)>,
    /// Channel to receive aggregated results to submit to miner
    aggregate_rx: mpsc::Receiver<GatewayToMiner>,
}

impl MinerClient {
    pub fn new(
        config: GatewayConfig,
        registry: Arc<RwLock<ValidatorRegistry>>,
        block_tx: mpsc::Sender<(UnverifiedBlock, Vec<BLSPubkey>)>,
        aggregate_rx: mpsc::Receiver<GatewayToMiner>,
    ) -> Self {
        Self {
            config,
            registry,
            block_tx,
            aggregate_rx,
        }
    }

    /// Connect to the miner and maintain the bidirectional stream.
    ///
    /// On connection:
    /// 1. Register managed pubkeys with the miner
    /// 2. Receive UnverifiedBlocks and forward to local router
    /// 3. Submit PartialAggregates back to miner
    pub async fn run(mut self) -> eyre::Result<()> {
        info!(
            endpoint = %self.config.miner_endpoint,
            "connecting to miner"
        );

        // Connection loop with reconnection
        loop {
            match self.connect_and_serve().await {
                Ok(()) => {
                    info!("miner connection closed normally");
                    break;
                }
                Err(e) => {
                    warn!(?e, "miner connection error, reconnecting in 5s");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }

        Ok(())
    }

    async fn connect_and_serve(&mut self) -> eyre::Result<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let (ws_stream, _) =
            tokio_tungstenite::connect_async(&self.config.miner_endpoint).await?;
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        info!("connected to miner, registering pubkeys");

        // Register our managed pubkeys
        let pubkeys = self.registry.read().await.pubkeys();
        let register_msg = GatewayToMiner::RegisterPubkeys(pubkeys);
        let json = serde_json::to_string(&register_msg)?;
        ws_sender.send(Message::Text(json.into())).await?;

        loop {
            tokio::select! {
                // Receive blocks from miner
                msg = ws_receiver.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<MinerToGateway>(&text) {
                                Ok(MinerToGateway::NewBlock { block, target_pubkeys }) => {
                                    debug!(
                                        block_number = block.blockbody.number,
                                        num_pubkeys = target_pubkeys.len(),
                                        "received block from miner"
                                    );
                                    let _ = self.block_tx.send((block, target_pubkeys)).await;
                                }
                                Ok(MinerToGateway::PubkeyRequest) => {
                                    let pubkeys = self.registry.read().await.pubkeys();
                                    let msg = GatewayToMiner::RegisterPubkeys(pubkeys);
                                    let json = serde_json::to_string(&msg)?;
                                    ws_sender.send(Message::Text(json.into())).await?;
                                }
                                Err(e) => {
                                    debug!(?e, "failed to parse miner message");
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            return Err(eyre::eyre!("miner connection closed"));
                        }
                        _ => {}
                    }
                }
                // Submit aggregated results to miner
                Some(aggregate) = self.aggregate_rx.recv() => {
                    let json = serde_json::to_string(&aggregate)?;
                    if let Err(e) = ws_sender.send(Message::Text(json.into())).await {
                        warn!(?e, "failed to send aggregate to miner");
                        return Err(e.into());
                    }
                }
            }
        }
    }
}
