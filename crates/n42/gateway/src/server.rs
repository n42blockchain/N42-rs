// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! WebSocket server for mobile validator connections.
//!
//! Accepts incoming WS connections from mobile validators,
//! registers their pubkey, forwards UnverifiedBlocks, and
//! collects attestation signatures.

use crate::{GatewayConfig, ValidatorRegistry};
use alloy_primitives::B256;
use n42_clique::{BlockVerifyResult, UnverifiedBlock};
use n42_primitives::BLSPubkey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Tracks an active mobile validator connection
struct ValidatorConnection {
    pubkey: BLSPubkey,
    /// Channel to send blocks to this validator
    block_tx: mpsc::Sender<UnverifiedBlock>,
}

/// WebSocket server managing mobile validator connections
pub struct WsServer {
    config: GatewayConfig,
    /// Registry of connected validators
    registry: Arc<RwLock<ValidatorRegistry>>,
    /// Map from pubkey hex to connection sender
    connections: Arc<RwLock<HashMap<String, mpsc::Sender<UnverifiedBlock>>>>,
    /// Channel to forward collected signatures to aggregator
    signature_tx: mpsc::Sender<BlockVerifyResult>,
}

impl WsServer {
    pub fn new(
        config: GatewayConfig,
        registry: Arc<RwLock<ValidatorRegistry>>,
        signature_tx: mpsc::Sender<BlockVerifyResult>,
    ) -> Self {
        Self {
            config,
            registry,
            connections: Arc::new(RwLock::new(HashMap::new())),
            signature_tx,
        }
    }

    /// Start accepting WebSocket connections.
    pub async fn run(&self) -> eyre::Result<()> {
        let listener = TcpListener::bind(&self.config.ws_listen_addr).await?;
        info!(
            addr = %self.config.ws_listen_addr,
            max_connections = self.config.max_connections,
            "Gateway WS server listening"
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let connections = self.connections.clone();
            let registry = self.registry.clone();
            let signature_tx = self.signature_tx.clone();
            let max_connections = self.config.max_connections;

            tokio::spawn(async move {
                // Check connection limit
                if connections.read().await.len() >= max_connections {
                    warn!(
                        %addr,
                        "rejecting connection: max connections reached"
                    );
                    return;
                }

                debug!(%addr, "new mobile validator connection");

                match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws_stream) => {
                        if let Err(e) =
                            Self::handle_connection(ws_stream, connections, registry, signature_tx)
                                .await
                        {
                            debug!(%addr, ?e, "connection handler error");
                        }
                    }
                    Err(e) => {
                        debug!(%addr, ?e, "WebSocket handshake failed");
                    }
                }
            });
        }
    }

    /// Handle a single validator WebSocket connection.
    async fn handle_connection(
        ws_stream: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        connections: Arc<RwLock<HashMap<String, mpsc::Sender<UnverifiedBlock>>>>,
        registry: Arc<RwLock<ValidatorRegistry>>,
        signature_tx: mpsc::Sender<BlockVerifyResult>,
    ) -> eyre::Result<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // First message should be the validator's pubkey for registration
        let pubkey_hex = match ws_receiver.next().await {
            Some(Ok(Message::Text(text))) => text.to_string(),
            _ => return Err(eyre::eyre!("expected pubkey as first message")),
        };

        let pubkey_bytes = hex::decode(&pubkey_hex)?;
        let mut pubkey = BLSPubkey::default();
        if pubkey_bytes.len() == 48 {
            pubkey.copy_from_slice(&pubkey_bytes);
        } else {
            return Err(eyre::eyre!("invalid pubkey length: {}", pubkey_bytes.len()));
        }

        // Register the validator
        registry.write().await.register(pubkey);

        // Create per-validator block channel
        let (block_tx, mut block_rx) = mpsc::channel::<UnverifiedBlock>(16);
        connections
            .write()
            .await
            .insert(pubkey_hex.clone(), block_tx);

        debug!(pubkey = %pubkey_hex, "validator registered");

        // Bidirectional message loop
        loop {
            tokio::select! {
                // Forward blocks from miner to mobile
                Some(block) = block_rx.recv() => {
                    let json = match serde_json::to_string(&block) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(?e, "failed to serialize block");
                            continue;
                        }
                    };
                    if let Err(e) = ws_sender.send(Message::Text(json.into())).await {
                        debug!(pubkey = %pubkey_hex, ?e, "failed to send block to validator");
                        break;
                    }
                }
                // Receive signatures from mobile
                msg = ws_receiver.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<BlockVerifyResult>(&text) {
                                Ok(result) => {
                                    let _ = signature_tx.send(result).await;
                                }
                                Err(e) => {
                                    debug!(pubkey = %pubkey_hex, ?e, "invalid verification result");
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            debug!(pubkey = %pubkey_hex, "validator disconnected");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Cleanup
        connections.write().await.remove(&pubkey_hex);
        registry.write().await.unregister(&pubkey);
        debug!(pubkey = %pubkey_hex, "validator unregistered");

        Ok(())
    }

    /// Broadcast a block to all connected validators with matching pubkeys.
    pub async fn broadcast_to_validators(
        &self,
        block: &UnverifiedBlock,
        target_pubkeys: &[BLSPubkey],
    ) {
        let connections = self.connections.read().await;
        for pubkey in target_pubkeys {
            let pubkey_hex = hex::encode(pubkey);
            if let Some(tx) = connections.get(&pubkey_hex) {
                if tx.try_send(block.clone()).is_err() {
                    debug!(pubkey = %pubkey_hex, "failed to send block to validator (slow or disconnected)");
                }
            }
        }
    }
}
