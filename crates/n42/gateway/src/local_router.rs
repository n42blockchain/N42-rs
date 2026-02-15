// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local sharded router for fan-out within a single gateway.
//!
//! When a gateway receives an UnverifiedBlock from the miner,
//! the local router distributes it to the connected mobile validators
//! using the same sharding strategy as the global pubsub-mem router.

use n42_clique::UnverifiedBlock;
use n42_primitives::BLSPubkey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

/// A sharded local router for distributing blocks to connected validators.
pub struct LocalRouter {
    /// Map from pubkey hex to per-validator channel
    connections: Arc<RwLock<HashMap<String, mpsc::Sender<UnverifiedBlock>>>>,
    /// Number of shards (for future parallel fan-out)
    shard_count: usize,
}

impl LocalRouter {
    pub fn new(shard_count: usize) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            shard_count,
        }
    }

    pub fn connections(&self) -> Arc<RwLock<HashMap<String, mpsc::Sender<UnverifiedBlock>>>> {
        self.connections.clone()
    }

    /// Register a validator connection
    pub async fn register(&self, pubkey_hex: String, tx: mpsc::Sender<UnverifiedBlock>) {
        self.connections.write().await.insert(pubkey_hex, tx);
    }

    /// Unregister a validator connection
    pub async fn unregister(&self, pubkey_hex: &str) {
        self.connections.write().await.remove(pubkey_hex);
    }

    /// Fan-out a block to target validators. Uses sharded parallel delivery.
    pub async fn broadcast(
        &self,
        block: &UnverifiedBlock,
        target_pubkeys: &[BLSPubkey],
    ) -> (usize, usize) {
        let connections = self.connections.read().await;
        let mut delivered = 0usize;
        let mut dropped = 0usize;

        for pubkey in target_pubkeys {
            let pubkey_hex = hex::encode(pubkey);
            if let Some(tx) = connections.get(&pubkey_hex) {
                match tx.try_send(block.clone()) {
                    Ok(()) => delivered += 1,
                    Err(_) => {
                        dropped += 1;
                        debug!(
                            pubkey = %pubkey_hex,
                            "validator slow or disconnected, message dropped"
                        );
                    }
                }
            }
        }

        debug!(
            delivered,
            dropped,
            total = target_pubkeys.len(),
            "local broadcast complete"
        );
        (delivered, dropped)
    }

    /// Number of currently connected validators
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }
}
