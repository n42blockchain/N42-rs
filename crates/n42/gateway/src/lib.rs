// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 Gateway Node
//!
//! Sits between APoS Miner nodes (Tier 1) and Mobile Validators (Tier 3)
//! as an intermediate Tier 2 layer for horizontal scaling.
//!
//! Architecture:
//! ```text
//! Tier 1: APoS Miner (IDC, 1-3 nodes)
//!   ↕ TCP binary protocol (<5ms latency)
//! Tier 2: Gateway Nodes (IDC, 50-200 instances)
//!   ↕ WebSocket/TLS (50-200ms latency)
//! Tier 3: Mobile Validators (1M+)
//! ```
//!
//! Each Gateway manages ~20K mobile connections, performing:
//! - Local fan-out of UnverifiedBlocks to managed validators
//! - Intermediate BLS signature aggregation
//! - Health monitoring and connection management

pub mod aggregator;
pub mod health;
pub mod local_router;
pub mod miner_client;
pub mod server;

use n42_primitives::BLSPubkey;
use std::collections::HashSet;

/// Gateway configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// WebSocket listen address for mobile validators (e.g. "0.0.0.0:9100")
    pub ws_listen_addr: String,
    /// Miner TCP endpoint (e.g. "miner.internal:9200")
    pub miner_endpoint: String,
    /// Maximum concurrent mobile connections
    pub max_connections: usize,
    /// Number of local router shards
    pub router_shard_count: usize,
    /// Aggregation batch size before submitting to miner
    pub aggregation_batch_size: usize,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            ws_listen_addr: "0.0.0.0:9100".to_string(),
            miner_endpoint: "127.0.0.1:9200".to_string(),
            max_connections: 20_000,
            router_shard_count: 16,
            aggregation_batch_size: 64,
            health_check_interval_secs: 30,
        }
    }
}

/// Tracks which validators are managed by this gateway
#[derive(Debug, Default)]
pub struct ValidatorRegistry {
    /// Set of pubkeys managed by this gateway
    pubkeys: HashSet<Vec<u8>>,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, pubkey: BLSPubkey) {
        self.pubkeys.insert(pubkey.to_vec());
    }

    pub fn unregister(&mut self, pubkey: &BLSPubkey) {
        self.pubkeys.remove(&pubkey.to_vec());
    }

    pub fn contains(&self, pubkey: &BLSPubkey) -> bool {
        self.pubkeys.contains(&pubkey.to_vec())
    }

    pub fn count(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn pubkeys(&self) -> Vec<BLSPubkey> {
        self.pubkeys
            .iter()
            .map(|pk| {
                let mut key = BLSPubkey::default();
                key.copy_from_slice(pk);
                key
            })
            .collect()
    }
}
