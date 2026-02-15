// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Health monitoring for gateway connections.
//!
//! Tracks connection health for both the miner upstream connection
//! and individual mobile validator connections.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Health status of a connection
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Tracks health metrics for a single connection
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    pub last_message_at: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub errors: u64,
    pub latency_ms: Option<u64>,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            last_message_at: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            errors: 0,
            latency_ms: None,
        }
    }
}

impl ConnectionMetrics {
    pub fn record_sent(&mut self) {
        self.messages_sent += 1;
        self.last_message_at = Instant::now();
    }

    pub fn record_received(&mut self) {
        self.messages_received += 1;
        self.last_message_at = Instant::now();
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    pub fn health(&self, timeout: Duration) -> ConnectionHealth {
        if self.last_message_at.elapsed() > timeout {
            ConnectionHealth::Unhealthy
        } else if self.errors > self.messages_received / 10 {
            ConnectionHealth::Degraded
        } else {
            ConnectionHealth::Healthy
        }
    }
}

/// Aggregated health status for the gateway
#[derive(Debug)]
pub struct GatewayHealth {
    /// Miner connection status
    pub miner_connection: ConnectionHealth,
    /// Total connected validators
    pub connected_validators: usize,
    /// Number of healthy validator connections
    pub healthy_validators: usize,
    /// Number of degraded validator connections
    pub degraded_validators: usize,
    /// Number of unhealthy validator connections
    pub unhealthy_validators: usize,
    /// Blocks processed in last epoch
    pub blocks_processed: u64,
    /// Signatures aggregated in last epoch
    pub signatures_aggregated: u64,
}

/// Health checker that periodically evaluates connection health
pub struct HealthChecker {
    check_interval: Duration,
    connection_timeout: Duration,
    miner_metrics: ConnectionMetrics,
    validator_metrics: HashMap<String, ConnectionMetrics>,
}

impl HealthChecker {
    pub fn new(check_interval_secs: u64) -> Self {
        Self {
            check_interval: Duration::from_secs(check_interval_secs),
            connection_timeout: Duration::from_secs(check_interval_secs * 3),
            miner_metrics: ConnectionMetrics::default(),
            validator_metrics: HashMap::new(),
        }
    }

    pub fn miner_metrics_mut(&mut self) -> &mut ConnectionMetrics {
        &mut self.miner_metrics
    }

    pub fn validator_metrics_mut(&mut self, pubkey_hex: &str) -> &mut ConnectionMetrics {
        self.validator_metrics
            .entry(pubkey_hex.to_string())
            .or_default()
    }

    pub fn remove_validator(&mut self, pubkey_hex: &str) {
        self.validator_metrics.remove(pubkey_hex);
    }

    /// Get current gateway health snapshot
    pub fn check(&self) -> GatewayHealth {
        let miner_health = self.miner_metrics.health(self.connection_timeout);

        let mut healthy = 0usize;
        let mut degraded = 0usize;
        let mut unhealthy = 0usize;

        for metrics in self.validator_metrics.values() {
            match metrics.health(self.connection_timeout) {
                ConnectionHealth::Healthy => healthy += 1,
                ConnectionHealth::Degraded => degraded += 1,
                ConnectionHealth::Unhealthy => unhealthy += 1,
            }
        }

        GatewayHealth {
            miner_connection: miner_health,
            connected_validators: self.validator_metrics.len(),
            healthy_validators: healthy,
            degraded_validators: degraded,
            unhealthy_validators: unhealthy,
            blocks_processed: 0,
            signatures_aggregated: 0,
        }
    }

    /// Clean up unhealthy connections that haven't sent data in a long time
    pub fn cleanup_stale(&mut self) -> Vec<String> {
        let stale_timeout = self.connection_timeout * 2;
        let stale: Vec<String> = self
            .validator_metrics
            .iter()
            .filter(|(_, m)| m.last_message_at.elapsed() > stale_timeout)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &stale {
            self.validator_metrics.remove(key);
            debug!(pubkey = %key, "removed stale validator metrics");
        }

        stale
    }
}
