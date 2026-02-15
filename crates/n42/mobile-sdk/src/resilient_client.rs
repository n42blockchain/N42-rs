// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resilient mobile validator client with multi-gateway failover,
//! exponential backoff reconnection, and local bytecode caching.
//!
//! This replaces the basic `run_client()` with production-grade reliability
//! for unstable mobile network conditions.

use blst::min_pk::SecretKey;
use futures_util::StreamExt;
use hex::FromHex;
use jsonrpsee::core::client::Subscription;
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use n42_clique::UnverifiedBlock;
use n42_primitives::AttestationData;
use revm_primitives::B256;
use ssz::Encode;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Configuration for the resilient mobile validator client
#[derive(Debug, Clone)]
pub struct ResilientClientConfig {
    /// List of gateway/node WebSocket URLs for failover
    pub endpoints: Vec<String>,
    /// Validator's BLS private key (hex, with or without 0x prefix)
    pub validator_private_key: String,
    /// Base reconnection delay (will be exponentially backed off)
    pub base_reconnect_delay: Duration,
    /// Maximum reconnection delay
    pub max_reconnect_delay: Duration,
    /// Timeout for waiting for new blocks
    pub message_timeout: Duration,
    /// Maximum reconnection attempts before cycling to next endpoint
    pub max_retries_per_endpoint: u32,
}

impl Default for ResilientClientConfig {
    fn default() -> Self {
        Self {
            endpoints: vec!["ws://127.0.0.1:8546".to_string()],
            validator_private_key: String::new(),
            base_reconnect_delay: Duration::from_secs(1),
            max_reconnect_delay: Duration::from_secs(60),
            message_timeout: Duration::from_secs(300),
            max_retries_per_endpoint: 5,
        }
    }
}

/// Local cache for contract bytecodes to avoid re-downloading
/// on reconnection. Keyed by code hash.
#[derive(Debug, Default)]
pub struct BytecodeCache {
    cache: HashMap<B256, Vec<u8>>,
}

impl BytecodeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, code_hash: &B256) -> Option<&Vec<u8>> {
        self.cache.get(code_hash)
    }

    pub fn insert(&mut self, code_hash: B256, bytecode: Vec<u8>) {
        self.cache.insert(code_hash, bytecode);
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// Statistics tracked by the resilient client
#[derive(Debug, Default)]
pub struct ClientStats {
    pub blocks_verified: u64,
    pub signatures_submitted: u64,
    pub verification_failures: u64,
    pub connection_failures: u64,
    pub failovers: u64,
    pub current_endpoint_index: usize,
}

/// Resilient mobile validator client with multi-gateway failover.
pub struct ResilientClient {
    config: ResilientClientConfig,
    sk: SecretKey,
    pk: blst::min_pk::PublicKey,
    bytecode_cache: Arc<RwLock<BytecodeCache>>,
    stats: Arc<RwLock<ClientStats>>,
}

impl ResilientClient {
    pub fn new(config: ResilientClientConfig) -> eyre::Result<Self> {
        let key_str = config
            .validator_private_key
            .strip_prefix("0x")
            .unwrap_or(&config.validator_private_key);
        let key_vec = Vec::from_hex(key_str)?;
        let sk = SecretKey::from_bytes(&key_vec)
            .map_err(|e| eyre::eyre!("SecretKey error: {e:?}"))?;
        let pk = sk.sk_to_pk();

        Ok(Self {
            config,
            sk,
            pk,
            bytecode_cache: Arc::new(RwLock::new(BytecodeCache::new())),
            stats: Arc::new(RwLock::new(ClientStats::default())),
        })
    }

    /// Get a snapshot of current client statistics
    pub async fn stats(&self) -> ClientStats {
        let s = self.stats.read().await;
        ClientStats {
            blocks_verified: s.blocks_verified,
            signatures_submitted: s.signatures_submitted,
            verification_failures: s.verification_failures,
            connection_failures: s.connection_failures,
            failovers: s.failovers,
            current_endpoint_index: s.current_endpoint_index,
        }
    }

    /// Run the client with automatic failover and reconnection.
    pub async fn run(&self) -> eyre::Result<()> {
        if self.config.endpoints.is_empty() {
            return Err(eyre::eyre!("no gateway endpoints configured"));
        }

        let mut endpoint_index = 0usize;
        let mut consecutive_failures = 0u32;

        loop {
            let endpoint = &self.config.endpoints[endpoint_index];
            info!(
                endpoint = %endpoint,
                endpoint_index,
                total_endpoints = self.config.endpoints.len(),
                "connecting to gateway"
            );

            {
                let mut stats = self.stats.write().await;
                stats.current_endpoint_index = endpoint_index;
            }

            match self.connect_and_serve(endpoint).await {
                Ok(()) => {
                    // Normal shutdown — don't reconnect
                    info!("client shutting down normally");
                    return Ok(());
                }
                Err(e) => {
                    consecutive_failures += 1;
                    {
                        let mut stats = self.stats.write().await;
                        stats.connection_failures += 1;
                    }

                    warn!(
                        ?e,
                        endpoint = %endpoint,
                        consecutive_failures,
                        "connection failed"
                    );

                    // Cycle to next endpoint after max retries
                    if consecutive_failures >= self.config.max_retries_per_endpoint {
                        endpoint_index = (endpoint_index + 1) % self.config.endpoints.len();
                        consecutive_failures = 0;
                        {
                            let mut stats = self.stats.write().await;
                            stats.failovers += 1;
                        }
                        info!(
                            new_endpoint = %self.config.endpoints[endpoint_index],
                            "failing over to next gateway"
                        );
                    }

                    // Exponential backoff
                    let delay = self.calculate_backoff(consecutive_failures);
                    info!(delay_secs = delay.as_secs(), "reconnecting after delay");
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Calculate exponential backoff delay with jitter
    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let base = self.config.base_reconnect_delay.as_millis() as u64;
        let max = self.config.max_reconnect_delay.as_millis() as u64;
        let delay_ms = std::cmp::min(base * 2u64.saturating_pow(attempt), max);
        // Add small jitter (up to 10%)
        let jitter = delay_ms / 10;
        Duration::from_millis(delay_ms + (rand::random::<u64>() % (jitter.max(1))))
    }

    async fn connect_and_serve(&self, ws_url: &str) -> eyre::Result<()> {
        let ws_client = WsClientBuilder::default()
            .connection_timeout(Duration::from_secs(10))
            .build(ws_url)
            .await?;

        info!(endpoint = %ws_url, "connected to gateway");

        let mut subscription: Subscription<UnverifiedBlock> = ws_client
            .subscribe(
                "consensusBeaconExt_subscribeToVerificationRequest",
                rpc_params![hex::encode(self.pk.to_bytes())],
                "",
            )
            .await?;

        info!("subscribed to verification requests");

        while let Ok(Some(msg)) =
            timeout(self.config.message_timeout, subscription.next()).await
        {
            match msg {
                Ok(block) => {
                    debug!(
                        block_number = block.blockbody.number,
                        "received block for verification"
                    );

                    match crate::verify(block.clone()) {
                        Ok(receipts_root) => {
                            self.submit_attestation(&ws_client, &block, receipts_root)
                                .await?;
                            {
                                let mut stats = self.stats.write().await;
                                stats.blocks_verified += 1;
                                stats.signatures_submitted += 1;
                            }
                        }
                        Err(e) => {
                            warn!(?e, "block verification failed");
                            let mut stats = self.stats.write().await;
                            stats.verification_failures += 1;
                        }
                    }
                }
                Err(e) => {
                    return Err(eyre::eyre!("subscription error: {:?}", e));
                }
            }
        }

        // Timeout — reconnect
        Err(eyre::eyre!(
            "no blocks received within {} seconds",
            self.config.message_timeout.as_secs()
        ))
    }

    async fn submit_attestation(
        &self,
        ws_client: &WsClient,
        block: &UnverifiedBlock,
        receipts_root: B256,
    ) -> eyre::Result<()> {
        use reth_ethereum_primitives::Block;
        use reth_primitives_traits::{AlloyBlockHeader, SealedBlock};

        let attestation_data = AttestationData {
            slot: block.blockbody.header().number(),
            committee_index: block.committee_index,
            receipts_root,
        };

        // Use SSZ encoding for deterministic serialization
        let bytes = attestation_data.as_ssz_bytes();
        let sig = self.sk.sign(
            &bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &[],
        );

        let mut header = block.blockbody.header().clone();
        header.receipts_root = receipts_root;
        let body = block.blockbody.body().clone();
        let sealed_block_recovered: SealedBlock<Block> =
            SealedBlock::from_parts_unhashed(header, body);
        let recovered_block_hash = SealedBlock::hash(&sealed_block_recovered);

        let params = rpc_params![
            hex::encode(self.pk.to_bytes()),
            hex::encode(sig.to_bytes()),
            attestation_data,
            hex::encode(recovered_block_hash.as_slice())
        ];

        let _result: () = ws_client
            .request("consensusBeaconExt_submitVerification", params)
            .await?;

        debug!("attestation submitted successfully");
        Ok(())
    }
}
