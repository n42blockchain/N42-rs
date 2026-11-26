// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `debug_traceTransaction` answered from a once-per-block trace
//! (`docs/EXPLORER_RPC_PERF.md`).
//!
//! reth traces transaction `i` of a block by replaying transactions
//! `0..i` on the parent state first, so an explorer that traces every
//! transaction of a block (Blockscout's geth variant: batches of
//! `debug_traceTransaction` with `callTracer`) costs O(n^2) executions per
//! block: 0.85 blocks/s at ~1,000 transactions a block where
//! `debug_traceBlockByNumber` does 135. Here a request for a transaction of a
//! block with at least [`TraceCacheConfig::min_block_txs`] transactions,
//! under a deterministic built-in tracer, traces the whole block once
//! (`debug_traceBlock`, the same replay with the same tracer options), keeps
//! every transaction's result keyed by (block hash, options) and answers from
//! it; concurrent requests for one block wait for that one trace. Each result
//! is the one the per-transaction path computes (same parent state, same
//! preceding transactions, same tracer and transaction context); the JSON
//! is compared in the doc's diff step.
//!
//! Anything else -- JS and struct-logger tracers, small blocks, unknown
//! transactions, a block whose trace fails -- goes to reth's own
//! `debug_traceTransaction` unchanged. `N42_TRACE_BLOCK_CACHE_TXS` bounds
//! the cached results (transactions, least recently used blocks evicted
//! first; 0 turns the cache off), `N42_TRACE_BLOCK_CACHE_MIN_TXS` sets the
//! block size from which the block path is taken.

use alloy_primitives::B256;
use alloy_rpc_types_trace::geth::{
    GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace, TraceResult,
};
use futures::future::BoxFuture;
use jsonrpsee::types::ErrorObjectOwned;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::OnceCell;

/// Where a transaction sits: its block's hash, its index there, and the
/// block's transaction count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxLocation {
    /// The including block.
    pub block_hash: B256,
    /// The transaction's index in it.
    pub index: usize,
    /// The block's transaction count.
    pub block_txs: usize,
}

/// Finds a transaction (None: unknown, the fallback answers).
pub type LocateFn = Arc<dyn Fn(B256) -> BoxFuture<'static, Option<TxLocation>> + Send + Sync>;
/// Traces a whole block by hash.
pub type TraceBlockFn = Arc<
    dyn Fn(B256, GethDebugTracingOptions) -> BoxFuture<'static, Result<Vec<TraceResult>, ErrorObjectOwned>>
        + Send
        + Sync,
>;
/// reth's own per-transaction trace.
pub type TraceTxFn = Arc<
    dyn Fn(B256, GethDebugTracingOptions) -> BoxFuture<'static, Result<GethTrace, ErrorObjectOwned>> + Send + Sync,
>;

/// Sizing of the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceCacheConfig {
    /// Cached transaction results at most (0: off).
    pub max_txs: usize,
    /// Blocks with fewer transactions take the per-transaction path.
    pub min_block_txs: usize,
}

impl Default for TraceCacheConfig {
    fn default() -> Self {
        Self { max_txs: 200_000, min_block_txs: 4 }
    }
}

impl TraceCacheConfig {
    /// The defaults with `N42_TRACE_BLOCK_CACHE_TXS` / `N42_TRACE_BLOCK_CACHE_MIN_TXS` applied.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(v) = std::env::var("N42_TRACE_BLOCK_CACHE_TXS").ok().and_then(|v| v.parse().ok()) {
            config.max_txs = v;
        }
        if let Some(v) = std::env::var("N42_TRACE_BLOCK_CACHE_MIN_TXS").ok().and_then(|v| v.parse().ok()) {
            config.min_block_txs = v;
        }
        config
    }
}

/// A block's traces: computed once, `Err` when the block trace failed (its
/// transactions then take the per-transaction path).
type Entry = Arc<OnceCell<Result<Arc<Vec<TraceResult>>, ()>>>;
type Key = (B256, String);

#[derive(Default)]
struct Lru {
    map: HashMap<Key, (Entry, usize)>,
    order: VecDeque<Key>,
    txs: usize,
}

/// Counters, for the doc's measurements and the tests.
#[derive(Debug, Default)]
pub struct TraceCacheStats {
    /// Requests answered from a cached block trace.
    pub hits: AtomicU64,
    /// Block traces run.
    pub block_traces: AtomicU64,
    /// Requests sent to the per-transaction path.
    pub fallbacks: AtomicU64,
}

/// The cache and the three operations it is built on.
pub struct BlockTraceCache {
    config: TraceCacheConfig,
    locate: LocateFn,
    trace_block: TraceBlockFn,
    trace_tx: TraceTxFn,
    lru: Mutex<Lru>,
    /// Counters.
    pub stats: TraceCacheStats,
}

impl std::fmt::Debug for BlockTraceCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockTraceCache").field("config", &self.config).finish_non_exhaustive()
    }
}

/// The options key of a cacheable request: the options minus `timeout`
/// (it bounds a JS tracer's run and changes no built-in tracer's output),
/// or None when the tracer's per-transaction answer could differ from its
/// in-block one (JS tracers, the struct logger) or is too large to keep.
pub fn cache_key(opts: &GethDebugTracingOptions) -> Option<String> {
    match opts.tracer.as_ref()? {
        GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer
            | GethDebugBuiltInTracerType::FlatCallTracer
            | GethDebugBuiltInTracerType::PreStateTracer,
        ) => {}
        _ => return None,
    }
    let mut keyed = opts.clone();
    keyed.timeout = None;
    serde_json::to_string(&keyed).ok()
}

impl BlockTraceCache {
    /// A cache over the given operations.
    pub fn new(config: TraceCacheConfig, locate: LocateFn, trace_block: TraceBlockFn, trace_tx: TraceTxFn) -> Self {
        Self { config, locate, trace_block, trace_tx, lru: Mutex::new(Lru::default()), stats: TraceCacheStats::default() }
    }

    fn fallback(
        &self,
        hash: B256,
        opts: GethDebugTracingOptions,
    ) -> BoxFuture<'static, Result<GethTrace, ErrorObjectOwned>> {
        self.stats.fallbacks.fetch_add(1, Ordering::Relaxed);
        (self.trace_tx)(hash, opts)
    }

    /// The entry for a key, created (and older blocks evicted) on a miss.
    fn entry(&self, key: Key, txs: usize) -> Entry {
        let mut lru = self.lru.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((entry, _)) = lru.map.get(&key) {
            let entry = entry.clone();
            if let Some(pos) = lru.order.iter().position(|k| *k == key) {
                let k = lru.order.remove(pos).expect("position is in range");
                lru.order.push_back(k);
            }
            return entry;
        }
        while lru.txs + txs > self.config.max_txs {
            let Some(old) = lru.order.pop_front() else { break };
            if let Some((_, n)) = lru.map.remove(&old) {
                lru.txs -= n;
            }
        }
        let entry: Entry = Arc::new(OnceCell::new());
        lru.map.insert(key.clone(), (entry.clone(), txs));
        lru.order.push_back(key);
        lru.txs += txs;
        entry
    }

    /// `debug_traceTransaction`.
    pub async fn trace_transaction(
        &self,
        hash: B256,
        opts: GethDebugTracingOptions,
    ) -> Result<GethTrace, ErrorObjectOwned> {
        let Some(key) = (self.config.max_txs > 0).then(|| cache_key(&opts)).flatten() else {
            return self.fallback(hash, opts).await;
        };
        let Some(loc) = (self.locate)(hash).await else { return self.fallback(hash, opts).await };
        if loc.block_txs < self.config.min_block_txs || loc.block_txs > self.config.max_txs {
            return self.fallback(hash, opts).await;
        }
        let entry = self.entry((loc.block_hash, key), loc.block_txs);
        let traces = entry
            .get_or_init(|| async {
                self.stats.block_traces.fetch_add(1, Ordering::Relaxed);
                let mut block_opts = opts.clone();
                block_opts.timeout = None;
                (self.trace_block)(loc.block_hash, block_opts).await.map(Arc::new).map_err(|_| ())
            })
            .await;
        match traces {
            Ok(traces) => match traces.get(loc.index) {
                Some(TraceResult::Success { result, tx_hash }) if tx_hash.is_none_or(|h| h == hash) => {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    Ok(result.clone())
                }
                _ => self.fallback(hash, opts).await,
            },
            Err(()) => self.fallback(hash, opts).await,
        }
    }

    /// The JSON-RPC module that replaces reth's `debug_traceTransaction`.
    pub fn into_rpc(self: Arc<Self>) -> jsonrpsee::RpcModule<Arc<Self>> {
        let mut module = jsonrpsee::RpcModule::new(self);
        module
            .register_async_method("debug_traceTransaction", |params, cache, _| async move {
                let mut seq = params.sequence();
                let hash: B256 = seq.next()?;
                let opts: Option<GethDebugTracingOptions> = seq.optional_next()?;
                cache.trace_transaction(hash, opts.unwrap_or_default()).await
            })
            .expect("one method on a fresh module");
        module
    }
}

#[cfg(test)]
#[path = "trace_cache_tests.rs"]
mod tests;
