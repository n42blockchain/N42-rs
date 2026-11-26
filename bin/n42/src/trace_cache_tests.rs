// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use alloy_primitives::{Address, U256};
use alloy_rpc_types_trace::geth::{CallFrame, GethDebugTracerConfig};
use std::sync::atomic::AtomicUsize;

/// A chain of blocks `b` (hash `b`) of `txs[b]` transactions; tx hash `(b, i)`
/// encodes its place. Its call frame's value is `b * 1000 + i`.
struct Fake {
    txs: Vec<usize>,
    block_calls: AtomicUsize,
    tx_calls: AtomicUsize,
    fail_block: Option<usize>,
}

fn tx_hash(b: usize, i: usize) -> B256 {
    let mut h = [0u8; 32];
    h[0] = 1;
    h[8..16].copy_from_slice(&(b as u64).to_be_bytes());
    h[16..24].copy_from_slice(&(i as u64).to_be_bytes());
    B256::from(h)
}

fn block_hash(b: usize) -> B256 {
    B256::from(U256::from(b + 1))
}

fn frame(b: usize, i: usize) -> GethTrace {
    GethTrace::CallTracer(CallFrame {
        from: Address::ZERO,
        value: Some(U256::from(b * 1000 + i)),
        typ: "CALL".into(),
        ..Default::default()
    })
}

fn cache(fake: Arc<Fake>, config: TraceCacheConfig) -> Arc<BlockTraceCache> {
    let f1 = fake.clone();
    let locate: LocateFn = Arc::new(move |hash: B256| {
        let f = f1.clone();
        Box::pin(async move {
            if hash[0] != 1 {
                return None;
            }
            let b = u64::from_be_bytes(hash[8..16].try_into().unwrap()) as usize;
            let i = u64::from_be_bytes(hash[16..24].try_into().unwrap()) as usize;
            Some(TxLocation { block_hash: block_hash(b), index: i, block_txs: f.txs[b] })
        })
    });
    let f2 = fake.clone();
    let trace_block: TraceBlockFn = Arc::new(move |hash: B256, opts: GethDebugTracingOptions| {
        let f = f2.clone();
        Box::pin(async move {
            assert!(opts.timeout.is_none(), "the block trace runs without the request's timeout");
            f.block_calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            let b = U256::from_be_bytes(hash.0).to::<usize>() - 1;
            if f.fail_block == Some(b) {
                return Err(ErrorObjectOwned::owned(-32000, "boom", None::<()>));
            }
            Ok((0..f.txs[b]).map(|i| TraceResult::Success { result: frame(b, i), tx_hash: Some(tx_hash(b, i)) }).collect())
        })
    });
    let f3 = fake;
    let trace_tx: TraceTxFn = Arc::new(move |hash: B256, _| {
        let f = f3.clone();
        Box::pin(async move {
            f.tx_calls.fetch_add(1, Ordering::SeqCst);
            let b = u64::from_be_bytes(hash[8..16].try_into().unwrap()) as usize;
            let i = u64::from_be_bytes(hash[16..24].try_into().unwrap()) as usize;
            Ok(frame(b, i))
        })
    });
    Arc::new(BlockTraceCache::new(config, locate, trace_block, trace_tx))
}

fn call_tracer() -> GethDebugTracingOptions {
    GethDebugTracingOptions::call_tracer(Default::default())
}

fn fake(txs: Vec<usize>) -> Arc<Fake> {
    Arc::new(Fake { txs, block_calls: AtomicUsize::new(0), tx_calls: AtomicUsize::new(0), fail_block: None })
}

#[tokio::test]
async fn every_transaction_of_a_block_from_one_trace() {
    let f = fake(vec![10, 10]);
    let c = cache(f.clone(), TraceCacheConfig::default());
    for i in 0..10 {
        assert_eq!(c.trace_transaction(tx_hash(1, i), call_tracer()).await.unwrap(), frame(1, i));
    }
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.tx_calls.load(Ordering::SeqCst), 0);
    assert_eq!(c.stats.hits.load(Ordering::Relaxed), 10);
}

#[tokio::test]
async fn concurrent_requests_share_one_block_trace() {
    let f = fake(vec![50]);
    let c = cache(f.clone(), TraceCacheConfig::default());
    let all = futures::future::join_all((0..50).map(|i| {
        let c = c.clone();
        async move { c.trace_transaction(tx_hash(0, i), call_tracer()).await.unwrap() }
    }))
    .await;
    assert_eq!(all, (0..50).map(|i| frame(0, i)).collect::<Vec<_>>());
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn timeout_does_not_split_the_key() {
    let f = fake(vec![8]);
    let c = cache(f.clone(), TraceCacheConfig::default());
    let mut with_timeout = call_tracer();
    with_timeout.timeout = Some("5s".into());
    c.trace_transaction(tx_hash(0, 0), with_timeout).await.unwrap();
    c.trace_transaction(tx_hash(0, 1), call_tracer()).await.unwrap();
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 1);
    // A different tracer config is a different key.
    let only_top = GethDebugTracingOptions::call_tracer(alloy_rpc_types_trace::geth::CallConfig {
        only_top_call: Some(true),
        ..Default::default()
    });
    c.trace_transaction(tx_hash(0, 2), only_top).await.unwrap();
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn other_tracers_small_blocks_and_unknown_txs_fall_back() {
    let f = fake(vec![2, 10]);
    let c = cache(f.clone(), TraceCacheConfig::default());
    // A block under min_block_txs.
    c.trace_transaction(tx_hash(0, 1), call_tracer()).await.unwrap();
    // The struct logger and a JS tracer.
    c.trace_transaction(tx_hash(1, 1), GethDebugTracingOptions::default()).await.unwrap();
    let js = GethDebugTracingOptions {
        tracer: Some(GethDebugTracerType::JsTracer("{}".into())),
        tracer_config: GethDebugTracerConfig::default(),
        ..Default::default()
    };
    c.trace_transaction(tx_hash(1, 1), js).await.unwrap();
    // An unknown transaction.
    c.trace_transaction(B256::repeat_byte(9), call_tracer()).await.unwrap();
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.tx_calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn a_failed_block_trace_falls_back_once_per_block() {
    let f = Arc::new(Fake { txs: vec![6], block_calls: AtomicUsize::new(0), tx_calls: AtomicUsize::new(0), fail_block: Some(0) });
    let c = cache(f.clone(), TraceCacheConfig::default());
    for i in 0..6 {
        assert_eq!(c.trace_transaction(tx_hash(0, i), call_tracer()).await.unwrap(), frame(0, i));
    }
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 1, "the failure is remembered");
    assert_eq!(f.tx_calls.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn least_recently_used_blocks_are_evicted() {
    let f = fake(vec![10, 10, 10]);
    let c = cache(f.clone(), TraceCacheConfig { max_txs: 20, min_block_txs: 4 });
    c.trace_transaction(tx_hash(0, 0), call_tracer()).await.unwrap();
    c.trace_transaction(tx_hash(1, 0), call_tracer()).await.unwrap();
    c.trace_transaction(tx_hash(0, 1), call_tracer()).await.unwrap(); // 0 is now the most recent
    c.trace_transaction(tx_hash(2, 0), call_tracer()).await.unwrap(); // evicts 1
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 3);
    c.trace_transaction(tx_hash(0, 2), call_tracer()).await.unwrap();
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 3, "block 0 stayed");
    c.trace_transaction(tx_hash(1, 2), call_tracer()).await.unwrap();
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 4, "block 1 was evicted");
    // A block larger than the whole budget is never cached.
    let big = fake(vec![30]);
    let c = cache(big.clone(), TraceCacheConfig { max_txs: 20, min_block_txs: 4 });
    c.trace_transaction(tx_hash(0, 0), call_tracer()).await.unwrap();
    assert_eq!(big.block_calls.load(Ordering::SeqCst), 0);
    assert_eq!(big.tx_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_rpc_method_takes_optional_options() {
    let f = fake(vec![10]);
    let module = cache(f.clone(), TraceCacheConfig::default()).into_rpc();
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"debug_traceTransaction","params":["{}",{{"tracer":"callTracer","timeout":"5s"}}]}}"#,
        tx_hash(0, 3)
    );
    let (response, _) = module.raw_json_request(&request, 1).await.unwrap();
    let value: serde_json::Value = serde_json::from_str(response.get()).unwrap();
    assert_eq!(value["result"]["value"], "0x3");
    assert_eq!(f.block_calls.load(Ordering::SeqCst), 1);
    let request = format!(r#"{{"jsonrpc":"2.0","id":2,"method":"debug_traceTransaction","params":["{}"]}}"#, tx_hash(0, 4));
    let (response, _) = module.raw_json_request(&request, 1).await.unwrap();
    let value: serde_json::Value = serde_json::from_str(response.get()).unwrap();
    assert!(value.get("result").is_some(), "{value}");
    assert_eq!(f.tx_calls.load(Ordering::SeqCst), 1, "no tracer: the struct logger, per transaction");
}
