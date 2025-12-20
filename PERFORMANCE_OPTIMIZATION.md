# N42 Performance Optimization Plan

**Version:** 1.0  
**Date:** December 2024  
**Target:** Maximize TPS and minimize RPC response latency

---

## Executive Summary

This document outlines a comprehensive performance optimization strategy for the N42 blockchain client, targeting:
- **TPS Goal:** 1000+ transactions per second
- **RPC Latency Goal:** < 50ms for common queries (eth_call, eth_getBalance)
- **Block Time:** Maintain consistent 8-second block intervals

---

## 1. Current Architecture Analysis

### 1.1 Consensus Layer (APoS)
```
Current Bottlenecks:
├── RwLock contention on snapshot cache (recents)
├── RwLock contention on recent_headers and recent_tds
├── Fixed cache sizes (INMEMORY_SNAPSHOTS=128, INMEMORY_TDS=1024)
└── Synchronous snapshot lookups during validation
```

### 1.2 Storage Layer
```
Current Bottlenecks:
├── Sequential block writes (not batched)
├── Multiple database transactions per block
├── Trie updates blocking main execution
└── History index updates on every block
```

### 1.3 Network Layer
```
Current Bottlenecks:
├── Poll budget limiting throughput (4 iterations)
├── Session message processing sequentially
└── Transaction broadcast not optimized
```

### 1.4 RPC Layer
```
Current Bottlenecks:
├── Default cache sizes may be insufficient
├── Concurrent DB request limit (512 default)
└── State queries hitting database frequently
```

---

## 2. Optimization Strategies

### Phase 1: Quick Wins (1-2 days)

#### 2.1 Increase Cache Sizes

**File:** `crates/n42/clique/src/apos.rs`

```rust
// BEFORE
const INMEMORY_SNAPSHOTS: u32 = 128;
const INMEMORY_TDS: u32 = 1024;

// AFTER - Increase cache for better hit rate
const INMEMORY_SNAPSHOTS: u32 = 512;      // 4x increase
const INMEMORY_TDS: u32 = 4096;           // 4x increase
const CHECKPOINT_INTERVAL: u64 = 2048;    // Keep same
```

**Rationale:** Higher cache sizes reduce database lookups during block validation.

#### 2.2 Replace RwLock with parking_lot

**Benefits:**
- 2-3x faster lock acquisition
- No poisoning (panic-safe)
- Better fairness under contention

```rust
// BEFORE
use std::sync::RwLock;

// AFTER
use parking_lot::RwLock;
```

#### 2.3 Increase RPC Cache Configuration

**Recommended CLI flags:**
```bash
--rpc-cache.max-blocks=2000 \
--rpc-cache.max-receipts=4000 \
--rpc-cache.max-headers=4000 \
--rpc-cache.max-concurrent-db-requests=1024
```

---

### Phase 2: Structural Optimizations (1 week)

#### 2.4 Parallel Block Validation

**Current:** Sequential header validation
**Proposed:** Parallel validation with rayon

```rust
use rayon::prelude::*;

fn validate_headers_parallel(&self, headers: &[SealedHeader]) -> Result<(), Error> {
    headers.par_iter().try_for_each(|header| {
        self.validate_header(header)
    })
}
```

#### 2.5 Batch Database Writes

**File:** `crates/storage/provider/src/writer/mod.rs`

**Current (line 169-194):** Individual writes per block
**Proposed:** Batch multiple operations

```rust
pub fn save_blocks_batched<N>(&self, blocks: Vec<ExecutedBlockWithTrieUpdates<N>>) -> ProviderResult<()> {
    // Collect all data first
    let mut all_blocks = Vec::new();
    let mut all_states = Vec::new();
    let mut all_hashed_states = Vec::new();
    
    for block in blocks {
        all_blocks.push(block.recovered_block);
        all_states.push(block.execution_output);
        all_hashed_states.push(block.hashed_state);
    }
    
    // Batch write blocks
    self.database().insert_blocks_batch(all_blocks, StorageLocation::Both)?;
    
    // Batch write states
    self.database().write_states_batch(&all_states)?;
    
    // Batch write hashed states
    self.database().write_hashed_states_batch(&all_hashed_states)?;
    
    Ok(())
}
```

#### 2.6 Async Trie Updates

**Current:** Blocking trie updates on critical path
**Proposed:** Background trie worker

```rust
// Spawn dedicated trie update worker
let (trie_tx, trie_rx) = tokio::sync::mpsc::channel(1000);

tokio::spawn(async move {
    while let Some(trie_update) = trie_rx.recv().await {
        database.write_trie_updates(&trie_update).await;
    }
});
```

---

### Phase 3: Advanced Optimizations (2-4 weeks)

#### 2.7 Read-Through Caching Layer

Implement tiered caching:
```
Request → L1 (In-Memory LRU) → L2 (Memory-Mapped) → L3 (Database)
```

```rust
pub struct TieredCache<K, V> {
    l1: parking_lot::RwLock<LruCache<K, V>>,     // Hot data, ~10K entries
    l2: Arc<MemoryMappedCache<K, V>>,            // Warm data, ~100K entries
    db: Arc<dyn Database>,                        // Cold data
}

impl<K, V> TieredCache<K, V> {
    pub async fn get(&self, key: &K) -> Option<V> {
        // Check L1
        if let Some(v) = self.l1.read().get(key) {
            return Some(v.clone());
        }
        
        // Check L2
        if let Some(v) = self.l2.get(key).await {
            self.l1.write().insert(key.clone(), v.clone());
            return Some(v);
        }
        
        // Fallback to DB
        if let Some(v) = self.db.get(key).await {
            self.l2.insert(key.clone(), v.clone()).await;
            self.l1.write().insert(key.clone(), v.clone());
            return Some(v);
        }
        
        None
    }
}
```

#### 2.8 Connection Pooling for Database

```rust
use bb8::{Pool, ManageConnection};

pub struct DbPool {
    pool: Pool<DatabaseManager>,
    max_connections: usize,
}

impl DbPool {
    pub fn new(max_connections: usize) -> Self {
        let manager = DatabaseManager::new();
        let pool = Pool::builder()
            .max_size(max_connections as u32)
            .build(manager)
            .await
            .unwrap();
        Self { pool, max_connections }
    }
}
```

#### 2.9 Parallel Transaction Execution (Future EVM)

```rust
// Identify independent transactions that can execute in parallel
fn identify_parallel_txs(txs: &[Transaction]) -> Vec<Vec<&Transaction>> {
    let mut dependency_graph = DependencyGraph::new();
    
    for tx in txs {
        let reads = tx.state_reads();
        let writes = tx.state_writes();
        dependency_graph.add(tx, reads, writes);
    }
    
    dependency_graph.topological_groups()
}

// Execute independent groups in parallel
async fn execute_parallel(groups: Vec<Vec<&Transaction>>, state: &mut State) {
    for group in groups {
        let results: Vec<_> = group.par_iter()
            .map(|tx| execute_tx(tx, state.snapshot()))
            .collect();
        
        // Merge results sequentially
        for result in results {
            state.apply(result);
        }
    }
}
```

---

## 3. Network Optimizations

### 3.1 Increase Poll Budget

**File:** `crates/net/network/src/manager.rs` (line 1122-1131)

```rust
// BEFORE
let mut budget = 4;

// AFTER - Allow more iterations before yielding
let mut budget = 16;
```

### 3.2 Transaction Broadcast Optimization

```rust
// Use binary encoding for transaction broadcast
fn encode_transactions_binary(txs: &[Transaction]) -> Bytes {
    let mut encoder = CompactEncoder::new();
    for tx in txs {
        encoder.encode_tx(tx);
    }
    encoder.finish()
}

// Batch transaction announcements
fn batch_announce_txs(txs: Vec<B256>) -> Vec<NewPooledTransactionHashes> {
    txs.chunks(4096)
        .map(|chunk| NewPooledTransactionHashes::from(chunk))
        .collect()
}
```

### 3.3 Peer Connection Optimization

```bash
# Recommended network configuration
--max-outbound-peers=100 \
--max-inbound-peers=100 \
--discovery.port=30303 \
--trusted-only=false
```

---

## 4. Memory Optimization

### 4.1 Object Pooling

```rust
use crossbeam::queue::ArrayQueue;

pub struct TransactionPool {
    pool: ArrayQueue<Transaction>,
}

impl TransactionPool {
    pub fn acquire(&self) -> Transaction {
        self.pool.pop().unwrap_or_else(Transaction::new)
    }
    
    pub fn release(&self, mut tx: Transaction) {
        tx.reset();
        let _ = self.pool.push(tx);
    }
}
```

### 4.2 Arena Allocation for Block Processing

```rust
use bumpalo::Bump;

pub fn process_block_with_arena(block: &Block) {
    let arena = Bump::new();
    
    // Allocate temporary data in arena
    let temp_state = arena.alloc_slice_copy(&block.state_changes);
    
    // Process...
    
    // Arena automatically freed when dropped
}
```

---

## 5. Monitoring & Metrics

### 5.1 Key Performance Indicators

```rust
// Add these metrics
metrics::gauge!("n42.consensus.snapshot_cache_hit_rate").set(hit_rate);
metrics::histogram!("n42.consensus.block_validation_time_ms").record(duration);
metrics::counter!("n42.rpc.requests_total").increment(1);
metrics::histogram!("n42.rpc.response_time_ms").record(response_time);
metrics::gauge!("n42.storage.pending_writes").set(pending_count);
```

### 5.2 Profiling Commands

```bash
# CPU profiling
cargo flamegraph --bin n42 -- node --dev

# Memory profiling
MALLOC_CONF=prof:true ./target/release/n42 node --dev

# Lock contention analysis
cargo run --features lock-tracking -- node --dev
```

---

## 6. Implementation Priority

| Priority | Optimization | Effort | Impact |
|----------|-------------|--------|--------|
| 🔴 P0 | Increase cache sizes | 1 hour | High |
| 🔴 P0 | parking_lot locks | 2 hours | High |
| 🟠 P1 | Batch DB writes | 2 days | High |
| 🟠 P1 | Increase poll budget | 1 hour | Medium |
| 🟡 P2 | Tiered caching | 1 week | High |
| 🟡 P2 | Async trie updates | 3 days | Medium |
| 🟢 P3 | Parallel validation | 1 week | Medium |
| 🟢 P3 | Connection pooling | 3 days | Medium |

---

## 7. Expected Results

### Before Optimization
- TPS: ~100-200
- RPC eth_call: ~100-200ms
- Block validation: ~500ms

### After Phase 1
- TPS: ~300-400
- RPC eth_call: ~50-80ms
- Block validation: ~200ms

### After Phase 2
- TPS: ~600-800
- RPC eth_call: ~20-40ms
- Block validation: ~100ms

### After Phase 3
- TPS: ~1000+
- RPC eth_call: ~10-20ms
- Block validation: ~50ms

---

## 8. Testing Strategy

### 8.1 Benchmark Suite

```bash
# TPS benchmark
cargo bench --package n42-bench -- tps

# RPC latency benchmark
wrk -t12 -c400 -d30s -s rpc_bench.lua http://localhost:8545

# Storage benchmark
cargo bench --package reth-storage -- write_blocks
```

### 8.2 Load Testing

```bash
# Generate load
cargo run --release --bin n42-loadgen -- \
  --tps=1000 \
  --duration=60s \
  --rpc-url=http://localhost:8545
```

---

*Document prepared as part of N42 performance optimization initiative.*

