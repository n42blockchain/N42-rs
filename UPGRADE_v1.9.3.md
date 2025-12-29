# N42 升级到 reth v1.9.3 文档

## 概述

本文档记录了 N42 从 reth v1.5.0 升级到 v1.9.3 的主要变更和解决方案。

## 版本信息

- **升级前版本**: reth v1.5.0
- **升级后版本**: reth v1.9.3
- **升级日期**: 2025-12-27

---

## 主要变更

### 1. RPC API 变更

#### 1.1 `EthApiBuilder` trait 变更

**问题**: `EthApiBuilder` 的 trait bounds 发生了变化，需要 `RpcConvert` 和 `SignableTxRequest` 支持。

**解决方案**: 更新 `crates/n42/engine-types/src/node.rs`:

```rust
impl<N> EthApiBuilder<N> for EthereumEthApiBuilder
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthChainSpec + EthereumHardforks,
            Primitives: NodePrimitives<
                Block = reth_ethereum_primitives::Block,
                Receipt = reth_ethereum_primitives::Receipt,
            >,
        >,
    >,
    N::Network: NetworkInfo,
    N::Provider: FullProvider<N::Types>,
    EthApiNodeBackend<N>: TransactionConvert<N>,
    AlloyTxEnvelope: From<<RpcConverter<Ethereum, N::Pool, N::Network> as TransactionConvert<N>>::Transaction>,
{
    // ...
}
```

### 2. Engine Validator 变更

#### 2.1 `BasicEngineValidator` 替换 `EthereumEngineValidator`

**问题**: `EthereumEngineValidator` 返回 "block execution not implemented" 错误。

**解决方案**: 
1. 实现 `ConfigureEngineEvm<ExecutionData>` trait for `EthEvmConfig`
2. 更新 `BasicEngineValidatorBuilder` 的 trait bounds

**文件**: `crates/ethereum/evm/src/lib.rs`

```rust
impl ConfigureEngineEvm<ExecutionData> for EthEvmConfig {
    fn evm_env_for_payload(&self, header: &HeaderTy<ExecutionData>, cfg: &CfgEnvWithHandlerCfg) -> EvmEnv {
        // Implementation
    }
    
    fn context_for_payload(&self, payload: &ExecutionData, evm_env: EvmEnv) -> Result<ContextTr<ExecutionData>, BlockExecutionError> {
        // Implementation
    }
    
    fn tx_iterator_for_payload<'a>(&self, payload: &'a ExecutionData) -> impl Iterator<Item = Result<RecoveredTx<<ExecutionData as ExecutionPayload>::Primitives>, AnyError>> + 'a {
        // Implementation
    }
}
```

### 3. 存储层变更

#### 3.1 `DBProvider::commit` 方法变更

**问题**: 默认的 `DBProvider::commit` 不提交 static files，导致 "no header found for Number(0)" 错误。

**解决方案**: 在 `DatabaseProvider` 的 `DBProvider` 实现中重写 `commit` 方法：

**文件**: `crates/storage/provider/src/providers/database/provider.rs`

```rust
impl<TX: DbTxMut + DbTx + 'static, N: NodeTypes> DBProvider for DatabaseProvider<TX, N> {
    fn commit(self) -> ProviderResult<bool> {
        // Commit static files first
        let unwind_queued = if let Some(ref static_file_provider) = self.static_file_provider {
            let queued = static_file_provider.has_unwind_queued();
            if !queued {
                static_file_provider.commit()?;
            }
            queued
        } else {
            false
        };

        // Then commit DB transaction
        self.tx.commit()?;
        Ok(unwind_queued)
    }
}
```

#### 3.2 `IntegerList` 排序要求

**问题**: `BlockNumberList::new_pre_sorted` 要求输入已排序且无重复。

**解决方案**: 在 `append_history_index` 中添加排序和去重：

```rust
last_shard.sort_unstable();
last_shard.dedup();
```

### 4. 共识层变更

#### 4.1 Total Difficulty 缓存问题

**问题**: Payload builder 和 miner 使用不同的 `consensus` 实例，导致 TD 缓存未命中。

**解决方案**: 在 miner 中直接计算 TD：

**文件**: `crates/n42/consensus-client/src/miner.rs`

```rust
// 直接计算新区块的 TD，避免缓存未命中
let parent_td = self.consensus.total_difficulty(block.header().parent_hash());
let max_td = parent_td + block.header().difficulty();
```

### 5. EVM 配置变更

#### 5.1 `excess_blob_gas` 设置条件

**问题**: Cancun 之后的版本也需要设置 `excess_blob_gas`。

**解决方案**: 将条件从 `spec_id == SpecId::CANCUN` 改为 `spec_id >= SpecId::CANCUN`。

### 6. 网络层变更

#### 6.1 `subscribe_block` 返回空流问题

**问题**: `subscribe_block()` 创建了一个 broadcast channel，但发送方 `_tx` 立即被丢弃，导致流始终返回 `None`。

**解决方案**: 在 `NetworkInner` 中添加 `block_announcer` 字段：

**文件**: `crates/net/network/src/network.rs`

```rust
struct NetworkInner<N: NetworkPrimitives = EthNetworkPrimitives> {
    // ... 其他字段
    /// Sender for block announcement events.
    block_announcer: EventSender<NewBlock<N::Block>>,
}

impl<N: NetworkPrimitives> BlockAnnounceProvider for NetworkHandle<N> {
    fn subscribe_block(&self) -> EventStream<NewBlock<Self::Block>> {
        // 返回真正的监听器
        self.inner.block_announcer.new_listener()
    }
}
```

---

## 新增依赖

在相关 `Cargo.toml` 文件中添加：

```toml
[dependencies]
alloy-network.workspace = true
reth-rpc-eth-api.workspace = true
reth-rpc-server-types.workspace = true
```

---

## 已移除/弃用的功能

1. `BeaconConsensusEngineHandle` → `ConsensusEngineHandle`
2. `BeaconConsensusEngineEvent` → `ConsensusEngineEvent`
3. `StorageLocation` 参数从多个方法中移除
4. `recover` CLI 命令被移除

---

## API 重命名

| 旧名称 | 新名称 |
|--------|--------|
| `rand::thread_rng()` | `rand::rng()` |
| `rand::Rng::gen()` | `rand::Rng::random()` |
| `BeaconConsensusEngineHandle` | `ConsensusEngineHandle` |
| `BeaconConsensusEngineEvent` | `ConsensusEngineEvent` |

---

## 测试

运行以下命令验证升级:

```bash
# 格式化代码
cargo fmt

# 编译
cargo build --release --bin n42

# 运行测试
cargo test --release -p n42
cargo test --release -p n42-primitives

# 启动节点
rm -rf /path/to/datadir
target/release/n42 node \
  --chain n42-devnet \
  --authrpc.jwtsecret /path/to/jwt.hex \
  --dev.consensus-signer-private-key 0x... \
  --datadir /path/to/datadir
```

---

## 已知问题

1. 大量 "missing documentation" 警告 - 这些是代码风格警告，不影响功能
2. 部分 "unreachable pub item" 警告 - 可以通过将 `pub` 改为 `pub(crate)` 解决

---

## 文件变更摘要

| 文件路径 | 变更类型 | 描述 |
|----------|----------|------|
| `crates/n42/engine-types/src/node.rs` | 修改 | 更新 RPC API trait bounds |
| `crates/n42/engine-types/src/payload.rs` | 修改 | 修复 gas_limit/basefee 访问方式 |
| `crates/ethereum/evm/src/lib.rs` | 修改 | 实现 ConfigureEngineEvm, 修复 excess_blob_gas |
| `crates/storage/provider/src/providers/database/provider.rs` | 修改 | 重写 commit 方法, 修复排序问题 |
| `crates/n42/consensus-client/src/miner.rs` | 修改 | 直接计算 TD 避免缓存问题 |
| `crates/n42/clique/src/apos.rs` | 修改 | 添加 TD fallback 逻辑 |
| `crates/node/builder/src/rpc.rs` | 修改 | 更新 BasicEngineValidatorBuilder |
| `crates/ethereum/node/src/engine.rs` | 修改 | 更新 EthereumEngineValidator |
| `crates/n42/alloy-rpc-types-engine/src/payload.rs` | 修改 | 添加缺失的 ExecutionPayload 方法 |

---

## 贡献者

- N42 开发团队

## 许可证

MIT OR Apache-2.0

