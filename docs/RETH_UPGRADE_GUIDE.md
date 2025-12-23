# Reth 升级指南

## 当前状态

- **当前版本**: reth v1.4.3
- **Workspace 版本**: 1.8.4
- **Tag**: v1.4.3-n42-base

## Fork 的 Crate

项目 fork 了以下 9 个 reth crate：

| Crate | 目录 | N42 定制内容 |
|-------|------|--------------|
| primitives-traits | crates/primitives-traits | N42 常量、clique_utils |
| consensus | crates/consensus/consensus | APoS 共识 trait |
| chainspec | crates/chainspec | N42 链规格 |
| hardforks | crates/ethereum/hardforks | N42_HARDFORKS |
| db-api | crates/storage/db-api | Beacon 表定义 |
| db | crates/storage/db | - |
| storage-api | crates/storage/storage-api | - |
| network | crates/net/network | - |
| revm | crates/revm | cached 模块 |

## 升级挑战

### v1.4.3 → v1.4.4 尝试结果

**依赖变化**:
- alloy-* 从 1.0.5 → 1.0.9
- alloy-evm 从 0.8.1 → 0.10.0
- revm 从 23.1.0 → 24.0.0
- op-alloy-* 从 0.16.0 → 0.17.2

**遇到的问题**:
1. `alloy_trie::TrieAccount: From<GenesisAccount>` 不满足
2. `revm-inspectors` API 不兼容（CallLogFrame 缺少 index 字段）
3. 多个版本的 `alloy-primitives` 冲突（0.8.26 vs 1.5.2）

### v1.4.3 → v1.9.3 尝试结果

**依赖变化**:
- revm 从 23.1.0 → 31.0.2 (+8 major)
- revm-state 从 4.0.0 → 8.1.1 (+4 major)
- alloy-* 从 1.0.5 → 1.0.41

**遇到的问题**:
1. `Bytecode::Eof` 枚举变体被移除
2. `Receipt` trait 改为 blanket impl
3. `InMemorySize for Log` 需要新实现
4. `Nibbles::into()` 改为 `to_vec()`
5. `BlockNumberAddressRange` 新类型缺失
6. `DatabaseWriteOperation::Put` API 变化

## 推荐升级策略

### 策略 A：等待稳定版本（推荐）

等待 reth v2.0 或下一个 LTS 版本，那时 API 会更稳定。

**优点**: 工作量最小，风险最低
**缺点**: 无法使用最新特性

### 策略 B：减少 Fork 依赖

将 N42 定制移出 fork crate，使用 trait extension：

```rust
// 例如：将 Consensus trait 扩展移到 n42-consensus-traits
pub trait AposConsensus: reth_consensus::Consensus {
    fn prepare(&self, ...) -> Result<...>;
    fn seal(&self, ...) -> Result<...>;
}
```

**已创建的独立模块**:
- `n42-consensus-traits` - APoS 共识扩展
- `n42-storage` - N42 存储表
- `n42-consensus-core` - 核心共识逻辑
- `n42-chainspec` - 链规格
- `n42-fusaka` - Fusaka 硬分叉支持

**优点**: 减少与上游的耦合
**缺点**: 需要大量重构

### 策略 C：同步 Fork（高成本）

为每个 fork crate 同步上游变化：

1. 对比每个 fork 文件与上游差异
2. 保留 N42 定制，更新 API
3. 逐个 crate 验证

**优点**: 保持最新
**缺点**: 工作量大，每次升级都需要重复

## 升级检查清单

升级前请确认：

- [ ] 备份当前状态 (`git tag`)
- [ ] 记录所有依赖版本
- [ ] 运行完整测试套件
- [ ] 创建升级分支

升级步骤：

1. [ ] 更新 `Cargo.toml` 中的 reth tag
2. [ ] 更新匹配的 alloy 版本
3. [ ] 更新匹配的 revm 版本
4. [ ] 同步 fork crate 的 API 变化
5. [ ] 修复编译错误
6. [ ] 运行测试
7. [ ] 提交并打 tag

## 版本兼容性矩阵

| reth | revm | alloy | Rust |
|------|------|-------|------|
| 1.4.3 | 23.1.0 | 1.0.5 | 1.86 |
| 1.4.4 | 24.0.0 | 1.0.9 | 1.86 |
| 1.9.3 | 31.0.2 | 1.0.41 | 1.86 |

## 当前测试状态

```
v1.4.3-n42-base:
- 258 个测试通过
- 编译成功
- 所有功能正常
```

