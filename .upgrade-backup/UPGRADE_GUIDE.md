# N42-rs 升级至 reth v1.9.3 指南

## 版本信息
- 当前版本: reth v1.4.3
- 目标版本: reth v1.9.3
- Rust 版本要求: 1.88 (从 1.86 升级)
- Edition: 2024 (从 2021 升级)

## 重要变更摘要

### 1. Rust 版本和 Edition 升级
```toml
# 旧版本
edition = "2021"
rust-version = "1.86"

# 新版本
edition = "2024"
rust-version = "1.88"
```

### 2. Consensus Trait 接口变化
reth v1.9.3 的 `Consensus` trait 已精简化，移除了以下方法：
- `prepare()` - N42 自定义
- `seal()` - N42 自定义
- `set_eth_signer_by_key()` - N42 自定义
- `get_eth_signer_address()` - N42 自定义
- `snapshot()` - N42 自定义
- `propose()` - N42 自定义
- `discard()` - N42 自定义
- `proposals()` - N42 自定义
- `total_difficulty()` - N42 自定义
- `wiggle()` - N42 自定义

**解决方案**: 创建 `N42Consensus` 扩展 trait 包含这些方法

### 3. 存储层变化
- 新增: `reth-storage-rpc-provider`
- `reth-codecs` 路径变更为 `crates/storage/codecs`
- 新增: `BlockNumberHashedAddress` 模型
- 新增: `TrieChangeSetsEntry` 类型

### 4. 删除的依赖/模块
- `reth-auto-seal-consensus` 可能已重命名或移除
- `reth-blockchain-tree` 可能有变化
- `reth-blockchain-tree-api` 可能有变化

### 5. 新增的依赖/模块
- `reth-bench-compare`
- `reth-era`, `reth-era-downloader`, `reth-era-utils`
- `reth-ress-protocol`
- `reth-storage-zstd-compressors`

## 升级步骤

### 步骤 1: 更新 Cargo.toml
将所有 `reth-*` 依赖从 `tag = "v1.4.3"` 更新到 `tag = "v1.9.3"`

### 步骤 2: 更新 Rust 版本
```bash
rustup update
rustup default 1.88
```

### 步骤 3: 编译并修复错误
```bash
cargo build 2>&1 | tee build_errors.log
```

### 步骤 4: 重新应用 N42 定制
1. 恢复 `clique_utils.rs` 到 `primitives-traits/src/header/`
2. 恢复 N42 硬分叉定义
3. 恢复存储层定制表
4. 恢复 N42 Consensus 扩展方法

### 步骤 5: 测试
```bash
cargo test --workspace
```

## 需要保留的 N42 定制

1. **crates/n42/** - 所有 N42 专有模块
2. **clique_utils.rs** - Clique 签名恢复工具
3. **n42.rs** (hardforks) - N42 硬分叉定义
4. **beacon.rs, snapshot.rs, validator.rs** - 存储模型和 API
5. **ast.rs** (bootnodes) - N42 引导节点

## 风险评估

| 变更类型 | 影响范围 | 风险等级 |
|---------|---------|---------|
| Rust Edition 2024 | 全项目 | 中 |
| Consensus Trait 变化 | APoS 共识 | 高 |
| 存储 API 变化 | 数据层 | 高 |
| 依赖版本升级 | 编译 | 中 |

## 回滚计划

如果升级失败，执行:
```bash
git checkout main
git branch -D feature/upgrade-reth-1.9.3
```
