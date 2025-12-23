# Reth 升级指南

## 当前状态

- **当前版本**: reth v1.4.3
- **Workspace 版本**: 1.8.4
- **状态**: 稳定运行，258+ 测试通过

## Fork 的 Crate 清单

项目 fork 了以下 12 个 reth/alloy crate：

| Crate | 补丁行数 | N42 定制内容 |
|-------|---------|--------------|
| chainspec | 2627 行 | N42 链规格、genesis 文件、常量 |
| consensus/consensus | 577 行 | APoS 共识 trait、n42_tests |
| ethereum/hardforks | 360 行 | N42_HARDFORKS、BeijingFork |
| net/peers | 337 行 | n42_testnet_nodes |
| node/core | 1147 行 | N42 节点配置、版本 |
| primitives-traits | 1699 行 | N42 常量、clique_utils、header |
| revm | 108 行 | cached 模块 |
| storage/db | 1448 行 | Beacon 表定义 |
| storage/db-api | 806 行 | 数据库 API |
| storage/provider | 9120 行 | 存储提供者 |
| storage/storage-api | 786 行 | 存储 API |
| rpc/rpc-types-compat | 82 行 | RPC 类型兼容 |
| n42/alloy-rpc-types-beacon | - | 自定义 beacon 类型 |
| n42/alloy-rpc-types-engine | - | 自定义 engine 类型 |

## 补丁升级方法

### 生成补丁

```bash
# 克隆上游 v1.4.3 作为基准
git clone --depth 1 --branch v1.4.3 https://github.com/paradigmxyz/reth.git reth-143

# 为每个 fork crate 生成补丁
for crate in chainspec "consensus/consensus" ...; do
  diff -ruN reth-143/crates/$crate N42-rs/crates/$crate > patches/${crate}.patch
done
```

### 应用补丁

```bash
# 克隆目标版本
git clone --depth 1 --branch v1.4.X https://github.com/paradigmxyz/reth.git reth-14X

# 调整路径并应用补丁
sed -i 's|reth-143/|reth-14X/|g' patches/*.patch
for patch in patches/*.patch; do
  patch -p0 < $patch
done

# 检查冲突
find . -name "*.rej"
```

## 升级尝试记录

### v1.4.3 → v1.4.4 ❌

**问题**: 上游 v1.4.4 本身无法编译！

```bash
cd reth-144-clean && cargo check -p reth-chainspec
# error[E0277]: the trait bound `alloy_trie::TrieAccount: From<GenesisAccount>` is not satisfied
```

**原因**: alloy-trie 0.8.1 与 alloy-genesis 1.0.9 之间的版本不兼容。

### v1.4.3 → v1.4.5 ❌

**补丁应用**: ✅ 成功（仅格式化冲突）

**编译问题**:
1. `revm-inspectors` API 不兼容 - `CallLogFrame` 缺少 `index` 字段
2. `alloy-rpc-types-engine` API 变化 - `ExecutionPayloadV1` 结构变化
3. 多版本 alloy-primitives 冲突 (0.8.26 vs 1.5.2)

**根因**: 我们的 `n42/alloy-rpc-types-engine` patch 基于 v1.0.5 API，与 v1.0.9 不兼容。

## 核心阻塞因素

~~1. **alloy-rpc-types-engine patch**: 需要同步到 v1.0.9+ API~~ ✅ 已完成
~~2. **alloy-rpc-types-beacon patch**: 需要同步到 v1.0.9+ API~~ ✅ 已完成  
~~3. **Fork crate 复杂依赖**: storage/db-api 等有 N42 特有依赖~~ ✅ 不需要（上游变化很小）
4. **⚠️ 依赖版本解析冲突**: Cargo 会拉入更高版本的 alloy 包，导致与 alloy-trie 0.8.1 不兼容

### v1.4.3 → v1.4.5 上游变化（极小）

只有 7 个文件变化，大部分是注释格式修复：
- `recovered.rs`: +1 新方法 `recovered_transaction()`
- `extended.rs`: +4 From 实现
- `access_list.rs`: 注释格式（反引号）
- `consensus/lib.rs`: 注释格式
- `log.rs`: +1 新方法 `init_tracing_with_layers()` + 重命名
- `config.rs`: +Hoodi 链支持
- `masks.rs`: 注释格式

### 依赖版本冲突详解

```
问题链:
1. reth v1.4.5-v1.4.8 需要 alloy-trie 0.8.1
2. alloy-trie 0.8.1 期望 alloy-genesis 实现 Into<TrieAccount>
3. 但 Cargo 解析了 alloy-genesis 1.1.3（而非 1.0.9）
4. alloy-genesis 1.1.3 的 GenesisAccount 与 alloy-trie 0.8.1 不兼容
```

上游使用的版本：
- alloy-genesis: 1.0.9
- alloy-trie: 0.8.1
- alloy-eips: 1.0.9

我们解析的版本：
- alloy-genesis: 1.1.3 ❌ (Cargo 拉入更高版本)
- alloy-trie: 0.8.1 ✅
- alloy-eips: 1.1.3 ❌

### 已尝试的版本

| 版本 | 结果 | 阻塞原因 |
|------|------|----------|
| v1.4.4 | ❌ | 上游 bug (alloy-trie/genesis 不兼容) |
| v1.4.5 | ❌ | alloy 版本冲突 |
| v1.4.6 | ❌ | alloy 版本冲突 |
| v1.4.8 | ❌ | alloy 版本冲突 + revm-inspectors Debug issue |

### alloy patch 1.1.3 更新已完成

已成功更新 `alloy-rpc-types-engine` 和 `alloy-rpc-types-beacon` 到 1.1.3 基础代码，添加了 N42 的 difficulty/nonce 字段。但由于依赖冲突未能编译通过。

## 已完成的升级准备工作

### alloy patch 更新进度 ✅

已成功更新 alloy patch 到 v1.0.9 API：

**alloy-rpc-types-engine 修改**:
- 在 `ExecutionPayloadV1` 中添加 `difficulty: U256` 和 `nonce: B64` 字段
- 更新 `try_into_block()` 使用这些字段
- 更新 `from_block_unchecked()` 填充这些字段
- 更新 SSZ 解码（ExecutionPayloadV2 和 V3）
- 更新 serde 反序列化（Fields enum + 处理逻辑）
- 禁用 extra_data 大小检查（N42 APoS 需要）

**alloy-rpc-types-beacon 修改**:
- 在 `BeaconExecutionPayloadV1` 中添加 `difficulty` 和 `nonce` 字段
- 更新 From/Into 实现

### 升级阻塞因素

当前阻塞升级到 v1.4.5 的主要问题是 **fork crate 之间的复杂依赖**：
- `storage/db-api` 依赖 `merkle_db_rs`（N42 特有）
- 直接替换整个 fork crate 会破坏这些依赖

## 升级所需工作

### 最小升级路径 (v1.4.5)

1. ✅ 更新 `n42/alloy-rpc-types-engine` 到 v1.0.9 API
2. ✅ 更新 `n42/alloy-rpc-types-beacon` 到 v1.0.9 API
3. ✅ 手动合并 fork crate 修改（只有 7 个文件）
4. ⚠️ 修复依赖版本冲突（需要锁定 alloy 版本）
5. 🔲 测试验证

### 解决方案选项

**方案 1: 等待 alloy 生态稳定**
- 当 alloy 1.0.x 系列稳定后，版本冲突会减少
- 风险：不确定时间

**方案 2: 复制上游 Cargo.lock**
- 使用上游 v1.4.5 的 Cargo.lock 作为基础
- 需要处理 N42 特有依赖

**方案 3: 使用 [patch.crates-io] 锁定版本**
- 在 Cargo.toml 中 patch alloy-genesis 和 alloy-eips
- 复杂且难以维护

### 估计工作量

| 任务 | 时间估计 | 状态 |
|------|---------|------|
| 更新 alloy patch | 2-4 小时 | ✅ 完成 |
| 手动合并 fork crate | 1 小时 | ✅ 完成（只有 7 文件）|
| 解决依赖冲突 | 4-8 小时 | ⚠️ 阻塞中 |
| 测试验证 | 1-2 小时 | 🔲 待开始 |
| **总计** | **1-2 天** | |

## 推荐策略

### 策略 A：保持稳定 (推荐)

保持 v1.4.3，等待更重要的功能需求再升级。

**优点**: 零风险，无需工作
**缺点**: 无法使用新功能

### 策略 B：最小升级

升级到 v1.4.5，只更新必要的 alloy patch。

**优点**: 获得 bug 修复
**缺点**: 需要 1-2 天工作

### 策略 C：减少 Fork 依赖

将 N42 定制移出 fork crate，使用独立模块：

- ✅ `n42-consensus-traits` - 已创建
- ✅ `n42-storage` - 已创建
- ✅ `n42-consensus-core` - 已创建
- ✅ `n42-fusaka` - 已创建
- 🔲 `n42-chainspec` - 待完成
- 🔲 移除 alloy patch 依赖 - 待完成

**优点**: 长期维护成本最低
**缺点**: 需要大量重构

## 版本兼容性矩阵

| reth | revm | alloy | 状态 |
|------|------|-------|------|
| 1.4.3 | 23.1.0 | 1.0.5 | ✅ 稳定 |
| 1.4.4 | 24.0.0 | 1.0.9 | ❌ 上游有 bug |
| 1.4.5 | 24.0.0 | 1.0.10 | 🔶 需要更新 patch |
| 1.5.0+ | 变化大 | 变化大 | ❌ 重大 API 变更 |

## 补丁文件位置

已生成的补丁保存在 `/tmp/n42-patches/`:
- chainspec.patch
- consensus-consensus.patch
- ethereum-hardforks.patch
- net-peers.patch
- node-core.patch
- primitives-traits.patch
- revm.patch
- storage-db.patch
- storage-db-api.patch
- storage-provider.patch
- storage-storage-api.patch
- rpc-rpc-types-compat.patch

