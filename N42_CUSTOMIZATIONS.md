# N42 定制修改清单

## 模块1: primitives-traits
### 定制文件:
- `crates/primitives-traits/src/header/clique_utils.rs` - **N42独有**, 提供 clique 签名恢复和 seal hash 计算
- `crates/primitives-traits/src/header/mod.rs` - 导出 `clique_utils` 模块

### 定制内容:
- `recover_address()` - 从区块头恢复签名者地址
- `seal_hash()` - 计算 clique 共识用的 seal hash
- `recover_address_generic()` - 泛型版本
- `seal_hash_generic()` - 泛型版本

## 模块2: consensus
### 定制文件:
- `crates/consensus/consensus/src/lib.rs` - 扩展 `Consensus` trait

### 定制内容:
- `prepare()` - APoS 准备区块头
- `seal()` - APoS 签名封装
- `snapshot()` - 获取快照
- `propose()` - 投票提案
- `discard()` - 撤销提案
- `proposals()` - 获取当前提案
- `total_difficulty()` - 获取总难度
- `wiggle()` - 计算 wiggle 时间
- `set_eth_signer_by_key()` - 设置签名者
- `get_eth_signer_address()` - 获取签名者地址
- 自定义错误类型: `SignHeaderError`, `SaveSnapshotError`, `NoSignerSet`, `AposErrorDetail`

## 模块3: storage
### 定制文件:
- `crates/storage/db-api/src/models/beacon.rs` - **N42独有**, beacon 数据模型
- `crates/storage/db-api/src/tables/mod.rs` - 添加 beacon 相关表

### 定制内容:
- `BeaconStateRecord` 表
- `BeaconBlockRecord` 表
- `BeaconNum2Hash` 表
- `PlainValidatorState` 表
- `ValidatorsHistory` 表
- `ValidatorChangeSets` 表
- QMDB 读取钩子（`reth_storage_api::n42_state`：`on` / `verify` 模式，`N42_HASHED_TABLES=off`
  时拒绝未应答的读取）与分块并行的 hashed post-state：最新状态在
  `crates/storage/provider/src/providers/state/latest.rs`；历史/叠加状态自 reth v2.7.0 起在
  `crates/storage/storage-overlay/src/provider.rs`（上游删除了 `HistoricalStateProvider`，
  该 crate 为此新增 vendored，见 `docs/RETH_2_7_0_UPGRADE.md`）
- `crates/storage/provider/src/providers/database/provider.rs`：`N42_HASHED_TABLES=off` 时不写 hashed 表
- reth v2.7.0 删除的 `MemoryOverlayStateProvider` 保留在 vendored 的
  `crates/storage/provider/src/providers/state/memory_overlay.rs`（N42 新增文件，
  `n42_engine_types::memory_overlay` 重新导出）；`BlockchainProvider::state_provider_for_state`
  （`latest` / `pending` / `state_by_block_hash` 在内存块上的状态）默认用它逐读遍历内存块、
  其下是持久化锚点的状态（`n42_layered_state_provider`），不再走上游按 tip 摊平整个内存链的
  `ExecutionOverlay`；`N42_OVERLAY_READS=upstream` 恢复上游路径（loop308 的跟随者减速，见
  `docs/RETH_2_7_0_UPGRADE.md`）
- `crates/storage/provider/src/providers/state/overlay_filter.rs`（N42 新增文件）：每个内存块一个
  split-block Bloom 过滤器（512 位块、每键 8 位、11 位/键，约 1% 假阳性，147k 账户约 200 KB），
  覆盖该块 `BundleState` 的地址（账户与存储读）和合约代码哈希（字节码读）。
  `MemoryOverlayStateProvider` 逐块读之前先查过滤器，未命中即跳过该块，命中照旧探测，结果按构造不变。
  过滤器按执行输出（`Arc` 地址 + `Weak` 校验）缓存在有界侧表（64 项，块释放即淘汰），
  在第一次有覆盖层打开在该块上时由后台线程构建一次，打开者从不等待。`N42_OVERLAY_FILTER=0` 关闭。
  `N42_OVERLAY_FILTER_CAP`（默认 1024，下限 64）：过滤器缓存容量，须不小于内存中的块数，否则每次打开都会全部未命中并重建；满时淘汰最近最少使用的条目。
  计数器 `overlay_filter_skips` / `overlay_probes` 在 `N42_PHASE_TIMERS=1` 时打印在领导者的阶段行上
- `crates/storage/provider/src/providers/op_metrics.rs`（N42 新增文件）：`N42_STORAGE_OP_METRICS=0`
  时跳过每次操作的存储指标——静态文件写入器每追加一行交易/收据/发送者的计数与耗时直方图
  （`StaticFileProviderMetrics::record_segment_operation`）以及 RocksDB 每次点读写的指标
  （`RocksDBProvider::execute_with_operation_metric`）；未设置或其他值保持上游行为（loop314 剖析：
  `storage-*` 线程 8% 花在这些指标上）
- `crates/storage/storage-overlay/src/{manager,builder,provider}.rs`：`OverlayManager::without_state_trie_overlay()`
  （N42 新增构造函数）——不带 `state-ovly` 工作线程池，插入块时不预计算，执行叠加层改为分层
  （`ExecutionOverlay::layered`：按块从新到旧逐读查各块的 `BundleState`，不摊平、不缓存）；
  状态树叠加层（MPT 根/证明用）仍按需在调用线程上计算。由 `--engine.state-trie-overlay`
  （见模块6）选择
- `crates/storage/provider/src/providers/n42_persist.rs`（N42 新增文件）：持久化批次的计时器与开关
  （`docs/PERSISTENCE_COST_STUDY.md`）。计时器与上游 `save_blocks_*` 同在 `storage.providers.database`
  作用域：`save_blocks_pre_scope` / `_plain_reverts` / `_scope` / `_post_scope` / `_qmdb_persisted`、
  `save_blocks_account_history_{map,reads,batch}`（`rocksdb/provider.rs` 的 `write_account_history`
  三个阶段）、`save_blocks_sf_{headers,transactions,senders,receipts,account_changesets,storage_changesets}`
  （`static_file/manager.rs` 的 `write_segment`，含 `sync_all`）。不改变行为
- `N42_PERSIST_QMDB_IN_SCOPE=1`（默认关）：`save_blocks_inner` 把 QMDB 读视图的 `on_state_persisted`
  放到独立线程，与静态文件/RocksDB/MDBX 写并行，在 commit 之前 join（`run_with_qmdb_persisted`）。
  它只需要块列表与 QMDB forest，不读数据库事务
- `N42_ACCOUNT_HISTORY=on|off`（默认 `on`，与上游逐字节相同）：`off` 时 storage v2 批次只跳过
  RocksDB `AccountsHistory` 索引写（`RocksDBWriteCtx::write_account_history`）；账户 changeset
  （回滚来源）照旧写入静态文件。第一个缺索引的块作为缺口标记写入 `StageCheckpoints` 的
  `N42AccountHistoryGap` 键（与批次同一 MDBX 事务）；`IndexAccountHistory` 检查点照常推进（不触发
  启动时的 pipeline 一致性检查）。有缺口时：`HistoryReader::account_history_info` 只信任缺口以下的
  索引，缺口内用 changeset 扫描回答（`database/n42_account_history.rs`），扫描超过
  `N42_ACCOUNT_HISTORY_SCAN_MAX`（默认 100000 块）则返回点名该模式的错误，绝不返回错值；
  `rocksdb/invariants.rs` 的 `heal_accounts_history` 不修复（不 unwind）缺口内的范围；unwind 到缺口以下
  时删除标记（`update_pipeline_stages_after_unwind`）。`StoragesHistory` 不变

## 模块4: network
### 定制内容:
- 增加了网络预算参数 (budget.rs)
- N42 特定的导入/验证逻辑

## 模块5: ethereum/evm
### 定制内容:
- `evm_env()` 中使用 `recover_address()` 获取 beneficiary（已过时：该 fork 早已退回上游。2026-09-13 起此逻辑在 `crates/n42/engine-types/src/n42_evm.rs`：非 HotStuff 链执行区块时，`evm_env` 与 `evm_env_for_payload` 以 Clique 封签恢复出的签名者为 beneficiary，与出块器的 coinbase 一致；HotStuff 链沿用区块头 beneficiary）
- `blob_max_and_target_count_by_hardfork()` 方法

## 模块6: node/builder
### 定制文件:
- `crates/node/builder/src/launch/executed_inserts.rs`（N42 新增）
- `crates/node/builder/src/launch/engine.rs`（引擎循环多一个 select 分支）
- `crates/node/builder/src/lib.rs`（`pub use launch::executed_inserts`）
### 定制内容:
- 一条进入引擎循环的通道：节点把自己已经执行过的块（`BuiltPayloadExecutedBlock`）交给引擎，
  循环转成 `EngineApiRequest::InsertExecutedBlock` 并回执。reth 只对 payload 事件流里带执行结果的
  payload 走这条路，以太坊 payload 类型不带；N42 的共识在构建之后才封装块头、哈希会变，
  所以由节点自己配对（`bin/n42/src/payload_serve.rs`）。纯增量，默认对上游行为无影响。
- `--engine.state-trie-overlay <bool>`（环境变量 `RETH_ENGINE_STATE_TRIE_OVERLAY`，
  `crates/node/core/src/args/engine.rs` 新增字段 `state_trie_overlay: Option<bool>` 与
  `EngineArgs::state_trie_overlay_enabled(genesis)`）：未设置时，genesis 声明 QMDB 状态承诺或
  `N42_HASHED_TABLES=off` 则为 false，否则 true。`launch/engine.rs` 据此创建
  `OverlayManager::new(池)` 或 `OverlayManager::without_state_trie_overlay()`；
  `crates/ethereum/cli/src/app.rs` 在 false 时把运行时的 `state-ovly` 池缩到 1 个（空闲）线程
  （reth v2.7.0 默认 4 个，loop309/310 每轮约 22k CPU 单位，见 `docs/RETH_2_7_0_UPGRADE.md`）

## 其他 N42 独有模块:
- `crates/n42/clique/` - APoS 共识实现
- `crates/n42/primitives/` - beacon 链原语
- `crates/n42/engine-types/` - 引擎类型
- `crates/n42/engine-primitives/` - 引擎原语
- `crates/n42/consensus-client/` - 共识客户端
- `crates/n42/mobile-sdk/` - 移动端 SDK
- `crates/n42/merkle_db_rs/` - Merkle DB
- `crates/n42/pubsub-mem/` - 内存 pub/sub
- `crates/n42/alloy-rpc-types-engine/` - RPC 类型
- `crates/n42/alloy-rpc-types-beacon/` - Beacon RPC 类型
- `crates/ethereum/hardforks/` - N42 特定硬分叉
