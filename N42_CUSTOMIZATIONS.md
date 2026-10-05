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
- `crates/storage/provider/src/providers/static_file/n42_sf.rs`（N42 新增文件）：交易静态文件段的写入开关
  （`docs/PERSISTENCE_COST_STUDY.md` 第 11 节）。`static_file/writer.rs` 新增两个方法（只加不改）：
  `append_transactions_encoded`（追加已按 `Compact` 编码好的行，tx 编号检查、段头范围与 offset
  与逐条 `append_transaction` 完全相同）与 `n42_start_writeback`（对数据文件调用
  `sync_file_range(SYNC_FILE_RANGE_WRITE)`，只是提示，失败忽略）；`static_file/manager.rs` 的
  `write_transactions` 改为经 `n42_sf::append_block_transactions` 写每个块。
  `N42_SF_PARALLEL_ENCODE=1`（默认关）：每块的行在 storage 线程池上按 4096 行一组并行编码，再按序追加，
  磁盘字节与串行路径逐字节相同；`N42_SF_EARLY_WRITEBACK=1`（默认关）：每块追加后启动数据文件回写，
  批次末尾的 `sync_all` 不变（持久性语义不变），只需等最后一块。测试在 `static_file/n42_sf_tests.rs`
  （两条路径逐文件逐字节比较、原读取器读回、同一文件混写与重启、unwind 后重写、崩溃自愈）；
  provider 的 dev-dependency 新增 `n42-tx-types`。两个开关同样覆盖 `Receipts` 与 `AccountChangeSets` 段：
  `writer.rs` 另加 `append_receipts_encoded` 与 `append_account_changeset_entries_encoded`（只加不改；后者向
  `begin_account_changeset` 开始的块追加已排序、已编码的条目，`.csoff` 不变），`manager.rs` 的
  `write_receipts` / `write_account_changesets` 改经 `n42_sf::append_block_receipts` /
  `append_block_account_changeset`。账户 changeset 的并行路径按 reverts 原顺序编码（`AccountInfo` 按引用转换），
  再对 `(address, 位置)` 排序（即按地址的稳定排序）后按序拼接，行与顺序与串行路径相同；串行路径即原代码。
  测试在 `static_file/n42_sf_seg_tests.rs`

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
- `N42_ENGINE_EXEC_CACHE=on`（未设置或其他值即跳过；不改任何 fork 的 reth crate，代码在
  `crates/n42/qmdb-reth/src/exec_cache.rs`，由 `QmdbEngineValidatorBuilder` 包装引擎树的验证器）：
  QMDB 链上默认跳过——以"已执行"方式插入引擎的块不再写入 reth 的跨块执行缓存
  （`on_inserted_executed_block` 里的 `insert_state`，一个 16.3 万笔交易的块在引擎线程上
  14-46 ms）；其余效果照旧（延迟排序的 trie 数据在 `deferred-trie` 工作线程上计算，
  `ExecutedBlock` 不变；只少记 reth 私有的三个排序直方图）。N42 路径上没有任何读者：跟随者
  在已发布的分片上执行，出块器有自己的状态路径；reth 自己执行的块按父哈希取缓存，哈希不符时
  拿到清空的缓存，不会读到错误状态。以前哪个节点付这笔开销取决于启动顺序（错过 view 1 那个
  未提交的块 1 的节点，见 `docs/INDUSTRY_SURVEY_2026_10.md` 11.11）。`on` 恢复上游行为做 A/B；
  非 QMDB 链始终是上游行为。启动时打印一行 `executed inserts and reth's cross-block execution cache`
  （`mode=skip|update`）。

## 跟随者直接导入的交接路径（不改任何 fork 的 reth crate）:
- `N42_HANDOFF_ON_LANDED=1`（默认关；代码在 `bin/n42/src/follower_import.rs` 的
  `handoff_on_landed` / `note_handed` / `wait_until_parent_handed`，`payload_serve.rs` 在引擎对
  直接导入的块答复 `newPayload` VALID 时记下该块）：在父块已发布输出上执行的块，交给引擎前只等
  父块的直接导入被引擎答复，不再等父块成为 canonical。reth 的 `InsertExecutedBlock` 只检查块号
  不低于 canonical 高度、树里没有，然后挂到父块下；`newPayload` 对树里已有的块答 VALID；之后的
  forkchoice 经树把父块和本块一起变成 canonical；QMDB 森林里本块的树在交接前已由本块的根任务
  建好，`on_canonical` 照常找到；持久化只写 canonical 块。原来等 canonical 要等父块的提交
  forkchoice（验证者在父块导入答复后才发，引擎线程上 30-36 ms）再加最多 20 ms 的轮询（变成
  canonical 不唤醒任何等待者），见 `docs/INDUSTRY_SURVEY_2026_10.md` 11.12。打开后被记下的块
  立即唤醒子块的等待；集合有界（64）；父块走引擎自己的路径时仍按 canonical 判断（20 ms 轮询兜底），
  超时（3 s）行为不变。`direct import` 两行新增 `handoff_wait_us` 与 `handoff_before_canonical`
  （交接时父块是否尚未 canonical；开关关闭时恒为 false）。
- `N42_SHARDS_MERGE_OFF_PATH=1|verify`（默认关）：构建路径上把分片合并成一个 `BundleState`
  （引擎的已执行插入、持久化、已发布输出都要这个完整的 bundle，交接无法只拿一部分）时，账户表与
  回滚集（复制并排序）两半同时做（`FrozenShards::merged_timed`，
  `crates/n42/engine-types/src/output_shards.rs`），交接等较长的一半而不是两者之和；拼装顺序不变，
  结果与原合并逐字段相同（测试覆盖）。`verify` 另外按原方式再合并一次并比较，计数打印在
  `build path: the root's start after the execution` 一行的 `merge_verified` / `merge_mismatches`。
  该行无论开关都新增 `merge_ms`、`merge_wait_ms`（交接在 join 处等了多久）、`merge_state_ms`、
  `merge_reverts_ms`、`merge_append_ms`、`merge_mode`，以前合并时长只在 debug 行里。

## 出块器链式构建叠放的自建块层数（不改任何 fork 的 reth crate）:
- `N42_LEADER_LAYERS=2|3|4`（默认 2，即原行为；其他值打印警告并按 2；`N42_GRANDPARENT_SHARDS=0`
  时为 1，只叠父块；代码在 `crates/n42/engine-types/src/direct_build.rs` 的 `leader_layers` 与
  `opener_on_sealed_parent_with`）：在父块封印时开始的链式构建，把父块及其最近的 `层数-1` 个自建
  祖先（各自的冻结分片 + 残余，或 `StateReady` 后的整 bundle，均在封印哈希下）叠在引擎状态之上，
  引擎只需持有最深一层之下的块（2 层为 N-3，3 层为 N-4，4 层为 N-5）。E=1 时引擎在构建开始时落后
  两到三块，5-15% 的构建开始时落后四块（`docs/SHARED_EXECUTION_SCOPE.md` 8.2），多一层即可覆盖。
  一层的内存约为一个块的分片集合（163,000 笔约 40 MB，200,000 笔约 50 MB，250,000 笔约 65 MB，
  与构建存储和在途构建共享 `Arc`）。释放：新父块的 `keep` 释放不在其祖先链上的层（链前进时最老的、
  被放弃构建的分支、不相关的块）；canonical 通知（`bin/n42/src/main.rs` 的订阅者调用
  `leader_layers::on_canonical`）释放比引擎 tip 低 `层数` 块及以上的层（交接给其他执行层之后、
  被放弃的分支）；持久化本身不释放（持久化的块先已 canonical）。释放从不影响正确性：找不到层的构建
  少叠几层、等较浅的锚点。
  与层数无关的修正：最深的锚点不在引擎里时，等的是这个锚点本身（先落地的那个），而不是像以前那样
  轮询祖父块（引擎晚一次导入、60-90 ms 后才有）；等待由同一个 canonical 订阅唤醒
  （`direct_build::engine_landed`，未接线时仍为 2 ms 轮询，接线后 20 ms 兜底），超时（150 ms，
  再等父块 QMDB 根与 `Complete`）行为不变。`seal-first build phases` 一行新增 `state_wait_us`，
  `state_wait_split` 新增 `open_layers`（叠放层数，含父块）、`open_fallback`（是否等了引擎）、
  `open_engine_us`（该等待）、`open_keep_us`（`keep` 及其释放的层的析构）、`open_provider_us`
  （锚点状态的首次查找）；`state_wait_on` 新增具名原因 `layer_release` 与 `provider_open`，
  `open` 只剩无法归类的部分。

## 出块器并行执行的批次分派（不改任何 fork 的 reth crate）:
- `N42_BUILD_ONE_WAVE=1`（默认关；代码在 `crates/n42/engine-types/src/parallel_transfer.rs` 的
  `build_one_wave`、`batch_groups_one_wave` 与 `execute_for_build_opts`）：出块器的执行批次每个线程最多
  一个（批次数 = min(构建池线程数, 发送者组数)），按前缀和把整组按候选顺序切成大小相近的批次（每批与
  `总数/线程数` 至多差一组），并且一次性逐批 `spawn` 到构建池（每批一个任务，空闲线程直接取走），
  而不是原来最多两倍线程数的批次、由一个线程二分递归分发。原方式下第二波批次要等第一波某批结束
  才开始：loop334 L3FS70（200,000 笔、400 个 500 笔的发送者段、32 线程、58 批）的
  `batch_start_skew_ms` 等于 `batch_median_ms` + 2-3 ms（相关系数 0.96），执行是两个批次长。
  批次仍是整组发送者、候选顺序，和换一个池大小时一样；状态、收据、gas 与回滚逐项相同（测试比较
  QMDB 操作、gov5 收据根与 bloom、累计 gas、graft 后账户与回滚、输出分片合并后的 bundle）。
- `seal-first build phases` 一行无论开关都新增：`batch_first_start_us`、`batch_last_start_us`、
  `batch_dispatch_us`（每个跑过批次的线程都已开始其第一批的时刻；两波时 `batch_last_start_us` 减它
  即第一波长度）、`batch_last_end_us`（均为相对交给池的时刻）、`batches`、`batch_threads`、`one_wave`；
  帧选择的拆分 `start_walk_ids_us`、`start_walk_check_us`、`start_walk_settle_us`、`start_walk_us`；
  父块封印之后到本构建开始的路（`crates/n42/engine-types/src/post_seal.rs`，仅观测）：
  `prev_seal_to_header_us`（chain header 写给验证者）、`prev_seal_to_answer_us`（答复写完）、
  `prev_seal_to_request_us`（本构建请求的第一个字节）、`prev_seal_to_entry_us`（进入 `build_on_own`）、
  `prev_seal_to_start_us`（本构建开始）、`prev_seal_to_import_us`（任一密钥按头部导入父块的第一个请求，
  E=1 时即 leader 提案之后）；`sealed_unix_us`（本块封印的墙钟，用于与验证者的 `proposal sent`、
  `block committed` 行对齐）。`next_start_gap_ms` / `next_entry_gap_ms` 改为在构建开始时记录：以前在
  完成时才读上一次封印，那时已被本块自己的封印覆盖，所以一直是 0。

## 多个验证者密钥共享一个执行层（不改任何 fork 的 reth crate）:
- `N42_IMPORT_ONCE=1`（默认关；代码在 `bin/n42/src/import_once.rs`，由 `payload_serve.rs` 的
  `OWN_BLOCK`、`COMPACT_BODY`、`FOREIGN_BODY`、`NEW_PAYLOAD` 四条导入路径使用）：按块哈希登记，
  每个执行层每块只导入一次。第一个请求照旧做全部工作；同一哈希的后续请求（任何连接、任何密钥）
  不解码、不组装、不执行，等第一个请求的检查完成即收到 CHECKED，导入落地后收到同一个最终状态；
  导入完成后才到的请求直接从登记表答复。哈希在任何工作之前取得：`OWN_BLOCK` 解头部，
  两条 body 路径读帧里声明的哈希，`NEW_PAYLOAD` 从帧里直接读（不解码 19 MB 的 payload）。
  第一个请求没有给出最终状态就结束（连接断开、路径拒绝、引擎失败）时登记重置，等待者之一接手。
  只有 VALID/INVALID 会答复之后到的请求；SYNCING/ACCEPTED 只答复当时在等的请求。
  leader 自己的块：不论 leader 的 `OWN_BLOCK` 还是其他密钥的 body/payload 先到，都只把构建结果
  交给引擎一次（compact body 先到时按头部找到本节点的构建，按头部导入而不组装执行）；找到构建即
  发布 CHECKED（构建本身就是本执行层的结果）；共享时若验证者在封块时构建（`N42_BUILD_ON_SEAL`），
  payload 路径对构建用 `find` 而不是 `take`，与 `OWN_BLOCK` 一致。登记表保留最近 64 个哈希，
  先淘汰已完成的；仍在工作的条目超过 128 个才淘汰。与 `N42_VOTE_BEFORE_SLOT=1` 同时设置时启动报错
  （保留执行由一个验证者释放，无法在密钥间共享）；运行中收到带 `HOLD_EXECUTION` 的请求时答复错误。
  `own block imported by header`、`direct import` 两行和 `raw newPayload` 新增 `once_reqs`
  （本块到目前的请求数）、`once_served`（其中从登记表答复的）、`once_imports`、`once_blocks`、
  `once_takeovers`（启动以来累计；`once_imports == once_blocks` 即每块每执行层一次导入），
  开关关闭时恒为 0。关闭时每条路径与以前逐字节相同（测试覆盖）。
  本执行层自己构建的块：三条跟随者路径（compact body、foreign body、payload）在任何组装或解码之前
  按头部识别（同父块、块号、根、gas、交易根的保留构建；封块会把 withdrawals root 改成 gov5 的奖励
  承诺，两种形状都比较——原来按原值比较，loop328/330 中 1,179 个自建块有 1,175 个被再执行一次），
  立即回 CHECKED，等构建完成后按头部交给引擎、回最终状态；构建被放弃时才走普通导入。各行新增
  `own_from_build`（从构建导入的自建块，累计）与 `own_executed_again`（被再执行的自建块，累计，应恒为 0；
  发生时另有 warn 行）。

## 交易供给路径：ingest、队列闸门与剪枝（不改任何 fork 的 reth crate）:
- `N42_INGEST_RUNTIME=1`（默认关；代码在 `crates/n42/tx-ingest/src/runtime.rs`，由 `n42_tx_ingest::spawn_serve`
  使用）：ingest 的监听、每个连接的读循环、闸门、解码、答复、admitter、闸门 watcher 与 5 s 统计行都跑在
  自己的 tokio runtime 上（线程名 `n42-ingest`，异步 worker 数 `N42_INGEST_RUNTIME_WORKERS`，默认 8，
  限 1..=64），不再与执行层主 runtime 共用。恢复（attested frame 检查或逐笔验签）在这个 runtime 的
  blocking 池上运行，并且在 blocking 线程上取恢复槽（`N42_TX_INGEST_RECOVER_PARALLEL` 个，一个普通的
  计数信号量，线程阻塞等待），连接任务既不持有也不 await 许可，所以不会出现"许可已发给一个还没被
  调度的任务"的车队（`docs/SHARED_EXECUTION_SCOPE.md` 10.2）。blocking 池的线程上限 = 槽数 + 2（无界时
  512）。`acq_us_per_frame` 此时是 blocking 线程上等槽的时间，`spawn_us_per_frame` 是此前的交接。
  runtime 建不起来时退回主 runtime 与原来的异步信号量，并打 warn。线上协议与 flood 的帧格式不变。
- `N42_QUEUE_PRUNE_THREAD=1`（默认关；代码在 `bin/n42/src/queue_prune.rs`）：每个已提交块的队列剪枝
  （own block settle、lanes/帧索引/taken 列表移除、by-hash 索引移除）从主 runtime 的 tokio 任务移到专用
  线程 `n42-queue-prune`；tokio 任务只转发通知（并照旧调用 `canonical_head::saw`）。线程醒来时取走所有
  已到的通知（合并唤醒，逐块按序处理）。`canonical blocks pruned from the queue` 一行新增 `fold_us`、
  `lock_us`、`free_us`、`frames_swept`、`coalesced`、`prune_wait_ms`；`remove_us` 现在只是持锁移除的时间。
- 无开关的内部改动（行为相同）：
  - 闸门与答复读的队列深度（`TxQueue::gate_len`）不再取 lanes 锁：`len` 与 `parked_len` 在每次释放锁时
    写入一个原子镜像，inbox 部分仍读实时的 `staged`；drain 先把批次加进镜像再从 `staged` 减去，所以
    读数在无人持锁时与持锁读数完全相同，有人持锁时是上一次释放时的值（陈旧至多一次持锁），drain
    永远不会被少算。`gate_len_locked` 保留原读法供测试对照。
  - 剪枝一遍完成（`TxQueue::prune_block`）：块的 (sender, nonce) 按连续段折叠（锁外）、lane 头已高于
    已挖 nonce 时不 split、taken 列表一遍按段拆分、帧清扫只删死帧自己的 `by_first` 项、by-hash 索引
    按分片一次写锁（大批量在队列自己的小池上并行）、移出的 `Arc` 全部在锁外交给队列的释放线程
    `n42-queue-free`（通道满四块时就地释放）。单元测试（40 万深、20 万一块）：三次调用 69-76 ms，
    一遍 5-10 ms。`remove_mined_batch` 与 `forget_hashes` 共用同一实现。
  - 5 s 的 `ingest` 一行新增 lanes 锁与 drain 的计时：`lock_holds`、`lock_duty_pct`、`lock_hold_max_us`、
    `lock_hold_max_at`（最长持锁的调用位置）、`lock_wait_max_us`、`lock_wait_us`、`drains`、`drain_txs`、
    `drain_us_mean`、`drain_us_max`（`n42_tx_queue::take_lock_stats`，每行一个区间）。

## 封块链：预先选帧、整帧取出、限时 drain 与只带布局的紧凑应答（不改任何 fork 的 reth crate）:
`docs/SHARED_EXECUTION_SCOPE.md` 第 12 节。四个开关默认全关；关闭时行为与以前相同（测试覆盖）。
- `N42_TX_QUEUE_DRAIN_CHUNK=<n>`（默认 0 = 一次持锁；代码在 `crates/n42/tx-queue/src/lib.rs`
  `TxQueue::drain_now`/`drain_chunked`）：drainer 不持 lanes 锁取走 inbox（批次计入新的 `in_hand`，闸门照读），
  在锁下放进 `Inner::pending_drain`，然后每次持锁最多插入 n 笔、两次之间释放锁；插入顺序与一次持锁的
  drain 完全相同，批次的帧在插入最后一笔的那次持锁里建索引。其他任何 drain（构建开始、剪枝）先把剩余
  部分插完再处理 inbox，所以 lanes 看到的永远是 inbox 的顺序；深度镜像计入剩余部分，闸门不会少算。
  建议 8192（单元测试：每次持锁约 0.4 ms，一次持锁的 drain 约 1 ms/17,500 笔）。`ingest` 行新增
  `drain_chunks`、`drain_chunk_max_txs`、`drain_finished`。
- `N42_PLAN_AHEAD=1`（默认关；代码在 `crates/n42/tx-queue/src/lib.rs` `Prepared`、`prepare_next_plan`、
  `frames_for_build_ahead`）：帧构建在自己的选帧之后，由应用 take 的那个线程立即为下一个构建预先选帧
  （在当前构建 take 之后的 lanes 上，算法与现场选帧相同），其帧移出 lanes 存放在 `Inner::prepared`。下一个
  帧构建只有在以下条件全部成立时才用它：其间没有别的构建开始；上一构建的 take 被 hand-off 整个作为一个
  自建块已挖而遗忘，且该块（`hold_own_block` 给出的哈希）就是新父块；上一 take 没有剩余；gas 够；它涉及的
  每个 sender 链上都没挖到它的 nonce、lane 里也没有比它更低的 nonce。否则还回 lanes（链已挖的除外）后现场
  选帧；规范剪枝挖到其中 nonce 时立即作废。没有截断帧且 gas 有余时用其后到达的帧补足。构建阶段行新增
  `plan_ahead`（0 现场/1 预选/2 预选+补足）、`plan_age_us`、`plan_prep_us`、`plan_topup_txs`、
  `plan_discard`；`ingest` 行新增 `plan_discards`（按原因计数）。
- `N42_PULL_BY_FRAMES=1`（默认关；代码在 `crates/n42/engine-types/src/frame_blocks.rs` `select`/`take_bulk`
  与 `payload.rs`）：帧构建在并行步骤与 puller 都开启、且 sender 不是待验证的声明时，用
  `QueueBest::take_frame_segments` 整帧取出全部计划帧，在 build 池上并行复制每帧切片的 `Arc`，构建拿着这个
  向量直接开始并行步骤，不启动 puller 线程（迭代器留在构建线程上处理拒绝与归还）。候选交易与顺序不变。
  阶段行新增 `pull_bulk_txs`、`pull_bulk_us`（计入 `start_best_ms`，`par_pull_ms` 随之约为 0）。
- `N42_ANSWER_LAYOUT_ONLY=1`（默认关；代码在 `crates/n42/h2-execution/src/{driver,raw_engine}.rs`、
  `h2-el-rpc/src/engine.rs` 与 `bin/n42/src/payload_serve.rs`；隐含 `N42_TAKE_COMPACT=1`，且仅在
  `N42_FRAME_BLOCKS=1` 时生效）：提议者在 build-on-own 请求末尾加标记，执行层在块的 frame layout 非空且
  总和等于交易数时，COMPACT_BUILT 应答省略交易哈希列表（200,000 笔约 6.4 MB），也不计算哈希向量；旧执行层
  忽略标记照常带哈希，未按帧对齐的块也照常带哈希，解码只在布局覆盖整块时接受空列表。验证者之间交换的
  紧凑块体逐字节不变（测试覆盖）。执行层的 "built ahead" 行与验证者的 "proposal sent" 行新增
  `answer_layout_only`。

## HotStuff-2 结算标签（不改任何 fork 的 reth crate）:
- `N42_SETTLEMENT_TAGS=split|legacy`（默认 `split`；代码在 `crates/n42/h2-execution/src/settlement.rs`，
  由 `ExecutionDriver` 的每个 forkchoice 使用）：`latest` = 共识已提交的块；`safe` = 执行已认证的块
  （延迟执行下 N+1 提交即认证 N——N+1 的头携带 N 的执行字段且其法定人数核对过；分叉前提交即认证本块）；
  `finalized` = 已认证且不高于本节点最后持久化块的块。三者只前进、`finalized` ≤ `safe` ≤ `latest`；
  不能证明是 head 祖先的标签以零哈希发送（引擎视为"不变"）。全新链以创世块为下限；重启的节点在第一次
  提交前发零标签，不会把 reth 从磁盘恢复的标签拉回。持久化高度由验证者现有的 50 ms 轮询器读取
  （`n42Engine_inMemoryBlocks` 之外同一 tick 读新增的 `n42Engine_persistedBlock`，
  `bin/n42/src/engine_ext.rs`）；执行层没有该方法时 `finalized` 跟随 `safe` 并警告一次。
  `legacy` 逐字节恢复以前的 head = safe = finalized = 已提交块，用于 A/B；`payload_serve` 在 `split`
  下给兄弟块重提议的 head 回退发零标签。只影响本节点 Engine API / RPC 语义
  （`eth_getBlockByNumber("safe"|"finalized")`），验证者之间交换的内容不变，APoS 路径不变。
  见 `docs/PHASE_D_DEFERRED_EXECUTION.md` 17.7。

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
