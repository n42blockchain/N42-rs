# Ethereum 主网 witness 回放：用 Rust 超越 gov5 的方案（2026-08-27）

本文是新方向的起点文档：先把 `../N42-gov5` 最近几天 witness 执行的代码、
优化过程和实测数据读清楚，再据此给出在本仓库用 Rust（reth 2.5.1 / revm 42）
做同一件事、并明确以 gov5 生产数字为基线去超越的架构与里程碑。
所有 gov5 数字均来自其仓库 `docs/ethel/` 下的交接文档与本机 `/data/blockchain`
的输入集；本文中标注"估"的数字是推断，必须以实测替换。

## 1. gov5 在做什么，做到了多快

`cmd/witness-replay`（`internal/ethel/witness_replay_*.go`）把 Ethereum 主网
`0..25,765,565` 共 25,765,566 个块、3,678,100,106 笔交易**无状态地**重放一遍：
每个块自带执行时读到的全部状态值（witness），块与块之间没有依赖，
worker 池按块并行，聚合器按块号重排。验收口径固定为：

- 每块 `GasUsed` 必须等于 header；
- Byzantium 之后 receipts root 必须等于 header（`EthReceiptHash` = 标准 receipt trie）；
- `failed=0` 才算通过，`--skip-verify`/`--continue-on-error` 的结果不算。

本机（AMD EPYC 9B45，128C/256T，136 GiB，NVMe）上的实测演进：

| 阶段 | 配置 | 墙钟 | CPU-s | 备注 |
|---|---|---:|---:|---|
| 起点 | 104w，bodyc 输入 | 2h27m10s | 456,881 | 部分 band 塌陷到 165–292 blk/s |
| 生产 t3 | 128w / 6 reader / GOGC 300，geth freezer 输入 | **49m48s** | **376,118** | 全量 + 验证，failed=0 |
| 最快墙钟 | 256w | 45m56s | 482,741 | 256w 下间歇性 nonce 失败未解 |

全量平均 ≈ 8,600 blk/s、≈ 1.23M tx/s；密集 band（24.5–25.5M）在 256w 下
2,472–2,876 blk/s。CPU-s 口径在 SMT 下偏大（256 线程忙时每"CPU 秒"约半个物理核）。

gov5 侧的结论（`witness-bodyc-vs-freezer-and-full-run-2026-08-25.md`、
`witness-replay-handoff-2026-08-26.md`）：

- 已证伪：GOMAXPROCS 超订、reader 数、内存上限、汇编 keccak（更慢）。
- 瓶颈实证：bodyc 整段物化（8192 块一段 zstd）造成长 run 塌陷 → 改读 geth freezer；
  GOGC 必须跟随活堆；256 线程时 2/3 的锁等待在 `mallocgc` 的 mcentral 锁上
  ——Go 分配器是并发上限。

## 2. gov5 单块执行剖面：钱在哪里

`evm-block-execution-optimization-map-2026-08-26.md`（24.0–24.2M 四分片合并
profile，15,338 CPU-s；heap 682 GiB / 110 亿对象）：

| 层 | CPU | 在 Rust/revm 里 |
|---|---:|---|
| interpreter 循环 + opcode | ≈ 60% | revm 的解释器（跳转表、`U256` 栈、共享内存）已是该层的成熟实现，不需要我们写 |
| 预编译（ecrecover cgo 2.95%、bn256 4.5%、modexp 1.9%） | 9.6% | 共识必需；revm-precompile 可选 `secp256k1`（C）、`blst`、arkworks bn、aurora modexp——需逐项 A/B |
| 状态访问（IBS 的三张 map、accessList、aeshash） | ≈ 11% | 结构性问题：Go 内建 map 不能换哈希、键按值拷贝。Rust 里自定义 `FxHash`/开放寻址表是常规操作 |
| 每 tx 串行（Hash、Prepare、FinalizeTx 拷 dirty→origin、receipt+bloom） | ≈ 10% | revm 的 journal 是带标签枚举而非 `interface{}` 装箱；tx 结束是 O(1) |
| 分配器 + GC | 4.9% + GC mark | **没有 GC**；用 `mimalloc`/线程本地 bump arena，无 mcentral 锁 |
| 每块串行（Reset、receipt trie） | 3.1% | 不可摊薄；receipt trie 用 alloy `ordered_trie_root` |

gov5 自己的排序表把"无共识风险的小项"合计估为 7–8% CPU，第二梯队再 6–7%，
做完后 interpreter 之外的开销从 ~17% 降到 ~5%。**在 Rust 里这两梯队的大部分
是语言与库天然给的**（无装箱、无 GC、值类型、可换哈希），剩下要靠我们的
是 §4 的并行结构与输入管线。

## 3. 输入集与格式（本机 `/data/blockchain`）

| 目录 | 内容 | 大小 |
|---|---|---:|
| `witness/` | N42 列式：`headerc`（4.8G）、`bodyc`（598G）、`witness`（178G）、`senders`（41G）、`codes`（5.7G），`MANIFEST.txt` 有源端摘要 | 826G |
| `witness-geth/` | geth ancient 风格 `headers.NNNN.cdat` / `bodies.NNNN.cdat`（64 块一批 zstd）——生产 run 用的是它 | 854G |
| `code-mdbx/` | MDBX，只有 Code 表（热层兜底） | 19G |

格式要点（`modules/rawdb/freezer/{table,freezer}.go`、`internal/ethel/{body,header}_compact.go`）：

- **cidx**：可选 16 字节头 `"NCIX"‖version‖flags‖batchSize‖entrySize‖start(BE u64)`，
  其后每项 6 字节 geth 索引 `fileNum(2 BE)‖offset(4 BE)`；`flags` 0x01 = 项为
  zstd 压缩，0x02 = 批模式（同批 64 项共享一个 offset，一个 zstd blob 内部再分项），
  0x08 = 地址索引（26 字节项 `addr‖fileNum‖offset`，codes 专用）。geth 写的 cidx
  末尾有"下一写入"哨兵项。数据文件 2×10^9 字节轮转。
- **headerc/bodyc**：8192 块一段、列式 + 段级 zstd。headerc 去掉了可推导字段
  （parentHash、bloom、number、post-merge 常量）；bodyc 按 txType/R/S/to 字典/
  nonce+gas varint/value/feeCap/tipCap/blobFeeCap/calldata/accessList/blobHashes/
  authList 分列，段标志 `bfAuthVFull` 决定 7702 的 V 编码（旧段 V=27/28 被折成 0，
  回放靠 header 的 txRoot 消歧）。
- **witness**：每块一条，`[len:1][data:len]` 的**顺序读流**（`witness.go`）：
  `ReadAccountData` 写入 `StateAccount.MarshalV2`（缺失写 len 0），
  `ReadAccountStorage` 写入值字节（空写 0）。**没有 key**。
- **senders**：每块一条，`20 × n` 字节按 tx 顺序（省掉 ecrecover）。
- **codes**：按内容寻址（`codes.hidx`）或旧版 20 字节 `codeHash[:20]` 前缀索引，
  每段 zstd；读取后必查 keccak 等于账户 codeHash，不等则视为重部署落到热层。

## 4. 决定性的约束：witness 是位置式的

gov5 的回放读取器 `WitnessReplayReader` 不看地址和 slot，只按调用顺序从流里
取下一个值。正确性完全依赖**回放时状态读取的发生顺序与录制时逐字节一致**。
录制端为此专门把所有 map 迭代改成 `sortedAddresses`，并且顺序里包含了
IntraBlockState 特有的时点，例如 `FinalizeTx` 里对 `balanceInc` 中"从未被加载
过"的账户按地址排序补读、`nilAccounts` 对缺失账户的块内缓存、每块 `Reset` 后
首次触碰才读等。

revm 的读取时点不同（access list 预热时就加载账户与 slot；coinbase 在结算时
加载；`SELFDESTRUCT`/`CREATE` 的存在性检查路径不同）。让 revm 逐字节复刻
Erigon 派 IBS 的读序，等于在 Rust 里重写一个 IBS，且 25M 块里任何一个时点
差异都会以 gas/receipt 不匹配的形式在很远的地方爆出来——这是**不该走的路**。

**决策（2026-08-27 修订）：witness 保持位置式、无 key，但由 reth 自己录制。**
带 key 的格式被否决：回放时每块要做数千次 map 查询、2500 万块合计上百亿次，
且 key（20/52 字节）普遍比值大，存储与性能优势一起丢掉；位置式回放是 0 查询。

改为让 reth 在执行阶段按 revm 自己的读取顺序写出流：录制端和回放端跑的是
同一份 revm `State` 与同一份 reth 块执行器，读序**由构造保证一致**，不需要
任何一方模仿对方。实现见 `docs/patches/0001-feat-witness-record-*.patch`
（打在 n42blockchain/reth `23316e3ff8`、分支 `witness-record`）：

- vendored `revm-database` 42.0.0 加 `State::read_observer`（`StateReadObserver`：
  每次 `basic`/`storage` 回答后、每次提交前通知）；
- `reth-witness` crate：流格式（`[len:1][data]`，账户 = nonce/balance/codeHash
  紧凑编码，缺失 = len 0；槽位 = 去前导零的大端值）、磁盘存储
  （`witness.idx` 16 字节头 + 每块 12 字节 `(offset u64, len u32)`，
  `witness.NNNN.dat` 2 GiB 段，逐块 zstd，可在执行检查点续写/回退）、
  录制器、`replay_block`/`WitnessDb`；
- 录制器的核心：执行阶段的批量 `State` 跨块缓存，它发给 provider 的读并不是
  新鲜 `State` 会发出的读，所以录制器每块维护一个**影子**新鲜 `State`，把批量
  `State` 回答的每次读都喂给影子，由影子自己的 cache 决定哪些读会到达数据库
  ——这正是回放端新鲜 `State` 将做出的同一决定、同一段代码；提交也镜像到影子。
  影子解释不了的读（先读槽位后读账户、提交从未读过的账户）让该块大声失败。
- 接线：`Executor::{set_read_observer, read_observer_mut}`、
  `ExecutionStage::with_witness_dir`、`ExecutionConfig::witness_dir`、
  `reth node --debug.witness-dir <DIR>`。

已验证：单元测试（格式、存储续写/回退/缺口）、三块链（跨块 cache 命中、上一块
创建的合约、先缺失后创建的账户、revert 帧内的读、withdrawals）在批量执行器下
录制、逐块在新鲜 state 回放 receipts 一致并通过 `validate_block_post_execution`，
错块/篡改的 witness 不通过；`ExecutionStage` 带 `witness_dir` 跑出的块可无状态回放。

**2026-08-27 补充：`../pevm`（n42blockchain/pevm，reth 1.10.2 / revm 34）已经实现了同一件事，
而且更合适**——它对 reth 归档库逐块并行执行（每块 `history_by_block_number(n-1)` +
新鲜 `State`），在 DB 层录制恰好就是新鲜 cache 的 miss 序列，不需要影子 `State`；
流格式与 gov5 的 `MarshalV2`、`NCIX`/64 块批 zstd 容器逐字节一致（只是顺序是 revm 的，
gov5 的 Go 回放器消费不了）。审计发现并已修（分支 `witness-verify`）：录制与回放都不
校验执行结果、回放在流耗尽时回退到过期状态的数据库。现在录制必须通过
`validate_block_post_execution`，回放必须恰好消费完流并通过同一校验，
`--witness-verify N` 让录制 run 每 N 块自证。**硬约束：谁录谁放**——revm 34 与 42 的
`State` 语义已有分歧（state-clear 标志），回放器必须与录制器同版本。

录制成本：主网全量执行一遍（用户估约 20 小时，Windows 宿主 `d:\reth2k`），
一次性；回放端零额外查找。pevm 一类并行执行器与位置式 witness 不兼容——
读序必须来自顺序执行——录制只能走顺序的执行阶段。

## 5. Rust 架构

执行口径必须遵守 [`EXECUTION_PATHS.md`](./EXECUTION_PATHS.md)：本工具属于
`historical_parallel_blocks`，不是 `historical_pevm`，更不是 `live_sequential`。
外部 `../pevm` 的历史结果也不得混入 live TPS。

新 crate `crates/n42/witness-replay`（lib + bin `n42-witness-replay`），只依赖
reth 2.5.1 已在图里的 crate，不碰 vendored fork。

```
reader 线程 ×R ──segment 解码──▶ 有界 reservoir（按内存计）──▶ worker 线程 ×W ──▶ 聚合/校验/可选输出
   mmap cidx/cdat                 (block, witness, senders)      每线程 EVM + arena
```

- **输入层**：`mmap` 打开 cidx/cdat，`zstd` crate（或 `ruzstd`）解段；
  headerc/bodyc 列解码直接产出 alloy `Header` / `TransactionSigned`
  （bodyc 的列布局要按 `body_compact.go` 逐列移植，用 gov5 生成的字节精确 fixture
  锁定——与 `n42-h2-wire` 一样只比原始字节 SHA-256）。geth freezer 输入
  （`witness-geth/`）是 64 块一批的 RLP，作为第二输入源，生产 run 就是它。
  解码按 segment 惰性、按块交付，不整段物化（gov5 塌陷的根因）。
- **状态层**：`WitnessDb: revm DatabaseRef`——`basic()` 查 keyed witness 的
  账户表并**顺带带上 bytecode**（从 codes 表按 codeHash 取、keccak 校验、进程级
  `code_hash → Arc<Bytecode>` 缓存，含 jumpdest 分析结果，只做一次）；
  `storage()` 查 slot 表；`block_hash()` 从 headerc 取最近 256 个 header 的哈希
  （每 worker 一个环）；缺 key = 该块 witness 不完整，直接判失败，不猜。
- **执行层**：reth 2.5.1 `EthEvmConfig`（主网 ChainSpec）→
  `BlockExecutor::execute_one(&RecoveredBlock)`，senders 来自 senders 表
  （`RecoveredBlock::new_unhashed(block, senders)`，不做 ecrecover）；
  校验 = `reth_ethereum_consensus::validate_block_post_execution`
  （gas、receipts root、bloom）。`--no-output` 下不构造 BundleState 的历史，
  `State` 用 `without_state_clear`/不建 reverts。
- **并行层**：W 个固定线程（`core_affinity` 绑核，SMT 下先测 128 vs 256），
  每线程常驻一个 EVM 与一个 bump arena（`bumpalo`，每块 reset），全局分配器
  `mimalloc`；块任务经无锁 SPSC/`crossbeam` 队列分发，无中央锁；重块（>50k
  tx-gas·µs）优先调度以消除尾部（gov5 的 24–25M band 长尾）。输出（changeset）
  可选，格式沿用 gov5 的 acctcs/storcs 以便对拍。
- **可观测性**：每 100k 块一行 `band blk/s tx/s Mgas/s failed rss`，与 gov5 的
  runbook 同格式，方便逐 band 对比；`perf`/`samply` 火焰图落 `docs/witness/`。

### 预期（估，待实测替换）

gov5 生产 run 每 tx 约 102 CPU-µs（含 SMT 偏差）。reth 在同类硬件上无状态
内存执行的经验值：ETH 转账 1–2 µs、ERC-20 5–10 µs、AMM swap 50–100 µs，
混合负载 20–40 µs/tx。据此估 CPU-s 降到 gov5 的 1/2.5–1/4，墙钟受输入解码
与长尾块限制，目标 **全量 < 20 分钟**（gov5 49m48s），密集 band > 6,000 blk/s
（gov5 2,876）。这些数字在 M1 之前不许写进任何对外材料。

## 6. 里程碑

| # | 交付 | 验收 |
|---|---|---|
| M0 | cidx/cdat、headerc、bodyc、senders、codes 的 Rust 读取器 + gov5 生成的字节精确 fixture；`n42-witness-replay dump --block N` 与 gov5 `freezer-heads`/dump 对拍 | 0..25.77M 全部块 header hash 与 geth 一致（只读，跑一次） |
| M0' | gov5 端 keyed witness v2 导出（改 `WitnessReplayReader`，`--emit-keyed-witness`），一次全量生产 | v2 表 items = 25,765,566，抽样块 key 集合 = 顺序流条目数 |
| M1 | 单线程单块回放通过 → 1M 密集块 `24.5–25.5M` 多线程 run | `failed=0`；报告 blk/s、CPU-s、RSS，对比 gov5 同 band 2,876 blk/s |
| M2 | 全量 `0..25.77M`，128/256 线程各一次 | `failed=0`；墙钟、CPU-s、逐 band 表，与 gov5 t3 并排 |
| M3 | 极限：PGO + fat LTO、预编译实现 A/B、K∈{1,8,32} 多块局部性、NUMA/绑核、输入预取深度 | 每项独立 A/B，留数据 |

M0 可以立刻开始（不依赖 gov5 改动）；M0' 是唯一需要 gov5 侧配合的项，
应尽早提出。

## 7. 未决与要向 gov5 侧确认的事

- `codes.hidx` 是否存在于本机 `witness/`（只看到 `codes.cidx`）；若只有 20 字节
  前缀索引，Rust 端同样做前缀查找 + keccak 校验 + 热层（MDBX Code 表）兜底。
- bodyc 中 `bfAuthVFull` 未置位的旧段：7702 的 V=27/28 已不可逆，需要与 gov5
  一样用 header txRoot 消歧，或直接改用 `witness-geth/` 的 RLP bodies。
- `witness` 表是批模式（`ForceBatchSize(64)`）：一批 64 块共享一个 zstd blob，
  批内分项格式要在 `table.go:retrieveBatch` 里确认。
- gov5 256w 下的间歇性 nonce 失败根因未明；Rust 端若在同一块上稳定通过，
  可反向帮助定位。
- 全量 run 只在系统空闲时跑（与 §1 同机，独占），与本仓库其它长时测试
  （`scripts/devnet-fleet.sh` 的 LATE_DELAY/GOV5_DELAY 长时间重加入）同一纪律。
