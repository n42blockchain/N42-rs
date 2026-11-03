# 以太坊兼容线:reth 深度优化计划(2026-10-28 起)

分支 `eth/reth-deep-opt` 维护。另外两条线:5M 审计 `audit/5m-full-2026-10`(`docs/PLAN_5M_AUDIT.md`),
7 节点 E=7 `e7/independent-execution`(`docs/PLAN_E7_FLEET7.md`)。三条线分开维护。
开发平台:Windows 为主(`docs/PLAN_WINDOWS_DEV.md`,Linux bench 主机硬件故障)。

## 0. 定位与约束

- **不改以太坊协议语义。** 标准 EVM、MPT 状态根、以太坊主网的链规则与区块格式;不用 QMDB、
  帧区块、0x50 交易、延迟执行等 N42 共识规则。本线的每个改动都要能在 `--chain mainnet`
  (或 sepolia/hoodi)上运行并通过以太坊的一致性检查。
- **优化的是 reth 本身**:执行(revm 解释器、预编译、状态读取)、状态根(稀疏 trie、
  multiproof、哈希)、持久化(MDBX、静态文件、修剪)、同步流水线与内存。
- **能上游的尽量上游。** 与协议无关、对上游有价值的改动按
  `docs/RETH_FORK_REDUCTION.md` 的原则做成增量补丁,经 `../reth`(n42blockchain/reth fork)
  提交 paradigmxyz/reth;只对 N42 有意义的放在本仓库。不扩大 fork 面
  (`crates/` 下的 vendored 改动保持增量、带默认实现)。
- 每个优化先写可复现的基准(criterion 微基准、固定区块范围的重执行),在同一台机器上做 A/B 对。

## 1. 可复用的已有成果

| 来源 | 内容 | 能否直接用于以太坊语义 |
|---|---|---|
| 5M 线(`BREAKTHROUGH_DESIGN.md` 10.x、`KNOBS.md`) | pruner 的释放挪出线程、静态文件页缓存的分段丢弃、持久化阈值、并行状态提交、tokio/rayon 线程配置、大页 | 逐项甄别:与 QMDB/帧无关的部分可移植 |
| witness 回放(`WITNESS_REPLAY_RUST_PLAN.md`) | 主网区块的单块执行剖面:解释器 37%、状态/journal 28%、keccak 12.5%、预编译 9%、分配 6%;PGO -2.7~-3.7% | 直接适用,是执行侧优化的基线 |
| reth 升级记录(`RETH_2_8_1_UPGRADE.md`) | 2.8.1 的持久化默认值变化、revm 43 的执行路径 | 适用 |

## 2. 阶段

1. **基准与数据。** 选定测量对象:(a) 固定主网区块段的重执行(`reth re-execute` 或等价工具),
   (b) 实时同步的吞吐(gas/s),(c) 状态根计算时间。主网数据原在 Linux bench 主机的
   `/data/blockchain`,主机故障期间需要在本机(D: 盘)重新准备一段数据,或从可用节点取。
2. **执行侧。** 以 witness 回放的剖面为起点:PGO 构建流程、keccak 缓存、分配器、
   解释器热点;每项给出 A/B 结果。
3. **状态根与持久化。** sparse trie / multiproof 的并行度、MDBX 写放大、静态文件写入、
   持久化阈值与内存缓冲。
4. **上游化。** 每个已验证的改动整理成上游补丁,记录状态。

## 3. 状态

| 项 | 状态 |
|---|---|
| 1 基准与数据 | 待开始(需本机准备主网数据) |
| 2-4 | 待开始 |
