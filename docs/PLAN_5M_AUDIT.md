# 5M 线完整审计计划(2026-10-28 起)

分支 `audit/5m-full-2026-10` 维护;7 节点 E=7 线在 `e7/independent-execution`
(`docs/PLAN_E7_FLEET7.md`),两条线分开。

目标:把 5M 线(`fleet7-x22-5.2M-20261024`,main `47b8180ab` 起的 X22 配置)的代码做一次完整审计,
范围覆盖 2026-10 成熟度审计(`docs/MATURITY_HARDENING_2026_10.md`,基线 `91a360b57`)之后合入的全部代码。

## 0. 前提与约束

- **保留现有执行验证与深度优化。** 审计的修复一律不得拿掉 X22 的任何已采纳优化
  (`docs/KNOBS.md` 中 `adopted` 行),不得削弱跟随者对区块的执行与字段校验
  (`bodygate`/`d2gate` 所查的那些)。修复优先选零成本或只在冷路径上付费的形式;
  任何可能触及热路径的修复必须先过一次 X22 bench 对(`scripts/fleet7-runs`),
  按"单轮差异 <10% 不可见"的规则判读。
- **Linux bench 主机目前断电**(电源模块疑似故障,见 `MATURITY_HARDENING_2026_10.md` 8.3)。
  需要 mmap、满载或多节点的验证都排在主机恢复之后;Windows 上只能跑不涉及
  mmap/截断的单元测试。
- 5M 数字的口径:E=1(七个验证者密钥共用一个执行层,`N42_IMPORT_ONCE=1`)、单网关
  背书帧、预签名回放集(12,500 个发送者的纯转账)、单机环回。对外引用时必须带上这些前提。

## 1. 审计

### 1.1 范围

| 领域 | 代码 | 重点 |
|---|---|---|
| A 共识核心 | `h2-consensus`、`h2-wire`、`h2-primitives` | 安全性(不会对冲突块双重最终确认)、活性、QC/TC 校验、BLS 聚合与密钥校验、视图切换、未认证输入的边界 |
| B 共识集成 | `h2-node`、`h2-execution`、`h2-net`、`h2-el-rpc` | 延迟执行下的投票与结算标签、区块头内嵌 QC(6.9)、区间同步的 QC 校验(6.6)、对端输入的 DoS 面、本地故障停机(6.5) |
| C 帧背书信任模型 | `tx-types`(frame、sender_cache、altsig)、`tx-ingest`、`tx-queue`、`engine-types` 的帧路径 | 网关背书的信任根、f+1 规则、`shard`/`leader` 校验模式、帧对齐区块的事务根、跟随者按描述组装区块时到底校验了什么、0x50 批量验签 |
| D QMDB 持久化 | `qmdb-reth`、`qmdb-state`、`twig-core`、`bmt-core`、`crates/storage/{provider,storage-api,storage-overlay}` 的 N42 钩子、`crates/chain-state` | 与 MDBX 的持久化顺序、崩溃一致性与恢复、checkpoint/归档、读视图正确性、mmap `unsafe`、压缩 stage 2 |
| E 审计后增量 | `91a360b57..origin/main` 中 A-D 以外的部分(`bin/n42`、`engine-types`、`env` 等),以及分支 `design/qmdb-compact-stage2`、`design/qmdb-compact-stage1` | 新代码的正确性与鲁棒性,上一轮修复是否修对 |

不在本轮范围(另列):上游 reth 2.8.1 本身、依赖漏洞(Dependabot 告警单独处理)、
mobile/APoS 旧路径。

### 1.2 方法

1. 五个领域各做一次独立的只读审查,沿用上一轮的分级:P0 = 生产中可达的 panic、
   错误状态或共识安全破坏;P1 = 正确性或资源缺陷;P2 = 鲁棒性与可维护性。
   每条发现给出 `文件:行`、触发场景、影响、不伤性能的修复建议和置信度。
2. 汇总后逐条复核(读代码确认触发路径),去重,剔除误报;原始清单入库
   (上一轮没有入库,本轮补上:`docs/audit/2026-10-5m/`)。
3. 修复按领域开分支(`audit/5m-<领域>`),每个修复带单元测试;热路径修复带 bench 对。
4. 主机恢复后:Linux 上全量 `cargo test`、`cargo clippy`、fleet7 `roll --kill`
   字段检查、devnet 含 gov5 成员的三种形态(`gov5late`/`late`/`absent`),
   再跑 X22 对确认无性能回退。
5. 对外审计:本轮内部审计的结论与信任模型说明整理成外部审计的输入包。

### 1.3 交付

- `docs/audit/2026-10-5m/` 的发现清单与复核结论;
- 帧背书信任模型说明(什么被信任、信任谁、单网关 bench 配置与生产配置的差别);
- 修复分支与验证记录;
- 外部审计输入包。

## 2. 状态

| 项 | 状态 |
|---|---|
| 1.1-1.2 五个领域审查 | 进行中(2026-10-28 起) |
| 1.2 复核与入库 | 待审查完成 |
| 1.2 第 4 步 Linux 验证 | 等主机 |
