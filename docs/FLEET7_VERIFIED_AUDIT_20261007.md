# Native 七节点验签审计与实测（2026-10-07）

## 结果与范围

`n42-rs` native 路径，七个独立执行层、七个验证器。正式窗口 20 秒确认
**8,120,696 笔交易，406,035 TPS**；54 个不同高度，无重复高度计数。
平均 gas 占用 90.4%，41/54 个块达到 95% 占用，平均周期 0.370 秒。
完整回放及排空共确认 9,361,408 笔 Ed25519 转账；另有窗口之前的 2,000 笔 ECDSA 资金准备交易。
10 秒预热窗口为 432,046 TPS，仅作为预热记录。

两轮均通过七节点 hash/stateRoot/receiptsRoot/transactionsRoot 一致性检查，
七节点在后续三秒继续出块。正式轮共同检查高度 167；抽样收款账户在七节点均为 6 wei，
抽样 `0x50` 转账回执成功，gasUsed 21,000。篡改签名经 RPC 提交得到
`-32602: invalid transaction signature`，没有被接受。

这是单机、单个 20 秒正式窗口的 native 测量，不是持续容量、网络故障、
拜占庭容错或 Go Gov5 的 `0x50` 支持验收。Go 审计与本次 Rust 实测分别记录。
没有与网关跳验、共享执行层或其他硬件数字作同条件对比，也没有把结果归因于某项修复的提速。

## 实际路径

- 普通交易为 ECDSA；高性能交易为 `0x50` Ed25519。解码公钥与签名字节共享缓冲区，
  批量验签合并相同公钥的计算项，批量失败逐笔判定。共识 BLS 是另一层机制。
- 测量前生成 16,000,000 笔签名交易，32 个文件共 2.59 GB。
  测量阶段使用 `--replay`，资金准备和全部发送账户 nonce 检查先完成。
  正式回放四次进度记录均为 `sign 0s`、`rejected 0`。
- 七个实际进程均为 `N42_INGEST_VERIFY=all`，没有配置 `N42_FRAME_GATEWAYS`，
  没有分片跳验。正式轮入口验签计数为 9,330,176 至 9,361,408。
  缓存复用已验证发送者；未命中仍验签。
- genesis 声明 QMDB、altSigTx 和 frameBlocks；启用 QMDB entry-file/read-view，
  关闭 hashed-state 表写入。状态使用 QMDB 二叉树，交易使用帧树及 native 描述块/紧凑块传输。
  未调用 MPT proof 作为性能验收。
- 普通转账走 EVM 语义的 native 快路径，不满足前提时回退解释器；
  定向测试比较状态、费用及回退行为。

源码：[交易及批量验签](../crates/n42/tx-types/src/alt_sig.rs)、
[已验证发送者缓存](../crates/n42/tx-types/src/sender_cache.rs)、
[帧承诺](../crates/n42/tx-types/src/frame.rs)、
[QMDB 状态根](../crates/n42/qmdb-reth/src/strategy.rs)、
[转账快路径](../crates/n42/engine-types/src/fast_transfer.rs)、
[预签名回放](../crates/n42/h2-node/examples/tx_flood.rs)。

## 修复与失败尝试

| 提交 | 修复 |
| --- | --- |
| 2df20c878 | checked addition 拒绝溢出帧布局，避免加法或后续切片 panic |
| 3745b8b57 / c22ddc41a | 检查节点、验证器、压测器及共享源码的新旧关系；修复 `/src/` 路径误匹配；审计配置拒绝跳验 |
| 728999d55 | 检查每个发送账户 nonce；RPC 失败时拒绝回放 |
| 72fdb0ac2 | 小持久化窗口显式设置 state masking 0，避免继承 Reth 的 30 块默认值 |
| ee7c954c2 | 就绪要求进程存活和 RPC 响应；读不到基础费不能当作 0 |
| c6b0f6097 | 先启动跟随节点，最后启动初始领导节点 |
| 7584158e7 | 审计帧区块测量必须开启携带帧布局的 native 描述块协议 |

失败尝试不计入结果：state-masking 参数冲突；配置漏开 entry-file，读视图无法注册；
初始提案未收齐票、链未推进；原始 payload 重建帧区块失败且预热后活性检查 FAIL。
最后一种虽然产生 211,900 TPS 的窗口读数，仍作废。
补齐 entry-file、描述块/紧凑块及对应 native 构建配置后，重新完成预热与正式测量。
启动顺序改进不等同于这些故障下的完整协议恢复验收。

## 验证与配置

105 项 Rust 测试通过：tx-types 21、tx-ingest 65、fast-transfer 10、tx_flood replay 9。
6 项脚本保护回归通过；5 项既有 benchmark 类测试按默认设置忽略。
`cargo build --locked --release`、修改脚本 `bash -n`、`git diff --check` 通过。
构建仍有既有 Rust warning，本轮没有宣称全工作区 clippy 零告警。

实际机器 AMD EPYC 9B45，128 个物理核心、256 个逻辑 CPU。
每个执行层绑定 16 个物理核心及 SMT 同胞，验证器共用对应 CPU；回放使用剩余 16 个物理核心。
每轮全新执行数据：chainId 1143，gas ceiling 3,423,000,000，pacing 350ms，leader tenure 16，
2,000 个发送账户，2,000,000 个分散收款地址，batch 256、32 个回放 worker。
验签 batch 256，同公钥合并开启，sender cache 4,194,304。
正式轮起始 huge-page pool 42 GB。独占协议 supervisor 返回 0、没有竞争 claim；
所有本轮进程停止后释放 claim。

命令：

```sh
cargo test --locked -j 4 --target-dir /data/n42-build/agents/fleet7-audit -p n42-tx-types --lib
cargo test --locked -j 4 --target-dir /data/n42-build/agents/fleet7-audit -p n42-tx-ingest --lib
cargo test --locked -j 4 --release --target-dir /data/n42-build/agents/fleet7-audit -p n42-engine-types --lib fast_transfer
cargo test --locked -j 4 --release --target-dir /data/n42-build/agents/fleet7-audit -p n42-h2-node --example tx_flood
python3 scripts/tests/test_fleet7_guards.py
```

[机器可读证据](evidence/fleet7-verified-20261007.json) 保存源码提交、二进制与预签名文件 SHA256、
两轮窗口和全轮交易数、七节点承诺、验签计数、回执及坏签名拒绝结果。
[运行检查器](../scripts/fleet7-audit-check.py) 与本轮实际执行文件一致。
完整运行脚本、配置、日志及独占记录保留在 `/data/blockchain/fleet7-audit-20261007/`；
链数据、JWT 和私钥没有提交。
二进制版本字符串保留缓存的 base `a97a146`；实际源码构建及脚本提交以证据提交和二进制 SHA256 为准，
没有通过 `F7_SKIP_STALE_CHECK` 绕过源码新旧检查。
