# 最近一个月代码审计与修复（2026-10-06）

## 范围

- 分支：`feat/native-fleet7`；审计 HEAD：`09a1284e4`。
- 时间窗口：2026-09-06 00:00（America/Toronto）至审计 HEAD，共 1088 次提交。
- 窗口前基线：`95d170fd3dd9ed5e8a3f6666b69f705d39496c3c`；累计差异 970 个文件，219785 行新增、12731 行删除。
- 开始时工作区干净。远端同步后无分支差异；审计结束时修复尚未提交；后续按用户要求分组提交推送。

采用风险优先的代码审查与行为测试，重点检查 QMDB 状态重放、持久化、交易入口、批量签名、原始 Engine 通道、输出分片、共识与证明。没有逐行审查全部 970 个文件；发现入口问题后，也检查了该入口调用的既有代码。

## 已修复问题

| 问题 | 原行为与影响 | 修复与回归证据 |
| --- | --- | --- |
| QMDB 多块 checkpoint 增量重放 | 将所有追加记录标为有效，包括已被后续块淘汰的记录；恢复出的活动位图与原状态不一致 | 内存模式按追加记录的 `active` 标志恢复；文件模式在现有 `changed` 字段携带本批追加后淘汰的槽位；两种模式连续覆盖同一账户后，都与完整快照位图比较 |
| QMDB 增量失败时破坏旧状态 | snapshot 先截断再验证；checkpoint 先改位图再验证。非法增量返回错误后仍留下部分修改 | 先验证追加跨度和所有槽位，再写入；回退、错误槽位和极端游标均验证失败后状态不变 |
| Snappy 与 varint 解码 | 短于 CRC 的数据块可导致切片越界或减法下溢；溢出 varint 和超过声明长度的数据未严格拒绝 | 检查十字节 varint 的最高字节、CRC 最小长度及实际解压输出；添加畸形块测试 |
| Compact/RPC/Engine 列表分配 | 不可信计数直接用于分配，短消息可声明巨大列表；部分标志和尾随数据被接受 | 分配前按剩余字节验证计数，compact 总交易数上限与恢复通道一致；严格检查可选标志、消息类型、尾随数据及 Prague/Cancun 组合 |
| 原始 Engine 客户端回包 | 服务端可声明数 GiB 长度，客户端在读取内容前直接分配 | 各字段长度上限 256 MiB，哈希与请求数也设上限；TCP 回归测试只发送超大长度、不发送正文，客户端须立即拒绝。这是字段级边界，不等于全连接总资源预算 |
| 交易入口整帧资源上限 | 单笔长度虽有限制，10000 笔可让一帧累计约 10 GiB | 增加 64 MiB 总交易字节上限；真实 socket 测试验证收到超限长度后，无需正文即可拒绝 |
| Gossip 入站批次 | 接收端在完整 RLP 分配之后才限制数量，且未落实发送端的字节上限 | 解码前限制 256 KiB，逐项读取并在超过 256 笔时拒绝；合法边界与超限均测试 |
| 移动端聚合证明元数据 | 有效签名与不匹配的参与者声明可以一起通过，且声明计数用于预分配 | 先限制位图长度并核对实际置位数、声明数和 registry；真实签名的篡改计数测试通过 |
| QMDB 账户 nonce 溢出 | 第十个 varint 字节高位可被截掉，异常记录解出错误 nonce | 在 shift=63 时只允许 0/1；保留 u64 最大值正例 |
| Ed25519 批量验签复杂度 | 每个新公钥线性搜索历史公钥，全不同发送者形成二次扫描 | 使用随机化 HashMap 定位，保持首次出现的点顺序及原验证等式；255 个不同发送者的批量结果与逐笔验证一致 |
| macOS 编译失败 | QMDB、交易恢复和节点诊断无条件调用 Linux 线程/CPU 绑定/接收时间戳接口 | Linux 保留原调度与诊断；其他平台不修改整个进程优先级，线程缺页计数置零，进程统计保留；接收时间戳报告不支持，但读取与 EOF 保持正常；栈诊断不安装信号处理器 |

QMDB 补充反例直接提取原版和修复版的方法体，以相同最小类型驱动三项断言：原版 0/3 通过，修复版 3/3 通过。该反例用于证明问题，不能替代下面的仓库测试。

## 验证（初次代码审计）

以下进程均已结束，退出码为 0。共 **1086 项通过、0 失败、22 项按原配置忽略**；不重复计入先前运行和单独运行的 forest 测试。

| 测试组 | 通过 / 忽略 | 日志 |
| --- | --- | --- |
| H2 consensus / execution / net / primitives / wire / mobile-verify（`--lib`） | 454 / 0 | `/tmp/n42-audit-final-protocol-tests.log` |
| Engine 原始 RPC（`--lib --tests`，含 5 组集成测试） | 91 / 0 | `/tmp/n42-audit-engine-rpc-tests.log` |
| Engine 核心（`--lib -- --test-threads=1`） | 229 / 10 | `/tmp/n42-audit-state-tests-final.log`，其中 Engine 组通过；该轮 QMDB 失败已由后续修复与完整重跑关闭 |
| 输出分片（`--test output_shards`） | 13 / 0 | `/tmp/n42-audit-shards-tests.log` |
| qmdb-reth / qmdb-state / tx-ingest / tx-types（`--lib -- --test-threads=1`） | 165 / 7 | `/tmp/n42-audit-state-tests-final2.log` |
| n42 节点（`--bin n42 --lib -- --test-threads=1`，最终状态修复后重跑） | 134 / 5 | `/tmp/n42-audit-node-tests-final3.log` |

所有 Cargo 测试均带 `--locked`。22 项忽略包括既有计时、大内存基准和向量打印，不记为通过。

QMDB 最终分别为 reth 57 项、state 24 项通过；交易入口 63 项、交易类型 21 项通过。恢复测试包含 20,000 块日志轮转与重启（完整 QMDB 组耗时 241.55 秒）、损坏尾部恢复、checkpoint 迁移、两种存储模式的快照导入和多块活动位恢复。

静态检查：

- `cargo clippy --locked -p n42-h2-consensus -p n42-h2-execution -p n42-h2-net -p n42-mobile-verify -p n42-qmdb-reth -p n42-tx-ingest -p n42-tx-types -p n42-h2-el-rpc --lib --tests`：退出 0，日志 `/tmp/n42-audit-clippy-final.log`。
- 最终 forest 修复后，`cargo clippy --locked -p n42-qmdb-reth -p n42-qmdb-state --lib --tests`：退出 0，日志 `/tmp/n42-audit-clippy-state-final.log`。
- Clippy 保留已有警告，没有使用 `-D warnings`，因此不称为零警告。
- `git diff --check`：通过。初次代码审计未改变 `Cargo.lock`；后续依赖升级更新了锁文件。

文件增量沿用现有序列化字段，读取旧日志的恢复测试通过；旧二进制会拒绝含追加槽位退役标志的新文件模式增量，因此回退旧程序前需要使用相应旧 checkpoint/日志备份。本次未实施线上升级或回退。

## 依赖升级与 4 条漏洞告警关闭

用户授权升级后，`cargo audit --json` 的漏洞数量由 4 降为 **0**，退出码为 0。未添加忽略规则，也未删除依赖扫描范围。

| 原告警 | 修复路径 | 当前版本 |
| --- | --- | --- |
| h2 0.3.27 / [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | 移除 ethers 的旧 reqwest/hyper RPC 栈 | h2 0.4.20 |
| ring 0.16.20 / [RUSTSEC-2025-0009](https://rustsec.org/advisories/RUSTSEC-2025-0009.html) | 移除 ethers-providers → jsonwebtoken 8 链路 | ring 0.17.14 |
| hickory-proto 0.25.2 / [RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html)、[RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html) | libp2p 0.56 → 0.57，带入 DNS 0.45 / mDNS 0.49；提高 workspace resolver 版本下限 | Hickory 0.26.3 |

这些旧版本均已从锁文件消失。版本信息通过 crates.io 的 `cargo info` 核对。由于 [ethers 上游已停更并推荐 Alloy](https://github.com/gakonst/ethers-rs)，SDK 示例的 RPC 与签名改用仓库现用的 Alloy 2.5.0；库只保留最新版 ethers-core 2.0.14 的 ABI 和交易类型，保持公共 Rust 类型、C/JNI JSON（包括 `data` 字段）和金额解析行为。交易发送仍显式使用原有 legacy gas 定价；批量发送从 pending nonce 开始递增。

libp2p 0.57 的 Codec 改用原生异步方法，相关实现和依赖已适配。其 Yamux 0.14 后端只提供自适应接收窗口，旧固定窗口/缓冲区接口已移除：`N42_YAMUX_WINDOW_MB` 不再控制窗口，显式配置时记录一次警告。新增 2 MiB 难压缩正文的真实 TCP loopback 回归。此升级改变流控与内存预算，尚未做原 163,000 笔交易集群负载对照，不能宣称吞吐或内存占用与旧版相同。

libp2p-swarm 0.48 精确约束 wasm-bindgen-futures 0.4.58，连带约束 wasm-bindgen 0.2.108；因此保留上游支持的兼容组合，而不是强行替换该浏览器依赖链。

该轮扫描当时还保留 **7 条停维护提示、1 条既有 lru 健全性警告**。初次审计为 8 条停维护提示、1 条健全性警告。lru 0.16.4 由锁文件中的旧 Alloy provider 1.8.3 引入，当前 workspace 默认依赖图中未选中；可选 feature 仍需单独验证。这些提示不记为本次 4 条漏洞的修复，也不代表整个依赖树没有风险。

升级后的最终验证均已结束，退出码为 0；共 **368 项通过、0 失败、5 项按原配置忽略**。这是升级后的验证组，不与初次审计的重复测试相加。

| 最终命令 | 通过 / 忽略 | 日志 |
| --- | --- | --- |
| `cargo test --locked -p n42-h2-net -p n42-h2-node --lib --tests` | 199 / 0 | `/tmp/n42-libp2p-dependency-tests-final3.log` |
| `cargo test --locked -p n42 --bin n42 --lib -- --test-threads=1` | 134 / 5 | `/tmp/n42-dependency-node-tests.log` |
| `cargo test --locked -p mobile-sdk --lib --examples` | 35 / 0 | `/tmp/n42-mobile-dependency-tests-final2.log` |
| `cargo check --locked -p n42-h2-node --examples` | 编译检查通过 | `/tmp/n42-dependency-node-examples-final.log` |

SDK 回归覆盖存款、退出和费用查询交易，比较转换后的字段、calldata 与 legacy 签名哈希；测试发现 ethers RPC JSON 不序列化 chain_id，转换现已显式保留该字段。示例检查另发现验证器无条件调用 Linux prctl，已补充 Linux 平台条件，macOS 编译通过。没有运行真实 RPC 提交或链上交易。

扫描日志：`/tmp/n42-dependency-audit-final.json`。升级后的编译保留既有警告；未重跑升级后的 Clippy，不将初次审计的 Clippy 结果作为新依赖组合的证据。

## 其他验证边界

全仓 `cargo fmt --all -- --check` 失败，输出约 7498 处格式差异，首处位于未修改的 pubsub-mem。没有为通过格式检查重写全仓；本次检查单独确认补丁空白无误。

本次验证不包含在线集群、生产部署、长时间负载、真实设备或 Linux 主机运行验证。

## 分批提交

QMDB 状态、网络协议、交易与证明、平台兼容、初次审计记录、依赖升级、验证器示例平台修复、最终验证记录分为八次英文提交，逐次推送至 `origin/feat/native-fleet7`，每次通过 `ls-remote` 核对提交号。未合并至默认分支，GitHub 默认分支告警是否关闭需以合并后的扫描为准。

## 后续维护提示修复

用户随后授权修复剩余 7 条停维护提示和 1 条 lru 警告。最终扫描为 0 条漏洞、0 条提示；本轮 1031 项测试通过、8 项按原配置忽略，主节点与 OP 可选功能编译检查通过。详见 [依赖维护提示修复记录](DEPENDENCY_REMEDIATION_2026_10_06.md)。不与前面重复测试相加。
