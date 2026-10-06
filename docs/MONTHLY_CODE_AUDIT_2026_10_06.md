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

## 验证

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
- `git diff --check`：通过。`Cargo.lock` 未改变。

文件增量沿用现有序列化字段，读取旧日志的恢复测试通过；旧二进制会拒绝含追加槽位退役标志的新文件模式增量，因此回退旧程序前需要使用相应旧 checkpoint/日志备份。本次未实施线上升级或回退。

## 尚未关闭的项目

`cargo audit --json` 返回 4 条安全告警。核对锁文件和实际依赖图后：

- `h2 0.3.27`：[RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html)。链路为 mobile-sdk → ethers → reqwest 0.11 → hyper 0.14；修复版本需要 h2 0.4.16 以上，不能仅在当前锁文件中做补丁版本更新。
- `ring 0.16.20`：[RUSTSEC-2025-0009](https://rustsec.org/advisories/RUSTSEC-2025-0009.html)。链路为 mobile-sdk → ethers-providers → jsonwebtoken 8；修复版本为 ring 0.17.12 以上，需迁移旧 SDK 依赖。
- `hickory-proto 0.25.2`：[RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html)、[RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html)。锁文件中的旧 libp2p-mdns/解析器链路未出现在当前 workspace 的实际反向依赖图（含 `--target all`）中；锁文件告警仍然存在，不能记为已修复。

当前节点实际使用 h2 0.4.19、ring 0.17.14、hickory-proto 0.26.3。上述依赖图检查仅说明当前构建路径，不证明所有可选 feature 或部署配置均安全。旧 ethers SDK 的迁移需要独立兼容验证，本次未作未经验证的大版本替换。

全仓 `cargo fmt --all -- --check` 失败，输出约 7498 处格式差异，首处位于未修改的 pubsub-mem。没有为通过格式检查重写全仓；本次检查单独确认补丁空白无误。

本次验证不包含在线集群、生产部署、长时间负载、真实设备或 Linux 主机运行验证。

## 分批提交

QMDB 状态、网络协议、交易与证明、平台兼容四组已逐组推送至 `origin/feat/native-fleet7`，每次均通过 `ls-remote` 核对提交号。用户随后授权继续升级依赖并关闭 4 条安全告警，依赖修复将另行记录验证结果。
