# 2026-10 5M 审计:遗留问题清单与分工

更新日期:2026-10-30。两个会话不在同一会话列表里,通过本文件协调:**认领一项时把"负责"改成自己并推送,
完成后在"状态"写提交号**,同时照常在 `ROUND2.md` / `ROUND3.md` 状态表追加一行。每项仍先写失败测试再修。

- **Windows 会话**:Windows 主机上的 Claude Code(WSL2 编译,无 bench)。
- **Linux 会话**:bench 主机上的会话(完整测试、clippy 基线、fleet7/devnet、同机 A/B)。

分工原则:改动落在 5M 出块/导入热路径、需要同机 A/B 才能合入的归 Linux;非热路径、可本地单测闭环的归 Windows;
Windows 合入的改动由 Linux 在下一次整体验证时一并覆盖。

## A. 正在进行

| 项 | 负责 | 状态 |
|---|---|---|
| X22 同机配对(main `b91411e27` 对 `native-qc`),结果写入 `HANDOFF.md` "Linux 会话结果" | Linux | 运行中(10-30 01:22 UTC 起) |

## B. 非热路径,可本地闭环(Windows)

| 项 | 来源 | 内容 | 负责 | 状态 |
|---|---|---|---|---|
| R3-N5 余项 | ROUND3 | Timeout 先查重再验签(当前先验签,重复的 Timeout 每条都付一次 BLS 验证) | Windows | 已修(见 `git log --grep R3-N5`) |
| R3-N3 余项 | ROUND3 | by-hash 回复先核头哈希再解 body | Windows | 待做 |
| R3-P9 | ROUND3 | EL 响应体按字节上限读取(`h2-el-rpc` transport) | Windows | 待做 |
| R3-P8 余项 | ROUND3 | APoS 验证队列入队前校验成员与块哈希 | Windows | 待做 |
| R3-E3 | ROUND3 | 并行执行器单笔 gas_limit ≤ 剩余 gas 的加固检查(当前不可达) | Windows | 待做 |
| R3-N1 余项 | ROUND3 | 每 peer 入站 RPC 连接上限 | Windows | 待做 |
| R2-X2 余项 | ROUND2 | tx-ingest 帧间空闲超时(端口默认只绑回环) | Windows | 待做 |
| R3-C2 | ROUND3 | 头部 QC 共用检查:按 gov5 `decodeHeaderExtra` / `verifyHeaderWithBatch`,用 gov5 夹具对齐;实时路径与拉取路径共用。跨客户端,合入前需 Linux 跑 devnet gov5 三形态 | Windows 写,Linux 验 | 待做 |

## C. 热路径或需设计 + A/B(Linux)

| 项 | 来源 | 内容 | 负责 | 状态 |
|---|---|---|---|---|
| R3-E1 | ROUND3 | builder 与 follower 的可纳入性规则对齐(先与 gov5 对齐规则) | Linux | 待做 |
| R3-P2/P3/P4 | ROUND3 | tx-queue 有界 lane、加价替换、`Lagged` 补齐,与帧索引一起设计 | Linux | 待做 |
| R3-N4 | ROUND3 | gossip `validate_messages()` + 回报 Accept/Reject/Ignore | Linux | 待做 |
| R3-G4 | ROUND3 | leader 首次导入的多余 payload 克隆 | Linux | 低优先 |
| R3-E2 | ROUND3 | 零手续费块 beneficiary 触碰:先用 gov5 夹具确认根 | Linux | 待做 |
| 热路径 A/B | ROUND2/3 | R2-X1、R2-I1、R2-R4/Q4、R2-C7、R2-I6、R2-R3、R3-N2、R3-N3、R3-G2、R3-C3 | Linux | X22 配对覆盖整体;单项回退再拆 |

## D. 需协议/跨仓库决定(先记录,不动手)

| 项 | 来源 | 卡在哪里 |
|---|---|---|
| R3-P5 余项 | ROUND3 | h2_validator 需从 EL 取真实块号与 receipts root;`--mobile` 默认关 |
| R3-P6 余项 | ROUND3 | 注册 PoP 与收据独立 DST 是手机协议变更,需 mobile-sdk 同步 |
| R3-P7 余项 | ROUND3 | mobile HTTP 仍单线程(每连接最多占 10 s) |
| R2-C1 余项 | ROUND2 | 入站 `high_tc` 采纳需 TC 验证缓存设计 |
| R2-R2 | ROUND2 | 按 view leader 校验头部封印 |
| R2-C9 余项 | ROUND2 | gov5 header vote / deferred vote 未移植 |
| R2-X4 余项 | ROUND2 | 声明不按声明者分键(EL 不知道 peer) |

## E. 需要用户操作

`design/qmdb-compact-stage1`(本地 `7e379dc62`)与 `fix/qmdb-compact-stage2-audit`(4 个提交:E-2/E-3/E-6/E-7)
未推送,推送曾被权限拒绝:

```
git push origin design/qmdb-compact-stage1 fix/qmdb-compact-stage2-audit:design/qmdb-compact-stage2
```
