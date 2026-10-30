# 2026-10 5M 审计:遗留问题清单与分工

更新日期:2026-10-30(Linux 05:50 UTC:10-30 全部待 A/B 项闭合,见 A 与 HANDOFF.md "第二轮 Linux 结果")。**10-30:除 R3-E1/E3/E2(Linux,同一组文件)外的全部遗留由 Windows 认领,按 G4 → R2-R2 → P5 → P7 → R2-X4 → P2/P3/P4 → N4 → R2-C9 → P6 的顺序推进;Linux 若要接手某项,改负责列并推送即可。**两个会话不在同一会话列表里,通过本文件协调:**认领一项时把"负责"改成自己并推送,
完成后在"状态"写提交号**,同时照常在 `ROUND2.md` / `ROUND3.md` 状态表追加一行。每项仍先写失败测试再修。

- **Windows 会话**:Windows 主机上的 Claude Code(WSL2 编译,无 bench)。
- **Linux 会话**:bench 主机上的会话(完整测试、clippy 基线、fleet7/devnet、同机 A/B)。

分工原则:改动落在 5M 出块/导入热路径、需要同机 A/B 才能合入的归 Linux;非热路径、可本地单测闭环的归 Windows;
Windows 合入的改动由 Linux 在下一次整体验证时一并覆盖。

## A. 正在进行

| 项 | 负责 | 状态 |
|---|---|---|
| X22 同机配对(main `b91411e27` 对 `native-qc`),结果写入 `HANDOFF.md` "Linux 会话结果" | Linux | 完成(5ab8fffea):win1 -0.1%、轮总量 -0.8%,无可见代价;第一至三轮热路径 A/B 闭合 |
| 第二次配对 stage `fw`(main `5a0d895c3` + R3-E1 = `6f0913d92` 对 `b91411e27`)+ devnet 五形态(三个重连形态 + 两个 `twoPhaseVoteGate` gov5 混跑) | Linux | 完成(10-30 05:50 UTC):win1 -0.9%、轮总量 -0.7%,四腿门净;devnet 全部同哈希、gov5 error 0。10-30 的全部热路径合入(P2/P3/P4、N4、C2、N5 余项、P9、G4、R2-R2、R2-C1、R2-C9 余项)与 E1/E3 一并闭合 |

## B. 非热路径,可本地闭环(Windows)

| 项 | 来源 | 内容 | 负责 | 状态 |
|---|---|---|---|---|
| R3-N5 余项 | ROUND3 | Timeout 先查重再验签(当前先验签,重复的 Timeout 每条都付一次 BLS 验证) | Windows | 已修(见 `git log --grep R3-N5`) |
| R3-N3 余项 | ROUND3 | by-hash 回复先核头哈希再解 body | Windows | 不修(无放大,见 ROUND3) |
| R3-P9 | ROUND3 | EL 响应体按字节上限读取(`h2-el-rpc` transport) | Windows | 已修(见 `git log --grep R3-P9`) |
| R3-P8 余项 | ROUND3 | APoS 验证队列入队前校验成员与块哈希 | Windows | 暂缓(APoS 旧路径,见 ROUND3) |
| R3-E3 | ROUND3 | 并行执行器单笔 gas_limit ≤ 剩余 gas 的加固检查(当前不可达) | Linux(随 E1) | 已修(随 R3-E1 同一提交,合入 main) |
| R3-N1 余项 | ROUND3 | 每 peer 入站 RPC 连接上限 | Windows | 已修(见 `git log --grep R3-N1`) |
| R2-X2 余项 | ROUND2 | tx-ingest 帧间空闲超时(端口默认只绑回环) | Windows | 不修(帧体已有期限,见 ROUND3) |
| R3-C2 | ROUND3 | 头部 QC 共用检查(实时路径投票闸门),方案见下 | Windows 写(10-30 认领),Linux 验 A/B 与 devnet gov5 | 已修(d5fe4495d;Linux 10-30:devnet gov5 三形态两轮同哈希、无 header-QC 拒绝,X22 stage fw 无可见代价) |

### R3-C2 实现方案(Windows 会话 10-30 读码结论)

gov5 `verifyHeaderWithBatch`(`internal/consensus/hotstuff/adapter.go:389`)对头部 QC 的规则:
`decodeHeaderExtra` 失败即拒(先按 QC+seal 解,失败再按旧布局整段解);`qc.View > headerView` 即拒;
`ResolveQCValidatorSet` 解出非空集合时 `verifyQCAnyDomainWithSet` 必须通过,解不出则跳过。
gov5 `unpackBoolBitmap` 宽松:计数越界、数据不足时返回 nil 签名者(不报错),之后由验签失败拒绝。

Rust 现状:
- 拉取路径 `check_pulled_block`(`h2-node/src/service.rs`,约 4570 行)已实现上面三条,外加祖先链检查;
  比 gov5 严的只有 h2-wire `decode_h2_qc` 对位图的严格解码(集合未知时 gov5 接受、Rust 拒绝;
  诚实 gov5 不产生这种位图)。
- 实时路径(gossip / push / by-hash / compact 各条 body 入口)不看头部 QC;跟随者照常导入并投票,
  gov5 会拒绝同一块,即拜占庭 leader 可造出 Rust 认证、gov5 拒绝的块。

方案:
1. 从 `check_pulled_block` 抽出 `check_header_qc(&self, header) -> Result<Option<QuorumCertificate>, String>`
   (extra 解码、QC 解码含旧布局回退、view 比较、`engine.verify_header_qc`),拉取路径改为调用它再做祖先检查。
2. 投票闸门放在 engine 收到 `BlockImported` / `BlockChecked` 之前:`apply_driver_action` 的
   `DriverAction::Consensus` 分支与 `ExecuteBlock` 已导入分支(约 3089 行)。`block_headers` 里没有头部时放行
   (不比现在弱)。本节点自己的块跳过。
3. 代价:`verify_qc_any_domain_or_known` 只对 locked/last_committed 免验;头部嵌的是建块时的 committed QC,
   跟随者投票时常已前进,未命中即一次 BLS 聚合验签(毫秒级,X22 周期 40 ms)。需加一个按 QC 字节哈希
   键控的已验证小缓存(engine 在 proposal/commit 路径验过的 QC 也写入),否则热路径代价不可接受。
4. 测试:service_net_tests 里仿 `a_pulled_block_with_a_forged_parent_qc_*` 构造头部 QC view 大于头部 view、
   以及签名伪造的块,投递 `BlockImported` 后断言 engine 不投票;gov5 夹具补一个带 QC 的头部。
5. 合入前:Linux 同机 A/B(X22)与 devnet gov5 三形态。

## C. 热路径或需设计 + A/B(Linux)

| 项 | 来源 | 内容 | 负责 | 状态 |
|---|---|---|---|---|
| R3-E1 | ROUND3 | builder 与 follower 的可纳入性规则对齐(先与 gov5 对齐规则) | Linux(10-30 认领) | 已修并合入 main(分支 fix/r3-e1-builder-includability 527e009fb,X22 stage fw 持平后 no-ff 合入):串行循环 Σgas_limit 预算 + 每 sender 最坏花费账本;并行步每 sender run 同一账本;R3-E3 一并 |
| R3-P2/P3/P4 | ROUND3 | tx-queue 有界 lane、加价替换、`Lagged` 补齐 | Windows 已修(4f6256c4d P4 / c1814476f P3 / ad3ece18d、c402f298a P2);Linux A/B 10-30 stage fw | 已修,A/B 闭合:win1/轮总量 -0.9%/-0.7%(噪声内);5M 负载下 `refused=0`、`refused_at_cap=0`、`frames_refused=0`,无 `Lagged` 读回 |
| R3-N4 | ROUND3 | gossip `validate_messages()` + 回报 Accept/Reject/Ignore | Windows 已修(eb9146203);Linux A/B + gov5 混跑 10-30 | 已修,A/B 闭合(stage fw);gov5 混跑五形态(gov5late/late/absent + gov5late2p/gov5now2p)全部同哈希、gov5 error 0,网格评分无异常(gov5 全程封块/提交) |
| R3-G4 | ROUND3 | leader 首次导入的多余 payload 克隆 | Windows(10-30 认领),Linux A/B | 已修(见 `git log --grep R3-G4`),A/B 闭合(stage fw) |
| R3-E2 | ROUND3 | 零手续费块 beneficiary 触碰:先用 gov5 夹具确认根 | Linux(与 R3-E1 同改 `payload.rs` / `parallel_transfer.rs`,Windows 不动) | 待做 |
| 热路径 A/B | ROUND2/3 | R2-X1、R2-I1、R2-R4/Q4、R2-C7、R2-I6、R2-R3、R3-N2、R3-N3、R3-G2、R3-C3 | Linux | 已由 X22 配对整体闭合(5ab8fffea);10-30 之后的热路径改动(R3-N5 余项、R3-P9、R3-C2、P2/P3/P4、N4、G4、R2-C9 余项、E1/E3)由 stage `fw` 一次闭合(HANDOFF.md "第二轮 Linux 结果") |

## D. 需协议/跨仓库决定(先记录,不动手)

| 项 | 来源 | 卡在哪里 |
|---|---|---|
| R3-P5 余项 | ROUND3 | h2_validator 需从 EL 取真实块号与 receipts root;`--mobile` 默认关。**Windows 已修(见 `git log --grep R3-P5`;延迟执行下仍无 root)** |
| R3-P6 余项 | ROUND3 | ~~注册 PoP 与收据独立 DST~~ **已修**(Windows,39b3657ae / dd68fba75 / 886468e86;手机客户端需按 `RECEIPT_DST` 签名并在注册时带 PoP,仓库内无此客户端) |
| R3-P7 余项 | ROUND3 | mobile HTTP 仍单线程(每连接最多占 10 s)。**Windows 已修(见 `git log --grep R3-P7`)** |
| R2-C1 余项 | ROUND2 | 入站 `high_tc` 采纳:**Windows 已修(见 `git log --grep R2-C1`)**;只在 TC 能让本节点前进时验证,无需缓存。Linux devnet gov5 五形态(含 absent/late)10-30 覆盖,通过 |
| R2-R2 | ROUND2 | 按 view leader 校验头部封印。**Windows 已修(见 `git log --grep R2-R2`)** |
| R2-C9 余项 | ROUND2 | ~~gov5 header vote / deferred vote 未移植~~ **已修**(Windows,aab6c13b1 / 47afc33ee;deferred vote 已由 `BlockChecked` 覆盖)。Linux 10-30 与 gov5 两阶段 fleet 混跑通过:devnet 基因副本 `twoPhaseVoteGate: true`(Rust 验证者打印 `vote gate : two-phase`,gov5 链库 chainspec 同值),gov5late2p 160 块 / gov5now2p 133 块两客户端同哈希、gov5 error 0、Rust 超时数与普通形态相同 |
| R2-X4 余项 | ROUND2 | 声明不按声明者分键(EL 不知道 peer)。**已修(待 A/B)**(Linux,分支 `fix/r2-x4-claims-by-source`,未合 main):h2-node 带来源转发至多 4 份不同 layout,EL 每 root 每来源一槽;见 ROUND2 状态行。A/B:只在整块回退路径(本节点无自己的 layout)生效,常见情形(一份 body)不变 |

## E. 需要用户操作

(已完成 10-30:`design/qmdb-compact-stage1` `7e379dc62` 与 `design/qmdb-compact-stage2` `62265d47c` 已推送;Linux 把两者合到
main `5a0d895c3` 上为 `integ/qmdb-compact-stage12`(`7ce44bdb4`,forest.rs 一处平凡冲突),五个 QMDB crate 19 套件 571 测试、
`bin/n42` + `h2-node` check、entry-file 模式 `roll --kill` 现场检查通过后 no-ff 合入 main `c992a5ee4`;
见 `docs/MATURITY_HARDENING_2026_10.md` §6.2 / §8。)
