# 2026-10 5M 审计:第二轮

第一轮(A-E,`FIX_PLAN.md`)全部修完后做的第二轮深度审计。五路并行审阅:第 3 批回归复核、共识核心
(h2-consensus/h2-primitives/h2-wire,对照 gov5 18f1f266)、共识集成(h2-node/h2-net/h2-execution/h2-el-rpc)、
交易摄入/队列、QMDB 持久化。全部为读代码所得;每项修复前先按代码核实,先写复现测试(修复前失败)。

编号:R2-X(交易)、R2-Q(QMDB)、R2-C(共识核心)、R2-I(共识集成)、R2-R(回归复核)。

## 发现

| id | 级别 | 位置 | 问题 | 修复要点 |
|---|---|---|---|---|
| R2-X1 | P0 | `tx-types/src/alt_sig.rs` | ed25519-dalek 的批量方程不乘余因子:R 或 A 带挠点时和为 `z·T`,判定随同批其他签名的转录系数变化;`verify()` 也是一元批。altSigTx 链上各节点切批不同即分叉 | 全部走 `batch_equation_holds`,和乘余因子后判单位元;`N42_ED25519_MERGE=0` 只关合并。共识规则变更,所有节点同时升级;诚实签名不受影响 |
| R2-X2 | P2 | `tx-ingest/src/lib.rs:433,437,1293` | 单笔 1 MiB、帧 64 MiB、256 连接,整帧读完才过闸,无空闲超时 | 降上限、按字节的信号量、空闲超时 |
| R2-X3 | P2 | `tx-ingest/src/lib.rs:1879` | 池拒收时仍 `note_frame`,帧索引上限 16384 | 仅当结果全为 Ok/AlreadyImported 时记帧 |
| R2-X4 | P3 | `engine-types/src/frame_blocks.rs:644,710` | C-1 残留:`CLAIMED_LAYOUTS` 只留第一个声明的布局 | 按声明者分键 |
| R2-Q1 | P1 | `qmdb-reth/src/node_state.rs:3330-3405` | 量出 delta 后、追加前的 I/O 错误丢掉翻转;`forget_changes` 还会清掉流水线 N+1 的翻转 | 出错时把 delta 的槽位还回 `dirty_slots`;逐个推进 `cursor.head` |
| R2-Q2 | P2 | `node_state.rs:3215` | `settle_through` 不核对头在链上 | 记录最近 ~256 个 (number, hash) |
| R2-Q3 | P2 | `node_state.rs:3471` | `checkpoint_sync()` 分支不查 `cursor.compacting` | 压缩中则返回 |
| R2-Q4 | P3 | `forest.rs` `move_to` | D-4 回归:任何低于 `flushed_slots` 的回退(含未持久化的 N+1)都在森林锁下 fsync | 另设 `persisted_slots` 水位,只在其下 sync |
| R2-Q5 | P3 | `node_state.rs:2195` | `persisted_state_root` 不与 `HeadRoots` 记录对照 | 对照,不符即报错 |
| R2-C1 | P1 | `h2-consensus/src/protocol/timeout.rs:122`, `wire_bridge.rs` | 弱同步器与 gov5 不同:只在恰好同一未来 view 有 f+1 个超时时跳;不转发 TC。重启后 view 分散(4/2/1)即永久停摆 | 移植 gov5 按发送者的 futureTimeouts、取第 f+1 高 view;接受入站 `high_tc` |
| R2-C2 | P2 | `state_machine.rs:1242,1403,1452` | 未来 view 的 proposal 缓冲:QC 未签,8 个篡改副本占满发送者槽位,真副本被丢 | 携带 QC 伪造或不安全时不缓冲 |
| R2-C3 | P2 | `proposal.rs:458`, `h2_validator.rs:460`, `persistence.rs:486` | `N42_VOTE_BEFORE_IMPORT` 跳过 extends 规则;它与 `N42_VOTE_LOG_NOSYNC` 都不受 `N42_BENCH_UNSAFE` 门控 | 该路径也查 `extends_justify`;两开关加门控、用 `n42_env::flag` |
| R2-C4 | P3 | `proposal.rs:128-262` | A-3 未覆盖 leader 自己的 proposal | `on_block_ready` 设置 `processed_proposal` |
| R2-C5 | P3 | `timeout.rs:183` | 本地锁前进后,带 genesis high QC 的 timeout/NewView 整条被拒;gov5 接受 | 接受,genesis QC 不参与锁更新 |
| R2-C6 | P3 | `h2_v4.rs:76`, `wire_bridge.rs:338` | gov5 profile 下 Decide 信封的 `changes_hash` 未认证 | gov5 下非零即拒 |
| R2-C7 | P3 | `proposal.rs:210-244`, `voting.rs:179,226` | leader 路径 vote-log 写失败后不重试 | 先写日志或出错回滚阶段 |
| R2-C8 | P3 | `state_machine.rs:1202,1815` | 回放缓冲消息时置位的 `unauthenticated` 归咎给触发推进的正当消息(回归复核也报) | 回放前后保存/清除 |
| R2-C9 | P3 | `qmdb-reth/src/hotstuff.rs:35` | `twoPhaseVoteGate` 被静默忽略 | 读取;移植 R2 门或拒绝启动 |
| R2-I1 | P1 | `h2-node/src/service.rs:4821` `import_unsolicited` | B-3 可绕过:`first` 在裁剪前读取,低于最小高度的 body 总是"首个";无界 `import_queue`、挤出各缓存 | 只急切导入父已知且高度在窗口内的 body;`import_queue` 加上限与 HashSet |
| R2-I2 | P1 | `service.rs:4220-4465` | B-1 同族:未认证的 status 高度让在线节点无限追赶,空 QC 头被导入 | 连续 K 个无可验 QC 的头即结束并拒该 peer;近期提交过的节点不追赶 |
| R2-I3 | P1 | `service.rs:4991-5019`, `block_body.rs:184` | `BODY_ONCE` 下伪造交易的 body 占住诚实哈希,后续诚实副本全被当重复丢弃 | `Rejected`/`NotYet` 时清掉该哈希并换 peer 重取;`import_once` 不因 body 不符缓存 INVALID |
| R2-I4 | P1 | `driver.rs:1838-1871,2904` | leader 自己的导入无结论失败(超时/EL 重启)后卡到重启 | 回报非 Valid、移出 `imported`、退避重试 |
| R2-I5 | P2 | `service.rs:2821`, `transport.rs:1099` | VoteHello 任意 peer 任意速率触发 BLS 配对 | 不发直投时忽略;每连接一次;已学过则跳过 |
| R2-I6 | P2 | `service.rs:2516,2653` | B-4 同族:by-hash 与 fill 服务不计字节预算 | 用同一 `ServeGuard` |
| R2-I7 | P3 | `driver.rs:108` | 导入任务 panic 被当作 `Invalid` | 报 `NotYet` |
| R2-R1 | P2 | `service.rs:3034-3041` | A-2 回归:已按范围导入的块被提议时不 `remember_parent`,不投票 | 先 `remember_parent` |
| R2-R2 | P2 | `service.rs` `import_unsolicited` | B-3:匿名 peer 抢占高度后诚实 leader 的块失去急切导入 | 与 R2-I1 一起:按 view leader 验封印或豁免 leader 直推 |
| R2-R3 | P2 | `driver.rs:2873`, `service.rs:3998` | B-5 的"重试"不重新执行,x22 下还丢掉 compact body 并向全体 peer 取整块 | 独立的 `RetryImport` 动作,退避后重排 |
| R2-R4 | P3 | `forest.rs` `note_move` | D-5:每次计算都算"移动",簿记跳过清理而累积 | 第一次持锁时 `mem::take` 簿记,追加失败再并回 |
| R2-R5 | P3 | `h2-node` `consider_catch_up` | A-7 后 `unproven_from` 停在顶端,每次都查 EL 头 | 有界,低优先 |

## 状态

| id | 状态 |
|---|---|
| R2-X1 | 已修(见下) |
