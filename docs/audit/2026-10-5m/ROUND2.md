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
| R2-X1 | 已修 afdd51d80:测试 `a_torsion_component_in_r_gets_one_verdict_in_every_batch` 修复前失败(nonce 1 单独验证被拒,nonce 0 通过) |
| R2-Q1 | 已修:`QmdbForest::remeasure`,两条追加路径出错时把未落日志的 delta 还给簿记;测试 `a_failed_delta_append_loses_no_flip` 修复前重启报 duplicate active key。`checkpoint()` 失败后重试整树重写,不丢 |
| R2-Q4, R2-R4 | 已修:`logged_slots` 水位(取走/量出 delta 时设置),`move_to` 只在切到已记日志的槽位以下时 fsync;取走 delta 的同一次持锁里清簿记,去掉第二次持锁与移动计数比较(热路径少一次加锁)。测试 `only_a_cut_below_the_logged_slots_syncs_the_entry_file`、`a_build_between_the_persistence_holds_keeps_only_its_own_bookkeeping` 修复前失败 |
| R2-Q3 | 已修:`rewrite_checkpoint` 先查 `compacting` 再走同步路径;测试 `the_synchronous_checkpoint_waits_for_a_running_compaction` 修复前失败 |
| R2-Q2 | 已修:`QmdbForest::canonical_at`,头高于持久块时核对该块在规范链上(记录不够远时仍按高度);测试 `the_persist_hook_refuses_a_block_off_the_canonical_chain` 修复前失败 |
| R2-Q5 | 已修:`persisted_state_root` 重建的根与 `forest.roots` 记录比对,不符返回 `RestoredRootMismatch`;测试 `a_rebuilt_historical_root_is_checked_against_its_record` 修复前失败 |
| R2-C1 | 部分已修:按 gov5 `handleFutureViewTimeout` 移植按发送者的最高未来超时 view,取第 f+1 高 view 跳入;测试 `scattered_future_timeouts_join_the_f_plus_first_highest_view` 修复前失败。入站 `high_tc` 的采纳(gov5 `processEmbeddedTC`)未做:每条消息多一次 TC 验证,需要缓存设计,另列 |
| R2-R1 | 已修:已导入块的 `ExecuteBlock` 快捷路径先 `remember_parent`(多一次哈希查找);测试 `a_proposed_block_the_pull_imported_has_its_parent_recorded` 修复前失败 |
| R2-I4 | 已修(主体):自己块的导入无结论(错误/SYNCING/ACCEPTED)时按 0.2/0.5/1/2/4 s 退避重试,最终失败记 error;测试 `an_own_import_without_a_verdict_is_tried_again` 在无重试时失败。重试全部失败后仍留在 `imported`(追赶跳过它)未改,极端情况仍需重启 |
| R2-I3 | 已修:`Rejected` 时丢掉该哈希的 body(store、compact、driver 缓存),下一份副本照常导入且不再转发伪造字节;EL 的 import-once 只保留 VALID 供后续请求复用(INVALID 是对所带字节的判决)。测试 `a_rejected_body_is_forgotten_so_the_next_copy_is_taken`、`only_a_valid_verdict_answers_later_requests` 修复前失败。未做:记录供应者、向其他 peer 重取 |
| R2-I1 | 已修:未请求的 body 只在 `(tip, tip + far_ahead + 1]` 窗口内急切导入,低于全部记住高度的不算"首个";测试 `an_unsolicited_body_outside_the_tips_window_waits_for_a_proposal` 修复前失败。热路径代价:每个未请求 body 多一次 `imported_tip()`(几次哈希查找)。窗口外的 body 原本也会被 far-ahead 扣住,行为不变 |
| R2-R2 | 未修:窗口内仍是先到先得,匿名 peer 抢占某高度会让诚实 leader 的块失去急切导入(只推迟到 proposal 到达时导入,不丢票)。根治要按 view leader 校验头部封印,另列 |
