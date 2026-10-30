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
| R2-I2 | 已修(主体):已提交高度之上 64 块以外、无可验 QC 的拉取块结束拉取并拒该 peer(冷节点尚无提交时不限);测试 `a_pull_far_past_the_committed_height_stops_at_the_first_unproven_block` 修复前失败。未做:在线节点不因未认证 status 发起追赶(64 块以内的伪造仍可导入为 head,永不 safe/finalized,A-7) |
| R2-C3 | 已修(门控):`N42_VOTE_BEFORE_IMPORT`、`N42_VOTE_LOG_NOSYNC` 需 `N42_BENCH_UNSAFE=1`,否则 h2_validator 拒绝启动,vote log 也不跳过 sync;测试 `the_unsafe_vote_knobs_need_the_bench_acknowledgement` 在加门控前失败。vote-before-import 路径不加 extends 检查(导入前父块未知,加了等于永不投票),由门控限定为 bench |
| R2-X3 | 已修:池路径只在每笔结果为 Ok/AlreadyImported 时记帧(每帧一次对结果的遍历,池路径非 5M 的 direct 路径);测试 `a_frame_the_pool_refused_is_not_indexed` 修复前失败 |
| R2-X2 | 已修(上限):单笔 1 MiB → 256 KiB,单帧 64 MiB → 16 MiB,256 连接合计 ≤ 4 GiB;测试 `what_the_connections_can_hold_is_bounded` 修复前失败。未做:按字节的全局信号量、帧间空闲超时(端口默认只绑回环) |
| R2-I7 | 已修:导入任务 panic/运行时丢失报 `NotYet`(重新请求)而非 `Invalid`;测试 `an_import_task_that_ends_without_a_verdict_reports_not_yet` 修复前失败,原测试改为新语义 |
| R2-I5 | 已修:gossip 模式不验 hello、已学到的 (index, peer) 不再验、每连接每 peer 至多 4 次;测试 `hellos_are_verified_only_where_they_can_matter` 修复前失败 |
| R2-C2 | 已修:跳转校验发现携带 QC 伪造的未来消息不再缓冲;缓冲未来 proposal 时校验其 justify QC(与回放同一校验,集合未知则仍缓冲),代价每个缓冲的未来 proposal 一次聚合验签;测试 `forged_qc_copies_of_a_future_proposal_do_not_crowd_out_the_genuine_one` 修复前失败。旧去重测试改用 view-0 QC 保持原意 |
| R2-C8 | 已修(确认可达):回放中晚到的伪造投票被记到触发推进的 Decide 头上;`advance_to_view` 回放前取出、回放后恢复 `unauthenticated`;测试 `a_forged_message_found_at_replay_is_not_blamed_on_the_trigger` 修复前失败 |
| R2-C4 | 已修:`on_block_ready` 记录本 view 的 `processed_proposal`,被回传的自身 proposal 在投票或超时后按重复丢弃;测试 `a_leader_given_back_its_own_proposal_after_a_timeout_drops_it` 修复前失败(重新发出 ExecuteBlock) |
| R2-C5 | 已修:真 genesis QC(view 0、零哈希、无签名者)作为 timeout/NewView 的 high QC 一律接受,与 gov5 一致;锁只向更高 view 移动,不会回退;测试 `a_timeout_with_the_genesis_high_qc_counts_after_the_lock_moved` 修复前失败 |
| R2-C6 | 已修:gov5 profile(H2V4/Gov5Legacy)下 Decide 的 `validator_changes_hash` 非零即拒(`H2V4ValidatorChangesUnsupported`),在验 QC 之前;测试 `a_gov5_decide_naming_validator_changes_is_refused` 修复前失败(伪造哈希触发 SyncRequired) |
| R2-C7 | 已修:leader 提案的 vote-log 写入挪到任何状态改动之前(失败时视图仍在等提案);失败的自身提案与 R2 自投 commit 票记入 `vote_log_retry`,下一个事件(`process_event` / `process_authenticated_message`)先重试,仅 fatal 错误上抛。热路径代价:每个事件一次 `Option` 判空。测试 `a_leader_retries_after_a_failed_log_write_in_both_rounds` 修复前失败 |
| R2-C9 | 已修(部分移植):genesis `twoPhaseVoteGate` 读入 `HotStuffGenesisConfig`,`h2_validator` 置 `set_two_phase_vote_gate`;开启时 PrepareQC 若块未在本地导入/检查则挂起 commit 票,`on_block_imported` 放行,换 view 清除(gov5 `pendingCommitQC`)。R1 仍按导入门控(比 gov5 两阶段 R1 更严、更慢);gov5 的 header vote / deferred vote 未移植。开关默认关,原生 fleet 与 5M 不受影响。测试 `under_the_two_phase_gate_the_commit_vote_waits_for_the_import` 修复前失败 |
| R2-I6 | 已修:transport 增加 `respond_block_holding` / `respond_block_txns_holding`(guard 保留到 `ResponseSent`/`InboundFailure`);by-hash(store 命中、elided、EL 查询)与 fill 回复都从独立的 `MAX_FILL_SERVE_BYTES`(512 MiB)预算取许可,预算不够时回 not found / server busy。热路径代价:每个 fill/by-hash 回复一次 `try_acquire_many_owned` 和一次 HashMap 插入删除。测试 `block_and_fill_replies_hold_their_guard_until_sent`(h2-net)、`fill_and_block_replies_draw_on_a_byte_budget_held_until_dropped`(修复前不能编译:没有持有式回复 API) |
| R2-R3 | 已修:`ImportVerdict` 新增 `NoVerdict`(EL 出错、SYNCING/ACCEPTED、任务死亡),与"compact body 拼不出来"的 `NotYet` 分开;`NoVerdict` 由 driver 按 `OWN_IMPORT_BACKOFF`(0.2/0.5/1/2/4 s)排程,service 每次 drain 调 `retry_failed_imports()` 用仍持有的 payload/body 重新执行,用尽后才 `PayloadMissing`;不再丢 compact body、不再立刻向全体 peer 取整块。热路径代价:每次 drain 一次 `is_empty`。测试 `an_import_without_a_verdict_is_executed_again_from_what_is_held`(修复前不能编译:没有重试 API),3 个旧测试改为新语义 |
| R2-X4 | 已修(缓解):每个 root 保留至多 `CLAIMS_PER_ROOT`=4 份不同的声明 layout(同 root 内先进先出),`root_for_body` 逐个尝试,第一份能在 body 自身哈希上复现 root 的即采用。未按声明者分键:EL 不知道描述来自哪个 peer;一个 peer 在真声明之后连发 4 份不同的假 layout 仍能挤掉它。代价仅在整块回退路径(本节点没有自己的 layout 时)每份错误声明多算一次 frame 树。测试 `a_wrong_layout_claimed_first_does_not_keep_the_right_one_out` 修复前失败 |
| R2-X4 余项 | 已合 main 766a89654(A/B 过:stage fx VX2,win1 4.993/4.980M 对 main 5.040/4.920M,轮总量 443.4/450.6M 对 452.1/443.2M,闸门干净):声明按来源分键。两端一起改:(1) h2-node 对同一块哈希除第一份 compact body 外,再把至多 3 份**不同 layout**、**每个 peer 一份**的 frame description 以 `request::CLAIM_LAYOUT`(新,raw 通道,只登记声明不导入)交给 EL,带来源 `ClaimSource`(peer id 的 keccak 前 8 字节,`[0;8]` 保留给本节点);簿记 `compact_claims` 与 `compact_bodies` 同界、同时清除,只有一份 body 时不建簿记;(2) foreign/compact body 帧加可选来源尾(tag `1` + 8 字节,无来源时字节不变,旧解码器照读),`ForeignBody.source`、`describe_compact_body_from`、`claim_compact_body`;(3) `CLAIMED_LAYOUTS` 每 root 每来源一槽(同来源再声明替换自己的槽),至多 `CLAIMS_PER_ROOT`=4 个来源,跨来源先进先出,`OWN_CLAIM_SOURCE` 不被外来声明挤掉,同一 layout 只存一次。gov5 话题与 body 格式未动。测试:engine-types `one_peers_wrong_layouts_do_not_evict_another_peers_right_one`、`foreign_sources_are_bounded_and_the_own_claim_survives_them`、`a_verified_layout_is_used_whatever_peers_claim`;h2-execution `a_foreign_body_carries_its_source_as_an_optional_tail`;h2-node `distinct_frame_layouts_from_two_peers_both_reach_the_execution_layer_with_their_sources`、`layout_claims_per_block_are_one_per_peer_distinct_and_bounded` |
| R2-R5 | 已修:`consider_catch_up` 的"无需读 EL"判断推广到 `unproven_from` 存在时,以 `min(上次读到的高度, unproven_from-1)` 比较 peer 高度;没有 peer 超过它就不再每次 drain 读一次 EL。测试 `no_peer_past_the_unproven_start_reads_the_layer_once_not_every_drain` 修复前失败 |
| R2-C9 余项 | 已修:gov5 header vote 移植。`ConsensusEngine::header_known(block, parent)` 记录父块，并在 two-phase gate 下为待决提案放行 R1(父哈希非零且满足 extends-justify,`try_header_vote`;提案先到或区块头先到均可);commit 票仍等导入。h2-node 在 `remember_block` 首次记住区块头且 gate 开启时，先过 R3-C2 的 header QC 检查再交给引擎。gov5 的 deferred vote 无需移植：`BlockChecked` 已与导入同样放行投票。测试 `under_the_two_phase_gate_the_vote_goes_out_on_the_header`(h2-consensus)、`under_the_two_phase_gate_a_header_reaches_the_engine_once_its_qc_passes`(h2-node),修复前均失败。gate 默认关，原生 fleet 不受影响;与 gov5 两阶段 fleet 混跑待 Linux。aab6c13b1 / 47afc33ee |
| R2-C9 余项 / R2-C1 余项 | Linux gov5 混跑(2026-10-30):devnet 基因副本 `twoPhaseVoteGate: true`,gov5 成员晚到(gov5late2p,160 块)与从头在场(gov5now2p,133 块)两形态两客户端同哈希、gov5 error 0,Rust 验证者启动打印 `vote gate : two-phase`,gov5 链库 chainspec 同值;Rust 侧超时数与 gate 关闭的形态相同(leader 侧 20 / 2)。R2-C1 的 `high_tc` 采纳由 late/absent 形态覆盖(重连成员追上并再提交)。两项已修 |
