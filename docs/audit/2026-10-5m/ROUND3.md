# 2026-10 5M 审计:第三轮

第二轮(`ROUND2.md`)全部处理完后做的第三轮深度审计。五路并行只读审阅:第二轮修复的回归复核、
网络输入解析(h2-net/h2-wire/h2-node 消费端)、engine-types 执行确定性、共识核心薄弱区、
RPC/快照/tx-queue/mobile。每项修复前先按代码核实,先写复现测试(修复前失败)。

编号:R3-G(回归)、R3-N(网络)、R3-E(执行)、R3-C(共识)、R3-P(RPC/快照/队列/mobile)。

## 发现

| id | 级别 | 位置 | 问题 | 修复要点 |
|---|---|---|---|---|
| R3-P1 | P1 | `bin/n42/src/init_snapshot.rs:190-297` | `init` 只核对 JSONL 首行自报的 root,账户/槽位不与 portable 快照对照就写入 MDBX;默认读 MDBX,篡改的 dump 让节点在错误前状态上执行 | 先验证 portable 快照得到树,逐行对照每个账户/槽位的叶值,地址严格递增,最后按 gov5 `verifyExportCoverage` 核对覆盖 |
| R3-P2 | P1 | `tx-queue/src/lib.rs`, `bin/n42/src/main.rs:817-886` | 队列无上限;池的淘汰/替换不同步到队列;非 nonce 拒绝永远 give_back,外部可复现 round-44 形状 | 有界 lane、只喂 pending 或镜像 Discarded/Replaced、多次拒绝后丢弃(热路径,需 A/B) |
| R3-P3 | P2 | `tx-queue/src/lib.rs:6413,6476` | 同 (sender, nonce) 的加价替换被当重复丢弃 | 费用更高且未被取走时替换 |
| R3-P4 | P2 | `bin/n42/src/main.rs:937-972`, `tx-queue/src/lib.rs:3781` | 规范通知 `Lagged` 只告警:跳过的块不 prune;`settle_own_block` 丢掉被跳高度上自己块的交易 | Lagged 时从 provider 补齐 `pruned_through()+1..head` |
| R3-P5 | P2 | `h2_validator.rs:367,703`, `mobile-service/src/service.rs:239`, `mobile-verify/src/verification.rs:51` | mobile 阈值 1、期望 receipts root 恒为 None:任何人一张收据即 `attested`,诚实收据永远聚合不成 | 传真实块号与 receipts root;root 未知不报 attested |
| R3-P6 | P2 | `mobile-verify/src/attestation.rs:54,136`, `mobile-service/src/rpc.rs:102` | 注册无 PoP(rogue key 聚合)、注册表无界、收据与共识共用 DST | 注册带 PoP、上限、独立 DST |
| R3-P7 | P2 | `mobile-service/src/http.rs:38-160` | 单线程阻塞 HTTP,无读写超时,头部无长度上限 | 超时、头部 `take(16 KiB)`、有界并发 |
| R3-P8 | P2 | `bin/n42/src/consensus_ext.rs:154-235`, `consensus-client/src/miner.rs:671` | APoS:公开订阅任务泄漏;验证队列可被公开调用占满 | 监听 `sink.closed()`;入队前校验成员与块哈希 |
| R3-P9 | P3 | `h2-el-rpc/src/transport.rs:181,236` | EL 响应体无大小上限(`--el-rpc` 也走它) | 按字节上限读取 |
| R3-N1 | P1 | `h2-net/src/rpc.rs:75-95`, `status.rs:259-308` | 帧读取每读一块就从头重扫;零长度可跳过块不限个数,O(N²) 钉住 tokio worker;声明长度直接 `vec![0; len]` | 增量扫描、限制块数、按实际解码增长、每 peer 连接上限 |
| R3-N2 | P0 | `h2-net/src/rpc.rs:478-507`, `h2-node/src/service.rs:1237,5144,5838` | `block_txns` 请求 2^20 个可重复索引,先拷贝出回复再查字节预算,超额回复被截到整个预算后照发:远程 OOM | 索引严格递增唯一;拷贝前求和,超过 32 MiB 拒绝;超额不再截断放行 |
| R3-N3 | P1 | `block_body.rs:281`, `service.rs:2710-2773,5093` | push/by-hash 允许 64 MiB 解码、1 字节交易无数量上限;by-hash 回复先全解码后核哈希 | 先核头哈希再解 body;交易数上限;push/by-hash 上限对齐 gossip |
| R3-N4 | P2 | `h2-net/src/config.rs:151`, `transport.rs:918` | gossip 未开 `validate_messages()`,先转发后校验;来源 peer 被丢弃 | 开启校验并回报 Accept/Reject/Ignore;透传 `propagation_source` |
| R3-N5 | P2 | `transport.rs:1144`, `direct_votes.rs:144`, `timeout.rs:337-381` | `/n42/vote/1` 任意 peer 任意消息类型,无去重限速;Timeout 先验签后查重 | gossip 模式忽略;只收 Vote/CommitVote;限速与去重 |
| R3-N6 | P3 | `h2-net/src/message_id.rs:34` | message id 每份拷贝整份 payload 后再哈希 | 增量 Keccak |
| R3-C1 | P1 | `engine-types/src/hotstuff_consensus.rs:303` | 延迟执行下头部 `gas_used` 是父块的执行,却按本头 `gas_limit` 校验;gov5 按父 limit(`adapter.go:446-460`)。满块后 limit 下调即 Rust 拒绝 gov5 接受的头 | 延迟执行激活时 `gas_used` 对照父 `gas_limit` |
| R3-C2 | P1 | `h2-consensus/src/header_profile.rs:197-278`, `h2-node/src/service.rs:4577-4638`, `wire_bridge.rs:125` | 实时路径不解码/验证头部 QC(gov5 拒绝不可解码、`qc.view > view`、验签失败);拉取路径反而比 gov5 严(位图填充位、祖先链) | 共用一个按 gov5 的检查,投票前与拉取路径都用 |
| R3-C3 | P3 | `h2-consensus/src/protocol/timeout.rs:241-273` | 重复超时时不重发本 view 的投票(gov5 `timeout.go:61-71` 重发) | 记住本 view 发出的 Vote,重复超时时重发 |
| R3-C4 | P3 | `h2-execution/src/driver.rs:2771,3001,2443` | 首个 body 被拒(R2-I3 后按字节判)时丢掉 `pending_commits`,下一份副本导入后不再提交;`remember_commit_ahead` 从 HashSet 任意驱逐 | Invalid 时移入 `commits_ahead`;驱逐按顺序 |
| R3-E1 | P1 | `engine-types/src/payload.rs:5199,2524`, `fast_transfer.rs:535`, `bin/n42/src/follower_import.rs:1081` | 延迟执行下 follower 按 Σgas_limit ≤ L 与按 max_fee 的最坏花费校验可纳入性,builder 按实际用量/有效价格装块:一笔 gas_limit 富余的交易即让每个 leader 造出被拒的块 | builder 用同一规则(累计 gas_limit、每 sender 最坏花费),或提议前自查剔除 |
| R3-E2 | P2 | `parallel_transfer.rs:4806,5268`, `payload.rs:3374` | 零手续费块并行路径不写 beneficiary,串行路径写(touch),QMDB 根不同;当前因 coinbase 奖励而潜伏 | 并行执行过交易即总是提交 beneficiary |
| R3-E3 | P3 | `parallel_transfer.rs:4603,5108` | 并行执行器不查单笔 gas_limit ≤ 剩余 gas(可纳入性更强,当前不可达) | 加累计检查 |
| R3-G1 | P2 | `qmdb-state/src/forest.rs:1293,1308,1641` | R2-Q1 修复不完整:追加失败后被取走的 delta 不还给记录,重试换到更高目标时走 `delta_since` 回退路径,已被 `forget_changes` 清掉的更高块翻转丢失 | 失败时把取走的 delta 还回各记录 |
| R3-G2 | P2 | `h2-node/src/service.rs:2654,5839` | R2-I6 的 512 MiB 预算全局共享,一个慢读 peer 可占满,所有 fill/by-hash 回复被拒 | 每 peer 字节上限 |
| R3-G3 | P3 | `h2-consensus/src/state_machine.rs:1224,1262` | R2-C7 每个事件都重试并计入连续失败,几毫秒内达到致命阈值 3 | 重试不计入,或限速 |
| R3-G4 | P3 | `h2-execution/src/driver.rs:1880` | R2-I4 首次导入也多克隆一次整个 payload(leader 每块) | 只在需要重试时克隆 |
| R3-G5 | P3 | `driver.rs:2749,2770` | 等待式 `execute()` 的 Valid/Invalid 不清 `import_retries` | 各终态清除 |
| R3-G6 | P3 | `tx-ingest/src/lib.rs:435,1431` | R2-X2 的 256 KiB 单笔上限拒绝带 sidecar 的 blob 交易并断开连接 | type 3 单独上限 |

## 状态

| id | 状态 |
|---|---|
| R3-P1 | 已修:`init` 先验证 portable 快照得到树(在链上、在头部块、root 等于头部),写入时逐行核对账户叶值与每个非零槽位,地址严格递增,最后按 gov5 `verifyExportCoverage` 核对覆盖(保留的 EIP-161 空账户除外);测试 `init_refuses_a_dump_the_snapshot_does_not_authenticate` 修复前失败(篡改余额的 dump 被接受)。仅 init,无热路径 |
| R3-N1 | 已修:`read_framed_limit` 逐块累计(不再每块从头重扫),可跳过块(流标识/填充)至多 16 个;`unframe_payload_limit` 按实际解码增长输出(不再按声明长度 `vec![0; len]`)。测试 `a_frame_padded_with_skippable_chunks_is_refused` 修复前失败(10,000 个填充块被接受)。热路径:body 解码器,只减不增;线格式不变(gov5 只发一个流标识)。未做:每 peer 连接上限 |
