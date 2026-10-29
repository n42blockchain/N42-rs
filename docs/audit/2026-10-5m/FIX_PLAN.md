# 2026-10 5M 审计:修复排期

依据:同目录 A-E 五份复核后的发现(每份末尾的 Verification 表)。原则:

- 每项先写能复现的测试(测试在修复前失败),再改代码;修复不得改变 5M 测量配置的热路径行为,
  需要改热路径的项写明代价并在 bench 主机恢复后做同机 A/B。
- 与 gov5 互通的规则(线格式、头部校验、投票传输)按 gov5 源码核对后再改,结论记在对应条目。
- 依赖 `reth-provider` 的 crate(h2-node、qmdb-reth、engine-types、tx-ingest、bin/n42)在 WSL2 中编译和测试
  (`docs/PLAN_WINDOWS_DEV.md` W6)。

## 第 0 批:已完成

| id | 级别 | 提交 | 说明 |
|---|---|---|---|
| E-1 | P1 | 93addab2a(本分支) | `N42_CANON_NOTIFY_LEAN` 移出 X22,改为 bench-only |
| E-4, E-8 | P1/P2 | 7e379dc62(`design/qmdb-compact-stage1`) | offsets 目录满时返回错误,段长度断言,clone 不占预取池,32 位可编译 |

## 第 1 批:P0 与持久化 P1(先写复现测试)

| 顺序 | id | 级别 | 复现测试 | 修复 |
|---|---|---|---|---|
| 1 | B-1 | P0 | h2-node:落后节点向伪造链服务端按范围拉取(空 QC / view-0 QC / 未知验证者集),之后诚实 peer 的更高链无法再触发追赶 | 拉取的块不再仅凭父链接接受:有 QC 时校验签名与域;无可校验 QC 的头不推进追赶基准(`imported_height` 只由已认证的高度推进),或在诚实 peer 的已认证链与 EL 头冲突时回退并重拉;保持 gov5 头部规则(见 gov5 核对) |
| 2 | D-1 | P0(d2 配置) | qmdb-reth:d2 genesis + entry-file + fold 头高于 MDBX 头时重启 | `persisted_state_root` 文件分支先查 `archived_file_checkpoint`,同 heap 分支 |
| 3 | D-2 | P1 | qmdb-reth:注入一次压缩失败后在进程内重试 | sealed head 存进 `PersistCursor`,`rewrite_checkpoint` 用刚追加的块;重试退避;d2 下 frontier 失败不再让已写日志的块报错 |

## 第 2 批:其余 P1

| 顺序 | id | 级别 | 修复要点 |
|---|---|---|---|
| 4 | B-7 | P1 | 自己的块被自己的 EL 判 `Invalid`/`Syncing`:error 级日志、计数、按本地故障停投票(与 `commit_invalid` 同处理) |
| 5 | B-2 | P1 | elided/整块服务占 `ServeSlot`、移出共识循环、先查 `body_store`;两个队列共用上限 |
| 6 | C-1 | P1 | 他人声明的布局与自己封块的布局分表;`payload_serve` 只用自己的布局 |
| 7 | E-2 | P1(stage2 分支) | `relocated_len == 0` 时写 v1 checkpoint |

## 第 3 批:P2 加固(按区排列,一项不漏)

| 区 | id | 修复要点 |
|---|---|---|
| A | A-1 | 批量路径的 vote-log 错误上报为本地故障,设置 `METRIC_VOTING_HALTED` |
| A | A-2 | 父块未知时的 extends-justify 行为按 gov5 核对结果保留或收紧 |
| A | A-3 | 相同 proposal 去重;重放不得重置阶段、重复计超时、在已超时的 view 里放出首票 |
| A | A-4 | 验证者集合去重(重复公钥)与 PoP 检查(加载 genesis 时) |
| A | A-5 | Native profile:先 `commit_pending_changes` 再提交;view 推进时清理 `imported_parents` |
| A | A-6 | 非 genesis 形状的 view-0 QC 一律拒绝 |
| A | A-7 | 代码中写明"拉取的块永不 safe"是唯一防线并加测试;域检查收紧到头部所用的域 |
| A | A-8 | 验证失败返回可区分的错误,供将来 peer 计分 |
| B | B-3 | 未请求的 body 不急切导入(需对应 proposal 或请求);h2-net 连接上限 |
| B | B-4 | 服务内存按字节计,槽位持有到 libp2p 发完 |
| B | B-5 | 超时与 `Invalid` 分开:超时返回可重试状态(raw 与 HTTP 两条路径) |
| B | B-6 | 快速路径也执行 `check_local_faults` |
| C | C-2 | `N42_FRAME_GATEWAYS` 需 `N42_BENCH_UNSAFE=1`;认证分支调用 `ed25519_key()`;`fleet7-env.sh` 对 gateway leg 显式确认 |
| C | C-3 | `N42_TX_INGEST_DIRECT` 纳入 `N42_BENCH_UNSAFE` 门控;修正 KNOBS.md 的"presence only" |
| C | C-4 | 启动脚本不再自动导出 `N42_BENCH_UNSAFE`,由 leg 显式给出 |
| D | D-3 | `settle_through` 成功后 fdatasync `forest.roots`;非延迟执行链用 MDBX 头的 state root 复核 |
| D | D-4 | 低于持久游标的截断前先落盘 rewind delta |
| D | D-5 | `forget_changes` 并入第一次持锁 |
| D | D-6 | 删除失败时返回错误,或像 rollback 归档那样复制日志 |
| D | D-7 | 归档退役留余量;文档注明 sync-mode 依赖 |
| D | D-8 | 读视图改用 `checked_record`,坏偏移时拒读而非 panic |
| D | D-9 | 文件模式恢复保留 `rollback-*` 归档 |
| E | E-3 | 打开时忽略 `relocated_len` 之后的组 / 跳过名字仍活跃的 dead 组;压缩上限夹到持久 checkpoint 的 `next_slot`;修正"幂等"注释(stage2 分支,stage 3 排程前必须完成) |
| E | E-5 | x22 的 `N42_VOTE_TRANSPORT=direct` 加链门控,或改为 `both`(按 gov5 核对结果) |
| E | E-6 | `open_relocated` 只把 `UnexpectedEof` 当作撕裂尾部,其余错误上抛(stage2 分支) |
| E | E-7 | 压缩上限纳入 `self.pending`(stage2 分支) |
| E | E-9 | 修正 `main.rs` 的 SAFETY 注释(解析链规格会启动 rayon) |
| E | E-10 | profile 内的 `== "1"` 读取改为 `n42_env::flag`;空值语义写进 KNOBS.md |

## 状态

| 批次 | 状态 |
|---|---|
| 第 0 批 | 完成 |
| 第 1 批 | 完成:D-1、D-2 为 2cba0a42f,B-1 为 5e6e8c677;复现测试修复前均失败、修复后通过;h2-node 与 qmdb-reth 全部测试通过(WSL2) |
| 第 2 批 | 完成:B-7 为 892c549cc,B-2 为 624b4d1e3,C-1 为 d72c8a9d9(本分支);E-2 为 6a438c5f0(分支 `fix/qmdb-compact-stage2-audit`,基于 `origin/design/qmdb-compact-stage2`,E-3/E-6/E-7 也在那里修) |
| 第 3 批 | 完成:A-1 cc308e5cf,A-2 602e1d266,A-3 3a98d8495,A-4 2c8c7edcf,A-5 e8612e544,A-6 d5575f368,A-7 0b1fc50eb(头部 QC 只证明它所指的块及以下;B-1 的 `unproven_from` 改为被认证高度 + 1),A-8 a66cd6e18;B-3 f746f3523,B-4 b9aaf3bf8,B-5 1d59a6539(EL 交换失败返回 NotYet/PayloadMissing,不再判 Invalid),B-6 ee2d9c815;C-2 a463d27a1,C-3 35e816b7d,C-4 b4aafea36(网关、直通 ingest、leader/shard 都需启动参数里显式的 `N42_BENCH_UNSAFE=1`);D-3 ae864461c(`forest.roots` 每个持久化批次 fdatasync 一次;非延迟执行链缺记录时用 MDBX 头部 state root 复核);D-4 3855292e8(按用户选择:fail-stop + 截断后 fsync,窗口内崩溃由重启根校验拒绝,有测试固定),D-5 4fb1c76a9(移动计数,两次持锁间有移动则不清簿记),D-6 ac7169469(删除失败时归档日志改为独立副本);D-7 8f555cf34(归档退役余量 64 块,模块文档注明 sync-mode 依赖),D-8 a666343db(`try_record` 拒读),D-9 3b1b8daed(文件模式 rollback 归档,恢复搜索跳过 rollback);E-5 05ff65894(`N42_VOTE_TRANSPORT=direct` 需 `frameBlocks`),E-9 cc45539c0,E-10 4565e2a3d + fe96b656a(60 处开关改用 `n42_env::flag`,源码扫描测试);stage2 分支:E-3 4294ec587(打开时跳过 dead 记录与检查点活跃位冲突的组;(b) 的"夹到 checkpoint next_slot"未做——旧 twig 的击杀与 next_slot 无关,夹位挡不住,由 (a) 覆盖),E-6 8414c0bc2,E-7 62265d47c(stage2 分支推送待用户授权);审计分支与 main 已推送;b76df48f8 把 11 个被误转成 CRLF 的文件恢复为 LF |
