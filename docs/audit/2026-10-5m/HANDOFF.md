# 2026-10 5M 审计:交接文档(第三轮结束时)

更新日期:2026-10-29。分支 `audit/5m-full-2026-10`,每次推送同时快进 `main`。

## 文档索引

| 文件 | 内容 |
|---|---|
| `FIX_PLAN.md` | 第一轮发现与修复计划 |
| `A-*.md` … `E-*.md` | 第一轮分领域审计记录 |
| `GOV5_CROSSCHECK.md` | 与 gov5 的跨客户端核对 |
| `ROUND2.md` | 第二轮发现与状态 |
| `ROUND3.md` | 第三轮发现(表"发现")与逐项状态(表"状态",两列:`编号 | 已修/未修:说明`) |

## 第三轮结果

已修(每项先写失败的复现测试,再修):

| 编号 | 级别 | 提交 | 摘要 |
|---|---|---|---|
| R3-P1 | P1 | f983aba72 | `n42 init` 用 portable 快照逐行认证 JSONL dump |
| R3-N1 | P1 | 260a47975 | 帧读取增量扫描,可跳过块至多 16 个,按实际解码增长 |
| R3-N2 | P0 | 2a8c7f289 | `block_txns` 索引严格递增,拷贝前按 32 MiB 求和拒绝 |
| R3-N3 | P1(主体) | b2c81f560 | body 交易数上限 `gas_limit / 21000` |
| R3-N5 | P2(部分) | 1ef8ee7fe | `/n42/vote/1` 只收 Vote/CommitVote/Timeout |
| R3-N6 | P3 | 947f31aad | message id 增量 Keccak |
| R3-C1 | P1 | a400424a1 | 延迟执行下 `gas_used` 对照父块 gas limit(同 gov5) |
| R3-C3 | P3 | e036b0f1b | 重复超时重发本 view 的投票(同 gov5) |
| R3-C4 | P3 | 6f7b568d1 | 被拒 body 的等待提交移入 `commits_ahead`;按序驱逐 |
| R3-G1 | P2 | 9e4e2c17f | 追加失败时 `forest.restore_deltas` 交还 delta |
| R3-G3 | P3 | 5ccd625d9 | vote log 重试不计入连续失败 |
| R3-G5 | P3 | 168c4744c | 导入终态清除 `import_retries` |
| R3-P5 | P2(部分) | 9468037f6 | 未知 receipts root 不报 `attested` |
| R3-P6 | P2(部分) | 93f3ea2cf | 验证者注册表上限 100,000 |
| R3-P7 | P2 | df642b630 | mobile HTTP 10 s 期限、写超时、头部 16 KiB |
| R3-G2 | P2 | 9807d44d2 | fill/by-hash 回复预算按 peer 分份(每 peer 至多 1/8),断开时释放 |
| R3-G6 | P3 | df25a5ef9 | blob 交易(type 3)单笔上限 1 MiB,其余仍 256 KiB |
| R3-P8 | P2(部分) | b3d980d4a | APoS 公开订阅在 sink 关闭时结束并向 router 发 `Disconnect` |

另有一个测试夹具修正(67449f7ba):engine-types `a_described_block_of_many_chunks_with_fills_is_the_decoded_block`
的 gas limit 改为 60M(R3-N3 的上限让 30M 夹具装不下它的交易数)。

未修与原因(详见 `ROUND3.md` 状态表):

| 编号 | 原因 |
|---|---|
| R3-E1 | builder 与 follower 的可纳入性规则需先与 gov5 对齐;每笔交易热路径,需 A/B |
| R3-C2 | 头部 QC 检查需按 gov5 `decodeHeaderExtra` / `verifyHeaderWithBatch` 写共用检查并用 gov5 夹具对齐,直接加会拒绝 gov5 接受的块 |
| R3-E2 | gov5 对零金额不置脏,"总是写 beneficiary"可能偏离 gov5;当前因块奖励潜伏 |
| R3-E3 | 当前不可达,随 E1 |
| R3-G4 | 每块一次克隆,改所有权的风险大于收益 |
| R3-P2/P3/P4 | tx-queue 有界 lane、替换、Lagged 补齐需与帧索引一起设计,热路径需 A/B |
| R3-P9 | 信任边界内(本机 EL) |
| R3-N4 | gossip `validate_messages()` 影响转发时机与 gov5 网格评分,需单独设计与 A/B |
| R3-P8 余项 | 验证队列入队前校验成员与块哈希(APoS 路径,未做) |
| R2-C1 high_tc | 第二轮遗留,见 `ROUND2.md` |

## 待做:同机 A/B(bench 主机恢复后)

5M 配置热路径上的改动,每项都需 `scripts/fleet7-bench.sh` 同机对照(看总量与 window 1,单轮差异 <10% 不可见):

| 编号 | 代价 |
|---|---|
| R3-N2 | 每个 fill 回复多一次 O(n) 遍历 |
| R3-N3 | 每块一次除法,每笔一次比较 |
| R3-G2 | 每个 fill/by-hash 回复多一次 HashMap 查找与一个 semaphore permit |
| R3-C3 | 每次投票一次克隆 |
| R3-N1、R3-N6 | 只减成本 |

## 未推送的分支

推送曾被拒,未重试。需要时由用户执行:

```
git push origin design/qmdb-compact-stage1 fix/qmdb-compact-stage2-audit:design/qmdb-compact-stage2
```

## Linux 会话接手(bench 主机或任意 Linux)

在 Linux 上不需要 WSL 与 `sync.sh`,直接在仓库里跑 cargo。

```bash
git fetch origin && git checkout audit/5m-full-2026-10 && git pull --ff-only
git log --oneline -25            # 第三轮提交从 f983aba72 起

# 1. 第三轮触及的全部 crate(含 Windows 上无法编译的)
cargo test -p n42-h2-net -p n42-h2-consensus -p n42-h2-execution \
           -p n42-mobile-verify -p n42-mobile-service
cargo test -p n42-h2-node --lib
cargo test -p n42-qmdb-state -p n42-qmdb-reth
cargo test -p n42-engine-types --lib
cargo test -p n42-tx-ingest --lib
cargo test -p n42 --lib consensus_ext     # n42 lib 编译慢,不要加短 timeout
cargo test -p n42 --bin n42-init-snapshot init_refuses  # R3-P1

# 2. CI 门槛
cargo check --workspace
cargo clippy --workspace --lib --bins --examples
```

各修复的复现测试名都写在 `ROUND3.md` 状态表里,可以单独跑,例如
`cargo test -p n42-h2-node --lib one_peer_cannot_hold_the_whole_fill_budget`。

A/B(见下一节)按 `CLAUDE.md` 的 bench 规则做:

```bash
# B:第三轮之前的提交(R3 第一个提交的父提交);A:当前分支头
# 需要 n42 与示例 h2_validator / h2_keygen / tx_flood(fleet7-repeat.sh 会复制这四个)
build() { cargo build --release -p n42 --bin n42 &&           cargo build --release -p n42-h2-node --example h2_validator --example h2_keygen --example tx_flood; }
git worktree add ../n42-r3-base f983aba72~1
(cd ../n42-r3-base && build)
build
# 两边各跑 >=3 轮,交替进行,比较总量与 window 1
F7_BIN=$(cd ../n42-r3-base && pwd)/target/release scripts/fleet7-repeat.sh 3 --tag r3-base
scripts/fleet7-repeat.sh 3 --tag r3-head
```

`memory :` 头行显示大页池低于约 30 GB 的一轮不可比;第一轮之前先让 `fleet7-bench.sh` 的
`dropcache.py` / `hugeprep.py` 跑完。结果记到 `ROUND3.md` 状态表对应行末尾。

## 工作环境(Windows 主机)

- Linux bench 主机不可用;reth-provider 相关 crate 在 WSL2 Ubuntu-24.04(用户 `n42`)里编译测试,
  `~/sync.sh` 把 `D:` 上的工作树同步到 `~/N42-rs`。C: 空间紧,一切放 D:。
- Windows 上可直接编译:h2-net、h2-execution、h2-consensus、mobile-verify、mobile-service。
  需 WSL:h2-node、qmdb-reth、engine-types、tx-ingest、bin n42(`n42` lib 编译很久,别加短超时)。
- `bash ~/check.sh`:h2-node 与 qmdb-reth 的 clippy 前后对比(基线 20/20),并构建 `four_node_fleet`。
- 提交前统一行尾(仓库混有 CRLF 文件);不要提交
  `scripts/fleet7-runs/results/manykeys-loop351D2S12P30T64X10i.txt`(本地运行产物)。
- 规则:先失败测试后修;vendored reth crate 只做增量改动;gov5 夹具按字节比对;新 N42 文件带 SPDX 头;
  提交信息英文、Conventional Commits。

## 分工(Windows 会话 / Linux 会话)

Windows 会话(无 bench 主机,WSL 编译)已完成第三轮全部可在本机验证的修复,止于 b3d980d4a 与本文档。
Linux 会话接手:

1. 在 Linux 上跑一遍"Linux 会话接手"一节的全部测试与 `cargo check --workspace`
   (Windows 侧只跑了触及 crate 的 lib 测试与 h2-node/qmdb-reth 的 clippy 对比)。
2. 同机 A/B,结果写回 `ROUND3.md` 状态表。
3. 按下面顺序推进未修项;每项仍先写失败测试。

## 下一轮建议顺序

1. bench 主机恢复后先做上面的 A/B,再动任何热路径项。
2. R3-C2(共识安全,跨客户端):先写 gov5 夹具驱动的共用 QC 检查。
3. R3-E1:与 gov5 对齐可纳入性规则后,builder 与 follower 同改。
4. tx-queue 组(P2/P3/P4)一起设计。
5. R3-N4 与 R3-P5/P6 余项(PoP、独立 DST 需 mobile-sdk 同步)。

## Linux 会话结果(2026-10-30,bench 主机电源更换后)

主机 10-28 17:54 UTC 第四次在负载台阶上掉电(一次 `cargo test` 的多线程测试二进制,87 W → 337 W),
用户 10-29 更换电源;以下是更换后的第一轮验证,main `b91411e27`(链脚本
`/data/n42-build/audit-notes/scripts/main-verify.sh`,日志 `ci/main-verify.log`):

| 步骤 | 结果 |
|---|---|
| 测试(交接表全部 crate:deferred-reverts、engine-types、env、h2-consensus、h2-el-rpc、h2-execution、h2-net、h2-node、mobile-service、mobile-verify、qmdb-reth、qmdb-state、twig-core、tx-ingest、tx-queue、tx-types、h2-wire、n42 lib+bins) | 71 套件 ok,0 失败。第一遍在 `93f3ea2cf` 上只挂 `a_described_block_of_many_chunks_with_fills_is_the_decoded_block`(R3-N3 的上限 vs 30M 夹具),与 Windows 的 `67449f7ba` 同一修法 |
| `cargo check -p n42 -p n42-h2-node --tests --examples`;`cargo check --workspace` | 通过 |
| `cargo clippy --workspace --lib --bins --examples` | 1500 条警告,基线(`4e43be3ac`)1504 |
| native 构建(`target-cpu=native`,n42 + h2_validator/tx_flood/h2_keygen/send_tx) | 通过 |
| x22 探针(七节点,`N42_PROFILE=x22`,200 tx/s,90 s) | 高度 28 / 持久化 21 / 内存 7,与审计前探针逐字相同;`N42_BENCH_UNSAFE` 由 main 的 `fleet7-env.sh` 自给 |
| devnet 三形态(gov5 成员) | gov5late:160 块,gov5 封 40 / 提交 200,块 160 两客户端同哈希;late:121 块,补拉成员同哈希;absent:185 块,归来成员再提交 103。gov5 日志 2 条 error 是晚加入后 36 s 内两次 "committed block not executed locally"(number 0,EL 未追上的瞬态),之后正常 |
| fleet7 `roll --kill`(`N42_QMDB_ENTRY_FILE=1`,首杀 20 s) | node1 高度 8 从块 0 检查点 + entry 文件恢复,node2 从块 21,node3 从块 42;三者都重新加入并再提交 |
| X22 同机配对 | bench 树 stage `fv`(`bench/main-x11t16` `c00ebb297`):main `b91411e27` natives 对 `native-qc`(= 审计前 main `f2a1ff86c`),WARM + 四腿交替,600M 回放集;stage 导出 `N42_BENCH_UNSAFE=1`(审计后的二进制拒绝 runner 的直通 ingest),X11 本就显式带 `N42_CANON_NOTIFY_LEAN=1`。结果见下 |

X22 配对结果(2026-10-30 01:22-01:51 UTC,`loop351fv.launch.out`;WARM 一腿后四腿交替,每腿 3 × 30 s 窗口,
600M 回放集,全部腿 bodygate/d2gate 干净:invalid 0、字段不匹配 0、运行中 TC 0):

| 腿 | 二进制 | win1 | win2 | win3 | 轮总量 | cycle | 满块 |
|---|---|---|---|---|---|---|---|
| VMa | main `b91411e27`(审计后) | 5,046,667 | 5,066,667 | 4,993,333 | 453.2M | 40 ms | 756/757 |
| VM0 | `native-qc`(审计前 `f2a1ff86c`) | 5,060,000 | 5,106,667 | 4,900,000 | 452.0M | 40 ms | 758/759 |
| VMb | 审计后 | 5,040,000 | 5,000,000 | 4,926,667 | 449.0M | 40 ms | 755/756 |
| VM0b | 审计前 | 5,040,000 | 5,120,000 | 5,080,000 | 457.2M | 40 ms | 755/756 |

win1 审计后 5.047 / 5.040M 对审计前 5.060 / 5.040M(-0.1%),轮总量均值 451.1M 对 454.6M(-0.8%):
按"单轮差异 <10% 不可见"的规则,第三轮(及第一、二轮)热路径改动在 5M 配置下**无可见代价**,
R3-N1/N2/N3/N6/C3/G2 的 A/B 一并闭合。一处差别可记:两条审计后的腿里七个节点都在 view 1 形成了一次
启动 TC(leader 已提案、票未到,6 s 后进 view 2),两条审计前的腿没有;但 10-28 的 `fq` 腿(与审计前
同一二进制)也有 7 条,属启动时序,窗口内无影响。新电源下守护峰值 349 W / Tctl 54 C。

