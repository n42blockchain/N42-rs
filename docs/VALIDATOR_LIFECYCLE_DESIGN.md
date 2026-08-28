# N42 验证者与委员会的加入 / 退出流程设计（2026-08-28）

本文回答两个问题：其它链是怎样安全地增减验证者的，N42 应该怎样做。
对象是 N42 的两层参与者——**IDC 验证者**（HotStuff-2 出块与投票）和
**委员会池成员**（真机手机接管模拟池位、为每块出具委员会证据与移动证明）。
现状取自 gov5 `internal/consensus/hotstuff/{reconfig,validator,slashing}.go`、
`internal/blspool`、`internal/api/{hotstuff_reconfig_api,consensus_api}.go` 与
`docs/mobile-attestation-design.md`；本仓库的对应实现在
`crates/n42/h2-consensus`（`EpochManager`、`committee_pool`）与
`crates/n42/primitives`（APoS 时代的 Ethereum 式 beacon 层：`Validator`、
`process_registry_updates`、churn、deposit/exit）。

## 0. 现状与问题

链 94（`mainnet_qmdb_staggered`）：7 个验证者写死在 chainspec，`epochLength` 200。

| 环节 | gov5 今天怎么做 | 问题 |
|---|---|---|
| 加验证者 | `hotstuff_proposeAddValidator(address, blsPubKey)` 管理 RPC → 本地 `ReconfigurationManager` → 下一个 CommitQC 标记 committed → epoch 边界 stage → 下一 epoch 激活 | **提案不上链、不 gossip**：只有收到 RPC 的节点知道。7 个运营者必须在同一 epoch 内各自调一次同样的 RPC，漏一个就集合分叉。代码注释写的 "via on-chain transaction" 并不存在 |
| 退验证者 | `hotstuff_proposeRemoveValidator` | 同上；没有最短服务期、没有退出队列、没有提取延迟 |
| 惩罚 | `SlashingExecutor`：本地保存的双签证据 → 删除 deposit 记录 | 证据不上链，各节点各判各的；被罚者不会被移出集合 |
| 委员会池位接管 | `consensus_registerCommitteeValidator(slot, pubkey, proofSig)`，POP 签 `"n42-committee-register-v1"‖slot‖pubkey`；`consensus_submitCommitteeSignature` 每块提交 | 注册只写进**收到 RPC 的节点**的 rawdb；其它节点仍用模拟密钥算该池位 → **委员会证据根分叉**，`parentBeaconRoot` 校验会拒绝对方的块。链 94 未开 `allowHandover`，所以还没触发 |
| 跨客户端 | v4 签名域含 `changesHash`（`H2V4ProposalSigningMessage`），本应承诺集合变更历史 | 两端都恒填零，集合分叉不会被签名校验发现 |

结论：现有机制只适合静态集合。任何动态加入 / 退出，第一原则都是**从已提交的链上状态确定性地推导**，让 Rust 与 Go 客户端算出同一个集合，并把这个集合的承诺放进签名域。

## 1. 参考：其它链怎样做

| 链 | 加入 | 生效时机 | 退出 | 惩罚 / 剔除 | 值得学的点 |
|---|---|---|---|---|---|
| Ethereum（Electra） | 存款合约 32 ETH，`DepositRequest`（EIP-6110）随块执行进 `requestsHash`；BLS 对 `DOMAIN_DEPOSIT` 的 proof of possession | 存款块最终化后进队列，按 churn 上限（每 epoch 最小 4 / 余额权重）激活，`MAX_SEED_LOOKAHEAD`=4 epoch 提前确定，防止对随机数的 grinding | `VoluntaryExit`（BLS 签名，最短服务 256 epoch）或执行层触发的 `WithdrawalRequest`（EIP-7002）；退出也走 churn 队列；退出后 256 epoch 才可提取 | 双签 / 环绕证据上链 → slashing + 强制退出 + 举报奖励；不活跃泄漏；余额低于 ejection 自动退出 | 一切从链上状态推导；POP；最终化后才有资格；提前期；双向 churn；提取延迟覆盖证据窗口 |
| Cosmos / Tendermint | `MsgCreateValidator` 交易（自质押） | 验证者更新在 EndBlock 产生，**高度 +2 生效**（让下一个提案者提前知道集合） | `MsgUndelegate`，解绑 21 天 | 双签立即 tombstone；宕机（窗口内签名率不足）jail | 集合更新是块的输出，不是 RPC；固定 1 块提前期；按投票权截取前 N 名 |
| Polkadot（NPoS） | 质押 + `set_keys` 登记会话密钥 | 会话密钥**排队一个 session 后**生效；每 era（24 h）用 Phragmén 重选 | 解绑 28 天 | 惩罚延迟 28 era 执行，可被治理取消 | 密钥轮换是一等操作，且总是"下一期生效" |
| Aptos / Diem（Jolteon） | 加入 stake pool | **重配置由当前集合提交**：epoch 变更事件随块 commit，新集合从下一 epoch 生效（commit-then-activate） | 离开 stake pool，下一 epoch 生效，锁定期 | 治理 | 与 HotStuff-2 论文 §5 一致，gov5 已采用这一形状，只差"提案也在块里" |
| Solana | 质押账户 | 每 epoch 只允许一定比例的质押 warm-up / cool-down | 同左 | 无 slashing（协议层） | 变化速率上限而不是数量上限 |
| Avalanche | `AddValidatorTx` 带开始 / 结束时间、最短时长 | 到开始时间生效 | 到期自动退出 | 在线率不足不发奖励 | 显式服务期 |
| Algorand | 参与密钥登记交易，带首末轮 | 登记后 320 轮才生效 | 密钥到期 | — | 提前期 + 密钥有效期 |

抽出来的原则（后文按编号引用）：

- **P1 链上推导**：成员变更只能来自已提交的链上状态（交易 / 请求），任何客户端都能重算；不允许节点本地配置参与。
- **P2 密钥所有权**：POP 签名，签名域包含链 id 与创世哈希，防跨链重放。
- **P3 资格延迟**：变更所在的块必须已提交（HotStuff-2 的 commit 即最终化），再加一个固定提前期。
- **P4 提前期**：下一 epoch 的集合在本 epoch 开始时就已确定并 stage，谁也不能在最后一刻改动或对随机数 grinding。
- **P5 双向 churn 上限**：每个 epoch 能进、能出的数量有上限，避免一次性换血或集体退出打掉活性。
- **P6 退出的三条路**：自愿（自己签）、被动（提取地址触发）、强制（证据 / 不活跃）；退出后有提取延迟，且 ≥ 证据窗口。
- **P7 密钥轮换**：单独的操作，下一 epoch 生效，不需要退出重进。
- **P8 旧集合提交新集合**：变更由当前集合的 CommitQC 敲定，新集合在干净的 epoch 边界生效，历史集合保留用于验证跨边界的 QC。
- **P9 承诺进签名域**：集合（及其变更历史）的哈希进入每条消息的签名域，两个客户端算错即刻暴露，而不是静默分叉。

## 2. N42 的角色与边界

| 角色 | 是否在共识路径 | 数量 | 加入门槛 | 变更影响 |
|---|---|---|---|---|
| IDC 验证者 | 是：提案、投票、QC | 7（目标 ≤ 100） | 存款（质押）+ POP | 改变 quorum（`n`、`f`），进 `changesHash` |
| 委员会池成员（真机） | **否**：只产出委员会证据 / 移动证明，永不投票、永不阻塞出块（gov5 移动证明设计的硬边界） | 池 200k、每块 512 | POP，无质押，轻量 sybil 抵抗 | 只改变 `parentBeaconRoot` 里的证据根，不进 `changesHash` |
| 观察者 | 否 | 任意 | 无 | 无 |

两层的共同要求是 P1、P2、P9 式的确定性；不同的是验证者层需要完整的质押 /
churn / 惩罚，委员会层需要的是覆盖率与活性，可以宽松得多。

## 3. 登记通道：系统合约 + EIP-7685 请求

N42 的 header 已经有 `requestsHash`（gov5 目前写空根），执行层已有 Prague 系统
合约与 EIP-7002 提取合约（本仓库 `mobile-sdk/deposit_exit.rs` 已在用）。沿用
以太坊 Electra 的通道，不发明新的：

| 请求类型 | 发起方 | 载荷 | 用途 |
|---|---|---|---|
| `DepositRequest`（EIP-6110 形状） | 任何地址向 `ValidatorDeposit` 合约转账 | `pubkey(48) ‖ withdrawal_credentials(32) ‖ amount ‖ signature(96) ‖ index` | 加入验证者（首次）或追加质押 |
| `WithdrawalRequest`（EIP-7002） | 提取凭证地址 | `source_address ‖ pubkey ‖ amount`（amount=0 即完全退出） | 被动退出验证者 |
| `VoluntaryExit` | 验证者 BLS 密钥 | `validator_index ‖ epoch ‖ signature` | 自愿退出 |
| `KeyRotation` | 验证者旧密钥 + 新密钥 | `index ‖ new_pubkey ‖ sig_old ‖ pop_new` | 轮换（P7） |
| `CommitteeRegister` / `CommitteeExit` | 任何地址 | `pubkey(48) ‖ pop(96)` / `pubkey ‖ sig` | 委员会池成员进出 |
| `EquivocationEvidence` | 任何人（举报者） | 同一 view 的两条冲突签名消息 | 强制退出 + 惩罚 + 举报奖励 |

签名域统一为 `domain_type(4) ‖ chain_id(8) ‖ genesis_hash(32)`（P2）；`DepositRequest`
用现有 `DOMAIN_DEPOSIT`，委员会登记沿用 gov5 的 `"n42-committee-register-v1"`
前缀但补上链身份。

请求由块执行产生、被 `requestsHash` 承诺，共识层从**已提交**的块里读请求——
这就是 P1 与 P8 的实现：谁加入、谁退出，是当前集合提交的块说了算。gov5 现有的
`hotstuff_proposeAddValidator` 保留为便利入口，但改成"构造并发送这笔交易"，不再
直接改本地状态。

## 4. 验证者生命周期

```
Deposited ──committed + ELIGIBILITY_DELAY──▶ Eligible ──churn 队列──▶ Queued
   Queued ──activation_epoch──▶ Active ──退出请求 / 证据 / 不活跃──▶ Exiting
   Exiting ──exit_epoch──▶ Exited ──WITHDRAWABILITY_DELAY──▶ Withdrawable ──▶ Withdrawn
```

每个验证者记录（沿用本仓库 `n42_primitives::Validator` 的字段）：
`pubkey, withdrawal_credentials, effective_balance, slashed,
activation_eligibility_epoch, activation_epoch, exit_epoch, withdrawable_epoch`。

**epoch 边界算法**（每个客户端在提交 epoch `E` 最后一个块时执行，全部确定性）：

1. 从该块的注册表状态（合约存储）读出所有请求已处理后的验证者记录。
2. 激活：`Eligible` 中按 `(activation_eligibility_epoch, index)` 排序，取前
   `churn(E)` 个，`activation_epoch = E + 2`（P4：提前一整个 epoch）。
3. 退出：退出请求按到达顺序排队，每 epoch 放行 `churn(E)` 个，`exit_epoch ≥ E + 2`，
   `withdrawable_epoch = exit_epoch + WITHDRAWABILITY_DELAY`。
4. 强制退出：证据请求命中的验证者 `slashed = true`，立即进入退出队列头部；
   过去 `INACTIVITY_EPOCHS` 个 epoch 内在 QC 位图（header extra 里的 QC，已在链上）中
   的参与率低于 `INACTIVITY_THRESHOLD` 的验证者进入退出队列。
5. 轮换：`KeyRotation` 在 `E + 2` 生效，旧密钥保留用于验证 `≤ E + 1` 的 QC。
6. 得到 epoch `E + 2` 的集合 `S`，`f = (|S| − 1) / 3`；
   `changes_hash(E+2) = blake3(changes_hash(E+1) ‖ encode(S))`，其中 `encode` 是按
   index 排序的 `(address, pubkey)` 列表。stage 到 `EpochManager`（两端都有
   `StageNextEpoch`），`E + 2` 的第一视图激活。
7. 从 `E + 2` 起，所有 v4 消息的签名域用 `changes_hash(E+2)`（P9）。

**参数建议**（链 94：period 3 s，epoch 200 视图 ≈ 10 分钟）：

| 参数 | 建议值 | 依据 |
|---|---|---|
| `ELIGIBILITY_DELAY` | 1 epoch | commit 即最终化，一个 epoch 给同步与运营留余量（Ethereum 用 follow distance + 1 epoch） |
| 提前期 | 集合在 `E` 边界定、`E+2` 生效 | Cosmos 的 +2、Ethereum 的 `MAX_SEED_LOOKAHEAD`；gov5 现有 stage/activate 结构正好对应 |
| `churn(E)` | `max(1, ⌊n/8⌋)`，进出各自计 | Ethereum 的 `max(MIN, n/65536)` 太慢，Solana 的 25 %/epoch 太快；n=7 时每 epoch 1 个，n=64 时 8 个 |
| `MIN_SERVICE_PERIOD` | 8 epoch | 防止快进快出刷奖励（Ethereum 256 epoch 按比例缩放） |
| `WITHDRAWABILITY_DELAY` | 16 epoch ≈ 2.7 h | 必须 ≥ 双签证据窗口，让退出者仍可被罚 |
| `INACTIVITY_EPOCHS` / `THRESHOLD` | 3 / 50 % | Cosmos 的宕机 jail；参与率来自链上 QC 位图，无需额外证据 |
| 最小 / 最大集合 | 4 / 100 | 4 是 `f = 1` 的最小值；100 是 512 人委员会证据之外 BLS 聚合与 gossip 的舒适上限 |
| 最小存款 | 由治理定 | 链 94 是 replay 出来的开发网，存款合约里目前没有真实质押 |

**安全性说明**：HotStuff-2 的重配置安全性来自"旧集合用 CommitQC 提交了新集合"
（P8），不要求新旧集合重叠；churn 上限保护的是**活性**——一个 epoch 里最多换 1/8，
新成员来不及同步、或一批成员同时退出，都不会把集合压到无法成 quorum。跨边界的
QC 用对应 epoch 的集合验证（两端 `EpochManager` 都保留历史集合），
`changes_hash` 保证两个客户端算出的集合一致——不一致时是签名失败，而不是分叉。

## 5. 委员会池成员的加入 / 退出

委员会不在共识路径（gov5 设计不变量），所以它的规则以**覆盖率与确定性**为目标：

1. **登记**：`CommitteeRegister{pubkey, pop}` 交易。无质押；sybil 抵抗用交易费 +
   每地址一个密钥 + 冷却期（P2 之外只需轻量措施，gov5 §8.2）。
2. **池位分配**：不由调用者指定 slot（今天的 RPC 让调用者选，会撞车）。每个 epoch
   边界，把该 epoch 内提交的登记按 `(block, tx index)` 排序，依次分配**当前最小的
   模拟池位**，`E + 2` 起该池位由真机密钥代替模拟密钥参与委员会抽签与签名。
   所有节点从链上状态得到同一份"池位 → 密钥"表，委员会证据根自然一致。
3. **每块职责**：抽中即须对 `SigningMessage(number, hash)` 签名并提交
   （`consensus_submitCommitteeSignature` 保留为提交通道，可从任一节点进入，
   节点间用现有 gossip 转发部分签名）。证据里 `SignersPacked` 位图记录谁签了。
4. **覆盖率阈值**：某块的真机签名不足 `COMMITTEE_THRESHOLD`（建议 2/3）时，
   缺席的池位**由模拟密钥补签**——`rampBlocks` 机制的延续，出块永远不等手机。
5. **退出**：`CommitteeExit` 交易，或**自动停用**：连续 `PARK_AFTER` 次抽中未签
   （从链上 CE 位图统计）的池位在下一边界回到模拟密钥，重新登记即可回来。
6. **`allowHandover`** 从节点配置改为 chainspec 的分叉开关：某个 epoch 起全网同时
   允许接管，避免半数节点认接管、半数不认。

委员会成员变更不进 `changes_hash`（不改 quorum），但进委员会证据根，所以同样必须
只来自链上状态（P1）。

## 6. 威胁与对策

| 威胁 | 对策 |
|---|---|
| 运营者本地提案不一致（今天的模式） | §3：提案是交易，只有上链的算数 |
| 对委员会 / 领导者随机数的 grinding | 集合与委员会 seed 在 `E` 定、`E+2` 用（P4）；委员会抽签 seed 建议从块 `N-1` 的 header 印章（BLS 签名，确定性、领导者不可改）派生，替代今天的 `(N, hash_N)`——需两端同时切换 |
| 跨链重放存款 / 登记 | 签名域含 `chain_id ‖ genesis_hash` |
| 密钥泄露 | `KeyRotation`（P7）；提取凭证地址可独立发起退出（EIP-7002 形状） |
| 双签 | 证据上链、罚没、强制退出、举报奖励；`WITHDRAWABILITY_DELAY` 让退出中的人仍可被罚 |
| 集体退出 / 一次性换血 | 双向 churn（P5）、最小集合 |
| 新成员被 eclipse | 加入时的引导包由 ≥ f+1 个当前验证者签名（N42-26 的 bootstrap bundle 形状可复用） |
| 登记垃圾 | 交易费、每地址一密钥、冷却期 |
| 手机层 nothing-at-stake | 手机不影响最终性；证据只作透明度与奖励依据（gov5 §1） |

## 7. 落地：分阶段与两个客户端的改动

| 阶段 | 内容 | n42-rs | gov5 |
|---|---|---|---|
| 0（立刻可做） | `changes_hash` 不再恒零：静态集合也按 §4.6 算；两端必须一致 | `h2-node` 发送 / 校验时填入 | `interop_v4.go` 同步 |
| 1 | 系统合约 + 六种请求 + `requestsHash` 非空；共识层从已提交块读请求；`hotstuff_proposeAddValidator` 改为发交易 | 执行层：`HotStuffConsensus` 校验 `requestsHash`（今天只认空）；`h2-node` 解析请求驱动 `EpochManager::stage_next_epoch`；复用 `n42_primitives::{Validator, process_registry_updates, get_validator_churn_limit}` | 同样的解析与 stage；去掉本地 `ReconfigurationManager` 直改 |
| 2 | churn、退出队列、提取延迟、证据请求与不活跃剔除 | `n42_primitives` 已有 `initiate_validator_exit`、`compute_activation_exit_epoch`、inactivity score，改接 HotStuff 视图 | `slashing.go` 改为处理链上证据 |
| 3 | 委员会登记上链、池位确定性分配、覆盖率阈值、`allowHandover` 分叉化 | `committee_pool` 加"池位 → 真机密钥"覆盖层与部分签名折叠 | `blspool` 同样改动；`Register` 不再走本地 RPC |
| 验证 | 每阶段在 devnet 混合舰队上跑：加一个 Rust 验证者、退一个 Go 验证者、轮换一把密钥、提交一份双签证据、接管一个池位，各跨两个 epoch 边界，两端同头且 `changes_hash` 一致 | `scripts/devnet-fleet.sh` 加场景 | — |

阶段 0 与 1 完成后，路线图里"边界上的验证者集合变更实测"才有意义——今天能测的
只是静态集合跨边界（已通过）。
