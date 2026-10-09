# N42 DDN 实现与验收

本目录提供公开提案的链上决策应用层和只读运维决策工具。DecisionHub、ProposalRouter、relay、SDK 和示例页面移植自 n42-26；推理结果由运营方签名背书，不能据此证明模型执行或答案正确。当前没有移植 gov5 的完整分布式计算、质押结算、worker 网络或推理预编译，也没有完成部署验收。

## 构建与检查

DDN 是独立 Cargo workspace，根 workspace 显式排除本目录。依赖锁定在本目录的 Cargo.lock，构建产物放在 ddn/target，不占用节点 workspace 的构建锁。检查脚本以单编译任务和 nice 19 运行，不会启动节点或模型、修改性能参数、读取运行中的日志或调用云模型。

从仓库根运行：

```sh
./ddn/check.sh --local
./ddn/check.sh
```

第一条运行 Rust、Clippy、Python 和 SDK 检查。第二条还要求 Foundry，编译并执行 Solidity 测试；缺少 Foundry 时明确失败。两条都不部署合约。链上测试网完整流程仍需另行执行。

[中文接入指南](docs/decision/README.md) 和 [英文接入指南](docs/decision/README.en.md) 中的命令应在 ddn/ 目录运行；从该目录启动静态文件服务，浏览器访问 examples/decision-dapp/。

## 实现对照

参考源码版本：n42-26 `99238f1198d9a940c4c0f5c364f201ab27baea79`，N42-gov5 `4533358fc28db215a12b78577968037ee4fec33d`。

| 参考实现 | 本目录实现与边界 |
| --- | --- |
| n42-26 contracts/decision | EIP-712 报价、结果签名、模板阈值、消费、到期退款与人工复核；保持原有链上 ABI |
| n42-26 bin/n42-decision-relay | quote/evaluate/submit/watch、请求绑定、原始证据首次写入、游标恢复；最终性读取适配到本仓库 EL |
| n42-26 sdk/decision-ts、examples/decision-dapp | 公开提案原始 UTF-8 字节、Keccak、钱包提交与查询 |
| n42-26 scripts/decision_* | 只读采样、标注合并、规则基线、可选本地 GLiClass 和 Jev、网关与评估工具 |
| gov5 inference/service.go、cache.go | 参考请求状态迁移、结果缓存 TTL 和输出副本隔离；本目录不宣称实现完整 opML 服务 |
| gov5 inference/executor_scheduler.go、scheduler/scheduler.go | WASM 确定性、租约小于截止时间、quorum/optimistic 验证与单次终态结算；属于后续分布式计算移植范围 |
| gov5 worker/protocol.go、messaging/identity/did.go | 请求与 worker 绑定签名、DID 地址身份；没有接入本目录的单运营方 relay |
| gov5 vm/contracts_ai_inference.go | 节点本地注册表及执行进度不属于共识状态，源码明确禁止在未完成共识结算前启用多验证者推理预编译；本次不启用该预编译 |

## 审计修补

relay 通过 `eth_getBlockByNumber("finalized", false)` 取得结算起点，再核对交易所在区块的祖先关系。本仓库 H2 的 legacy 模式将 finalized 指向 committed；split 模式将其指向已认证且已持久化的区块，见 crates/n42/h2-node/examples/h2_validator.rs 的结算标签配置。缺失或无效最终性、RPC 失败、区块哈希不匹配、零 parent、自环和超出 4096 步都失败；不回退到 latest 或 safe。信任来源仍为运营方完整节点，未提供独立 QC 证明。

运维网关将 provider 输入限制为 id、source、observed_at_ms 和脱敏 text，隔离本地与云 provider 对输入的修改。异常返回类型、非法标签、布尔概率、非有限或越界概率统一转为 UNKNOWN 并升级人工分析；严重规则的升级要求保留。新增测试覆盖异常输入、附加字段泄漏、输入修改隔离、最终性失败与有界祖先查询。SDK 补充严格 uint64/uint256 校验，拒绝 NaN、无穷值、布尔值、不安全整数、零提案 key 和零地址；校验最长一天的截止时间。

合约补充错误模型、答案篡改、重复履约、非 consumer 消费、Router 任意调用者分流、重复分流、强制人工审核及 reviewer 权限测试。保留暂停、撤销 signer、退款和证据首次写入的原有回归用例。

## 验收状态

当前环境已通过 Rust 20 个单元和传输注入测试、Clippy（全部目标，-D warnings）、Python 24 个单元测试及 SDK 6 个测试。TCP mock 测试曾因沙箱禁止 bind 而失败，随后改为测试生产逻辑使用的可注入 RPC 传输；尚未完成真实 HTTP 和测试网集成验收。

Foundry 未安装，Solidity 测试尚未执行。源码审查和本地测试不能替代合约执行或外部安全审计；当前不能标记升级验收通过。没有启用云调用或使用实际密钥。

变更按链上合约、SDK、relay 与最终性适配、运维工具与审计回归、文档与示例分段提交。根 Cargo.toml 的 ddn 排除项随 relay 段提交。Solidity 和真实 HTTP、测试网验收仍待完成。
