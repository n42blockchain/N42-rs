# N42 × TypeSafe Jev 测试网 M1

依赖版本、上游来源和本次验证结果见 [2026-10-05 升级记录](dependency-upgrade-20261005.md)。


本功能把公开提案交给 Jev 分类，再由 N42 合约记录结果并选择审核队列。AI 输出是运营网关的签名声明，不是链上重算或模型正确性的密码学证明。资金提案的分类只决定审核队列，不批准支出。

## 组成与状态

- `DecisionHub.sol` 注册固定模板、验证 EIP-712 报价和结果签名、托管费用，管理 Pending → Ready/Review/Expired → Consumed。过期费用由原付款人 `refundTo` 主动提取。
- `ProposalRouter.sol` 绑定公开提案唯一键、输入 hash 和 requestId。Ready 结果由任意 keeper 触发 `route`；Review 由固定 reviewer 人工分类。
- `n42-decision-relay` 提供 `quote`、`evaluate`、`submit` 和 `watch` 命令。`watch` 从已提交高度扫描事件并顺序处理，持久化游标。`evaluate` 检查收据所属块是 N42 最新已提交块的祖先，核对事件中的准确输入字节，调用 Jev，归档首份有效响应并输出签名结果。`submit` 签署并广播结果交易，等待最终提交。
- `sdk/decision-ts` 提供输入编码、Keccak hash、报价约束和钱包 ABI；`examples/decision-dapp` 是公开提案页面。

该测试网版本的 `watch` 可持续处理 Router 事件；报价发放和账户配额仍由应用/运营方接入。网关仅接受 Router 的公开提案格式，暂不支持私密材料。运营方自己的完整节点是最终性信息的信任来源。

## 部署

需要 Rust、Node 和 Foundry。在仓库的 `ddn/` 目录编译并运行合约测试：

```sh
forge build
forge test --match-path 'contracts/decision/test/*'
nice -n 19 cargo test --locked -j 1 -p n42-decision-relay
npm test --prefix sdk/decision-ts
```

部署 `DecisionHub` 时传入 `N42_DECISION_SIGNING_KEY` 对应的地址。用 `registerTemplate` 注册首个模板，`documentHash` 是审核后固定的 `examples/decision-dapp/template.json` 原始字节的 Keccak-256，`modelHash` 是 UTF-8 字符串 `jev-1.13.0` 的 Keccak-256；数组依次为：

```text
kinds               [1, 3]
sizes               [4, 0]
minProbabilityPpm   [900000, 800000]
minConfidencePpm    [700000, 0]
reviewOption        [3, 255]
```

部署 `ProposalRouter(hub, templateId, reviewer)`。合约 owner、报价/结果签名密钥和交易 gas 密钥应分开。`N42_TX_SIGNING_KEY` 对应账户要有测试网原生币。不要把任何密钥或 TypeSafe API key 放进页面。

## 使用流程

1. 用本地静态文件服务打开 `examples/decision-dapp/index.html`。页面生成规范 JSON 字符串和 `inputHash`；提案正文会出现在公开事件中。页面依赖 EIP-1193 钱包及浏览器加载的 viem ESM 包。
2. 运营方确认模板、账户配额和报价后，准备 `quote.json`：字段为 `chainId`、`hub`、`requester`（Router）、`consumer`（Router）、`refundTo`（用户钱包）、`templateId`、`inputHash`、`deadline`、`signerVersion`、`fee`（十进制字符串）、`quoteExpiry`。运行 `N42_DECISION_SIGNING_KEY=... cargo run -p n42-decision-relay -- quote quote.json`，将输出的完整 `quote` 和 `signature` 给页面。报价签名只用于请求，不用于提交交易。
3. 用户在页面确认费用并提交，页面展示 `requestId`。运营方建立 `job.json`，包含下方字段，运行 `TYPESAFE_API_KEY=... N42_DECISION_SIGNING_KEY=... cargo run -p n42-decision-relay -- evaluate job.json ./archive > result.json`。`TYPESAFE_API_URL` 默认官方 `https://api.typesafe.ai/v1/systemone`；仅测试时可设为本机 loopback mock 服务。
4. 运行 `N42_TX_SIGNING_KEY=... cargo run -p n42-decision-relay -- submit job.json result.json`。结果交易确认后，页面可查询状态，Ready 可点击分流。Review 需 reviewer 调用 `resolveReview`。如果到期，任何人调用 Hub `expire(requestId)`，原付款人调用 `withdrawRefund()`。

持续处理可配置 `watch.json` 并运行 `N42_DECISION_SIGNING_KEY=... N42_TX_SIGNING_KEY=... TYPESAFE_API_KEY=... cargo run -p n42-decision-relay -- watch watch.json`。设置 `startBlock` 为 Router 部署所在块，避免从创世块逐块扫描。游标记录下一个待处理区块；每个区块内任务完成后才前进，故重启时复用响应归档，已结算的请求自动跳过。任务失败时进程退出，由服务管理器重启；检查错误并修复 API、RPC、gas 或模板配置后再继续。示例：

```json
{
  "chainId": 94,
  "hub": "0x1111111111111111111111111111111111111111",
  "router": "0x2222222222222222222222222222222222222222",
  "rpcUrl": "http://127.0.0.1:8545",
  "templateId": 1,
  "templatePath": "examples/decision-dapp/template.json",
  "template": {"model": "jev-1.13.0", "questions": [{"type": "choice", "options": ["technical", "community", "funding", "needs_more_information"]}, {"type": "noul"}]},
  "signerVersion": 1,
  "startBlock": 100,
  "archiveDir": "./decision-archive",
  "cursorPath": "./decision-archive/cursor"
}
```

`job.json` 的关键结构：

```json
{
  "chainId": 94,
  "hub": "0x1111111111111111111111111111111111111111",
  "templateId": 1,
  "templatePath": "examples/decision-dapp/template.json",
  "router": "0x2222222222222222222222222222222222222222",
  "rpcUrl": "http://127.0.0.1:8545",
  "requestTxHash": "0x3333333333333333333333333333333333333333333333333333333333333333",
  "requestId": "1",
  "signerVersion": 1,
  "inputHash": "0xdbc9509175d68eb73e5ca525c222f4c8b48c154c124bc1eeaaa744a486a486e9",
  "template": {
    "model": "jev-1.13.0",
    "questions": [
      {"type": "choice", "options": ["technical", "community", "funding", "needs_more_information"]},
      {"type": "noul"}
    ]
  },
  "evaluation": {
    "model": "jev-1.13.0",
    "state": "{\"title\":\"公开提案\",\"body\":\"材料\",\"proposalKey\":\"0x3333333333333333333333333333333333333333333333333333333333333333\"}",
    "questions": {"q0": {"type": "choice", "instructions": "Classify this public proposal by the queue that should review it first. Choose needs_more_information if the proposal lacks enough detail to route.", "criteria": {"technical": "Protocol, software, security, or infrastructure work", "community": "Community programs, education, or events", "funding": "Treasury funding or budget requests; classification is not approval", "needs_more_information": "Insufficient information to choose a review queue"}}, "q1": {"type": "noul", "instructions": "Does this proposal contain enough concrete information for the assigned review queue to begin reviewing it?"}}
  }
}
```

这是字段示例；实际 `state` 和 `inputHash` 必须从页面同一次生成取得，`requestTxHash` 必须是该次提交交易。网关会核对链上 `documentHash` 与模板文件原始字节、问题内容及候选顺序。`evaluate` 会检查响应版本、所有问题、概率范围、量化后分布和证据归档；重启后复用首次存档响应。不得按结果好坏反复请求。

## 运行边界

首期没有账户限流、API 成本统计、私密输入或独立 Jev 推理证明；`watch` 为单进程顺序队列，未实现多实例租约。`eth_getBlockByNumber("finalized", false)` 的最终性标签与祖先核对依赖运营方完整节点，未提供独立轻客户端证明。没有真实 TypeSafe key、可用测试网和 Solidity 编译器时，无法完成线上 Jev 调用、合约部署或跨合约交易验证；上线前必须补跑上述合约测试和一条完整的测试网流程。
