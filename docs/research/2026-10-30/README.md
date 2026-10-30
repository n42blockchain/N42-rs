# N42 公链研究追赶实验（2026-10-30）

基线 `d2e05062b0`。本目录是隔离研究代码，不接生产共识、交易池或 opcode。用户已选择 N42-rs；n42-26 未修改。工作树中原有/大小写冲突的 fleet 结果文件不纳入提交。

## 实施与结果

1. **PQ registry / signer 状态机**：`testing/research_20261030/pq_registry.py`。10,000 模拟 validator，8 项/实验区块；注入 verifier；登记包含网络、角色、算法版本、owner、previous epoch，轮换间隔 256 epoch。验证原子回滚、旧登记重放、跨域/错误权限、双 signer 和恢复。签名前独立 fence 先占用 leaf；签名字节缓存后重发，未完成的 reservation 必须烧掉。链数据库回滚不回退 signer。单独恢复 signer DB 时由保留的 fence 拒绝再次签名。
2. **32 逻辑节点 mempool**：100,000 交易，10,000 注入 nonce 冲突、200/1,000 wrapper 过期、5,000 恶意 dependency；三种策略接纳集合一致（69,494）。依赖证明工作量 independent=2,223,808，hash_partition=69,494，proof_reuse=63,025。哈希分区减少重复计算，但小 wrapper 仍有较高传输开销；数值只说明给定模型参数下的行为。
3. **KZG**：固定 `markolazic01/blober@a8a647d83366f1bb7d2ea683236c01fc7b53b374`。未修改的 59 项参考测试通过；自有 sweep 修改仅扩展 n=1…100 并新增实际 ABI calldata 长度记录，4 项测试通过。三种 gas 曲线、calldata CSV、工具版本和可复现 patch 见 `kzg/`。
4. **CALLSTATUS**：按 Draft 58 个场景编号建立模型清单。两个 frame evaluator、8 线程执行和丢弃 speculative result 后重放一致。父 frame 自身异常的场景只记录无可读结果；没有实现 EVM bytecode/gas adapter。不能把 58 个模型条目称为 58 个真实 N42 EVM 测试。

Python 全套 10 项测试通过，其中包含 10,000 次变更消息的重复 leaf 尝试，全部拒绝。`chain-tests.log.gz` 为证据。KZG 是 Foundry 参考 EVM，不是 N42 节点 CPU/部署验收。所有外部命令与测试都使用本地合成数据，没有接触生产密钥或广播资金交易。

## 关键边界

- registry 不使用 SSZ/BLS/leanXMSS；测试签名明确带 `NOT-A-PQ-SIGNATURE` 标记且可伪造，只用于状态机。不可将此 verifier 接入生产。fence 必须由独立不可回滚存储/HSM 提供；同时恢复 signer 和 fence 或两个完全独立 fence 无法保证防重用。当前 SQLite fence 只模拟该可信边界。
- 当前 EIP-8450 与周报快照不同：builder 无 VRF，恢复锚点论证已重新出现。登记不代表切换就绪。生产冻结/纠正权限必须经协议治理决定，不能直接用当前 BLS signer 自行解冻。
- mempool CPU 字段是 Python 模拟器 CPU，p95 是模型接纳延迟，不是入块延迟。没有 STARK 电路或真实 peer。Mode 1 未设置 circuit cap 时关闭；2 MiB 是独立传输限制。per-tx fixture 模拟已验证 dependency，不等同于验证一个含恶意 dependency 的递归证明。peer scoring 缺少归因而关闭，因此零误罚不是生产 scoring 验收。缓存绑定电路版本，但网络丢包、离线 owner、动态拓扑和缓存 TTL 尚待真实 adapter。
- KZG 参数检查仅确认参考代码声明 Ethereum mainnet setup；N42 完整参数同一性、原生 CPU、错误批次定位成本保留 null。不得从微基准推出 DA 吞吐结论。本机已有 N42 release binary 时间早于当前源基线，未拿它冒充本次源码构建。
- CALLSTATUS 不修改 N42 opcode 集；真实串行/Block-STM/state-gas 差分仍是单独验收门槛。

## 复现

```sh
python3 -m unittest discover -s testing/research_20261030
python3 testing/research_20261030/mempool_sim.py --output /tmp/n42-mempool-model.json
python3 testing/research_20261030/run_kzg_reference.py --forge "$HOME/.foundry/bin/forge" --output /tmp/n42-kzg
```

Python 3.9+（实测 Homebrew Python 3.14）。KZG runner 使用独立临时 clone、固定 commit 和 submodule，需网络和 Foundry；不部署合约。库存见 `cryptographic-inventory.json`。本轮没有 Rust 生产代码变更，因此不宣称 workspace cargo suite 已跑。

## 后续计划和决策门槛

| 项目 | 下一步 | 必须有的证据 |
| --- | --- | --- |
| P0 密钥控制 | owner、当前 signer、独立恢复人的权限决策；不可回滚签名服务 | 审阅后的威胁模型、真实算法恢复/双机/断电测试 |
| P0 算法选择 | ML-DSA / SLH-DSA / 实验 Falcon 单独比较 | 实测签名尺寸、批验、移动资源；FN-DSA 未完成标准不可冒称 FIPS 206 合规 |
| P0 聚合成本 | 接真实电路与 p2p adapter | proof/tx、CPU、缓存上限、流量、p95 入块、误罚率 |
| P1 KZG | N42 当前源码构建和 trusted setup 指纹 | n=1…100 gas/CPU/字节与错误定位 |
| P2 CALLSTATUS | 等草案稳定后实现测试专用执行适配器 | 原始 58 场景及嵌套/重执行逐位一致，不先改变生产 opcode |

原始资料：[EIP-8450](https://eips.ethereum.org/EIPS/eip-8450)、[EIP-8288](https://eips.ethereum.org/EIPS/eip-8288)、[NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final)、[KZG PR](https://github.com/ethereum/EIPs/pull/12589)、[CALLSTATUS PR](https://github.com/ethereum/EIPs/pull/12586)。正式标准、草案和实验验收分开记录。
