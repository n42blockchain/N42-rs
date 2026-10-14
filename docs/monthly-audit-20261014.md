# 近一个月代码审计修复（2026-10-14）

统一报告：[三工程审计清单与证据](https://github.com/n42blockchain/n42-26/blob/main/docs/monthly-code-audit-20261014.md)。区间：2026-09-14 至 2026-10-14；主线冻结起点 `abe8891c6e76b77729c5e9522cf25503ad0c88e9`。

主线小提交已验证并推送：

- `8920ef505`：执行缓存后台销毁队列容量 2；满/断连时锁外销毁。
- `8c11a94dd`：QMDB 退休批次队列容量 2；满/断连时 forest 锁外销毁。
- `f84e7dae4`：复用执行结果时同时绑定 excess_blob_gas 和 blob_gas_used。
- `523759372`：flood 测试等待帧描述 inbox 完成，消除 1599/1600 的观察竞态。

主线 `cargo test --release --offline --locked --workspace`：3355 passed、0 failed、87 ignored（含上游/doc-test 汇总）；flood 回归另连续 20 次通过。
退休队列饱和时调用者会承担销毁耗时，因此本轮不能据此宣称 TPS 改善。

链 94 分支 `upgrade/reth-v2.7.0-chain94-20261012`：

- `31aa8ef39`：恢复槽缓存绑定实际执行环境、parent beacon root、withdrawal 余额输入及交易顺序；真实 TIMESTAMP 合约验证不同投机构建不互相覆盖。
- `fecb43bbd`：SSTORE/EOF 捕获仅在消费它的块执行器中开启，错误/unwind 自动清理，预热/raw EVM 不积累记录。
- 全量 workspace：1946 passed、0 failed、35 ignored。

该分支的内部缓存键修复不改变 H2、ETH ECDSA、区块或 QMDB bin 树格式。没有用本轮单元/集成回归替代历史冻结七节点运行证据，也没有为新二进制重新宣称一小时运行或 TPS 验收。
