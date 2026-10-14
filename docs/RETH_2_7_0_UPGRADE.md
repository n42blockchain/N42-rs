# Reth v2.7.0 chain94 兼容分支验收

分支：`upgrade/reth-v2.7.0-chain94-20261012`。记录日期：2026-10-13。

本分支保留自定义链 ETH ECDSA、Gov5 H2、QMDB bin 根及既有 header/Prague/EOF 兼容。
使用与 main 相同的 revm-inspectors 0.44.1 prestate 修复，保持原 Geth 快照工件。
专项快照 E2E（含 unchanged-beneficiary diff 检查）通过；完整 workspace
`cargo test --release --offline --locked --workspace -- --test-threads=4`
112 个结果组，1941 通过、0 失败、35 声明忽略。主线性能路线额外测试不混入此计数。
工件在 n42-26 `.artifacts/reth-stable-completion-20261012/build-service/095.log`。
该任务随后因重建驱动未指定 `n42-h2-node` package 而退出 101；失败记录保留，
它不代表前面已完成的 workspace 测试失败。重建应分别执行：

```sh
cargo build --release --offline --locked -p n42 --bin n42 --bin n42-init-snapshot
cargo build --release --offline --locked -p n42-h2-node --example h2_validator
```

实际依赖修复差异与来源见 `vendor/dependency-repairs/revm-inspectors-0.44.1/N42-PATCH.diff`
及 `N42-PROVENANCE.md`。完整运行验收以最终重建二进制 SHA256 和混合七节点 summary 为准。

Validator 是既有 example target；099 的错误 bin selector 记录保留，最终重建使用与先前已通过的恢复构建相同的 example 命令。


## 混合生产节奏补全（待最终回归）

首次修复后的混合90秒窗口完成43块/167成功交易/0失败且七执行头一致，但仅六个
生产者覆盖，故 FAIL 保留。兼容节点的墙钟父时间限制让过了自己的 leader view。
借用 main 已有 head_stamp 与父时间+period规则，receipt-based pacing 维持不变，
genesis fallback 和时间溢出另验。无 Ed25519/帧协议或 quorum 改动。
新增1个父时间恢复与4个节奏用例，语法/差异检查完成后分段推送。
最终 full workspace 与运行回归尚待共享机器；上文1941数值只对应前一版二进制。


## 2026-10-14 独占窗口最终结果

- 112 父时间恢复单元测试：10 通过，退出 0。
- 113 完整兼容 workspace：112 结果组，1942 通过 / 0 失败 / 35 声明忽略；另有 validator example 时间测试 4 通过。三个程序重建成功，任务退出 0。
- 114 混合短测 PASS：90.000751 秒，13654771→13654813，42 块 / 153 成功交易 / 0 失败，七生产者全部覆盖。
- 115 混合一小时 PASS：3600.000589 秒，13654824→13656623，1799 块 / 7184 成功交易 / 0 失败，七生产者全部覆盖；七节点 canonical hash、QMDB bin 根、收据及固定七密钥 QC 持续一致。
- 116 恢复 FAIL：健康前置通过，停止 RS 节点后六节点 60 秒从 13656666→13656693 继续提交；重启 RS 后 all-seven catch-up 在 300 秒内未完成。首次拉取 13656668 时 EL 返回 -32603，随后缺少 body 的重复处理；原因尚未闭环，不能宣称混合恢复验收完成。后续两节点掉线、四在线无 quorum、恢复 quorum 和整队重启阶段未执行。

上述 1–4 已实际执行，结果为前三项通过、第四项失败。原失败工件保留，不能用三个工程独立恢复 PASS 替代混合恢复结果。二进制哈希及各窗口原始摘要见 n42-26 的 `docs/chain94-mixed-acceptance-20261014.json`。注入为正确性负载，不代表极限 TPS。
