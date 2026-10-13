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
