# 依赖维护提示修复：2026-10-06

分支：`feat/native-fleet7`。起点：`ee802849da6fe888a8cf3da8008d6e6436f3af2d`。开始时工作区干净，本次未修改线上服务或合并默认分支。

## 扫描结果

原有 7 条停维护提示和 1 条 lru 健全性警告均已关闭。最终 `cargo audit --json` 退出码为 0：**0 条漏洞、0 条停维护提示、0 条健全性警告**。没有添加忽略规则、排除包或缩小扫描范围。日志：`/tmp/n42-maintained-dependencies-audit-final2.json`。

| 原包 / 提示 | 修复路径 |
| --- | --- |
| atomic-polyfill 1.0.3 / RUSTSEC-2023-0089 | test-fuzz 升级至 8.1.1；其内部 postcard 保留 `use-std`，关闭不需要的默认 heapless-cas，移除 heapless 0.7 和 atomic-polyfill |
| bincode 1.3.3 / RUSTSEC-2025-0141 | 自有库和 NippyJar 使用小型 `n42-legacy-codec` 适配层，底层为 [bincode_reloaded 3.1.24](https://github.com/butlergroup/bincode_reloaded)，使用 legacy 固定宽度、小端配置 |
| derivative 2.2.0 / RUSTSEC-2024-0388 | 自有 primitives 与旧版 ark-ff 改用 [Educe 0.8.1](https://github.com/magiclen/educe)，保留字段忽略、自定义比较和空泛型边界 |
| fxhash 0.2.1 / RUSTSEC-2025-0057 | sled 的内存 HashMap 使用 rustc-hash 1.1.0，保留 64 位主机的旧 Fx 算法；没有改写 sled 磁盘格式 |
| instant 0.1.13 / RUSTSEC-2024-0384 | sled 的旧 parking_lot 路径使用 web-time 1.1.0 的 Instant |
| paste 1.0.15 / RUSTSEC-2024-0436 | 消费者使用 [pastey 0.2.3](https://github.com/as1100k/pastey)，包含锁文件中可选的 Linux、profiling 和编译器链路 |
| proc-macro-error2 2.0.1 / RUSTSEC-2026-0173 | Aquamarine 改用 [proc-macro-error3 3.0.1](https://github.com/gamma0987/proc-macro-error3)；该版本满足 Alloy 宏的版本上限，源代码导入也同步修改 |
| lru 0.16.4 / RUSTSEC-2026-0253 | OP Alloy 0.23.1 → 2.0.0，移除旧 Alloy provider；锁文件仅保留 lru 0.18.5 |

以上 7 个旧包和 lru 0.16.4 均已从锁文件消失，不是对停维护包改名后继续使用原实现。

上游指定版本仍依赖停维护包，所以对 **20 个上游包、30 个文件**保留最小本地补丁。原版代码、许可证和可选功能均保留；[来源记录](../vendor/dependency-repairs/PROVENANCE.json)列出版本、来源和原 manifest SHA-256，[补丁差异](../vendor/dependency-repairs/PATCHES.diff)单独列出实际改动，[维护说明](../vendor/dependency-repairs/README.md)说明升级和移除补丁的条件。未来升级这些上游包时必须复核本地补丁，不能只更新锁文件。

## 数据兼容性

使用独立临时项目中的原版 crates.io bincode 1.3.3 生成 3 个文件样本：真实 QMDB checkpoint、ForestDelta、带 BLS 公钥的验证者变更列表。新实现须逐字节重新编码一致，后者也是共识哈希的输入。

六项编码测试验证旧样本读取、字节一致、连续记录边界、枚举与整数宽度、旧 free-function 允许尾随字节的行为，以及所有截断位置均拒绝。曾试用 bincode-next 3.1.1，但截断测试证明它会接受不完整的数组，已弃用；最终锁文件不包含这个候选依赖。

没有实施磁盘迁移。编码错误类型改为包装新 encoder/decoder 错误，不能再按旧 bincode::ErrorKind 变体匹配；仓库调用处均已编译验证。sled 测试验证 1024 条记录写入、flush、关闭和重开后的读取一致；未拿生产 sled 目录执行迁移。

## 最终验证

所有下面的进程均已结束，退出码为 0。共 **1031 项通过、0 失败、8 项按原配置忽略**。不重复计算编码适配层的单独重跑。

完整回归命令：

```sh
cargo test --locked -p n42-primitives -p n42-h2-consensus -p n42-h2-primitives -p n42-h2-wire -p n42-mobile-verify -p n42-qmdb-reth -p n42-qmdb-state -p n42-twig-core -p n42-dependency-compat-tests -p n42-legacy-codec -p n42-h2-net -p n42-h2-node -p mobile-sdk --lib --tests --examples
```

| 测试组 | 通过 / 忽略 |
| --- | --- |
| SDK / 示例 | 35 / 0 |
| H2 consensus | 262 / 0 |
| H2 net / node / 集成测试 / 示例 | 207 / 1 |
| H2 primitives / wire | 57 / 0 |
| mobile-verify | 62 / 0 |
| N42 primitives | 200 / 0 |
| QMDB reth / 集成测试 / 示例 | 58 / 4 |
| QMDB state / gov5 合约 | 34 / 1 |
| Twig core | 66 / 2 |
| 有限域与 sled 兼容性 | 2 / 0 |
| 旧编码兼容性 | 6 / 0 |
| NippyJar 存储测试（单独运行） | 8 / 0 |
| db-api / fuzz 生成与执行（单独运行） | 34 / 0 |

主回归日志：`/tmp/n42-maintained-dependencies-final-tests4.log`。包含四节点共识、大正文传输、移动证明、SSZ/JSON 回归、20,000 块 QMDB 日志轮转与重启，以及旧 ark-ff 0.3/0.4/0.5 feature 的编译验证。

补充命令：

- `cargo test -p reth-nippy-jar --lib`：`/tmp/n42-nippy-maintained-tests-final.log`。将该本地补丁列为 workspace member 后执行；锁文件随后已固定。
- `cargo test --locked -p reth-db-api --lib`：`/tmp/n42-fuzz-maintained-tests.log`。
- `cargo check --locked -p n42 --bin n42 --lib`：`/tmp/n42-maintained-main-check.log`。
- `cargo check --locked -p reth-rpc-types-compat --features op`：`/tmp/n42-maintained-op-check-final.log`。

示例编译发现 read_bench 无条件调用 Linux posix_fadvise，已加平台条件；没有成功执行缓存建议时，测量标为首次读取，不标为冷缓存。示例编译通过，但没有实际运行性能基准。

自有代码和新增补丁行的空白检查通过。上游导入代码的既有空白原样保留，全量差异空白检查因此仍报告上游空白；未对上游源码做格式重写。新的 Rust 文件单独使用 rustfmt。没有将编译警告称为零警告，也没有重跑本轮 Clippy 或全仓格式检查。

## 验证边界与提交

本次在 macOS 上验证。没有运行真实链上交易、线上集群、Linux/Windows/wasm 主机验证、profiling/JIT 的全部可选功能或生产数据库升级；本地补丁覆盖这些包的依赖声明，不代表其所有功能都已执行验证。

按密码学/ABI 宏、运行时/诊断宏、存储/fuzz 补丁、项目依赖适配、基准平台修复、报告拆为六组英文修复提交。首次两次推送被远端新增提交拒绝；获取后确认仅新增六个 fleet runner 脚本，以英文合并提交保留远端三次提交和本地改动，再继续推送。每次成功推送均核对远端提交号。新增脚本没有改变被验证的依赖或 Rust 代码，未执行这些脚本。没有合并至默认分支；GitHub 默认分支告警需等待合并后的扫描。
