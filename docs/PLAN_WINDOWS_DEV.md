# Windows 作为主开发平台(2026-10-28 起)

Linux bench 主机硬件故障(电源模块,`docs/MATURITY_HARDENING_2026_10.md` 8.3),在它修好或换机之前,
开发转到 Windows 工作站。本文件是三条线(`audit/5m-full-2026-10`、`e7/independent-execution`、
`eth/reth-deep-opt`)共用的基础设施计划;实现放在短期分支 `chore/windows-dev`,合入 main 后由三条线各自合入。

## 1. 工作站

| 项 | 值 |
|---|---|
| CPU | AMD Ryzen 9 9950X,16 核 32 线程(bench 主机为 128 个物理核) |
| 内存 | 126 GB |
| 磁盘 | D: 剩余约 1.6 TB(14 TB);E: 剩余约 0.6 TB;C: 剩余约 69 GB |
| 工具链 | rustc/cargo 1.97.0,`stable-x86_64-pc-windows-msvc`;LLVM clang;Git Bash;**WSL 未安装** |

## 2. 现状:哪些能做,哪些不能

| 事项 | Windows 原生 | 说明 |
|---|---|---|
| `cargo check --workspace` | **不通过,且无法在本仓库内修好** | 第一道障碍是 `tikv-jemalloc-sys` 不支持 MSVC;绕过它之后,**上游 reth v2.8.1 的 `reth-provider` 本身不能在 Windows 编译**:它无条件使用 `reth_static_file_types::ChangesetOffsetReader/Writer`,而上游把这两个类型限定在 `cfg(all(feature = "std", unix))`。补 Windows 实现需要再 vendor reth crate,与"不扩大 fork"的原则相悖 |
| 16 个 N42 crate(连同测试) | **可以**(2026-10-28 实测 `cargo check --tests` 通过) | `n42-bmt-core`、`n42-twig-core`、`n42-qmdb-state`、`n42-h2-primitives`、`n42-h2-wire`、`n42-h2-consensus`、`n42-h2-net`、`n42-h2-execution`、`n42-h2-el-rpc`、`n42-tx-types`、`n42-tx-queue`、`n42-mobile-verify`、`n42-legacy-codec`、`n42-env`、`n42-core-layout`、`n42-primitives` |
| 依赖 `reth-provider` 的 7 个 crate | **不能** | `n42`(节点本身)、`n42-qmdb-reth`、`n42-h2-node`、`n42-engine-types`、`n42-tx-ingest`、`n42-clique`、`n42-testing`(CI 跑的测试) |
| 不涉及 mmap 的单元测试 | 可以 | 已验证 twig-core、qmdb-state、legacy-codec 的大部分 |
| entry file 相关测试 | 8 个失败 | Windows 不允许截断仍被映射的文件(os error 1224),也不允许按当前共享模式再次打开(os error 5) |
| fleet 脚本(bash + `taskset` + `/proc` + THP) | 不能 | Linux 专用 |
| 5M/E=7 规模的性能测量 | 不能 | 核数差 8 倍;只能做同机 A/B 对和微基准 |
| 仓库检出 | 有一处冲突 | `scripts/fleet7-runs/results/` 下 `…X10i.txt` 与 `…X10I.txt` 只差大小写,Windows 上互相覆盖 |

## 3. 步骤

1. **W1 编译(结论:原生 Windows 只覆盖 16 个 crate)。** 曾尝试让 jemalloc 只在 unix 上启用,随后发现 `reth-provider` 在上游就不支持 Windows,改动不带来任何可编译的 crate,且会改变 Linux 上非 jemalloc 构建的 RocksDB 分配器,已撤回。**原生 Windows 用于上述 16 个 crate 的开发与单元测试;节点、qmdb-reth、h2-node、engine-types 等必须在 WSL2(W6)或 Linux 上编译测试。**
2. **W2 Linux 门禁改由 CI 承担。** GitHub Actions(`ubuntu-latest`)目前只跑 `n42-testing`;
   加一个 job 跑 twig-core、qmdb-state、qmdb-reth、h2-* 等被 Windows 平台限制挡住的测试,
   作为 bench 主机恢复前的 Linux 正确性门禁。
3. **W3 Windows 上的 mmap 测试。** Windows 只作开发平台、不作生产运行平台:
   受平台限制的测试加 `#[cfg_attr(windows, ignore = "…")]` 并注明原因,由 W2 的 Linux CI 覆盖;
   不为 Windows 改生产代码的截断与映射语义。
4. **W4 大小写冲突。** 把 `…X10I.txt` 改名(保留内容),消除检出冲突。
5. **W5 换行符。** 本机 `core.autocrlf=true`,导致 `scripts/reth-sync.py` 的三方合并整文件冲突。
   新建的 worktree 都用 `core.autocrlf=false`(LF);主检出目录改为同样设置并重新检出。
   跨客户端测试夹具已由 `.gitattributes` 保护(`-text`),不受影响。
6. **W6 WSL2(必需;需要管理员权限和重启,由用户执行)。** 由于 W1 的结论,WSL2 是在本机编译节点和跑 7 个 provider 相关 crate 的唯一途径。 `wsl --install` 装 Ubuntu 后,fleet 脚本、
   Linux 专用测试、`perf` 可以在本机跑小规模版本。性能数字与 bench 主机不可比,只作同机 A/B。
7. **W7 测量口径。** 本机上的任何吞吐数字都标注机器和规模,不与 bench 主机的记录并列;
   结论只来自同机、同配置、交替进行的 A/B 对。

## 4. 对三条线的影响

| 线 | 影响 |
|---|---|
| 审计 | 共识核心(A)和 h2-net/h2-execution 部分、帧的 tx-types/tx-queue 部分可在原生 Windows 修改并测试;QMDB 持久化(qmdb-reth)、h2-node、engine-types、ingest 需要 WSL2;Linux 验证由 W2 的 CI 承担;fleet 级验证(`roll --kill`、含 gov5 成员的 devnet)等 WSL2 或硬件 |
| E=7 | 七个独立执行层在 16 核上只能做功能性运行;规模测量等 Linux 硬件。当前先做不依赖硬件的部分:帧的跨主机分发设计、多主机脚本 |
| eth | 微基准与固定区块段的重执行可以在本机做;主网数据原在 bench 主机 `/data/blockchain`,需要在 D: 盘重新准备 |

## 5. 状态

| 项 | 状态 |
|---|---|
| W1 编译 | 完成:原生覆盖 16 个 crate,其余需 WSL2 |
| W2-W5 | 待开始 |
| W6 WSL2 | **阻塞项**,等用户安装 |
