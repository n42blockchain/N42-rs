# V3 SDK 连接当前 Rust 节点的 iPhone 真机测试

日期：2026-11-03。最终 Release 包 `1.0.0+8` 的真机复验通过，11 项检查全部完成。

## 本轮版本与环境

- 节点：本仓库 `2b75d4062aa2e3612653a310e453a7a488c0543a`，本机编译的 debug `n42`、`h2_validator`、`h2_keygen`。
- 网络：四个 Rust 验证节点、一个 QMDB 执行层；独立数据目录。手机连接验证节点 1，区块包由 sidecar 写入验证节点 0 后经 gossip 转发。
- SDK：Go iOS SDK `537fed759c4d504ace2323119ed59190359f5d34`，已逐项核对 XCFramework 的 provenance 校验值。Rust 节点通过 HTTP 与该 SDK 通信；本仓库的旧 Rust mobile-sdk 不是这次手机运行的 V3 SDK。
- sidecar：`N42-gov5` 的 `feat/mobileverify-packetd`，`8fe815dc2`，本机编译。
- 手机：USB iPhone 13 Pro Max，iOS 27.0.1；独立签名验收应用 `mining.ai.n42.www.flutterMiningExample`，Release `1.0.0+8`。原主应用 `ai.n42.www` 及其数据保留。
- App 验收源码：`n42appv2` 的 `feat/mining-v3-ios`，修复提交 `156fabf3d`。提交钩子递增的主应用版本不代表另一个真机包；本轮明确指定验收包版本 `1.0.0+8`。
- 入口：`http://192.168.0.56:21103`，仅转发 `/mobileverify/` 的 GET/POST 到本机验证节点 1。RPC、Engine API 和区块包 PUT 留在 loopback。
- 测试链：chain ID 94、SDK `mainnet_qmdb` 的执行规则、开发验证者和预置测试资金。它是独立测试链，未连接生产网络。

[产物与源码校验值](mobileverify-v3-ios-20261103/artifact.json)。节点运行数据、JWT 和验证者密钥未加入报告。

## 真机结果

[完整公共结果](mobileverify-v3-ios-20261103/device-results.json) · [最终日志画面](mobileverify-v3-ios-20261103/final-log.png) · [节点与负载快照](mobileverify-v3-ios-20261103/fleet-summary.json) · [交易块证书核对](mobileverify-v3-ios-20261103/certificate-proof.json)

| 检查 | 本轮实际结果 |
| --- | --- |
| 桥接、错误参数、未知方法、密钥与会话身份 | 通过；私钥未输出或保存到证据 |
| 注册与单块重执行 | device index 1；区块 61，6 笔交易，34ms；即时证书为空，不冒充已有证书 |
| 原生 miner 验证并获得证书 | 通过 |
| 前台持续运行 | 300190ms，新增验证 99 块、证书 98 块，失败 0 |
| 打开系统设置再返回 | 会话与计数保留；墙钟 18993ms，有效时长增加 3858ms，排除后台 15135ms |
| 手动停止后再次切换前后台 | 保持停止，有效时长固定 326093ms |
| 最终状态 | `passed`，验证 108 块、证书 106 块、失败 0；11 项检查通过 |
| 独立核对证书 | 区块 137，5 笔交易；验证节点 1 的证书 root 与 RPC 区块头 receipts root 一致 |
| 节点快照 | 四个验证者各提交 182 块，view timeout 和 error 均为 0；执行层 error 0 |
| 交易负载快照 | 已发送 1032 笔，拒绝 0；sidecar 已生成 182 个包，其中 176 个交易块包、合计 1027 笔交易；采样时其余交易尚在处理 |

sidecar 唯一的 error 行是启动时 block 0 没有 parent state，符合该工具对 genesis 的处理；交易区块没有丢包错误。验收后已停止本轮启动的 miner、节点、sidecar、负载和 LAN 转发，保留独立验收应用及本地证据。原主应用版本仍为 `73082`。

## 发现的问题与修正

1. 原入口 `192.168.0.217:21100` 拒绝连接。本轮使用上述当前源码编译的本机测试网。
2. 初次沿用 `gov5-local-genesis.py --fork-time shanghai=+1 --fork-time cancun=+1`，手机却选择原 `mainnet_qmdb_staggered` preset。空块通过，加入转账后连续失败：[首次计数](mobileverify-v3-ios-20261103/baseline-transaction-failures.json)、[真机错误](mobileverify-v3-ios-20261103/wrong-config-device-results.json)。同一份 5 笔交易区块包在 SDK 中使用生产 preset 报 nonce 错误，使用节点的 genesis 配置通过：[重放对比](mobileverify-v3-ios-20261103/replay-comparison.txt)。原因是分叉规则不同，block-start 系统调用消耗的读日志位置不同。本轮改用节点与 SDK 一致的 `mainnet_qmdb` 规则；没有关闭签名或 receipts-root 校验。
3. 验收工具只要求验证数、证书数增长，可能漏掉随后交易块的失败。App 提交 `156fabf3d` 增加健康持续测试及生命周期结束时的零失败检查，记录节点、chain、UTC 开始时间、最后验证块与交易数、原生错误和日志。已补充两端分叉配置必须一致的说明。

本轮没有据此修改 Rust 共识或执行规则。配置不一致时 SDK 拒绝验证，不应把这种失败改成成功。

## 自动检查

- `cargo build -p n42-h2-node --example h2_validator --example h2_keygen -p n42 --bin n42`：通过。
- `cargo test -p n42-mobileverify`：55 个单元测试、14 个跨客户端 fixture 测试、9 个 HTTP 测试通过；[日志](mobileverify-v3-ios-20261103/rust-mobileverify-tests.txt)。
- App `flutter test --no-pub test/features/mining_v3`：43 项通过；插件 `flutter test --no-pub test/mobileverify_test.dart`：8 项通过。
- Go `go test ./cmd/mobileverifyios -count=1`、`go test ./cmd/evmsdk -run 'Mobile|Miner' -count=1`：通过。
- sidecar `go test ./internal/streamverify/packetd -count=1`：[通过](mobileverify-v3-ios-20261103/packetd-tests.txt)。
- 最终验收工具的 `flutter analyze --no-pub integration_test/mobileverify_ios_smoke_app.dart`：[无问题](mobileverify-v3-ios-20261103/smoke-analysis.txt)。

## 复现要点

使用 SDK `537fed759` 的 `params/chainspecs/mainnet_qmdb.json` 作为执行配置，保留 Rust genesis 的区块字段与分配；替换为开发验证者，并明确使用本地已验证的 two-phase vote gate。以下命令从本仓库根目录执行，参数分别为 SDK worktree 和输出文件：

```sh
python3 - "$SDK_WORKTREE" "$TEST_DIR/genesis-qmdb.json" <<'PY'
import json, pathlib, sys
g = json.load(open('crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json'))
dev = json.load(open('crates/chainspec/res/genesis/n42_devnet.json'))
consensus = g['config']['hotstuff']
consensus['validators'] = dev['config']['hotstuff']['validators']
cfg = json.load(open(pathlib.Path(sys.argv[1]) / 'params/chainspecs/mainnet_qmdb.json'))
cfg['hotstuff'] = consensus
cfg.update(shanghaiTime=0, cancunTime=0, terminalTotalDifficulty=0,
           terminalTotalDifficultyPassed=True, mergeNetsplitBlock=0)
g['config'] = cfg
g['alloc']['f39fd6e51aad88f6f4ce6ab8827279cfffb92266'] = {'balance': '0x3635c9adc5dea00000'}
pathlib.Path(sys.argv[2]).write_text(json.dumps(g, indent=2) + '\n')
PY
```

使用独立 `N42_FLEET_DIR` 启动 `scripts/devnet-fleet.sh`，设置 `MOBILEVERIFY=1`、`DEVNET_GENESIS` 和 `PACKETD`。该脚本使用固定本机端口并会停止同一路径下的旧 fleet 进程，应先确认没有其他测试占用。

从 App 的 `plugins/flutter_mining/example` 构建：

```sh
flutter build ios --release --no-pub \
  --target integration_test/mobileverify_ios_smoke_app.dart \
  --dart-define=MINING_V3_IOS_SMOKE=true \
  --dart-define=MINING_V3_IOS_SOAK_SECONDS=300 \
  --dart-define=MINING_V3_URL=http://192.168.0.56:21103 \
  --dart-define=MINING_V3_CHAIN=mainnet_qmdb \
  --build-name=1.0.0 --build-number=8
```

安装到所选实体设备，运行独立验收应用并读取其公共结果。按 App 验收工具 README 驱动两次真实前后台切换；本轮通过打开系统设置并返回完成，没有把进程重启冒充恢复。负载使用公开开发账户向测试地址发送 EIP-1559 转账，约 2 tx/s。

## 验收边界

本轮不覆盖 Android、主应用完整业务流程、生产链同步、MobileAnchor/Glamsterdam 启用后的全部执行规则、多小时运行、锁屏、电话中断、脱离 USB 的耗电或温度测量。没有上传 TestFlight。
