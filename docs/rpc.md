# N42 JSON-RPC API Reference

N42 基于 reth v1.9.3 构建，支持所有标准以太坊 JSON-RPC 方法，并提供 N42 特有的共识扩展 API。

## 目录

- [标准 RPC 命名空间](#标准-rpc-命名空间)
- [N42 扩展 API](#n42-扩展-api)
- [使用示例](#使用示例)
- [连接方式](#连接方式)

---

## 标准 RPC 命名空间

N42 完全支持以下 reth/以太坊标准 RPC 命名空间：

| 命名空间 | 描述 | 默认启用 |
|---------|------|---------|
| `eth_` | 以太坊标准 API（交易、区块、状态查询等） | ✅ |
| `net_` | 网络信息（节点数、版本等） | ✅ |
| `web3_` | Web3 标准（客户端版本、SHA3 等） | ✅ |
| `admin_` | 节点管理（添加节点、数据目录等） | ❌ |
| `debug_` | 调试功能（追踪、状态转储等） | ❌ |
| `trace_` | 交易追踪（call trace、block trace 等） | ❌ |
| `txpool_` | 交易池状态（pending、queued 等） | ❌ |
| `rpc_` | RPC 元信息（已启用模块列表） | ✅ |
| `reth_` | Reth 特定功能 | ❌ |
| `ots_` | Otterscan 区块浏览器支持 | ❌ |
| `flashbots_` | Flashbots MEV 保护 | ❌ |
| `miner_` | 矿工/出块 API | ❌ |
| `mev_` | MEV 功能 | ❌ |

### 启用额外模块

```bash
# 启用特定模块
n42 node --http.api eth,net,web3,debug,trace

# 启用所有模块
n42 node --http.api all
```

---

## N42 扩展 API

N42 提供特有的 `consensusBeaconExt_` 命名空间，用于信标链共识交互。

### 区块查询

#### `consensusBeaconExt_get_beacon_block_by_number`

根据区块号获取信标区块。

**参数：**
- `block_id`: 区块号（十六进制）或 `"latest"`, `"safe"`, `"finalized"`

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_block_by_number",
    "params": ["0x11"],
    "id": 1
}
```

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_block_by_number",
    "params": ["latest"],
    "id": 1
}
```

#### `consensusBeaconExt_get_beacon_block_by_hash`

根据哈希获取信标区块。

**参数：**
- `hash`: 信标区块哈希（32 字节，0x 前缀）

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_block_by_hash",
    "params": ["0xd47417e1f170077bdc428101b437dac3673a6b39f6a94545302eb2acf90cae0a"],
    "id": 1
}
```

#### `consensusBeaconExt_get_beacon_block_hash_by_eth1_hash`

根据执行层区块哈希获取对应的信标区块哈希。

**参数：**
- `eth1_hash`: 执行层区块哈希（32 字节，0x 前缀）

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_block_hash_by_eth1_hash",
    "params": ["0x279d7bac0d42a0330f2d0017ad7f5bced07b0363805682a41b2cd1c7773916ad"],
    "id": 1
}
```

---

### 状态查询

#### `consensusBeaconExt_get_beacon_state_by_number`

根据区块号获取信标状态。

**参数：**
- `block_id`: 区块号（十六进制）或 `"latest"`, `"safe"`, `"finalized"`

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_state_by_number",
    "params": ["latest"],
    "id": 1
}
```

#### `consensusBeaconExt_get_beacon_state_by_beacon_block_hash`

根据信标区块哈希获取信标状态。

**参数：**
- `hash`: 信标区块哈希（32 字节，0x 前缀）

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_state_by_beacon_block_hash",
    "params": ["0xd47417e1f170077bdc428101b437dac3673a6b39f6a94545302eb2acf90cae0a"],
    "id": 1
}
```

---

### 验证者查询

#### `consensusBeaconExt_get_beacon_validator_by_pubkey`

根据 BLS 公钥查询验证者信息。

**参数：**
- `pubkey`: 验证者 BLS 公钥（48 字节，0x 前缀）

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_validator_by_pubkey",
    "params": ["0x96f841a5e6a8f2ff7015f599fcde19961e31c3b7d32c417d256f14c044d54406152d7db65a1dbbbb2142a87c0214e2e9"],
    "id": 1
}
```

**响应示例：**

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "activation_timestamp": 1760691561,
        "exit_timestamp": 0,
        "balance_in_beacon": 32000000000,
        "effective_balance": 32000000000,
        "inactivity_score": 0
    }
}
```

**字段说明：**
- `activation_timestamp`: 验证者激活时间戳（0 表示未激活）
- `exit_timestamp`: 验证者退出时间戳（0 表示未退出）
- `balance_in_beacon`: 信标链余额（单位：Gwei）
- `effective_balance`: 有效余额（单位：Gwei）
- `inactivity_score`: 不活跃分数

#### `consensusBeaconExt_get_total_effective_balance`

获取所有活跃验证者的总有效余额。

**参数：** 无

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_total_effective_balance",
    "params": [],
    "id": 1
}
```

---

### 验证者订阅 (WebSocket)

#### `consensusBeaconExt_subscribeToVerificationRequest`

订阅区块验证请求（用于验证者客户端）。

**参数：**
- `pubkey`: 验证者 BLS 公钥（十六进制字符串）

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_subscribeToVerificationRequest",
    "params": ["96f841a5e6a8f2ff7015f599fcde19961e31c3b7d32c417d256f14c044d54406152d7db65a1dbbbb2142a87c0214e2e9"],
    "id": 1
}
```

#### `consensusBeaconExt_submitVerification`

提交验证结果（用于验证者客户端）。

**参数：**
- `pubkey`: 验证者 BLS 公钥
- `signature`: BLS 签名
- `attestation_data`: 证明数据
- `block_hash`: 区块哈希

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_submitVerification",
    "params": [
        "96f841a5e6a8f2ff7015f599fcde19961e31c3b7d32c417d256f14c044d54406152d7db65a1dbbbb2142a87c0214e2e9",
        "signature_hex",
        {"slot": 100, "committee_index": 0, "receipts_root": "0x..."},
        "0xblock_hash"
    ],
    "id": 1
}
```

---

## 使用示例

### cURL

```bash
# HTTP JSON-RPC
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# 获取最新区块
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}'

# 获取信标状态
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"consensusBeaconExt_get_beacon_state_by_number","params":["latest"],"id":1}'
```

### JavaScript (ethers.js)

```javascript
import { JsonRpcProvider } from 'ethers';

const provider = new JsonRpcProvider('http://localhost:8545');

// 标准以太坊调用
const blockNumber = await provider.getBlockNumber();
const block = await provider.getBlock('latest');

// N42 扩展调用
const beaconState = await provider.send('consensusBeaconExt_get_beacon_state_by_number', ['latest']);
const validator = await provider.send('consensusBeaconExt_get_beacon_validator_by_pubkey', ['0x96f841...']);
```

### Rust (jsonrpsee)

```rust
use jsonrpsee::ws_client::WsClientBuilder;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let client = WsClientBuilder::default()
        .build("ws://localhost:8545")
        .await?;

    // 获取信标状态
    let state: serde_json::Value = client
        .request("consensusBeaconExt_get_beacon_state_by_number", rpc_params!["latest"])
        .await?;

    println!("{:?}", state);
    Ok(())
}
```

---

## 连接方式

### HTTP

默认端口：`8545`

```bash
n42 node --http --http.addr 0.0.0.0 --http.port 8545
```

### WebSocket

默认端口：`8546`

```bash
n42 node --ws --ws.addr 0.0.0.0 --ws.port 8546
```

### IPC

默认路径：`$DATADIR/reth.ipc`

```bash
n42 node --ipc
```

### 认证端点 (Engine API)

默认端口：`8551`（需要 JWT 认证）

```bash
n42 node --authrpc.addr 0.0.0.0 --authrpc.port 8551 --authrpc.jwtsecret /path/to/jwt.hex
```

---

## 错误码

| 错误码 | 描述 |
|-------|------|
| -32700 | 解析错误 |
| -32600 | 无效请求 |
| -32601 | 方法不存在 |
| -32602 | 无效参数 |
| -32603 | 内部错误 |
| -32000 | 服务器错误（通用） |
| -32001 | 资源不存在 |
| -32002 | 资源不可用 |
| -32003 | 交易被拒绝 |
| -32004 | 方法不支持 |
| -32005 | 请求超限 |

---

## 相关链接

- [以太坊 JSON-RPC 规范](https://ethereum.github.io/execution-apis/api-documentation/)
- [reth 文档](https://reth.rs/)
- [N42 GitHub](https://github.com/your-org/N42-rs)
