# RPC Documentation

For complete JSON-RPC documentation, see the [JSON-RPC Reference](./jsonrpc/intro.md).

## Quick Start

Enable the HTTP JSON-RPC server:

```bash
n42 node --http --http.api "eth,net,web3,txpool,debug,trace,admin,rpc,reth,ots"
```

## Available Namespaces

| Namespace | Description |
|-----------|-------------|
| [`eth`](./jsonrpc/eth.md) | Ethereum protocol interaction |
| [`web3`](./jsonrpc/web3.md) | Web3 client utilities |
| [`net`](./jsonrpc/net.md) | Network information |
| [`txpool`](./jsonrpc/txpool.md) | Transaction pool inspection |
| [`debug`](./jsonrpc/debug.md) | Geth-style debugging/tracing |
| [`trace`](./jsonrpc/trace.md) | Parity-style tracing |
| [`admin`](./jsonrpc/admin.md) | Node administration |
| [`rpc`](./jsonrpc/rpc.md) | RPC server information |
| [`reth`](./jsonrpc/reth.md) | N42/reth-specific methods |
| [`ots`](./jsonrpc/otterscan.md) | Otterscan compatibility |
| [`miner`](./jsonrpc/miner.md) | Block production control |
| [`flashbots`](./jsonrpc/flashbots.md) | MEV bundle submission |
| [`consensusBeaconExt`](./jsonrpc/consensus_beacon_ext.md) | N42 consensus extensions |

## Beacon Debug Examples

### Get Block by Number

```json
{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["latest", false],
    "id": 1
}
```

### Get Beacon Block Hash by ETH1 Hash

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_block_hash_by_eth1_hash",
    "params": ["0x279d7bac0d42a0330f2d0017ad7f5bced07b0363805682a41b2cd1c7773916ad"],
    "id": 1
}
```

### Get Beacon Validator by Public Key

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_validator_by_pubkey",
    "params": ["0x96f841a5e6a8f2ff7015f599fcde19961e31c3b7d32c417d256f14c044d54406152d7db65a1dbbbb2142a87c0214e2e9"],
    "id": 1
}
```

**Response:**

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

### Get Total Effective Balance

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_total_effective_balance",
    "params": [],
    "id": 1
}
```
