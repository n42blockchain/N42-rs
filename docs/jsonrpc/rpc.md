# `rpc` Namespace

The `rpc` API provides information about the RPC server and its modules.

## `rpc_modules`

Returns a list of available RPC modules and their versions.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "rpc_modules", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"rpc_modules","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "eth": "1.0",
    "net": "1.0",
    "web3": "1.0",
    "txpool": "1.0",
    "debug": "1.0",
    "trace": "1.0",
    "admin": "1.0",
    "rpc": "1.0",
    "reth": "1.0",
    "consensusBeaconExt": "1.0"
  }
}
```

## N42 Consensus

N42 uses a Proof of Authority (PoA) / Proof of Stake (PoS) hybrid consensus mechanism called APoS (Authority Proof of Stake).

### Key Features

- **Block Period**: Configurable block time (default: 8 seconds)
- **Epoch Length**: Configurable epoch for checkpoint and signer rotation
- **Signer Verification**: Blocks are signed by authorized validators
- **In-turn/Out-of-turn**: Validators take turns to propose blocks

### Consensus-related RPC

For consensus-specific operations, see the [`consensusBeaconExt`](./consensus_beacon_ext.md) namespace.

