# `reth` Namespace

The `reth` API provides N42/reth-specific methods that are not part of the standard Ethereum JSON-RPC specification.

## `reth_getClientVersion`

Returns the client version information.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "reth_getClientVersion", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"reth_getClientVersion","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "name": "N42",
    "version": "1.0.0",
    "commit": "abc1234",
    "arch": "x86_64-unknown-linux-gnu"
  }
}
```

## `reth_getBalanceChangesInBlock`

Returns all balance changes that occurred in a specific block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "reth_getBalanceChangesInBlock", "params": [blockNumber]}` |

### Parameters

- `blockNumber`: The block number (hex-encoded) or tag (`latest`, `earliest`, `pending`)

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"reth_getBalanceChangesInBlock","params":["0x100"],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "0x1234...": {
      "before": "0x1000",
      "after": "0x2000"
    },
    "0x5678...": {
      "before": "0x5000",
      "after": "0x4000"
    }
  }
}
```

## Notes

These methods are specific to N42's implementation based on reth and may not be available on other Ethereum clients.

