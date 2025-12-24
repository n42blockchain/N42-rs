# `web3` Namespace

The `web3` API provides utility functions for the web3 client.

## `web3_clientVersion`

Returns the current client version.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "web3_clientVersion", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "N42/v1.0.0/x86_64-unknown-linux-gnu"
}
```

## `web3_sha3`

Returns Keccak-256 hash of the given data.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "web3_sha3", "params": [data]}` |

### Parameters

- `data`: Data to hash (hex-encoded)

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"web3_sha3","params":["0x68656c6c6f"],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
}
```

