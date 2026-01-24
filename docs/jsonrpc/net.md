# `net` Namespace

The `net` API provides access to network information of the node.

## `net_version`

Returns the current network ID.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "net_version", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "42"
}
```

## `net_listening`

Returns `true` if the client is actively listening for network connections.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "net_listening", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"net_listening","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": true
}
```

## `net_peerCount`

Returns the number of peers currently connected to the client.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "net_peerCount", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x19"
}
```

