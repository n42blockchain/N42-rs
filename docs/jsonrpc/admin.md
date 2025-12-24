# `admin` Namespace

The `admin` API allows you to configure your node.

> **Warning**
>
> This namespace is sensitive. Methods in this namespace can be used to configure your node. It is recommended to not expose this namespace publicly.

## `admin_nodeInfo`

Returns information about the running node.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_nodeInfo", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "id": "...",
    "name": "N42/v1.0.0/...",
    "enode": "enode://...",
    "enr": "enr:...",
    "ip": "127.0.0.1",
    "ports": {
      "discovery": 30303,
      "listener": 30303
    },
    "listenAddr": "0.0.0.0:30303",
    "protocols": {
      "eth": {
        "network": 42,
        "difficulty": "0x...",
        "genesis": "0x...",
        "head": "0x..."
      }
    }
  }
}
```

## `admin_peers`

Returns information about connected peers.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_peers", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}' \
  http://localhost:8545
```

## `admin_addPeer`

Adds a peer to the node.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_addPeer", "params": [enode]}` |

### Parameters

- `enode`: The enode URL of the peer to add

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_addPeer","params":["enode://...@127.0.0.1:30303"],"id":1}' \
  http://localhost:8545
```

## `admin_removePeer`

Removes a peer from the node.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_removePeer", "params": [enode]}` |

### Parameters

- `enode`: The enode URL of the peer to remove

## `admin_addTrustedPeer`

Adds a trusted peer to the node. Trusted peers are always allowed to connect.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_addTrustedPeer", "params": [enode]}` |

## `admin_removeTrustedPeer`

Removes a trusted peer from the node.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_removeTrustedPeer", "params": [enode]}` |

## `admin_datadir`

Returns the data directory path.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_datadir", "params": []}` |

## `admin_startHTTP`

Starts the HTTP RPC server.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_startHTTP", "params": [host, port, cors, apis]}` |

## `admin_stopHTTP`

Stops the HTTP RPC server.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_stopHTTP", "params": []}` |

## `admin_startWS`

Starts the WebSocket RPC server.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_startWS", "params": [host, port, cors, apis]}` |

## `admin_stopWS`

Stops the WebSocket RPC server.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "admin_stopWS", "params": []}` |

