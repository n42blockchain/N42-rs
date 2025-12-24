# `trace` Namespace

The `trace` API provides Parity-style tracing methods for inspecting Ethereum state and transaction execution.

For Geth-style traces, see the [`debug`](./debug.md) namespace.

## Transaction Tracing

### `trace_call`

Executes a call and returns traces.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_call", "params": [callObject, traceTypes, blockNumber]}` |

#### Parameters

- `callObject`: Transaction call object
- `traceTypes`: Array of trace types (`trace`, `vmTrace`, `stateDiff`)
- `blockNumber`: Block number or tag

#### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"trace_call","params":[{"to":"0x...","data":"0x..."}, ["trace"], "latest"],"id":1}' \
  http://localhost:8545
```

### `trace_callMany`

Executes multiple calls and returns traces.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_callMany", "params": [calls, blockNumber]}` |

### `trace_rawTransaction`

Traces a raw transaction.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_rawTransaction", "params": [rawTx, traceTypes]}` |

### `trace_replayTransaction`

Replays a transaction and returns traces.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_replayTransaction", "params": [txHash, traceTypes]}` |

## Block Tracing

### `trace_block`

Returns traces for all transactions in a block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_block", "params": [blockNumber]}` |

### `trace_replayBlockTransactions`

Replays all transactions in a block and returns traces.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_replayBlockTransactions", "params": [blockNumber, traceTypes]}` |

## Filtered Traces

### `trace_filter`

Returns traces matching filter criteria.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_filter", "params": [filterObject]}` |

#### Filter Object

```json
{
  "fromBlock": "0x1",
  "toBlock": "0x100",
  "fromAddress": ["0x..."],
  "toAddress": ["0x..."],
  "after": 0,
  "count": 100
}
```

### `trace_get`

Returns a specific trace by block number and index.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_get", "params": [txHash, indices]}` |

### `trace_transaction`

Returns all traces for a transaction.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "trace_transaction", "params": [txHash]}` |

## Trace Types

| Type | Description |
|------|-------------|
| `trace` | Returns call trace |
| `vmTrace` | Returns VM trace with all opcodes |
| `stateDiff` | Returns state changes |

## Example Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "trace": [
      {
        "action": {
          "from": "0x...",
          "to": "0x...",
          "value": "0x0",
          "gas": "0x...",
          "input": "0x...",
          "callType": "call"
        },
        "result": {
          "gasUsed": "0x...",
          "output": "0x..."
        },
        "subtraces": 0,
        "traceAddress": [],
        "type": "call"
      }
    ],
    "vmTrace": null,
    "stateDiff": null
  }
}
```

