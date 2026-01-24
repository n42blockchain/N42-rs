# `debug` Namespace

The `debug` API provides several methods to inspect the Ethereum state, including Geth-style traces.

For Parity-style traces, see the [`trace`](./trace.md) namespace.

## Transaction Tracing

### `debug_traceTransaction`

Traces a transaction by hash using the specified tracer.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_traceTransaction", "params": [txHash, options]}` |

#### Parameters

- `txHash`: The hash of the transaction to trace
- `options` (optional): Tracing options object:
  - `tracer`: Name of built-in tracer or custom JavaScript tracer
  - `tracerConfig`: Configuration for the tracer
  - `timeout`: Timeout for JavaScript tracers

#### Built-in Tracers

| Tracer | Description |
|--------|-------------|
| `callTracer` | Traces all calls made during transaction execution |
| `prestateTracer` | Returns the pre-state of all accessed accounts |
| `4byteTracer` | Collects function selectors used |
| `noopTracer` | No-op tracer for benchmarking |
| `opCountTracer` | Counts opcodes executed |
| `flatCallTracer` | Flat call tracer |

#### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x...", {"tracer": "callTracer"}],"id":1}' \
  http://localhost:8545
```

### `debug_traceCall`

Traces a call without creating a transaction.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_traceCall", "params": [callObject, blockNumber, options]}` |

#### Parameters

- `callObject`: Transaction call object
- `blockNumber`: Block number or tag
- `options`: Tracing options

## Block Tracing

### `debug_traceBlock`

Traces all transactions in a block given the RLP-encoded block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_traceBlock", "params": [rlpBlock, options]}` |

### `debug_traceBlockByHash`

Traces all transactions in a block given the block hash.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_traceBlockByHash", "params": [blockHash, options]}` |

### `debug_traceBlockByNumber`

Traces all transactions in a block given the block number.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_traceBlockByNumber", "params": [blockNumber, options]}` |

## State Access

### `debug_getRawHeader`

Returns the RLP-encoded header of a block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_getRawHeader", "params": [blockNumber]}` |

### `debug_getRawBlock`

Returns the RLP-encoded block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_getRawBlock", "params": [blockNumber]}` |

### `debug_getRawTransaction`

Returns the raw transaction bytes.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_getRawTransaction", "params": [txHash]}` |

### `debug_getRawReceipts`

Returns the raw receipt data for a block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_getRawReceipts", "params": [blockNumber]}` |

## Bundled Tracing

### `debug_executionWitness`

Generates an execution witness for a block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_executionWitness", "params": [blockNumber]}` |

## Code Retrieval

### `debug_getBadBlocks`

Returns a list of invalid blocks.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "debug_getBadBlocks", "params": []}` |

