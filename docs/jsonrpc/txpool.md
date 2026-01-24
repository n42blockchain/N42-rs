# `txpool` Namespace

The `txpool` API allows you to inspect the transaction pool.

## `txpool_content`

Returns the details of all transactions currently pending for inclusion in the next block(s), as well as the ones that are being scheduled for future execution only.

See [Geth documentation](https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_content) for more details.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "txpool_content", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "pending": {
      "0x...": {
        "0": { ... },
        "1": { ... }
      }
    },
    "queued": {
      "0x...": {
        "5": { ... }
      }
    }
  }
}
```

## `txpool_contentFrom`

Retrieves the transactions contained within the txpool, returning pending as well as queued transactions of this address, grouped by nonce.

See [Geth documentation](https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_contentFrom) for more details.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "txpool_contentFrom", "params": [address]}` |

### Parameters

- `address`: The address to filter transactions by

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"txpool_contentFrom","params":["0x..."],"id":1}' \
  http://localhost:8545
```

## `txpool_inspect`

Returns a summary of all the transactions currently pending for inclusion in the next block(s), as well as the ones that are being scheduled for future execution only.

See [Geth documentation](https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_inspect) for more details.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "txpool_inspect", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"txpool_inspect","params":[],"id":1}' \
  http://localhost:8545
```

## `txpool_status`

Returns the number of transactions currently pending for inclusion in the next block(s), as well as the ones that are being scheduled for future execution only.

See [Geth documentation](https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_status) for more details.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "txpool_status", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "pending": "0xa",
    "queued": "0x3"
  }
}
```

