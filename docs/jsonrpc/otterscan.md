# `ots` Namespace (Otterscan)

The `ots` API provides Otterscan-compatible methods for enhanced block explorer functionality.

[Otterscan](https://github.com/otterscan/otterscan) is a block explorer for Ethereum that requires additional RPC methods beyond the standard Ethereum JSON-RPC API.

## Block Operations

### `ots_getBlockDetails`

Returns detailed information about a block including transaction count and total fees.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getBlockDetails", "params": [blockNumber]}` |

### `ots_getBlockDetailsByHash`

Returns detailed information about a block by hash.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getBlockDetailsByHash", "params": [blockHash]}` |

### `ots_getBlockTransactions`

Returns paginated transactions for a block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getBlockTransactions", "params": [blockNumber, pageNumber, pageSize]}` |

## Transaction Operations

### `ots_getTransactionBySenderAndNonce`

Returns a transaction by sender address and nonce.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getTransactionBySenderAndNonce", "params": [address, nonce]}` |

### `ots_getTransactionError`

Returns the revert reason for a failed transaction.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getTransactionError", "params": [txHash]}` |

### `ots_hasCode`

Checks if an address has contract code at a specific block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_hasCode", "params": [address, blockNumber]}` |

## Contract Operations

### `ots_getContractCreator`

Returns the transaction that created a contract.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getContractCreator", "params": [address]}` |

## Internal Operations

### `ots_traceTransaction`

Returns internal operations (calls, creates, etc.) for a transaction.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_traceTransaction", "params": [txHash]}` |

### `ots_getInternalOperations`

Returns internal operations for a transaction.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getInternalOperations", "params": [txHash]}` |

## Search Operations

### `ots_searchTransactionsBefore`

Searches for transactions before a specific block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_searchTransactionsBefore", "params": [address, blockNumber, pageSize]}` |

### `ots_searchTransactionsAfter`

Searches for transactions after a specific block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_searchTransactionsAfter", "params": [address, blockNumber, pageSize]}` |

## API Information

### `ots_getApiLevel`

Returns the Otterscan API version level.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "ots_getApiLevel", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"ots_getApiLevel","params":[],"id":1}' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": 8
}
```

## Integration with Otterscan

To use N42 with Otterscan:

1. Enable the `ots` namespace:

```bash
n42 node --http --http.api "eth,net,web3,ots"
```

2. Configure Otterscan to connect to your N42 node.

