# `eth` Namespace

The `eth` API allows you to interact with the Ethereum protocol. This includes querying blockchain data, sending transactions, and managing accounts.

Documentation for the standard Ethereum JSON-RPC API methods can be found on [ethereum.org](https://ethereum.org/en/developers/docs/apis/json-rpc/).

## Common Methods

### Chain State

| Method | Description |
|--------|-------------|
| `eth_blockNumber` | Returns the current block number |
| `eth_chainId` | Returns the chain ID |
| `eth_syncing` | Returns syncing status |
| `eth_gasPrice` | Returns current gas price |
| `eth_maxPriorityFeePerGas` | Returns max priority fee per gas |
| `eth_feeHistory` | Returns historical gas fee data |

### Blocks

| Method | Description |
|--------|-------------|
| `eth_getBlockByHash` | Returns block by hash |
| `eth_getBlockByNumber` | Returns block by number |
| `eth_getBlockReceipts` | Returns all receipts for a block |
| `eth_getBlockTransactionCountByHash` | Returns tx count by block hash |
| `eth_getBlockTransactionCountByNumber` | Returns tx count by block number |

### Transactions

| Method | Description |
|--------|-------------|
| `eth_getTransactionByHash` | Returns transaction by hash |
| `eth_getTransactionByBlockHashAndIndex` | Returns tx by block hash and index |
| `eth_getTransactionByBlockNumberAndIndex` | Returns tx by block number and index |
| `eth_getTransactionReceipt` | Returns transaction receipt |
| `eth_getTransactionCount` | Returns account nonce |
| `eth_sendRawTransaction` | Submits a raw transaction |
| `eth_sendTransaction` | Submits a transaction (requires unlocked account) |

### State & Accounts

| Method | Description |
|--------|-------------|
| `eth_getBalance` | Returns account balance |
| `eth_getCode` | Returns contract code |
| `eth_getStorageAt` | Returns storage value |
| `eth_getProof` | Returns Merkle proof for account/storage |

### Execution

| Method | Description |
|--------|-------------|
| `eth_call` | Executes a call without creating a transaction |
| `eth_estimateGas` | Estimates gas for a transaction |
| `eth_createAccessList` | Creates an access list for a transaction |
| `eth_simulateV1` | Simulates multiple transactions (EIP-7560) |

### Logs & Filters

| Method | Description |
|--------|-------------|
| `eth_getLogs` | Returns logs matching filter |
| `eth_newFilter` | Creates a new filter |
| `eth_newBlockFilter` | Creates a block filter |
| `eth_newPendingTransactionFilter` | Creates a pending tx filter |
| `eth_getFilterChanges` | Polls filter for changes |
| `eth_getFilterLogs` | Returns all logs for filter |
| `eth_uninstallFilter` | Removes a filter |

### Subscriptions (WebSocket only)

| Method | Description |
|--------|-------------|
| `eth_subscribe` | Subscribe to events (newHeads, logs, pendingTransactions) |
| `eth_unsubscribe` | Unsubscribe from events |

### Mining (if applicable)

| Method | Description |
|--------|-------------|
| `eth_coinbase` | Returns coinbase address |
| `eth_mining` | Returns mining status |
| `eth_hashrate` | Returns hash rate |

## Example

```bash
# Get current block number
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://localhost:8545

# Get account balance
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x...", "latest"],"id":1}' \
  http://localhost:8545
```

