# `flashbots` Namespace

The `flashbots` API provides methods for MEV (Maximal Extractable Value) bundle submission, compatible with the Flashbots relay protocol.

## `flashbots_sendBundle`

Submits a bundle of transactions to be included in a block.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "flashbots_sendBundle", "params": [bundleParams]}` |

### Parameters

- `bundleParams`: Bundle submission object:
  - `txs`: Array of signed transaction hex strings
  - `blockNumber`: Target block number (hex-encoded)
  - `minTimestamp` (optional): Minimum timestamp for inclusion
  - `maxTimestamp` (optional): Maximum timestamp for inclusion
  - `revertingTxHashes` (optional): Array of tx hashes that are allowed to revert

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{
    "jsonrpc": "2.0",
    "method": "flashbots_sendBundle",
    "params": [{
      "txs": ["0x...signed_tx_1...", "0x...signed_tx_2..."],
      "blockNumber": "0x100",
      "minTimestamp": 0,
      "maxTimestamp": 1234567890
    }],
    "id": 1
  }' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "bundleHash": "0x..."
  }
}
```

## `flashbots_callBundle`

Simulates a bundle without submitting it.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "flashbots_callBundle", "params": [bundleParams]}` |

### Parameters

Same as `flashbots_sendBundle`, with additional optional parameters:
- `stateBlockNumber`: Block number to use for simulation state
- `timestamp`: Timestamp to use for simulation

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{
    "jsonrpc": "2.0",
    "method": "flashbots_callBundle",
    "params": [{
      "txs": ["0x...signed_tx..."],
      "blockNumber": "0x100",
      "stateBlockNumber": "latest"
    }],
    "id": 1
  }' \
  http://localhost:8545
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "bundleGasPrice": "0x...",
    "bundleHash": "0x...",
    "coinbaseDiff": "0x...",
    "ethSentToCoinbase": "0x...",
    "gasFees": "0x...",
    "results": [
      {
        "txHash": "0x...",
        "gasUsed": 21000,
        "gasPrice": "0x...",
        "value": "0x..."
      }
    ],
    "stateBlockNumber": 255,
    "totalGasUsed": 21000
  }
}
```

## `flashbots_cancelBundle`

Cancels a previously submitted bundle.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "flashbots_cancelBundle", "params": [bundleHash]}` |

### Parameters

- `bundleHash`: The bundle hash returned from `flashbots_sendBundle`

## Bundle Simulation

Bundles can be simulated to estimate:
- Gas usage
- Coinbase profit
- Transaction success/failure

This is useful for:
- Testing bundle construction
- Estimating MEV extraction
- Debugging failed bundles

## Security Considerations

- Bundle transactions are executed atomically
- Failed transactions in a bundle cause the entire bundle to fail (unless in `revertingTxHashes`)
- Bundles should include appropriate gas prices to be competitive
- Consider privacy implications of bundle submission

## Integration

To enable the `flashbots` namespace:

```bash
n42 node --http --http.api "eth,flashbots"
```

