# `miner` Namespace

The `miner` API provides methods for controlling block production (mining/sealing) on the node.

> **Note**
>
> N42 uses Proof of Authority (PoA) consensus. These methods control block sealing rather than traditional Proof of Work mining.

## `miner_setExtra`

Sets the extra data to include in sealed blocks.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "miner_setExtra", "params": [extraData]}` |

### Parameters

- `extraData`: Extra data to include (hex-encoded, max 32 bytes for vanity)

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"miner_setExtra","params":["0x4e3432"],"id":1}' \
  http://localhost:8545
```

## `miner_setGasPrice`

Sets the minimum gas price for transactions to be included in blocks.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "miner_setGasPrice", "params": [gasPrice]}` |

### Parameters

- `gasPrice`: Minimum gas price in wei (hex-encoded)

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"miner_setGasPrice","params":["0x3B9ACA00"],"id":1}' \
  http://localhost:8545
```

## `miner_setGasLimit`

Sets the target gas limit for sealed blocks.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "miner_setGasLimit", "params": [gasLimit]}` |

### Parameters

- `gasLimit`: Target gas limit (hex-encoded)

## `miner_start`

Starts block sealing/production.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "miner_start", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"miner_start","params":[],"id":1}' \
  http://localhost:8545
```

## `miner_stop`

Stops block sealing/production.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "miner_stop", "params": []}` |

### Example

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"miner_stop","params":[],"id":1}' \
  http://localhost:8545
```

## `miner_setEtherbase`

Sets the address that receives block rewards.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "miner_setEtherbase", "params": [address]}` |

### Parameters

- `address`: The address to receive block rewards

## APoS Consensus Notes

In N42's APoS (Authority Proof of Stake) consensus:

- Block production is controlled by authorized signers
- The `miner` namespace controls whether a signer node actively produces blocks
- Block rewards are distributed according to the consensus rules
- The "mining" process is actually block sealing with a signature

