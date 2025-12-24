# Chain Data Migration

This document describes how to migrate data from an old N42 chain to a new node.

## Prerequisites

- A running old chain with accessible RPC endpoint
- A new N42 node binary
- Environment variables configured

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NODE_PRIVATE_KEY` | The consensus signer private key for the new node |
| `NODE_DATA_DIR` | The data directory for the new node |
| `OLD_CHAIN_RPC` | The RPC endpoint of the old chain to migrate from |

## Migration Command

```shell
#!/bin/bash

RUST_LOG=info ./n42 node \
    --chain n42 \
    --dev.block-time 4s \
    --disable-discovery --with-unused-ports \
    --dev.consensus-signer-private-key $NODE_PRIVATE_KEY \
    --datadir $NODE_DATA_DIR \
    --dev.migrate-old-chain-data-from-rpc $OLD_CHAIN_RPC
```

## Notes

- The migration process will fetch historical data from the old chain's RPC endpoint
- Ensure sufficient disk space in the `NODE_DATA_DIR`
- The migration may take some time depending on the amount of historical data
