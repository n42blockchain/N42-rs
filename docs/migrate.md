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
