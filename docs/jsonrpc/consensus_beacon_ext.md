# `consensusBeaconExt` Namespace

The `consensusBeaconExt` API provides N42-specific consensus extension methods for interacting with the beacon chain consensus layer.

> **Warning**
>
> This namespace contains sensitive methods for validators and should **not** be exposed publicly.

## Validator Methods

### `consensusBeaconExt_subscribeToVerificationRequest`

Subscribe to block verification requests. This is used by validators to receive blocks that need to be verified.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_subscribeToVerificationRequest", "params": [pubkey]}` |

#### Parameters

- `pubkey`: The validator's BLS public key (hex-encoded)

#### Returns

A subscription that emits `UnverifiedBlock` objects when new blocks need verification.

#### Example

```js
// Subscribe to verification requests
// > {"jsonrpc":"2.0","id":1,"method":"consensusBeaconExt_subscribeToVerificationRequest","params":["0x..."]}
{"jsonrpc":"2.0","id":1,"result":"0x1234..."}  // subscription ID

// Received event
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_subscribeToVerificationRequest",
    "params": {
        "subscription": "0x1234...",
        "result": {
            "blockbody": { ... },
            "committee_index": 0,
            "db": { ... }
        }
    }
}
```

### `consensusBeaconExt_submitVerification`

Submit a block verification result with the validator's signature.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_submitVerification", "params": [pubkey, signature, attestation_data, block_hash]}` |

#### Parameters

- `pubkey`: The validator's BLS public key (hex-encoded)
- `signature`: The BLS signature over the attestation data (hex-encoded)
- `attestation_data`: The attestation data object containing:
  - `slot`: The slot number
  - `committee_index`: The committee index
  - `receipts_root`: The computed receipts root
- `block_hash`: The recovered block hash (hex-encoded)

#### Returns

Nothing on success, or an error if verification fails.

#### Example

```js
// > {"jsonrpc":"2.0","id":1,"method":"consensusBeaconExt_submitVerification","params":["0xpubkey...","0xsignature...",{"slot":123,"committee_index":0,"receipts_root":"0x..."},"0xblockhash..."]}
{"jsonrpc":"2.0","id":1,"result":null}
```

## Beacon State Query Methods

### `consensusBeaconExt_get_beacon_block_hash_by_eth1_hash`

Returns the beacon block hash corresponding to an Ethereum 1.0 block hash.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_get_beacon_block_hash_by_eth1_hash", "params": [eth1Hash]}` |

#### Parameters

- `eth1Hash`: The Ethereum 1.0 block hash (hex-encoded)

#### Example

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_block_hash_by_eth1_hash",
    "params": ["0x279d7bac0d42a0330f2d0017ad7f5bced07b0363805682a41b2cd1c7773916ad"],
    "id": 1
}
```

### `consensusBeaconExt_get_beacon_block_by_hash`

Returns a beacon block by its hash.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_get_beacon_block_by_hash", "params": [blockHash]}` |

#### Parameters

- `blockHash`: The beacon block hash (hex-encoded)

### `consensusBeaconExt_get_beacon_block_by_number`

Returns a beacon block by its number.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_get_beacon_block_by_number", "params": [blockNumber]}` |

#### Parameters

- `blockNumber`: Block number (hex-encoded) or tag (`latest`, `safe`, `finalized`)

#### Example

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_block_by_number",
    "params": ["0x11"],
    "id": 1
}
```

### `consensusBeaconExt_get_beacon_state_by_beacon_block_hash`

Returns the beacon state for a given beacon block hash.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_get_beacon_state_by_beacon_block_hash", "params": [blockHash]}` |

### `consensusBeaconExt_get_beacon_state_by_number`

Returns the beacon state for a given block number.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_get_beacon_state_by_number", "params": [blockNumber]}` |

#### Parameters

- `blockNumber`: Block number (hex-encoded) or tag (`latest`, `safe`, `finalized`)

### `consensusBeaconExt_get_beacon_validator_by_pubkey`

Returns validator information by public key.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_get_beacon_validator_by_pubkey", "params": [pubkey]}` |

#### Parameters

- `pubkey`: BLS public key (hex-encoded)

#### Example

```json
{
    "jsonrpc": "2.0",
    "method": "consensusBeaconExt_get_beacon_validator_by_pubkey",
    "params": ["0x96f841a5e6a8f2ff7015f599fcde19961e31c3b7d32c417d256f14c044d54406152d7db65a1dbbbb2142a87c0214e2e9"],
    "id": 1
}
```

#### Response

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "activation_timestamp": 1760691561,
        "exit_timestamp": 0,
        "balance_in_beacon": 32000000000,
        "effective_balance": 32000000000,
        "inactivity_score": 0
    }
}
```

This validator was activated at timestamp `1760691561` and has not exited. Its balance in the beacon chain is 32 ETH, and its effective balance is 32 ETH. It is actively validating blocks.

### `consensusBeaconExt_get_total_effective_balance`

Returns the total effective balance of all active validators.

| Client | Method invocation |
|--------|-------------------|
| RPC    | `{"method": "consensusBeaconExt_get_total_effective_balance", "params": []}` |

## Validator Workflow

1. **Connect**: Establish a WebSocket connection to the N42 node
2. **Subscribe**: Call `consensusBeaconExt_subscribeToVerificationRequest` with your validator's public key
3. **Receive**: Wait for `UnverifiedBlock` events
4. **Verify**: Execute the block locally and compute the receipts root
5. **Sign**: Sign the attestation data using your BLS private key
6. **Submit**: Call `consensusBeaconExt_submitVerification` with the signature and data

### Example Client Code (Rust)

```rust
use jsonrpsee::ws_client::WsClientBuilder;
use jsonrpsee::core::client::{SubscriptionClientT, ClientT};

async fn run_validator(ws_url: &str, private_key: &SecretKey) -> Result<()> {
    let client = WsClientBuilder::default().build(ws_url).await?;
    let pubkey = private_key.sk_to_pk();
    
    // Subscribe to verification requests
    let mut subscription = client
        .subscribe(
            "consensusBeaconExt_subscribeToVerificationRequest",
            rpc_params![hex::encode(pubkey.to_bytes())],
            ""
        )
        .await?;
    
    while let Some(msg) = subscription.next().await {
        match msg {
            Ok(block) => {
                // Verify the block
                let receipts_root = verify_block(block.clone())?;
                
                // Create attestation data
                let attestation_data = AttestationData {
                    slot: block.blockbody.header().number(),
                    committee_index: block.committee_index,
                    receipts_root,
                };
                
                // Sign the attestation
                let sig = private_key.sign(&attestation_data.to_bytes(), BLS_DST_SIG, &[]);
                
                // Submit verification
                client.request(
                    "consensusBeaconExt_submitVerification",
                    rpc_params![
                        hex::encode(pubkey.to_bytes()),
                        hex::encode(sig.to_bytes()),
                        attestation_data,
                        hex::encode(block_hash.as_slice())
                    ]
                ).await?;
            }
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }
    
    Ok(())
}
```

## Security Considerations

- This namespace should only be exposed to trusted validators
- Use WebSocket over TLS (wss://) for production
- Protect your validator's BLS private key
- Monitor for double-signing to avoid slashing

