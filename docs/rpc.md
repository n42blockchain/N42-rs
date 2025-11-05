# examples for beacon debug
```json
{
     "jsonrpc":"2.0",
     "method":"eth_getBlockByNumber",
     "params":["latest", false],
    "id":1
}
```

```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_block_hash_by_eth1_hash",
     "params":
["0x279d7bac0d42a0330f2d0017ad7f5bced07b0363805682a41b2cd1c7773916ad"],
    "id":1
}
```

```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_block_by_hash",
     "params":
["0xd47417e1f170077bdc428101b437dac3673a6b39f6a94545302eb2acf90cae0a"],
    "id":1
}
```

```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_state_by_beacon_block_hash",
     "params":
["0xd47417e1f170077bdc428101b437dac3673a6b39f6a94545302eb2acf90cae0a"],
    "id":1
}
```

The block number in hexadecimal format or the string latest, safe or finalized
```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_state_by_number",
     "params":["latest"],
     "id":1
}
```

The block number in hexadecimal format or the string latest, safe or finalized
```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_block_by_number",
     "params":["0x11"],
    "id":1
}
```

params: [bls_pubkey_hex_str]
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_validator_by_pubkey",
     "params":
["0x96f841a5e6a8f2ff7015f599fcde19961e31c3b7d32c417d256f14c044d54406152d7db65a1dbbbb2142a87c0214e2e9"],
    "id":1
}

response:
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
This validator is activated at timestamp 1760691561 and has not exited; its balance in beacon is 32ETH, its effective balance in beacon is 32ETH; it is actively validating blocks.

```json
{
    "jsonrpc":"2.0",
    "method":"consensusBeaconExt_get_total_effective_balance",
    "params":[],
    "id":1
}
```
