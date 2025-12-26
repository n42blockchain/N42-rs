# examples for beacon debug
## eth_getBlockByNumber
```json
{
     "jsonrpc":"2.0",
     "method":"eth_getBlockByNumber",
     "params":["latest", false],
    "id":1
}
```

## consensusBeaconExt_get_beacon_block_hash_by_eth1_hash
```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_block_hash_by_eth1_hash",
     "params":
["0x279d7bac0d42a0330f2d0017ad7f5bced07b0363805682a41b2cd1c7773916ad"],
    "id":1
}
```

## consensusBeaconExt_get_beacon_block_by_hash
```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_block_by_hash",
     "params":
["0xd47417e1f170077bdc428101b437dac3673a6b39f6a94545302eb2acf90cae0a"],
    "id":1
}
```

## consensusBeaconExt_get_beacon_state_by_beacon_block_hash
```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_state_by_beacon_block_hash",
     "params":
["0xd47417e1f170077bdc428101b437dac3673a6b39f6a94545302eb2acf90cae0a"],
    "id":1
}
```

## consensusBeaconExt_get_beacon_state_by_number
The block number in hexadecimal format or the string latest, safe or finalized
```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_state_by_number",
     "params":["latest"],
     "id":1
}
```

## consensusBeaconExt_get_beacon_block_by_number
The block number in hexadecimal format or the string latest, safe or finalized
```json
{
     "jsonrpc":"2.0",
     "method":"consensusBeaconExt_get_beacon_block_by_number",
     "params":["0x11"],
    "id":1
}
```

## consensusBeaconExt_get_beacon_validator_by_pubkey
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

## consensusBeaconExt_get_total_effective_balance
```json
{
    "jsonrpc":"2.0",
    "method":"consensusBeaconExt_get_total_effective_balance",
    "params":[],
    "id":1
}
```

## consensusBeaconExt_subscribeToVerificationRequest
For websocket only.

params: [bls_pubkey_hex_str]

```json
{
    "jsonrpc":"2.0",
    "method":"consensusBeaconExt_subscribeToVerificationRequest",
    "params":["924aa3643a83bab96f51b5a9d920999968a575a8d240a46633966d17d2723dc709adf890de1a77f075d7e7fc84ddb09e"],
    "id":1
}
```

## consensusBeaconExt_submitVerification
For websocket only.

params: [bls_pubkey_hex_str, bls_signature_hex_str, attestation_data_json,
block_hash_hex_str]

```json
{
    "jsonrpc":"2.0",
    "method":"consensusBeaconExt_submitVerification",
    "params":[
"924aa3643a83bab96f51b5a9d920999968a575a8d240a46633966d17d2723dc709adf890de1a77f075d7e7fc84ddb09e",

"93eed5ae2c2b13cbccadd4ca42e642439657f724fab465552de1e722f3bb599412464b6239fcb85ac6525c0c11fa65ef168476c2167eab4c44fbbc3ffa53b1d6a2a282c48985e1de01fa00496f51dd3b3b3ca11b80112af88ff06ce2357dccbc",

 { "slot": 111654, "committee_index": 1, "receipts_root":
"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" },

 "0x6933b9f5e12e6366d8a25322c2f572694ebd45aaa63c496d6573d11d55620a5f"
],
    "id":1
}
```
