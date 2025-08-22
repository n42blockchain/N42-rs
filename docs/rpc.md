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
