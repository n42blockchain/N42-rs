# Revm inspectors prestate compatibility repair

Base: crates.io revm-inspectors 0.44.3; Cargo.lock original checksum
d578c9a58c30ce3736b30b5e99368376605c1f7cc34360a91834fb83f673afca.
Source and upstream licenses retained. Registry cache markers excluded.

Patch: DebugInspector default prestate includes the block beneficiary from the
pre-execution database when fee-disabled call execution omitted it from the
returned EVM state. Existing traced storage and modified accounts remain intact;
diff mode and disableCode behavior are preserved. No execution state, signatures,
wire format, or QMDB commitment is changed.

Reference: Geth OnTxStart explicitly looks up env.Coinbase:
https://github.com/ethereum/go-ethereum/blob/master/eth/tracers/native/prestate.go
Remove this replacement when the maintained dependency provides the same behavior.
