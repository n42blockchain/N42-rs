# Revm inspectors prestate compatibility repair

Base: crates.io revm-inspectors 0.44.1; Cargo.lock original checksum
3584d48ecc82f4df573c0b68994a27f46da53e06dfae224e446b1aa868bc1665.
Source and upstream licenses retained. Registry cache markers excluded.

Patch: DebugInspector default prestate includes the block beneficiary from the
pre-execution database when fee-disabled call execution omitted it from the
returned EVM state. Existing traced storage and modified accounts remain intact;
diff mode and disableCode behavior are preserved. No execution state, signatures,
wire format, or QMDB commitment is changed.

Reference: Geth OnTxStart explicitly looks up env.Coinbase:
https://github.com/ethereum/go-ethereum/blob/master/eth/tracers/native/prestate.go
Remove this replacement when the maintained dependency provides the same behavior.
