# evm2 inspectors prestate compatibility repair

Base: evm2 git revision f93318f120f6300599b21170d6c7bef81ed63d87
(https://github.com/alloy-rs/evm2, the revision reth v2.9.0 pins),
`crates/inspectors`, package evm2-inspectors 0.1.0. Upstream licenses retained.
`Cargo.toml` is flattened from the workspace manifest (`Cargo.toml.orig` is
the member manifest as published); tests and dev-dependencies are dropped.

Patch (`N42-PATCH.diff`): the DebugInspector default prestate includes the block
beneficiary from the pre-execution database when fee-disabled call execution
(`debug_traceCall`) never touched it, unless it was empty before execution
(the rule the builder applies to every account). Traced storage, modified
accounts, diff mode and disableCode behaviour are unchanged. No execution
state, signatures, wire format, or QMDB commitment is changed.

This carries the repair that lived in `revm-inspectors-0.44.3` (reth <= v2.8.1)
over to evm2's inspectors, where the same omission exists
(`geth_prestate_pre_traces` lists only the accounts in the pending state).

Reference: Geth OnTxStart explicitly looks up env.Coinbase:
https://github.com/ethereum/go-ethereum/blob/master/eth/tracers/native/prestate.go
Remove this replacement when the maintained dependency provides the same behavior.
