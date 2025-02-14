# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.3](https://github.com/alloy-rs/alloy/releases/tag/v0.5.3) - 2024-10-22

### Features

- Derive serde for `ExecutionPayloadSidecar` ([#1535](https://github.com/alloy-rs/alloy/issues/1535))

### Miscellaneous Tasks

- Release 0.5.3

## [0.5.2](https://github.com/alloy-rs/alloy/releases/tag/v0.5.2) - 2024-10-18

### Miscellaneous Tasks

- Release 0.5.2

## [0.5.1](https://github.com/alloy-rs/alloy/releases/tag/v0.5.1) - 2024-10-18

### Features

- Add ExecutionPayloadSidecar type ([#1517](https://github.com/alloy-rs/alloy/issues/1517))

### Miscellaneous Tasks

- Release 0.5.1
- Extract error types to new modules ([#1518](https://github.com/alloy-rs/alloy/issues/1518))
- Remove 7685 request variants ([#1515](https://github.com/alloy-rs/alloy/issues/1515))

## [0.5.0](https://github.com/alloy-rs/alloy/releases/tag/v0.5.0) - 2024-10-18

### Miscellaneous Tasks

- Release 0.5.0
- Flatten eip-7685 requests into a single opaque list ([#1383](https://github.com/alloy-rs/alloy/issues/1383))
- Refactor some match with same arms ([#1463](https://github.com/alloy-rs/alloy/issues/1463))
- Some small improvements ([#1461](https://github.com/alloy-rs/alloy/issues/1461))

### Other

- Add default to payload id ([#1442](https://github.com/alloy-rs/alloy/issues/1442))
- Replace assert_eq! with similar_asserts::assert_eq! ([#1429](https://github.com/alloy-rs/alloy/issues/1429))

## [0.4.2](https://github.com/alloy-rs/alloy/releases/tag/v0.4.2) - 2024-10-01

### Miscellaneous Tasks

- Release 0.4.2

## [0.4.1](https://github.com/alloy-rs/alloy/releases/tag/v0.4.1) - 2024-10-01

### Miscellaneous Tasks

- Release 0.4.1

## [0.4.0](https://github.com/alloy-rs/alloy/releases/tag/v0.4.0) - 2024-09-30

### Features

- [rpc-types-engine] Use strum for ClientCode ([#1386](https://github.com/alloy-rs/alloy/issues/1386))
- Replace std/hashbrown with alloy_primitives::map ([#1384](https://github.com/alloy-rs/alloy/issues/1384))
- [engine] Add Trin Execution client code ([#1372](https://github.com/alloy-rs/alloy/issues/1372))
- [transport-http] JWT auth layer ([#1314](https://github.com/alloy-rs/alloy/issues/1314))

### Miscellaneous Tasks

- Release 0.4.0
- Reexport BlobAndProofV1

## [0.3.6](https://github.com/alloy-rs/alloy/releases/tag/v0.3.6) - 2024-09-18

### Features

- Add block num hash helper ([#1304](https://github.com/alloy-rs/alloy/issues/1304))
- [rpc-types-beacon] `SignedBidSubmissionV4` ([#1303](https://github.com/alloy-rs/alloy/issues/1303))

### Miscellaneous Tasks

- Release 0.3.6

## [0.3.5](https://github.com/alloy-rs/alloy/releases/tag/v0.3.5) - 2024-09-13

### Bug Fixes

- Add missing conversion ([#1287](https://github.com/alloy-rs/alloy/issues/1287))

### Miscellaneous Tasks

- Release 0.3.5

## [0.3.4](https://github.com/alloy-rs/alloy/releases/tag/v0.3.4) - 2024-09-13

### Features

- [engine] Optional Serde ([#1283](https://github.com/alloy-rs/alloy/issues/1283))
- [engine] No_std engine types ([#1268](https://github.com/alloy-rs/alloy/issues/1268))

### Miscellaneous Tasks

- Release 0.3.4
- Remove eth rpc types dep from engine types ([#1280](https://github.com/alloy-rs/alloy/issues/1280))

## [0.3.3](https://github.com/alloy-rs/alloy/releases/tag/v0.3.3) - 2024-09-10

### Miscellaneous Tasks

- Release 0.3.3

## [0.3.2](https://github.com/alloy-rs/alloy/releases/tag/v0.3.2) - 2024-09-09

### Features

- [rpc-types-engine] Add forkchoice state zero helpers ([#1231](https://github.com/alloy-rs/alloy/issues/1231))

### Miscellaneous Tasks

- Release 0.3.2

## [0.3.1](https://github.com/alloy-rs/alloy/releases/tag/v0.3.1) - 2024-09-02

### Miscellaneous Tasks

- Release 0.3.1

## [0.3.0](https://github.com/alloy-rs/alloy/releases/tag/v0.3.0) - 2024-08-28

### Bug Fixes

- Remove optimism-related types ([#1203](https://github.com/alloy-rs/alloy/issues/1203))

### Dependencies

- Bump core and rm ssz feat ([#1167](https://github.com/alloy-rs/alloy/issues/1167))
- Bump jsonrpsee 0.24 ([#1067](https://github.com/alloy-rs/alloy/issues/1067))

### Features

- Add error for pre prague requests ([#1204](https://github.com/alloy-rs/alloy/issues/1204))
- [engine-types] `PayloadError::PrePragueBlockWithEip7702Transactions` ([#1116](https://github.com/alloy-rs/alloy/issues/1116))

### Miscellaneous Tasks

- Release 0.3.0
- Clippy für docs ([#1194](https://github.com/alloy-rs/alloy/issues/1194))
- [dep] Feature gate jwt in engine types ([#1131](https://github.com/alloy-rs/alloy/issues/1131))
- Release 0.2.1
- Release 0.2.0
- Add payloadbodies v2 to capabilities set ([#1025](https://github.com/alloy-rs/alloy/issues/1025))

### Refactor

- Replace `U64` with `u64`  ([#1057](https://github.com/alloy-rs/alloy/issues/1057))

## [0.1.4](https://github.com/alloy-rs/alloy/releases/tag/v0.1.4) - 2024-07-08

### Features

- Add execution payloadbodyv2 ([#1012](https://github.com/alloy-rs/alloy/issues/1012))
- Add consolidation requests to v4 payload ([#1013](https://github.com/alloy-rs/alloy/issues/1013))

### Miscellaneous Tasks

- Release 0.1.4

## [0.1.3](https://github.com/alloy-rs/alloy/releases/tag/v0.1.3) - 2024-06-25

### Miscellaneous Tasks

- Release 0.1.3
- Nightly clippy ([#947](https://github.com/alloy-rs/alloy/issues/947))

## [0.1.2](https://github.com/alloy-rs/alloy/releases/tag/v0.1.2) - 2024-06-19

### Documentation

- Touch up docs, TODOs ([#918](https://github.com/alloy-rs/alloy/issues/918))
- Add per-crate changelogs ([#914](https://github.com/alloy-rs/alloy/issues/914))

### Miscellaneous Tasks

- Release 0.1.2
- Update changelogs for v0.1.1 ([#922](https://github.com/alloy-rs/alloy/issues/922))
- Add docs.rs metadata to all manifests ([#917](https://github.com/alloy-rs/alloy/issues/917))

## [0.1.1](https://github.com/alloy-rs/alloy/releases/tag/v0.1.1) - 2024-06-17

### Bug Fixes

- Correct exitV1 type ([#567](https://github.com/alloy-rs/alloy/issues/567))

### Dependencies

- [deps] Bump all ([#864](https://github.com/alloy-rs/alloy/issues/864))
- Bump jsonrpsee 0.22 ([#467](https://github.com/alloy-rs/alloy/issues/467))

### Features

- [rpc] Split off `eth` namespace in `alloy-rpc-types` to `alloy-rpc-types-eth` ([#847](https://github.com/alloy-rs/alloy/issues/847))
- [serde] Deprecate individual num::* for a generic `quantity` module ([#855](https://github.com/alloy-rs/alloy/issues/855))
- Add methods to JwtSecret to read and write from filesystem ([#755](https://github.com/alloy-rs/alloy/issues/755))
- Add op payload type ([#742](https://github.com/alloy-rs/alloy/issues/742))
- Add payload envelope v4 ([#741](https://github.com/alloy-rs/alloy/issues/741))
- Impl `From` for exec payload v4 ([#695](https://github.com/alloy-rs/alloy/issues/695))
- Add MaybeCancunPayloadFields::as_ref ([#692](https://github.com/alloy-rs/alloy/issues/692))
- Add PayloadError variants ([#649](https://github.com/alloy-rs/alloy/issues/649))
- [engine] Add JSON Web Token (JWT) token generation and validation support ([#612](https://github.com/alloy-rs/alloy/issues/612))
- Add ClientVersionV1 ([#562](https://github.com/alloy-rs/alloy/issues/562))
- Add prague engine types ([#557](https://github.com/alloy-rs/alloy/issues/557))
- `std` feature flag for `alloy-consensus` ([#461](https://github.com/alloy-rs/alloy/issues/461))
- Rename alloy-rpc-*-types to alloy-rpc-types-* ([#435](https://github.com/alloy-rs/alloy/issues/435))

### Miscellaneous Tasks

- [clippy] Apply lint suggestions ([#903](https://github.com/alloy-rs/alloy/issues/903))
- [docs] Add doc aliases ([#843](https://github.com/alloy-rs/alloy/issues/843))
- Add engine_getClientVersionV1 ([#823](https://github.com/alloy-rs/alloy/issues/823))
- Add engine api v4 capabilities ([#822](https://github.com/alloy-rs/alloy/issues/822))
- Expose Claims is_within_time_window as pub ([#794](https://github.com/alloy-rs/alloy/issues/794))
- Actually impl from for payload v4 ([#698](https://github.com/alloy-rs/alloy/issues/698))
- Rename deposit receipt to deposit request ([#693](https://github.com/alloy-rs/alloy/issues/693))
- Replace `ExitV1` with `WithdrawalRequest` ([#672](https://github.com/alloy-rs/alloy/issues/672))

### Other

- Add clippy at workspace level ([#766](https://github.com/alloy-rs/alloy/issues/766))
- Expose inner `B64` from `PayloadId` ([#646](https://github.com/alloy-rs/alloy/issues/646))
- Use the same way to both serialize and deserialize `OptimismPayloadAttributes::gas_limit`. ([#563](https://github.com/alloy-rs/alloy/issues/563))

### Refactor

- Clean up legacy serde helpers ([#624](https://github.com/alloy-rs/alloy/issues/624))

### Styling

- Sort derives ([#499](https://github.com/alloy-rs/alloy/issues/499))

[`alloy`]: https://crates.io/crates/alloy
[alloy]: https://crates.io/crates/alloy
[`alloy-core`]: https://crates.io/crates/alloy-core
[alloy-core]: https://crates.io/crates/alloy-core
[`alloy-consensus`]: https://crates.io/crates/alloy-consensus
[alloy-consensus]: https://crates.io/crates/alloy-consensus
[`alloy-contract`]: https://crates.io/crates/alloy-contract
[alloy-contract]: https://crates.io/crates/alloy-contract
[`alloy-eips`]: https://crates.io/crates/alloy-eips
[alloy-eips]: https://crates.io/crates/alloy-eips
[`alloy-genesis`]: https://crates.io/crates/alloy-genesis
[alloy-genesis]: https://crates.io/crates/alloy-genesis
[`alloy-json-rpc`]: https://crates.io/crates/alloy-json-rpc
[alloy-json-rpc]: https://crates.io/crates/alloy-json-rpc
[`alloy-network`]: https://crates.io/crates/alloy-network
[alloy-network]: https://crates.io/crates/alloy-network
[`alloy-node-bindings`]: https://crates.io/crates/alloy-node-bindings
[alloy-node-bindings]: https://crates.io/crates/alloy-node-bindings
[`alloy-provider`]: https://crates.io/crates/alloy-provider
[alloy-provider]: https://crates.io/crates/alloy-provider
[`alloy-pubsub`]: https://crates.io/crates/alloy-pubsub
[alloy-pubsub]: https://crates.io/crates/alloy-pubsub
[`alloy-rpc-client`]: https://crates.io/crates/alloy-rpc-client
[alloy-rpc-client]: https://crates.io/crates/alloy-rpc-client
[`alloy-rpc-types`]: https://crates.io/crates/alloy-rpc-types
[alloy-rpc-types]: https://crates.io/crates/alloy-rpc-types
[`alloy-rpc-types-anvil`]: https://crates.io/crates/alloy-rpc-types-anvil
[alloy-rpc-types-anvil]: https://crates.io/crates/alloy-rpc-types-anvil
[`alloy-rpc-types-beacon`]: https://crates.io/crates/alloy-rpc-types-beacon
[alloy-rpc-types-beacon]: https://crates.io/crates/alloy-rpc-types-beacon
[`alloy-rpc-types-engine`]: https://crates.io/crates/alloy-rpc-types-engine
[alloy-rpc-types-engine]: https://crates.io/crates/alloy-rpc-types-engine
[`alloy-rpc-types-eth`]: https://crates.io/crates/alloy-rpc-types-eth
[alloy-rpc-types-eth]: https://crates.io/crates/alloy-rpc-types-eth
[`alloy-rpc-types-trace`]: https://crates.io/crates/alloy-rpc-types-trace
[alloy-rpc-types-trace]: https://crates.io/crates/alloy-rpc-types-trace
[`alloy-serde`]: https://crates.io/crates/alloy-serde
[alloy-serde]: https://crates.io/crates/alloy-serde
[`alloy-signer`]: https://crates.io/crates/alloy-signer
[alloy-signer]: https://crates.io/crates/alloy-signer
[`alloy-signer-aws`]: https://crates.io/crates/alloy-signer-aws
[alloy-signer-aws]: https://crates.io/crates/alloy-signer-aws
[`alloy-signer-gcp`]: https://crates.io/crates/alloy-signer-gcp
[alloy-signer-gcp]: https://crates.io/crates/alloy-signer-gcp
[`alloy-signer-ledger`]: https://crates.io/crates/alloy-signer-ledger
[alloy-signer-ledger]: https://crates.io/crates/alloy-signer-ledger
[`alloy-signer-local`]: https://crates.io/crates/alloy-signer-local
[alloy-signer-local]: https://crates.io/crates/alloy-signer-local
[`alloy-signer-trezor`]: https://crates.io/crates/alloy-signer-trezor
[alloy-signer-trezor]: https://crates.io/crates/alloy-signer-trezor
[`alloy-signer-wallet`]: https://crates.io/crates/alloy-signer-wallet
[alloy-signer-wallet]: https://crates.io/crates/alloy-signer-wallet
[`alloy-transport`]: https://crates.io/crates/alloy-transport
[alloy-transport]: https://crates.io/crates/alloy-transport
[`alloy-transport-http`]: https://crates.io/crates/alloy-transport-http
[alloy-transport-http]: https://crates.io/crates/alloy-transport-http
[`alloy-transport-ipc`]: https://crates.io/crates/alloy-transport-ipc
[alloy-transport-ipc]: https://crates.io/crates/alloy-transport-ipc
[`alloy-transport-ws`]: https://crates.io/crates/alloy-transport-ws
[alloy-transport-ws]: https://crates.io/crates/alloy-transport-ws

<!-- generated by git-cliff -->
