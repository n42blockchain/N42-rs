# Protocol conformance on native chains, 2026-11

Status 2026-11-19, branch `fix/protocol-conformance`.

An inventory listed places where the N42 Rust node may not follow the Osaka and Amsterdam rules that its dependencies (reth v2.11.0, evm2) and Ethereum provide. This page records, for each item:

- what the Rust node does, verified in code and pinned by a test;
- what gov5 does on a native (HotStuff/APoS) chain;
- what was changed, or the decision that is needed.

gov5 was read at main `73311004` (`/data/n42-build/gov5-wt-main`). Nothing in gov5 was changed.

Consensus rules were not changed. Where gov5 differs, or where a fix would change a rule, the item is written up as a decision.

## Summary

| # | Item | Rust node (verified) | gov5 on a native chain | Action |
| --- | --- | --- | --- | --- |
| 1 | EIP-7934, the 8 MiB RLP block bound | Not applied anywhere on a native chain: `HotStuffConsensus::validate_block_pre_execution` has no size check, and only reth's Ethereum consensus and the builder-validation RPC have one. The N42 builder budgets gas only, with no byte budget. Peers refuse a gossiped block that expands past `N42_MAX_GOSSIP_MB` (default 1 MiB). The block-by-hash/range stream allows 64 MiB. | Applied only in the Engine API `newPayload` handlers and the eth-el import paths, never on HotStuff import. The miner packs at most 9/10 of `MaxWireMessageSize` (min of the gossip and chunk caps), less 32 KiB and the header. | Not a gap. A test pins the behaviour: `hotstuff_consensus` `a_block_past_the_eip7934_bound_is_not_refused_on_a_native_chain`. The rule is stated below. Decision D1 covers the builder's missing byte budget. |
| 2 | EIP-7825, the 2^24 transaction gas cap | Enforced on every path. **Pool:** the cap comes from `evm_env(tip)`. **Ingest:** goes through the pool by default; in `N42_TX_INGEST_DIRECT` mode it goes to the queue and the builder drops the transaction. **Claimed build:** a wrapper around the builder's selection. **Builders, serial and parallel:** evm2's stock `prepare`. **Direct transfer and fast handler:** fall back to evm2, or wrap it. **Follower import, serial and parallel:** evm2's `prepare`. At Amsterdam the bound becomes EIP-8037's total cap of 2^32 - 1. | Pool and state transition: 2^24 at Osaka without Glamsterdam, 2^32 - 1 at Glamsterdam. | Not a gap. Tests added: `fast_handler` `the_transaction_gas_caps_bind_on_both_handlers`, `direct_transfer` `a_transfer_over_the_gas_cap_falls_back_to_evm2`, `payload` `a_transaction_over_the_eip7825_cap_is_neither_built_nor_imported` (serial and parallel build; serial and parallel import), and `n42_evm` `the_pool_rules_follow_the_amsterdam_execution`. Decision D2 covers includability under deferred execution. |
| 3 | EIP-7702, type 4 | Type-4 transactions are built and imported. The follower's batches stop at the first type-4 transaction (`import_key`: no authorization list), and the rest of the block runs in the serial tail. The parallel builder produces the serial builder's block. The pool admits them; the binary ingest decodes them. | Admitted by the pool (structure and authority checks from Prague). The binary ingest refuses type 4 (its protobuf decoder has no SetCode case). On native chains execution skips `checkSetCodeTxShape` (no create, non-empty list, Prague). The parallel processor has no per-type routing. | Not a gap on the Rust paths. Test added: `payload` `type_4_transactions_take_the_serial_paths_and_give_the_stock_block`. Its block holds a valid authorization delegating to a contract, an invalid one (another chain id) beside one forged by another key, a transfer to the delegated account that runs the contract's SSTORE, and plain transfers before and after. Serial build = parallel build; stock import = parallel import (tail 4); the delegation, the nonce and the slot are checked. The flood tool was not extended. Decision D3. |
| 4 | EIP-4844 blob transactions | **Pool:** admits them from Cancun when they come with a sidecar (RPC or ingest network form). **Builder:** includes them and sets `blobGasUsed` from the body. **Import:** `validate_cancun_gas` checks the header against the body. **Validator:** rebuilds the versioned hashes for `newPayload` from the transactions (`h2-consensus` `execution_data_for_block_with_bal`). No sidecar is gossiped or needed. An all-Rust fleet therefore builds and imports blob blocks end to end. **Deferred includability** counts blob gas in the sender's worst-case cost and does not refuse the transaction. | **Pool:** admits them; the binary ingest admits them without a sidecar. **Miner:** no blob handling. The HotStuff `FinalizeAndAssemble` writes `blobGasUsed = 0` whatever the body carries. **Import:** HotStuff does not verify blob header fields. **Execution:** applies the blob shape and fee checks. **Deferred includability:** refuses blob transactions. | **Decision D4.** gov5 does not refuse blobs on native chains, so nothing was refused here. A mixed fleet would split on a gov5 block carrying blobs: its header says 0 and the Rust node refuses it. Under deferred execution it would split on a Rust block carrying blobs: gov5's includability refuses it. |
| 5 | Amsterdam gaps | **G7:** closed by reth v2.11.0. The pool's intrinsic rules come from `N42EvmConfig`'s environment, so EIP-2780 applies from `glamsterdamTime`. **G4:** closed by evm2. Its Amsterdam version has `tx_total_gas_cap` = 2^32 - 1, checked in `prepare` and loaded by the pool. **G6:** unchanged. **EIP-7997:** absent. **EIP-8038 and EIP-8246:** in evm2's Amsterdam version, which native chains run from `glamsterdamTime`. | **G4 and G7:** as Rust now. **G6:** gov5 skips the EIP-3860 initcode cap on native chains before Amsterdam. **EIP-7997:** absent. **EIP-8038 and EIP-8246:** implemented with no native gate. | Tests: `n42_evm` `the_pool_rules_follow_the_amsterdam_execution` (G7, G4, and 7825 at the pool), and the item-2 tests (G4 in execution). `GLAMSTERDAM_EXECUTION_PARITY.md` was updated: G4 and G7 are closed, and a 7997 row was added. No code change was needed. Decision D5 is G6. |
| 6 | EIP-7910 `eth_config` | Was not registered at all ("method not found"). Upstream's Ethereum add-ons merge `EthConfigHandler`; the N42 add-ons did not. On a native chain reth's handler would also report a fork id and system contracts from before Amsterdam, beside evm2's Amsterdam precompiles. | Refused on native chains: `errEthConfigNativeChain`, "eth_config is only defined for Ethereum fork schedules". | **Fixed.** A native chain now gets gov5's refusal, word for word, with code -32004. Any other chain gets reth's handler (`bin/n42/src/native_rpc.rs`, wired in `main.rs`). Test: `native_rpc` `eth_config_is_refused_with_gov5s_message`. |
| 7 | RPC on QMDB/HotStuff | See `docs/RPC_SURFACE_NATIVE.md`. Everything listed works except three: `debug_executionWitness` answered with Merkle-Patricia witness nodes that do not verify on QMDB; `eth_simulateV1` errors on a MobileAnchor-gated chain; and `eth_feeHistory`'s `gasUsedRatio` is one block late under deferred execution. | Not compared method by method. | **Fixed:** `debug_executionWitness` and `debug_executionWitnessByBlockHash` are refused on a QMDB chain, as `eth_getProof` is (test `native_rpc` `both_witness_methods_are_refused`). The rest are listed in the RPC page. |

## The native-chain block-size rule (item 1)

On an N42-native chain no consensus rule bounds a block's bytes. EIP-7934 is an Ethereum mainnet rule. Neither client applies it on HotStuff import, and it would refuse the bench chain's blocks of 150,000-200,000 transactions (more than 20 MB, with `osakaTime` 0).

Two things bound a block in practice:

- **The gas limit.** It is a consensus rule.
- **The block gossip cap,** `N42_MAX_GOSSIP_MB`: 1 MiB by default, set the same on every member. It is a network-wide setting, not a rule. A block whose snappy-decoded RLP is larger cannot travel by gossip: every peer refuses it (`h2-net` `decompress_block_gossip`), followers never import it, and HotStuff makes no quorum on it.

The block fetch streams (`block_by_hash`, `bodies_by_range`) carry up to 64 MiB, so a member that falls behind can still fetch a large block that has been committed.

gov5's miner sizes its blocks to stay inside the gossip cap. The Rust builder budgets only gas (decision D1).

## Decisions needed

- **D1, a byte budget in the Rust builder.** gov5's miner packs at most 9/10 of the wire cap, less 32 KiB and the header, so it never seals a block the gossip cap refuses. The Rust builder can seal one when the gas limit allows more bytes than `N42_MAX_GOSSIP_MB`, and that block stalls the view. Option (a) adds gov5's budget to the N42 builder: builder policy, not a rule, but it touches the bench builder's hot path. Option (b) keeps the operator rule that the gas limit and the gossip cap are set together, as the bench scripts do.
- **D2, the transaction gas cap under deferred execution.** Under deferred execution neither client's includability check (gov5's `deferred_includable.go`, Rust's `follower_import.rs` `scan_range`) checks EIP-7825 or the total cap. A leader that seals a transaction over the cap gets votes, and the block then fails execution, which the next header must report. Option (a) adds the cap to both includability checks at once: a rule change in both clients, needing a gov5 change first. Option (b) leaves it as is, since an honest builder never includes such a transaction.
- **D3, the type-4 shape on native chains.** gov5 skips `checkSetCodeTxShape` on native chains. A block with a type-4 transaction that is a creation or has an empty authorization list is therefore executed by gov5 and refused by the Rust executor and includability check. Neither client's pool admits such a transaction. Option (a): gov5 drops the native exemption, which is recommended because the shape is part of the transaction type. Option (b): the Rust node copies the exemption, which needs evm2 changes.
- **D4, blob transactions on native chains.** A native chain has no sidecar network, and gov5's HotStuff producer writes `blobGasUsed = 0` whatever the body carries. A gov5 block with blobs would therefore be refused by the Rust node. Under deferred execution, a Rust block with blobs would be refused by gov5's includability check. Option (a), recommended: refuse type 3 on native chains in both clients, in the pool, the ingest, the builder and block validation, behind `IsN42Native` / `is_n42_native`. Option (b): keep them, and make gov5's producer compute blob gas and the Rust includability check refuse blobs under deferred execution, as gov5's does.
- **D5 (G6), the initcode cap before Amsterdam.** gov5 exempts native chains from the EIP-3860 initcode cap before Amsterdam; evm2 enforces it. A creation with initcode over 49,152 bytes splits the clients. Option (a): gov5 drops the exemption. Option (b): the Rust node disables evm2's cap on native chains before `glamsterdamTime`, through the EVM version's `max_initcode_size`.

## Evidence

- **Tests.** The test names are in the table. They are run under `--lib --tests` for every touched crate; the result lines are in the commit log of this branch and the CI logs under `/data/n42-build/audit-notes/ci/conform/`.
- **gov5 citations, at `73311004`:**
  - `internal/api/engine_payload_validation.go:155-172`
  - `internal/miner/block_size.go:38-88`
  - `internal/p2p/encoder/ssz.go:22-66`
  - `internal/state_transition.go:497-509`
  - `internal/txspool/txs_pool.go:679-690`
  - `internal/deferred_includable.go:191`
  - `internal/consensus/hotstuff/adapter.go:834-842`
  - `internal/api/eth_config.go:86-126`
  - `internal/state_transition.go:577-581`
  - `common/transaction/transaction.go:236-275`
