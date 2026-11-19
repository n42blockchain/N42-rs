# Protocol conformance on native chains, 2026-11

Status 2026-11-19, branch `fix/protocol-conformance`; the decisions were implemented on `fix/conformance-decisions` (see "Decisions, decided and done").

An inventory listed places where the N42 Rust node may not follow the Osaka and Amsterdam rules that its dependencies (reth v2.11.0, evm2) and Ethereum provide. This page records, for each item:

- what the Rust node does, verified in code and pinned by a test;
- what gov5 does on a native (HotStuff/APoS) chain;
- what was changed, or the decision that is needed.

gov5 was read at main `73311004` (`/data/n42-build/gov5-wt-main`); the review itself changed nothing in gov5. The decisions changed gov5 on branch `fix/native-conformance-2026-11` (D3, D4).

The review changed no consensus rule; where gov5 differed, or a fix would change a rule, the item was written up as a decision. D3 and D4 then changed rules on native chains in both clients, together.

## Summary

| # | Item | Rust node (verified) | gov5 on a native chain | Action |
| --- | --- | --- | --- | --- |
| 1 | EIP-7934, the 8 MiB RLP block bound | Not applied anywhere on a native chain: `HotStuffConsensus::validate_block_pre_execution` has no size check, and only reth's Ethereum consensus and the builder-validation RPC have one. The N42 builder budgets gas only, with no byte budget. Peers refuse a gossiped block that expands past `N42_MAX_GOSSIP_MB` (default 1 MiB). The block-by-hash/range stream allows 64 MiB. | Applied only in the Engine API `newPayload` handlers and the eth-el import paths, never on HotStuff import. The miner packs at most 9/10 of `MaxWireMessageSize` (min of the gossip and chunk caps), less 32 KiB and the header. | Not a gap. A test pins the behaviour: `hotstuff_consensus` `a_block_past_the_eip7934_bound_is_not_refused_on_a_native_chain`. The rule is stated below. Decision D1: **done**, the Rust builder now has gov5's byte budget. |
| 2 | EIP-7825, the 2^24 transaction gas cap | Enforced on every path. **Pool:** the cap comes from `evm_env(tip)`. **Ingest:** goes through the pool by default; in `N42_TX_INGEST_DIRECT` mode it goes to the queue and the builder drops the transaction. **Claimed build:** a wrapper around the builder's selection. **Builders, serial and parallel:** evm2's stock `prepare`. **Direct transfer and fast handler:** fall back to evm2, or wrap it. **Follower import, serial and parallel:** evm2's `prepare`. At Amsterdam the bound becomes EIP-8037's total cap of 2^32 - 1. | Pool and state transition: 2^24 at Osaka without Glamsterdam, 2^32 - 1 at Glamsterdam. | Not a gap. Tests added: `fast_handler` `the_transaction_gas_caps_bind_on_both_handlers`, `direct_transfer` `a_transfer_over_the_gas_cap_falls_back_to_evm2`, `payload` `a_transaction_over_the_eip7825_cap_is_neither_built_nor_imported` (serial and parallel build; serial and parallel import), and `n42_evm` `the_pool_rules_follow_the_amsterdam_execution`. Decision D2 covers includability under deferred execution. |
| 3 | EIP-7702, type 4 | Type-4 transactions are built and imported. The follower's batches stop at the first type-4 transaction (`import_key`: no authorization list), and the rest of the block runs in the serial tail. The parallel builder produces the serial builder's block. The pool admits them; the binary ingest decodes them. | Admitted by the pool (structure and authority checks from Prague). The binary ingest refuses type 4 (its protobuf decoder has no SetCode case). On native chains execution skips `checkSetCodeTxShape` (no create, non-empty list, Prague). The parallel processor has no per-type routing. | Not a gap on the Rust paths. Test added: `payload` `type_4_transactions_take_the_serial_paths_and_give_the_stock_block`. Its block holds a valid authorization delegating to a contract, an invalid one (another chain id) beside one forged by another key, a transfer to the delegated account that runs the contract's SSTORE, and plain transfers before and after. Serial build = parallel build; stock import = parallel import (tail 4); the delegation, the nonce and the slot are checked. The flood tool was not extended. Decision D3: **done** (gov5 holds native chains to the shape, `7826b798`). |
| 4 | EIP-4844 blob transactions | **Pool:** admits them from Cancun when they come with a sidecar (RPC or ingest network form). **Builder:** includes them and sets `blobGasUsed` from the body. **Import:** `validate_cancun_gas` checks the header against the body. **Validator:** rebuilds the versioned hashes for `newPayload` from the transactions (`h2-consensus` `execution_data_for_block_with_bal`). No sidecar is gossiped or needed. An all-Rust fleet therefore builds and imports blob blocks end to end. **Deferred includability** counts blob gas in the sender's worst-case cost and does not refuse the transaction. | **Pool:** admits them; the binary ingest admits them without a sidecar. **Miner:** no blob handling. The HotStuff `FinalizeAndAssemble` writes `blobGasUsed = 0` whatever the body carries. **Import:** HotStuff does not verify blob header fields. **Execution:** applies the blob shape and fee checks. **Deferred includability:** refuses blob transactions. | **Decision D4: done** -- type 3 is now invalid on native chains in both clients (see below). Before it: gov5 did not refuse blobs on native chains, so nothing was refused here. A mixed fleet would split on a gov5 block carrying blobs: its header says 0 and the Rust node refuses it. Under deferred execution it would split on a Rust block carrying blobs: gov5's includability refuses it. |
| 5 | Amsterdam gaps | **G7:** closed by reth v2.11.0. The pool's intrinsic rules come from `N42EvmConfig`'s environment, so EIP-2780 applies from `glamsterdamTime`. **G4:** closed by evm2. Its Amsterdam version has `tx_total_gas_cap` = 2^32 - 1, checked in `prepare` and loaded by the pool. **G6:** unchanged. **EIP-7997:** absent. **EIP-8038 and EIP-8246:** in evm2's Amsterdam version, which native chains run from `glamsterdamTime`. | **G4 and G7:** as Rust now. **G6:** gov5 skips the EIP-3860 initcode cap on native chains before Amsterdam. **EIP-7997:** absent. **EIP-8038 and EIP-8246:** implemented with no native gate. | Tests: `n42_evm` `the_pool_rules_follow_the_amsterdam_execution` (G7, G4, and 7825 at the pool), and the item-2 tests (G4 in execution). `GLAMSTERDAM_EXECUTION_PARITY.md` was updated: G4 and G7 are closed, and a 7997 row was added. No code change was needed. Decision D5 is G6: **done**, the Rust node matches gov5's exemption. |
| 6 | EIP-7910 `eth_config` | Was not registered at all ("method not found"). Upstream's Ethereum add-ons merge `EthConfigHandler`; the N42 add-ons did not. On a native chain reth's handler would also report a fork id and system contracts from before Amsterdam, beside evm2's Amsterdam precompiles. | Refused on native chains: `errEthConfigNativeChain`, "eth_config is only defined for Ethereum fork schedules". | **Fixed.** A native chain now gets gov5's refusal, word for word, with code -32004. Any other chain gets reth's handler (`bin/n42/src/native_rpc.rs`, wired in `main.rs`). Test: `native_rpc` `eth_config_is_refused_with_gov5s_message`. |
| 7 | RPC on QMDB/HotStuff | See `docs/RPC_SURFACE_NATIVE.md`. Everything listed works except three: `debug_executionWitness` answered with Merkle-Patricia witness nodes that do not verify on QMDB; `eth_simulateV1` errors on a MobileAnchor-gated chain; and `eth_feeHistory`'s `gasUsedRatio` is one block late under deferred execution. | Not compared method by method. | **Fixed:** `debug_executionWitness` and `debug_executionWitnessByBlockHash` are refused on a QMDB chain, as `eth_getProof` is (test `native_rpc` `both_witness_methods_are_refused`). The rest are listed in the RPC page. |

## The native-chain block-size rule (item 1)

On an N42-native chain no consensus rule bounds a block's bytes. EIP-7934 is an Ethereum mainnet rule. Neither client applies it on HotStuff import, and it would refuse the bench chain's blocks of 150,000-200,000 transactions (more than 20 MB, with `osakaTime` 0).

Two things bound a block in practice:

- **The gas limit.** It is a consensus rule.
- **The block gossip cap,** `N42_MAX_GOSSIP_MB`: 1 MiB by default, set the same on every member. It is a network-wide setting, not a rule. A block whose snappy-decoded RLP is larger cannot travel by gossip: every peer refuses it (`h2-net` `decompress_block_gossip`), followers never import it, and HotStuff makes no quorum on it.

The block fetch streams (`block_by_hash`, `bodies_by_range`) carry up to 64 MiB, so a member that falls behind can still fetch a large block that has been committed.

gov5's miner sizes its blocks to stay inside the gossip cap, and since decision D1 the Rust builder does the same.

## Decisions, decided and done (2026-11-19)

Rust branch `fix/conformance-decisions`; gov5 branch `fix/native-conformance-2026-11` (from origin/main `26ab4c33`), commits `7826b798` (D3), `c553fef9` (D4), `bfde8543` (D2/D4 miner test); local, not pushed. Both clients agree on every rule below.

- **D1 → (a), a byte budget in the Rust builder.** `crates/n42/engine-types/src/byte_budget.rs` mirrors gov5's `internal/miner/block_size.go`: on a native chain a block's transactions take at most `cap/10*9 - 32 KiB - header` bytes, `cap` being `N42_MAX_GOSSIP_MB` read as `h2-net` reads it (default 1 MiB); a transaction counts its pooled encoded length plus its RLP string header (gov5's `txPayloadSize`). Builder policy only, not a validity rule. Serial loop: a transaction that does not fit is handed back to the pool for the next block with its sender's later ones (gov5's `packSkipAccount`); under 100 bytes left, or eight misses in a row, ends the block (`packStop`). Parallel step: the candidates are cut to the prefix that fits, the rest pushed back to the lookahead and returned to the queue; with the plan-ahead body the plan's byte sum (summed on the plan pool, `PreparedBuild::bytes`) is checked against the budget instead of each candidate. Nothing is encoded on the build path. A cut counts the block as full. Headroom at the bench tier: `fleet7-bench.sh` sets the cap to gas ceiling / 60M, 57 MiB at 3,423,000,000, a budget of ~53.76 MB; a block full of 21,000-gas transfers at that ceiling (163,000 of them, 116-139 bytes each) is 19-22.7 MB, at most 42% of it, so the budget does not bind on the bench (test `byte_budget` `the_bench_tier_has_headroom`). It binds only on bytes cheaper than ~330 per 21,000 gas, i.e. calldata.
- **D2 → (b), no rule change.** Covered already on the Rust side by `payload` `a_transaction_over_the_eip7825_cap_is_neither_built_nor_imported` (serial and parallel build). gov5: new test `internal/miner/fill_native_tx_rules_test.go` `TestFillTransactionsNativeOsakaSkipsOverCapAndBlobTxs` (a native Osaka chain's miner leaves a 2^24+1-gas transaction out); the pool is pinned by `TestValidateTx_TransactionGasCapByFork`.
- **D3 → (a), gov5 drops the native exemption from `checkSetCodeTxShape`.** History: the exemption came in with the check itself (gov5 `bbfc32a6`, 2026-10-29, "enforce EIP-3860 and EIP-7702 tx shape on Ethereum chains"), whose message gives the reason as keeping native chains' "existing rules so their history replays unchanged" -- a blanket precaution, not a case on chain 94 or 95. gov5's pool has refused a creation or an empty authorization list since `ecfcd65d` (2026-06-05); chains 94/95 run Prague from 1746612311 (2025-05-07), so a malformed type-4 transaction could only be in their history if a miner packed one before June 2026 -- not checked against chain data. The Rust executor already refused these shapes, so a Rust node would already have diverged on such a block. The native case of `TestApplyTransactionRejectsMalformedSetCodeTx` now expects `ErrSetCodeTxCreate` / `ErrEmptyAuthList`. Rust unchanged.
- **D4 → (a), type 3 is invalid on native chains in both clients.**
  - Rust: pool (`no_eip4844` on a native chain), binary ingest (`decode_frame` drops it, counted as `dropped_blob_native`), serial builder (refused before execution; the parallel step never takes one), block validation (`N42Consensus::validate_block_pre_execution[_with_tx_root]`, for APoS and HotStuff), and execution (the type-3 handler of a native chain's registry refuses, so import, `eth_call` and simulation too). The message is "blob (EIP-4844, type 3) transactions are not supported on an N42-native chain" (`n42_tx_types::BLOB_TX_ON_NATIVE_CHAIN`).
  - gov5: pool `validateTx` (`ErrTxTypeNotSupported` wrapping `ErrBlobTxOnNativeChain`, same words; the ingest server goes through the pool, its hint-only mode admits nothing), state transition `preCheck` (any blob message on a native chain, with or without hashes), miner (serial and parallel fill skip the account without executing it).
  - Includability under deferred execution, after the change: gov5's `deferredTxPlan` refuses a transaction whose type is 3 or that carries blob hashes ("blob transactions are not includable under deferred execution", was: hashes only); Rust's `scan_range` (and its oracle `group_by_sender`, and the frame summary, which declines a frame holding one) refuses every type-3 transaction with the same words (was: counted its blob gas and admitted it). Only type 3 carries blob hashes, so the two refuse the same set, on every chain where deferred execution runs.
  - Ethereum chains: unchanged in both.
  - History: gov5 never refused blobs on native chains (no such check in its git history); its HotStuff producer writes `blobGasUsed = 0`, and no N42 producer or tool sends type 3, so no native chain's history is expected to hold one.
- **D5 → (b), the Rust node drops evm2's transaction-level initcode cap on native chains before `glamsterdamTime`,** matching gov5's existing exemption: `native_tx_rules.rs` runs a creation (types 0-2) with initcode over 49,152 bytes through evm2's stock `prepare` minus `validate_create_initcode`, then the stock execution; the opcode cap, the word gas and EIP-170 stay, and from `glamsterdamTime` EIP-7954's 131,072 bytes apply in both. The pool applies no initcode cap on a native chain, as gov5's. gov5 unchanged. `GLAMSTERDAM_EXECUTION_PARITY.md` G6 is closed.

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

## Verification of the decisions (2026-11-19)

- **Mixed devnet** (three Rust validators and one gov5 member built from `fix/native-conformance-2026-11`,
  Rust natives from `fix/conformance-decisions`): round cd2a, 240 s, height 107, the gov5 member sealed 27
  blocks, head hash equal in both clients, 0 errors; round cd2b with `GOV5_DELAY=120`, 360 s, height 160,
  gov5 sealed 40, head hash equal, 0 errors. Ordinary traffic only: no blob transaction and no oversized
  initcode was submitted end to end; those rules rest on each client's unit tests.
- **Fleet pair CDN** against the root-job natives: 5.09M / 5.21M against 5.21M, par_exec 30.0 / 29.2
  against 28.9 ms, sealed_at 37.5 / 36.5 against 36.6 ms: inside leg noise (three legs; the fourth
  yielded the box).
- **Open before the gov5 branch is merged into gov5 main:** the history of chains 94 and 95 has not
  been scanned for type-3 transactions or for type-4 transactions without a recipient or with an empty
  authorization list (D3, D4). Until then gov5 main still accepts what the Rust node refuses.
