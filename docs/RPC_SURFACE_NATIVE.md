# RPC surface on a native (HotStuff + QMDB) chain

Status 2026-11-19. This is item 7 of `docs/PROTOCOL_CONFORMANCE_2026_11.md`.

The verdicts come from reading the code at reth v2.11.0. No devnet round was run.

## How the RPC is wired

- **Namespaces.** `eth`, `debug` and `trace` are reth's stock v2.11.0 modules, so whatever `--http.api` enables is served. The vendored `crates/n42/reth-rpc` is not in the build: its patch line in `Cargo.toml` is commented out.
- **The node's own add-ons.** `N42Node` wraps reth's `RpcAddOns` with `N42EthApiBuilder` (`crates/n42/engine-types/src/node.rs`). `bin/n42/src/main.rs` `extend_rpc_modules` adds the N42 namespaces and the refusals below.
- **Execution paths use the N42 EVM.** Every method that executes runs on `N42EvmConfig`: call, simulate, trace and access-list creation. So 0x50 transactions and gov5's Amsterdam execution, from `glamsterdamTime`, behave as they do on import. When an inspector is attached, the fast-transfer handler steps aside (`fast_handler.rs`), so traces see the full frames.
- **No usable Merkle-Patricia state.** A QMDB chain does not maintain the Merkle-Patricia trie. Its trie tables stop matching the chain at the first QMDB block (`n42_qmdb_reth::strategy`), and with `N42_HASHED_TABLES=off` the hashed tables are empty. A header's state root is QMDB's.

## Methods

| Method | Verdict | Why |
| --- | --- | --- |
| `eth_getBlockReceipts` | works | Receipts are stored and converted by `engine-types/src/rpc.rs`. The header commits to gov5's receipts root, but fetching receipts does not depend on it. |
| `debug_getRawReceipts` | works | Each receipt is EIP-2718 encoded, so a 0x50 receipt carries its 0x50 type byte. |
| `eth_blobBaseFee` | works (the minimum) | Headers carry blob fields from Cancun on, and every native genesis has a blob schedule. Excess blob gas stays 0, so the answer is 1 wei. |
| `eth_callMany` | works | Stock EVM path on `N42EvmConfig`. Historical state reads go through the overlay provider and its QMDB reader hooks. |
| `eth_createAccessList` | works | Same path as `eth_callMany`. |
| `debug_traceBlockByNumber` | works | Replays the block on `N42EvmConfig` over the parent's state. |
| `trace_block` | works | Same replay. The total difficulty is 0, so the chain is post-Paris and no block-reward traces are added. The dev block reward is paid as withdrawals and is not traced, as on Ethereum. |
| `eth_feeHistory` | works, with a caveat | `gasUsedRatio` reads the header's `gasUsed`. Under deferred execution (`deferredExecutionTime`) the header carries the parent's execution, so the ratio is one block late. Reward percentiles use the block's own receipts and are correct. |
| `eth_simulateV1` | works, with two caveats | (1) On a MobileAnchor-gated chain (`mobileAnchorTime` and `glamsterdamTime` active) it errors. The simulated block is assembled by `N42HeaderAssembler`, which needs the registry root the payload attributes would name ("carries mobileRegistryRoot, and the payload attributes named none", `assembler.rs`). (2) With `--rpc.compute-state-root-for-eth-simulate` the state root is computed from the stale Merkle-Patricia trie and means nothing. It is off by default. |
| `eth_getProof` | refused (-32004) | On a QMDB chain it is replaced by a refusal that points to `n42_getProof`, which serves QMDB twig proofs in gov5's v2 layout at persisted blocks (`bin/n42/src/qmdb_proof_ext.rs`). |
| `debug_executionWitness`, `debug_executionWitnessByBlockHash` | **refused (-32004), fixed here** | Before this change they answered with witness nodes built from the trie and hashed tables. Those are stale or empty on a QMDB chain, so the nodes did not verify against the header's state root. They are now refused like `eth_getProof` (`bin/n42/src/native_rpc.rs`). |
| `eth_config` (EIP-7910) | **refused on a native chain, fixed here** | Before this change the method was not registered at all ("method not found"): upstream's Ethereum node merges `EthConfigHandler`, but the N42 add-ons did not. reth's handler would also mislead on a native chain. The fork id and system contracts come from the chain spec, which never schedules Amsterdam from `glamsterdamTime`, while the precompiles come from evm2's Amsterdam. gov5 refuses the method on native chains (`internal/api/eth_config.go`, `errEthConfigNativeChain`). The Rust node now gives the same message with code -32004. A chain that is not native gets reth's handler. |

## Left open

- **`eth_getLogs` under deferred execution, not checked.** The header's `logsBloom` is the parent's, and reth's log filter skips blocks by header bloom, so a range query may miss logs. This needs a devnet check on a deferred-execution genesis.
- **`eth_simulateV1` on a gated chain.** It could take the latest registry root, as the leader does. That is left as is, because the root is a validator-side value.
- **The method references.** `docs/rpc.md` and `docs/jsonrpc/*` say nothing about these limits. This page is the reference until they do.
