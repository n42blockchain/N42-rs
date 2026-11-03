# Glamsterdam execution parity: gov5 against revm 43 on N42-native chains

Status 2026-11-03. Workstream B of `docs/PLAN_OPEN_ITEMS_2026_11.md` (items B1 and B2).
It follows `docs/HEADER_FIELD_PARITY.md` 7.1, "Glamsterdam execution".

## 1. The problem

gov5 runs its Amsterdam state transition on every chain where `IsGlamsterdam(time)` holds,
N42-native chains included:

- `internal/state_transition.go:613` returns `transitionAmsterdam`, which lives in
  `internal/state_transition_amsterdam.go`.
- `params/config_rules.go:203`: Glamsterdam implies Osaka, not Fusaka.

The Rust node read `glamsterdamTime` only for the header tail (slot number and registry
root). The EVM ran Osaka.

Round mv4f showed the effect on the gated devnet. On every block with a transfer,
gov5's sidecar re-execution got a different receipts root. The gas used still matched,
because a transfer to an existing account costs 21,000 under both rule sets; the
EIP-7708 transfer log was the difference.

Sources compared:

- **gov5:** `/data/n42-build/gov5-wt-main` at 39cff9ce.
- **revm 43:** `revm-handler` 43.0.3, `revm-context` 43.0.3, `revm-context-interface`
  43.0.2, `revm-interpreter` 43.0.2, `revm-primitives` 43.0.0.
- **alloy-evm 0.39.0:** `eth/block.rs`, `block/system_calls`.
- **reth v2.8.1.**

"Native" means gov5's `IsN42Native` (`params/config.go:473`): consensus `hotstuff` or
`apos`, or a `hotstuff`/`apos` section in the config. gov5 has only three native-specific
branches that touch Amsterdam:

- **No EIP-7928 block access list:** `UsesEIP7928AccessList` (`config.go:466`).
- **Direct EIP-4788 writes:** `UsesDirectBeaconRootWrites` (`config.go:458`).
- **The pre-Amsterdam initcode-cap exemption** (`state_transition.go:646`). It does not
  apply at Amsterdam.

Everything else in the Amsterdam transition applies to native chains exactly as written.

## 2. Rule-set audit

"Same" means the same constants and the same charge points for every shape listed.
Effects are for N42's shapes:

- transfer to an existing account (T)
- transfer creating its recipient (TC)
- ERC-20-like contract call (C)
- contract creation (CR)
- 0x50 Ed25519 transfer (A)
- block reward paid as withdrawals (W)
- the Prague system calls (S)

| EIP | gov5 on a native chain | revm 43 / alloy-evm 0.39 at `SpecId::AMSTERDAM` | Verdict | Effect on N42 shapes |
| --- | --- | --- | --- | --- |
| 8037 state gas | CPSB 1530. New account 120 B (183,600), new slot 64 B (97,920), delegation 23 B (35,190), code 1 B/byte. The reservoir is `gas - intrinsic - min(2^24 - intrinsic, ...)`. Charges take from the reservoir first and spill into regular gas. A failed creating call refunds its charge. (`state_transition_amsterdam.go:131-193`, `vm/state_gas.go`, `eips_amsterdam_gas.go`) | Same table (`gas_params.rs:318-333`, `eip8037.rs`). Reservoir from `initial_gas_and_reservoir(gas, cap)`. Same refund on a failed first frame or CALL/CREATE (`handler.rs:519-529`). | same | TC: 204,600 receipt gas (21,000 regular + 183,600 state). C: +97,920 per new slot. CR: +183,600 + 1,530/byte. A: as T. |
| 8037 block gas | Header `gasUsed = max(Σ txExec, Σ txState)`, where `txExec = max(usedBeforeRefund - txState, floor)` (pre-refund). Receipts cumulate the post-refund `gasUsed`. (`state_processor.go:374,411`, `common/gaspool.go:96-121`) | `max(block_regular, block_state)`, where `block_regular = max(spent - state, floor)` (pre-refund). Receipts cumulate `tx_gas_used` (post-refund, floored). (`alloy-evm eth/block.rs:203-280,339`, `result.rs:263-293`) | same | Header gasUsed ≠ last cumulative whenever a block has state gas (TC, C, CR). |
| 8037 inclusion | `CheckGasAmsterdam(min(gas, 2^24), gas)` against both dimensions. | `min(gas, cap) ≤ limit - regular` and `gas ≤ limit - state` (`eth/block.rs:211-235`). | same | The N42 builder's own budget is stricter (Σ tx gas): it can only leave transactions out, never build what gov5 refuses. |
| 8037 total tx gas cap | `gas > 2^32 - 1` is invalid: `MaxTxTotalGasEIP8037` (`state_transition.go:507`, pool `txs_pool.go:677`). | No total cap with 8037; only the regular part is capped (`validation.rs:150-160,301-310`). | **different** | None while the block gas limit is under 2^32 (every N42 genesis and the 480M bench tier). Gap G4. |
| 2780 intrinsic | 12,000 base; +3,000 to another account; +6,000 with value; creation +12,000; self-transfer 12,000; calldata 4/16; initcode 2/word (`state_transition.go:220-298`). | `eip2780_base_to_value_gas` with the same constants (`gas_params.rs:1089-1105`). | same | T 21,000; a zero-value call 15,000; a self-transfer 12,000; CR 24,000 + data. |
| 7623 + 7976 floor | `tokens = 4·len(data) + 4·(20·addresses + 32·keys)`, ×16, on the 2780 base (`floorDataGasAmsterdam`, `state_transition_amsterdam.go:69`). | 16/token, zero bytes counted as nonzero, access-list floor tokens ×4, anchored on the 2780 base (`gas_params.rs:337-349,1061-1066`). | same | Calldata-heavy calls pay 64 gas/byte as the floor. |
| 7981 access-list data | Per address 2,900 + 20·64; per key 2,000 + 32·64. | Same (`gas_params.rs:400-403`). | same | No N42 shape carries an access list. |
| 8038 state access | Cold account 3,000, account write 9,000, storage write 10,000, clear refund 11,616, CREATE 12,000, CALL value 11,300, EXTCODESIZE/COPY +100. | Same (`eip8038.rs`, `gas_params.rs:351-404`, `instructions.rs:128-138`). | same | C: SSTORE and CALL prices. CR: 12,000 access. |
| 7708 transfer logs | LOG3 from `0xff…fe`, topic `Transfer(address,address,uint256)`, data = amount. Emitted on CALL with value (depth 0 included) when caller ≠ callee, on CREATE with endowment, and on a SELFDESTRUCT sweep. Not for fees, rewards, withdrawals or system calls; no burn log. (`vm/eips_amsterdam.go:204-223`, `evm.go:324,565`) | `journal/inner.rs:503,597,709,732,1122`: same emitter, topic and data. Skipped for a self-transfer and a zero value. `BURN_LOG_TOPIC` is defined but never emitted. | same | T, TC, A: one log each (the mv4f receipts root). W: none (an `increment_balances`, gov5 `AddBalance`). |
| 7778 pre-refund block gas | Part of the 8037 settlement above. | Same. | same | — |
| 3529 refund cap | `min(usedBeforeRefund/5, refunds)`; the base includes state gas. | `inner_refunded` capped at `total_gas_spent/5`, state included. | same | C (slot clears). |
| 7954 code / initcode size | Max code 65,536; max initcode 131,072, enforced on native chains too at Amsterdam (`state_transition_amsterdam.go:116`, `evm.go:587`). | `eip7954::MAX_CODE_SIZE`/`MAX_INITCODE_SIZE` = 0x10000/0x20000 (`cfg.rs:462-488`). | same | CR. Before Amsterdam gov5 exempts native chains from the initcode cap and reth does not (G6, not part of this item). |
| 7825 tx gas cap | 2^24 only at `IsOsaka && !IsGlamsterdam`. | Skipped when 8037 is on (`validation.rs:150`). | same | — |
| 8246 SELFDESTRUCT | To self: no burn, no log. A destroyed account with a balance is kept as balance-only at the end of the transaction (`intra_block_state.go:1934-1963`). | `eip8246_clear_selfdestructed_accounts` (`journal/inner.rs:285`). To self keeps the balance. | same | No N42 shape self-destructs. |
| 7843 SLOTNUM | Pushes `header.SlotNumber` on a Glamsterdam header, else 0 (`internal/evm.go:84`). With the header-parity branch a native header carries slot = number. | `block_env.slot_num` from the header (import) or the payload V4 (Engine API). The builder used to read 0 (`NextBlockEnvAttributes.slot_number: None`). | **different (fixed)** | Only for a contract that reads SLOTNUM. Gap G3, fixed in `next_evm_env`. |
| 8024 DUPN/SWAPN/EXCHANGE | 0xe6/0xe7/0xe8, 3 gas, immediate decoding as in §7 of the gov5 inventory. | `instructions/stack.rs:61-100`, the same decoding. | same | No N42 contract uses them. |
| 7928 block access list | Off on native chains (`UsesEIP7928AccessList`). | Recorded only when reth's chain spec says Amsterdam (`with_bal_builder_if`, reth `payload/src/lib.rs:194`; payload validator). | same | The chain spec's Amsterdam is never activated from `glamsterdamTime`, so no BAL on native chains. |
| 4788 beacon root | Direct slot writes on native chains, no EVM (`blockhelp.go:193-224`). | The system call into the 4788 contract, with the Amsterdam system-call reservoir (`system_call.rs:44-47`). | same state | S: the same two slots. Parity predates Amsterdam; the reservoir covers the two SSTOREs. |
| 2935 history | A contract call at Amsterdam (direct write before), 30M + 1,566,720 reservoir (`blockhelp.go:282-318`). | Always the system call. | same state | S. |
| 7002 / 7251 requests | End-of-block system calls; code required. | Same (`system_calls/mod.rs`). | same | S. |
| 8282 builder requests | Amsterdam end-of-block calls to `0x0000BFF4…8282` and `0x000064D6…8282`, on native chains too. **Code is required, else the block is invalid** (`blockhelp.go:349-379`, `system_contract_registry.go:36-42`). | Gated on reth's chain-spec Amsterdam, so not run on a native chain (`system_calls/mod.rs:86`). | **different** | Every native Amsterdam block: gov5 refuses it, since no bundled native genesis deploys these contracts. Gap G1. |
| 7907 / 7873 / 7904 | Not on the Amsterdam path (the 7904 constants are dead). | 7907 constants unused at Amsterdam (7954 wins); 7873 is a transaction-type remnant. | same | — |
| 0x50 Ed25519 | No such type in gov5 (types 0-5). | Executed as a custom type: 2780 intrinsic, 7708 log. | N42-only | A: no gov5 counterpart; gated by `altSigTx`, which no gated genesis sets. |
| Parallel paths | `ProcessParallel`/`BuildParallel` fall back to serial at Glamsterdam; the miner's parallel fill is off; the transfer fast path cannot match (7708 logs). | The N42 parallel build, follower parallel/graft paths and fast transfer modelled Osaka (21,000, no log, gas = Σ). | **different (fixed)** | The bench paths (off by default) would build or verify wrong gas and receipts. Gap G5, fixed. |
| Pool intrinsic | 2780 intrinsic, no floor check, total cap 2^32 - 1. | reth's pool computes the intrinsic from its own Amsterdam flag (chain spec), so it stays Osaka. Its gas caps follow the EVM config. | different (admission only) | A zero-value call with gas in [15,000, 21,000) is refused by the Rust pool and accepted by gov5's. No consensus effect. Gap G7. |
| Deferred includability | Amsterdam `IntrinsicGas`, no floor (`deferred_includable.go:212`). | Osaka intrinsic, with the floor. | **different (fixed)** | Under deferred execution only. Now Amsterdam with 2780 info; the floor check is kept, since the executor enforces it. |

## 3. Gaps and where they are fixed

**G1 — EIP-8282 end-of-block calls (blocking; gov5 finding).** gov5 runs the builder
deposit and exit request calls at every Amsterdam block, native chains included, and
declares the block invalid when either contract has no code. None of the bundled native
genesis files deploys them:

- `n42_devnet_mobileanchor.json`
- `n42_devnet.json`
- the gov5 chain-94 copy

So **a gov5 member on the gated devnet refuses every block** (its miner and import both
call `ProcessExecutionBlockEnd`). The mv4f oracle did not show this, because the sidecar
re-executes transactions only. The Rust node does not run these calls on a native chain.

Fix side, a decision:

- **(a) gov5 gates 8282 off on native chains**, like 7928. This is recommended: the
  builder queues are an ePBS mechanism a HotStuff chain has no use for.
- **(b) The native genesis files deploy the two contracts, and the Rust executor runs
  the calls.** This changes genesis hashes. The calls also reset each queue's excess
  counter in state.

The A1 mixed round on `n42_devnet_mobileanchor.json` cannot pass before this is decided.

**G2 — chain-94 schedule (finding).** gov5 `7529e2e9` (2026-10-29, "unschedule
Glamsterdam on the staggered chains") removed `glamsterdamTime` from
`mainnet_qmdb_staggered.json`; it is on gov5 main. The Rust copy
`crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json` still carries
1798761600.

With this change the Rust node would switch on the Amsterdam execution, and the slot and
root header tail, at 2027-01-01 on chain 94, while gov5 never does. Regenerate the file
from gov5 main with `n42-gov5-genesis` (the genesis hash does not change) before chain 94
is run (A2).

**G3 — SLOTNUM in the Rust builder: fixed.** The builder's environment had `slot_num` 0
while the header (and so every importer and gov5) carried the block number.
`N42EvmConfig::next_evm_env` now sets `slot_num = parent + 1` under the Amsterdam
execution when the attributes name no slot.

**G4 — total transaction gas cap 2^32 - 1 (latent).** gov5 refuses such a transaction;
revm admits it. It is unreachable while every block gas limit is under 2^32. If a chain
ever raises its limit past that, add the cap to the builder and the import check. Not
implemented.

**G5 — Osaka-modelled parallel paths: fixed.**
`payload.rs` (`parallel_build`) and `follower_import.rs` (`follower_parallel`,
`by_ref_road`) fall back to the serial executor on an Amsterdam-execution block, as
gov5 does. The fast transfer path already refused Amsterdam (`fast_transfer.rs:469`).

**G6 — pre-Amsterdam initcode cap on native chains (pre-existing, out of scope).**
gov5 skips the EIP-3860 cap on native chains before Amsterdam; revm enforces it. At
Amsterdam both enforce EIP-7954.

**G7 — pool admission intrinsic (no consensus effect).** reth's vendored pool takes its
Amsterdam intrinsic from the chain spec. Making it follow the EVM configuration needs a
change to `vendor/dependency-repairs/reth-transaction-pool-2.8.1`, a dependency repair,
not an N42 feature crate. It is left as a known difference: the pool is stricter by up to
6,000 gas for zero-value calls, and it checks the floor.

## 4. What the Rust node does now (B1)

- **`reth_chainspec::qmdb::is_n42_native` / `glamsterdam_execution_active_at`**
  (`crates/chainspec/src/qmdb.rs`): gov5's `IsN42Native` and `IsGlamsterdam` together.
  `N42ChainSpec::glamsterdam_execution_active_at` (`crates/n42/header`) wraps it.
- **`N42EvmConfig`** (`crates/n42/engine-types/src/n42_evm.rs`): `evm_env`,
  `next_evm_env` and `evm_env_for_payload` raise the configuration to
  `SpecId::AMSTERDAM` with revm's mainnet Amsterdam gas table, EIP-8037 and EIP-2780
  when the block executes under gov5's Amsterdam. The executor, the builder, the follower
  import and the Engine-API payload path all take their environment from here. The pool
  takes its gas caps from it too.
- **Unchanged:**
  - `EthereumHardfork::Amsterdam` is never activated from `glamsterdamTime`, so the
    header and payload stay in the native shape: no BAL hash, no block access list, and
    the same N42Header tail rules.
  - A chain without `glamsterdamTime`, or one that is not native, gets exactly the
    environment `EvmEnv::for_eth_block` makes. `the_ungated_devnet_environment_is_unchanged`
    checks this field for field.
- **Deferred includability** (`follower_import.rs` `spec_for_intrinsic_gas`,
  `frame_scan::intrinsic_gas_shortfall_from`): Amsterdam intrinsic with the sender's
  EIP-2780 information.

## 5. Evidence

- **Unit tests:** `crates/chainspec/src/qmdb.rs`
  (`amsterdam_execution_needs_a_native_chain`, `bundled_native_genesis_files`) and
  `crates/n42/engine-types/src/n42_evm.rs` (`glamsterdam_execution_tests`).
- **Cross-client fixture:**
  - **Generator:** gov5 branch `test/glamsterdam-native-fixtures`,
    `internal/glamsterdam_native_fixture_test.go`. It executes one block of eleven
    transactions on the gated devnet genesis (chain 1143, `glamsterdamTime` 0) with
    gov5's serial execution, covering T, TC, a zero-value call, a self-transfer, an
    SSTORE 0→x, an inner CALL creating an account, a contract log, a creation with
    endowment, SLOTNUM, an unpaid creating transfer that halts, and a calldata-floor
    call. It writes `internal/testdata/glamsterdam_native/block1.json`.
  - **Copy:** `crates/n42/engine-types/testdata/glamsterdam_native/block1.json`.
  - **Comparison:** `the_gated_devnet_block_matches_gov5` executes it with `N42EvmConfig`
    and compares by value every receipt's status, gas, cumulative gas and logs, the
    header gas used, the gov5 receipts root, and the touched accounts' balance, nonce,
    code and slot 0.
- **Field oracle (workstream A):**
  - the gated devnet with transfers: packetd's re-execution receipts root must equal the
    header's (mv4f);
  - the mixed round A1, which first needs G1 decided.
