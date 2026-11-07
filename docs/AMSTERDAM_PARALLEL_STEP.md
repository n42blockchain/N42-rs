# The parallel step and the fast transfer on an Amsterdam chain (stream H)

Status 2026-11-06. Plan row H1 (`docs/PLAN_OPEN_ITEMS_2026_11.md`), the two F6 leftovers "The Amsterdam
parallel step" and "The fast transfer on an Amsterdam chain" (`docs/RETH_2_9_0_UPGRADE.md`).

Code base: main 0ed56c1da (reth v2.10.0, evm2 `592bf18c`). Sources read for this note:

- evm2 `crates/evm2/src/ethereum/{mod,eip1559}.rs` (`prepare_with_hooks`, `execute_prepared`,
  `intrinsic_and_floor_gas`, `eip2780_base_to_value_gas`, `initial_gas_and_reservoir`,
  `prepare_initial_frame`, `settle_initial_frame_gas`, `finalize_gas`, `default_settle_gas`);
- evm2 `crates/evm2/src/evm/mod.rs` (`execute_call_message`, `log_eip7708_transfer`) and
  `evm/tx.rs` (`TxResultExt`: `execution_gas_spent`, `state_gas_spent`, `tx_gas_used`);
- reth `crates/ethereum/evm/src/executor.rs` (`validate_transaction_gas_limit`,
  `execute_transaction_with_commit_condition`, `commit_transaction`, `final_block_gas_used`);
- N42: `fast_handler.rs`, `direct_transfer.rs`, `parallel_build.rs`, `payload.rs` (the step and its
  gate), `bin/n42/src/follower_import.rs` (the import gate), `n42_evm.rs` (`spec_at`,
  `glamsterdam_execution_version`), `docs/GLAMSTERDAM_EXECUTION_PARITY.md`.

## 1. Which Amsterdam this is

A native chain past gov5's `glamsterdamTime` executes under evm2's `SpecId::AMSTERDAM` with the
mainnet Amsterdam feature set (`N42EvmConfig::spec_at`): EIP-2780 intrinsic gas, EIP-8037 state gas,
EIP-7708 transfer logs, EIP-8246, the Amsterdam gas table. reth's own `EthereumHardfork::Amsterdam` is
never activated from `glamsterdamTime`, so:

- **No block access list is kept for execution.** The executor records BAL entries only when its
  BAL builder is enabled (`enable_block_access_list_builder`), which the payload builder does only
  under reth's Amsterdam (`payload.rs`, `is_amsterdam`), and the follower never does.
  `set_transaction_block_access_index` is a no-op without the builder. The earlier F6-leftover text
  ("a batch does not write block access list entries") applies to reth's Amsterdam only, which no
  N42 chain schedules; that case stays serial (section 4).
- **EIP-8282 is not run** on a native chain (gov5 `fix/native-no-eip8282`; the Rust executor never
  ran it). It is a block-end system call in any case, outside the transactions the step takes.

What does change per transaction is the gas, the receipt's logs, and one state read that becomes
order-dependent. The devnet that runs this today is `n42_devnet_mobileanchor.json`
(`glamsterdamTime` 0); chain 94 no longer schedules it (G2), but any chain that does needs the step.

## 2. What the serial Amsterdam execution does per plain transfer

For a call with no input and no access list from `caller` to `to` with `value`, `gas_limit`,
price `p` (settled) and tip `t = p - basefee`, the stock evm2 handler does, beyond the Prague/Osaka
path:

| # | Rule | Where in evm2 | Prague/Osaka | Amsterdam |
| --- | --- | --- | --- | --- |
| A1 | EIP-2780 intrinsic | `intrinsic_and_floor_gas` / `eip2780_base_to_value_gas` | 21,000 for any plain call | 12,000 base + 3,000 to another account + 6,000 with value: 21,000 with value, **15,000 without**, 12,000 to self |
| A2 | EIP-7623 floor | same, anchored on the 2780 base | 21,000 base, no tokens | the 2780 base (21,000 / 15,000), no tokens: never above the intrinsic |
| A3 | gas split | `initial_gas_and_reservoir` | `(gas_limit - intrinsic, 0)` | regular budget `min(gas_limit, 2^24) - intrinsic`, the rest the reservoir |
| A4 | EIP-8037 new-account state gas | `prepare_initial_frame` | none | value > 0 to an **empty** recipient (absent, or nonce 0, balance 0, no code): `spend_state(new_account_state_gas)` = 120 B x 1,530 = 183,600, reservoir first, then regular gas. If it does not fit, the transaction is a runtime out-of-gas halt (`runtime_oog_result`): all regular gas spent, nothing moved, the sender still pays |
| A5 | EIP-7708 transfer log | `execute_call_message` -> `log_eip7708_transfer` | none | value > 0 and `caller != to`: one LOG3 from `0xff..fe`, topics `[Transfer, caller, to]`, data the 32-byte value; in the receipt, so in the receipts root |
| A6 | settlement | `settle_initial_frame_gas`, `finalize_gas`, `default_settle_gas` | `tx_gas_used` = 21,000 | `total_gas_spent` = intrinsic + state gas; `state_gas_spent` = 183,600 or 0; `tx_gas_used` = `total_gas_spent` (no refund, floor not binding). The sender is refunded `(gas_limit - tx_gas_used) x p`, the beneficiary paid `tx_gas_used x t`: **a creating transfer pays 204,600 x p, its beneficiary 204,600 x t** |
| A7 | block gas | `EthBlockExecutor` | `gas_used` = sum of `tx_gas_used` | separate counters: `regular += execution_gas_spent`, `state += state_gas_spent`; header `gas_used = max(regular, state)`; receipts still cumulate `tx_gas_used` |
| A8 | inclusion check | `validate_transaction_gas_limit` (called by `execute_transaction*`, **not** by `commit_transaction`) | `min(gas_limit, cap) <= limit - cumulative` | `min(gas_limit, cap) <= limit - regular` and `gas_limit <= limit - state` |
| A9 | caps | `validate_tx_gas_limit_cap`, `validate_execution_gas_limit_cap` | `gas_limit <= 2^24` (Osaka) | no total cap; the 2^24 cap bounds the regular part only |

Nothing else in the Amsterdam handler touches a plain transfer: the delegation-target charge (A4's
neighbour in `prepare_initial_frame`) needs a recipient with an EIP-7702 delegation, which every
fast path already refuses as "has code"; EIP-8038 access costs are inside the 2780 intrinsic at
depth 0; EIP-8246 acts on SELFDESTRUCT; 7702 authorization state gas needs type 4.

## 3. What the batch path and the fast handler do not do today, and what each needs

The batch path is `parallel_build::execute_batches_into` (each batch: the direct path, else an evm2
EVM with the fast handler), then `commit_run` (receipts through `commit_transaction`, the cache
half), and the fold at `finish`.

### 3.1 Already right on Amsterdam, by construction

- **Receipts, logs, cumulative gas, the header's gas (A5-A7) on the evm2 path.** The batch EVM is
  made from the block's environment, so the stock handler inside a batch applies A1-A6 itself, and
  `commit_run` hands each result to the stock `commit_transaction`, which adds `execution_gas_spent`
  and `state_gas_spent` to the separate counters and builds the receipt (logs included) from the
  result. `finish` reports `max(regular, state)`.
- **The fee split.** The beneficiary's credit is part of each batch's bundle and the merge sums the
  credits, whatever the per-transaction amount.
- **No BAL bookkeeping** (section 1).

### 3.2 Needed on the batch path (per batch, checked or folded in transaction order at finish)

1. **"Ran no code" check.** A batch refuses a transaction that ran code (code can read another
   batch's accounts) by `tx_gas_used != 21,000`. On Amsterdam that check is wrong both ways: a
   creating transfer uses 204,600 (refused though plain), and a zero-value call has a 15,000
   intrinsic, so code costing up to 6,000 (a cold BALANCE) would pass. Needed: on Amsterdam,
   `execution_gas_spent == intrinsic(caller, to, value)` (A1). A halt at the runtime phase (A4 not
   affordable at a 21,000 gas limit) passes it, as a halted transfer does on Prague.
2. **Order-dependent emptiness (A4).** The state gas, and whether a creating transfer halts, depend
   on whether the recipient is empty *at that transaction*. A batch sees the parent plus its own
   transactions; the serial execution also sees every earlier transaction of other batches. The only
   way another batch changes a recipient's emptiness is by creating it (a value credit to an empty
   account; a debit cannot empty a sender, whose nonce is already above 0). So: per batch, collect
   the accounts its bundle created (original absent or empty); refuse the run (the block goes serial)
   if any account one batch created is the recipient of a transaction in another batch. Within a batch
   the order is the serial one. On Prague the same pair is harmless (equal gas, no log) and is not
   checked.
3. **The inclusion check (A8) on what the batches executed.** `commit_transaction` skips it. On
   Prague the builder's step only takes 21,000-gas transfers and counts them against the limit, which
   is the same check; on Amsterdam the state dimension can exceed the limit (183,600 per creation).
   Needed: before `commit_run`, the stock rule over the executed transfers in block order with their
   real `execution_gas_spent` / `state_gas_spent`; a failure refuses the step (builder: serial loop;
   follower: serial import, which refuses the block with the stock error if it is really invalid).
   The follower's Prague import has the same gap (it accepts a transfer whose gas limit exceeds the
   block's remaining gas, which the stock import refuses); left as it is here, see section 6.
4. **The builder's take.** It takes only 21,000-gas transfers (`transfer_key`); a creating transfer
   on Amsterdam needs at least 204,600 (`--gas 210000` in `tx_flood`, see the memory note on
   EIP-8037 gas). Needed on Amsterdam: plain transfers of any gas limit, cut before execution to the
   prefix that passes A8 with each transfer's worst case (regular 21,000; state 183,600 when its gas
   limit can pay it, else 0), so that the check in item 3 cannot fail on what the step built.
5. **Late receipts' block gas (A7).** `late_receipts` returns the sum of `tx_gas_used` as the
   block's gas (the early-seal path, `N42_EVM2_RECEIPTS_LATE`). Needed: `max(sum regular, sum state)`
   when EIP-8037 is on.
6. **The gates.** `payload.rs` (`parallel_build && !glamsterdam`) and `follower_import.rs`
   (`follower_parallel && !amsterdam_execution`) send every Glamsterdam block to the serial path. They
   become "not under reth's Amsterdam (BAL)". The early seal already excludes only reth's Amsterdam.

### 3.3 Needed on the direct path (`direct_transfer.rs`)

It refuses the block (`refusal`: spec, `EIP2780`, `EIP8037`). To model Amsterdam it needs:

- the intrinsic and floor per value class (A1, A2): with value and without;
- A4: when value > 0 and the recipient is empty, the state gas, applied only if
  `gas_limit - intrinsic >= 183,600` (else a fallback to evm2, which produces the halt);
- A5: the log in the result when `EIP7708` and `LOG_COLLECTION` are on (value > 0; the path never
  takes a self-transfer);
- A6: the fee and the reward on `tx_gas_used` (21,000 / 15,000 / 204,600), not 21,000;
- the result per transaction: `total_gas_spent`, `state_gas_spent`, the floor of its value class, the
  logs.

A feature set that is not "all of 2780, 8037 and 7708" or "none of them" keeps refusing.

### 3.4 Needed in the fast handler (`fast_handler.rs`)

`covers` excludes Amsterdam. The handler already computes the intrinsic, the floor and the split
through evm2's own functions with the version, so A1-A3 are right as they stand. It needs A4 (charge
the new-account state gas on the transaction tracker after the checks, before the transfer, and hand
the transaction to the stock `execute` when the charge does not fit, nothing written yet), A5 (emit
the log through `Evm::log` after the transfer, as `execute_call_message` does), and A6 (the frame's
result made from the tracker after the charge, settled with the charge as `charged_state_gas`).

## 4. What stays serial

- Blocks under reth's own Amsterdam (`is_amsterdam_active_at_timestamp`, BAL builder on): the step
  writes no BAL entries. No N42 chain schedules it.
- Every per-transaction refusal above lands where it does on Prague: the builder's serial loop or
  give-back, the follower's serial import.

## 5. Implementation and evidence

(Filled in by the commits of stream H; see the plan row H1.)

## 6. Findings outside the scope

- **The follower's parallel import skips the inclusion check on every fork.** `commit_run` commits
  through `commit_transaction`, which, unlike `execute_transaction`, does not call
  `validate_transaction_gas_limit`. A leader's block whose leading transfer has a gas limit above
  the block's remaining gas is refused by the stock import and accepted by the parallel import. On
  Amsterdam this note adds the check (3.2 item 3); on Prague/Osaka the behaviour is left unchanged,
  as the brief requires, and the fix (the same check, cheap) is for the coordinator to schedule.
