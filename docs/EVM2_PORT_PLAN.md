# n42-rs EVM layer on evm2: what is left, and the plan for it

Dated 2026-11-24, written against main `ad42dc269` (reth v2.11.0, evm2 rev `66687c18`).
Planning only: no code has changed. **Start condition: after mixed-client gate 3 passes**
(see section 7 for one step the owner may want earlier).

## 1. The premise has to be corrected first

The brief, the root `Cargo.toml` comment at line 399 ("revm 43 / alloy-evm 0.39 stay until the N42
EVM layer is ported to evm2") and the note added today in `docs/GLAMSTERDAM_EXECUTION_PARITY.md`
section 3 (commit `ad42dc269`, "n42-rs skips these calls only because alloy-evm 0.39 gates them on
the chain spec") all describe n42-rs as still running revm 43 / alloy-evm 0.39. **It does not.**
The port was done in workstream F and merged on 2026-11-06:

- `6703c576f merge: reth v2.9.0 port, revm replaced by evm2 (upgrade/reth-v2.9.0)`.
  `docs/RETH_2_9_0_UPGRADE.md`: F3 shallow layer (bundle types, `EthExecutorSpec` dropped,
  `CachedReads` serde, 0x50 as `TxEnvelope::Eip1559`, `N42EvmConfig` on reth's `RethEvmFactory`),
  F4 a correct node on the stock evm2 handler, F5 the performance paths rebuilt on evm2 (gate E16:
  parity with v2.8.1 + X22, 4.66-4.82M against 4.68-4.91M), F6a the revm-era paths and the
  `legacy-revm-paths` feature deleted, F6 field gate passed (all-Rust devnet, gov5 mixed devnet with
  equal block hashes, the MobileAnchor mixed round, `roll --kill` at 90 s and 20 s).
- v2.9.0 → v2.10.0 (`0ed56c1da`) and v2.10.0 → v2.11.0 (`4a2317a8a`) needed no N42 EVM source
  change beyond a callback signature and `receipts()` (`docs/RETH_2_11_0_UPGRADE.md` "Code changes":
  "`N42BlockExecutor`, the fast handler, the direct transfer path, `parallel_build`, `graft_fold`,
  `batch_state` and the follower import needed no source change against evm2 `66687c18`").
- Later evm2-era performance work is merged on top (`perf/evm2-fees-in-exec` `7fc4e4df5`,
  `perf/evm2-par-exec` `84b9fe6b5`), and the 5.0-5.2M / 5.69M fleet legs of November ran on evm2.
- n42-26's own devlog (`docs/devlog-186-reth-2110-evm2-upgrade-20261119.md`, "调研结论") says the
  same: "n42-rs 2.9→2.11 几乎不需改 N42 代码", and it took `tx-types/src/evm.rs`, `n42_evm.rs`,
  `fast_handler.rs`, `direct_transfer.rs`, `batch_state.rs`, `graft_fold.rs`, `parallel_build.rs`
  and `parallel_common.rs` **from n42-rs**. The reference port runs the other way.

Evidence on this tree:

| Check | Result |
|---|---|
| `Cargo.lock` packages named `revm*`, `alloy-evm`, `op-revm`, `revm-inspectors` | **none**. `evm2 0.1.0` is used by `n42`, `n42-clique`, `n42-ef-tests`, `n42-engine-types`, `n42-qmdb-reth`, `n42-sharded-output`, `n42-tx-types`, `reth-chain-state`, `reth-engine-tree` |
| `use revm` / `revm::` / `alloy_evm::` in `crates/n42`, `bin/n42` | 12 / 6 / 2 lines, **all in `crates/n42/reth-rpc`**, which is not a workspace member and has been disabled since v1.9.3 (`Cargo.toml:715`) |
| crates whose `Cargo.toml` names `revm` or `alloy-evm` | `crates/n42/reth-rpc` only |
| `evm2::` lines per crate | engine-types 124, bin/n42 19, qmdb-reth 6, ef-tests 5, tx-types 1, sharded-output 1, clique 1 |
| `evm2::` lines per file (top) | `parallel_build.rs` 36, `n42_evm.rs` 26, `follower_import.rs` 16, `direct_transfer.rs` 13, `payload.rs` 12, `fast_handler.rs` 10, `native_tx_rules.rs` 7, `output_shards.rs` 5, `frame_scan.rs` 5, `batch_state.rs` 4, `graft_fold.rs` 3 |
| files using `reth_evm::` / `reth_evm_ethereum::` | engine-types 13 / 5, bin/n42 4, clique 3, ef-tests 2 / 2, tx-ingest 2, tx-types 1, mobile-sdk 1 |

So there is no EVM port left to do. What is left is small, and one item in it is a live gap that
the "alloy-evm still gates it" belief has been hiding:

1. **The EIP-8282 end-of-block calls are not gated on native chains today** (section 2).
2. Stale revm-era declarations in `Cargo.toml` and the vendored repairs (section 4, step S3).
3. Three documents that now say the wrong thing (step S0).

## 2. The EIP-8282 calls on n42-rs main, as they are

evm2 `66687c18`, `crates/evm2/src/block/ethereum/execution.rs:383-450`
(`post_execution_system_call_state_changes`): with `context.system_calls` set and
`spec_id.enables(PRAGUE)` it runs the EIP-7002 and EIP-7251 calls, and with
`spec_id.enables(SpecId::AMSTERDAM)` (line 422) the builder deposit and builder exit calls at
`0x0000BFF46984E3725691FA540A8C7589300D8282` and `0x000064D678505AD48F8CCB093BC65613800E8282`.
The spec id is the executor's own (`block/ethereum/mod.rs:204`, taken from the EVM), there is no
hook and no rule in `EthBlockRules` to turn the calls off.

n42-rs runs that executor unmodified: `N42BlockExecutor` (`crates/n42/engine-types/src/n42_evm.rs:54-208`)
wraps reth's `EthBlockExecutor`, which wraps evm2's. And `N42EvmConfig::spec_at`
(`n42_evm.rs:455-464`) raises the spec to `SpecId::AMSTERDAM` on a native chain past
`glamsterdamTime`; profile 1 (`n42Profile: 1`, `amsterdamTime: 0`) is Amsterdam from block 0
(`reth_chainspec::qmdb::glamsterdam_time`, `qmdb.rs:157-168`). Therefore **on every profile-1 block
and every MobileAnchor-devnet block n42-rs makes the two 8282 calls today.**

Why nothing has shown it:

- No native genesis deploys code there (V1 `genesis_8s.json` allocs only 7002, 7251 and 2935;
  `n42_devnet_mobileanchor.json` and the chain-94 copy none). evm2's `system.rs` doc: "Calling an
  address without code succeeds as an empty call and produces no state changes."
- An empty call returns empty output; `Requests::push_request_with_type` omits a type-only
  request and `requests_hash` hashes only `len() > 1` entries (alloy-eips 2.5.0 `eip7685.rs:79-143`).
- Hence gov5 vectors V1/V3/V4/V5/V6/V8, the F6 mixed rounds and mv4h4b2 all agree.

Why it is still a defect:

- The standard says off: `docs/MIXED_PRODUCTION_STANDARD.md` D2 ("no EIP-8282 calls"), gov5
  `UsesEIP8282BuilderRequests(time)` = Glamsterdam and not `IsN42Native` (branch
  `fix/native-no-eip8282`, 3d25f36d), and n42-26 is gating them now (uncommitted work on
  `feat/evm2-no-8282-native`, a vendored evm2 with `EthBlockExecutor::set_eip8282_builder_requests`).
- The off state rests on an empty address, which a user can change: the predeploys go in by Nick's
  method (n42-26's note), and native chains admit pre-EIP-155 transactions
  (`native_tx_rules.rs:94`). From the first block with code there, n42-rs makes calls gov5 does
  not: the contracts' system-call writes change the state root. A paid queue entry also adds a
  0x03/0x04 request, which changes the requests hash that AM25 makes a deferred field. A user could
  split the chain.
- `docs/GLAMSTERDAM_EXECUTION_PARITY.md` G1's "No Rust change: the Rust node never ran them on a
  native chain" was true on 2026-11-03 under alloy-evm 0.39 and stopped being true on 2026-11-06.

## 3. The four behaviours the change must keep

(a) **EIP-8282 calls off on native chains** (gov5 and the standard): the new explicit gate,
    section 5. On a non-native chain (Ethereum mainnet shape, `n42-ef-tests`) the calls stay as
    evm2 makes them.

(b) **Block `gas_used` stays the EIP-8037 block figure** (`max(regular, state)`, standard B13).
    evm2 sets `separate_block_gas` from `evm.version().feature(EIP8037)` (`mod.rs:205`, `:293`), not
    from the executor's spec id, and `final_block_gas_used` reads only that flag and the two
    counters. The gate below changes only the spec id. V5's B13 block (state gas the larger) is the
    proof.

(c) **AM25 and the deferred fields stay byte-identical.** The 7002 / 7251 calls and the EIP-6110 log
    scan must still run (spec still enables PRAGUE). `requestsHash` stays the deferred
    EIP-7685 hash of the parent's execution. stateRoot / receiptsRoot / logsBloom / gasUsed are
    carried per A10. The proof is V3 / V5 unchanged, plus V5's AM25 request block, the one that
    produces one withdrawal request and one consolidation request.

(d) **Performance paths.** The gate touches only the block finish, so per path:

| Path / knob | Where | Touched by the gate? | Risk |
|---|---|---|---|
| Parallel build (`N42_PARALLEL_BUILD`, `N42_PARALLEL_BUILD_THREADS`, batches, early seal, plan body) | `parallel_build.rs`, `payload.rs`, `frame_blocks.rs`, `output_shards.rs` | its finish goes through `N42BlockExecutor::finish_*` (fold after the inner finish) | low: one extra `set_spec_id` per block. The early-seal path that writes `EMPTY_REQUESTS_HASH` (`parallel_build.rs:1301`, `payload.rs:2113`) is unaffected |
| Follower graft / parallel import (`N42_FOLLOWER_GRAFT`, `N42_FOLLOWER_PARALLEL`, copy-aside) | `bin/n42/src/follower_import.rs`, `graft_fold.rs`, `batch_state.rs` | same finish | low, but it must be **tested**: a follower that kept the calls would disagree with its leader only once code is at the addresses |
| Direct transfer (`N42_BATCH_DIRECT_TRANSFER`-class knobs, `evm2_direct_hits`) | `direct_transfer.rs` | no (per transaction) | none |
| Fast handler (registry handler for transfers) | `fast_handler.rs`, `native_tx_rules.rs` | no | none |
| Sender caches (`N42_ALTSIG_SENDER_CACHE`, ingest recover cache) and 0x50 (`N42_ED25519_BATCH`) | `tx-types`, `tx-ingest` | no | none |
| Deferred execution (check / vote / import split, `N42_FOLLOWER_*`) | `fields_at_seal.rs`, `built_executions.rs`, `engine_validator.rs` | reads the finished output only | the AM25 vector covers it |
| QMDB changes (`changes.rs`), persistence, `roll --kill` | `qmdb-reth` | no | none |

## 4. Steps, proofs and estimates

Estimates are **engineer-days for one engineer who knows `n42_evm.rs`**. They exclude box-queue
time and wall-clock of rounds owned by other lanes. Assumption: the `set_spec_id` route of
section 5 holds. If it does not, and evm2 has to be vendored as n42-26 does, add 1-2 days to S1
plus 0.5 day per later evm2 bump.

| Step | Content | Proof | Estimate |
|---|---|---|---|
| **S0** | Correct the record. (1) Rewrite the `ad42dc269` note in `GLAMSTERDAM_EXECUTION_PARITY.md` §3: n42-rs is on evm2 and makes the calls, as no-ops, until S1. (2) Annotate G1's "No Rust change" line with the 2026-11-06 date and S1. (3) Replace the `Cargo.toml:399` comment. (4) Post a correction to n42-26 and gov5 in the HANDOFF file: n42-rs does **not** gate on the chain spec, and n42-26's `eip8282_builder_requests_active` doc comment repeats the wrong claim. (5) Ask the owner to update CLAUDE.md "Upgrading reth" (it still says v2.8.1 / revm 43 / alloy-evm 0.39); agents do not edit it | review | 0.25 |
| **S1** | The explicit gate (section 5): predicate `eip8282_builder_requests_active(genesis)` = `!is_n42_native(genesis)`, computed once in `N42BlockExecutorFactory`, carried by `N42BlockExecutor`, applied in both `finish_*` methods (and any post-execution entry reached through `Deref`) | S2 tests; `scripts/clippy-n42.sh` | 0.5-1 |
| **S2** | Tests (section 6): native with code at both addresses and a queued request (no call, no request, contract storage untouched, root equal to the no-call reference), the same block through every execution path, the non-native counterpart, gas_used / AM25 unchanged | the tests themselves, red before S1 | 1-1.5 |
| **S3** | Dependency hygiene, no behaviour change. Drop `revm`, `revm-*`, `op-revm`, `revm-inspectors`, `alloy-evm` from `[workspace.dependencies]` (`Cargo.toml:399-414`). Drop the `revm-bytecode_43_0_0` patch (`Cargo.toml:752`) and `vendor/dependency-repairs/revm-bytecode-43.0.0` if `cargo` reports the patch unused. Update `vendor/dependency-repairs/README.md` / `PROVENANCE.json`. Decide on `crates/n42/reth-rpc`, the last revm user: not a member, disabled since v1.9.3. Recommendation: delete it, with a note in `N42_CUSTOMIZATIONS.md`, or mark it historical | `Cargo.lock` byte-identical; `cargo check --workspace --tests` clean; `cargo tree -i revm` and `-i alloy-evm` empty | 0.5 |
| **S4** | Code gate | gov5 vectors **V1, V3, V4, V5, V6, V8 pass unchanged** (`qmdb-reth`, `engine-types` `profile1_vectors.rs` / `profile1_v5.rs`, `h2-consensus` V6, byte-exact `testdata/profile1/gov5/`). `cargo test -p n42-testing`. The workspace tests (engine-types, n42, qmdb-reth, tx-types, ef-tests, the ported-crate fixture set). The parallel-vs-serial equivalence tests in `parallel_build.rs` (`requests` asserted) and `follower_import_tests.rs` | 0.5 |
| **S5** | Field gate, all-Rust | All-Rust devnet (`scripts/devnet-fleet.sh`, 300 s, 4 validators: commits = views, timeouts 0, err 0). MobileAnchor devnet (`n42_devnet_mobileanchor.json`, native Glamsterdam). A profile-1 all-Rust round (`profile1-round.sh` on `genesis_8s.json`). **A profile-1 round with the 8282 predeploys put in mid-round** (a pre-155 Nick's-method deploy, or a genesis variant with the code in the alloc) plus a paid builder-deposit call: every validator keeps committing and the roots stay equal | 1-1.5 |
| **S6** | Mixed round with gov5 | The gate-2 shape (gov5 `vectors/V1/genesis_8s.json`, validators 0-1 gov5, 2-3 n42-rs, 8 s, 30 min), repeated with the S5 predeploy injection: block hashes equal on both clients, 0 refusals. Before S1 this injection splits the chain; after S1 it must not | 0.5-1 (+ gov5's script) |
| **S7** | Performance check (owner's perf lane runs it, not this stream) | **One fleet7 A/B pair against main**: `scripts/fleet7-bench.sh` at the current bench tier, X22 (`N42_PROFILE=x22`), secp256k1 flood. **One pair with `F7_FLOOD_ALG=ed25519`** (0x50 path). Metrics: TPS window 1 and total, occupancy, `sealed_at`, `par_exec`, follower import ms. Expectation: inside the A/A spread (about ±2.5%), since the gate is one `set_spec_id` per block | 0 (lane time) |
| **S8** | Cross-client vector | Propose a V5 case to gov5 (the vector author): a native block with code at both 8282 addresses and a queued builder request, which must produce no request, leave the contracts' storage alone and carry `sha256("")`. n42-rs adds it under `testdata/profile1/gov5/V5` once published. n42-26 runs the same case | 0.25 (+ gov5) |
| | **Total** | | **3.5-6** |

For comparison, the port the brief asked for was sized at 27-41 days in the v2.9.0 spike and was spent in
F3-F6 between 2026-11-03 and 2026-11-09.

Order: S0 → S1 + S2 (one branch; S2's tests written first, red on main) → S3 (separate branch, it
must leave `Cargo.lock` unchanged) → S4 → S5 → S6 → S7 → merge. S8 runs beside S5. Small commits,
one logical step each, pushed after each.

## 5. The gate, concretely

Route recommended for n42-rs: **reth's public `EthBlockExecutor::set_spec_id`**, no fork. reth
v2.11.0 `crates/ethereum/evm/src/executor.rs:121-124` documents it as "Sets the Ethereum fork used for
block system calls and deposit request processing". It forwards to evm2's
`EthBlockExecutor::set_spec_id` (`mod.rs:272`). That field is read by `apply_post_execution_changes`
(`mod.rs:311-372`) and the pre-execution calls (`mod.rs:480-488`); the EVM's own version is not.

```rust
// n42_evm.rs, in both finish_with_block_access_list and
// finish_with_prepared_block_access_list, before the inner finish:
if !self.builder_requests && self.inner.spec_id_enables_amsterdam() {
    // Native chain (standard D2, gov5 UsesEIP8282BuilderRequests): run the
    // post-execution system calls under Osaka's gating. Prague's 7002/7251
    // calls and the 6110 scan still run; the EVM version (EIP-8037 gas,
    // separate block gas) is untouched.
    self.inner.set_spec_id(evm2::SpecId::OSAKA);
}
```

(The spec check reads the executor's EVM spec, `self.inner.evm().spec_id()` or equivalent.
`builder_requests` is filled by `create_executor` from
`eip8282_builder_requests_active(chain_spec.genesis())`.)

- Predicate: `!reth_chainspec::qmdb::is_n42_native(genesis)` (`qmdb.rs:183-190`, gov5's
  `IsN42Native`; profile 1 included). It is gov5's rule exactly: there the calls run iff the chain
  is Glamsterdam and not native. n42-26's predicate (calls only when the chain spec carries reth's
  Amsterdam) gives the same result on every chain the three clients share. n42-rs keeps gov5's
  form because the standard and gov5 name nativeness, not a reth hardfork.
- The pre-execution calls (4788, 2935) are untouched: the gate is set at finish only.
- Why not n42-26's route? n42-26 vendors all of evm2 at `66687c18` as a dependency repair. n42-rs
  already patches evm2 through the `DaniPopes/evm2` URL (`Cargo.toml:721-730`), and a full evm2
  vendor would need a re-merge on every evm2 bump. Keep it as the fallback if a test in section 6
  shows that `set_spec_id(OSAKA)` changes anything besides the two calls. Long term: an upstream
  evm2 PR adding a `builder_requests` flag to `EthBlockRules` would serve both clients. Track it;
  do not wait for it.
- Every finish has to go through `N42BlockExecutor`. Today the engine-tree import, the payload
  builder, the parallel build, the follower import, `init_snapshot` replays and RPC tracing all get
  their executor from `N42EvmConfig`'s factory (construction sites: `n42_evm.rs`, `node.rs`,
  `payload.rs`, `parallel_build.rs`, `follower_import.rs`, `main.rs`, `qmdb-reth/src/strategy.rs`,
  `profile1_v5.rs`, `profile1_vectors.rs`). The risk is a caller that reaches the inner
  `apply_post_execution_changes` or `finish_segment` through `Deref`. None does today, by grep.
  S1 either stops exposing those through `Deref` or puts the gate in a helper that they also call.

## 6. Tests for the gate

In `crates/n42/engine-types` (beside `glamsterdam_execution_tests` in `n42_evm.rs`), built on V1's
`genesis_8s.json` as `profile1_v5.rs` builds its chain:

1. `native_chain_makes_no_eip8282_calls_even_with_code_deployed`: allocAdditions put the EIP-8282
   predeploy bytecode at both addresses (take it from reth v2.11.0
   `crates/ethereum/evm/src/execution.rs` test `collects_amsterdam_builder_requests` or from
   EIP-8282), with storage that holds one queued builder deposit. Execute a block. Expected: no
   0x03 / 0x04 request; both contracts' storage byte-equal before and after (queue head, count and
   excess not touched); state root equal to the root of the same block with the calls removed;
   `requests_hash` of the execution `sha256("")`.
2. The same block through each path: the payload builder (serial), the parallel build (batches on),
   the engine-tree import, the follower import (graft on and off), and the deferred-fields check
   (`fields_at_seal`). All outputs equal, field by field (`BlockExecutionResult`, bundle, QMDB root).
3. `non_native_amsterdam_chain_keeps_the_eip8282_calls`: the same alloc on a non-native genesis
   with reth's Amsterdam scheduled produces the 0x03 request and the contract's writes, as evm2 does.
   This guards against over-gating.
4. `the_gate_keeps_prague_requests_and_block_gas`: on the native block, a paid 7002 and 7251 call
   still produce their requests (AM25). `gas_used` is the EIP-8037 figure, with state gas the larger,
   as in V5's B13 block, equal to the value without the gate.
5. A pre-155 Nick's-method deploy of the two predeploys in block N, followed by a builder-deposit
   call in block N+1, on the native chain: block N+1's state root and requests equal those of an
   execution with the calls removed (the S5 / S6 field scenario as a unit test).
6. The reth-bump rule gains a line: after any evm2 rev move, tests 1-5 must pass before anything else
   is measured. A new spec-gated finish item in evm2 would show up here.

## 7. Start condition, and one exception to consider

The default is the owner's condition: **S1-S8 start after gate 3 passes**, so nothing moves under
gates 2 and 3. The gate is provably neutral on every genesis those rounds use (no code at the 8282
addresses; S4's unchanged vectors would show it), and the gate rounds run on closed test keys
where nobody deploys the predeploys. Gates 2-3 are therefore not exposed.

What the owner may want to decide earlier: until S1 lands, **any public native network that n42-rs
validators join can be split by one Nick's-method deploy**. If such a network will run before
gate 3 passes, S0 + S1 + S2 + S4 (about 2-3 days) could go in early as a correctness fix, because
they cannot change any execution result the gate rounds validate. S0 is documentation only. It can
go in now regardless, because the current text misleads n42-26 and gov5.

## 8. What to take from n42-26, and what not

- Take: its finding (evm2 gates 8282 on the spec id, `execution.rs:422`) and its point that the
  predeploys can be put in by Nick's method. Its behaviour-difference checklist (devlog "行为差异"):
  touched-but-unchanged accounts (n42-rs settled this as R3-E2), the restored-slot rule and the
  revert storage merge are already pinned by n42-rs tests. Re-run them in S4; do not re-port them.
- Do not take: the vendored evm2 (section 5) unless `set_spec_id` fails a test; its
  `eip8282_builder_requests_active` doc comment (it repeats the wrong claim about n42-rs); its
  leader-side perf fixes (devlog 2026-11-20: streamed batch merge, `MergedBatches` in bundle shape).
  Those repaired regressions in n42-26's own port; n42-rs's equivalents are already merged
  (`84b9fe6b5`, `7fc4e4df5`) and measured.
- Keep both clients on the same evm2 rev (`66687c18` on both today). Diverging revs would make a
  mixed n42-rs / n42-26 round test two EVMs as well as two clients.

## 9. Risks

1. **`set_spec_id` semantics drift.** The gate relies on evm2's executor spec id gating only
   system calls and request processing (true at `66687c18`). A later rev could tie something else
   to it. Mitigation: tests 1-5 run on every evm2 move (section 6, item 6); the vendored-evm2
   fallback is in section 5.
2. **A finish path that bypasses `N42BlockExecutor`.** A follower that keeps the calls while its
   leader drops them would agree on every block until code appears at the addresses, then split.
   Mitigation: test 2 covers every path; S1 closes the `Deref` route.
3. **Exposure window until S1** on any public native network (section 7).
4. **Adjacent, not in this plan's scope:** evm2 treats a 7002 / 7251 system call to an address
   without code as a successful empty call. AM25 says such a block is invalid, as on Ethereum, and
   gov5 refuses it. Profile 1's alloc and P4 make it unreachable today. Record it in the standard's
   status file as a known client difference, not a fix for this stream.
5. **Measurement noise.** S7's expected effect is below the A/A spread (about ±2.5%), so one pair
   can only show "no regression beyond the noise". Two pairs is the minimum; a difference under
   about 10% between single rounds is invisible (CLAUDE.md).
6. **Stale-document risk.** Three documents and the root manifest describe a revm-based n42-rs.
   Until S0 lands, peers plan against the wrong client (n42-26 already has).
