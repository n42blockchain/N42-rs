# Porting list: n42-rs profile-1 code into n42-26

Date 2026-11-24. Author: n42-rs session (read-only survey, no builds, nothing run).
Sources read: standard `/data/n42-build/wt-docs/docs/MIXED_PRODUCTION_STANDARD.md` (AM1-AM23 override),
n42-26 review `.artifacts/profile1-reply/n42-26-reply-v0.2.md` §4-§5, the 04:15 / 04:25 posts in
`HANDOFF-gov5-performance-5m-2026-10-15.md`, vectors under `/data/blockchain/wr-logs/qs-scratch/profile1/vectors/`.

Paths: `RS` = `/data/n42-build/wt-docs` (n42-rs main 86e3f63da). `N26` = n42-26 main 4831e77 as checked out in
the worktree `/home/n42/src/n42/n42-26/.artifacts/reth-upgrade-2110/n42-26-p1` (branch `feat/profile1-genesis`).
`N26-WIP` = the UNCOMMITTED files in that worktree (written 2026-11-24 04:20-04:27, after the 04:25 post).

## 0. Three facts to read first

1. **The checkout at `/home/n42/src/n42/n42-26` is stale.** Its `main` is 5847275 on reth v2.8.1 (revm 43,
   `reth-source.lock` `upstream_tag: v2.8.1`) and does not contain 4831e77. n42-26's real main (4831e77) is on
   **reth v2.11.0 with evm2** (`reth-source.lock` in the worktree; root `Cargo.toml:127-130` pins evm2 rev
   66687c18), the same upstream as n42-rs (`RS/Cargo.toml:272`, tag v2.11.0). Both are edition 2024,
   rust-version 1.97 (`RS/Cargo.toml:3-4`; n42-26 `Cargo.toml:34-35`, toolchain 1.97.1). The edition-2021 notes
   in `RS/docs/N42_26_PORT.md` §"Edition-2021 adaptations" are history: the let-chains that port rewrote can be
   left as they are in n42-26.
2. **n42-26 has already started steps 1 and 2 (uncommitted).** N26-WIP: `crates/n42-chainspec/src/profile1/`
   (`config.rs` 446 lines: closed key lists, `Profile1Config::from_genesis`, `parse_dev_block_reward`;
   `header.rs` 334: `Profile1Header` 24 elements, `Profile1Extra`, `seal_hash`/`seal`/`verify_seal`;
   `mod.rs` 342: `PROFILE1_FORBIDDEN_ENV`, `qmdb_genesis_tree`, `check_profile1_alloc`,
   `profile1_genesis_header`), `crates/n42-consensus-service/src/profile1_header.rs` (431:
   `validate_profile1_header`, `check_profile1_vote_time`), `bin/n42-node/src/chainspec_parser.rs`,
   `crates/n42-chainspec/tests/profile1_vectors.rs` (11 tests: V8 allowed keys, every V8 refused genesis,
   genesis_8s -> V1 genesis header, V1 headers hash/seal hash/seal, V1 layout refusals) with a copy of V1/V8
   under `crates/n42-chainspec/testdata/profile1/` (38 files). Not built or run by me. **Do not overwrite
   any of it with n42-rs code**; use n42-rs only as a second reference where a vector case fails.
3. **The stateRoot finding** (0xac68... vs 0x7eec...): see §3, step 1. Short form: the QMDB computation is the
   same in both clients; n42-26 main simply does not put the QMDB root into a `--chain <file>` genesis header.

## 1. Conventions to keep

- Licence: both workspaces are `MIT OR Apache-2.0` (`RS/Cargo.toml:5`, n42-26 `Cargo.toml:36`). n42-rs files
  start with `// Copyright (c) 2017-2025 N42 Contributors` + `// SPDX-License-Identifier: MIT OR Apache-2.0`
  (e.g. `RS/crates/n42/qmdb-state/src/alloc.rs:1-2`); n42-26 files carry no per-file header (e.g.
  `crates/n42-bmt-core/src/lib.rs` starts with `//!`). Recommendation: a file copied from n42-rs keeps its
  two header lines and gains one line `// Ported from n42-rs <path> at 86e3f63da`, as n42-rs did the other way.
- Commit and comment language English; n42-26 conventions otherwise (its CLAUDE.md, not inspected).
- Fixtures: compare vectors by SHA-256 of raw bytes; n42-rs keeps `SHA256SUMS.md` next to its V1 copy
  (`RS/crates/n42/h2-consensus/testdata/profile1/`).

## 2. Differences that will bite when moving code

| Area | n42-rs | n42-26 | Consequence |
| --- | --- | --- | --- |
| reth consumption | git tag v2.11.0 + vendored forked crates patched over the graph; profile-1 helpers live INSIDE the forked `reth-chainspec` (`RS/crates/chainspec/src/qmdb.rs`, used as `reth_chainspec::qmdb::*`) | local path `../reth` with an adapted patch series (`reth-source.lock`) | Everything under `reth_chainspec::qmdb` must move into `n42-chainspec` (N26-WIP already did this for the genesis part). |
| Header type | the whole node runs on `N42Header` (`RS/crates/n42/header/src/lib.rs:56`, 24 elements) through `N42Primitives` / `N42EngineTypes` | alloy `Header` + side registry `Gov5NativeHeader` (`N26 crates/n42-consensus/src/gov5_native_header.rs`, field 23 = registry root, wrong for profile 1) + N26-WIP `Profile1Header` | Functions taking `&N42Header` (header_rules.rs, header_profile.rs) need a type swap to `Profile1Header` or a thin trait. "adapt". |
| Tx envelope | `N42TxEnvelope` (0x50 AltSig) from `crates/n42/tx-types` | n42-26 `crates/n42-tx-types` (own 0x50 + frame) | V4 checks port as logic, not as types. |
| EVM | evm2 via `N42EvmConfig` (`RS/crates/n42/engine-types/src/n42_evm.rs:345`) | evm2 via `crates/n42-execution/src/evm_config.rs` (520 lines) | Same library version now; port the spec-raising logic, not the struct. |
| Consensus process | consensus in a separate `h2_validator` process driving `bin/n42` over the Engine API; deferred check in the EL (`follower_import.rs`, `hotstuff_consensus.rs`) | in-process orchestrator (`n42-consensus-service`, ~14.7k-line orchestrator per `N42_26_PORT.md`) | Deferred execution and sync are "different architecture, re-implement against vectors". |
| Protocol core | `crates/n42/h2-consensus/src/protocol/*` (15,665 lines) is a fork of n42-26's `n42-consensus/src/protocol/*` (9,679 lines) | origin | `VoteRules` and the gate sites copy back with renames (`n42_h2_primitives` -> `n42_primitives`, `ValidatorInfo` minimal type -> n42-26's). |
| libp2p | n42-rs own pin | git rev of 0.57.0 | Not needed for profile 1 unless h2-net code is moved; avoid. |

## 3. The porting list, in order

Each step names the standard items, the vector cases that prove it, the n42-rs source, what n42-26 has, the
distance, and MY estimate (one engineer who knows n42-26, full time; assumption per row).

### Step 1. Genesis: V8 + V1 genesis hash (0x188e9d93...90dc since AM24; 0x6f733745...7e4f before it)

Items: A1-A3, A5-A8, A15-A19, A22-A23, J3 (P4 closed keys), J4/AM10 (forbidden env), AM3 (requestsHash), B3
(ommers 0), B12 (element 22 gap), B11/AM12/AM16 (faucet non-zero, reward string, whole gwei).
Vectors: V8 `allowed-keys.json` and all 33 `refused/*.json` (`committee_pool_enabled`, `deferred_depth_2`,
`extra_data`, `gas_limit_mismatch`, `json_number_reward`, `legacy_*` (8), `max_timeout_below_base`,
`missing_*` (6), `nonzero_fork`, `profile_2`, `profile_string`, `reward_not_whole_gwei`,
`reward_over_u64_gwei`, `storage_only_alloc_entry`, `three_validators`, `unknown_config_key`, `unknown_key`,
`unknown_validator_key`, `zero_epoch_length`, `zero_faucet`, `zero_leader_tenure`, `zero_value_storage`); V1
`genesis` (fields, RLP, hash) from `genesis_8s.json`.

n42-rs:
- `RS/crates/n42/qmdb-reth/src/profile1.rs` (1,076 lines): `CONFIG_KEYS`:44, `ZERO_FORK_FIELDS`:73,
  `HOTSTUFF_KEYS`:94, `COMMITTEE_POOL_KEYS`:110, `VALIDATOR_KEYS`:113, `LEGACY_*_FIELDS`:118/141/155,
  `PROFILE1_DEFERRED_EXECUTION_DEPTH`:163, `MIN_VALIDATORS`:166, `ACTIVATIONS`:176, `Profile1Error`:197,
  `Profile1Config`:248 (`header_rules()`:284, `dev_block_reward_gwei()`:306), `profile1()`:317,
  `header_rules()`:584, `fixed_gas_limit()`:590, `max_block_bytes()`:596, refused env/flags `FORBIDDEN_ENV`:663,
  `FORBIDDEN_FLAGS`:680, `refuse_overrides()`:694, `refuse_process_overrides()`:744; tests 777-1048.
- `RS/crates/chainspec/src/qmdb.rs`: `is_profile1`:42, `state_scheme`:59, `qmdb_genesis_root`:368,
  `genesis_header`:382 (state root :388, `ommers_hash = 0`:398, `requests_hash = EMPTY_ROOT_HASH`:399,
  `block_access_list_hash = None`:400), `sealed_genesis_header`:409.
- `RS/crates/n42/qmdb-state/src/alloc.rs`: `validate_alloc`:39 (Q-S1), `changes_from_alloc`:54.
- `RS/crates/n42/h2-consensus/src/header_rules.rs` `validate_profile1_genesis_header`:534.
- Testdata: `RS/crates/n42/qmdb-reth/testdata/profile1/refused_*.json` (33) + `gov5/`;
  `RS/crates/n42/h2-consensus/testdata/profile1/{genesis_8s.json,header_profile_v1.json,SHA256SUMS.md}`.

n42-26 today: main `n42_chainspec_from_genesis` (`crates/n42-chainspec/src/lib.rs:438-450`) =
`ChainSpecBuilder::default().genesis(genesis).cancun_activated()` with chain id from `N42_CHAIN_ID`. N26-WIP
replaces this (see §0 fact 2): own closed lists, env refusal, alloc check, `profile1_genesis_header`.
Distance: **already being implemented natively; no copy needed.** Cross-check only: n42-rs's 33 refused files
vs N26-WIP's 38 testdata files (n42-rs has `refused_legacy_mobile_anchor_time`, `refused_legacy_pool_enabled`,
`refused_unknown_hotstuff_key`, `refused_missing_leader_tenure`, `refused_depth_not_implemented` that gov5's V8
dir lacks; worth adding).

**stateRoot finding.** n42-rs: genesis root = `QmdbForest::genesis(B256::ZERO, &changes_from_alloc(alloc)).root()`
(`qmdb.rs:368-371`), i.e. gov5's key derivation (`gov5_account_key`/`gov5_storage_key`) and account encoding
(`encode_gov5_account_value_into`, `RS/crates/n42/twig-core/src/qmdb_compat.rs:76`) over every alloc entry, one
sorted batch. n42-26: the same computation exists as `gov5_qmdb_genesis_tree` (`crates/n42-node/src/qmdb_state.rs:65`
on main; N26-WIP moves it to `n42-chainspec/src/profile1/mod.rs:175` `qmdb_genesis_tree`), but on main it is
called ONLY on the gov5-bootstrap paths (`bin/n42-node/src/main.rs:453,545`, compared against a gov5 range file).
A plain `--chain genesis_8s.json` start goes through reth's `ChainSpecBuilder`, whose genesis header carries
reth's Ethereum MPT root of the alloc. That is the 0xac68... value (inference from the code path; I did not
compute the MPT root to confirm). The two QMDB functions differ only in forms that do not change bytes on
profile 1: n42-26 writes code hash `B256::ZERO` for a codeless account where n42-rs writes `KECCAK_EMPTY`, and
both encoders treat either as "no code" (`qmdb_compat.rs:68` in n42-rs, `:60` in n42-26 — identical
`has_code` test); n42-26 skips empty accounts and zero slots, which profile 1 refuses at genesis anyway
(V8 `zero_value_storage`, `storage_only_alloc_entry`). N26-WIP's `profile1_genesis_header` uses the QMDB tree,
so it should produce 0x7eec60e5...; its test `genesis_8s_loads_to_the_v1_genesis_header` decides.

Estimate (mine): **1-3 days** to finish and land N26-WIP, assuming its vector tests pass or fail on small
items. Then wire the profile-1 genesis header into the node's actual chain spec/DB (the header reth stores
must be the 24-element one): +2-4 days, assumption: n42-26 already does a header rewrite for the gov5
bootstrap that can be reused (not inspected).

### Step 2. Headers: V1 (blocks 1-2 and 25 refusals)

Items: B1 (QC in Extra), B2/AM4 (seal), B3, B4 (timestamp >= parent, <= floor(now)+2), B5 (parentBeaconRoot =
committee evidence), B6 (rewards as withdrawals, order: reward function output, then coinbase, then faucet;
pinned in gov5's 04:09 post), B8/AM3, B9, B10 (element 23 = block number), B11/B12 (element 24 always
present, element 22 gap), B14 (base fee), A23 (gasLimit exact), E13 (header QC: commit domain, quorum,
ancestor).
Vectors: V1 `headers` (block 1 view 1 no QC; block 2 view 2 with block 1's CommitQC) and `refusals`: `extra
over 4096 bytes`, `extra without seal`, `encoded empty QC`, `QC view not below header view`, `QC in the vote
domain`, `QC below quorum`, `QC names a non-ancestor`, `seal by a non-leader`, `seal over a different header`,
`coinbase not the leader`, `difficulty 1`, `nonce 1`, `mixHash non-zero`, `ommersHash = empty-list hash`,
`timestamp before parent`, `withdrawalsRoot absent`, `requestsHash sha256 of nothing`, `requestsHash
empty-ommers hash`, `blobGasUsed 1`, `excessBlobGas 1`, `element 22 present`, `baseFee off by one`, `gasLimit
not hotstuff.gasLimit`, `timestamp beyond floor(now)+2`, `body rewards differ from withdrawalsRoot`.

n42-rs:
- `RS/crates/n42/h2-consensus/src/header_rules.rs` (564): `HeaderRules`:91 (`check_header`:143,
  `check_qc_ancestry`:163, `check_against_parent`:195), `Profile1Error`:211, `verify_profile1_qc`:347,
  `decode_profile1_extra`:373, `validate_profile1_header`:406, constant fields :446, `verify_profile1_seal`:464,
  `validate_profile1_against_parent`:479, `profile1_base_fee`:507, `profile1_timestamp`:527.
- `RS/crates/n42/h2-consensus/src/header_profile.rs` (1,518): `gov5_rewards_root`:86,
  `rewards_to_withdrawals`:111, `withdrawals_to_rewards`:135, `HeaderExtra`:149 (`encode`:181, `decode`:199),
  `seal_hash`:345, `seal_header`:356, `verify_seal`:372, `gov5_receipts_root`:411. (`is_empty_requests_hash`:143
  is the second spelling AM3 removes: do not port.)
- `RS/crates/n42/h2-consensus/src/committee_pool.rs` `parent_beacon_root`:246 (B5); genesis-side
  `CommitteePoolGenesis` `RS/crates/n42/qmdb-reth/src/hotstuff.rs:166`.
- `RS/crates/n42/header/src/lib.rs` `N42Header`:56 (24-element RLP).
- Where it runs on import: `RS/crates/n42/engine-types/src/hotstuff_consensus.rs` `HotStuffConsensus`:62, rules
  installed :86, `validate_header`:340 (profile-1 branch :415), `validate_header_against_parent`:406,
  pre-execution :560/:703.
- Tests: `header_rules_v1_tests.rs` (212 lines, the V1 cases), `header_rules_tests.rs` (366),
  `hotstuff_consensus.rs` `profile1_consensus()`:1317.

n42-26 today: B1 done (`crates/n42-network/src/gov5_block.rs:135-145,210-238`); committee pool
`crates/n42-consensus/src/committee_pool.rs` `parent_beacon_root`:389 (same origin as n42-rs's; the `enabled`
flag at :87-93 is touched by N26-WIP's diff); rewards `crates/n42-consensus/src/gov5_rewards.rs:36-73`; import
override `crates/n42-consensus/src/adapter.rs:516-581` (difficulty 0 or 1 at :78, requestsHash nil at :236-250,
blob fields H2 unchecked at :101; per the review). N26-WIP: `Profile1Header` with `seal_hash`/`seal`/
`verify_seal` (`profile1/header.rs:301-325`), `validate_profile1_header` (`profile1_header.rs:106`) and tests
`v1_headers_hash_seal_hash_and_seal`, `layout_refusals_of_v1_are_decode_errors`.
Distance: header layout and seal are **being implemented natively** (do not overwrite). What N26-WIP's test
list does not yet name, and n42-rs can serve as reference for: the QC refusals (`verify_profile1_qc`,
`check_qc_ancestry`: commit domain, quorum, ancestor walk), parent rules (`validate_profile1_against_parent`,
`profile1_base_fee`, `profile1_timestamp`), and `body rewards differ from withdrawalsRoot`
(`rewards_to_withdrawals` + `gov5_rewards_root`). "adapt": logic copies, `&N42Header` -> `&Profile1Header`.
Then the import wiring: n42-26's `adapter.rs` must call these on the live path (E13 today only in
`range_catchup.rs`, `observe` default).
Estimate (mine): **4-8 days**, assuming N26-WIP's header type round-trips V1 and only the rule set and the
import wiring remain.

### Step 3a. Amsterdam execution set + write sets: V3; tx validity: V4

Items: A4/A20/AM1 (`amsterdamTime: 0` = exactly the GLAMSTERDAM_EXECUTION_PARITY set: evm2 Amsterdam gas
table, EIP-8037, EIP-2780, SLOTNUM = block number, EIP-7954 initcode cap 131,072; no EIP-7928 BAL, no EIP-8282
end-of-block calls, no EIP-7997, direct 4788 writes), AM2/B15 (no 8 MiB cap), C2 (no blobs), C3, C5/C6, D3
(system caller leaf only if changed; none under Glamsterdam), D4, D5, A9.
Vectors: V3 `main.json` cases `empty-block`, `plain-transfer`, `contract-create`, `storage-set`,
`storage-reset-and-unchanged`, `a9-no-op`, `empty-account-touch`, plus `system_address_live.json`; carries
`genesisQmdbStateRoot`. V4 `transactions.json` cases `type-0-legacy`, `type-1-access-list`,
`type-2-dynamic-fee`, `type-3-blob`, `type-4-set-code`, `type-4-empty-auth-list`, `type-4-create`,
`type-5-post-quantum`, `type-6`, `type-0x50`, `type-0x51`, `type-0x5f`, `gas-at-block-limit`, `gas-at-cap`,
`gas-over-cap`, `initcode-at-cap`, `initcode-over-cap`. (gov5's PIN 1 / PIN 2 in its 04:07 post are still OPEN.)

n42-rs:
- Doc: `RS/docs/GLAMSTERDAM_EXECUTION_PARITY.md` §3 (G1-G7), §4, §5.
- Gate: `RS/crates/chainspec/src/qmdb.rs` `glamsterdam_time`:157 (profile 1 maps `amsterdamTime` to it),
  `glamsterdam_active_at`:172, `is_n42_native`:183, `glamsterdam_execution_active_at`:201.
- EVM: `RS/crates/n42/engine-types/src/n42_evm.rs` `N42EvmConfig`:345, spec raise :455-464 (Amsterdam without
  activating reth's `EthereumHardfork::Amsterdam`, so no BAL), `evm_env`:539, `next_evm_env`:546 (slot_num, G3),
  `evm_env_for_payload`:626; tests `glamsterdam_execution_tests`, `the_gated_devnet_block_matches_gov5` with
  fixture `RS/crates/n42/engine-types/testdata/glamsterdam_native/block1.json`.
- Initcode/native rules: `RS/crates/n42/engine-types/src/native_tx_rules.rs` (453; under profile 1 only the
  Amsterdam branch matters). Blob refusal: `RS/crates/n42/engine-types/src/consensus.rs` `refuse_blob_txs`:233.
- Write sets: `RS/crates/n42/qmdb-reth/src/changes.rs` `changes_from_execution`:96, `system_caller_leaf_at`:329
  (Prague and not Glamsterdam: on profile 1 always false); `changes_from_alloc` re-export.
- Includability (deferred, Amsterdam intrinsic): `RS/bin/n42/src/follower_import.rs` `spec_for_intrinsic_gas`:770,
  `RS/crates/n42/engine-types/src/frame_scan.rs` `intrinsic_gas_shortfall_from`:91.
- n42-rs has NO V3/V4 harness yet (no test references `V3/main.json` or `transactions.json`); n42-rs
  conformance to V3/V4 is itself unproven today. Port the logic, not a test.

n42-26 today: `crates/n42-execution/src/evm_config.rs` (520 lines; Amsterdam handling not inspected);
`crates/n42-node/src/native_payload.rs` turns on BAL when chain-spec Amsterdam is active (:105, :134) and
enforces `MAX_RLP_BLOCK_SIZE` at build (:227) and import (:447) (AM2: remove on profile 1); write sets
`crates/n42-node/src/qmdb_state.rs` `gov5_qmdb_operations`:117 (emits every non-`NotModified` account, i.e. the
gov5 replay-v2 rule; whether it matches A9/D3/D5 as V3 pins it is unverified, and its system-caller handling not
inspected); pool type gate `pool.rs:132-138` (per review).
Distance: EVM gate "adapt" (both evm2 on reth v2.11.0: the spec-raise logic of `n42_evm.rs:455-464` and
`next_evm_env` slot rule move almost verbatim into n42-26's config; keep reth's Amsterdam hardfork OFF in the
chain spec so `native_payload.rs` never builds a BAL). Write-set rules "adapt" (n42-rs `changes.rs` is n42-rs's
own code over `BlockChanges`; n42-26 maps a `BundleState` to `QmdbOperation`s directly: port the rules D3/D5/A9,
verify by V3). V4: re-implement as a pool + block-validity + includability check in n42-26, prove with V4.
Estimate (mine): **8-15 days**, assumption: evm2 in n42-26 exposes the same `SpecId::AMSTERDAM` gas table and
EIP-8037/2780 switches n42-rs uses, and V3's `genesisQmdbStateRoot` matches after step 1.

### Step 3b. Deferred execution, depth 1 (A10, B13, F7, AM19) — LONG POLE

Items: A10/O4 (header N carries N-1's state root, receipts root, bloom, gasUsed), B13, AM19 (Round-1 vote only
after the deferred check, includability against the state the block runs on, and the parent's import; Commit
vote only after OWN execution), E14 (latest/safe/finalized split), F7.
Vectors: V1 block 1 and 2 headers carry deferred fields (block 2's fields describe block 1 — from the V1
README; the cases are in `headers`), V3 blocks (consecutive executed blocks), V5 (gov5 has not published it;
announced for the equal-timestamp pair and an EIP-8037 state-gas block). No vector exercises the vote gate end
to end: the proof is step 5.

n42-rs:
- `RS/crates/n42/h2-consensus/src/deferred_depth.rs`: `ParentLink`:42, `UnsupportedDepth`:66,
  `expected_fields`:139, `check_carried`:155.
- `RS/crates/n42/qmdb-reth/src/executed_fields.rs` (367): the per-block record of executed fields a header is
  checked against; `RS/crates/chainspec/src/qmdb.rs` `deferred_execution_depth`:306 / `_at`:360.
- `RS/bin/n42/src/follower_import.rs`: `validate_against_parent`:568 (consensus check against the parent's
  fields this node filed itself), `published_ancestry`:1319, `import_foreign_block`:1896; tests
  `follower_import_tests.rs`.
- Settlement tags: `RS/crates/n42/h2-execution/src/settlement.rs` (`N42_SETTLEMENT_TAGS=split`).
- Design: `RS/docs/PHASE_D_DEFERRED_EXECUTION.md` (incl. 17.7).
n42-26 today: none on the H2 path (review §4 A10; `N42_DEFER_STATE_ROOT` is a bench zero-root). Its
build-on-output (`n42-consensus-service/src/el.rs:192`, review §6) is the natural place for the leader side.
Distance: **different architecture, re-implement against the vectors.** n42-rs's deferred check lives in the
execution layer (reth engine + a side record) behind an Engine-API process boundary; n42-26's orchestrator is
in-process. Reuse `deferred_depth.rs` verbatim (pure logic, no reth types) and read `executed_fields.rs` /
`follower_import.rs` for the rules and edge cases (restart, sibling rebuild, persisted labelling), not for code.
Estimate (mine): **15-30 days**; assumption: n42-26's engine post-execution comparison, QMDB root check and
RPC can be re-pointed to "N checked by N+1" without a reth patch; if a reth patch is needed, the upper end.

### Step 4. Consensus votes and QC: V6

Items: A13/AM19 gate, E6, E10/A14 (H2-v4 only), E11, E17, AM19 lock rules, A15/A22 (tenure, rotate-on-timeout),
AM5 (fixed set; refuse staged change), G5 (64 KiB).
Vectors: V6 `messages` (`proposal_v2`, `prepare_vote_v2`, `prepare_qc_v2`, `commit_vote_v2`, `decide_v2`,
`timeout_v10800`, `newview_tc_epoch_boundary`, `proposal_after_tc`) and `verdicts` (`round1_gate`,
`round1_refused_block`, `proposal_wrong_proposer`, `proposal_vote_domain_signature`,
`proposal_justify_foreign_set`, `lock_refuses_lower_justify`, `lock_moves_to_higher_justify`, `round2_gate`,
`prepare_qc_foreign_set`, `prepare_qc_legacy_domain`, `prepare_qc_commit_domain`, `decide_prepare_domain`,
`decide_foreign_set`, `decide_wrong_width`, `decide_valid`, `tc_epoch_boundary_follower`,
`tc_leader_proposes_on_high_qc`, `tc_foreign_set`, `tc_wrong_next_view`).

n42-rs:
- `RS/crates/n42/h2-consensus/src/vote_rules.rs` (111): `VoteRules`:26, `round1_needs_check`:40,
  `commit_vote_needs_own_import`:46, `progress_votes_allowed`:51, `direct_votes_allowed`:57,
  `vote_before_slot_allowed`:63, `legacy_settlement_allowed`:68, `finalized_needs_reported_persistence`:74,
  `repeat_parent_registry_root`:80.
- Gate sites: `protocol/proposal.rs:478,528,605,732,752`; `protocol/state_machine.rs:412` (field),
  `:1114`, `set_vote_rules`:1119; tests `state_machine_profile1_tests.rs`, `state_machine_rotate_tests.rs`.
- n42-rs has NO V6 harness yet (no reference to `consensus_messages_v6.json`).
n42-26 today: origin of the protocol core; H2-v4 Round 1 already import-gated with extends-justify
(`crates/n42-consensus/src/protocol/proposal.rs:420-441,590-660`, per review); rotate-on-timeout and genesis
leader schedule on main (4831e77, `validator/selection.rs`; N26-WIP extends it by 105 lines); equivocation
detection `protocol/voting.rs:10`; H2-v4 refuses set changes (`error.rs:143`, `quorum.rs:37-60`).
Distance: **same origin, copy with rename** for `VoteRules` and its call sites (types: `n42_h2_primitives` ->
`n42_primitives`, the minimal `ValidatorInfo` -> n42-26's). The gate's content (what "check" means) is step 3b.
Estimate (mine): **3-6 days** plus a V6 harness (2-3 days), assumption: V6's JSON messages decode with
n42-26's existing H2-v4 codec (`n42-network/src/h2_v4.rs`, origin of n42-rs `h2-wire`).

### Step 5. Follow a gov5 + n42-rs chain as a verifying non-validator node (AM6)

Items: SYNC §3 (anchors enforced, committed-only range serving, by-hash serves proposals, conflict halt fail
closed per gov5's 04:09 post), B11/AM12 (carry `mobileRegistryRoot`, no re-derivation), G2 (no legacy topics on
profile 1), E14, J4.
Proof: a mixed round on `genesis_8s.json` (equal hash at every height), no vector.
n42-rs:
- `RS/crates/n42/h2-node/src/sync_anchor.rs` (259; `SyncAnchorMode`:38), `sync_pipeline.rs` (787;
  `parse_pipeline`:87, `pipeline_from_env`:98, `stall_from_env`:108), `sync_safety.rs` (263; `Origin`:43,
  `Certified`:54, `HaltKind`:68, `SyncHalt`:87).
n42-26 today: range client `crates/n42-consensus-service/src/range_catchup.rs` (2,475 lines; `observe` default at
:60 per review), `/1` server with clean EOF `crates/n42-network/src/gov5_rpc.rs:158-248`, 64 MiB chunks
`:23-34`; no `/2`, no `commit_qc/1`, no state servers.
Distance: sync is **n42-26's own (keep it)**; port the conflict-halt rule as logic from `sync_safety.rs`
("adapt", pure types), flip anchors to enforce. `/2` + `commit_qc/1` are milestone 2.
Estimate (mine): **5-10 days** of integration and round debugging, assumption: steps 1-4 done and one mixed-round
slot on the box per 2-3 days.

### Step 6. Lead

Items: F1/A17 (pacing from `blockIntervalMs`), F2 (no empty skip), F3 (byte budget from `maxBlockBytes`), F6, F7
(seal before own execution of N is allowed, propose N+1 only after executing N), A23 (gas limit exact), B2 sign,
B4 stamp, B1 QC-less rule, I1/I2 (mobileverify) with AM23 fallback.
n42-rs:
- Seal: `header_profile.rs` `seal_header`:356; header assembly for a view `gov5_h2_header_for_view_with_qc`:790,
  `normalize_to_gov5_h2_with_header`:862.
- AM23 fallback: `RS/crates/n42/h2-node/src/mobile.rs:259-273` (a leader without a service repeats the parent's
  `mobileRegistryRoot`; switched by `VoteRules::repeat_parent_registry_root`).
- Mobileverify service: `RS/crates/n42/mobileverify` (5,755 lines; registry, StreamPacket V2, cohort
  certificates, hyper router; fixtures test `tests/gov5_fixtures.rs`), node side `h2-node/src/mobile.rs` (407).
  Spec `RS/docs/MOBILEVERIFY_V3_PARITY.md`.
n42-26 today: slot-grid scheduling (`consensus_loop.rs:53-100`), empty-skip `state_mgmt.rs:36-41`, builder gas
limit `gas_limit_with_target` (`native_payload.rs:106-107`), zero seal written, own mobile stack (`n42-mobile`,
StarHub QUIC, not wire-compatible) (all per review).
Distance: builder changes "re-implement" in n42-26's builder; AM23 fallback is a few lines ("copy");
mobileverify "copy with rename" is possible (the crate has no reth dependency, not verified in detail) but is
NOT required to lead thanks to AM23.
Estimate (mine): builder/lead **8-15 days**; mobileverify service **10-20 days** (deferrable past M1).

### Milestone-2 items (not on the path to following or leading at M1)

`bodies_by_range/2` + client, `commit_qc/1`, state-sync servers (W12, the review's L/XL), public serving (W4),
E15 persistence/RPC, J2 metrics, the 100-validator review (AM17, AM22: batched vote verification, non-quadratic
TC). n42-rs sources for these: `sync_pipeline.rs` (design reference only), not inspected further here.

## 4. Dependencies

1 (genesis) -> 2 (headers: needs the genesis header as parent) -> 3a (execution: block 1's state root is checked
against 3b's carried field) -> 3b (deferred: needs 3a's results to compare) -> 4 (Round-1 gate content is 3b's
check; `VoteRules` plumbing itself can land in parallel with 2) -> 5 (needs 1-4) -> 6 (needs 5 plus the builder;
mobileverify can trail thanks to AM23). V5 (not yet published) gates the end of 3a/3b.

## 5. Long poles

1. Deferred execution depth 1 on import and in the vote gate (3b): 15-30 days, different architecture.
2. Amsterdam execution parity + write sets proven by V3 (3a): 8-15 days, and n42-rs itself has no V3 harness
   yet, so the first V3 run may find work on both sides.
3. MobileVerify v3 service (10-20 days), off the critical path because of AM23.
4. Milestone-2 sync servers (W12).

## 6. My range (not a promise)

Follow (steps 1-5): about **6-11 weeks** of one engineer's work from today, of which steps 1-2 may shrink to
about 1-2 weeks because N26-WIP is already there. Lead (step 6 without mobileverify): **+2-3 weeks**.
Assumptions: one engineer who knows n42-26 full time; no reth bump during the work (both on v2.11.0); gov5
publishes V5 in time and closes PIN 1/PIN 2; mixed-round box time available; n42-rs code used as reference
and for pure-logic modules (`deferred_depth.rs`, `vote_rules.rs`, header rule functions), not as a node
transplant. This is close to n42-26's own 8-11 weeks to follow; the saving is mainly in steps 2, 3a and 4.

## 7. What n42-26 has that n42-rs lacks, and must NOT be overwritten

- N26-WIP profile-1 work (§0 fact 2), uncommitted in `.artifacts/reth-upgrade-2110/n42-26-p1`.
- Rotate-on-timeout + genesis leader schedule (4831e77; `validator/selection.rs`, `timeout.rs`).
- B1 QC embedding and its QC-less fallback (`gov5_block.rs:135-238`).
- Range catch-up client (`range_catchup.rs`) and the `/1` server with clean EOF (`gov5_rpc.rs`).
- Committee pool and gov5 rewards (`committee_pool.rs`, `gov5_rewards.rs`): same origin, already conformant.
- Equivocation detection + `n42_equivocations` RPC (`voting.rs:10`, `n42-node/src/rpc.rs:272,710`).
- The Native signing profile with a non-zero `changesHash` (`protocol/proposal.rs:16-60`): the candidate for
  AM5's future E2 design; line-2 keep.
- Line-2 / performance features: build-on-output (`el.rs:192`), `n42-parallel-evm`, `n42-jmt`, `n42-zkproof`,
  `n42-mobile` (StarHub), frame blocks, the in-process orchestrator, QMDB restart/rebase handling (1972b59).
  Per AM9 these stay, unreachable on a `"n42Profile": 1` genesis.

Not inspected: n42-26's Amsterdam handling inside `evm_config.rs`; its system-caller and 4788 write path; its
header rewrite into the reth DB; mobileverify's dependency list for a copy; rewards-list construction site in
n42-rs (only `rewards_to_withdrawals` was located).

## Note added at commit time (n42-rs main 6f0f75306)

Written against n42-rs main 86e3f63da. Since then n42-rs gained the vector harnesses this list
says it lacks: `crates/n42/engine-types/src/profile1_vectors.rs` runs gov5's V3 (write sets, QMDB
roots, genesis root and hash) and V4 (17 transaction verdicts); `crates/n42/h2-consensus/tests/profile1_v6.rs`
runs V6 (8 messages, 19 verdict cases). All equal gov5's. They are the harnesses to port for
steps 3a and 4. gov5's three V3/V4 pins are answered in the handoff file (a storage-only account
gets an account op; gas above the block limit is invalid; D4 in its reachable form).
