# Mixed production standard, profile 1: status per client

**2026-11-24 21:15 EST — gate 2 PASSED.** Mixed round 3 (gov5 v0/v1 + n42-rs v2/v3, genesis-mixed-3 0xe6b358e8…): heights 0..227 byte-equal on all four, each validator led 57-58 blocks, 0 refusals, timeouts only at startup. Round 2 (12:00) was void and found the n42-rs justify-extension defect (fixed, main d8185220d) and a gov5 rebuild-on-genesis defect (fixed, gov5 1d72bf1b). Open from round 3: A17 timestamp stamping point (gov5 stamps at build start, n42-rs at publication), proposal AM26.

As of 2026-11-24 (after the 05:05 EST post). Rules: `docs/MIXED_PRODUCTION_STANDARD_V1_RC.md` (v1.0-rc2).

Levels: `—` not done · `impl` implemented · `vec` the item's vector passes · `mix` a profile-1 mixed round
passed (no cell is `mix`: no mixed round on profile 1 has run) · `?` the client's own posts do not say.

Evidence rules: **n42-rs** from this repository's main (`5c7bc9562`; commit ids and paths below).
**gov5** and **n42-26** only from their own posts in
`/data/blockchain/wr-logs/HANDOFF-gov5-performance-5m-2026-10-15.md` (EST, 2026-11-24). gov5's
vector files are generated from gov5's code, so a gov5 `vec` means "gov5 produced the vector and its post says
so"; gov5's profile-1 work is on branches (`feat/profile1`, `feat/profile1-header`, `feat/profile1-tx`,
`feat/profile1-limits`), no post says they are merged. n42-26's profile-1 work is on branch
`feat/profile1-genesis` (fb298d5..fa6b125), "not yet pushed or merged" (05:05), and its header validator is
"a library function with vector tests; it is not yet called from n42-26's import or vote path" (05:05).

Post keys: gov5 — `g0252` (~02:52), `g0255` (~02:55), `g0307` (~03:07), `g0316` (03:16), `g0331` (03:31,
slice 1 + V8), `g0346a` (03:46, V1), `g0346b` (03:46, slice 5), `g0407` (04:07, V3/V4), `g0409` (04:09),
`g0442` (04:42). n42-26 — `n0415` (04:15), `n0425` (04:25), `n0505` (05:05), `AM13` (n42-26's own status post
as quoted in the standard).

> **AM24 (owner, 2026-11-24): requestsHash = `sha256("")`, standard genesis hash `0x188e9d93…90dc`.** n42-rs
> main (17b55fd0a) carries it with gov5's regenerated V1/V3/V4/V6. Every gov5 and n42-26 `vec` cell below was
> earned on the pre-AM24 vectors (genesis `0x6f733745…7e4f`) and holds for AM24 only once that client posts a
> pass on the regenerated ones (gov5: its PR #6 on `feat/profile1`; n42-26: its `feat/profile1-genesis`).

## Summary

82 rows (89 item ids; alias rows such as `A3 / E1` count once). Levels per client:

| Client | `vec` | `impl` | `—` | `?` | `mix` |
| --- | --- | --- | --- | --- | --- |
| gov5 | 41 | 13 | 2 | 26 | 0 |
| n42-rs | 53 | 24 | 2 | 3 | 0 |
| n42-26 | 25 | 5 | 12 | 40 | 0 |

- gov5: every published vector (V1, V3, V4, V6, V8) comes from gov5's code; its `?` are mostly consensus and
  networking items its posts do not cover (V6 is published but no gov5 post reports it).
- n42-rs: V1, V3, V4, V6, V8 pass with no difference (04:28 post); open: E15, J2, three `?`, the sync servers.
- n42-26: V1 and V8 pass in a library on an unmerged branch (05:05); Amsterdam, deferred execution, the AM19
  gate, V3/V4/V6 and production are still ahead.
- Vectors V2, V5, V7, V9 and the cut V8 genesis are not published; so gate 1 is not complete for any client.
- **Next gate: gate 2 — the first idle mixed round, gov5 (validators 0-1) + n42-rs (validators 2-3) on
  `V1/genesis_8s.json`, 30 min at 8 s. Owners: gov5 and n42-rs together; it needs gov5's profile-1 branches on
  a runnable binary.**

## Table

Alias rows (`A3 / E1` …) are one row: the second id is defined by the first.

| Item | gov5 | n42-rs | n42-26 | proof / where |
| --- | --- | --- | --- | --- |
| A1 | vec | vec | vec | V1 genesis hash (`0x188e9d93…90dc` since AM24; the posts quoted were on `0x6f733745…7e4f`): gov5 g0346a; n42-rs `engine-types` genesis-hash test (1661b773a), `--chain-id`/`--genesis` refused (`qmdb-reth/src/profile1.rs` FORBIDDEN_FLAGS); n42-26 n0505 "header equals V1 … byte for byte" |
| A2 | vec | vec | vec | V8 closed key list: gov5 g0331; n42-rs `profile1.rs` CONFIG_KEYS / HOTSTUFF_KEYS, test vs gov5 V8 (7f45b0537); n42-26 n0505 "key lists equal allowed-keys.json" |
| A3 / E1 | vec | vec | vec | V8 `three_validators`, `unknown_validator_key`; gov5 g0331; n42-rs MIN_VALIDATORS + V8; n42-26 n0505 (all 33 refused) |
| A4 / D1 | vec | vec | — | V3/V4 executed on Amsterdam: gov5 g0407; n42-rs `engine-types/src/profile1_vectors.rs` (23893b81d); n42-26 n0505 "Still to do: Amsterdam set (AM1)" |
| A5 | vec | vec | vec | V8 `missing_state_scheme`; V3 genesis QMDB root; n42-26 n0505 (QMDB genesis root equal) |
| A6 | vec | vec | vec | V1 `genesis`; n42-rs `chainspec/src/qmdb.rs` genesis_header (72b1c21f9); n42-26 n0505 |
| A7 | vec | vec | vec | V8 `storage_only_alloc_entry`, `zero_value_storage`: gov5 g0331 + g0409 (adding n42-rs's cases); n42-rs ab8396bc6 + `refused_*` files; n42-26 n0505 |
| A8 | vec | vec | impl | V8 reward/faucet cases + V3 reward ops: gov5 g0331, g0407; n42-rs V8 + V3; n42-26 n0505 V8 reward cases only, V3 not run |
| A9 / C8 | vec | vec | ? | V3 `a9-no-op` + storage-only pin: gov5 g0407; n42-rs V3 (04:28 post, 23893b81d); n42-26 V3 not run (n0505 "then V3/V4") |
| A10 | impl | impl | — | depth 1, V8 `deferred_depth_2`; carried-field check has no vector until V5: gov5 g0316 (CheckDeferredBlock); n42-rs `h2-consensus/src/deferred_depth.rs`, `bin/n42/src/follower_import.rs`; n42-26 n0505 "deferred execution" to do |
| A11 / C4 | vec | vec | ? | V4 `type-0x50/0x51/0x5f`, `type-5`, `type-6`; V8 `legacy_alt_sig_tx`: gov5 g0407; n42-rs V4; n42-26 genesis key refused (n0505 V8) but no transaction refusal reported |
| A12 | vec | vec | vec | V8 `legacy_frame_blocks`; n42-rs also refuses `N42_FRAME_BLOCKS`; n42-26 n0505 |
| A13 | ? | vec | — | V6 `round1_gate`, `round2_gate`, `round1_refused_block`: n42-rs `h2-consensus/tests/profile1_v6.rs` (696e6c07d), `h2-execution/tests/profile1_vote_gate.rs` (b5fa88cef); gov5 g0316 says it drops the header vote on profile 1 (plan), no post on V6; n42-26 n0505 "AM19 gate" to do |
| A14 | ? | vec | ? | V6 `prepare_qc_legacy_domain`, `decide_prepare_domain`: n42-rs V6; gov5 g0255 plan only; n42-26 no post |
| A15 / E3 | vec | vec | vec | V8 `zero_leader_tenure`, `missing_*`; n42-26 n0505 "tenure … from the genesis" |
| A16 | vec | vec | vec | V8 `max_timeout_below_base`, `missing_mandatory_field`; n42-rs `--timeout-ms` refused |
| A17 | impl | impl | impl | gov5 g0346b "pacing = wait until parent first held + blockIntervalMs"; n42-rs cc71c34e2, `--block-interval-ms` refused; n42-26 n0505 "consensus config … from the genesis" |
| A18 | vec | vec | vec | V8 `zero_epoch_length`; V6 `tc_epoch_boundary_follower` (n42-rs) |
| A19 | vec | vec | vec | V8 `committee_pool_enabled`; V1 block 2 `parentBeaconRoot` |
| A20 | vec | vec | — | V1 elements 23/24 + Amsterdam via V3/V4; n42-26 Amsterdam to do (n0505) |
| A21 | vec | vec | vec | closed key list refuses `fastPropose` & co. (V8 `unknown_key`); n42-rs LEGACY_HOTSTUFF_FIELDS |
| A22 / E4 | impl | vec | impl | gov5 g0252 (on main, from view 0 under n42Profile); n42-rs `h2-consensus/testdata/rotate_on_timeout_vectors.json` (SYNC §10.4) + V6 `tc_*` (458ebe44d, 08e94c7f1); n42-26 4831e77 (n0415) + n0505 "rotate-on-timeout is on from view 0" |
| A23 | vec | vec | vec | V1 refusal "gasLimit not hotstuff.gasLimit", V8 `gas_limit_mismatch`; gov5 g0346b; n42-rs `--builder.gaslimit` refused; n42-26 library (n0505) |
| B1 | vec | vec | vec | V1 headers + QC refusals: gov5 g0346a; n42-rs `h2-consensus/src/header_rules_v1_tests.rs` (a05d7352e); n42-26 library, not wired (n0505) |
| B2 | vec | vec | vec | V1 sealHash/seal + "seal by a non-leader": n42-26 verifies in library; "producing sealed headers" to do (n0505) |
| B3 | vec | vec | vec | V1 constant-field refusals |
| B4 | vec | vec | vec | V1 "timestamp before parent" (import) and "beyond floor(now)+2" (vote); equal-timestamp pair for V3/V5 not yet published |
| B5 | vec | vec | vec | V1 block 2 `parentBeaconRoot` (V2 not published) |
| B6 | vec | vec | — | V1 "body rewards differ from withdrawalsRoot" + order pin (g0409); n42-26 n0505 "the B6 body check" to do |
| B7 | ? | impl | ? | V2 not published; n42-rs `h2-consensus/src/header_profile.rs` gov5_receipts_root |
| B8 | vec | vec | vec | V1 two requestsHash refusals |
| B9 | vec | vec | vec | V1 blob-field refusals |
| B10 | vec | vec | vec | V1 headers (element 23) |
| B11 | vec | vec | vec | V1 element 24 present, zero; gov5 presence check g0307; n42-rs repeat-parent fallback 9501762b0; n42-26 layout (n0505) |
| B12 | vec | vec | vec | V1 "element 22 present" refusal |
| B13 | impl | impl | — | V5 not published; gov5 g0316; n42-rs `deferred_depth.rs` check_carried; n42-26 to do |
| B14 | vec | vec | vec | V1 "baseFee off by one" |
| B15 | impl | impl | — | gov5 g0346b; n42-rs 78626c49f (`h2-net` set_max_block_bytes), `N42_MAX_GOSSIP_MB` refused; n42-26 still enforces 8 MiB (n0505, AM2) |
| B16 | ? | impl | ? | n42-rs: no count bound |
| C1 | vec | vec | ? | V4 types 0/1/2 (g0407); n42-26 V4 not run |
| C2 | vec | vec | ? | V4 `type-3-blob` |
| C3 | vec | vec | ? | V4 `type-4-*` |
| C5 | vec | vec | ? | V4 `gas-at-block-limit`, `gas-at-cap`, `gas-over-cap` + pin (g0409 / 04:28) |
| C6 | vec | vec | ? | V4 `initcode-at-cap`, `initcode-over-cap` |
| C7 | impl | impl | ? | gov5 g0407 "refused in pool, builder, block validity, includability, execution"; n42-rs pool is a subset (its 128 KiB size cap refuses the valid initcode-at-cap transaction: pool policy, 04:28) |
| D2 | vec | vec | — | V3 executed blocks; n42-26 Amsterdam to do |
| D3 | vec | vec | ? | V3 `system_address_live.json` |
| D4 | vec | vec | ? | V3 `empty-account-touch` (reachable form, pin 04:28) |
| D5 | vec | vec | ? | V3 `contract-create`, `storage-*` |
| D6 | vec | vec | impl | V3 QMDB roots; n42-26 genesis QMDB root equal (n0505), V3 not run |
| E2 | impl | vec | — | fixed set: gov5 g0331 (AM5), g0442; n42-rs a88afa0e8 + V6 `*_foreign_set`; n42-26 "refusing staged set changes (AM5)" to do (n0505) |
| E5 | ? | impl | ? | n42-rs pacemaker (not consensus-visible) |
| E6 | ? | vec | ? | V6 `proposal_*`, `lock_*`, `tc_leader_proposes_on_high_qc` |
| E7 | ? | vec | ? | V6 gates; n42-rs refuses `N42_VOTE_LOG_NOSYNC` |
| E8 | ? | impl | ? | n42-rs refuses `N42_VOTE_BEFORE_SLOT`, `N42_VOTE_BEFORE_IMPORT` |
| E9 / F8 | ? | impl | ? | n42-rs `h2-consensus/src/vote_rules.rs` progress_votes_allowed off on profile 1; `--straggler-grace-ms` refused |
| E10 | ? | vec | ? | V6 preimages |
| E11 | ? | vec | ? | V6 QC/TC wire bytes, `decide_wrong_width` |
| E12 | impl | vec | ? | V6 `decide_valid`; conflict halt: gov5 g0409 (commit_conflict.go, safety_halt.go); n42-rs 5c7bc9562 (`h2-node/src/safety_halt.rs`, tests 8f3438971) |
| E13 | impl | vec | ? | gov5 g0346b anchors enforced; n42-rs V6 + V1 QC refusals + strict anchor verifier (d1efe75da); n42-26 strict-anchor range client (AM13), not reported for profile 1 |
| E14 | — | impl | ? | gov5 g0255 "finality tags aliased to latest (E14 fixed in M2)"; n42-rs split tags only on profile 1 (f31f32bc6, `h2-execution/src/settlement.rs`) |
| E15 | — | — | ? | gov5 g0255 "equivocation evidence stores hashes only"; n42-rs detects in `h2-consensus/src/protocol/voting.rs`, no persisted pair, no `n42_equivocations` RPC, no metric |
| E16 | ? | impl | ? | n42-rs 4c818ee56 (every vote on the consensus topic), `N42_VOTE_TRANSPORT=direct` refused |
| E17 | ? | vec | ? | V6 Decide wire / snappy gossip bytes |
| F1 | impl | impl | — | gov5 g0346b; n42-rs cc71c34e2; n42-26 does not produce profile-1 blocks yet (n0505) |
| F2 | ? | impl | ? | n42-rs proposes empty blocks |
| F3 | impl | impl | — | gov5 g0346b "maxBlockBytes*0.9 - 32 KiB - header"; n42-rs `engine-types/src/payload.rs` 9/10 of the block bound (the −32 KiB term not checked here); n42-26 not producing |
| F5 | ? | vec | ? | V6 `tc_leader_proposes_on_high_qc` |
| F6 | ? | ? | ? | n42-rs: same-parent rebuild path not verified against F6 |
| F7 | ? | impl | — | n42-rs deferred execution + sealed own block; n42-26 not producing |
| G1 | ? | impl | ? | n42-rs `h2-net` |
| G2 | ? | impl | ? | n42-rs `h2-net` topics incl. mobileverify |
| G3 | ? | impl | ? | n42-rs `h2-net` message id |
| G4 | ? | impl | ? | V9 not published; n42-rs `gov5_gossipsub_config` |
| G5 | impl | ? | ? | gov5 g0346b "consensus gossip messages capped at 64 KiB decoded"; n42-rs: 64 KiB on direct vote bodies (`h2-net/src/rpc.rs` MAX_VOTE_BODY), gossip-side cap not found |
| G6 | ? | impl | ? | n42-rs: no single-client protocol needed by another |
| I1 | ? | impl | ? | n42-rs `crates/n42/mobileverify`, `h2-node/src/mobile.rs` (`docs/MOBILEVERIFY_V3_PARITY.md`) |
| I2 | ? | impl | ? | gov5 g0316 "gov5 adds the repeat-parent fallback" (plan); n42-rs 9501762b0 |
| J1 | ? | ? | ? | no evidence found for `eth_config` −32004 on profile 1 |
| J2 | ? | — | ? | n42-rs: none of the seven metric names exists in `crates/` |
| J3 | vec | vec | vec | V8 `legacy_*` cases |
| J4 | impl | impl | impl | gov5 g0331 (AM10, incl. `--miner.gasceil`, `--block-interval-ms`); n42-rs `profile1.rs` refuse_overrides / FORBIDDEN_ENV / FORBIDDEN_FLAGS (f31f32bc6); n42-26 n0505 (AM10) |

Sync (§3 of the standard; not item ids, not counted above):

| Sync rule | gov5 | n42-rs | n42-26 | proof / where |
| --- | --- | --- | --- | --- |
| anchors enforced | impl | impl | ? | gov5 g0346b "sync anchors pinned to enforce"; n42-rs e6f4efe59, `N42_SYNC_ANCHOR` refused unless enforce; n42-26 strict-anchor client (AM13), default not reported |
| ranges committed-only | impl | impl | ? | gov5 g0346b; n42-rs 92b81a20e |
| by-hash serves proposals, miss `0x03` | impl | — | ? | gov5 g0346b; n42-rs serves proposals but defines only codes 1 and 2 (`h2-net/src/rpc.rs`) |
| `bodies_by_range/2` | — | — | — | gov5 g0252 "follow M1"; n42-rs none in `crates/`; n42-26 AM13 |
| `commit_qc/1` | — | — | — | same |
| state-sync servers (`qmdb_*`, `code_by_hash`) | — | — | — | same |
| conflict halt on the sync path | impl | impl | ? | gov5 g0409; n42-rs 643a83949, 50202ac13 |

## n42-rs items still at `—`, `impl` or `?`, and what is missing

- **A10, B13** (impl): the carried-field check runs on the fleet but has no vector; needs V5 (gov5).
- **A17, F1, F2, F3, F7** (impl): production behaviour; proven only by gate 2. F3: compare the builder's
  budget with `maxBlockBytes / 10 · 9 − 32 KiB − header`.
- **A22** is `vec` (§10.4 table + V6), but a mixed round with the rule on has never run.
- **B7** (impl): needs V2 (gov5).
- **B15** (impl): no vector; gate 2/3 exercise it.
- **B16, C7, E5, E8, E9/F8, E16, G1-G4, G6, I1, I2** (impl): implemented; no profile-1 vector (G4 waits for V9).
- **E14** (impl): split tags only on profile 1; no vector and no round yet.
- **E15** (—): persist the signed pair, add the `n42_equivocations` RPC and `n42_equivocations_total`.
- **J2** (—): none of the seven common metrics.
- **J1** (?): check `eth_config` (−32004) and the witness/proof refusals on a profile-1 node.
- **F6** (?): verify one signed proposal per (view, proposer) on the same-parent rebuild path.
- **G5** (?): find or add the 64 KiB decoded cap on gossiped consensus messages.
- **V8**: the test reads gov5's first 14 refused files (`qmdb-reth/testdata/profile1/gov5/V8/refused`); gov5's
  19 later cases are the equivalents of n42-rs's own 33 `refused_*.json`. Re-copy gov5's 33 to close it.
- **Sync** (—): `block_by_hash` miss as `0x03`; `bodies_by_range/2`; `commit_qc/1`; the state-sync servers
  (gates 3 and 4).

## Gate 3 PASSED (2026-11-25, round gate3d, T0 08:45 EST)

Mixed catch-up on the AM27 binaries of all three clients (gov5 586e74ce, n42-rs 04ff7b45f, n42-26 follower 5679751):
heights 0..378 equal across n42-rs v2/v3, gov5's five nodes and n42-26's follower; n42-26 equal to n42-rs's
heads up to 700. Every header on the AM27 slot grid (deltas 8 x350, 32 x26, 40 x1, every non-8 inside an
absent-member window). 3a fresh join (15 blocks in 0.1 s, voting after 16 s), 3b/3d gov5 member down twice,
3c n42-rs member restarted under load (18 blocks in 0.4 s, voting after 26 s), 3e n42-26 follower from genesis.
0 block refusals, no halt, 52,248 transactions. Open, not a gate criterion: transactions entering at one
n42-rs member rarely reach the other n42-rs member (fix/profile1-tx-relay).

## Gate 4a PASSED (2026-11-25, round gate4a, T0 11:30 EST)

Snapshot join in both directions on the AM27 binaries: gov5's live bundle (P=73, CommitQC on 74) imported into an
n42-rs member, which voted after 8 s and led after 24 s; n42-rs's bundle (P=143) imported into a gov5 member,
which then voted and sealed. Heights 0..252 equal on every node, 0 refusals.

## Gate 6 PASSED (2026-11-25, round gate6c, T0 19:00 EST)

n42-26 as a producing validator (index 3) beside two gov5 validators and one n42-rs validator: heights 0..182
equal on every node; n42-26 led all of its 44 slots and every block was accepted; it rejoined after a 3-minute
outage and led again; all headers on the AM27 grid (8 x173, 32 x8, the 32 s only while a member was down);
0 refusals, no halt.

Open after gates 3-6 (block quality, not gate criteria): n42-26 does not yet take gossiped transactions into its
pool (its blocks are empty); a gov5 member that follows another gov5 member builds speculatively against a pool
that has not yet dropped the previous block's transactions (near-empty blocks); n42-rs's pool gossip ran once per
block (fixed on main cbdb5ba5d). A mixed re-check with all three fixes must show an even per-leader transaction split.

## Gate 5 PASSED (2026-11-25, round gate5b, T0 20:55 EST) — gates 1-6 all passed

100 validators in one mixed round: 30 gov5 processes (indices 0..29), 69 n42-rs keys over four shared execution
layers (30..98) and one n42-26 validator (99). Heights 0..183 equal on every dump of all three clients; all 100
validators proposed (gov5 58 blocks, n42-rs 124, n42-26 1); AM27 deltas 8 s except one 40 s at startup; every
gov5 leader counted 100/100 votes; 0 refusals, no halt. The first attempt (gate5a) stalled because gov5's
consensus-topic subscription used a 32-message queue that dropped most of a 99-vote burst; gov5 raised it to
16384 and now warns on drops. Absent-leader behaviour at n=100 is covered by the all-Rust r100x round (33 absent).

