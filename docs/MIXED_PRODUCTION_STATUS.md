# Mixed production standard, profile 1: status per client

> ## v1 CLOSED (2026-11-26 01:50 EST)
>
> Every gate of the standard (as amended by AM28-AM30) passed in mixed rounds of gov5, n42-rs and n42-26:
>
> | Gate | Round(s) | Result |
> | --- | --- | --- |
> | 1 vectors | V1, V3, V4, V6, V8 (all 33 gov5 refused cases) | pass on each client |
> | 2 idle mixed | mixed-3 (11-24) | 0..227 equal |
> | 3 catch-up | gate3d | 0..378 equal, all four pull directions |
> | 4 long absence | 4a snapshot files; 4c 70 min absent (gov5 15, n42-rs EL + 17 keys, n42-26 v99) | 0..410 equal; catch-up 13-30 s, voting <= 27 s after |
> | 5 scale | 5b n=100, 5c killed leaders, 5d 33 absent | 0..183 / 0..176 / 0..147 equal, no halt |
> | 6 n42-26 producer | gate6c | 0..182 equal, led every slot |
> | block quality | txcheck2 | per-leader spread 1.8%, p90 inclusion 7.2-7.4 s |
>
> Releases: gov5 main 5eb5aba9 (binary 854a1982…), n42-rs main 6a793112e, n42-26 main 9feef34 (binary 9bba532a…;
> AM28 fields in PR #47, approved by the owner, merge pending in n42-26's session).
>
> ## v1.1 CLOSED (2026-11-26 21:20 EST)
>
> `bodies_by_range/2` + `commit_qc/1` run in all three clients, client and server, with `/1` kept as fallback.
> Mixed rounds:
>
> | Round | What it showed | Headers equal |
> | --- | --- | --- |
> | gate 4b | full-block sync from genesis | 0..368 |
> | 4b-S | non-gov5 clients as servers | 0..287 |
> | scale leg S1 | 3.67M tx; every client rejoined from genesis | 0..3129 |
> | 4b-R / 4b-R2 | n42-rs catch-up defaults | 0..623 / 0..296 |
> | Q1 | n42-rs as the only server | 0..203 |
>
> In Q1, n42-26 v3's 20:53 resync pulled 1..56 over `/2` from n42-rs v2 and anchored its tail with v2's
> `commit_qc/1` (#56). That was the last coverage gap.
>
> Releases: gov5 main 5464ee6e, n42-rs main 30f1cac4a, n42-26 main 80ecf52.
> Moved to v1.2 by AM31: p2p state sync and a mixed equivocation round; the n42-rs injector is on main
> (`docs/P1_EQUIVOCATION_INJECTOR.md`). AM33 (backoff per group of TCs) and AM34 are v1.2 rules.
> Still open from v1: the §7 items (vectors now published by gov5; runs pending) and the negative-leader round
> M3d. Work list: `docs/PLAN_P1_REMAINING_2026_11.md`.
>
> **Risks carried:** (1) liveness — k consecutive absent leaders stall about 24 + 48 + 96·(k−2) s (5d: 464 s for six);
> mitigation candidates for v1.1: cap backoff across consecutive TCs, or a leader order that interleaves operators.
> (2) Host — a full `/data` killed two members mid-round (round scripts now refuse under 50 GB free).
> (3) gov5's consensus topic once used a 32-message queue (fixed, now warns on drops) — any client's subscriber
> queue must hold a full vote burst at n = 100.
>
> ## v1.2 state (2026-11-27 review)
>
> | Rule | gov5 | n42-rs | n42-26 |
> | --- | --- | --- | --- |
> | AM33 timeout backoff | main | main | main b64f650 |
> | AM34 late equivocation (item 6) | main | main | main e5932de |
> | AM34 items 3-5, vectors V2/V7/V9 | main | main | open |
> | AM35 durable commit vote (PROPOSED) | main 08ecf671 | branch, 5 commits | uncommitted WIP |
>
> AM35's gate (timed whole-set SIGKILL, 10 kills) has no kill tool yet. Order and owners:
> `docs/PLAN_P1_REMAINING_2026_11.md` items E5-E9 and F1-F3.


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

## Gate 5e: AM33 rerun of gate 5d (2026-11-27 01:35-02:05 EST) -- PASSED

Same 100-validator mix and schedule as 5d (gov5 0..29 on 2d2c9690 with AM33 and the restart fix, n42-rs
30..98 on main d8a5e54d2 over 4 execution layers, n42-26 99 on b64f650 with AM33): 33 members absent at once
(gov5 10..19, n42-rs 40..62) from T0+8m to T0+18m, leaving exactly q = 67. Headers 0..175 equal on all 8
dumps (4 n42-rs layers, gov5 0/20/29, n42-26 v99), 100 distinct proposers, 0 refusals, every absent member
back and voting after its restart. Block intervals: 172 x 8 s, one 32 s (one absent leader at the restart
edge, 24 + 8), one 48 s (start-up) and one **224 s** for six consecutive absent leaders (views 57..62: TCs
24, 24, 24, 48, 48, 48 s = 216 s plus the 8 s slot), exactly AM33's sequence with g = 3; 5d paid 464 s for
the same six. Closes plan item E3.

## M90b: 90-minute steady-load memory round (2026-11-26 22:50 - 2026-11-27 00:26 EST)

Gate-6 set at ~150 tx/s for 92 min (gov5 main ef2f6bb0, n42-26 17e3a7c = PR #51, n42-rs main d8a5e54d2).
Headers 0..701 equal on all 7 dumps, gov5 refusals 0, n42-rs 1 timeout and 0 refusals, 808k tx with 0
errors. Memory (RSS):

| Client | Start | End | Rate at the end | Reading |
| --- | --- | --- | --- | --- |
| n42-rs v2 EL / validator | 181 / 41 MiB | 682 / 51 MiB | EL ~2.5 MiB/min, slowing; validator flat | not flat within 92 min; RocksDB memtable history (B6) is the known candidate |
| n42-26 v3 | 337 MiB | 1,804 MiB | ~3.5 MiB/min (jemalloc) | PR #51 caps hold but are not reached (~2,900 blocks needed); RocksDB memtable 238 -> 375 MiB |
| gov5 v0 / v1 / verifier | 557 / 408 / 537 MiB (23:02) | 1,261 / 1,652 / 1,139 MiB | rising | txpool leak (included txs never staled in the priced heaps), fixed in gov5 main 08ecf671 |

Next: one round of at least 6.5 h (so n42-26's caps engage) with gov5 08ecf671 and the n42-rs memtable
knob if its legs pass (plan B5, B6, B7).

## M3d: mixed equivocation round (2026-11-26 22:00-22:40 EST) -- PASSED

Gate-6 set (chain 1144, genesis-m3d.json sha256 96369975...26cd2, hash 0x9a1ea7f0...3eb13): gov5 v0, v1 and a
verifier on gov5 main ef2f6bb0, n42-26 v3 on fc558d6 (PR #51 + #52), n42-rs v2 on main d8a5e54d2 with the
test-only injector (`N42_TEST_EQUIVOCATE` + `--test-equivocate`, chain 1144 only). v2 signed a second,
conflicting message in every view: commit votes 22:09-22:13, R1 votes 22:13-22:23, proposals 22:23-22:33,
then clean. (v2 was down 22:03-22:09: the round tool unset every N42_* variable, so the validator refused
`--test-equivocate` without its spec; fixed in the tool, v2's slots timed out meanwhile.)

| Member | commit_vote | vote | proposal | standalone check |
| --- | --- | --- | --- | --- |
| gov5 v0 | 7 (every view it led) | 19 | 19 | 45/45 |
| gov5 v1 | 7 | 19 | 19 | 45/45 |
| n42-26 v3 | 7 (views 51..75) | 19 (79..151) | 19 (154..226) | 45/45 (gov5's verifier) |

Every record names validator 2. The standalone check (gov5's verifier, outside any node) verifies both
BLS signatures against the record's key, that key against genesis validator[2], and that the two signed
messages differ; n42-26's records parse with gov5's own evidence type unchanged (AM28 shape). Votes and
commit votes are recorded by the leader of the view, proposals by every member. Headers 0..257 equal on
all 7 dumps, no twin committed, no halt, gov5 refusals 0, load 322k tx with 0 errors. Closes plan items D2
and E1.

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
| E15 | impl | impl | ? | AM28 shape: n42-rs main 6413d13b2 (persisted pair, `n42_equivocations`, `n42_equivocations_total`); gov5 feat/p1-j2-e15 5eb5aba9 (vote/commit_vote kinds; merge pending) |
| E16 | ? | impl | ? | n42-rs 4c818ee56 (every vote on the consensus topic), `N42_VOTE_TRANSPORT=direct` refused |
| E17 | ? | vec | ? | V6 Decide wire / snappy gossip bytes |
| F1 | impl | impl | — | gov5 g0346b; n42-rs cc71c34e2; n42-26 does not produce profile-1 blocks yet (n0505) |
| F2 | ? | impl | ? | n42-rs proposes empty blocks |
| F3 | impl | impl | — | gov5 g0346b "maxBlockBytes*0.9 - 32 KiB - header"; n42-rs `engine-types/src/payload.rs` 9/10 of the block bound (the −32 KiB term not checked here); n42-26 not producing |
| F5 | ? | vec | ? | V6 `tc_leader_proposes_on_high_qc` |
| F6 | ? | impl | ? | n42-rs 2460fa4e6: one signed proposal per (view, proposer), tested incl. a restart inside the view |
| F7 | ? | impl | — | n42-rs deferred execution + sealed own block; n42-26 not producing |
| G1 | ? | impl | ? | n42-rs `h2-net` |
| G2 | ? | impl | ? | n42-rs `h2-net` topics incl. mobileverify |
| G3 | ? | impl | ? | n42-rs `h2-net` message id |
| G4 | ? | impl | ? | V9 not published; n42-rs `gov5_gossipsub_config` |
| G5 | impl | impl | ? | n42-rs: consensus gossip decoders refuse > ~8 KiB declared length before decompressing (stricter than 64 KiB; = gov5 v4 cap), pinned by 0c1f934b2 |
| G6 | ? | impl | ? | n42-rs: no single-client protocol needed by another |
| I1 | ? | impl | ? | n42-rs `crates/n42/mobileverify`, `h2-node/src/mobile.rs` (`docs/MOBILEVERIFY_V3_PARITY.md`) |
| I2 | ? | impl | ? | gov5 g0316 "gov5 adds the repeat-parent fallback" (plan); n42-rs 9501762b0 |
| J1 | ? | impl | ? | n42-rs: `eth_config` −32004 and proof/witness refusals on a profile-1 genesis, pinned by 1486f03f4 |
| J2 | impl | impl | ? | all seven `n42_*` metrics: n42-rs 02d187fd7 (`h2_validator --metrics`); gov5 feat/p1-j2-e15 5eb5aba9 (merge pending) |
| J3 | vec | vec | vec | V8 `legacy_*` cases |
| J4 | impl | impl | impl | gov5 g0331 (AM10, incl. `--miner.gasceil`, `--block-interval-ms`); n42-rs `profile1.rs` refuse_overrides / FORBIDDEN_ENV / FORBIDDEN_FLAGS (f31f32bc6); n42-26 n0505 (AM10) |

Sync (§3 of the standard; not item ids, not counted above):

| Sync rule | gov5 | n42-rs | n42-26 | proof / where |
| --- | --- | --- | --- | --- |
| anchors enforced | impl | impl | ? | gov5 g0346b "sync anchors pinned to enforce"; n42-rs e6f4efe59, `N42_SYNC_ANCHOR` refused unless enforce; n42-26 strict-anchor client (AM13), default not reported |
| ranges committed-only | impl | impl | ? | gov5 g0346b; n42-rs 92b81a20e |
| by-hash serves proposals, miss `0x03` | impl | impl | ? | gov5 g0346b; n42-rs `RESPONSE_CODE_RESOURCE_UNAVAILABLE` (`h2-net/src/rpc.rs`) |
| range sync (`bodies_by_range/1`, AM30) | mix | mix | mix | gates 3 and 4c: members of all three clients caught up by range in mixed rounds; `/2` -> v1.1 |
| `commit_qc/1` | — | — | — | v1.1 (AM30); v1 anchors from header QCs and Decide; gov5 uses the layout only inside the 4a bundle |
| state-sync servers (`qmdb_*`, `code_by_hash`) | — | — | — | v1.1 gate 4b (AM29); v1 long absence = range pull (4c) or snapshot file (4a) |
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
- **E15, J2, J1, F6, G5, V8, by-hash `0x03`: closed 2026-11-26** (main 47f1792b9, 70c39164d, 6413d13b2; rows above).
- **Sync:** range sync on `/1` proven mixed (gates 3, 4c; AM30); `bodies_by_range/2`, `commit_qc/1` and the
  state-sync servers are v1.1 (AM29, AM30).
- **A17, F1-F3, F7, A22, B15, E14:** production behaviour now exercised by the mixed gates 2-6 and the transaction
  re-check (txcheck2); still no dedicated vector.

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

Gate 5c (2026-11-25, T0 21:37 EST, same 100-validator mix, gov5 main f7bf6b09): a gov5 leader (index 10) and an
n42-rs leader (index 40) were each absent for their view; both views ended in a TC (gov5 now publishes its own
timeouts at n=100) and cost exactly one 32 s interval each. Heights 0..176 equal on every dump, 0 refusals.

Gate 5d (2026-11-25, T0 23:00 EST): 33 members absent at once (gov5 10..19, n42-rs 40..62) for ten minutes, leaving
exactly q = 67. Heights 0..147 equal on every dump, 0 refusals, every absent member voted again after its restart.
Six consecutive absent leaders (views 57..62) cost one 464 s gap (TC backoff 24/48/96/96/96/96 s): a liveness cost,
not a safety one, recorded as a v1.1 risk. With 5c (killed leaders) and 5d, gate 5 is complete as written.

## Mixed transaction re-check PASSED (2026-11-25, round txcheck2, T0 23:45 EST)

With all three fixes in (gov5's speculative-fill rebuild, n42-rs's pool relay, n42-26's transaction_v2 ingest),
four leaders (gov5 v0/v1, n42-rs v2, n42-26 v3) sealed 158.5-161.5 transactions per block in steady state (spread
1.8%), and transactions submitted to any client's RPC were included with p90 7.2-7.4 s (within one slot); 17,602
sent, all included. Heights 0..146 equal, 0 refusals. The block-quality items opened after gates 3-6 are closed.

## Gate 4c PASSED (2026-11-26, T0 00:20 EST) — long absence by range (AM29)

Same 100-member mix. Absent 70 min under load: gov5 member 15 (with its execution layer), n42-rs layer 3 (one
execution layer + 17 validator keys) and n42-26 v99. The chain advanced 32 -> 335 meanwhile. On restart: n42-rs
caught up ~300 blocks in 18 s and voted 0.3 s later; n42-26 304 blocks in 13 s, voted at once and led block 424;
gov5 member 15 at the head 30 s after restart, voting after 27 s. Heights 0..410 equal on all eight dumps, deltas
8 x335 / 32 x74 (absent leaders) / 48 x1 (startup), 0 refusals, 45,000 transactions with 0 errors.


## v1.1 gate 4b — join by full block sync from genesis (2026-11-26, PASSED)

Mixed round T0 04:42:00 EST, genesis `genesis-gate4b.json` (sha256 ee123441…ffe14, hash 0x62829812…e9dd), gate-6 set:
gov5 v0, v1 + verifier 4 (main fe5e02ed, binary 00aa020a…, byte-identical to ecaa51f7), n42-rs v2 (main 004ac1167,
h2_validator 5326bb5e…), n42-26 v3 (64b5b10 + PR #48 + e3d22dd, c20104ef…). Load 25,800 tx, 0 errors.
Each member wiped once (keys kept, genesis re-initialised, restarted at once), one down at a time:

| Wipe | Range pulled (/2) | Served by | commit_qc/1 anchor | At head | First vote (after head) |
| --- | --- | --- | --- | --- | --- |
| n42-rs v2, 04:52:00 | 1..71, 617 KB | gov5 v1 | #71, gov5 v1 | 04:52:04.3 | 04:52:08 (4 s) |
| gov5 v1, 05:02:00 | 1..146, 1.39 MB | gov5 v0 | #146, gov5 v0 | 05:02:08 | 05:02:24 (16 s) |
| n42-26 v3, 05:12:01 | 1..220, 2.15 MB | gov5 v1 | #220, gov5 v1 | 05:12:29 | 05:13:04 (35 s) |

Headers 0..368 equal on all seven dumps (gov5 node0..4, n42-rs v2, n42-26 v3), 0 mismatches, 0 off-grid; one slot
missed (block 222, v3's own slot during its wipe). No `/1` used. The pre-run (04:02, `genesis-pre4b.json`) found the
n42-26 tail-release stall (range timer deadline slid under tx gossip; fixed in e3d22dd with tests) and the n42-rs
`/2` busy code (0x02 -> 0x04 "1000", 004ac1167).

Open for v1.1 after 4b: (a) [closed by 4b-S below] every `/2` and `commit_qc/1` in this round was served by gov5 — n42-rs and n42-26 as SERVERS to
another client are covered only by vectors and same-client loopback tests, a mixed leg with gov5 serving disabled is
still due; (b) the scale leg (long history; chain-94 shared state `gov5-work/p1scale/out/`); (c) n42-26's 35 s from head
to first vote and gov5's repeated `/2 145..146` asks are noted, not failures.

### Gate 4b-S — non-gov5 clients as servers (2026-11-26, PASSED)

T0 05:46:00 EST, genesis `genesis-gate4bS.json` (sha256 cebbf1ed…2e3c, hash 0x86d68d21…c15c). gov5 0064ffd3
(68cdfe04…, = fe5e02ed + `N42_SYNC_RANGE_SERVE=off`, which leaves `/1`, `/2` and `commit_qc/1` unregistered) on
v0/v1/v4, so only n42-rs v2 (004ac1167) and n42-26 v3 (e3d22dd) could serve. The switch reached gov5's nodes only
after a one-by-one restart at 05:48:40-50 (gov5's harness stripped `N42_*`); nothing was served by gov5 before it.

| Wipe | Refused by (no protocol) | Range pulled (/2) | Served by | Tail anchor | First vote after head |
| --- | --- | --- | --- | --- | --- |
| gov5 v1, 05:56:01 | gov5 v0, v4 | 1..62 | n42-26 v3 | commit_qc/1 #62, n42-26 v3 | 8 s |
| n42-rs v2, 06:06:00 | gov5 v0, v1, v4 | 1..137, 1.38 MB, 1.5 s | n42-26 v3 | commit_qc/1 #137, n42-26 v3 | 3.4 s |
| n42-26 v3, 06:16:01 | gov5 v1, v4 | 1..211, 180 ms | n42-rs v2 | live QCs | 3.6 s |

Also n42-rs v2 served gov5 v4 `/2` 16..17 at 05:50 (v4's switch restart). Headers 0..287 equal on all seven dumps,
0 mismatches; no slot missed during a wipe (block 17's 80 s gap is gov5's switch restart). Load 21,000 tx (5 send
errors + 10 late receipts from that restart, all mined).

Cross-client serving now exercised in mixed rounds: `/2` gov5->both, n42-26->both, n42-rs->both; `commit_qc/1`
gov5->both, n42-26->both. n42-rs as a `commit_qc/1` server to another client is still covered only by the gov5
vectors and same-client loopback tests. Notes (not failures): gov5's client retries a protocol-refusing peer ~10
times in a second (gov5 todo); n42-26's e3d22dd has no serve-side log for `commit_qc/1`.


v1.1 releases (2026-11-26): gov5 main fe5e02ed (node binary 00aa020a…, byte-identical to ecaa51f7; the serve switch
`N42_SYNC_RANGE_SERVE` is on branch 0064ffd3); n42-rs main 004ac1167 (sync v1.1) + docs; n42-26 main 053b4f6 (PR #48,
tree = e3d22dd, gate binary c20104ef…; follow-ups in PR #49: commit_qc/1 serve log, deferred-check timing).

### v1.1 scale leg S1 — heavy history, every client rejoins from genesis (2026-11-26, PASSED)

T0 06:42:00 EST, genesis `genesis-scaleS1.json` (sha256 92161d53…7f57), gate-6 set, binaries as gate 4b (gov5
fe5e02ed, n42-rs 004ac1167 — before the catch-up/memory merges — n42-26 e3d22dd). gov5 load 150 tx/s for 6 h 50 m:
3.67M transfers, ~1,200 tx and ~140 KB per block, 0 send errors. Headers 0..3129 equal on every dump (gov5 node0..4,
n42-rs v2, n42-26 v3), 0 mismatches; missed slots only the wiped member's own slots during its wipe.

| Rejoin from genesis | Blocks / txs / bytes | Restart->head | blocks/s | tx/s | MB/s | Peak RSS (catch-up) | Datadir | Vote after head |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| n42-rs v2, 12:42 | 2,699 / ~3.24M / 379 MB | 66.5 s pull | 40.6 | ~49k | 5.7 | EL 2.42 GB + val 0.42 GB | 1.43 GB | ~9 s |
| gov5 v1, 13:02 | 2,840 / 3.40M / ~400 MB | 110.6 s | 25.7 | 30.7k | 3.6 | 4.0 GB | 4.1 GB | 15 s |
| n42-26 v3, 13:22 | 2,983 / 3.58M / 419 MB | 66.9 s | 44.6 | 53.5k | 6.3 | 2.86 GB | 4.5 GB | 29 s |

All three are execution-bound (fetch is pipelined and small: gov5 served 2,726 blocks / 384 MB to n42-26 in ~2 s).
Steady RSS under load at ~3k blocks: n42-rs 2.6 GB (EL 2.38 + val 0.22, pre-memory-work binary), n42-26 2.80 GB
(grows with state, not a leak); gov5 not measured in S1 (its earlier "~0.4 GB" was retracted, see P50). Catch-up and memory work continues per AM31 as idle-time items (n42-rs main 535bbe121 and
c3e028040 carry the first steps; re-measure on this history).

### P50 — 30 min under S1-shaped load, current binaries (2026-11-26 13:59-14:34)

gov5 22bee6b3, n42-rs main ffe484787 (profile-1 memory defaults, catch-up step 2, explorer RPC), n42-26 6d0ea9b (PR #50,
sender cache for the pre-import check). Headers 0..243 equal on all 7 dumps; 267.9k tx, 0 errors. RSS under the
same load (1,200 tx/block):

| Client | Start | End of load (block ~240) | Trend |
| --- | --- | --- | --- |
| n42-rs (EL + validator) | 369 MiB | 571 MiB (505 + 66) | slowing (+~30 MiB / 5 min at the end) |
| gov5 | 154 MiB idle | 960-1017 MiB | +~120 MiB / 5 min, no plateau; 116-120 MB decoded block txs in heap (gov5 checking the bound) |
| n42-26 | ~785 MB at 17 min | 1.01 GB at 34 min (~259 blocks) | same as S1 at equal time (739 MB at 17 min); PR #50 adds no memory (fixed 131k-entry sender cache) |

n42-26 pre-import vote: 56 % of follower views (S1 old code 35 %); the check now ends 2.0 ms after block data (was
~20 ms); the rest lose to Decide on localhost (2f+1 in ~3 ms without v3) — no liveness effect.


### 4b-R — n42-rs catch-up defaults in a mixed round (2026-11-26 15:25-16:57)

n42-rs main 9f9713306 (lazy QC screening + batch import on by default, parallel QC screening; n42 7f22a41a…,
h2_validator d3ea377b…), gov5 22bee6b3, n42-26 6d0ea9b. Genesis gate6/genesis-g4bR.json (sha256 0a271bd9…,
hash 0x3fe4571d…). **Headers 0..623 equal on all 7 dumps, mismatch 0**; 733k tx, 0 send errors.

- n42-rs v2 could not start at T0: gov5's separate memory A/B held 31700-31703, and v2's body channel is its
  libp2p port + 1000 (31702). The chain ran on three members until 15:36; gov5 keeps 31700-31799 free from now on.
- 15:36:17 v2 fresh: 1..35 pulled (commit_qc/1 anchor from gov5 v1), first vote 15:36:20.
- 16:30:09 v2 wiped again, fresh pull of 1..439 heavy blocks (~1.2k tx, 148 KB each; 65 MB): **4.43 s = 99 blk/s**
  (S1, old build: 40.6), 5 requests, checked=18 of 439 (lazy), 0 faults, 0 disconnects. Served by gov5 v0/v1/v4
  (16 requests) and n42-26 v3 (385..439). EL 782 MiB + validator 87 MiB right after.
- gov5 and n42-26 logged no refusal, score change, rate limit or INVALID caused by v2's requests.
- Open (catch-up step 4): batch import did not engage on these heavy blocks (437 forkchoices), and after the
  pull v2 refetched the unanchored tail block 440 three times; first vote 16:30:44, 28 s after the pull
  (S1 old build ~9 s; within M3's 60 s).
- n42-26: pre-import votes 272 of 475 follower views (57 %); RSS 1.69 GB at 92 min (same trend as S1).
  gov5: RSS 1.6-1.8 GB on main (512-block cache full); fix/p1-steady-rss plateaus ~650 MB RssAnon (owner merge pending).

### 4b-R2 — re-check on n42-rs main e8db589e5 (2026-11-26 18:28-19:10)

n42-rs main e8db589e5 (memory step 2, byte-budgeted pull, live commit anchors the pulled tail; n42 a6080183…,
h2_validator 9bef0215…), gov5 22bee6b3, n42-26 6d0ea9b. Genesis gate6/genesis-g4bR2.json (sha256 35e7b1f6…,
hash 0x3a4c3076…). **Headers 0..296 equal on all 7 dumps, mismatch 0**; 322k tx, 0 errors; no missed slot at the wipe.

- n42-rs v2 under ~150 tx/s (EL / validator MiB): 182/42 at start, 354/50 at 12 min, 447/51 at 24 min,
  469/51 at 28 min — about 520 MiB in all (P50 on ffe484787: 571 MiB at 30 min).
- 18:58:01 v2 wiped; fresh pull 1..221 heavy blocks (29.3 MB, 4 requests of ~8 MB under the 32 MiB budget) in
  1.96 s = 112 blk/s, anchored by n42-26 v3's commit_qc/1; **first vote 18:58:08, 1.5 s after the pull**
  (4b-R: 28 s). gov5 served 277 blocks / 24.5 MB in one request per node; no refusal, score, rate limit or
  INVALID caused by v2 on gov5.

### Q1 — n42-rs as the only `/2` + `commit_qc/1` server (2026-11-26 20:45-21:17, PASSED)

Genesis gate6/genesis-q1cqc.json (sha256 a9b1c0ed…, hash 0x04669856…). Binaries: gov5 5464ee6e with
`N42_SYNC_RANGE_SERVE=off` on every gov5 node (checked in /proc environ and the "range serving disabled" line;
gov5 served 0), n42-rs main e9f15edc4 (n42 1a7ba3fa…, h2_validator 1ee5fe72…), n42-26 80ecf52.
**Headers 0..203 equal on all 7 dumps**; 232k tx, 0 errors.

- **20:53, n42-26 v3** (an accidental live-datadir wipe on n42-26's side, which disturbed its window 20:45-20:53):
  - `/1` asked of gov5 v1 and v4, refused because serving was off;
  - `/2` 1..56 from n42-rs v2 in 66 ms;
  - **`commit_qc/1` for #56 from n42-rs v2 (QC 151 B + 1 header) anchored the tail**;
  - caught up to head 58 with 0 faults, first vote 20:53:56.
- **21:05:30, gov5 node4** (non-validator, wiped while n42-26 v3 was down 21:05-21:09):
  - one `/2` request 1..145 at 21:05:42, served by n42-rs v2 (peer 16Uiu2HAm5qn… in v2's log);
  - its tail was authorised by the live Decide it followed, so no `commit_qc/1` was needed;
  - reached the wipe-time head in 13.4 s.
- No refusal, score change or INVALID naming v2 on gov5.


## AM36 smokes smk / smk2 (2026-11-27)

Gate-6 set (gov5 v0, v1 + verifier, n42-rs v2, n42-26 v3), 25 min each, ~150 tx/s (gov5 loader).
- smk (02:50 EST): gov5 fix/p1-validate-then-forward (78c76e2e) and n42-26 PR #58 (10952c3) on AM36;
  n42-rs on the AM35 branch (forwarding decode-only). Headers 0..168 equal on 7 dumps; 178k tx, 0 errors;
  0 Reject on gov5 and n42-26 (74,157 messages received on n42-26), no peer penalised.
- smk2 (03:25 EST): all three on AM36 (n42-rs integ/p1-am35-am36 7e9e3c165). Headers 0..165 equal on 7 dumps;
  178k tx, 0 errors; 0 Reject / 0 Ignore on every client, no peer penalised. PASS.

## E9 mixed whole-set SIGKILL gate, run e9g (2026-11-27 04:05 EST)

Gate-6 set under ~150 tx/s: gov5 v0, v1 + verifier (vtf-78c76e2e: AM35 + AM36), n42-rs v2 (integ/p1-am35-am36
7e9e3c165), n42-26 v3 (PR #57 72facd3, AM35 only). Watcher `e9-watch.sh` wrote `am35-trigger/e9-<n>`; each
client's killer SIGKILLed only its own members (n42-rs 2-9 ms after the trigger, n42-26 8-12 ms, gov5
45-232 ms) and restarted them with the same datadirs at trigger + 5 s (gov5 + 7.1 s).

| kill | trigger | restart height | recovered (+3 on all five ELs) |
| --- | --- | --- | --- |
| 1-5 | a commit line (gov5) | 17, 25, 34, 43, 51 | 48, 65, 23, 48, 63 s |
| 6, 8, 9 | n42-rs follower's AM35 release line | 60, 77, 86 | 23, 65, 23 s |
| 7 | gov5 follower's held commit vote | 69 | 48 s |
| 10 | gov5 follower's held commit vote | 94 | gov5 + n42-rs: yes (94 -> 103); n42-26 v3: EL stuck at 95 |

- Kill 10 on n42-26 v3 (its diagnosis): v3's durable lock lagged the commit when it committed by Decide
  without its own R2, so every snapshot save was refused; after the kill its snapshot (block 91) was below
  reth's persisted head (94), catch-up sent a forkchoice below the head ("too deep reorg") and later
  children were refused as parent-unknown. Consensus safety unaffected; the chain went on. Fixed in n42-26
  272ca33 (lock raised to the commit QC; snapshot saved before the finalize forkchoice); the suffix
  re-admission on recovery is a second, separate n42-26 fix.
- No committed block lost on any gov5 member (each member's last commit before every kill is canonical).
- Headers: 0..95 equal on 8 dumps (n42-rs, gov5 x6, n42-26); 0..112 equal between n42-rs and gov5 x3.
- n42-rs: 10/10 recovered on 7e9e3c165. The gate as a whole is rerun as e9h (05:00 EST) with n42-26 272ca33.

## E9 gate PASSED: rerun e9h (2026-11-27 04:50 EST)

Same shape as e9g with n42-26 v3 on PR #57 272ca33 (AM35 + lock-lag fix + main with #51/#58); gov5
vtf-78c76e2e (= gov5 main 78c76e2e), n42-rs integ/p1-am35-am36 7e9e3c165. Ten whole-set SIGKILLs: kills 1-5
on a commit line, kills 6-10 on a follower's commit-vote release (gov5 held-commit-vote line x3, n42-rs AM35
release line x2). Kill latency after the trigger: n42-rs 1-7 ms, gov5 4-11 ms, n42-26 4-12 ms.
- Every kill RECOVERED: all five ELs +3 past the restart height (14, 23, 31, 40, 48, 57, 65, 74, 82, 91) in
  48 or 63 s.
- No committed block lost: every gov5 member's last commit before each kill is canonical.
- Headers 0..104 equal on 5 dumps (n42-rs v2, gov5 node0/1/4, n42-26 v3).
- Result: AM35 gate passed for all three clients. n42-rs merged integ/p1-am35-am36 into main as 9b373ce00
  (code identical to 7e9e3c165) under the owner's pre-approval.
