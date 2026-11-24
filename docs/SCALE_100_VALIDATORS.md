# n42-rs consensus and network at 100+ validators

Status: 2026-11-24, branch `test/scale-100-validators`. Scope: AM17 / AM22 of
`docs/MIXED_PRODUCTION_STANDARD.md` (Profile 1: 8 s slot, base timeout 24 s, max 96 s,
tenure 1, fixed genesis set) for n42-rs's consensus engine (`crates/n42/h2-consensus`),
wire (`h2-wire`, `h2-primitives`), network (`h2-net`) and validator service (`h2-node`), at
n = 100 and n = 200 as a stress point. Header rules, the vote gate and config are other
lanes and are only referenced here.

Summary: nothing in the certificate format or the consensus engine is quadratic in
signature work or size. QCs and TCs are one aggregate signature plus a bitmap (a 100-member QC
is 163 bytes, a header's extra data 271 of its 4096 bytes); a TC is verified in 0.8 ms at
n = 100 and 200. The in-process 100-engine network commits every view in steady state, recovers
a dead leader in one base timeout, commits every live-leader view with f = 33 silent, and with
34 silent commits nothing, does not panic and holds its buffers flat for a virtual hour. Two
caps sized for seven members were wrong at 100 and are fixed (the future-message buffer and the
body channel). What remains is cost and transport shape, not correctness: per-vote and
per-timeout BLS verification is linear per node (0.1-0.3 s per view at n = 100-200, fine at an
8 s slot); timeouts are broadcast all-to-all and relayed (about 1.6 n^2 deliveries per timed-out
view); GossipSub's flood-publish sends every own message (including a block body) to all n-1
peers; and gov5 is said to cap its peers near 50, below a 100-member static mesh.

## 1. Review, per item

Cost is per node unless stated; "pairing" is one BLS verification (0.72 ms here, section 2).

| # | Item | Where | Cost as a function of n | Small-n assumption | Verdict at 100 / 200 |
| --- | --- | --- | --- | --- | --- |
| 1 | Validator set | `h2-consensus/src/validator/set.rs:91` (`ValidatorSet::new`, `Vec` of entries), `:110` `quorum_size = n - f`, `f = (n-1)/3` from genesis | index lookup O(1); `index_of_public_key` O(n) compare (once per timeout, 48-byte compares) | `epoch.rs:36` `MIN_VALIDATOR_COUNT = 4` (floor only) | fine; quorum 67 of 100, 134 of 200 |
| 2 | QC representation | `h2-primitives/src/consensus/messages.rs:47` (view, hash, one aggregate G2 signature, `BitVec` signer bitmap of n bits) | size 150 + ceil(n/8) bytes on the wire | wire bitmap: u16 count, `h2_wire.rs:17` `MAX_VALIDATORS = 4096`, `:14` `MAX_BITMAP = 1024` B | 163 B (100), 166 (128), 175 (200), 214 (512) |
| 3 | QC in header extra | `header_profile.rs:63-67,181` `N42H ‖ view ‖ QC ‖ seal(96)`, cap `MAX_HEADER_EXTRA_LEN = 4096` (`h2-net/src/block_gossip.rs:40` same) | 108 + QC = 258 + ceil(n/8) | none | 271 B (100), 274 (128), 283 (200), 322 (512); the cap is hit only past the 4096-validator wire cap |
| 4 | QC verification | `quorum.rs:582` `collect_signer_keys` + `:618` `verify_qc_with_profile` (`fast_aggregate_verify`: key sum + one pairing) | O(n) G1 additions + 1 pairing: 0.75 ms (100), 0.80 (200), 0.90 (512) | none | flat in n. `verify_qc_any_domain` (`quorum.rs:704`) tries prepare then commit: a commit QC there costs two pairings (1.6-2.0 ms); used for proposal `justify_qc`, timeout `high_qc`, header QCs on the live path |
| 5 | Vote verification (default) | `voting.rs:67-100` `process_vote_inner`: one pairing per vote on the leader, on the engine's thread (the service's consensus loop) | n-1 pairings per round, two rounds: 2 x 99 x 0.72 = 143 ms per view at 100, 287 ms at 200 (leader only) | none, but the duplicate check (collector) comes after the pairing, so a vote seen on two topics or by gossip + direct costs two pairings | fine at 8 s (1.8 % / 3.6 % of the slot); 10x lever below |
| 6 | Vote verification (batched) | `vote_batch.rs` (`N42_VOTE_AGGREGATE_VERIFY=1`): same-message randomised batch per drain once the group can reach quorum, fallback per vote; duplicates dropped before any pairing (`:113`, `:136`) | 1 batch per group: 11 ms for 67 votes incl. aggregation (100), 18 ms (200) | `:63` queue cap `4n` (min 64), `:66` parked `2` per validator per view: both scale | the 100-engine run is 28 % faster in total wall with it (section 2b); default off (vote-gate lane decides) |
| 7 | QC formation | `quorum.rs:275-377` `build_qc_with_profile_message`: verified votes go straight in; an unverified tail is a randomised multi-message batch; `aggregate` (`bls/aggregate.rs:17`) re-runs the G2 subgroup check on every signature | aggregation 3.8 ms at 67 signers, 6.4 ms at 134 (all subgroup checks; the signatures were already checked) | none | fine; proposal P5 |
| 8 | Duplicate handling | collector `quorum.rs:212` (DuplicateVote), timeouts `timeout.rs:356-363` (before pairing), future timeouts `timeout.rs:36-42`, direct path `h2-node/src/direct_votes.rs:56` dedupe ring of 8192 | O(1) | dedupe ring 8192 = ~40 views of 2n votes at 100 | fine |
| 9 | Timeout message | `messages.rs:182`: view, sender's high QC (whole), signature over `"timeout" ‖ view` | 582 B on the wire at 100 (with a high TC) | none | each receiver: 1 pairing for the signature + the high QC's check unless it equals its own locked / committed QC (`state_machine.rs:2137`) |
| 10 | Timeout certificate | `messages.rs:86`: ONE aggregate signature + bitmap + ONE high QC (the highest the signers carried); formed `quorum.rs:451`, verified `quorum.rs:743` | size 144 + ceil(n/8) + QC: 294 B at 100, 318 at 200; verify O(n) additions + 1 pairing: 0.82 ms (100), 0.79 (200) | none | already non-quadratic: no n highQCs, no n signatures. NewView 415 B (100), 439 (200); wire caps 8 KiB (`h2_v4.rs:14`, `h2_wire.rs:12`) and gossip 1 MiB never bind |
| 11 | Timeout collection | `timeout.rs:329-443` (current view), `:16-170` (future views, `future_timeout_collectors` per view within the 50-view window) | n-1 pairings per node per timed-out view: 71 ms (100), 143 ms (200); embedded high QC +0.75-1.6 ms when it differs | none | fine; same-message batch would cut it 9x (P2) |
| 12 | Timeout relay | `timeout.rs:418-424` and `:110-118`: every non-leader sends each newly counted timeout to the next leader; in `h2-node/src/service.rs:4485` a non-vote `SendToValidator` is a gossip publish | messages: n broadcasts x (n-1) receivers + up to (n-1)^2 relays = ~1.6 n^2 deliveries per timed-out view in the simulation (16,170 at 100, 65,730 at 200) | relays are the same bytes as the original, so on the real transport GossipSub drops them as duplicates at publish (same message id) | O(n^2) messages is the all-to-all timeout, inherent to the rule; work per node stays O(n) |
| 13 | Repeat timeouts | `timeout.rs:244-283`: a view that cannot form a TC re-broadcasts its timeout and re-sends its vote every timer period | the period stays at 2 x base (48 s) because `consecutive_timeouts` grows only on the first timeout of a view | none | bounded: with 34 silent, 75 repeats an hour, buffers flat |
| 14 | View change / NewView | `timeout.rs:447` `process_new_view`: leader check, TC verify (1 pairing), high QC verify | O(n) additions + 2 pairings per node | none | fine |
| 15 | Leader schedule | `validator/selection.rs` `(view / tenure) % n`; `view_after_timeout` with overflow guards | O(1) | none | tenure 1: a member leads once every n views (100 x 8 s = 13.3 min) |
| 16 | Future-message buffer | `state_machine.rs:161-190` (`FUTURE_VIEW_WINDOW = 50`, per sender 8), `:1663` | O(buffer) scan per insert | **was: per view 64, total 256** - below one 67-member quorum, although the unchecked class was meant to hold `n + 2` | **fixed** (section 3, F1): per view `max(64, 2n+2)`, total `max(256, 2 x per view)` |
| 17 | Other per-validator maps | `voters_seen` (8 views x n), `parked_votes` (2n per view), `future_timeout_views` (n), equivocation trackers (n), `imported_blocks` (fifo 64, `proposal.rs:8`) | O(n) | none | flat in the f+1-silent hour (peaks in section 2b) |
| 18 | GossipSub mesh | `h2-net/src/config.rs:21-37,146-165`: D 8 / Dlo 6 / Dhi 12, heartbeat 700 ms, mcache 6/3, seen TTL 30 s, max size `N42_MAX_GOSSIP_MB` (gov5 wire contract, unchanged) | each node meshes 8 of 99 peers per topic; ~log_8(100) = 2-3 hops; each message reaches a node once per topic plus up to D duplicates filtered by the seen cache | `flood_publish` is libp2p's default `true` (not set): an own publish goes to every subscribed peer, not to D | votes / timeouts: fine. A block body published by gossip leaves the leader 99 times (2.4 MB x 99 = 240 MB per full block, 30 MB/s at 8 s). Proposal P3 |
| 19 | Gossip validation | `transport.rs:1085-1122`: decode only, no BLS before forwarding | O(1) per message | none | fine; consensus traffic is on two topics (v4 + gov5 native), so twice |
| 20 | Peer scoring | none configured (libp2p default off) | - | - | a Rejected message is not penalised; acceptable for a closed validator set |
| 21 | Connection limits | `transport.rs:492` 4 per peer, `:500-506` inbound `N42_H2_MAX_INBOUND` default 128, static full mesh dialled and redialled every 10 s (`:721`) | n-1 connections per node, n(n-1)/2 in all (4,950 at 100, 19,900 at 200) | default 128 inbound holds 100 (99 + some simultaneous dials), not 200 | at 200 set `N42_H2_MAX_INBOUND=512`; gov5 "caps its peers near 50" (comment at `:499`): a gov5 member cannot hold a 100-member static mesh - gov5 to confirm |
| 22 | Direct vote transport | `h2-node/src/direct_votes.rs`, `h2-net/src/rpc.rs:1372` `/n42/vote/1` over the existing connection; hellos `:53` 4 per peer | n-1 streams into the leader per round; no extra connections (the mesh already exists) | none | fine; with `gossip` (default, mixed fleets) every vote floods to all n nodes and is dropped unverified by followers |
| 23 | Body channel (plain TCP push) | `h2-node/src/body_channel.rs:216`, `BodyPushers::connect` dials every member | n-1 inbound TCP connections per node | **was: 64 connections, the rest closed on accept** | **fixed** (F2): 1024 |
| 24 | Status handshake | `h2-net/src/status.rs` (72-byte SSZ), one request per new connection | n-1 at start, O(n^2) fleet-wide once | none | fine |
| 25 | Committee pool beside the set | `h2-consensus/src/committee_pool.rs:207` `build_evidence`: draw 512 slots, sum scalars, ONE signature; `parent_beacon_root` per header | 0.38 ms and 405 bytes per block, independent of n; pool init 200k key derivations once per process (`:141`, parallel) | none | fine (A19 / AM23: no security meaning) |
| 26 | Catch-up QC per header | `state_machine.rs:2216` `verify_sync_anchor_qc` (commit domain, the exact view's set), `:2184` `verify_header_qc` (any domain); seal `verify_seal` (`service.rs:6005`) | 0.75 ms (100) / 0.84 ms (200) for the QC + 0.72 ms seal = ~1.5 ms per header on one thread | none | ~650 headers/s bound, nearly flat in n; a day of 8 s blocks (10,800) is ~17 s of signature work |
| 27 | Straggler grace (`F7_STRAGGLER_GRACE_MS`) | `h2-node/src/straggler.rs`, rule `All` by default | the leader waits for all n votes of the previous view | sized for seven | with any member silent at 100 every block waits the full grace; Profile 1 should run without it or with `N42_STRAGGLER_RULE=quorum` |

## 2. Measurements

Host: this box under load (load average ~80 during the runs; numbers are best-of-5 and
indicative to about 10-20 %). Release build, one thread.

### 2a. Certificate micro-benchmark

`cargo test --release -p n42-h2-consensus --test scale_100_bench -- --ignored --nocapture`
(log: `/data/n42-build/audit-notes/ci/s100-bench1.log`). H2-v4 ciphersuite (the mixed fleet's).

Sign one vote 321 us; verify one vote 720 us.

| n | quorum | verify QC (prepare) us | commit QC via any-domain us | verify commit QC us | verify TC us | QC B | header extra B | TC B | NewView B | Timeout B | Proposal B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 7 | 5 | 735 | 1468 | 758 | 741 | 151 | 259 | 270 | 391 | 546 | 499 |
| 100 | 67 | 753 | 1640 | 752 | 819 | 163 | 271 | 294 | 415 | 582 | 523 |
| 128 | 86 | 765 | 1608 | 916 | 773 | 166 | 274 | 300 | 421 | 591 | 529 |
| 200 | 134 | 802 | 1959 | 843 | 791 | 175 | 283 | 318 | 439 | 618 | 547 |
| 512 | 342 | 901 | 1776 | 953 | 1745 | 214 | 322 | 396 | 517 | 735 | 625 |

(Timeout and Proposal sizes include a high TC and a piggybacked PrepareQC respectively; the
TC size excludes its 4-byte length prefix.)

Forming a QC from a quorum of votes (us):

| n | quorum | verify each + aggregate | collector tail (multi-message batch) + aggregate | same-message batch + aggregate | aggregate only |
| --- | --- | --- | --- | --- | --- |
| 7 | 5 | 4,811 | 1,494 | 1,753 | 240 |
| 100 | 67 | 64,416 | 7,780 | 11,223 | 3,832 |
| 200 | 134 | 130,130 | 11,813 | 18,182 | 6,439 |

A TC's signatures (us): one by one 60,166 (100) / 129,211 (200); same-message batch 6,476 /
12,279; building the TC from verified timeouts 3,953 / 7,819 (the aggregation's subgroup checks).

Committee evidence (pool 4096, 512 signers): 375 us and 405 bytes per block.

### 2b. 100 and 200 engines on a virtual clock

`cargo test --release -p n42-h2-consensus --lib scale_tests -- --ignored --nocapture --test-threads 1`
(`crates/n42/h2-consensus/src/protocol/state_machine_scale_tests.rs`; logs
`/data/n42-build/audit-notes/ci/s100-sim-{steady,faults,200}.log`). Profile 1 values: slot
8 s (the virtual cost of a proposal), base 24 s, max 96 s, tenure 1, rotate-on-timeout on.
Every signature is real and the whole fleet runs on one thread, so "wall per view" is the
fleet's total consensus CPU for a view; divide by n for one node. Deliveries count each
message handed to one engine (a broadcast to 99 counts 99).

| case | n | result | wall | wall / view (fleet) | deliveries / view |
| --- | --- | --- | --- | --- | --- |
| steady state, 50 views | 100 | every view 1-50 commits, one block a slot, no conflict | 25.5 s | 499 ms | 485 (5 x 97: proposal, vote, PrepareQC, commit vote, Decide) |
| same, batched votes | 100 | same | 18.3 s | 359 ms | 485 |
| one leader down (view 10) | 100 | view 10 times out, view 11 commits; stall 32 s = 24 s base + 8 s slot | 15.0 s | 714 ms | 1,218 (the timed-out view: ~16,200 timeout deliveries) |
| f = 33 silent (every third member) | 100 | all 20 live-leader views of 1-30 commit, the 10 others time out; no conflict | 48.5 s | 1,564 ms | 3,066 (a timed-out view: ~8,800 timeouts among 67 live) |
| f + 1 = 34 silent, one virtual hour | 100 | no commit, no panic, no engine error; stays in view 1, re-broadcasting every 48 s | 11.0 s | - | 321,750 timeouts and 4,875 votes in the hour |
| steady state, 20 views | 200 | every view commits | 20.2 s | 963 ms | 948 |
| one leader down | 200 | stall 32 s | 50.0 s | 2,379 ms | 4,035 (the timed-out view: ~65,700 timeouts) |

Per-node peaks over every run: future buffer 0, future timeout collectors 0, voters ledger 1
view, parked votes 0, imported blocks <= 1, vote queue 0. Nothing grows with time in the
f + 1 hour. Per node and per view this is ~5 ms of consensus CPU at n = 100 in steady state
(~10 ms at 200), and ~40 ms (100) / ~150 ms (200) in a timed-out view.

What the simulation does not cover: real transport latency and loss, the two-topic gossip
duplication, the execution layer (blocks are "imported" instantly), and nodes at different
views except through silence. The in-process run at 100 is fast enough (seconds to a minute
per case) that it can be a regular `#[ignore]` regression; it found no engine bug.

## 3. Fixes made (each its own commit, each with a test)

- **F1** `fix(h2-consensus): scale the future-message buffer with the validator set`
  (`state_machine.rs:166-190`, `:1655-1663`, `:1703`). The per-view cap of 64 cut a 67-member
  vote or commit quorum for a future view short, against the stated intent of the unchecked
  class (`n + 2`). Now per view `max(64, 2n + 2)`, total `max(256, 2 x per view)`; seven
  members keep 64 / 256. Test `scale_tests::a_100_member_commit_quorum_fits_the_future_buffer`.
- **F2** `fix(h2-node): let the body channel serve a 100+ member fleet`
  (`body_channel.rs:216`). 64 connections, the rest closed on accept: in a 100-member fleet a
  third of the leaders could not push a body to a given node. Now 1024 (idle connections hold
  no body buffer). Test `body_channel::tests::a_200_member_fleet_is_served` (fails at 64 with
  "connection 64 refused").
- Plus `test(h2-consensus): measure certificates and the engine at 100 and 200 validators`
  (the benchmark and the simulation above).

## 4. Proposals (not done here)

| # | Proposal | Why | Estimate | Owner / collision |
| --- | --- | --- | --- | --- |
| P1 | Check `collector.has_vote_from(voter)` (and the commit collector) before the pairing in `process_vote_inner` / `process_commit_vote` (`voting.rs:84-100`), as the batch path already does | a vote received on two topics or by gossip + direct is verified twice today; after the quorum, late copies are pure cost | 0.5 day | vote-gate lane (state-machine vote path) |
| P2 | Profile 1 default `N42_VOTE_AGGREGATE_VERIFY=1`, and the same same-message batch for timeouts of the current view (collect, verify at quorum, fall back per signature) | 9-10x fewer pairings on the leader (64 -> 11 ms per round at 100) and per node in a timed-out view (60 -> 6.5 ms); 28 % less fleet CPU in the steady 100-engine run | default flip: 0.5 day + a fleet A/B; timeout batch: 2 days | vote-gate lane for votes; timeouts in `timeout.rs` |
| P3 | Block bodies at 100: `flood_publish(false)` on the block topic only (local, not wire-visible) or the direct body channel / fetch-on-miss as the main path | flood publish sends a full body to all 99 peers (240 MB per 2.4 MB block, 30 MB/s from the leader at 8 s) | 1 day + measurement; needs gov5's agreement because it changes how fast its members get bodies | h2-net / gov5 |
| P4 | Drop the timeout relay when the timeout already arrived by gossip, or relay only from f+1 designated members | ~(n-1)^2 extra `SendToValidator` per timed-out view; on gossip they are publish-time duplicates (cheap), but on direct streams they would be real | 1 day | `timeout.rs` |
| P5 | Aggregate already-verified signatures without the second subgroup check (`AggregateSignature::aggregate(.., false)` for verified inputs) | 3.8 ms per QC at 100, 6.4 ms at 200, on the leader, twice a view | 0.5 day, crypto review | h2-primitives |
| P6 | Verify a commit QC in the commit domain first where the caller knows it is one (proposal `justify_qc` after a Decide, header QCs) | the any-domain path pays a failed prepare pairing first: 1.6-2.0 ms instead of 0.75 | 0.5 day | engine / header lane |
| P7 | Catch-up: verify one anchor QC per range and link the rest by parent hash, instead of a QC (and seal) per header | 650 headers/s single-threaded bound | 2-3 days | sync lane |
| P8 | Default `N42_H2_MAX_INBOUND` to `max(128, 2n)` from the genesis set, and confirm gov5's peer cap at 100 members | 128 does not hold a 200-member static mesh; gov5 "near 50" would not hold 100 | 0.5 day (ours); gov5 to answer | h2-net, gov5 |

## 5. What a real 100-validator mixed round on one host needs

The standard asks for >= 100 validators of all three clients, several validators per execution
layer, and a round with f = 33 absent and a leader killed (AM17).

- **Genesis.** A Profile 1 genesis (AM22 values) whose `hotstuff.validators` lists 100+ members
  (n42-rs derives dev keys from a public seed; the same derivation must give gov5 and n42-26
  their keys), `f = 33`, and the committee pool as AM23 keeps it. The h2-v4 wire caps hold
  4096 members; nothing in the header changes.
- **Processes.** 100+ validator processes (`h2_validator`, gov5 members, n42-26 members) plus
  the execution layers. One `h2_validator` per key; an execution layer serves several
  validators: 10 n42 execution layers x 10 validators each, plus gov5's and n42-26's own. A
  follower EL receives the same block from each of its validators (idempotent `newPayload`);
  only the leader's validator builds.
- **Ports.** Per validator: one libp2p TCP port, plus the body channel (`--body-port-offset`)
  if direct push is on, plus `--mobileverify.http` if the MobileAnchor gate is part of the
  round (2101<i> today: needs a wider scheme past 9 members). Per execution layer: p2p, http,
  authrpc (and ws). A 100-member fleet needs ~100-200 validator ports and ~40 EL ports; the
  scripts' fixed per-member ports (`scripts/devnet-fleet.sh`: 18545/18551/30313 ...) need a
  base + index scheme.
- **Connections.** Static full mesh: n(n-1)/2 = 4,950 libp2p connections (x2 FDs on one host
  = ~10k), plus 9,900 body-channel sockets if direct push is on. `ulimit -n` >= 65536 for the
  round. gov5 members must accept ~99 peers (P8).
- **Memory.** Consensus state is small (per node O(n) maps, kilobytes). Each validator process
  is a libp2p swarm with gossip queues (handler queue 5000 messages per peer: bounded, but at
  99 peers a stalled peer can hold up to 5000 x message size); estimate 100-200 MB per
  validator process, 10-20 GB for 100. Execution layers dominate: an 8 s slot at the devnet's
  load is light, but 10-20 ELs at ~1-3 GB each plus the committee pool (200k scalars, 6.4 MB,
  and 1-2 s of parallel key derivation at each start). The box has 136 GB; a round fits if no
  fleet7 run shares it.
- **CPU.** Per node consensus CPU is ~5 ms per 8 s view (steady) and ~40 ms per timed-out view
  at n = 100 (section 2b); 100 validators are ~0.1 core in steady state. GossipSub and block
  bodies (P3) and execution are what will load the host.
- **Bandwidth on loopback.** Votes and timeouts: tens of MB per view fleet-wide. Bodies by
  gossip at 480M gas: up to ~2 GB per block fleet-wide with flood publish (P3) - measure the
  first round with small blocks.
- **Absent-member and killed-leader legs.** f = 33 absent: the 67 present must all be live
  for every commit (any extra loss stalls), every third view times out (24 s + 8 s each), so
  the round should run long enough for at least one full rotation (100 views ~ 15-25 min).
  Killing a leader costs one base timeout (32 s with the slot), as simulated.
- **Settings for the round.** No straggler grace (or rule `quorum`); `N42_H2_MAX_INBOUND`
  >= 256; batched vote verification optional (P2); vote transport `gossip` or `both` (gov5
  members speak gossip only).
