# Profile 1 at 100 validators (gate 5 preparation)

2026-11-25, branch `feat/profile1-100-validators` (from main 07fd6ad89). The standard is
`docs/MIXED_PRODUCTION_STANDARD_V1_RC.md`: A3 (`f = (n-1)/3`, `q = n - f`; n = 100 gives f = 33, q = 67),
E10/E11 (signing domains; QC and TC are plain BLS aggregates over a bitmap of width n), §6 gate 5 (a mixed
round with >= 100 validators, several per execution layer, a killed leader and 33 absent members;
prerequisites "batched vote verification and a timeout-certificate path that is not quadratic in n, in every
participating client"), AM11/AM17/AM22. Nothing in the standard asks for a wire change, and none is made.

## 1. What a node verifies per view at n = 100

Steady state (no timeout). Every validator publishes one Round-1 vote and one CommitVote on the consensus
topic (E16), so each node receives about 2n = 200 votes plus the proposal, the block body and the Decide.

| Who | What | How (before this branch) | After |
|---|---|---|---|
| leader | up to 2(n-1) = 198 votes | one pairing check each (`voting.rs:93-97`, `voting.rs:297`), ~1.1 ms: ~220 ms of the leader's loop per view, ~150 ms of it on the quorum path (2(q-1) = 132) | same-message randomised batches per transport drain (`protocol/vote_batch.rs`, `ConsensusSigningProfile::verify_same_message`, `quorum.rs:155`): one batch per (round, block) group once it can reach the quorum; a failed batch falls back to single checks. Was off unless `N42_VOTE_AGGREGATE_VERIFY=1`, and the profile-1 round scripts unset every `N42_*`; now the profile-1 default (`service.rs` `with_vote_rules`, `vote_aggregate_default`) |
| follower | the votes | decoded, not verified (`voting.rs:85-87`: a non-leader returns before the check) | unchanged |
| everyone | proposal seal + justify QC, Decide's CommitQC | one single check (proposal) and one aggregate check per QC (`quorum.rs:618-639`, `660-682`: n_signers G1 additions + 2 pairings) | unchanged: O(1) pairings per certificate |
| leader | building the QC | votes enter the collector verified (`add_verified_vote`); `build_qc_with_profile_message` (`quorum.rs:275-374`) only aggregates | unchanged |

## 2. View change (timeout) at n = 100

| Step | Cost | Where |
|---|---|---|
| every node broadcasts one timeout (signature over the view only, E10) carrying its high QC | n messages on the topic | `timeout.rs:221-324` |
| each node verifies each timeout it receives | one single check each (~1.1 ms) + the embedded high QC, skipped when it equals the node's locked or committed QC (`state_machine.rs:2188-2203`), else one aggregate check: O(n) pairings per node, linear (gov5 does the same, `timeout.go:137-195`) | `timeout.rs:330-379`, `timeout.rs:16-83` |
| any node with q timeouts forms the TC | aggregation of already-verified signatures (`quorum.rs:451-559`) | |
| TC on the wire | one 96-byte aggregate, an n-bit bitmap, one high QC: O(1) signatures | E11 |
| TC verification (NewView, piggybacked TC) | one aggregate check: n_signers G1 additions + 2 pairings, plus the high QC's aggregate check | `quorum.rs:743-764`, `timeout.rs:504-507`, `539-546` |
| **relay (the quadratic part, fixed)** | every non-leader relays each first-seen timeout to the next leader (`timeout.rs:424-429`, `113-120`); on the gossip transport that is a publish of bytes the node already holds, gossipsub refuses it as a duplicate, and the duplicate path (`service.rs` `publish`) then sent the timeout **directly to every connected peer**: n relays x n peers = ~10^4 direct sends per node and ~10^6 across the set per view change, each decoded by its receiver before the duplicate check. Now a relay that the topic already carries goes nowhere else; only a node's own repeated timeout keeps the direct retransmission (late subscribers) | `service.rs` `send_to_validator` -> `publish_with(.., false)`; test `a_relayed_timeout_already_on_the_topic_is_not_fanned_out_to_every_peer` (fails without the fix) |

So the TC itself was already O(1) pairings to verify and O(n) bits on the wire; what was not linear was the
relay amplification around it. After the fix a view change costs each node O(n) messages and O(n) pairings.

## 3. Gossip message counts per view

Distinct messages: 1 proposal + 1 body + n Round-1 votes + n CommitVotes + 1 Decide ~= 2n + 3 = 203 at n = 100
(plus n timeouts and one NewView in a view that times out). The originator publishes to every connected peer
(`flood_publish`, gossipsub default), the mesh forwards with D = 8 (the GossipSub parameters are gov5's wire
contract, `h2-net/src/config.rs`), so each node receives each message a few times and drops the copies by
message id (`h2-net/src/message_id.rs`) before any decode.

## 4. What the standard requires and where n42-rs stood

| Requirement | Before | Now |
|---|---|---|
| batched vote verification (§6 gate 5, AM22) | implemented, off by default; off on every profile-1 round | on by default on profile 1 (`N42_VOTE_AGGREGATE_VERIFY=0` turns it off) |
| TC path not quadratic in n (§6 gate 5, AM22) | TC verify O(1) pairings; relay fan-out O(n^2) per node | O(n) per node |
| 100 validators designed and tested (AM11, AM17) | in-memory 100/200-validator engine tests (`state_machine_scale_tests.rs`), never a node round | the round below |
| several validators per execution layer (§6 gate 5) | supported (`N42_IMPORT_ONCE=1` on the layer: one import per block however many keys bring it, `bin/n42/src/import_once.rs`; allowed on profile 1, `qmdb-reth/src/profile1.rs:655`) but no profile-1 tooling | `scripts/profile1-many.sh` |

Not changed: timeouts are still verified one at a time on receipt (linear, as in gov5); a batched form like
`vote_batch` is possible but not needed for the requirement.

## 5. The 100-validator all-Rust round

`scripts/profile1-many.sh` (genesis, init, up, status, timing, down). Topology: P1M_E execution layers, each
started with `N42_IMPORT_ONCE=1`; validator i drives layer i mod E over the Engine API, all validators run
`--propose` (each leader builds on its own layer; the other keys on that layer send the same newPayload and
forkchoice, answered once by the import-once registry), full libp2p mesh. No new mode in `h2_validator` was
needed: E=1 with 99 keys was already exercised on the fleet7 chain (`docs/E1_MANY_KEYS.md`).

Genesis `genesis-100.json`: `genesis_8s.json` (V1) with only `config.hotstuff.validators` replaced (checked:
every other field equal); validators 0-3 are V1's entries, validator i's BLS secret is
`0x00 || sha256("n42-profile1-test-validator-<i>")[1:]` (the round script's test derivation, checked against
V1's four keys), the address of i >= 4 is `sha256("n42-profile1-test-validator-address-<i>")[0:20]`. n = 100,
f = 33, q = 67. Keys are test-only.

**Round r100a** (2026-11-25 05:39-05:50Z, 100 validators over 4 layers, idle, ~11 min,
`/data/n42-build/p1-many/r100a/`, summary `/data/n42-build/p1-many/r100a.out`):

| Criterion | Result |
|---|---|
| 8 s cadence | height 8 -> 84 between the two samples 605 s apart: 76 blocks, 7.96 s a block |
| every validator votes | every one of views 1-84: all 99 non-leaders sent the Round-1 vote and the CommitVote (the missing one is exactly the leader, v mod 100, which counts its own) |
| leaders rotate | 84 views led by 84 distinct validators (leader(v) = v mod 100, tenure 1) |
| refusals / timeouts / halts | 0 refusal lines, 0 view timeouts, 0 safety halts |
| equal heads | the four layers at the same height and hash at every sample (84: `0xfc1b8ad1...a284`) |
| QC formation at n = 100 | leader build -> PrepareQC p50 43 ms, p90 49, max 56 (views 2-84; view 1 waits for the start-up mesh, 5981 ms); build -> commit p50 67 ms, p90 74; QCs carry 67 signers |
| batched verification | a leader's view, e.g. view 50: `R1_collect=45ms R2_collect=21ms votes=67+67 verify_n=149 verify_batches=2 verify_us=14965 verify_fallbacks=0` (one-by-one would be ~164 ms) |
| CPU | 100 validators: 891 CPU-s in 605 s = 1.47 cores (0.015 a validator); 4 layers: 439 CPU-s = 0.73 cores |
| memory | validators 19.8 GB RSS (~198 MB each, 99 connections each), layers 1.9 GB |

**Round r100k** (killed leader, 2026-11-25 06:03-06:09Z, `/data/n42-build/p1-many/r100k/`, summary
`r100k.out`): validator 30 SIGTERMed at 06:04:50Z, before its view. View 30 timed out on all 99 live
validators at its 24 s `baseTimeoutMs`; every one of them formed the TC itself, the first timeout at
06:06:58.612Z and the last node's TC at 06:06:58.717Z (105 ms for the whole set); each node counted 67
timeouts (6,633 `received timeout` lines = 99 x 67, the collector stops at q) and **0 direct
retransmissions** (`duplicate timeout gossip; retransmitting directly`: 0 lines); view 31 committed, the chain
went on to height 43 with equal heads on the four layers, 0 refusals, 0 halts, every other view led by its
own leader (44 views, 44 leaders), build -> PrepareQC p50 41 ms. Before the relay fix each of the 99 nodes
would have sent each relayed timeout to its 98 connected peers (~66 relays x 98 = ~6,500 direct sends a node).

## 6. What gov5 needs for a mixed 100-validator round

- **Peers.** gov5's `--p2p.max-peers` defaults to 5 (`cmd/n42/cmd.go:508-513`); a gov5 member of a 100-member
  round has to raise it to the static peer count it dials (or the round uses a sparser static topology than
  this script's full mesh).
- **Several validators per execution layer.** Gate 5 says "several per execution layer, every producing
  client present". A gov5 node is one process per validator key with its own execution state; either gov5
  runs one process per key (100 gov5 processes are not needed: the Rust side can carry most keys) or gov5
  needs a multi-key mode. n42-rs does it with one `h2_validator` per key over a shared layer.
- **Keys and genesis.** Load `genesis-100.json` as is (validators 0-3 are V1's, so gov5's existing four test
  keys stay valid); a gov5 member at index i >= 4 uses the secret derivation above.
- **Prerequisites.** gov5 already batches Round-1 votes (`voting.go:175-182`, `batchVerifyVotes`
  `voting.go:486`), verifies a TC as one aggregate (`timeout.go:354`) and does not relay timeouts
  (`timeout.go:137-195`), so its TC path is linear per node. Nothing in its wire format has to change.
- **Timing.** 100 validators on one host cost ~1.5 cores idle; a mixed round adds gov5's processes. The
  killed leader costs one `baseTimeoutMs` (24 s) view, and 33 absent members leave exactly q = 67.
