# E=1 with many validator keys: 21 and 99 keys on one execution layer

Audit and loop347 preparation, 2026-10-07. Read from code, the loop345 ALL logs and a dry run of the launch plans; nothing was
built or run. **Measured** means read from loop345 ALL (7 keys, 60 ms, 200k transfers); **estimate** is arithmetic from it and from
blst's published cost (a single BLS verify ~1.1 ms on this class of core: 2 Miller loops, the final exponentiation, hash to G2 and, with
`verify(true, ...)` at `h2-primitives/src/bls/keys.rs:149`, a signature subgroup check). Quorum and f follow the node's rule
`f = (n-1)/3`, quorum `n-f` (`h2-consensus/src/validator/set.rs:28,93`, `qmdb-reth/src/hotstuff.rs:232`, `h2_validator.rs:249`): 7 -> f 2, quorum 5;
**21 -> f 6, quorum 15; 99 -> f 32, quorum 67**. The genesis files carry only the validator list.

## 1. The two suspected O(N) points

**(a) The leader verifies every vote on its loop, one signature at a time.** The service feeds each gossip message to the engine as its own
event (`service.rs:2142`, `ConsensusEvent::Message`). `process_vote_inner` (`voting.rs:62-95`) calls `verify_single` -> blst
`verify_prevalidated` for every R1 vote *before* it looks at the collector, so votes after the quorum are verified too, until the view moves; a
late R1 vote of a past view is verified again in `note_late_vote` (`voting.rs:32-50`), up to twice (the progress-vote message, then the vote message;
progress votes exist only with the grace on). R2 votes are verified one by one the same way (`voting.rs:262-269`), but a vote that arrives after
the commit QC is dropped on the view mismatch (`voting.rs:252`) unverified. The QC itself costs almost nothing: votes enter the collector as
`add_verified_vote`, so `build_qc_with_profile_message` (`quorum.rs:236-247`) only aggregates. The batch machinery exists and is not wired:
`ConsensusEngine::authenticate_vote_batch` (`state_machine.rs:722`, a randomised multi-pairing, ~0.5 ms a signature because every signature
re-hashes the same message) and `process_authenticated_message` (`:996`) are called from tests only; `AggregateSignature::verify_aggregate`
(`aggregate.rs:24`, `fast_aggregate_verify`) is used for QCs. Followers do not verify other keys' votes: a non-leader returns before the check
(`voting.rs:78`); they still *decode* every vote (`h2_wire.rs:604` `BlsSignature::from_bytes`, a G2 decompression, ~60 us).

Cost on the leader's loop per block, estimate (R1 N-1 verifies + R2 q-1): **7 keys 10 verifies = 11 ms; 21 keys 34 = 37 ms; 99 keys 164 = 180 ms**
(+35 ms when the grace's late and progress votes pay their second attempt). On the *critical path* (quorum assembly: q-1 verifies for PrepareQC,
then q-1 for CommitQC, each batch of votes arriving together after the proposal / the PrepareQC): 2(q-1) x 1.1 = **9 / 31 / 145 ms**. Check against
loop345 ALL: `R2_collect` p50 5 ms with q-1 = 4 verifies (measured; 4 x 1.1 = 4.4), `R1_collect` p50 5, p90 29 (the tail is the followers' import).
So at 21 keys the vote road alone is half of a 60 ms cycle and at 99 it is 2.4 cycles: **the cycle at 99 keys is bound near 150-300 ms by
verification, whatever the layer does.** The batched form: one check per round over *the same message*: aggregate the arrived signatures and
public keys (G2/G1 additions, ~2 us each) and run one `fast_aggregate_verify` (~1.3 ms for 66 votes, flat), bisecting only on failure so the
equivocation and bad-signature handling is unchanged; the keys are the registered validator set the QC check already trusts, so no new assumption.
It needs (i) `h2-primitives`: `verify_same_message_batch(msg, sigs, pks)` over blst's aggregate API; (ii) `service.rs`: collect the Vote/CommitVote
events of one `drain_transport` step (up to `MAX_TRANSPORT_DRAIN` = 256, `service.rs:657`) when this node is the leader, authenticate them as one batch
and hand them to `process_authenticated_message`; (iii) votes after the quorum verified in one aggregate when the loop is idle, or not at all when
the grace is off (they only feed `voters_seen`). Result: ~3 ms a round at any N. A cheap, separate saving: decode the vote signature lazily so a
non-leader drops a vote without the G2 decompression (196 x 60 us = 12 ms a block per follower at 99 keys, estimate).

**(b) The leader waits for every voter (`F7_STRAGGLER_GRACE_MS`, default 600 in the bench).** `propose_if_leader` (`service.rs:2669-2689`): for
view v the leader reads `voters_seen(v-1)` (verified R1 voters of its own previous view, kept for 8 views, `state_machine.rs:23,878`); if `0 < seen < N`
and fewer than `grace` ms have passed since the commit QC of v-1 (`commit_qc_formed`), the proposal is deferred ("waiting for the stragglers'
votes"). It proceeds when all N votes (real or progress) have arrived, or the grace runs out. It was added for the round-43 tenure-handover stall
(`service.rs:1222-1236`): with one layer per key, the keys outside the quorum imported slower than the leader proposed, fell a block behind each view,
and the next leader, if it was one of them, could not propose until it had caught up (10-40 s stalls). Followers whose vote was withheld because
the view had passed send a progress vote after their import (`state_machine.rs:1364`), which is what the leader counts. At 99 keys the rule is "the
slowest of 99": every block waits for the last of 98 follower loops, and one key that is merely 20 ms late on every block puts 20 ms on every cycle;
one dead or wedged key makes every block 600 ms (the grace) after it. Loop345 ALL already shows the signature at 7 keys: `total` max 600 ms, two
proposal intervals >= 500 ms in 4,323. **At E=1 the handover reason is gone**: all keys read one layer, which imports each block once, so a key
cannot be "a block behind" on import; what lags is its validator loop, and that is not what the next leader needs. Rule change (local policy, no
protocol change): *wait for the next leader and for lag, not for the last voter.* The leader keeps, per validator, the last view it was seen at (the
ledger it has, `note_voter`); it defers the proposal only while (1) the next tenure's leader has not been seen at view v-1 and the tenure ends within the
next D = 2 views, or (2) some voter's last seen view is more than D = 2 behind (a voter one block late never holds anything), and in either case at
most `min(grace, 2 x median cycle)` since the commit QC. Steady state at 99 keys: no wait; a key that falls 3 blocks behind costs one short grace and
is then ignored until it returns, with its lag capped at D blocks at every handover, which is what the stall needed. Keep `F7_STRAGGLER_GRACE_MS=600`
on the seven-layer chains where the stall was measured; `K99G0` (grace 0) tests the E=1 claim.

## 2. Every other per-key cost at E=1 (per block unless stated)

| Item | Per key | 21 keys | 99 keys | Basis |
| --- | --- | --- | --- | --- |
| Gossip messages (distinct) | - | ~46 | ~200 (2N votes + proposal, QCs, body) | each vote is *published*; v4 has no direct-to-leader channel (`service.rs:2367-2373`) |
| Deliveries to a node | 8-12 copies of each | ~370 in, ~370 out | ~1.6k in, ~1.6k out | `flood_publish` is on (libp2p-gossipsub default, not overridden in `h2-net/src/config.rs:88-100`): the publisher sends to all peers, then every receiver forwards on its mesh (D 8, Dlo 6, Dhi 12, gov5 values). IDONTWANT only above 1000 B, votes are smaller. |
| Gossip loop time | ~20 us a delivery (estimate) | 15 ms | 64 ms | the swarm is polled *inline* in the service loop (`service.rs:1581-1621`, `transport.rs:735`): same thread as the engine |
| Hops | 1 for the originator's flood, mesh adds duplicates not hops; mesh-only diameter of a random 8-regular graph on 99 nodes is 3-4 | 1-2 | 1-3 | not logged by gossipsub; the traced arrival delay of the proposal is the proxy |
| libp2p connections | 98 dialled each way (`--peer` x N-1, `fleet7-env.sh`), up to 2 per pair | <= 420 | <= 9,702 (4,851 pairs x 2) | libp2p keeps both of a simultaneous dial; valsample347 counts them. Noise handshakes ~1.5 ms x 2 each: ~30 CPU-s at start. fd limit 524,288, somaxconn 4,096: fine |
| Requests to the layer | 1 compact body (header only, 15 KB, `payload_serve`) + the CHECKED/final status, ImportOnce answers all but the first at once | 21 | 99 (1.5 MB over loopback) | `once_reqs` counts them; registry cap 64 hashes (`import_once.rs:40`) is ample |
| Commit forkchoice | ~1.1 (7.7 a block at 7 keys, measured, ~28 us on the engine thread) | 23 (0.6 ms) | 109 (3 ms, +5% of the engine thread; a burst of 99 queued messages delays the next one up to ~3 ms) | `SHARED_EXECUTION_SCOPE.md` 9.3 |
| Pollers (`n42Engine_inMemoryBlocks` + `persistedBlock`, every 50 ms, `h2_validator.rs:445`) | 40 JSON-RPC calls/s | 840/s | 3,960/s (~0.2-0.3 core on the layer's runtime) | only the leader reads the gauge: start it for the leader only |
| Vote signature decode | ~60 us x 2N | 2.5 ms | 12 ms | `h2_wire.rs:604` |
| Leader: verification | see 1(a) | 37 ms | 180 ms | |
| CPU of a follower key | 0.15-0.20 core measured at 7 keys (threadcpu, loop345 ALL) | ~0.35 (estimate) | ~1.1: the loop alone needs ~80 ms per 60 ms block | gossip + decode + base 6 ms |
| **Validators' CPU, all keys** | | **~7 cores** | **~100 cores (60-130)** | the 16-CPU set of today holds 7 keys at 1.2 cores |
| RSS | 0.28 GB measured at 7 (2.0 GB / 7) | ~6 GB | ~30-40 GB (+~0.15 MB a connection) | host has 136 GB; the layer 29 GB, the huge-page pool 40 GB: tight, see section 3 |
| Log volume | 12 MB a leg | 250 MB | 1.2 GB; the traced validators log ~400 lines a block more | `F7_TRACE_VALIDATOR=0,1,2` only |

## 3. Anything else that assumes a small N

Not scaled by N (checked): `baseTimeout` 6,000 / `maxTimeout` 30,000 (genesis), `epochLength` 200 and the 200,000-key `committeePool` (seeded independently of
the validator list, static validator set), `MAX_BITMAP` 1,024 B / `MAX_VALIDATORS` 4,096 (`h2_wire.rs:14,17`), `VOTERS_SEEN_WINDOW` 8, the
`HELD_EXECUTIONS` map (refused under import-once), the import-once cap 64, leader tenure 1,024 (a leg of ~10k views has <= 10 distinct leaders: keys 0-2 in the
window). **Startup:** the view clock starts when the first mesh peer appears (`service.rs:2433-2446`), not when a quorum exists; `f7_spawn` polled for the pid file every
200 ms, a 20 s launch span for 99 validators with views timing out meanwhile (fixed, 20 ms). **Memory:** validators start after the layer and take ~35 GB of the free pool before
the flood's `thp:always` heaps ask for it; the runner skips a K99 leg under 75 GB available. **Layer size:** the budget is 224 CPUs and 99 validators need ~100, so K99 gets a 128-CPU layer; `K7L`
(7 keys, the same 128-CPU layer) separates that effect from the key count.

## 4. Dry-run findings (`scripts/fleet7.sh plan` for 7, 21, 99; 7 is byte-identical to before)

1. `fleet7-env.sh` refused N > 7: only seven network keys. Keys >= 7 are now `sha256("n42-fleet7-netkey-<i>")` (first seven unchanged).
2. The node CPU budget was `F7_NODES x F7_CORES_PER_NODE` (99 x 32 = 3,168 CPUs: a 3,072-CPU layer and validators placed past the host). `f7_fleet_cpus` (`F7_FLEET_CPUS=224`) replaces it in all seven places; K7 plans exactly as loop345.
3. `f7_spawn` polling 200 ms -> 20 ms; `F7_TRACE_VALIDATOR=0,1,2` turns `N42_H2_TRACE_MSGS` on for those validators only (fleet-wide it would be 400 lines a block each).
4. The loop346 runner hard-coded seven (EL map default, verify, log copies, wipes); `run-loop347.sh` takes the count from the map, removes stale `node<i>` dirs of a larger previous fleet, and `LOOP347_DRY=1` prints every stage's plans (all 0 refusals).
5. Genesis: `scripts/fleet-genesis-many.py --nodes 21 99` writes `n42_fleet7_bench_v21.json` / `_v99.json`: validators 0-6 and the BLS keys from `h2_keygen --seed n42-fleet7-validator` (index-only derivation, so the first seven equal the bench file's), derived addresses for the rest, `extraData` vanity `n42-fleet7-bench-v<N>` (distinct hashes); alloc, forks, gas limit, period, timeouts, committeePool equal (checked).

## 5. loop347 (not launched): `launch-loop347.sh <a|b|c>` -> `run-loop347.sh`

Base = loop345 ALL verbatim (E=1, `N42_IMPORT_ONCE=1`, 200k, 60 ms, depth 1); each leg appends its key count, chain, `F7_VAL_CPUS` and `F7_TRACE_VALIDATOR=0,1,2`. Stage **a**: WARM, WARMb, `K7` (16 val CPUs, layer 208 = loop345), `K21` (32 / 192), `K99` (96 / 128). **b**: WARM, `K7b`, `K21b`, `K99b`. **c**: WARM, `K7L`, `K21P50`, `K99P50` (`F7_BLOCK_INTERVAL_MS=50`), `K99G0` (`F7_STRAGGLER_GRACE_MS=0`) only if >= 1% of K99's proposal intervals are >= 500 ms.
Gates as loop346 (build and tests, 120 G a leg, 75-minute cap a stage, 600 s a leg, replay and body gates). Report per leg (`manykeys347.py`, `valsample347.py`): `R1/R2_collect` and `votes=` of the leader; proposal -> first vote -> quorum -> last vote
for R1 and R2 (the slowest key = the last arrival; its delay distribution) from the traced leaders' `recv` lines; proposal intervals and the count >= 500 ms (the grace); `slow step` lines by event kind; proposal arrival delay at the traced followers (hop proxy); validators' CPU (cores, per key), RSS, threads and the libp2p connection count (`/proc/net/tcp`).
**Missing fields, for a code change:** the leader's vote-verification time (add `verify_us` and `verify_n` to `ViewTiming`, `state_machine.rs:26`, summed around `verify_single` at `voting.rs:88,269` and printed in `summary()`); the voter index on the trace line (`service.rs:2144`) to name the slowest key; hop count (not exposed by gossipsub).
Predictions to test (estimates): K21 cycle 70-85 ms at 60 ms pacing (leader loop ~75 ms), K21P50 no faster; K99 150-300 ms, validator CPUs saturated, `R2_collect` ~70 ms; K99G0 recovers only what the grace cost. If K99 looks like that, the vote batch (1a) and the lazy decode are the first code to write.

## 6. What was built (2026-10-08): four switches, all off by default

Code, not measured on the fleet yet. Off, every path is the one before (tests), and nothing on the wire changes under any switch.

**`N42_VOTE_AGGREGATE_VERIFY=1` (1a).** `h2-primitives/src/bls/verify.rs` `verify_same_message_batch`: n signatures over one message,
random non-zero 64-bit weights, `e(sum r_i s_i, g1) = e(H(m), sum r_i pk_i)`: H(m) once, one verification, two single-threaded Pippenger
sums and one G2 subgroup check per signature. The weights matter: a plain aggregate (`fast_aggregate_verify` of the sum) accepts two invalid
signatures that cancel (test `cancelling_signatures_do_not_pass_the_weighted_batch`); with them a passing batch means every member verifies on its own
(to 2^-64), so a vote's meaning is unchanged. Timing (`same_message_batch_timing`, release, ignored test): 66 signatures 4.4 ms against 41 ms one
by one; 14: 1.7 ms against 8.6. Engine (`h2-consensus/src/protocol/vote_batch.rs`): the service hands every vote to `queue_vote` and calls
`flush_votes` at the end of each `drain_transport` (the drain boundary is the event loop's natural batch). A group (same view, block hash, and for
R2 the changes hash) is verified when the collector could reach its quorum with it (or it is not for the collector's block: equivocation evidence,
verified at once as before); smaller groups wait for the next drain, which costs nothing since no QC can form without them. A failed batch falls back
to one-by-one checks of its members: **bound 1 + n checks for n votes, and a vote is verified on its own at most once**, so a peer that poisons every
batch (anyone can gossip a vote naming any voter) brings the leader back to today's cost plus one batch per group and drain, never above. Exact
repeats are dropped before the batch, and a vote naming a voter the collector already has is dropped without a check. After the PrepareQC (and for
late or progress votes after the view), R1 votes are **parked unverified** (at most 2N a view, 8 views): the protocol does not need them, and the
voters ledger (`voters_seen`, the straggler rule's input) verifies them only when the rule asks, `settle_voters_seen(view, voters)`: one batch per
message (vote, then progress), so post-quorum votes now cost nothing at arrival and a couple of batches at proposal time. R2 votes after the
CommitQC are dropped on the view mismatch, as before. Accepted votes enter the collector through `process_verified_vote` / `process_verified_commit_vote`,
the path the existing randomised batch verifier already used. The leader line of `block committed!` gains `verify_us verify_n verify_batches
verify_fallbacks` (also counted on the one-by-one path). Tests (`vote_batch_tests.rs`): batched equals sequential and the PrepareQC and Decide
encode to the same gov5 wire bytes; one bad vote of 20 rejected, 19 accepted, `verify_fallbacks=1`; votes wait until the quorum is reachable;
post-quorum votes parked and settled only on demand; a late progress vote settles under its own message.

**`N42_STRAGGLER_RULE=quorum` (1b, needs the grace).** `h2-node/src/straggler.rs`, `service.rs` `quorum_straggler_defers`. Why the grace exists:
round 43 (`with_straggler_grace`, `service.rs` doc; `docs/NATIVE_FLEET7.md` round 43): with one layer per key the keys outside the quorum imported more
slowly than the leader proposed, fell one more block behind every view, and when the tenure passed to one of them it could not propose until it had
caught up: 10-40 s stalls at each handover. `All` prevents it by bounding *everyone's* lag to zero, at the price of the slowest of N every block.
`Quorum` bounds what the stall needed: (i) while the handover is at most D = 2 views away (`next_tenure_leader`; every view under tenure 1) the
outgoing leader waits until the incoming leader has voted (or sent its progress vote, which a follower sends only after its import,
`state_machine.rs` `withheld_votes`) at the previous view, so it has imported the parent of its first block when the tenure passes; it is never given
up on; (ii) any voter whose last verified vote is older than `view - 2` is waited for, so no live voter's lag grows past 2 blocks, which is what made
the round-43 lag unbounded; a voter one block late holds nothing. Each wait is capped at `min(grace, 2 x median of the last 16 commit intervals)`; a
lagger still missing at the cap is given up on until it is seen within the bound again (a dead key costs one wait, not one per block), and its lag
is then the protocol's ordinary f. Worst case at a handover: the incoming leader is at most D = 2 blocks behind (it was bounded by (ii)) and the
outgoing leader has spent up to 2 capped waits on it. Unset, the grace path is the old code with one addition: under batching it settles the parked
votes of the previous view before counting them. Tests: `the_outgoing_leader_waits_for_an_incoming_leader_that_is_behind`,
`one_slow_voter_among_seven_is_not_waited_for`, `a_lagging_voter_costs_one_wait_then_is_given_up_until_it_returns`, the cap. The `proposal sent`
line gains `straggler_waits` (cumulative) and `straggler_wait_us` (this proposal, from the decision of the previous view).

**`N42_GOSSIP_OFF_LOOP=1` (3a).** `h2-net/src/pump.rs`, `transport.rs`: `H2V4Transport` keeps its API and wraps the inline core or a tokio task that
owns the swarm (on the validator's multi-thread runtime, so off the thread that runs `block_on(service)`). Inbound: decoded events through a bounded
channel (4096; when the loop is behind the task waits, nothing is dropped; one FIFO, so per-peer order is kept); publishes through a second bounded
one (1024; full is the transient `AllQueuesFull` the service already retries, and transiently refused publishes are retried by the task);
requests, responses, pushes and dials through an unbounded command channel (a dropped response would leave a peer waiting out its timeout).
GossipSub's configuration is untouched. What the loop still does per message: one channel receive, `wire_bridge::to_engine` (field copies; the G2
decompression and the envelope or native decode happened on the task), the direct-vote dedupe when on, and `queue_vote` or `process_event`.
Both timing lines gain `inbound_queue_max` and `gossip_poll_us` (the task's poll time off the loop, the drain's own polls inline). Tests:
`h2-net/tests/off_loop.rs` (both directions over a socket, order kept, stats), and `four_node_fleet.rs` passes with `N42_GOSSIP_OFF_LOOP=1`
`N42_VOTE_AGGREGATE_VERIFY=1` and either `N42_VOTE_TRANSPORT`.

**`N42_VOTE_TRANSPORT=direct|both|gossip` (3b, default `gossip`).** `h2-net/src/rpc.rs` `VOTE_PROTOCOL` = `/n42/vote/1`: `tag (1) || len (4, BE) ||
body`, tag 1 `Hello` (index BE, 96-byte signature), 2 the vote's native-topic bytes, 3 its v4 envelope bytes; one ack byte back (fixtures pinned in
`vote_protocol_tests`). A received vote becomes `TransportEvent::DirectVote` wrapping the same `Native` / `Envelope` event gossip produces, so the
receiving path is the gossip one. The leader's peer id comes from the hello each member sends on connect when it runs `direct` or `both`: its
index and a BLS signature by its consensus key over `"n42/vote-hello/1" || genesis hash || peer id` (`h2-consensus/src/protocol/vote_hello.rs`;
the Noise handshake authenticates the peer id, so a hello cannot be replayed for another peer). `direct` sends to the leader when its hello has
verified and by gossip otherwise (`fallbacks`); `both` sends by both. A leader deduplicates before the engine by (round, view, voter, signature):
the two copies of a real vote are the same bytes, and keying by (view, voter) alone would let a forged vote that arrives first shadow the real one.
The gossip path is byte-identical in every mode, and `gossip` sends nothing new (no hello). **gov5 does not speak the protocol: a mixed fleet runs
`gossip` or `both`.** For gov5 to adopt it: register a libp2p stream handler for `/n42/vote/1` with this framing, verify the hello against its
validator set and keep index -> peer id, send its own hello on connect, send a vote to the leader's stream (keeping the topic as fallback), and
dedupe by (round, view, voter, signature) before its vote handler. Tests: `a_vote_by_gossip_and_directly_reaches_the_engine_once`,
`a_direct_vote_falls_back_to_gossip_until_the_leader_announces_itself` (a wrong-key hello names no one), `both_sends_by_both_paths_and_gossip_by_one`.

Fleet legs (on loop345 ALL's env, `F7_STRAGGLER_GRACE_MS=600`): per key count 7, 21, 99, add in order and measure each: (1)
`N42_VOTE_AGGREGATE_VERIFY=1` (expect `verify_us` per view ~2 batches: K99 ~10 ms against ~180, R2_collect down to the arrival spread); (2) + `N42_STRAGGLER_RULE=quorum` (expect
the >= 500 ms proposal intervals to vanish, `straggler_waits` near the handovers only); (3) + `N42_GOSSIP_OFF_LOOP=1` (expect `slow step` lines and the
leader's `gossip_poll_us` on the loop to go, `inbound_queue_max` small); (4) + `N42_VOTE_TRANSPORT=direct` (all-Rust only; expect the deliveries per
node to fall from ~1.6k to ~2N + gossip of the rest at K99).

### 6.1 The silent key (loop347 void legs): a validator that joined after view 1 holds every block forever (fixed 2026-10-08, see "The fix" below)

Evidence: `scripts/fleet7-runs/results/loop347K7b-void-node4-v.head.txt`, `loop347b-void.out` (K7b: cycle 0.612 s, 326,667 TPS, R1 "views with fewer than 6 votes received: 266" of 266, `proposals_given_up=2`). The void leg's own logs were overwritten by the rerun; `bench-loop347WARMb` is a healthy start (node4 saw view 1 at 03:50:18.56), so the sequence below is read from the head file and the code.

**Sequence on validator 4.** It starts at 04:46:41.7 on a fresh consensus state, dials peers (6 not yet up: "dial failed"), and its first line after `running...` is `view 2`, with the compact body of the view-2 block (hash 0xf635..., the block after 0xa19f...). It never printed `view 1`, a body or `COMMIT view=1`: the view-1 block was gossiped before its mesh formed, and gossip does not replay. At once: `block runs ahead of the execution layer; held until the pull reaches it` (`number=2 tip=0`). From then on every block is held, `a block body has been held far too long` appears per block, and `NO BODY` (`PayloadMissing`) from the validator example. Nothing ever releases it.

**Why.** `H2Service::far_ahead` (`service.rs`) holds a block when its parent is not in `self.imported` and `number > tip + 1`. `imported_tip()` reads the tip from `driver.head()` (this validator's own driver, still at genesis because it imported nothing) and the in-flight imports; `imported_height` is only the fallback "for a head this node never saw a header for", and the genesis header is always known, so it is never consulted. The only other way out is the pull: `consider_catch_up` starts a range pull only when a peer's height is above the layer's `latest_block_number`. At E=1 all seven keys share one layer, which the other six keys have already filled, so `height <= latest` returns before any pull ("a block the fleet gossiped before this node connected never comes by itself" is handled only when the layer lacks it). The layer holds everything; this validator's view of it (`imported_height`) is updated by that very read, yet `imported_tip()` ignores it. Held forever: neither the head nor the parent set can move without an import, and an import needs the block released. The other six keys saw the view-1 block, so block 2's parent was in `imported` (the exemption on the first arm of `far_ahead`) and they voted. With one layer per key (E=7) the layer of a late key is behind, so the pull does run; the defect exists only where the layer is ahead of the validator, i.e. E=1. Why the second leg of a claim: unmeasured; the common factor is a start where node 4's mesh joins after node 0 has proposed view 1 (node 0's first block precedes the other keys' dial), which the warm second leg makes likelier. Not proven.

**Why nothing caught it.** `fleet7-verify` and the body gate read the shared layer's chain, which is complete and valid (six keys build it); a key that does not vote leaves no hole in it. The counter that shows it is the leader's vote-road report: R1 `views with fewer than 6 votes received` equals the number of views (266 of 266), and `votes at formation: R1 median 5 max 5`, while R2 reads 1. Per-leg, `proposals_given_up` and `engine_idles_over_5s` did not name a key. No line names the silent index; the validator's own `held far too long` WARN is the only direct one.

**Would `N42_STRAGGLER_RULE=quorum` contain it?** Yes for the cost, no for the key. Key 4 is never seen (`last_seen = None`), so it is "more than 2 views behind"; at view 3 the leader waits `min(grace, 2 x cycle)` (600 ms while no cycle is known), then `given_up` holds it and every later view proceeds on the 5-of-7 quorum (the next-leader clause does not apply: tenure is 1024 views, key 4 is not the next leader). Expected cycle: the healthy 7-key cycle, one 600 ms wait per leg instead of one per view. The key itself would never recover: there is no path from "held" to "fetched" at E=1, so it stays silent and stays given up (a rule that tolerates it also hides it).

**Smallest fix.** In `imported_tip()` take the higher of the driver head and `imported_height` (the layer's last read, which `consider_catch_up` already sets): `tip_of(head, in_flight)` becomes `max` over three values. A key whose own layer already holds the chain then sees the tip at `latest`, `far_ahead` is false, the held block is released by the next drain and executed (the layer answers it as known/valid), and the vote follows. Additionally, make a held block ask: when `say_held` reaches `HELD_TOO_LONG`, force a `consider_catch_up` layer read, so the release does not depend on a peer height arriving. Not checked here (no build): whether the driver needs the missing ancestor (block 1) to be known to it when it executes block 2 under deferred execution; if it does, release by fetching block 1 by hash from the layer (the `block_by_hash` road) before the held drain.

**The fix (2026-10-08).** `imported_tip()` is now the highest of the driver's head, the imports in flight and `imported_height` (the layer's last read; `tip_of(head, in_flight, layer)`), so a driver at genesis beside a layer at 5 has a tip of 5 and block 2 is not far ahead. A block held past `HELD_TOO_LONG` forces a layer-height read (`refresh_layer_for_held`, at most one per `HELD_TOO_LONG`), so release does not wait for a peer's height. The open question is answered from the code: the driver does not need block 1. It hands the body to the execution layer, which holds block 1 itself (shared layer); the driver's own lineage (`Settlement`) feeds only the safe/finalized tags, and a commit whose parent link is unknown moves nothing until the next blocks note themselves. So no fetch-by-hash is needed before release, at depth 1 or 2. E>1 is unchanged: a lagging own layer reads low, the block stays held and the pull brings the gap (test `a_lagging_layer_still_holds_a_far_ahead_block_after_the_forced_read`). Visibility: the "held far too long" WARN now carries `layer_height`; the leader names a key with no verified vote for 16 views (`SilentKeys`, WARN "a validator key has not voted for many views", field `key`, once per episode, read at view-2 so late votes have arrived).

**Test.** In `service.rs` tests, beside `a_head_one_behind_this_nodes_own_last_block_holds_everything_after_it`: (a) pure: `tip_of` extended with the layer height gives `Some(5)` for head 0, no imports in flight, layer read 5, so `runs_far_ahead(2, 5)` is false; (b) service level with `MockExecutionLayer` reporting `latest_block_number = 5` and a driver at genesis: deliver the body of a block numbered 2 whose parent was never seen, run a drain, and assert it is not in `held_bodies` and `ExecuteBlock` ran. Before the fix (b) leaves `held_bodies.len() == 1` after any number of drains, which is the logged `held=1`.
