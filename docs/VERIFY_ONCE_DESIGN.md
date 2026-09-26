# Verification paid once: the design question behind the last 3% (2026-09-26)

Where the four-to-three-node campaign ends (`FLEET7_PLAN_V4.md` sections 7-9): the fleet consumes 950-975k
transfers a second on a window with every block full at a 155-165 ms cycle, and the term that binds is that
**every node verifies every transaction's signature at its ingest** (10 us a signature at batch 256, 12 recovery
slots, ~820-850k/s admitted a node) on the same cores its vote road uses. Nothing configurable moves it (7.11,
7.14, 7.19, 7.22-7.24, 9.1). This note states what "verify once" can mean, what each form costs in safety, and
which one is worth building first.

## 1. What the protocol does today

A transaction reaches every node's pool through the ingest (or gossip); the ingest decodes it, verifies its
signature in batch, records its sender, and admits it. A leader builds a block from its pool; a follower assembles
the proposed block from its own pool by the description (the hash list), fetching what it lacks from the proposer,
and votes only when it holds every transaction -- so every transaction a follower votes for has been verified
by that follower. With deferred execution the header of block n+1 carries n's execution, and a follower checks it
against its own execution of n before voting on n+1. Safety therefore rests on: no honest node votes for a block
holding a transaction it has not verified itself.

`N42_INGEST_VERIFY=leader` (plan v5, 5.3) already lets a follower queue a frame's transactions under the
generator's *claimed* sender without verifying; the follower then verifies what a block carries on its vote road
(163k signatures in batch on 16 threads, ~130 ms) -- a relocation, not a saving, because the road is the cycle's
critical path.

## 2. Three forms of "once"

### A. Verification at execution, deterministic skip

Move the check into execution: a block may carry a transaction with a bad signature; execution verifies as it
applies and *skips* (no transfer, no nonce, no fee) deterministically; both leader and followers execute the same
rule, so the state roots agree. Safety holds by construction (an unsigned transfer moves nothing). Cost: the
verification lands on the follower's import (the execution of n), which with deferred execution precedes its vote
on n+1 -- the same 163k signatures a block on the same cores, on a path that is already 170-190 ms against a
160 ms cycle (7.4, 7.13). No saving on this fleet; a saving only where execution has idle cores the ingest does
not. Not first.

### B. Sharded verification with f+1 coverage

n nodes, f faults tolerated. Each transaction is verified at ingest by a fixed set of f+1 nodes (by hash: node i
verifies shard i, and each shard is owned by f+1 nodes); the others admit it under its claimed sender. A follower
votes for a block only when every transaction in it is covered: verified by itself, or attested by every one of the
f+1 owners of its shard (at least one of which is honest, so a bad signature cannot be attested by all of them).
Attestations are batched: each node periodically signs (BLS, once per batch) a compact set of the hashes it
verified in the last interval -- a bitmap over the interval's frame indices, or a Merkle root the follower can
check against its own copy of the frames -- and gossips it; a follower's vote road checks coverage with a set
lookup per transaction, not a signature. Per-node verification cost falls to (f+1)/n of today's: 1/3 at n=3 (f=0),
1/2 at n=4 (f=1), 3/7 at n=7 (f=2). Safety: with at most f faulty nodes, every attested shard has an honest
verifier; liveness: a slow attestation delays a vote, so the interval must be shorter than the cycle and the
attestation must travel with (or ahead of) the block description -- in practice the proposer can carry the
attestations for its block's transactions in the proposal. This is the form that saves, and it is a protocol
extension: an attestation message, its schedule, the coverage check on the road, and a fault case (a shard
owner that stops attesting must be replaced or the shard re-verified locally).

### C. Trust the generator's claim (a benchmark probe, not a protocol)

The f=0 three-node fleet already assumes no faulty node; under that assumption B collapses to "each node
verifies its own shard, the rest are admitted under the claim" with no attestations. It is unsafe under any f>0
and says nothing about production -- but it measures exactly what B would deliver on this box: the ingest at a
third of its cost, the road with its cores back. It is what to run first, as a number, before building B.

## 3. Expected numbers

At 3 nodes, the ingest's busy time falls from ~10 us to ~3.3 us a transaction; the recovery slots go from 75% to
~25% busy; the road's B (113-134 under a 950k/s ingest) should return toward the ~80 it reads when the ingest is
light (6.13); the cycle then sits at the leader's 136-142 plus the hand-off, ~150-155 ms, which at 163k is
1.05-1.09M/s -- provided the generator's send loop delivers it (9.1: the flood tops at ~950k/s because the
nodes reply slowly; with the ingest three times cheaper the replies should shorten and the flood follow).

## 4. Decision to take

Run C as `N42_INGEST_VERIFY=shard` with `N42_INGEST_SHARD=<i>/<n>` (loop262): if a window passes 1M, the design B
is worth its extension (attestations, coverage, faults) and a safety write-up; if it does not, the ingest was not
the last term and the number says what is.
