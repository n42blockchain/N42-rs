# Deferred execution for the N42 HotStuff-2 chain -- a proposal to the gov5 side

*2026-09-10, from the fleet7 campaign (`docs/FLEET7_PLAN_V3.md` phase D, section 5). A
cross-client rule change: nothing in it is decided by this repository alone. Numbers are the
seven-node bench on one box at the 163,000-transfer / ~147,000-account block shape.*

## 1. Why: the cycle is a sum, and the sum has a floor

Every follower executes a block before it votes on it. So a block's cycle is

    cycle = push (~35 ms) + slowest follower's import (~330-360) + vote/commit (~10)
          + proposal/seal/encode (~20-40) + straggler wait
          = ~540 ms median today (loop125: 56 blocks in 30 s, 296,936 TPS)

and the leader's build of the next block (~460 ms with build-on-seal) is hidden only because
it is shorter than that sum. Two things follow. The fixed part (~100 ms of push, votes, seal,
proposal) is a fifth of the cycle and does not shrink with per-transaction work. And the
follower's import and the leader's build are *serialised by the vote*: the leader cannot
propose N+1 until the followers have executed N, so however fast both sides become, the
cycle is import + fixed, never max(build, import).

At ~300 ms a side (plan v3 phase C) the cycle would be ~400 ms (75 blocks, ~400k); the
target is 1M, a 163 ms cycle at this block shape. No per-pass cut reaches it under the sum.

## 2. What: the header of N commits to the execution of N-1

The same idea as Ethereum's EIP-7862 (delayed execution): a block's header carries the
*post-state of its parent*, not its own.

- `stateRoot`, `receiptsRoot`, `logsBloom`, `gasUsed` (and the QMDB root the chain uses as
  `stateRoot`) in the header of block N are those of block N-1 after execution.
- Block N's own execution result appears in the header of N+1.
- The genesis header carries the genesis state (as now); block 1's header carries the genesis
  state too (nothing was executed before it); block 2's header is the first to carry an
  executed post-state (block 1's).

A follower votes on N once it has checked:

1. the proposal (leader, view, QC, committee evidence, signatures) -- as now;
2. the body is available and well-formed (transaction decode, gas limit, size) -- as now;
3. **the header's execution fields equal the follower's own result for N-1**, which it has:
   it executed N-1 during the previous round, in the time the vote round on N-1 took;
4. the transactions are *includable* without executing them: sender recovered (the Ed25519
   cache, or a batch verification), nonce is the next one for the sender in the post-state
   of N-1 plus this block's earlier transactions from the same sender, balance covers
   `gas_limit * max_fee + value` on the same basis, intrinsic gas fits. This is the check
   that keeps execution from ever failing a block (see 4).

Then it executes N while N+1 is being proposed and voted. The leader builds N+1 on its own
post-state of N the moment it seals N -- exactly what build-on-seal does today.

The cycle becomes

    cycle = max( leader build of N+1, followers' execution of N, network + votes + seal )

with the three overlapped, instead of their sum. At today's sides that is max(460, 360,
~130) = ~460 ms -> 65 blocks -> ~353k at this shape from the protocol alone; with the
phase-C sides at ~300 it is ~300 ms -> 100 blocks -> ~540k; and every further cut on
*either* side pays until the network floor.

## 3. What it changes, by component

| where | today | with deferred execution |
| --- | --- | --- |
| header profile (both clients) | execution fields of N | execution fields of N-1; block 1 repeats genesis |
| gov5 `VerifyHeader` / this node's `HotStuffConsensus` | recompute N, compare | compare against the stored result of N-1; check includability of N's transactions |
| the vote (`h2-consensus`) | "I executed N and it matches" | "N-1 executed as N says, and N is includable" |
| the leader's build | on its own post-state of N (build-on-seal) | unchanged |
| the follower's import | on the critical path before the vote | off it: after the vote, overlapped with the next round |
| finality of a transaction's *effects* | the block's commit | one block later (its post-state is committed by the header of N+1) |
| committee evidence (`parentBeaconRoot` link) | unchanged | unchanged |
| mobile receipts / state proofs (`mobile-verify`) | proof against header N's `stateRoot` for state after N | the proof for state after N is against header N+1's `stateRoot`; the receipt of a transaction in N is under `receiptsRoot` of N+1 |
| RPC `eth_getBlockByNumber` etc. | fields of N | fields describe N-1; the RPC layer can present "execution of N" from N+1 when it exists (EIP-7862 leaves them as the header has them) |
| sync / range import (`bodies_by_range`) | execute and compare per block | execute N, compare with header N+1 (one block of look-ahead; the tip's execution is unverified until the next block, as on Ethereum with 7862) |
| the invalid-block hook, `n42-init-snapshot` header/state pairing | pairs header N with state N | pairs header N with state N-1 (the snapshot tool takes the header of N+1 for state N) |

## 4. The rule that makes it safe: execution cannot fail a block

If a follower votes before executing, a block whose execution would fail must not exist, or
the chain would have committed to a state it cannot produce. EIP-7862's answer, adopted here:

- Inclusion is checked without execution (section 2, item 4): sender, nonce, balance for the
  worst case, intrinsic gas, gas limit sum. A block with a transaction that fails these is
  invalid *structurally* and is not voted for.
- Given those checks, execution of every included transaction succeeds in the sense that
  matters: it may revert, but it can be charged, its nonce advances, and the block's
  post-state is defined. A transaction that reverts is not a failure of the block.
- The block reward and the withdrawals (the flood's funding, the faucet) are applied in
  execution as now; they are part of the post-state the next header commits to.
- Base fee: unchanged, byte for byte. EIP-1559 derives `baseFeePerGas(N)` from the parent
  header's `gasUsed` and `gasLimit` fields *as the parent header carries them*; under the rule
  the parent's `gasUsed` field is the grandparent's executed gas, so the fee responds one block
  later than today and every existing base-fee check stays valid without a fork branch. The
  includability check reads the block's own `baseFeePerGas`, which the header carries as now.

The one thing deferred execution costs is that a transaction's *effects* are final one
block later than its inclusion: a wallet that waits for a commit today waits for the next
commit. At a 0.3-0.5 s cycle that is a small price; it should be stated in the mobile
receipt format (a receipt of N is proven under N+1).

## 5. What it does not change

- The QMDB root, its append semantics, the frozen-leaf commitment, the portable snapshot and
  the cross-client vectors: the root of state S is the same value; only which header carries
  it moves by one.
- The transaction types (0x50 Ed25519 included), the pool, the ingest, the gossip topics.
- The leader rotation, tenure, the straggler grace, the view timeouts.
- The committee, the evidence link, the Decide, the finality rule of HotStuff-2.

## 6. What to measure before deciding

On this bench, without any client change, the gain can be *bounded* by a follower that votes
before importing (`N42_VOTE_BEFORE_IMPORT=1` on the Rust validator: vote on the verified
proposal, import after, the commit's forkchoice deferred until the import lands -- unsafe,
for measurement only; loop128): that reads the cycle the protocol would give at today's
sides, and says whether the ~460 ms leader build then becomes the floor (in which case
phase A3's build cuts pay 1:1 again). If it reads ~65 blocks a window against 56, the
proposal is worth the cross-client work; if the leader's build or the network floor caps it
lower, the number says so before anyone changes a header profile.

**Measured (loop129, 2026-09-11):** with the import off the loop, the followers' votes are
collected in 5-40 ms instead of ~500, the commit follows within ~10 ms, and the leader's next
proposal comes at the bench's pacing: the cycle became the pacing (450 ms, 62-66 blocks a
window against 54-55) -- the coupling is exactly the difference the model predicts. What the
bench could not show is the TPS at that cadence: the box's ingest, sharing its cores with
seven followers now executing off the loop, supplied 130-150k transactions a second and the
blocks emptied (4.4M transactions over 62 blocks). The protocol's gain at full blocks is a
seven-machine measurement, or one with a supply that does not share the fleet's cores.

## 7. Open questions for the gov5 side

1. Header layout: reuse the existing fields with the shifted meaning (EIP-7862 style, no new
   fields, a fork-time switch), or add explicit `parentStateRoot` / `parentReceiptsRoot` and
   keep the old fields empty? The first keeps every tool's field names; the second keeps the
   old semantics readable.
2. The activation: a fork block number in the genesis `config` (`deferredExecutionBlock`),
   after which headers are read the new way; the block *at* the fork carries the state of
   its parent as executed under the old rule.
3. Sync: a range importer verifies N's execution against N+1; the tip's execution stays
   unverified for one block. Acceptable for the mobile verifier? (It already verifies the
   Decide, and a Decide on N+1 certifies the state after N.)
4. Whether gov5's `VerifyHeader` can cheaply produce the includability check (nonce and
   balance from the parent post-state for 163,000 senders) -- this node does it from the
   parallel sender groups it already builds.

## 8. The gov5 side's reading (2026-09-11, via the gov5 session)

Agreed in principle; their answers to section 7, and what they add:

1. **Header layout: reuse the fields, 7862 style, no new fields.** A hashed header field on
   their side lands in three codecs (RLP hash, proto/trailer, the compact storage codec) plus
   the mobile SDK, DATC and the proof tools; reuse has zero wire surface and keeps header
   hashes and every codec byte-compatible across clients. The cost is semantic and local: an
   `executed_root_of(N) = header(N+1).state_root` helper for state-as-of proofs, `eth_getProof`
   and the snapshot tool; the places that assume `header.Root` is the state after N (their
   Finalize root comparison at import, the miner's tree reload check, the QMDB applied marker,
   hotstuff-reset tooling) get the fork check. All fork-gated, all local.
2. **Activation: a timestamp fork, `deferredExecutionTime` in the genesis config** -- every
   gov5 gate is `header.Time` (MobileAnchorTime, PQPrecompilesTime, AIInferenceTime).
   **Fork invariant:** the first deferred header F carries the state after F-1 under the old
   rule, which is exactly `header(F-1).Root`, so `header(F).Root == header(F-1).Root` is the
   assert at the switch.
3. **Sync and the tip: acceptable.** Their range importer's per-block root check becomes
   "`header(N).Root` equals the executed root of N-1 I stored"; the tip's executed root sits
   unverified for one buffered header. The mobile anchor is unaffected (MobileRegistryRoot is a
   separate accumulator). One semantic shift to write down: a state divergence stops being
   "reject block N" and becomes "refuse to vote on N+1" -- N's transactions are committed, and
   the majority's execution result reaches consensus through N+1's QC. Their BAD BLOCK
   watchdog, own-unverified sibling mark and qs-hsreset assume root-at-N and need a pass;
   none is a blocker.
4. **Includability in VerifyHeader: cheap.** Sender recovery already precedes execution
   (pool sender hints + a 16M-slot sender cache: ~100 ms hinted for 163k, ~460 ms cold);
   nonce/balance from the parent post-state through their Block-STM workers' QMDB reads
   (~23k accounts across 16 goroutines in 4 ms; the worst case of 163k distinct senders
   ~30-40 ms). The pass: group by sender, nonces contiguous from the parent's, sum(value +
   gasLimit*feeCap) <= parent balance, intrinsic gas <= gasLimit, block gas sum <= limit --
   one read per sender. **The hard requirement it places on the follower: the parent
   post-state must be its own executed state of N-1, so a follower votes on N only after
   importing N-1 -- pipeline depth 1**, which is what makes the cycle max(build, import)
   rather than a deeper pipeline.

Their own numbers: the chained cycle is 1.5-1.9 s at 163k (follower import 0.8-1.1 s, seal to
QC ~1.4 s, leader build ~0.6 s), so max(build 0.6, import 1.0) instead of the sum would take it
from ~1.75 to ~1.1 s -- worth more than any single lever left on their list. gov5 already has a
chainspec gate `hotstuff.twoPhaseVoteGate` (R1 static vote, R2 commit vote held until import)
whose R1-only behaviour is the equivalent of this bench's `N42_VOTE_BEFORE_IMPORT=1`, so their
cycle floor can be measured before the rule change too. They offered to prototype the gov5 side
behind `deferredExecutionTime` on their worktree after their current round queue.

## 9. Agreed names and the split

- Genesis: `config.deferredExecutionTime` (u64 seconds; absent = never).
- Helper, both clients: `executed_root_of(n)` = the state root after block n = `header(n+1).state_root`
  once `header(n+1).timestamp >= deferredExecutionTime`, else `header(n).state_root`; likewise
  `executed_receipts_root_of`, `executed_logs_bloom_of`, `executed_gas_used_of`.
- The switch: for a header H with `H.timestamp >= deferredExecutionTime`, H's execution fields
  are the parent's executed values; the first such header F asserts `F.state_root ==
  parent.state_root` (the invariant of section 8.2). Headers before the fork are unchanged.
- The vote (both clients): a proposal for H is voted for once the follower has imported the
  parent, H's execution fields equal the follower's own result for the parent, and H's
  transactions pass the includability check against that post-state. Pipeline depth 1.
- Rust side: the chainspec field, `HotStuffConsensus` header validation, the builder's
  header assembly (the block's fields from the parent's `BuiltExecution`), the follower's
  direct import (compare against the stored result of the parent, then execute for the next
  header), the mobile receipt/proof binding (`mobile-verify`: state after N under N+1),
  `n42-init-snapshot` pairing, the RPC presentation. gov5 side: the mirror list of section 8.1,
  behind the same gate.
- A cross-client vector: a short chain across the fork (F-2 .. F+3) with every header's
  fields and roots, checked byte-for-byte by both clients' test suites.

## 10. Rust side, stage 1 (2026-09-11): the header semantics are in

Behind `config.deferredExecutionTime` (`reth_chainspec::qmdb::{deferred_execution_time,
deferred_execution_active_at}`):

- `n42_qmdb_reth::executed_fields`: a registry of what each block's execution produced
  (`ExecutedFields { state_root, receipts_root, logs_bloom, gas_used }` by block hash), fed
  by every path that executes a block -- the builder under the sealed hash, the follower's
  direct import, the engine's QMDB state-root job -- and seeded at startup from the persisted
  head (its header before the fork; the forest's root and the database's receipts after it).
- The builder (`default_n42_payload`): a header at or past the gate takes the parent's fields
  (`parent_executed_fields`: the parent's own header before the fork or for genesis, the
  registry otherwise; an unknown parent is a build error, never a guess) and records its own.
- `HotStuffConsensus::validate_header_against_parent`: at or past the gate the four fields
  must equal the parent's result (`DeferredExecutionError::{ParentUnknown, Mismatch}`);
  `validate_block_post_execution` records the block's receipt side instead of comparing it
  with its own header. The first header past the fork repeats its parent's fields by the same
  rule (section 8.2's invariant), with no special case.
- The follower's direct import and the engine's state-root job file the block's QMDB root and
  record it (`QmdbNodeState::insert_block_operations`); the engine job hands reth the header's
  root as the outcome, since reth compares the outcome with the header.
- Base fee: unchanged (section 4).
- Test: `n42-testing` `test_deferred_execution__headers_carry_the_parents_execution_across_the_fork`
  runs a QMDB dev chain with the fork at genesis: block 1 repeats the genesis fields, block N
  carries block N-1's root and gas, the registry holds each block's own result, and a restart
  restores the head's own root while its header carries its parent's.

- Cross-client vector: `crates/n42/n42-testing/testdata/deferred_execution_vectors.json`,
  written by that test with the fork two blocks in (F = 3, blocks 1..6 = F-2..F+3, transfers
  in blocks 2, 3 and 5): the genesis (header, alloc, hash), and per block its transactions
  (raw 2718), the full header as carried and the `executed` fields its own execution
  produced. Keys and timestamps are fixed, so the document is reproducible; the test
  compares every run with it (`N42_WRITE_VECTORS=1` rewrites it).

## 11. Rust side, stage 2 (2026-09-11): the vote before the import

From the fork on a follower's block goes through *check, vote, import* instead of *import,
vote*, and the next block's check overlaps this block's import:

- **Execution layer** (`bin/n42`, the direct import behind `N42_FOLLOWER_DIRECT_IMPORT=1`):
  a gated block is first checked without its parent -- header rules, body, sender recovery
  (the ingest's caches, the Ed25519 batches) -- then waits for the parent to land (a
  condvar bumped by every landing, polled every 20 ms for blocks the engine's own path
  imports, 10 s at most), checks its header's four fields against the parent's recorded
  result (`validate_header_against_parent` under the gate) and its transactions'
  includability on the parent's post-state (section 8.4's pass: per sender one account
  read on the worker pool, nonces contiguous, balance over value + gas at the fee cap,
  chain id, fee cap over the base fee, priority under the cap, a transfer's gas at least,
  the block's gas limits within the header's), and only then executes. The raw payload
  channel answers the check on a `CHECKED` frame (`raw_engine::reply::CHECKED`, an
  encoded VALID status) before the import's final answer on the same request; a block
  before the fork gets no such frame. Each request holds its own connection, so the next
  block's request goes out while this one executes.
- **Driver** (`n42-h2-execution`): `set_deferred_execution_time` from the genesis; a gated
  block is sent at once on a task, no queue -- the execution layer orders by parent -- and
  the task reports `ImportReport::Checked` when the frame arrives and `ImportReport::Done`
  with the import's verdict. Imports in flight and deferred commits are sets now. The
  execution-layer seam is `ExecutionLayer::new_payload_checked` (a oneshot for the check;
  the default drops it and the vote waits for the import, so an execution layer without
  the frame is safe, just unpipelined).
- **Consensus** (`n42-h2-consensus`): `ConsensusEvent::BlockChecked` releases the pending
  import-gated vote exactly as `BlockImported` does (the parent is remembered for the
  extends rule); the import event still follows and moves the node's head and build-ahead
  parent. `N42_VOTE_BEFORE_IMPORT=1` stays a bench flag for pre-fork chains.
- What a vote now attests: the parent's result as this node computed it, and that the block
  can execute on it. A block whose execution then fails here (an intrinsic-gas or
  state-dependent failure the includability pass does not see, EIP-8037's state gas among
  them) leaves this node without a recorded result for it, so it refuses to vote on the
  child (section 8.3's semantic shift), as an invalid block would be refused today.
- The leader's own block reaches its execution layer as a sealed header whose hash differs
  from the build's (the validator normalises the header): the handoff files the build's
  recorded result under the sealed hash too, as it already did the QMDB tree. Without it the
  leader's followers-to-be waited 10 s for a parent result that was there under the other
  hash (the first smoke run).
- Smoke test (2026-09-11, `scripts/fleet7.sh` on `n42_fleet7.json` with the fork at genesis,
  200 tx/s offered for 90 s, every node its own execution layer): 28 blocks at the 3 s
  interval, all seven at the same height and hash, every block voted for on its check (2-8
  ms after the body), 189 tx/s sealed, no rejection.
- loop132 A1 (the first bench leg with the fork at genesis) stalled at 3-6 blocks a window
  with a 10 s cycle: a follower's vote on N now precedes N's import, so the Decide for N
  arrives while N is still executing, and the validator's service dropped that commit as
  "a block the execution layer has not imported" -- N never got its forkchoice, never became
  canonical, and N+1's check waited the full parent timeout for a header the provider could
  not see. Fixed: a commit for a block whose import is in flight goes to the driver, which
  runs the forkchoice when the import lands. Blocks 1-81 (the base-fee decay, empty or small)
  had passed because their imports finished before the Decide; the smoke run passed for the
  same reason.
- Cycle: the follower's serial chain per block becomes the includability pass plus the
  execution (the stateless half of the check overlaps the previous import), and the leader
  gets the QC while the followers execute; the idle gap between a follower's import and the
  next body is gone. Measured by loop132 (`n42_fleet7_bench_deferred.json` =
  the bench genesis with `deferredExecutionTime: 0`, against the same binary on the
  ungated genesis).

## 12. Measured and adopted (2026-09-11 21:08)

loop132-135 (`NATIVE_FLEET7.md`): four defects of the pipeline, each visible only at the
bench tier -- a commit dropped while its block was importing, the far-ahead hold measuring
against a tip that moved only when an import landed, the leader's own result recorded under the
build's hash rather than the sealed one, and a new leader's build refused while its parent was
still importing -- and then, on the same binary, window 1 299,865 / 302,811 at 56 blocks against
293k ungated, window 2 +3-10%, the best round 22,200,112. The follower's check is ~130 ms, its
import ~400 ms beside the loop, the cycle's median 485 ms; the leader's build chain (~430 ms a
full block) is the cycle now. `n42_fleet7_bench.json` carries `deferredExecutionTime: 0`;
`n42_fleet7.json` and the devnet stay ungated until the gov5 side has the rule (sections 8-9).

## 13. Stage 3 (design, 2026-09-12): the leader seals before it finishes

With the follower off the critical path (section 12) the cycle is the leader's build: on a
full block ~430 ms, of which the parallel execution is ~60 and the rest is serial -- the fold
of the batches' state (~115), the finish (~110: post-execution changes, the bundle merge, the
hashed post-state, and the QMDB root ~57 beside the transactions root ~25), the assembly and
seal (~30). Under deferred execution a header carries the *parent's* execution fields, so
none of that serial work is needed to seal the block: the header needs the transactions root,
the parent's fields, the attributes and the gas limit. The leader can therefore seal right
after the parallel execution and the transactions root (~90 + 25 ms after the pull), publish,
and do the rest behind the seal.

- `default_n42_payload` takes an `early_seal` hook. With it, under the gate, when the parallel
  step filled the block (nothing for the serial loop, no blobs, no Amsterdam access list), the
  builder assembles the header itself -- `prepare` + transactions root + the parent's recorded
  fields (waited for, since the parent's own finish may still be running) + gas limit, base
  fee, withdrawals root, blob fields, `EMPTY_REQUESTS_HASH` -- seals it, files the block as
  *pending* in `built_executions`, hands the payload to the hook, and continues: the fold,
  the executor's finish (the rewards' withdrawals) and the bundle merge, then `state_ready`
  (the next build reads this post-state), then the hashed post-state, the QMDB root and the
  receipts root in parallel, then `complete` (the executed block for the engine's handoff,
  the block's own fields in `executed_fields`, the cached reads).
- `build_on_own` (build-on-seal, every block of a tenure but the first) runs the build on a
  thread and answers the validator with the early payload; the thread finishes behind it.
  The next `build_on_own` waits for the parent's `state_ready` (and its fields before the
  header), the own-block handoff for `complete`; the QMDB root of N+1 waits for N's tree.
- Expected chain per block: N's fold + merge (~150) then N+1's execution and root (~115), the
  parent's fields ready in time: ~280-300 ms a block against 480, i.e. the follower's chain
  (includability + import beside the loop, ~275) becomes the cycle again. On this box the
  supply (each node verifying every transaction at ~25 us) caps what that is worth in
  transactions; on a fleet with cores of its own it is the leader's 1.6x.
- The requests hash: a block of transfers produces no EIP-7685 requests, so the header is
  sealed with the empty hash and the finish asserts it; a chain with system-contract requests
  would defer `requests_hash` too, which section 9's rule does not yet say.
- Knob: `N42_SEAL_FIRST` (on by default since loop140; `0` turns it off; the gate is a
  precondition). Measured on loop137-140 (`NATIVE_FLEET7.md`): the seal path from the
  build's start 472 -> 398 -> 295 ms as the fold's cache inserts, the results' sort and the
  transactions root left it; window 1 306k / 317k against 297-303k, the round +2.7%, no
  failed finish in ~600 early seals; the cycle is the 450 ms pacing now.


## 14. gov5 proposal (2026-09-12): a BLAKE3 binary transactions root, fork-gated

*Left here by the gov5 session because the cross-session message was not
approved before it expired. Not decided by either side alone.*

Both clients spend ~70 ms a block on the transactions root today: the
Ethereum keccak Merkle-Patricia trie (`alloy_consensus::proofs::
calculate_transaction_root` here, `DeriveShaErigon` in gov5 since a73a7258;
NATIVE_FLEET7 notes 72-78 ms of serial keccak, gov5's follower body phase is
~100 ms). The chain's state is a BLAKE3 binary forest; the body root should
follow it.

Definition (gov5 `hash.Blake3BinaryRoot`, tests and vectors in
`common/hash/txroot_blake3_test.go`):

    leaf_i = blake3(0x00 || enc_i)          enc_i = the transaction's consensus encoding (the EIP-2718 bytes the MPT hashed)
    node   = blake3(0x01 || left || right)   pairs in list order, level by level
    an odd node at the end of a level is carried up unchanged (RFC 6962)
    root   = the last node; a one-entry list's root is its leaf
    empty  = blake3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262

Vectors: one entry `[01 02 03]` ->
`f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32`;
three entries `[01]`, `[02]`, `[03]` ->
`d304c27fcf395c7809a2733472060a0d2bc7eb7bf014d2377dc3be20f74fb098` (odd
promotion). O(n) hashes, every level parallel: 163k leaves 70 -> 6 ms.

Activation: chain config `txRootBlake3Time` (timestamp fork, absent = never);
`header.timestamp >= it` -> the binary root, else the MPT. Receipts root
unchanged for now. gov5 runs it behind the gate (`TxRootAt(txs,
header.Time)` on production and validation) with a bench-only env override
on its seven-node fleet until the chainspec carries the field. If the
domain bytes, the odd-promotion rule or the empty root should differ for
the Rust side, say so here; otherwise it goes into the shared chainspec
proposal next to `deferredExecutionTime`.

## 15. gov5 side implemented behind the gate (2026-09-12 04:00 EDT)

gov5 commit 93e31b89 on n42blockchain/N42 main: `config.deferredExecutionTime`
(`IsDeferredExecution`), the stored per-block execution result
(`rawdb.ExecutedResult`: root, receipts root, bloom, gas used, by block hash),
`ExecutedResultOfHeader` (a pre-fork header's own fields, so the fork
invariant needs no special case), the import's pre-execution header check,
the builder stamping the parent's result (own sealed record for chained
builds, stored result, or the parent header before the fork), and the vote:
the sync layer's `CheckDeferredBlock` (header vs the parent's stored result,
parent is the applied head, includability -- per sender nonces contiguous
from the state, sum(value + gas x fee cap) within the balance, intrinsic
gas within the gas limit, block gas within the limit) raises
`EventBlockChecked`; the engine votes when the block is checked AND its
JustifyQC block is imported, in either order, never twice. Not yet: the
RPC/proof presentation of `executed_root_of`, the mobile receipt binding
under N+1. First fleet round (35zzn, gov5-only) queued behind the BLAKE3
tx-root round with a bench-only gate override; the fixture (F-2..F+3) from
your side will go into our header tests as agreed.

## 16. Audit of the session's code (2026-09-12 05:30), what it found and what changed

Two independent reviews of `9ba1470c2..HEAD` (builder/store side, follower/driver side). Fixed:

- **A rejected block kept its vote evidence and lost its commit.** `BlockChecked` put the hash in
  `imported_blocks`; an import that then failed left it there (a re-proposal of the hash would be
  voted for at once, unchecked) and the commit parked for it was never dropped. Now
  `ConsensusEvent::BlockRejected` withdraws the evidence and the driver drops the parked commit
  and the cached payload, loudly.
- **SYNCING under the deferred path was final.** The awaited path retries (`PayloadMissing`); the
  spawned paths turned it into a rejection. `ImportVerdict::NotYet` retries as before.
- **Unbounded pipeline depth.** The in-flight imports counted as the tip and every admitted block
  raised it; a follower that fell behind admitted every body at once (a sender recovery each,
  a payload and a state each). At most two imports are in flight now (one executing, one being
  checked); the rest queue.
- **A spawned import that died left its hash in flight forever** (commits parked, a leader with
  that head deferring every proposal). A guard reports a verdict on drop.
- **`requests_hash` was checked by nobody past the fork.** It is the block's own, not a deferred
  field, and `validate_block_post_execution` now holds it to the EIP under the gate too.
- **The direct import waited 3 s for an unknown parent on ungated chains** (the old path failed at
  once and let the engine answer SYNCING), after a full sender recovery, on the one connection.
  Before the fork the parent is looked up first and an unknown one fails at once, as before.
- **The check did not cover intrinsic gas.** A transaction with calldata and a 21,000 gas limit
  passed the check and would fail execution. The intrinsic gas (kind, calldata, access list,
  authorizations, the fork's floor) is required to fit the gas limit.
- **Seal-first skipped the fold's cache writes without the withdrawals guard.** The executor's
  finish credits the block's rewards through the state's cache; a grafted account (the faucet,
  on a funding block) missing there was loaded from the parent and overwrote the graft. The
  skip needs `withdrawals_clear` as it always did.
- **Under the gate the build store's identity degenerated** to (parent, number): the roots and gas
  it keyed on are the parent's, the same for every sibling. The transactions root is part of the
  identity now wherever the caller has a header.
- **The store re-filed a build that advanced after eviction**, evicting a live one; it keeps three
  builds (the one finishing, the one ready, the one sealed) and drops a late advance. A finish
  that fails behind the seal removes its entry (`fail`) so waiters return at once.
- The engine's state-root job computed the MPT-style change set before the deferred branch that
  never used it (~48 ms on the follower); the key cache is capped at ~50 MB; a batch worker that
  executed a candidate twice is an error, not a silent drop.

Known and left: the check does not see state-dependent gas (EIP-8037 on an Amsterdam chain) or a
recipient spending what it received in the same block (the check refuses; the block takes the
ordinary path); the provisional post-state is a bundle clone per block (~60 MB) until the
finish replaces it.

### 16.1 What the bench found in the audited build (loop143-145)

- A block queued behind the two imports in flight was not "importing": the new leader proposed
  on it and the tenure timed out. `is_importing` covers the queue (`5c38c8798`); the check's
  intrinsic-gas pass runs inside the per-sender parallel loop, and the seal-first fold does not
  re-insert every account into the cache (both were regressions of the audit's own changes).
- The commit for a queued block ran a forkchoice the engine answered SYNCING; the driver took
  that as a rejection, withdrew the block's vote evidence and the node's head stopped (loop144 A1,
  node0 at 173 with consensus at view 327). A queued block's commit now waits for its import like
  an executing one's, and a refused forkchoice is a warning and `Ignored` (`98ceadeb4`).
- Not deferred execution's, but found by these legs: the transaction queue stranded the sender
  whose run a full block cut short (`9465fdb9f`, `NATIVE_FLEET7.md` loop143-145).

### 16.2 The reorg path after a sibling re-proposal (loop147-154), fixed

A leader whose tenure is cut by a TC after it handed a block to its engine re-proposes the
height with a different block. loop147 showed two defects behind that (`NATIVE_FLEET7.md`
loop147), neither reachable while the chain does not fork:

- The header-only own-block `newPayload` (`request::OWN_BLOCK`, an empty transaction list; the
  engine's conversion takes the sealed block from `built_executions::take_sealed`) executed an
  empty body when the sealed block was gone from the store, and `validate_block_post_execution`
  then recorded receipts root empty / gas 0 for the block. The conversion must refuse a payload
  whose body does not hash to the header's transactions root, so the validator falls back to
  the full payload as designed.
- The QMDB forest with the entry file (`N42_QMDB_ENTRY_FILE=1`) could not follow the canonical
  switch to the sibling: `delta expected append cursor 16218563, found 16234384` -- the sibling's
  entries were appended after the branch it replaced had filed its own, and the delta's cursor
  bookkeeping assumes the file's tail is the branch being extended.

Both fixed in `4e55c33ed` (`built_executions::find_sealed` + the header-only guard in
`engine_validator`; `QmdbForest::delta_since` rewinding to the move's low-water mark). loop151-152
then showed two more on the same path:

- The hand-off's executed insert and the header-only `newPayload` of the same sibling raced in the
  tree; the payload's execution was aborted part way and `validate_block_post_execution` recorded
  the partial result (receipts root empty, gas 0). A result whose receipts do not cover the
  block's transactions is not recorded (`27d13a625`).
- reth's tree drops an executed insert whose number is not above its canonical block number
  ("outdated block"), so a sibling at the height of the own block already made canonical was never
  inserted and the payload executed it on the fork path, against the head's QMDB state. The
  hand-off now moves the engine's head to the sibling's parent first (`df0e9f4c2`).

With all four in, loop154 A1 went through a stall and two TCs with no header rejected, and
loop154 A2, loop155 A1 and A2 ran clean (`NATIVE_FLEET7.md` loop154-155).

### 16.3 Found on the way: a follower's commit that runs before the block arrives

A follower can hear the Decide for a block before the body channel delivers it (1-50 ms under
load, sometimes block after block). The commit's forkchoice then names a block the engine does
not have; nothing makes the block canonical after its import lands; the next block's direct
import waits `PARENT_WAIT` (3 s) for a parent the provider cannot see and falls to the ordinary
path; the node falls behind, its queue crosses the ingest gate, and the flood (which waits for
every node) stops. Three forms, three fixes: the engine answers SYNCING (`61af2de22`: the commit
waits for the import); the engine answers as if done and the import lands for the last committed
block (`6f5007b58`); commits run ahead of several imports in a row (`f888c8257`: the driver keeps
the imports that landed and the commits that ran for blocks it had not imported, and repeats each
when its block lands). loop155 A2 still showed one 3 s parent wait late in window 3, on an empty
block (open; `docs/FLEET7_HANDOFF.md`).

### 16.4 Open: the leader's stall

7-10 s before the leader's own-block `newPayload` is answered, about once a leg at a tenure change;
the validator's 8 s HTTP timeout then forms a TC (survivable since 16.2's fixes, but it costs the
seconds). Ruled out: reth's persistence backpressure (`backpressure_stall_duration_count` 0 on
every node), a slow branch of the node launcher's engine service loop (`took_ms=0`), and that loop
going unpolled (its 250 ms tick never came late). Left: the request not reaching the engine's
channel in time, or the tree busy with something unlogged before it. The case to exercise on
purpose is a TC during a leader's tenure with a fresh build in its engine.

## 17. Settlement and backpressure (2026-10-04)

Written after reading Near One's SPICE note (2026-09-30,
https://blog.nearone.org/research/2026/09/30/spice-01-intro.html), which names ordering, data
availability and execution certification as separate steps. Two questions this document did not
answer in one place: what is "settled", and when; and what bounds the execution debt when
execution, import or persistence fall behind ordering. 17.1-17.3 describe the code as of this
branch (`feat/native-fleet7`, read, not run). 17.4-17.5 are **proposals**: nothing in them exists
yet. Numbers carry the section of `docs/BREAKTHROUGH_DESIGN.md` (BD) where they were measured, all
on the three-node fleet at the 163,000-transaction bench block (loop294-loop315).

### 17.1 The states a block passes through today

Block N under deferred execution (sections 2 and 11): its header carries the fields of N-1, its own
fields appear in the header of N+1.

| State | Who knows it | Evidence | Lag behind ordering (BD, ms) |
| --- | --- | --- | --- |
| Ordered | every validator | proposal + QC + committee evidence; a validator's vote on N attests: the body is held and well-formed, the transactions are includable on N-1's post-state (section 11), and the header's four fields for N-1 equal *its own* result for N-1 | the vote needs the parent's fields: `fields_ready` median 89-108 after the road start (BD 10.27, 10.34, 10.61); the leader's seal `sealed_at` median 80-84 (10.60) |
| Committed | every validator | the state machine's Decide, `EngineOutput::BlockCommitted` (`crates/n42/h2-execution/src/driver.rs` table; rule in `crates/n42/h2-consensus/src/protocol/state_machine.rs`, not re-derived here) | about one cycle after ordering; cycle 0.130-0.142 s (10.60) |
| Executed on a node | that node (its engine) | its own result for N: fields recorded (`n42_engine_types::executed_fields`), import line `fields_ready_ms`, `total_ms` | import `total_ms` median 124-155 (10.60, 10.63), tail: p99 446-583, max 1,505 (10.42); inside the node, beside the loop |
| Execution certified | anyone holding N+1's header | N's fields in N+1's header, and a quorum voted on N+1 (each voter checked them against its own result) | one block after ordering of N: the time of N+1's vote, ~one cycle (0.13-0.14 s, 10.60); never earlier |
| Persisted | that node | the persistence batch (`--engine.persistence-threshold 8`, `--engine.memory-block-buffer-target 6`, `scripts/fleet7-env.sh`) that holds N | derived, not measured: with threshold 8 and target 6 a block waits 6-8 blocks, about 0.8-1.1 s at a 137 ms cycle. The `node_state.rs` comment says persistence "runs 17-18 blocks back" (~2.4 s); its source run is not named there |
| Tags for an RPC client | that node's EL | `ExecutionDriver::commit` (`driver.rs`, `commit_forkchoice`; rules in `crates/n42/h2-execution/src/settlement.rs`) | `latest` = the last **committed** block; `safe` = the last **certified** block (the committed block's parent under deferred execution, one block behind); `finalized` = the last certified block at or below this node's **persisted** block. `N42_SETTLEMENT_TAGS=legacy` restores head = safe = finalized = committed |

What a wallet or bridge should wait for: **the state of N certified by a quorum**, i.e. the header of
N+1 carrying N's fields, with N+1 voted. Under deferred execution that is one block after ordering
(~0.14 s on the fleet, BD 10.60), and it is the first point at which a quorum has *attested the
result*, not just the order. Since 2026-10-04 the RPC tags say exactly this: `safe` is that block, and
`finalized` is the newest such block this node has also persisted, so a client reading `finalized`
the Ethereum way settles on a certified, durable state. (Before, `safe` and `finalized` both named
the last committed block, whose own state root no quorum had vouched for yet; 17.7 has the switch
back.)

Data availability is not a separate layer. A validator votes only after it holds the body (the body
gossip of `crates/n42/h2-net`, `bin/n42/src/payload_serve.rs` for fetch-on-miss), so "ordered" already
implies "every voter holds the body"; there is no separate availability certificate or store.

### 17.2 The debts that can accumulate, the counter that reads each, and what bounds it

| Debt | Counter today | Bound today |
| --- | --- | --- |
| Transaction queue depth | `queued`, `gate_us_per_frame` on the ingest line (`crates/n42/tx-ingest/src/lib.rs`, `gate_view`; depth is `TxQueue::gate_len`, `crates/n42/tx-queue/src/lib.rs`) | Soft: the gate holds frames at `N42_TX_INGEST_HIGH_WATER` (90,000) + up to 4 blocks of allowance. It lets a frame through after `N42_TX_INGEST_GATE_MAX_WAIT_MS` (15 s) anyway, so it is backpressure and not a rule; one stuck node is a trickle of ~32,000 transactions per 15 s (comment at `gate_max_wait`) |
| Leader builds ahead of proposals | chain slot log lines in `crates/n42/h2-el-rpc/src/engine.rs` | Hard: one chained build, "one ahead, never two" (`ChainState.slot`; a start while the slot is full is refused or, with `N42_BUILD_AHEAD_AT_SEAL=1`, deferred) |
| Follower's execution behind ordering | `parent_fields_wait_ms`, `fields_ready_ms`, `total_ms` on the direct-import line (`bin/n42/src/follower_import.rs`); imports over 600 ms; refusals | Hard but binary: a follower does not vote on N+1 without N's result; the wait for it is `PARENT_WAIT` = 3 s (`follower_import.rs`; section 11 still says 10 s, the code says 3 s), then the block is refused and the node withholds its vote. No bound on how far the *chain* may run ahead of a slow follower other than that the quorum can proceed without it |
| Unpersisted blocks in memory | no per-node counter in the runner lines; the engine's own persistence metrics | Soft: threshold 8 / target 6, but `--engine.persistence-backpressure-threshold` is raised to 1024 (`fleet7-env.sh`, because the default 16 stalled the engine 8-10 s, loop146-147), which makes reth's own bound effectively **no bound** at this block size |
| QMDB read view lag, journals held | `reader_lag`, `reader_lag_max`, WARN "the QMDB read view is falling behind the chain" at 1/2 and 3/4 of the cap (`crates/n42/qmdb-reth/src/node_state.rs`, `note_reader_lag`) | Hard cap, with a cliff: `N42_QMDB_READER_KEEP_CAP`, 64 default with the hashed tables on, 1024 with them off; at the cap the records are pruned and the view is invalidated for good, which with the tables off refuses blocks (loop183 V2a: a 33 s persistence stall, 29 refused blocks, per the comment). Journals needed by a batch's readers are held until it commits (BD 10.17, dee53c148) |
| Memory | `el_max_peak_g`, `min_avail_g`, `MEMORY FLOOR` line (`scripts/fleet7-runs/run-loop315.sh` and later runners; the line prints under 10 G free) | None in the node. The runner only reports; it does not stop anything. Peak 31.5-33.2 G on the baseline (BD 10.60, 10.61) |
| Persistence wall time against the cycle | not logged per batch in the runner lines | None. The comment at `fleet7-env.sh` gives ~365 ms a batch at threshold 2 (earlier code); a figure of ~97 ms a block at threshold 8 was supplied with the task and I did not locate it in BD |

### 17.3 What happens when each falls behind today

- **Stalls safely (votes withheld, then a timeout).** A follower whose execution is late: N+1's vote
  waits for N's fields; 10.42 shows one second-long root (1,034 ms) making the next block wait 917 ms
  and its vote 935 ms late. Past `PARENT_WAIT` the block is refused, the follower does not vote, and if
  a quorum cannot form a TC follows. The handover stall (BD 10.15-10.17, loops 278-280) and the
  leader's 7-10 s own-block wait (section 16.4, open) end the same way: an 8 s HTTP timeout, a TC.
  Stalls recover; they cost seconds, not state.
- **Degrades.** Window 2-3 decay: occupancy halves (BD 10.60 AHEAD 53%; 10.63 D30 windows 364k and
  170k at 0.45 and 0.36 s cycles) when memory is tight or imports slow. The transaction gate then
  backs the generator off; empty blocks prune nothing, so a gate that never reopens is a closed loop
  (loop190Y1a), broken only by the 15 s release.
- **Could exhaust memory.** Nothing in the node bounds it. 10.63's 30 s decay reached 51.0 G el peak
  and 2.1 G available on one leg (D30), and 9.0 G on D30NB, with 49 imports over 600 ms. A persistence
  stall holds executed blocks in memory with reth's backpressure at 1024: at ~30 MB of QMDB record a
  block (`node_state.rs` comment) the keep alone is ~2 GB at 64 blocks and ~30 GB at 1024.
  Not established: what an engine does at the OOM boundary; no leg went there.

### 17.4 Proposed thresholds (proposals; none implemented)

Each reads a counter that exists or is named as one to add. Starting values come from the measured
numbers above; the last column says what must be measured to set them.

| Proposal | Counter | Action | Starting value | To measure |
| --- | --- | --- | --- | --- |
| P1 unpersisted-block bound | unpersisted blocks (canonical head minus last persisted; add it to the runner line) | the leader stops building ahead (`N42_BUILD_AHEAD_AT_SEAL` off, slot refused), then slows proposals | K = 24 (3x the threshold of 8; the 17-18 seen in a healthy run is under it); hard stop at 48 | the distribution on a healthy leg, and the depth at which memory crosses the floor on a persistence-delayed leg (17.5 B) |
| P2 memory | `min_avail_g` as a node-side reading of `/proc/meminfo` | under M = 16 G available: P1's action; under 8 G: stop admitting at the gate | M = 16 G (D10 held 22 G, D30NB hit 9.0 G, D30 2.1 G; BD 10.63) | available memory against unpersisted depth, to tell a leak from a long decay |
| P3 follower's lag | `fields_ready_ms` and the count of blocks ordered but not executed | past L blocks behind, the follower says so by withholding its vote (it already does) and fetches by range instead of importing each | L = 4 blocks (a 600 ms import is ~4 cycles; 6-15 per leg, BD 10.43) | whether a node over L recovers by itself or must catch up |
| P4 ingest gate tied to persistence | `gate_view` plus the unpersisted count | high-water shrinks by the share of K used, so the generator slows before memory does | linear from 90,000 at 0 to 0 at K | the gate's effect on window-2 occupancy |
| P5 persistence wall | batch wall time (add) against the cycle | WARN when a batch exceeds the 8-block budget (8 x cycle) | 8 x 137 ms = ~1.1 s | the batch wall on a healthy leg; the supplied ~97 ms a block (~0.8 s a batch) leaves ~30% room |

Setting P1's K needs the unpersisted-block distribution, which no recorded run has; the 24 and 48 are
a ratio, not a measurement.

### 17.5 Fault-injection plan (not run)

Both on the three-node fleet (`scripts/fleet7.sh`, one flood leg), one follower faulted, records every
5 s from the fault's start to 60 s after it is lifted.

- **A. Slow execution on one follower.** An artificial delay in the import, 300 ms then 800 ms a
  block, for 60 s.
- **B. Slow persistence.** A delay in the save path (the persistence batch) of 1 s then 5 s per
  batch, for 60 s, on one node (the leader in a second leg, since the leader's own-block path is the
  one section 16.4 left open).

Record: execution lag in blocks (head ordered minus head executed) on each node; unpersisted blocks;
`el_max` and `min_avail`; `reader_lag_max`; `parent_fields_wait_ms` and imports over 600 ms; time from
ordering of N to N's certified state (N+1's header voted) on the healthy nodes and on the faulted one;
TC count; transactions sent against transactions in canonical blocks.

Pass: (1) the debt plateaus (execution lag and unpersisted blocks stay under the proposed L and K, or
under a fixed number named before the run if the proposals are not in); (2) it returns to the
baseline within 60 s of lifting the fault; (3) every accepted transaction is in a block or
refused, none lost; (4) time to certified state on the healthy nodes stays at one block while a quorum
(two of three) is healthy; (5) available memory stays above 10 G.

Hooks needed (none exist; none implemented here): an import delay (env, e.g. `N42_FAULT_IMPORT_DELAY_MS`,
in `bin/n42/src/follower_import.rs`); a persistence delay in the save path (e.g.
`N42_FAULT_PERSIST_DELAY_MS`, in the provider's save call); an unpersisted-block gauge; a per-batch
wall-time log line. Existing flags to reuse: `F7_PERSIST_THRESHOLD`, `F7_BLOCK_BUFFER_TARGET`,
`F7_PERSIST_BACKPRESSURE` (set 16 to see reth's own bound act, which is the control), and
`N42_QMDB_READER_KEEP_CAP`. With three nodes a faulted follower leaves two, which is exactly the
quorum; fault the leader only in leg B.

### 17.6 Relation to SPICE

The same: ordering is separate from execution, and execution is certified one block later by the vote
that carries the next header (sections 2 and 11). Different: N42 has no data layer apart from the
validators (every voter holds the body), validators execute and hold state rather than being
stateless, and the certificate is the header-field check plus the quorum on the next block, a rule of
the consensus, not a replaceable component. Nor does N42 have SPICE's explicit debt accounting; 17.2
shows the debts are bounded mostly by timeouts and by one hard cap (the chain slot), not by a stated
budget. This comparison rests on the SPICE note's summary only; I did not study its protocol in depth.

### 17.7 Settlement tags (implemented, 2026-10-04)

The driver sends every forkchoice with three distinct hashes (`N42_SETTLEMENT_TAGS=split`, the
default; `legacy` sends head = safe = finalized = the committed block, byte for byte as before):

- **latest** (head): the committed block, as before.
- **safe**: the newest certified block. A commit of N+1 under deferred execution certifies N (N+1's
  header carries N's fields and its quorum checked them, 17.1); before the fork a commit certifies
  its own block, since every vote was import-gated. A commit whose block the driver has never seen
  (no payload, body or pulled block for it) moves nothing.
- **finalized**: the newest certified block at or below this node's last persisted block, read by the
  validator's existing 50 ms persistence poller (`n42Engine_inMemoryBlocks` and, on the same tick,
  the new `n42Engine_persistedBlock`, `bin/n42/src/engine_ext.rs`). An unknown reading holds it; an
  execution layer without the method makes it follow `safe`, with one warning.

Both only move forward. A tag that is not provably an ancestor of the forkchoice's head (from the
number/parent links the driver keeps for the blocks it has seen) goes as the zero hash, which the
engine reads as "unchanged"; so a build or a pulled block below the tags, or a replayed commit of an
ancestor, never sends a tag above its head (which reth refuses, -38002). A fresh chain floors both
tags at genesis; a restarted node sends zero tags until its first commit, so the tags reth restored
from disk are never moved back. `payload_serve`'s head move for a re-proposed sibling sends zero tags
too. Range sync (`import_pulled`) moves neither tag.

What the lag does in reth v2.7.0 (read, `engine/tree/src/tree/mod.rs`): the in-memory trim
(`remove_until`) clamps finalized to the persisted block anyway, so with finalized ~= persisted
nothing is held longer; the changeset cache evicts below min(finalized, persisted - 64), unchanged
while finalized is within 64 of persisted; a forkchoice to a canonical ancestor above finalized is a
no-op rather than "too deep reorg"; backfill targets the finalized hash, which is now always a block
the node holds, so a far-behind node is caught up by the validator's range sync instead of starting a
devp2p backfill; the finalized and safe numbers saved to disk are what a restart restores. The QMDB
hooks (`on_canonical`, `on_persisted`) and the APoS path do not read either tag. Nothing validators
exchange changes.

Tests: `crates/n42/h2-execution/tests/settlement_tags.rs` (monotonicity, safe one behind the tip,
finalized capped by persisted and safe, restart, a dropped uncommitted block, async path, pulled
blocks, legacy forkchoices exactly as before) and the unit tests in `settlement.rs`.
