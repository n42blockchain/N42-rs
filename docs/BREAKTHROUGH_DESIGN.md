# Past the plateau: a layer-by-layer redesign against the measured ceilings (2026-09-26)

Every number here is measured on the three-node fleet of `FLEET7_PLAN_V4.md` sections 6-9 (163k-transfer blocks,
pacing 125, the node built for its CPU): **977,627 on a window, 950-976k on every control, a 153-170 ms cycle,
every block full**, and no configuration left that moves it. This note takes each layer from the generator to the
state store, names the term that binds it, and proposes a design that removes the term rather than trims it. Each
proposal ends with what would falsify it. They are ordered by leverage per line of code.

## 0. The shape of the plateau

| layer | what binds today | measured |
| --- | --- | --- |
| supply | the generator is closed-loop on the ingest's replies; every node verifies every signature (10 us) or holds frames at a gate or lets the queue deepen, and each of the three costs the road | 950k/s delivered; shard probe: 1/3 the CPU, no more throughput (9.3-9.6) |
| follower road (B) | assembling 163k transactions from the queue by hash, the transactions root, the copy: 65-77 ms, plus the validator's part; grows with the queue's depth | B 70-125 (6.13, 9.5) |
| leader period | hand-off 5 + pull 22 + prep 12 + partition 3 + wait for the parent's state 20-29 + execution 52-69 + commit 9 + seal 7 | seal at 135-142 (7.13) |
| execution | account reads at ~2.3 us each under sixteen threads (0.7 alone): 87% of the pool time | 52-69 leader, 95-122 follower (6.6) |
| state commit | the graft: 147k accounts inserted into one map, 40 ms of cache misses on one thread; the parallel form is slower | state_wait 20-29 (6.19) |
| follower import | execution + QMDB root 45-51 + engine insert 17-25 = 165-190, over the cycle | backlog at handovers (7.13) |
| block / cycle | 163k a block at ~160 ms = 1.02-1.06M/s of capacity; fixed costs per block on both sides ~100 ms | 200k a block not better (6.21) |
| state growth | ~147k account touches a block: windows 2-3 decay every leg | 770-870k on window 2 (7.15) |
| hardware | 128 physical cores shared by three nodes and the generator on one box; the state on the heap under THP | 6.11, 6.12 |

## 1. Frames as the unit of the whole pipeline (supply, road, block)

Today a frame of 500 transactions is the ingest's unit and nothing else's: the pool holds transactions, the
block names transactions by hash, the follower looks each of 163k hashes up in its queue, copies them, and
recomputes a 163k-leaf transactions root (24 ms). **Make the frame the unit end to end.** Every node receives the
same frames (the generator, or gossip, delivers whole frames); at ingest each node verifies the frame's signatures
in one batch (as now) and computes the frame's Merkle root once. The block's description becomes an ordered list
of frame ids (326 for a full block) with the leader's chosen prefix length for the last frame; the block's
transactions root is the Merkle root over frame roots (a 326-leaf tree, ~0.1 ms). A follower assembles the block by
reference (326 lookups, no copy: the body is the frames it already holds), checks the root in ~0.1 ms, and executes
frame by frame. The road falls from 65-77 to ~5 ms; B from 70-125 to the validator's own ~20-30. The queue's depth
stops mattering to the road (326 lookups whatever the depth), which removes 9.5's coupling and lets a shallow gate
throttle without cost.
- Constraints: the leader must include whole frames (a frame with a gapped sender's transaction is skipped whole;
  the ingest already orders a sender's transactions contiguously within a frame); the wire and the header keep
  their formats (the root is still a root over transactions -- the frame tree is just how it is computed, so it is
  a *consensus rule* that a block's transactions are frame-aligned, which gov5 would have to share).
- Expected: cycle 155 -> ~110 (B 75 -> 30, the copy gone); 163k / 0.11 s = 1.48M/s of capacity.
- Falsified if the leader cannot fill blocks from whole frames at the flood's shape (skipped frames), or if B does
  not fall below 40 with the road at 5.

## 2. Attested frames: verification paid once, at the edge (supply)

The shard probe (9.3-9.6) showed that saving verification CPU on every node does not raise throughput here,
because the closed loop throttles anyway. With frames as the unit (section 1) the loop changes: a frame's cost at a
node is one batch verification and one root. Then make the verification a property of the frame, not of the node:
the ingress that assembles a frame (the generator today; a gateway/sequencer tier in production, run by the
validators) verifies the 500 signatures once and signs the frame (BLS, one signature per frame). A node accepts a
frame carrying f+1 gateway signatures without verifying its transactions; a block may only reference attested
frames; an unattested frame is verified locally as today. Per-node ingest cost: one BLS check per 500
transactions (~1 us a transaction) instead of 10 us; the gate never closes because admission is cheaper than the
flood can send.
- Safety: with at most f faulty gateways, f+1 signatures include an honest verifier's; the same bound the
  consensus already assumes. Liveness: a frame with fewer signatures is verified locally (slow path), never dropped.
- Falsified if, with attested frames, the ingest admits under 1.2M/s a node, or if the road/B do not stay flat as
  the offer rises to 1.2M (which would say a fourth coupling exists).

## 3. Address-range output shards: no graft, no state wait (state commit)

The leader's batches execute by sender group and write into per-batch maps that the graft merges into one map
(40 ms, one thread, memory latency) so the next block reads one map; the chained build waits 20-29 ms for it.
**Partition the block's output by address range, not by batch**: 16 (or 64) shard maps keyed by the address's
top bits; a batch writes each touched account into the shard that owns it (a short lock per shard, or a
lock-free insert, since a sender group's accounts mostly spread evenly); at the end there is nothing to merge --
the block's state *is* the shard set, and a reader (the next block's overlay, the root job, the follower's
import) probes exactly one shard by prefix. The parallel state commit already builds QMDB leaves per shard.
- Expected: graft 40 -> ~0 (contention on shard inserts ~5-10 ms inside the execution), state_wait 20-29 -> ~5,
  the leader's period 135 -> ~100; the follower's merge 18 -> ~0.
- Falsified if shard-insert contention costs the execution more than the graft saved (watch `par_exec_ms`), or
  if the overlay's per-read probe into a shard set is slower than the one-map probe.

## 4. The reads: 2.3 us under sixteen threads against 0.7 alone (execution)

The largest single per-transaction cost is the account read inside execution -- 87% of the pool time on both
sides, three times slower under contention than alone, and no lock or overlay change moved it (K, L, 6.5).
That ratio is a shared structure, not DRAM (326k misses a block at 100 ns is 33 ms of pool time, not 379).
Two designs, one measurement first:
- **Measure**: a CPU profile of the execution's threads (`kernel.perf_event_paranoid` must be lowered to 1 for
  `scripts/fleet7-profile.sh`; it has been 4 all campaign) -- the only instrument that names a contended line.
- **Design A -- a per-block read set built once**: the block's touched accounts are known before execution (the
  senders from the description, the recipients from the decoded calldata-free transfers); read them in one parallel
  pass into a flat vector sorted by address (one probe each, the twig/SBMT lookup done once), and let the batches
  execute against that vector by binary search or a perfect hash (no shared mutable structure, no lock, cache-
  friendly). 150k reads at 0.7 us on 16 threads is ~7 ms; execution then is arithmetic.
- **Design B -- dense account ids**: the state store keeps accounts in a flat table by a dense id assigned at
  creation, with the address -> id map as the only hashed structure; the per-block read set (A) then resolves ids
  once and every later access is an array index. This is the LayerZero-style locality the QMDB evaluation noted.
- Expected: execution 52-69 -> 20-25 on the leader, 95-122 -> 40-50 on the follower.
- Falsified if the profile shows the 2.3 us in the view's lookup itself (then B, the store) rather than a shared
  structure (then A suffices), or if A's read pass costs more than it saves.

## 5. The follower's import off the vote's chain entirely (consensus)

With deferred execution the follower must execute n before voting on n+1 (the header carries n's fields). The
import (165-190) is therefore under the cycle only because the road is long; with sections 1 and 4 the road is
short and the execution is what the cycle waits for. **Two changes**: (a) the follower executes n *as the frames
arrive* -- frame-granular execution (section 1) lets execution start on frame 1 while frames 2..326 are still on
their way, so by the time the block is complete most of it is executed (pipelining the road and the execution
inside one block); (b) the QMDB root and the engine insert stay beside the next execution (as now) but on a pool
that does not share the execution's cores (the 37 physical cores a node has room for both once the ingest is
cheap). Expected: the follower's chain per block ~60 (execution of the last frames + root of the block) instead of
165-190.
- Falsified if frame-granular execution loses the sender-group parallelism (a frame's transactions are from many
  senders; groups form across frames) -- then execute per sender group as now but start groups whose frames are
  complete.

## 6. The block and the cycle (protocol parameters)

With sections 1, 3 and 4 the fixed costs a block (hand-off, seal, roots, insert, prune ~100 ms on each side)
dominate a 160 ms cycle. Two options: shorter cycles at the same block (pacing follows the leader's period, which
becomes ~60-80 ms) or bigger blocks at the same cycle (326k at 160 ms = 2M/s of capacity, the road O(frames) so it
costs nothing). The right point is where the follower's per-block fixed costs (root, insert, prune) are ~30% of the
cycle; that is ~250-300k transactions a block at ~150 ms, i.e. **1.7-2M/s of chain capacity** -- if the supply
exists.

## 7. State growth and the decaying windows (state store)

Every leg's window 2 is 10-20% under window 1 and window 3 lower still, with no TC; the state touched grows and so
do the QMDB log, the checkpoints and the heaps. Before designing: measure which term grows (the root? the reads?
the heap's page faults? the checkpoint's compaction?) over a 190 s leg -- the per-window medians of `root_ms`,
`par_exec_ms`, `graft_insert_ms` and `Cached`/`AnonHugePages` are already in the logs. The likely design is the
LayerZero evaluation's: the twig store bounded by a compaction that runs off the critical path, and the heap
pre-sized so THP never collapses mid-leg.

## 8. Hardware and topology

The generator shares the box with the nodes (17-26 physical cores, one memory system, loopback TCP). A second
box for the generator makes the supply open-loop in practice (the network is the buffer) and gives each node
42 physical cores; NUMA-local memory for each node's state (the 9B45 has 12 CCDs; a node's heap should live on
its own CCDs' L3). Expected: the followers' road and import each ~10% faster; the offer no longer coupled to the
ingest's replies. Falsified if the same closed-loop shape reappears over a real NIC.

## 9. Order and expected ceiling

| step | design | lines | window expected | falsification leg |
| --- | --- | --- | --- | --- |
| 1 | frames as the unit: frame-id description, frame Merkle roots, reference assembly | consensus rule + road + builder | 1.05-1.15M (B 75 -> 30) | B under 40, blocks full |
| 2 | attested frames (verification once at the edge) | ingest + generator | supply to 1.2M+, gate never closes | ingest > 1.2M/s a node, B flat |
| 3 | address-range output shards | builder + overlay | cycle -40 ms | par_exec not up, state_wait ~5 |
| 4 | the read path (profile, then A / B) | execution + store | execution -30 to -50% | perf profile first |
| 5 | frame-granular execution on the follower | follower import | import under 80 | follower chain < cycle at pacing 80 |
| 6 | bigger blocks once the road is O(frames) | parameters | 1.7-2M/s of capacity | occupancy 100% at 300k |

Steps 1 and 2 are the breakthrough: they remove the two loops the campaign hit (the road's per-transaction cost
and the closed-loop supply) instead of shaving them, and each is a week of work with a leg that says yes or no.
Steps 3-5 are the second half of the cycle. Together they put the chain's capacity at 1.5-2M/s of transfers on
this box; whether the window shows it depends on step 2's supply.

## 10. Execution order (agreed 2026-09-26): 1 -> 2 -> 3 -> 4/5 -> 6

Step 1 is built in two phases: **A** -- frames first-class in the ingest and the queue (frame id = a binary Merkle
root over the frame's transaction hashes, computed once at admission; a frame index in the queue with whole-usable
tracking; the genesis flag `frameBlocks` and the root rule: the frame-tree root for a frame-aligned body, the MPT
root otherwise) -- and **B** -- the builder pulls whole frames in arrival order, the description names frame ids
and the last frame's prefix length, the road assembles by reference and checks the frame-tree root. The first leg
(loop266) reads B and the road's `assemble_ms` / `root_ms` against loop265's control.

### 10.1 First leg of step 1 (loop266): no block -- alignment must be per block

With `N42_FRAME_BLOCKS=1` on every node no block was committed: the chain's first blocks (the funding
transactions arrive by RPC and belong to no frame) are not frame-aligned, the builder described them by hashes,
and the followers under the flag refused every hash description as "not frame-aligned" -- 3,438 refusals, the
view timing out from view 1. The control leg ran normally (950,299; the ingest indexed 278,879 frames, 0
unaligned). The rule was written as a chain property; it has to be a block property: an aligned body carries the
frame-tree root and a version-2 description, any other body the MPT root and a version-1 description, both
acceptable under the flag, and a follower with a whole body verifies a version-2 layout from the transactions'
hashes without its own index. Being fixed (`step1/aligned-per-block`); loop267 repeats the legs.

### 10.2 Second leg of step 1 (loop267): frame blocks work end to end, and rehash what the index already holds

| leg | flag | win1 | win2 | occupancy | frames / block | missing | cycle | B | E | sealed_at | road total | frame_root_ms | import |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FRa | on | 754,422 | 706,288 | 100% | 326 | 0 | 212 | 138 | 56 | 224 | 139 | **96** | 127 |
| C950 | off | **965,582** | 728,462 | 98.5% | -- | -- | 162 | 115.5 | 9 | 140 | 74 | (MPT 25) | 178 |
| FRb | on | 749,752 | 711,744 | 99.9% | 326 | 0 | 218 | 137 | 59 | 224 | 138 | 96 | 126 |
| FR1000 | on | 749,764 | 728,041 | 100% | 326 | 0 | 215 | 143 | 57 | 230 | 140 | 96 | 124 |

The mechanism holds: every block is 326 whole frames, nothing missing, the pull is 1 ms (`par_pull` 25 -> 1), the
follower's import is 124-127 against 178 (a frame-ordered body executes with better locality). And the fleet is
22% slower, for one reason on each side: the road recomputes every frame's root from the transactions (96 ms,
serially) where the design has it read the id the ingest already computed (a 326-leaf tree, microseconds), and
the leader's seal does the same on its way to the root (+85 ms between the execution and the seal). Both are the
index-lookup the design describes, being fixed (`step1/frame-roots-indexed`). What the leg promises once they
are: the road at ~45 (assemble 20 + copy 5 + check + transport), B toward ~60, the leader's seal back at ~140 with
the pull gone, and the follower's import already 50 ms shorter.

### 10.3 Third leg of step 1 (loop268): B 115 -> 42, the road 74 -> 55, 981,318 on a window, and the blocks are short

| leg | flag | offer | win1 | win2 | occupancy | txs p10 | cycle | B | D | E | sealed_at | road | frame roots (indexed / hashed) | flood win1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FRa | on | 950k | 976,916 | 672,415 | 88.0% | 130,000 | 151 | **42.5** | 80.5 | 13 | 133 | 61 | 326 / 0 | 950k |
| C950 | off | 950k | 959,438 | 749,293 | 99.2% | 163,000 | 171 | 119 | 12.8 | 9 | 139 | 79 | -- | 911k |
| FRb | on | 950k | **981,318** | 703,927 | 87.3% | 128,500 | 151 | 43.5 | 80.7 | 13.5 | 128 | 55 | 326 / 0 | 950k |
| FR1000 | on | 1.0M | 969,058 | 758,828 | 88.1% | 131,500 | 153.5 | 42 | 75.6 | 15 | 126 | 56 | 326 / 0 | 949k |

With the roots read from the index (`frame_root_ms` 0, 326 of 326 indexed, the seal's layout and root 0 ms), the
design's number appeared: **the followers' road B is 42-44 ms against 115-119** (the road 55-61 against 74-79,
the leader's seal 126-133 with the pull at 1 ms), the cycle 145-151 -- and D, the leader waiting on the 125 ms
pacing, is now 75-81 of it. The window is **981,318**, 1.9% under 1M, and it is supply-bound: the blocks are 87-88%
full (p10 128-131k) because the flood delivers ~950k/s and the chain would take 1.1M/s at this cycle (163k every
145 ms); the 1.0M offer delivered 949k like the rest (9.1: the generator's loop). Two levers are now open that
were closed before: pacing under 125 (the leader is waiting), and more requests in flight from the flood -- 6.17 and
9.5's coupling came from the road's per-transaction and per-depth costs, both gone. loop269 runs them.
