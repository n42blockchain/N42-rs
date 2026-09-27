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

### 10.4 The reopened levers (loop269): the supply is pinned at ~950k/s by the ingest, whatever the flood does

| leg | conc | pacing | offer | win1 | win2 | occupancy | cycle | B | D | E | flood win1 | reply ms | ingest rate / node | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FC96 | 96 | 125 | 1.1M | 975,214 | **900,520** | 89.5% | 154 | 53 | 61.5 | 13 | 956k | 257-286 | 915k | 7 |
| FC128 | 128 | 125 | 1.1M | 971,765 | 707,708 | 89.9% | 151 | 49.5 | 70.7 | 11.5 | 945k | 384-396 | 752k | 1 |
| FP100 | 64 | 100 | 950k | 974,022 | 624,395 | 83.1% | 163 | 45 | 51.6 | 47 | 950k | 169 | 683k | 1 |
| FR950 | 64 | 125 | 950k | 974,302 | 652,308 | 88.6% | 154.5 | 49 | 74.4 | 13 | 950k | 169 | 795k | 2 |

B stays at 45-53 with 96 or 128 requests in flight -- the old coupling is gone, as step 1 predicted -- and the
window does not move: 972-975k in every leg, the flood delivering 945-956k/s whatever is asked, its replies
stretching from 169 to 257-396 ms as more is in flight. Pacing 100 only empties the blocks further (83%). So
the supply is pinned by the nodes' ingest: at 950k/s the twelve recovery slots are ~75% busy, and above it the
frames queue at the slots and the replies lengthen instead of the rate rising. **That is step 2's term exactly**:
verification paid once, at the edge, so a frame costs a node one signature check instead of five hundred.
Step 1 is adopted (`N42_FRAME_BLOCKS=1`, conc 64, pacing 125); the window stands at 981,318.

### 10.5 Step 2 on the fleet (loop270): 1,063,999 on a window

| leg | frames | attested | offer | win1 | win2 | occupancy | txs p10 | cycle | B | D | busy us/tx | slots busy | reply us/frame | flood win1 | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AT950 | on | yes | 950k | 979,039 | 677,874 | 86.2% | 112,000 | 150 | 38.5 | 81.8 | **1** | 9% | 3,174 | 950k | 138 |
| FR950 | on | no | 950k | 962,089 | 650,686 | 85.5% | 127,000 | 153 | 41 | 82.2 | 11 | 54% | 35,978 | 939k | 145 |
| AT1100 | on | yes | 1.1M | **1,063,999** | 727,130 | **99.8%** | 163,000 | 153 | 63 | 54.2 | 1 | 10% | 26,429 | **996k** | 133 |
| AT1200 | on | yes | 1.2M | 1,048,588 | 754,679 | 99.8% | 163,000 | 155 | 83 | 36.4 | 1 | 12% | 26,165 | 1,015k | 129 |

With the flood attesting its frames (one gateway, the bench's seed key) the nodes' ingest costs **1 us a
transaction against 11** (the recovery slots 9-12% busy against 54-75%), a frame's reply falls from 36 to 3 ms at
950k/s, and the generator's loop finally delivers past 950k: 996k/s at a 1.1M offer, 1.015M at 1.2M. **The
window is 1,063,999 at a 153 ms cycle with every block full** -- the first measurement past 1,000,000 -- and
1,048,588 at 1.2M. The road's B rises with the offer (38 -> 63 -> 83: the followers' ingest admitting 1M/s still
shares the node), the leader seals at 129-138 and waits 36-54 ms on the 125 ms pacing. Window 2 is 727-755k as
before (the state's growth, section 7). Tagged `fleet3-1M-window-20260926`.

What this measures and what it does not: the three-node fleet, on this box, with a frame-aligned block and a
supply attested at the edge by one gateway the nodes trust (design section 2's f+1 rule with f=0, the same fault
assumption the 3-of-3 quorum already makes); the transactions are 0x50 transfers of the flood's shape. The
protocol changes are two consensus rules (frame-aligned bodies with a frame-tree transactions root; attested
frames admitted on the gateways' word) that gov5 would have to share to interoperate.

### 10.6 The 1M window repeated (loop271): four legs at 1.037-1.059M, and the gate line is the next wall

| leg | offer | pacing | win1 | win2 | occupancy | cycle | B | D | queue (median) | gate us/frame | reply us/frame | flood win1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AT1100a | 1.1M | 125 | **1,054,006** | 673,141 | 99.9% | 146 | 97 | 30 | 834,500 | 19,854 | 25,611 | 1,010k |
| AT1100P100 | 1.1M | 100 | 1,037,700 | 733,313 | 100% | 155 | 122 | 3.8 | 834,500 | 21,900 | 26,765 | 1,003k |
| AT1200P100 | 1.2M | 100 | **1,059,321** | 689,306 | 99.9% | 150 | 107.5 | 6.2 | 834,000 | 20,076 | 25,362 | 995k |
| AT1100b | 1.1M | 125 | 1,036,935 | 792,859 | 99.8% | 148 | 95 | 27 | 836,000 | 23,153 | 29,060 | 977k |

The window holds: with loop270's 1,063,999 and 1,048,588 that is six legs in a row between 1.037M and 1.064M
(a 2.5% spread), every block full, the ingest at 1 us a transaction. Pacing 100 buys nothing because the cycle is
no longer the leader's wait but B: 95-122 ms against 38-63 at 950k, with the followers' queue sitting at
834-836k -- exactly the gate line of the 1,000,000-slot pool (9.4: the gate holds every frame 20-23 ms, the replies
25-29 ms, the vote slips). The depth's old cost on the road is gone (the road is O(frames), 55-62 ms here), so the
lever 9.5 closed is open again: a pool whose gate line the supply cannot reach. loop272: pool 2,000,000 at 1.1M,
1.2M and 1.3M, pacing 100 and 125.

### 10.7 The 2M pool (loop272): the queue follows the gate line, the window follows the cycle

| leg | offer | pacing | win1 | win2 | cycle | B | D | queue (median) | gate us/frame | flood win1 | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P2M1100 | 1.1M | 125 | 1,062,986 | 678,838 | 143.5 | 62 | 55.6 | 1,579,500 | 21,191 | 996k | 8 |
| P2M1200 | 1.2M | 100 | 1,053,369 | 553,973 | 154 | 109.5 | 7.3 | 1,583,000 | 19,786 | 999k | 2 |
| P2M1300 | 1.3M | 100 | 1,048,538 | 923,628 | 154 | 104 | 11 | 1,589,000 | 20,239 | 998k | 4 |
| P2M1200b | 1.2M | 125 | **1,063,770** | 683,875 | 147 | 85 | 29.4 | 1,607,000 | 20,758 | 1,005k | 1 |

The queue sits at 1.58-1.61M -- the 2M pool's gate line -- as it sat at 834k with 1M: whatever the cap, the supply
exceeds the consumption and the gate is where the balance settles, at ~20 ms a frame either way. The windows are
the same 1.049-1.064M, which is the consumption at the cycle: 163k every 153 ms is 1.065M/s. So the supply is no
longer the term (the flood delivers ~1.0M/s and would deliver more if consumed); **the cycle is**, and the cycle is
B (62-110 with the gate's hold in it) + the leader's seal (126-135) overlapping. The road's own 51-60 still holds
step 1's leftovers -- `take_frames` looks each of 163k transactions up by (sender, nonce) (assemble 20-22 ms) and
the body is still copied and re-encoded for the payload list -- and the leader's period holds step 3's target
(the state wait 20-29 behind the graft's 40) and step 4's (the reads, 55-60 of execution). Ten legs now sit at
1.037-1.064M; pool 1M stays (2M changed nothing and threw 8 TCs once).

### 10.8 The road by reference confirmed; the first output shards lose to the graft (loop273)

Pool 1M, offer 1.1M, pacing 125, attested frames, frame blocks; REF/REFb = the road by reference (4783c3df6:
the frame index holds the transactions' Arcs, `take_frames` is one clone per frame, the payload list is encoded
beside the import), S16/S64 = the same plus step 3's output shards (2a46d9f7a, `N42_OUTPUT_SHARDS`).

| leg | win1 | cycle | B | D | E | assemble | par_exec | graft | state_wait | sealed_at | shard_insert / wait (pool ms) | merge |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REF | 1,062,799 | 146 | 76 | 41.6 | 8 | 4 (take 0, body 2, encode 0) | 55 | 42 | 10 | 128 | - | - |
| S16 | 1,021,421 | 156 | 41 | 78.5 | 21 | 3 | 107 | 0 | 0 | 164 | 138 / 637 | 52 |
| S64 | 999,006 | 162 | 42 | 77.8 | 31 | 4 | 110 | 0 | 0 | 169 | 122 / 535 | 52 |
| REFb | **1,064,718** | 144 | 84 | 38.1 | 8 | 3 | 54 | 41 | 12 | 127 | - | - |

The road is now what section 1 asked for: `assemble_ms` 20-22 -> 3-4, with no per-transaction lookup and no
encoding on it (the whole vote road 51-60 -> 34-38, the rest being the description check 14-16 and the copy 8).
The window did not move because the road was not the cycle's term: the cycle is the leader's build chain
(`sealed_at` 128 from the build's start plus ~18 to the next start = 146), and the vote (B 76-84) overlaps it.

The shards did what the design said -- no graft, no state wait, the chained opener reads the shard set -- but
the inserts cost more than the graft they replaced: 122-138 ms of pool time under the shard mutexes with 535-637
ms of waiting on them (16 batches folding at once, each shard's map growing under its lock), so `par_exec` 55 ->
107-110 and the seal moved from 128 to 164-169; the lazy merge behind the seal (52) then delays `state_ready`
and the roots. 16 and 64 shards wait the same, so it is not the shard count -- it is the fold's shape. The fix
is the design's own point taken literally: the batch appends to a local per-shard vector (no lock, no hashing),
and the fold is S parallel tasks each building its own shard map with the exact capacity reserved, so the whole
fold is one parallel pass of 147k / 16 threads (~3-5 ms wall) instead of a serialised insert. With that the
leader's period is 128 - 42 - 10 = ~76 + the exec, and pacing 125 becomes the bound (loop272 showed pacing 100
only raises B while the seal is 128; with the seal at ~80 the pacing can follow).

### 10.9 Output shards v2 (loop274): the lock-free fold loses too; the flag-off legs read 1.076-1.081M

Same configuration as 10.8; the shards are 8b48b24a4 (batch-local per-shard vectors, S parallel fold tasks
with the capacity reserved, the QMDB root and the hashed post-state read the frozen shards, the merge on a
thread beside the roots).

| leg | win1 | cycle | B | D | E | par_exec | append (pool) | fold (wall) | graft | state_wait | sealed_at | roots | state_ready | merge |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OFF | **1,080,927** | 142 | 57 | 52.6 | 8 | 56 | - | - | 42 | 11 | 129 | 39 | 10 | - |
| S16 | 1,021,392 | 155 | 48 | 71.9 | 18 | 62 | 31 | 34 | 0 | 0 | 158 | 66 | 66 | 64 |
| S64 | 1,026,844 | 159 | - | - | - | 65 | 33 | 33 | 0 | 0 | 161 | 67 | 67 | 64 |
| S16P100 | 1,026,254 | 159 | - | - | - | 62 | 30 | 33 | 0 | 0 | 157 | 66 | 66 | 64 |
| OFFb | 1,075,751 | 145 | - | - | - | 60 | - | - | 42 | 12 | 134 | 36 | 10 | - |

The graft is 42 ms single-threaded for ~147k accounts -- 0.29 us an account, already memory speed -- and every
partition of it costs another pass over the same accounts: the append 30-37 ms of pool time inside the execution
(`par_exec` +6-9), the fold 33-34 ms wall (16 tasks each 9k inserts: not 3-5 -- the task's map build is as
memory-bound as the graft and the pool's wake-up is in it), the roots 39 -> 66 reading the view over S maps, and
the merge 64 beside them. The seal moved to 157-161 and the window fell 5% twice; pacing 100 changed nothing.
**Step 3 is falsified twice** (the mutex fold in 10.8, the lock-free fold here); the code stays behind
`N42_OUTPUT_SHARDS` (0 = off) and the graft stays. The leader's period is not to be split by address -- it is
to be shortened where a term is not memory-bound: the selection (`start_best_ms` 25 -- the frame selector still
walks transactions where the road now takes 326 Arcs), the prep 10, the commit 9 (the body copy 6), the seal 6.

The two flag-off legs are the best windows so far: 1,080,927 and 1,075,751 (twelve legs now at 1.021-1.081M;
tag `fleet3-1.08M-window-20260927`). The chain per block on the leader is start 26 + prep 10 + exec 56 + commit
9 + seal 6 + state wait 10 = ~117 of the 129 `sealed_at`, and the cycle is that plus the handover to the next
build (~15).

### 10.10 The leader's selection by reference (loop275): the start halves, the wait for the parent's fold takes it

dad16f613: the frame entry carries its gas total, the selection checks sender runs in parallel against the
frame's own Arcs, the lanes are settled on a helper thread after the build has its frames (cold bench 30 -> 5).
Same configuration as 10.9, shards off.

| leg | pacing | win1 | cycle | start_best (walk / handoff) | prep | exec | commit | fold (graft) | state_wait | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SEL | 125 | 1,074,749 | 152 | 13 (7 / 4) | 3 | 57 | 8 | 54 (44) | 27 | 130 |
| SELP100 | 100 | 1,069,355 | 152 | 13 (7 / 4) | 4 | 56 | 9 | 54 (44) | 27 | 129 |
| SELb | 125 | 1,059,455 | 154 | 13 (7 / 4) | 3 | 58 | 8 | 54 (45) | 28 | 131 |
| SELP100b | 100 | **1,077,680** | 151 | 13 (7 / 4) | 3 | 59 | 8 | 53 (44) | 28 | 132 |

The start fell 26 -> 13 and the prep 10 -> 3, and every millisecond of it moved into `state_wait` (10 -> 27-28):
the chained build now reaches its execution before the parent's fold has published the state, so `sealed_at`
stays 129-132 and the window 1.059-1.078M. The leader's chain is therefore, per block, the parent's fold (54:
graft 44) running against the child's start + prep (16), then the child's exec 57 + commit 8 + seal 6 --
**the fold is the exposed term** and the only one left that is not the execution itself. Step 3 attacked it
by address partition and lost twice (10.8, 10.9), but the loss is not explained: the graft inserts 147k accounts
in 44 ms single-threaded (300 ns each, i.e. cache misses, not bandwidth), while v2's 16 parallel tasks of 9k
inserts each took 33 ms wall -- 3.6 us an insert, twelve times the graft's -- which points at the fold's shape
(the transposition, per-task allocation, cloning in the add rules, the pool's wake-up), not at the idea. Next: a
microbenchmark of the fold against the graft on the block's shape, off the fleet, until the fold is under ~8 ms
wall, then one leg.

### 10.11 The fold off the fleet (microbenchmark, e3179b06d): the fold is 4 ms, the fleet's 33 is the cores

`crates/n42/engine-types/tests/output_shards_bench.rs` (ignored; the block's shape, jemalloc with the fleet's
`MALLOC_CONF`, 16 cores, medians of 20). Milliseconds:

| path | v2 | v4 |
| --- | --- | --- |
| graft (single-threaded) | 23.2 | 24.3 |
| append, wall / summed pool | 3.7 / 55 | 0.8 / 8 |
| fold, wall | 3.5-3.9 | 4.5 |
| merge | 25.2 | 28.9 |
| roots from the merged bundle (QMDB ops / hashed) | 4.9 / 16.4 | 5.2 / 16.5 |
| roots from the shard view (build / ops / hashed) | 0.44 / 4.5 / 15.6 | 0.46 / 4.6 / 15.8 |
| fold pipelined with 0 / 8 / 16 busy threads on the cores | 4.5 / 13.4 / 28.0 | 7.6 / 18.1 / 32.1 |

The fold's own work is 0.38 us an insert -- the graft's speed, sixteen ways. The fleet's 33 ms is reproduced
only by putting 16-32 busy threads on the fold's cores: the fold waits for its slowest task, and on the fleet
the parent's merge (25-29) and roots run on those cores beside it; the roots' 66-vs-39 is the same contention
(merge + roots together 34-37 against roots alone 21, the same 1.7x). The append's 55 ms of pool time was the
move of a 264-byte account into a fresh per-shard vector inside the execution; v4 hands the batch's map over
whole with per-shard address lists, so the fold copies from it (append 8, fold +1 idle / +3 pipelined). What
remains, on the fleet, is the ordering in `payload.rs`: the merge and the roots must not share the build pool's
cores with the child's execution and fold. loop276 runs v4 with the fold split logged ("output shards folded":
queue / skew / task_max / tail) to name the fleet's fold.

### 10.12 v4 on the fleet (loop276): the fold's tasks themselves take 40 ms there

| leg | win1 | cycle | par_exec | append | fold (wall) | fold split: queue / skew / tail us, task_max ms | merge | roots | state_ready | state_wait | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OFF | 1,064,865 | 153 | 59 | - | graft 45 | - | - | 36 | 9 | 28 | 134 |
| S16 | 1,037,723 | 157 | 57 | 5 | 39 | 15 / 29 / 28, **39.7** | 58 | 60 | 61 | 0 | 147 |
| S16b | 1,048,568 | 155 | 59 | 6 | 41 | 14 / 29 / 27, **41.8** | 61 | 64 | 63 | 0 | 151 |
| OFFb | 1,070,302 | 152 | 57 | - | graft 45 | - | - | 35 | 9 | 28 | 131 |

The append is now 5-6 ms of pool time (55 before) and the fold's queue, skew and tail are microseconds -- so
it is not the pool's wake-up, not a descheduled task, not the transposition. The slowest task takes 40 ms for
~9k inserts (4.4 us each) where the same task takes 3.5 ms off the fleet (0.38 us), and every task takes the
same 40 (skew 29 us). A shared, serialised resource inside the tasks' own work: the likeliest is memory --
the 16 tasks allocating and first-touching ~40 MB of fresh shard maps at once (page faults under one mmap lock,
page zeroing) where the microbenchmark's warm rounds reuse freed memory, or the batch maps' accounts being
read from other cores' caches. The merge (58-61) and roots (60-64) run beside the child's fold and execution and
stay 1.7x their idle cost. The window is 1.038-1.049M against 1.065-1.070M off, the seal 147-151 against 131-134.
Next: count the fold's minor faults and CPU time per task on the fleet, reproduce with the fleet's liveness
(the parent's shards alive in the child's overlay while the child folds), and recycle the shard maps' allocations
across blocks; if the tasks are then ~4 ms the seal is ~95 and the chain follows.

### 10.13 The fold with the fleet's liveness, off the fleet (2769bc095): not the faults -- the cores

The pipelined bench (`bench_output_shards_fold_live`: three blocks' shards and merged bundles held, the parent's
merge and roots beside the child's add and fold, `BENCH_LOAD=n` busy threads on the fold's 16 cores), release,
medians of 20, per fold task:

| busy threads | task wall / CPU ms, minor faults a block | with map recycling |
| --- | --- | --- |
| 0 | 4.9-5.9 / 4.3, 3-9 | 6.8-7.0 / 4.6, 2-3 |
| 16 | 20.4 / 8.3, 2,055 | 19.4 / 8.1, 4 |
| 24 | 26.6-27.2 / 9.0-9.3, ~2,000 | 24.8-27.3 / 8.1-8.7, 7-9 |
| 32 | 31.3 / 8.5, 2,117 | 26.8 / 7.6, 36 |

With the fleet's liveness and no load a task is 5 ms and faults almost never (jemalloc reuses its dirty
pages); the 40 comes back only with busy threads on its cores, where wall is 2.5-3.7x CPU and the CPU itself
doubles (SMT siblings, memory). Recycling the maps (`N42_SHARD_RECYCLE=1`, off) saves nothing under load and
costs the idle fold 2-3. So the fold's cost on the fleet is the node's other threads -- the parent's roots (the
global rayon pool, 16), the merge, the ingest (12), tokio (16) -- on the build pool's cores: 60 busy threads on a
node's 74 logical CPUs (37 physical + siblings). The single-threaded graft is immune to that; sixteen tasks are
not. loop277 logs each task's CPU, faults, migrations and preemptions on the fleet, and runs one S16 leg with
fewer competing threads (rayon 8, ingest recover 4: attested frames need no verification) to see whether the
fold, and the execution beside it, get their cores back.

### 10.14 The fold's tasks on the fleet (loop277): CPU equals wall, no faults, no preemption -- memory

| leg | win1 | cycle | fold (wall) | task_max / task_cpu_max ms | faults (max / sum) | migrated / preempted | merge | roots | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OFF | 1,070,094 | 152 | graft 45 | - | - | - | - | 36 | 133 |
| S16 | 1,053,399 | 155 | 40 | 40.8 / 40.8 | 452 / 453 | 0 / 0 | 58 | 60 | 145 |
| S16Q (rayon 8, ingest 4) | 1,004,901 | 162 | 39 | 38.9 / 38.9 | 545 / 546 | 0 / 0 | 57 | 61 | 143 |
| OFFb | **1,091,680** | 149 | graft 44 | - | - | - | - | 36 | 132 |

The slowest task's CPU time is its wall time to the microsecond, it is never preempted or migrated, and single
lines show tasks at 29.8 ms with one fault and 41.5 with 366: the faults are not it, the scheduler is not it,
and fewer competing threads (S16Q) changed nothing. A task spends 30-40 ms of CPU on ~9k inserts -- 3.3-4.4 us
each against 0.4 off the fleet -- and CPU time on a stalled load is still CPU time: **the fold is memory-bound
under the fleet's memory load.** Each insert reads a 264-byte account from a batch map written ~50 ms earlier on
another core (cold: the node's 60 threads have been through the caches since) and writes it into a fresh map --
ten or so cache lines a piece, and under three nodes' worth of roots, merges, executions and floods on one
socket the miss latency is what it is. The graft (44-45 on the fleet, 24 off) pays the same per-line price but
misses one line at a time from one thread; sixteen threads missing at once do not go sixteen times faster on a
saturated memory system. Closing 10.9's question: the partition was not slow by shape, it is slow by bytes.

The loop's best window is now 1,091,680 (OFFb; sixteen legs at 1.005-1.092M). What the five step-3 legs
establish is that the leader's fold is bound by the bytes it moves (147k x 264 B in, the same out) rather than
by the thread count, so the way to shorten it is to move fewer bytes: keep the batches' maps as they are and
build only an *index* (address -> batch, slot: 16 bytes) as the block's map -- 2.4 MB instead of 40, one
probe more on a read -- with the roots and the merge iterating the batches directly. That is a rewrite of the
graft rather than of the shards, and it is the last step-3 attempt: if the index does not bring the fold under
~15 ms on the fleet, step 3 closes and the order moves to 4/5.

### 10.15 The index graft on the fleet (loop278): the fold 40 -> 11, the seal 130 -> 119, the pacing now binds

`N42_OUTPUT_SHARDS=16 N42_OUTPUT_INDEX=1` (2c6f18f06): the batch maps stay, the block's map is an index
address -> batch (22 bytes an entry), conflicts (4.5-4.8k a block) summed into a small map.

| leg | win1 | cycle | B | D | fold (index build) | task_max = CPU | graft | state_wait | par_exec | sealed_at | roots | merge |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OFF | 1,053,566 | 146 | 89 | 31.5 | graft 45 | - | 45 | 29 | 55 | 130 | 37 | - |
| IDX | **1,080,654** | 143 | 54 | 59.3 | 11 (10) | 10.4 | 0 | 0 | 58 | 119 | 61 | 59 |
| IDXb | 1,059,438 | 143 | - | - | 11 (10) | 10.3 | 0 | 0 | 58 | 120 | 65 | 61 |
| OFFb | 1,070,318 | 144 | - | - | graft 44 | - | 44 | 28 | 58 | 131 | 37 | - |

Moving 22 bytes an account instead of 264 brought the fold from 40 to 11 on the fleet (the task 10.4 ms of
CPU where the bench reads 0.6: the same memory-bound ratio as before, on a tenth of the bytes), the graft and
the state wait are 0, and the seal moved 130 -> 119 with the reads through the index costing the execution ~3.
The window did not move (1.059-1.081M against 1.054-1.070M) because the pacing now binds: D, the leader's wait
for its 125 ms interval, rose 31 -> 59 and B fell 89 -> 54 -- the chain is under the pacing for the first time
since 10.6. The roots are 61-65 beside the merge (59-61) as in v4; with the seal no longer waiting on them
that is off the chain, but the merge should still follow the roots rather than share their cores.

Two things to fix before pacing 100: **the tenure handover fails in the index mode** -- both IDX legs, at
views 1028-1038, had 3-9 own blocks "not the one committed" and 7-11 direct imports failing with "no gov5
header variant hashes to the payload's block hash" (a header the followers cannot reconstruct from the payload),
7-8 TCs and 8-12 s lost, where the OFF legs had 0 / 0 / 1; the v4 shard legs had it too (loop276 S16: 16 / 4 / 5,
S16b 0 / 3 / 3), so it is the shard path's, not the index's, and the failing block was the new leader's small first
build (1033: 14,000 transactions).
It is after the windows, so the numbers above stand, but the mode is not sound until the new leader's first
build (the path that does not seal early: the kept cache, `into_staged`, withdrawals put back) matches the
direct graft's header. Then pacing 100 and 110 with the index.

The handover read (ec04b9322): no state was wrong -- the followers refused the compact body ("13,000 of 14,000
transactions not held here"), fetched the whole payload and rooted it with the MPT while the leader had sealed
it with the frame tree, so no header variant matched; loop277 OFF had the same refusal once at 1348. Behind it,
in shard mode the parent's roots start at its seal, and the slow roots that come every ~44 blocks (575-650 ms)
hold the grandparent's hand-off to the engine (620 instead of ~40), so the chained build's 150 ms wait refused
with "no state found for block <grandparent>" -- 1-3 times a leg in every S16/IDX leg, never with the flag off --
and the view changes that followed left the followers with descriptions whose frames they did not hold. The fix
waits for the parent's `Complete` when the grandparent is missing, records a description's claimed root before
any refusal so a whole-payload conversion roots by the claim when the body reproduces it, and runs the merge
after the QMDB root instead of beside it. Still open: after a refused chained build the leader's prepared build
ends in "no payload build for id" ~5 s later (the actual stall), a separate defect. loop279: IDX (the handover
check), then pacing 100, 110, 100.


### 10.16 The handover holds (loop279); the merge behind the root moved the seal back to 131-135

| leg | pacing | win1 | cycle | no-variant / own-not-committed / TCs | invalid blocks | fold | sealed_at | roots stage | state_ready | merge |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| IDX | 125 | 1,064,894 | 153 | 0 / 0 / 2 | 2 | 11 | 135 | 96 | 97 | 54 |
| IDXP100 | 100 | 1,081,199 | 151 | 0 / 0 / 3 | 1 | 12 | 135 | 96 | 97 | 54 |
| IDXP110 | 110 | 1,070,283 | 152 | 0 / 0 / 1 | 0 | 12 | 132 | 94 | 95 | 53 |
| IDXP100b | 100 | 1,081,076 | 151 | 0 / 0 / 1 | 0 | 12 | 135 | 96 | 97 | 55 |

The handover is clean in all four legs (0 refusals, 0 own blocks lost, 1-3 TCs, as the flag-off legs). But the
seal went back from 119 (10.15) to 131-135 with every build phase unchanged (start 14, prep 4, exec 58, commit
9, fold 19): the merge now runs inside the roots stage (96 against 61), and the child's header needs the
parent's state root, so the seal waits for a root that is published 35 ms later than it is computed. Pacing
100 therefore gave nothing again (cycle 151). Two of the legs also rejected a block after the windows
("failed to apply blockhash contract call: the QMDB reader did not answer slot 0x0", then "links to previously
rejected block") -- new, and the QMDB reader shares the timing the merge changed. Next: publish the parent's
state root the moment the QMDB root job finishes and run the merge strictly after that, on a helper thread that
is neither the builder's nor the reader's; find why the reader did not answer.

### 10.17 The root first (loop280): the leader's chain is under the pacing; B and the follower's import are the cycle

5af5d3d17 (the state root published the moment the QMDB root job finishes, the merge after it on its own thread)
and dee53c148 (the journals a persistence batch's readers need are held until the batch commits: the batch had
grown past the 64-step journal depth, so every read until the commit was declined -- the "reader did not answer").

| leg | pacing | win1 | cycle | B | D | E | sealed_at | roots | state_ready | merge | exec | invalid / refusals / TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| IDXP100 | 100 | 1,075,734 | 147 | 107 | 8 | 8 | 128 | 36 | 97 | 52 | 62 | 0 / 0 / 1 |
| IDXP100b | 100 | 1,075,741 | 146 | 103 | 8 | 9 | 120 | 35 | 95 | 52 | 57 | 0 / 0 / 1 |
| IDX | 125 | 1,064,871 | 153 | - | - | - | 130 | 35 | 98 | 52 | 62 | 0 / 0 / 1 |
| IDXP110 | 110 | 1,070,327 | 152 | - | - | - | 124 | 35 | 100 | 54 | 57 | 0 / 0 / 1 |

Every leg clean. The roots are the root job alone again (35-36) and the seal 120-130 (it follows `par_exec`
57-62). At pacing 100 the leader's wait D is 8: **the leader's chain is under the pacing for the first time**, and
the cycle did not follow (146-147) because the term is now B, the proposal-to-quorum, at 103-107 -- of which
the followers' vote road is 28-38 (frames all held: `frames_missing` 0, `miss_wait` 0, `parent_wait` 0, check 14,
copy 8) and ~65 is outside the road, undissected: the description's transport, the validator's dispatch, the
vote's signing and return, the leader's aggregation. Behind B sits the follower's import beside the loop:
184 ms median for a full block (exec 72, checks 7, root 38, mined 4, engine 23, ~40 unnamed) against a 146 ms
cycle -- the followers import in overlap and fall behind under load (`imports_over_600ms` 19-106 a leg), and a
follower cannot vote on N+1 until it has what N+1's header claims about N. Step 3 is therefore done as far as
the leader is concerned (the fold 40 -> 11, graft and state wait 0, the chain 120-130 -> the pacing binds), and
the order moves to the followers: B's 65 ms outside the road, and the import's 184 (steps 4 and 5).

### 10.18 B dissected (loop280 IDXP100b): the road twice, and the leader's own wait for its seal

Per full block of window 1 across the three nodes' logs (the hosts share a clock): the leader's body prepared ->
the followers' receipt 0.17 ms; receipt -> vote road start 1.05; the road 37 (node1 31.5, node2 42); road end ->
vote sent 0.8; the later follower's vote -> the leader's commit 5.3. So a block's vote is the slower follower's
road plus ~7 ms of transit and aggregation -- ~50 -- and B's logged 103-111 is the rest: R1_collect starts at the
view, and the view starts before the leader's own build has sealed (the chain 120-130 against pacing 100). The
cycle is therefore still `sealed_at` + ~20 (loop278 119 -> 143, loop280 120 -> 146, 130 -> 153), and inside
`sealed_at` the execution (57-62) is the largest term, then the fold (index 11 inside `par_fold` 19-20), the start
(14), the commit (8), the seal (7). The follower's import is 172 (node1) / 199 (node2) with the named fields
summing to the total (exec 71-73, checks 7, root 38-46, mined 4, engine 16-28); imports overlap 68-86% of the
time, and the slow tail (>300 ms: 41-45 a leg, doubling from window 1 to 3) is an unnamed residual of 120-140
under that overlap. **Section 4 next**: the execution's reads, on both sides, with `N42_PHASE_TIMERS=1` for the
current shape first (the 2.3 us / 87% figures are from plan v4), and design A (the per-block read set) built in
parallel; the CPU profile still needs `kernel.perf_event_paranoid=1` on the host.

### 10.19 The execution timed (loop281, `N42_PHASE_TIMERS=1`): the reads are 0.57 us, and the timers see a third of the wall

| leg | win1 | par_exec (wall) | par_run | exec_read (pool ms) | evm | write | other | reads: cache / provider / view | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T | 1,064,180 | 59 | 70 | 215-269 | 19-20 | 27-29 | 9-10 | 326k / 72-97k / 20-66k | 128 |
| Tb | 1,080,524 | 60 | 70 | 222-281 | 19-20 | 27-30 | 9-10 | 326k / 69-88k / 19-75k | 129 |
| P100 (no timers) | 1,067,839 | 58 | 67 | - | - | - | - | - | 121 |

The timers cost nothing visible. A full block makes ~490k account reads (three a transfer: 326k from the
batches' own cache, 70-97k from the parent/grandparent outputs, 20-87k from the QMDB view), and they take
215-281 ms of pool time -- **0.57 us a read, not plan v4's 2.3**: the index-mode parent output and the read
view are not the contended structures they were. The reads are still 80% of what the timers see (read 281, evm
20, write 30, other 10 = ~340 pool ms) -- but 340 pool ms on 16 threads is 21 ms of wall, and `par_exec` is
59. Two thirds of the execution's wall is outside the timed transfer: the batches' spans are unequal or have
gaps (the sender-group partition's balance, the batch's setup and its map, the sink's append 8, the pool's
scheduling), and no field names it yet. So design A's ceiling on this shape is the read's ~280 pool ms (~15
ms of wall at best), and the larger term is the batches' shape. Next: per-batch spans (max, min, CPU) on the
phases line, then the read set (`N42_READ_SET=1`, built, untested until the box was free) in one leg.

### 10.20 Design A off the fleet (bf8e01dfd): the pass costs more than it saves; the view's read is 5x slower under 16 threads

`bench_build_prefetch` (163k transfers, a QMDB view over 2M accounts, 16 cores): plain execution 30-32 ms (batch
max 14, median 13); with the read set (`N42_READ_SET=1`) 46-48 = the pass 23 (dedup 3, 159k accounts resolved
in 20 at ~2 us of pool time each) + the batches 23-25 (max 9-10, median 8-9). Per-batch reading drops each batch
from 14 to 9, but the pass costs 23 to save 8: **design A is falsified as a pass on the chain**. The resolve
pass alone names design B's evidence: 395 ns a read on one thread, 781 on four, 1,964 on sixteen -- five times
slower per read under sixteen threads, and the shared answer counter is 4% of it. What remains inside the view's
lookup is the global `versions` read lock taken and held per read, the per-shard offset lock, a blake3 of the
key and two random reads of the mapped entry file; the bench cannot tell the lock from the mmap/TLB misses
(perf can). On the bench the batches run in two waves (32 batches on 16 threads, start skew one batch, no
waits), so `par_exec` is two batch lengths -- loop282 (T, Tb) puts the same spans on the fleet's line to say
whether its 59 ms is waves, imbalance, or per-batch overhead, and runs the read set once.

### 10.21 The batches' spans on the fleet (loop282): two waves of 29 ms, and 3.3 us a transfer outside the reads

| leg | win1 | par_exec | batch max / median / min | batch CPU max | start skew | wait | txs per batch | exec_read (pool) | read set | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T | 1,064,891 | 58 | 29 / 23 / 10 | 27 | 27 | 0 | 2,500-6,000 | 228-270 | - | 123 |
| Tb | 1,075,760 | 58 | 29 / 21 / 10 | 26 | 26 | 0 | 2,500-6,000 | 215-270 | - | 124 |
| RS | **1,081,190** | 72 | 22 / 18 / 8 | 22 | 21 | 0 | 2,500-6,000 | 169-222 | 20 (158k, 0 misses) | 135 |

The execution's wall is two waves of batches (start skew = one batch length, no waits, ~40 batches of 2,500-6,000
on 16 threads), each batch's CPU equal to its wall: no gaps, no imbalance -- the term is the batch's CPU, 29 ms
for 6,000 transfers = **4.8 us a transfer of pool time** (~850 pool ms a block on 16 threads is the 58 wall,
close to perfectly parallel). The timers inside `transfer` see 1.7 us of it (read 0.55 x 3, evm 0.12, write
0.18, other 0.06); the read set confirms the reads' share from the other side (batch max 29 -> 22 with the reads
resolved ahead, the pass 20 on top: falsified on the fleet as on the bench, `par_exec` 58 -> 72). **~3.3 us a
transfer is spent in the batch loop outside `transfer`** -- the transaction's access and sender resolution, the
checks, the receipt and its bloom, the sink's append, the gas accounting, the per-transaction allocations --
untimed and unnamed. That is the execution's largest term by a wide margin, on the leader and, by the same
loop, on the follower (`import_exec` 75). Next: time the batch loop's sections per transaction under
`N42_PHASE_TIMERS=1`, read the loop for its per-transaction costs, and cut them; the bench (batch 13 ms for 5k
= 2.6 us a transfer) can drive it off the fleet.

### 10.22 The batch loop off the fleet (ffeeb1590..e69007bf9): 1.62 -> 1.26 us a transfer alone, 2.5 under sixteen threads

The loop's sections under `N42_PHASE_TIMERS=1` (`loop_fetch/check/transfer/receipt/gas/sink/other_ns`,
`batch_setup/close_ns`; the loop has no pre-checks and builds no receipt -- `transfer` does every check and the
receipts come later) on the bench, ns a transfer of pool time, before -> after the cuts:

| section | 1 thread | 16 threads |
| --- | --- | --- |
| fetch | 52 -> 48 | 60 -> 50 |
| transfer (read / evm / write) | 714 -> 675 (620 -> 678 / 110 -> 75 / 105 -> 30) | 1,690 -> 2,030 (1,590 -> 2,020 / 110 -> 75 / 107 -> 31) |
| gas | 23 | 23 |
| sink | 390 -> 92 | 402 -> 93 |
| other | 77 -> 54 | 82 -> 56 |
| batch close | 365 -> 370 | 290 -> 268 |
| total | **1.62 -> 1.26** | **2.56 -> 2.52** |

Three cuts: the sink -- revm's `State::commit` looked each account up twice and rebuilt a plain account and a
transition every time; a `BatchState` keeps each account as its merged transition in one map and hands the
changed accounts to the same revert builder (be80847cc); the write -- `transfer_plain` returns the computed
accounts instead of an `EvmState` with three boxed originals a transfer; the read's clone -- the loaded info is
moved into `previous_info` on the first change instead of copied on every read (921de3899). The samplers had
timed each batch's coldest transfer once in 64, inflating `read_ns` (the fleet's `exec_read` before this leg
carries the same bias). Under sixteen threads the total barely moves because **the reads absorb what the loop
gave up** (1.59 -> 2.02 us a transfer): less work between reads is more pressure on the view's shared line.
The bench does not reproduce the fleet's 3.3 us outside `transfer` (its loop was 1.0 before the cuts), so what
the fleet's loop spends is still to be named (loop283, the same keys on the fleet: the fetch's `to_consensus`
clone and `tx_env`, `OutputShards::add` in the close, `open_db` in the setup are not in the bench). The view's
per-read lock is the next term either way (step 4c: a snapshot per batch, the answer counter per thread).

### 10.23 Step 4b on the fleet (loop283): the execution 58 -> 48, the seal 114-118, and the loop named

| leg | win1 | cycle | par_exec | batch max / median | sealed_at | loop ns a transfer: fetch / transfer / other / sink / gas | batch close / setup ns | exec_read (pool ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T | 1,074,392 | 152 | 48 | 23 / 17 | 114 | 451 / 1,704 / 302 / 137 / 25 | 490 / 9 | 191-265 |
| Tb | **1,090,470** | 149 | 49 | 24 / 17 | 118 | 457 / 1,704 / 302 / 137 / 25 | 504 / 10 | 200-265 |
| P100 (no timers) | 1,078,572 | 151 | 48 | 24 / 16 | 117 | - | - | - |

The three cuts hold on the fleet: the batch 29 -> 23-24, `par_exec` 58 -> 48-49, `sealed_at` 123 -> 114-118.
The loop on the fleet, per transfer: transfer 1.70 us (the reads' 1.2-1.6 with the sampler's bias still in the
fleet build), **fetch 0.45** (the bench's 0.05: the pooled transaction's `to_consensus` clone and `tx_env` on a
0x50 envelope), other 0.30, sink 0.14, gas 0.03, and the batch close 0.49 a transfer (the bundle build and the
sink's hand-over) -- 3.1 us in all, of which 1.4 is outside `transfer`. The cycle did not follow the seal this
time (149-152 against 114-118): the floor is elsewhere now -- the followers' import (205-207 for a full block,
overlapped) and their vote after it (section 5), or the road twice (10.18). Next, in parallel: the view's
per-read lock (4c, on both sides), the fetch and the close (4d), and section 5 on the followers.

### 10.24 The view's lock off the fleet (03b5ce507, ac71c4934): the 16-thread read 2.11 -> 0.57 us, the bench's execution halved

The one `versions` read lock every read took is now 128 cache-line-padded per-thread reader slots, each an
immutable copy of the versions owning the journals' Arcs; a reader holds only its slot's read lock through the
record read, a writer swaps every slot under its write lock (so a writer still waits out every read in flight:
a lock hoist, no change under a writer). The answer counter is 64 padded per-thread-slot counters summed on
read. A per-batch lock-free snapshot was rejected: the offset index moves in place and a truncation cuts the
mapped file (a SIGBUS for a reader without the lock).

| us a read, warm | 1 thread | 4 | 16 |
| --- | --- | --- | --- |
| at the head, before -> after | 0.38 -> 0.38 | 0.82 -> 0.46 | 2.11 -> **0.57** |
| 16 versions behind, before -> after | 1.97 -> 1.95 | 2.30 -> 2.02 | 4.16 -> 2.14 |

`bench_build_prefetch`: the resolve pass 390 / 805 / 2,014 -> 391 / 482 / 659 ns a read at 1 / 4 / 16 threads;
plain execution 28-32 -> 14 ms; batch max / median 14 / 13 -> 7 / 6. The 16-behind read is the walk through 16
journals, untouched. loop284 runs it on the fleet (both sides read through the view).

### 10.25 The view's lock on the fleet (loop284): the fleet reads elsewhere; 1,094,594; the followers' chain is the cycle

| leg | win1 | cycle | par_exec | batch max / median | exec_read (pool) | reads: cache / provider / view | sealed_at | import total / exec |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T | 1,080,591 | 151 | 49 | 24 / 17 | 196-258 | 326k / 135k / 11-28k | 116 | 207 / 78 |
| Tb | 1,089,690 | 149 | 52 | 27 / 17 | 195-288 | 326k / 125-134k / 21-29k | 120 | 206 / 78 |
| P100 (no timers) | **1,094,594** | 149 | 50 | 28 / 17 | - | - | 119 | 204 / 75 |

The best window so far (1,094,594), but not from the lock: the fleet's execution reads 326k from the batch's
own cache, 125-135k through the provider door (the parent's index-mode output and the grandparent's map) and
only 11-29k through the QMDB view -- the door the lock sat on is 5% of the fleet's reads, and `exec_read`,
`par_exec` and the batch are unchanged. The bench's halving was the bench's shape (every read a view read).
Where the fleet's reads go is now the provider door (the index probe + the batch map, 125-135k at ~0.5 us) and
the cache (326k) -- both per-thread structures with no lock to hoist; their cost is the memory line each touch
takes, which section 4's design B (dense ids, a flat table) is about.

The cycle is 149-151 with the leader's seal at 116-120: **the followers' chain is the cycle now.** A follower
votes on n+1 only after it has n's execution fields (deferred execution: n+1's header carries n's state root),
so per block it runs the road (28-42), the execution (75-78, the old loop: revm's `State`, the clone per read,
the `EvmState` map) and the QMDB root (38-46) in sequence -- ~150 -- and the leader, sealed at 120, waits for
the quorum. Section 5 is the step: start the follower's execution before the road ends (the frames are all
held; the description names them in order), give its loop 4b's cuts (75 -> ~50), and put the root on the pool
beside the last batches, so the follower's chain is ~80-90 and the leader's seal binds again.

### 10.26 The fetch, the slot and the close off the fleet (step 4d): 42 -> 32 ms on the real-path bench

`bench_build_real_path` (a full block of pooled 0x50 transfers through the builder's own `convert`, the sink in
index mode, the transactions-root job beside the batches on odd rounds), ns a transfer at 16 threads:

| | fetch | transfer | other | sink | gas | close | exec ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| base | 155 | 1,730 | 133 | 94 | 23 | 323 | 42 |
| the TxEnv by reference, the result slot an index | 127 | 1,710 | 56 | 86 | 23 | 370 | 33 |
| + the close in place (`BundleAccount` in `BatchState`, `take_bundle` one pass) | 110 | 1,787 | 52 | 80 | 23 | 130 | **32** |

The envelope clone was not the fetch's cost (a unit slot read the same 170); what remains is the cold read of
the pooled transaction (110 on the bench, 407-457 on the fleet where the pooled transactions are older and
scattered -- unconfirmed). The 470-byte result slot was "other" (133 -> 52). The close is the in-place bundle
(323 -> 130). A chunked fetch and a slot pre-read gained nothing and were dropped. A new test runs 16 batches
through revm's `State` and through `BatchState` and compares the bundles through the graft and the index.
On the fleet with the followers' chain as the cycle (10.25) this shows in `sealed_at`, not in the window, until
section 5 lands; measured together with it.

### 10.27 The follower's chain read from loop284 (section 5a, 9baaa674e..dbb78b394)

What the vote on n+1 waits for: all four of n's fields (state root, receipts root, logs bloom, gas), through
`wait_for_parent_fields` in the follower's import before `validate_against_parent`; the receipt half is filed
by the post-execution checks (7-9 ms), the state root last, by the QMDB root job. Timeline on node1, medians
of 756 full blocks, ms after block n's road start: vote on n 38 (p75 105), exec start 38, exec end 113, root
end 168 (p75 220), import end 228; n+1's road starts at 160 and its vote lands at 224. **Blocks alternate**: on
every other block the root takes 100-106 instead of 36-38 because it queues on the worker pool behind n+1's
execution batches, and n+1's vote then waits 66-85 for n's fields, landing at n's root end. The chain is
road -> exec -> root (made slow by the next block's execution) -> vote.

Four changes, one leg each: the timeline keys on the direct import line (`road_end_ms exec_start_ms exec_end_ms
root_end_ms fields_ready_ms parent_fields_wait_ms`, always on); the follower's batches on the leader's
`BatchState` + `transfer_plain` (`follower_batch`, on by default, `N42_FOLLOWER_BATCH_STATE=0` reverts; the
import bench 93-96 -> 79-81 by component); `N42_FOLLOWER_EXEC_EARLY=1` (the execution starts before the
includability check, which runs beside it on its own small pool; the check's error still wins, the vote still
follows the check); `N42_FOLLOWER_FIELDS_EARLY=1` (the QMDB root starts on its own thread the instant the
execution returns, hashed on a dedicated pool of 8, one root at a time). loop285 runs BASE / FIELDS / BOTH /
BOTHb with step 4d on the leader.

### 10.28 Step 4d and the follower's chain on the fleet (loop285): 1,130,438, and the blocks are no longer full

| leg | win1 | cycle | occupancy / full | leader par_exec / sealed_at | follower: road end / exec start / exec end / root end = fields ready | exec / root | import total | fields wait |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASE (4d, follower BatchState) | 1,097,485 | 149 | 99.9% / 201 of 202 | 33 / 102 | 58 / 47 / 125 / 206 | 75 / 56 | 204 | 0 |
| FIELDS (+ fields early) | 1,126,383 | 133 | 92.0% / 149 of 225 | 39 / 116 | 44 / 43 / 137 / 179 | 88 / 35 | 170 | 0 |
| BOTH (+ exec early) | **1,130,438** | 133 | 92.4% / 159 of 225 | 36 / 109 | 37 / 40 / 130 / 174 | 86 / 37 | 163 | 0 |
| BOTHb | 1,126,458 | 130 | 89.9% / 137 of 231 | 33 / 107 | 38 / 41 / 131 / 174 | 87 / 38 | 163 | 0 |

Step 4d on the leader: `par_exec` 48 -> 33 and the seal 116-120 -> 102-109 (the fetch, the slot and the close
were the fleet's 1.4 us outside `transfer`). On the followers the root on its own pool the instant the execution
returns takes the alternating 100 out (root 56 -> 35-38, fields ready 206 -> 174-179), and the execution
starting before the check moves the road's end from 58 to 37 -- the follower's chain is 174 from the road
start against 206. **The cycle fell 149 -> 130-133 and the window to 1,126-1,130k**, and for the first time
since the frames the blocks are not full (90-92% occupancy, 137-159 of 225-231 at 95%): the flood's 1.1M offer
(~1.0-1.05M delivered) is under what the fleet now consumes. The follower's execution is 86-88 here against 75
in BASE (the extra pools share the node's cores), which is the next term after the supply. Next: the offer at
1.2 and 1.3M with both flags, then the follower's execution.

### 10.29 The offer above the consumption (loop286): 1,156,338 with full blocks; the followers' chain again

| leg | offer | win1 | cycle | occupancy / full | queued | gate us | leader par_exec / sealed_at | follower: road end / exec end / fields ready | exec / root | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1200 (first leg) | 1.2M | 1,027,696 | 158 | 99.6% | 834,500 | 26,395 | 38 / 116 | 49 / 152 / 201 | 99 / 37 | 738k |
| R1300 | 1.3M | 1,139,512 | 143 | 99.8% | 787,000 | 17,027 | 34 / 114 | 38 / 124 / 169 | 80 / 38 | 700k |
| R1250 | 1.25M | **1,156,338** | 140 | 99.5% | 786,000 | 16,821 | 32 / 113 | 37 / 123 / 169 | 82 / 37 | 619k |
| R1200b | 1.2M | 1,148,373 | 142 | 99.7% | 797,000 | 16,636 | 33 / 114 | 37 / 123 / 169 | 82 / 38 | 641k |

With the offer at 1.2-1.3M the blocks are full again and the window is 1,139-1,156k -- the fleet's consumption at
a 140-143 ms cycle. The first leg after the build is the slow kind (10.6's void: the gate at 26 ms, the queue
at the line, the follower's execution 99). The queue now sits *under* the gate line (786-797k against 834k):
the supply no longer piles up, the fleet is the term. Its term is the followers' chain: fields ready at 169
after the road's start (road end 37, execution 80-82, root 37-38), against the leader's seal at 113-114 --
the follower's execution is 2.5x the leader's for the same transactions (section 5b: the follower through the
leader's build path -- the sender partition, `BatchState`, the index shards, no graft, the build pool). Window 2
falls to 619-738k at these offers (the base fee runs to 1e19 and the cycle to 0.22-0.26 s): window 1 is the
metric, as always, but the second window's decay is steeper than at 1.1M and is noted.

### 10.30 The follower through the leader's build path, off the fleet (b04460771..f5ec8b806)

`bench_follower_import` (163k transfers, 154k accounts, 16 threads), ms:

| path | exec | partition | batches wall (count, max / median) | fold | drop | merge |
| --- | --- | --- | --- | --- | --- | --- |
| components + graft (the fleet's path) | 86-88 | 12-14 | 58-59 (380, 8 / 2) | 5-7 | 5 | - |
| senders + graft | 84-85 | 5-6 | 63-65 (32, 46-48 / 25) | 6-7 | 5 | - |
| the build path (`N42_FOLLOWER_BUILD_PATH=1`) | **64-66** | 3-4 | 52 (32, 25 / 22-23) | 2 | 1 | 45 (one thread, beside the root) |

The build path removes the partition (12-14 -> 3-4), the fold (5-7 -> 2) and the drop (5 -> 1) -- ~20 ms -- and
the batches stay 23 ms each in two waves of 16, the leader's shape. The merge into one `BundleState` for the
published output (which the child's check and early execution read) is 45 ms on one thread beside the root:
longer than the root (35-38), so whether it pushes `fields_ready` or the child's vote later is the leg's
question. The follower's threads with it: the build pool (16) + the check pool (4), then the root pool (8, or
0 with `N42_FOLLOWER_ROOT_ON_BUILD_POOL=1`) + the merge thread beside the next block's 16. The fleet's 80-82
against the leader's 32-34 is still not explained by the bench (its batches are the leader's 23). loop287:
BASE / BP / BPR / BPb at the 1.25M offer.

### 10.31 The build path on the fleet (loop287): the follower's execution 82 -> 69-72, and the merge on the vote's chain

| leg | win1 | cycle (dissect) | B | D | follower exec (part / batches wall, count, max / median / merge) | road end / exec end / root end = fields | leader par_exec / sealed_at | win2 | imports > 600 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASE (first leg) | 1,149,978 | 131 | 54 | 37 | 99 (0 / 80, 263, 17 / 3 / 11) | 48 / 149 / 195 | 36 / 118 | 635k | 97 |
| BP | 1,124,178 | - | - | - | 71 (10 / 35, 30, 19 / 13 / 13) | 42 / 110 / 163 | 32 / 108 | 619k | 35 |
| BPR (root on the build pool) | 1,117,631 | - | - | - | 72 (10 / 36, 30, 20 / 13 / 13) | 39 / 111 / 155 | 33 / 113 | 706k | 37 |
| BPb | 1,117,075 | 139 | **106** | 5 | 69 (10 / 33, 30, 18 / 12 / 13) | 33 / 102 / 153 | 32 / 104 | **853k** | 23 |

The build path does what the bench said on the follower: the execution 82-99 -> 69-72 (the batches 33-36 wall,
30 of them at 12-13 median, the leader's shape), the fields ready at 153-163 instead of 169-195, a quarter of the
slow imports, and a much better second window (853k against 619-706k). But the first window fell 2-3% with the
cycle up 3-4 ms, and the dissection says why: **B (proposal -> quorum) 54 -> 106 while the leader's wait D
37 -> 5** -- the followers vote later. The vote on n+1 does not wait for n's fields (`parent_fields_wait` 0);
it waits for n's *published output*, which the child's includability check and early execution read, and on
the build path that output is the 45 ms single-threaded merge after the execution (10.30): the merge is on the
vote's chain. The fix is the leader's own: the child's check and execution read the parent's frozen shards
(as `ShardLayer` does for the chained build) and the merge is only for the engine's hand-off, off the chain.
Then the follower's chain is road 33 + exec 69 + root 38 = ~140 with nothing waiting on a merge, and the vote
lands at the road's end as in BASE (B ~55) with the fields 40 ms earlier than BASE's.

### 10.32 The check on the shards (loop288): 1,167,824; the follower's fields at 133-139; the leader's seal binds again

| leg | win1 | cycle | B | D | follower: road end / exec start / exec end / fields | exec (batches wall) / root | leader par_exec / sealed_at | win2 | imports > 600 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BP (first leg) | 1,019,331 | 160 | - | - | 31 / 24 / 103 / 155 | 75 (38) / 42 | 38 / 123 | 645k | 66 |
| BPb | **1,167,824** | 132 | 51 | 44 | 26 / 19 / 93 / 139 | 72 (35) / 41 | 33 / 114 | 803k | 25 |
| BASE | 1,143,003 | 142 | - | - | 38 / 42 / 125 / 170 | 81 (63) / 38 | 34 / 111 | 592k | 71 |
| BPR (root on the build pool) | 1,162,069 | 130 | - | - | 26 / 19 / 94 / 133 | 72 (35) / 34 | 34 / 113 | 722k | 45 |

With the child's check and execution on the parent's shards, B is back to 51 (106 in 10.31) and the build path
wins: 1,162-1,168k against BASE's 1,143k, the fields at 133-139 (BASE 170), the second window 722-803k against
592k. The follower's chain is now road 26 -> exec 19..93 -> root -> fields 133-139, under the cycle; **the
leader's seal binds again**: D (the leader's wait after the quorum) is 44 and the cycle 132 = `sealed_at` 114 +
~18. Inside the seal: start 15 (walk 8, hand-off 5), prep 4, exec 33 (two waves of ~17), commit 12 (body 6),
fold 24 (the index build 14 -- 1 ms on the bench, memory-bound on the fleet like everything else here -- and
10 around it), seal 7. Both flags (`N42_FOLLOWER_BUILD_PATH=1`, `N42_FOLLOWER_ROOT_ON_BUILD_POOL=1`) join the
bench line. Next: the leader's non-execution terms (start, fold, commit: 51 of the 114) and the follower's
execution overhead (exec 72 against batches 35: the partition 10, the fold 13, ~14 other).

### 10.33 The leader's terms and the follower's overhead, off the fleet (steps 6a and 5d)

A correction to 10.32's reading: `shard_fold_ms` (the index build, 14) is measured before the seal, between the
batches' join and the commit; `par_fold_ms` (24) starts after the commit and holds the work behind the seal
(the receipts job, `take_cached`, withdrawals, the fee commit). So the seal's own chain is start 15 + prep 4
+ exec 33 + index 14 + commit 12 + seal 7 = ~85 of the 114, and ~29 is elsewhere in the build's run.

Step 6a (e06753ec9..444387ada), bench: the parent's taken list is handed over whole when it matches the body
position by position (forget 3.9-4.4 -> 0.9-1.3 ms); `N42_OUTPUT_INDEX_LIVE=1` (off) enters each batch's
addresses into the shard indexes as the batch ends under per-shard `try_lock`s in rotated order, leaving the
freeze with the conflict sums (freeze 1.0-1.8 -> 0.5-0.6 on the bench, the append's pool time up 2-9 -> 9-21;
the fleet's 14 is where it should pay); the commit in two passes with the body read in the prep (4.9-5.9 ->
1.1-1.2, the prep +1.8); `next_start_gap_ms` / `next_entry_gap_ms` name the seal-to-next-start gap on the child's
line. (The bench had put every account in shard 0 -- `addr()`'s leading zero bytes -- and is fixed.)

Step 5d (057e8143e..832bf1f9e), bench: the build-path import's pieces named (`exec_setup/keys/pre/post/sink/
cached/residual/receipts/drop_ms`, `keys_ahead`); the keys in one parallel pass on the build pool, made ahead on
the road with `N42_FOLLOWER_PARTITION_AHEAD=1`; the executor's pre/post on the calling thread beside the batches,
the results in place (no 163k collect), the receipts beside the freeze; the root spawned at the execution's
return (`root_gap_ms`). The call 62-63 -> 56 with the keys ahead. loop289: A / LIVE / Ab / LIVEb.

### 10.34 Steps 6a and 5d on the fleet (loop289): 1,186,528; the seal 98-103, the follower's fields 107-118

| leg | win1 | cycle (dissect) | B | D | leader: start / prep / exec / index / commit / sealed_at | index append (pool) | follower: road end / exec / fields | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | 1,166,093 | - | - | - | 13 / 8 / 35 / 11 / 1 / 103 | 5 | 28 / 50 / 118 | 700k |
| LIVE | **1,186,528** | 125 | 39 | 55 | 14 / 9 / 38 / 3 / 1 / 98 | 52 | 26 / 44 / 107 | 760k |
| Ab | 1,181,815 | 127 | 46 | 49 | 14 / 10 / 33 / 12 / 1 / 103 | 7 | 26 / 49 / 113 | 760k |
| LIVEb (slow kind, gate 25 ms) | 1,112,102 | - | - | - | 13 / 9 / 41 / 3 / 1 / 99 | 49 | 29 / 47 / 118 | 711k |

The leader's commit 12 -> 1 (the body from the prep: prep 4 -> 8-10), the index 11-12 -> 3 with the live entry
(its append 5 -> 50 of pool time inside the execution: `par_exec` 35 -> 38-41, a wash on the seal), the seal
114 -> 98-103. The follower's execution 72 -> 44-50 and its fields 133 -> 107-118 (the keys ahead, the pieces
beside the batches, the root at the return). The whole hand-over never matched on the fleet (`queue_whole`
false on every block: the parent's taken list is not the body position by position there), and
`next_start_gap` is 0: the child starts at the parent's seal. **Neither chain is the cycle now**: the seal is
~100, the follower's fields ~110, and the cycle 125-127 (window 1,182-1,187k) with B 39-46 and D 49-55 -- the
leader waits ~50 after the quorum, and the pacing is 100. What the 25 between the seal and the cycle is (the
proposal after the seal, the view's turn, the pacing's rounding) needs the leader's own timeline: build start,
seal, proposal, quorum, next start, next seal, per block.

The leader's timeline (loop289 LIVE, 217 full blocks, medians / p75): build start -> seal 107 / 125; seal ->
proposal sent 90 / 111; proposal -> quorum 39 / 69; quorum -> next proposal 86 / 101; seal -> the next build's
start 2.8 / 9.7 (the chain is real). The last event before the proposal of n+1, of {its seal, n's quorum, the
pacing tick 100 ms after n's proposal}: **the pacing tick in 187 of 217 blocks**, the quorum in 23, the seal in
7; and the proposal follows the last event by 23 ms (p75 43). The cycle is 125 = the pacing 100 + the leader's
own 23-25 after the tick. So the chains are under the pacing and the pacing binds: 90, 80 and 70 ms next,
and the leader's 23 ms from the tick to the send after that.

### 10.35 The pacing followed down (loop290): nothing below 100

| leg | pacing | win1 | cycle | occupancy | queued / gate us | leader sealed_at / par_exec | follower: road end / exec / fields | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P90 | 90 | 1,157,927 | 140 | 99.4% | 807k / 22,072 | 98 / 41 | 29 / 47 / 117 | 771k |
| P80 | 80 | 1,126,904 | 142 | 98.2% | 824k / 22,830 | 96 / 39 | 28 / 44 / 113 | 313k (37% full) |
| P70 | 70 | 1,186,265 | 135 | 97.9% | 773k / 13,371 | 94 / 37 | 26 / 43 / 107 | 803k |
| P80b | 80 | 1,142,572 | 141 | 98.6% | 812k / 22,271 | 97 / 40 | 28 / 45 / 113 | 739k |

Below 100 the cycle does not follow the pacing (135-142 against 125 at 100) and the window stays 1,127-1,186k
(P70 ties the record with 98% occupancy): as 10.18 read it, a proposal made before the followers have the parent's
fields only lengthens B, and the followers' fields are ready at 107-117 after the road's start -- the follower's
chain (road 26-29, execution 43-47, root 33-35, ~15 of gaps) is the floor under the pacing, with the leader's
seal at 94-98 beside it. The queue sits at the gate line again at 80-90 (807-824k, the gate 22 ms) and P80's
second window collapsed to 37% full blocks. So the pacing stays at 100 and the terms are the two chains'
overheads: the leader's tick-to-send (step 6b, in flight), and the follower's road (26-29 for what the design
priced at ~5) and the gaps between its execution's end, its root and its fields.

### 10.36 The leader's tick-to-send and the follower's road, off the fleet (steps 6b and 5e)

Step 6b (825edb99d..37e3a8709): the 23 ms from the pacing tick to the proposal's send, read from loop289's
leader: the late wake 5.6 (a 10 ms retry poll where the tick should have been a `sleep_until`), the wait for
the build ahead ~4 (the seal late in a few blocks), the sign 7 (the BLS header seal plus a clone of the 163k
payload), the cache copy 2, the body encode 6 (26 MB of RLP for a 12.5 KB description and the body store); and
after the body is prepared, the vote log's fsync (8 median, kept: safety) and the proposal's wait for the
step's drain behind the next build request. The cuts: the leader sleeps until the tick itself; the proposal is
published the moment the engine makes it; a build ahead is sealed, cached and encoded in its own task before
the tick (taken only if view and hash match). A "proposal sent" line names the parts. Expected tick-to-send
~2-3 plus the vote sync.

Step 5e (0030ff71d..f1ada820f): the road's `check_ms` 14 is entirely `check_includable` -- a scan of every
transaction (chain id, fee caps, intrinsic gas, nonce runs, costs) in 32 chunks on the 4-thread check pool,
then a per-sender fold and each sender's total against the parent's shards. With `N42_FOLLOWER_FRAME_SCAN=1`
the ingest sums each clean frame once (gas, smallest fee cap, chain id, sender runs with nonces and costs,
~40 us a frame on the supply side) and the check reads the summary for every frame the block took whole. The
root's thread starts with the execution (its spawn and its wait for the parent's fields overlap the batches),
and the header/body consensus checks move onto the road beside the execution. The copy (8) stays on the road:
the build-path execution reads the owned block, not the frames' Arcs. loop291: P100 / P100S / P90S / P100Sb.

### 10.37 Steps 6b and 5e on the fleet (loop291): 1,211,401; tick-to-send 4.5 ms; the check 4 -> 0

| leg | win1 | cycle (dissect) | B | D | leader sealed_at | tick-to-send (us): late / preamble / take / sign / publish / total, presealed, tick-bound | follower: road end / check / exec / fields | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P100 | **1,211,401** | 128 | 46 | 53 | 102 | 576 / 444 / 7 / 1,123 / 783 / **4,480**, 1,021 of 1,023, 760 | 27 / 4 / 46 / 110 | 825k |
| P100S (frame scan) | 1,205,773 | - | - | - | 106 | - | 21 / 0 / 43 / 106 | 835k |
| P90S | 1,190,504 | - | - | - | 110 | - | 21 / 0 / 44 / 107 | 847k |
| P100Sb (slow kind, gate 22 ms) | 1,114,514 | - | - | - | 116 | - | 25 / 0 / 46 / 115 | 787k |

The leader's tick-to-send is 4.5 ms (23 in 10.34): the wake 0.6 late, the build presealed in 1,021 of 1,023
views, the sign 1.1, the publish 0.8. The follower's check is 0 with the frame summaries (326 of 326 frames
summarized; 4 without, 14 before 5e's split named it), the road's end 27 -> 21, the fields 106-110. The
window is 1,206-1,211k with the second window at 825-847k. But the cycle is still 128-135 with D 53: the tick
binds in 760 of 1,023 views yet the cycle is not the pacing plus 4.5 -- the tick is `block_seen[head]` + 100,
measured from when the leader saw its own head, not from the previous proposal's send, so the interval carries
B inside it. That is the next thing to read and set: the pacing from the send, or the pacing lowered to
match (loop290's 70-90 were before 6b).

The tick's origin, read: `block_seen[head]` is set in `remember_block` right after the leader's `build_block_on`
returns, 0.8 ms before the send, and in the 760 tick-bound views the tick fell 99.2 ms after the previous
send -- the pacing already counts from the send (the `N42_PACING_FROM_SEND` flag changes 0.8 ms and is not
taken). The 128 is the tail: send-to-send is a median 103 in the tick-bound views and 163 in the other 261,
where the tick arrived before the leader's own block had sealed (`take_sealed_us` 70-240 ms), and `publish_us`
spikes to 18-26 on the vote log's fsync. No follower-side constraint refuses an early proposal (the header's
timestamp is the parent's plus the period in whole seconds; `baseTimeout` is the view timeout). So the term
is the seal chain's tail, not the tick: which phase inflates in the slow quarter of builds is the next read.

### 10.38 The seal chain's tail (loop291 P100): waits, not work

`sealed_at` over the leg's 737 full builds: p25 83, median 102, p75 128, p90 153, max 906; 167 over 130. The
slow builds (>130) against the rest, medians: `state_wait` 0 -> 49, `par_run` 44 -> 96, `par_ms` 89 -> 144;
the execution +5, the index ±5, the start, the walk and the commit unchanged. The worst: block 925 (906 ms)
is 74% `parent_fields` (670), block 1014 (692) 87% `parent_fields` (601), block 804 (436) 78% `state_wait`
(341) -- and the validator's log before 925 and 1014 reads "own block imported by header round_trip_ms=1003"
and "commit forkchoice ... outcome=Syncing ... waits for its import": the leader's own block took a second to
enter its engine, and the child build waited for the parent's fields. The slow builds are scattered (gaps 7-72
blocks, no period, no persistence batch, one TC in the run at view 1); the followers' `fields_ready` is p25 97,
median 105-108, p75 120-126, p90 157-175, and their worst blocks are the leader's (925, 1014). **The tail is a
wait on the previous block -- its own-import round trip through the engine and its state's readiness -- not
execution, indexing or a periodic job.** Removing it is worth what the median says: the tick-bound views
already run at 103 (1.58M/s of 163k blocks) against the leg's 128 average.

Defect 22, read and fixed (198114f5f): view 925's timeline -- the seal at 0, "Canonical chain committed 923" at
+4 takes the QMDB forest lock in `on_canonical`, the root job for 924 queues behind it, the proposal goes out
at +23, the quorum at +148, the forkchoice at +152 answers Syncing, the root is published at ~+940
(`roots_ms` 975), the child seals at +939 with `parent_fields` 670, the own block reaches the engine at +1,019,
"imported by header" at +1,029 (`round_trip_ms` 1,003). The forest keeps block records for the read view and
moves that keep once per persistence batch (the view lags 30-50 blocks), so the first `set_canonical` after a
batch dropped 28-44 blocks of records -- 163,000 ops each, one allocation a value, plus thousands of 128 KiB
twig trees -- and freed them under the lock: 374 ms to free (0.1 ms under the lock once handed out). The fix
hands the dropped records back and frees them on a release thread after the lock. `state_wait_on=` names the
child's wait (block 804's 341 is not this lock). loop292: three P100 legs and a P90.
