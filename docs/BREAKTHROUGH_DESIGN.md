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

### 10.39 Defect 22's fix on the fleet (loop292): worse -- the freeing moved, it did not shrink

| leg | win1 | cycle | sealed_at median / p90 / over 130 | QMDB releases | follower fields | imports > 600 ms | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P100 | 1,075,288 | 151 | 121 / 224 / 507 | 290 | 119 | 54 | 646k |
| P100b | 964,222 | 168 | 114 / 200 / 430 | 306 | 116 | 43 | 830k |
| P100c | 1,195,725 | 135 | 108 / 174 / 358 | 332 | 108 | 34 | 814k |
| P90 | 1,200,457 | 135 | 110 / 177 / 355 | 338 | 108 | 39 | 818k |

Against loop291 (seal 102 / p90 153 / 167 over 130, 1,211k): the release fires 290-338 times a leg -- every
three blocks, not once per batch -- and the seal's tail widened (p90 174-224, 355-507 builds over 130) with
the legs erratic (964k to 1,200k). Freeing 163,000 one-per-value allocations a block (13 ms of `free` per
block, 374 ms per 28) on a side thread beside sixteen build threads allocating is a contest for the allocator
and the memory system; under the lock it was a burst every ~44 blocks, off the lock it is continuous. The
fix is not where the freeing happens but that there is freeing: a block's records in one allocation (the
values in one arena `Vec<u8>` with offsets, the twig trees pooled), so a head move drops a block in O(1).

### 10.40 Defect 22b on the fleet (loop293): 1,226,047; the median seal back to 96-100; the tail is the grandparent

| leg | win1 | cycle | sealed_at median / p90 / over 130 | roots | QMDB releases | follower fields | imports > 600 ms | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P100 | **1,226,047** | 132 | 100 / 157 / 285 | 34 | 340 | 102 | 27 | 840k |
| P100b | 1,193,030 | 136 | 96 / 166 / 257 | 30-33 | 321 | 107 | 30 | 558k (79% full) |
| P100c (slow kind, gate 22 ms) | 1,102,965 | 146 | 108 / 196 / 418 | 35 | 337 | 115 | 46 | 776k |
| P90 | 1,210,589 | 131 | 104 / 164 / 324 | 33 | 336 | 103 | 25 | 874k |

With a block's records in one arena the free is nothing (the releases still fire every three blocks, now for
0.3 ms), the roots are 30-35, the median seal 96-104 and the window 1,226k. The tail stayed: in P100, 161 of
741 builds sealed after 130, and against the rest they differ in one field -- `state_wait` 0 -> 49 (`par_run`
45 -> 98; the execution +6, the batch +4, nothing else) -- and `state_wait_split` says which wait: **the
grandparent**, 16-35 ms in 22% of builds (out/gp/root/complete = 0/16-35/0/0). The chained child opens on the
parent's shards under the parent's residual and then the grandparent *as an executed block in the engine*
(`grandparent_state`), and the grandparent's hand-off to the engine comes after its `Complete` (the merge, the
hashed state) and through the engine's own loop -- sometimes not yet there 100 ms after the parent's seal.
The follower already keeps two generations of shards for this (`FOLLOWER_SHARDS`); the leader's opener should
read the grandparent's frozen shards the same way and touch the engine only from the great-grandparent down.

### 10.41 The grandparent from its shards (loop294): the seal's median 90, its wait gone; the cycle's mean still 135

| leg | win1 | cycle mean / median (w1) | sealed_at median / p90 / over 130 | state_wait_split (top) | gp_layer / ggp_missing | follower fields | imports > 600 ms | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P100 | 1,206,763 | 135 / 116 | 90 / 128 / 111 | 0/0/0/0 x1,179 | 1,176 / 8 | 104 | 26 | 863k |
| P100b (slow kind, gate 21 ms) | 1,113,333 | 144 / 125 | 91 / 169 / 206 | 0/0/0/0 x1,175 | 1,175 / 10 | 114 | 58 | 825k |
| P100c | 1,190,786 | 136 / 119 | 90 / 160 / 170 | 0/0/0/0 x1,168 | 1,166 / 23 | 104 | 39 | 798k |
| P90 | 1,196,395 | 135 / 118 | 91 / 164 / 182 | 0/0/0/0 x1,170 | 1,170 / 14 | 106 | 44 | 722k |

The child reads its grandparent from the kept shards in 1,166-1,176 of ~1,180 builds (8-23 fell back to the
engine), the state wait is 0 in all but two or three builds a leg, the seal's median is 90 (100 before) and its
tail narrowed (over 130: 111-206 against 257-418). The window did not follow (1,113-1,207k against 1,226k):
the cycle's median in window 1 is 116-119 but its mean 135-136, and the seal's tail no longer explains the
gap -- the followers' do: 26-58 imports over 600 ms a leg, each a half-second hole in the votes. What those
imports wait on (10.18 read the slow tail as an unnamed residual under overlap; since then the build path, the
early root, the shards and the frame scan changed the import) is the next read, on the follower's
`build-path import` line and its timeline keys.

### 10.42 The followers' slow imports (loop294 P100): rare second-long roots, cascading

Follower imports (`total_ms`): node1 p25 108, median 127, p75 156, p90 293, p99 446, max 1,505 (67 over 300,
2 over 600); node2 median 131, p90 273, p99 583, max 1,352 (100 / 11). `fields_ready`: median 103, p90
140-150, p99 316-493, max 1,150-1,517. The slow imports (>300) against the rest: the fields only +10-15, the
execution +8-9, the batch +6-8, every named wait 0 -- and ~190 ms of the total that no field names (the
named sum 173-193 against a total 362-365): the hand-off after the fields (the merge, the engine insert, the
persistence), off the vote. They do not cluster across the followers (2 of 20 shared) nor with the leader's slow
seals (0-3 of 20), and 4 of 5 have nothing else in the log around them. The vote's delay after a slow parent
import is +24 ms median (43 against 19). **The cycle's tail is the rare cascade**: node1's block 1007 took
1,505 with `root_ms` 1,034, so 1008 waited 917 for its parent's fields and the vote came 935 late -- a few
second-long roots a leg (the leader had them too: 10.38's `roots_ms` 975) each costing the cycle a block or
more, which is the mean's 135 against the median's 116. What holds a root for a second when the records are
no longer freed under the forest lock is the next read: the lock's other holders (the head move itself, the
journal hold, the read view's advance, the persistence batch) timed and named.

Defect 24, read (28f0a5076): the slow roots land on the same blocks on every node -- 834, 877, 921, 964, 1007,
1051, ... -- a period of ~44 blocks, and what repeats every 44 blocks is the entry file sealing a 256 MiB chunk
inside the block's own append, under the forest lock: the append that crossed the chunk first doubled the write
buffer (a 256 MiB copy into 512 MiB of fresh pages, under direct compaction), then wrote the pending bytes and
mapped the chunk with `MAP_POPULATE` (65,536 page faults, read back from disk once the reclaim storm has dropped
them). The fix reserves the buffer once at the chunk size and seals before the record that would not fit, and
maps a chunk sealed while the tree grows without populate, faulting it in by `MADV_POPULATE_READ` on its own
thread. Every forest-lock acquisition is now labelled and timed (WARN over 20 ms held or waited), and the root
split named (`root_lock_wait_ms root_lock_held_by root_move_ms root_apply_ms root_hash_ms root_publish_ms
root_faults root_majflt root_twig_pool_misses root_seals root_seal_ms`). Still able to hold a root over 50 ms:
the offsets/twigs `Vec`s doubling under the lock (1-2 GB copies, once or twice a leg), `move_to` off the
parent, writeback stalls on the seal, page-cache misses on entry keys, the follower's one-root-at-a-time
cascade. loop295 measures.

### 10.43 Defect 24 on the fleet (loop295): the seals 2-3 ms, the slow imports a quarter; the cycle's mean still 133-135

| leg | win1 | cycle mean / median (w1) | sealed_at median / p90 / over 130 | roots median / p90 | root seals (count, ms) | forest-lock WARNs | imports > 600 ms | follower fields | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P100 | 1,196,934 | 135 / 116 | 89 / 130 / 115 | 34 / 60 | 81, 3 | 3,879 | 15 | 103 | 841k |
| P100b | 1,203,637 | 134 / 117 | 90 / 131 / 118 | 33-34 / 61 | 78, 2 | 4,194 | 15 | 106 | 879k |
| P100c | 1,223,578 | 133 / 118 | 91 / 124 / 102 | 34 / 57 | 80, 2 | 3,601 | 12 | 102 | 847k |
| P90 | 1,119,735 | 144 / 133 | 91 / 152 / 182 | 35 / 76 | 78, 3 | 4,991 | 6 | 110 | 830k |

The chunk seals are 2-3 ms now (78-81 a leg), the imports over 600 ms fell from 26-58 to 6-15, the seal's
p90 to 124-131 and the roots' p90 to 57-61; the windows are 1,197-1,224k at pacing 100 (the record 1,226k
stands, within the noise). The lock's holders, named: `insert_block_operations` holds the forest lock 21-26 ms
on every block -- the root's apply runs under it -- and `compute_operations` 21-23; 3,600-5,000 WARNs a leg
are those two at their normal length, so the threshold is under the normal hold and the apply is the lock's
occupant: anything else that needs the forest (a head move, a persistence step, the other side's root on the
same node) waits behind ~22 ms of apply. The cycle's mean (133-135) against its median (116-118) is still
16%: with the seal's and the imports' tails both cut, what is late in the slow cycles has to be read from the
cycle itself -- per block, which of the leader's seal, the followers' fields or the vote's transit is late.

### 10.44 The slow cycles read (loop295 P100c): two chains' variance against a 100 ms pacing

Window 1's cycle: p25 103.5, median 120, p75 157, p90 177, p99 250, max 337; 67 of 221 over 150. The slow
cycles are two classes of near-equal weight: (a) the tick came and the leader's own block was not sealed
(`take_sealed_us` 77-108 ms in those views: the seal chain's p75-p90 is over the pacing), and (b) the quorum
ran long (B 82 median, up to 253) because one follower's vote waited -- its vote delay tracks how far behind
its import pipeline is (r = 0.65), and the followers are systematically 164-205 ms behind on *finishing* the
parent's import when the new body arrives (the fields come earlier, at ~103, but their tail does not). Forest
lock holds, QMDB releases and TCs appear near 5 of the 15 slowest and do not scale with the cycle. **The tail
is the variance of two ~95-105 ms chains against a 100 ms pacing**: the median fits, the p75 does not. The
cheap experiment first: the pacing at 110-120 so both chains' p90 fit under it (loop290's 70-90 were the
other direction, before the chains were cut) -- a flat cycle of ~120 would beat a 120-median with a 133 mean.

### 10.45 The pacing above the chains (loop296): the mean cycle does not move

| leg | pacing | win1 | cycle mean / median (w1) | sealed_at median / p90 / over 130 | follower fields | imports > 600 ms | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P110 | 110 | 1,180,745 | 138 / 115 | 89 / 126 / 106 | 104 | 8 | 837k |
| P115 (slow kind, gate 20 ms) | 115 | 1,118,422 | 146 / 128 | 88 / 150 / 162 | 110 | 11 | 831k |
| P120 | 120 | 1,188,835 | 137 / 123 | 87 / 120 / 88 | 103 | 3 | 873k |
| P110b | 110 | 1,195,908 | 136 / 115 | 89 / 124 / 97 | 102 | 12 | 825k |

From 100 to 120 the median cycle follows the pacing (115 -> 123) and the mean does not (136-138): at 120 both
chains' p90 fit under the pacing (the seal's p90 120, the fields' 103) and the mean is still 14 over the
median. The window is 1,181-1,196k at every pacing: the fleet consumes 163k every ~136 ms whatever the tick
says, and the remaining tail is thinner than the seal's or the fields'. The per-block terms are now the
leader's seal (87-91: exec 38-40, start 13, prep 9, index 3, commit 1, seal 7) and the followers' fields
(102-104: road 21, exec 44, root 33), both memory-bound in their execution and root, and the fixed costs
around them (the road, the tick, the transit, the vote, B's 25). **Section 6 is the step left in the order**:
larger blocks amortise the fixed costs and the chains' tails -- `--gasceil` sets the genesis gas limit, so
250k-transaction blocks (5.25 G gas) at a ~140 ms cycle would be 1.8M/s if the supply and the memory-bound
terms scale (they are linear in the accounts touched: 10.14, `docs/BLOCK_SHAPE_SURVEY.md`).

### 10.46 Larger blocks (loop297): the fleet reads 1.16-1.19M whatever the block, because the supply is ~1.2M/s

| leg | block | offer | pacing | win1 | cycle mean / median | occupancy / full | queued | leader sealed_at / par_exec / roots | follower fields / exec / root | win2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G200 | 200k | 1.6M | 115 | 1,165,292 | 168 / 156 | 97.4% / 157 of 179 | 738k | 109 / 49 / 41 | 133 / 56 / 41 | 839k |
| G250 | 250k | 1.9M | 130 | 1,193,146 | 176 / 153 | 84.1% / 83 of 170 | 697k | 132 / 60 / 44-49 | 158 / 71 / 48 | 790k |
| G250b | 250k | 1.9M | 130 | 1,165,283 | 185 / 162 | 86.2% / 83 of 162 | 708k | 133 / 62 / 46-50 | 164 / 73 / 49 | 849k |
| G300 | 300k | 2.2M | 150 | 1,161,436 | 192 / 155 | 74.1% / 48 of 156 | 678k | 135 / 52 / 41-62 | 182 / 80 / 57 | 889k |

The chains scale as the shape survey said (the leader's execution 39 -> 49 / 60 / 52, the seal 89 -> 109 /
132 / 135; the followers' fields 103 -> 133 / 158 / 182), the blocks are not full (84-86% at 250k, 74% at
300k, the queue under the gate line at 678-738k) and the window is 1,161-1,193k in every leg: **the fleet
consumes what the flood delivers, ~1.2M/s, and the flood is the wall** -- its generation (Ed25519 signing on
its 17 cores, ~70k signatures a second a core) tops out where the fleet now is. The pre-generated set
(`/data/n42-pregen/o900000`, 192M transactions, made for this in 10.x when the generator was reply-bound and
not yet the term) is the next leg: replay at 1.6-1.9M with 200-250k blocks.

loop298 did not run: the flood refuses to replay a set made for other arguments -- `o900000` was generated
before the attested frames (no gateway key), and the attestation is baked into a set's frames. A set with the
gateway key (`g900000`) is generated first in loop299's launcher, then the same four legs.

loop299 (the replay set `g900000`: 192M attested frames, generated in 26 s at 7.3M/s) ran with a broken
runner -- the gas ceiling and the rate cap were lost in the leg lines -- so it read the replay at 163k blocks
with no rate limit: 1,114-1,171k with the queue at the gate line (840-852k) and the gate holding 21-25 ms;
the set ran out before the leg ended. Two things it still says: the attested replay works (384,000 frames
attested, 0 bad), and beyond ~1.2M/s the 163k block's cycle is the wall, not the supply -- an unlimited
supply changed nothing at 163k. loop300 repeats the larger blocks with the replay capped at the offer.

### 10.47 The replay at larger blocks (loop300): the chains scale with the block, the window does not move

| leg | block | offer (replay) | pacing | win1 | cycle mean / median | occupancy | queued | leader sealed_at / p90 / par_exec / roots | follower fields / exec / root | imports > 600 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R250 | 250k | 1.9M | 130 | 1,128,966 | 204 / 186 | 91.5% | 772k | 134 / 209 / 63 / 48-49 | 165 / 71 / 50 | 34 |
| R250b | 250k | 1.9M | 130 | 1,181,951 | 196 / 179 | 92.7% | 763k | 136 / 209 / 62 / 47-48 | 158 / 71 / 48 | 27 |
| R200 | 200k | 1.7M | 115 | 1,199,143 | 165 / 149 | 98.3% | 810k | 109 / 168 / 48 / 40 | 126 / 55 / 39 | 17 |
| R300 | 300k | 2.2M | 150 | 1,191,038 | 205 / 175 | 81.6% | 731k | 145 / 193 / 54 / 43-58 | 177 / 78 / 57 | 6 |

With the attested replay the supply is whatever is asked (384,000 frames attested a leg, the set ran out only
at the end), and the larger blocks still read 1,129-1,199k: **the chains scale with the block** -- the
leader's seal 89 -> 109 / 135 / 145 and the followers' fields 103 -> 126 / 160 / 177 for 163k -> 200k / 250k
/ 300k -- and the cycle with them (median 149 / 180 / 175, mean 165 / 200 / 205), so the transactions a second
stay where they are. The per-transaction chain cost is ~0.55-0.6 us on either side (execution + root +
index, all memory-bound per account, 10.14 / 10.21) and the fixed costs around a block are already small
(the road 21, the tick 4.5, B's transit ~7), so a bigger block buys nothing and a smaller cycle needs a
cheaper account. **This is the memory-bound plateau of the present design on this box, ~1.2M/s**; the
next terms are (a) the memory parallelism -- the build pool's 16 threads run the batches in two waves with
CPU equal to wall (memory latency), and a node has 37 physical cores: 24-32 threads on the pool and the
root is the cheap experiment; (b) design B (section 4: dense account ids, flat tables) for the bytes each
account costs; (c) the tails (the cycle's mean over its median, 10.44).

### 10.48 The memory parallelism (loop301): 24-32 threads cut both chains; the window stays; the root's faults are the tail

| leg | build threads | win1 | cycle mean / median | leader par_exec / batch max / median / sealed_at / p90 | roots median / p90 | follower exec / fields | imports > 600 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T16 | 16 | 1,175,174 | 138 / 118 | 41 / 22-23 / 15 / 92 / 149 | 34 / 72 | 47 / 111 | 22 |
| T24 | 24 | 1,165,804 | 139 / 127 | 35 / 19-20 / 11 / 85 / 153 | 35 / 76 | 40 / 101 | 13 |
| T32 | 32 | 1,180,070 | 137 / 122 | 34 / 23 / 12-13 / 85 / 147 | 35 / 73 | 40 / 100 | 5 |
| T32b | 32 | 1,182,703 | 137 / 121 | 33 / 22 / 12-13 / 84 / 137 | 34 / 61 | 39 / 96 | 9 |

More threads do what memory latency predicts: the execution 41 -> 33-35 on the leader and 47 -> 39-40 on the
follower, the seal 92 -> 84-85, the fields 111 -> 96-100 -- and the window stays at 1,166-1,183k with the
cycle's mean 137-139. The medians are now 15-20 under the pacing; the tail is the whole term. On T32b the
slow seals (105 of 746, over 120) differ from the rest in `parent_fields` 0 -> 47 and `sealed` 7 -> 56: the
child's seal waits for the parent's state root, and the parent's root is slow one time in seven (`roots_ms`
32 -> 66 in 109 of 746) with **`root_apply` 17 -> 28 and `root_faults` 276 -> 1,923**: page faults during the
apply. The twig pool misses 79 times a block even on the fast roots (fresh 128 KiB trees, 32 pages each; the
pool refills only at a head move), and the entry file's append touches fresh pages; a slow root is one where
those faults are expensive (the reclaim storm, 4 KB fallbacks). The tail's fix is to fault nothing on the root's
thread: the twig pool topped up ahead on the release thread, the entry file's append region populated ahead of
the cursor. The leader's per-block chain is then ~84 flat and the followers' ~96, both under the pacing, and the
cycle would follow the tick (~105: 1.55M/s) instead of its tail.

Defect 25, read and fixed off the fleet (5ce67ed06..081e0183d): the root's faults were the structural writes --
the leaves into fresh 128 KiB twig trees (79-80 pool misses a block for 30 of every 44 blocks: the pool refilled
only at a batch's head move), the undo record's lists (5.2 + 1.3 MB) doubling into returned pages, the offsets
`Vec` doubling (17-38 ms applies with few faults), the append buffer while the first chunk fills. A prefault
thread keeps a pool of pre-touched twig trees at a floor (512) and recycles the undo lists; the append buffer
is populated 32 MiB ahead of the cursor; the offsets grow by pre-touched 8 MiB segments; the key index's shards
grow on the pool. The bench (200 blocks of 163k on jemalloc): the apply 8.5 / 9.6 / 38 -> 7.3 / 7.9 / 11 ms
(median / p90 / max), faults 12 / 1,900 / 3,000 -> 0 / 2-7 / 640-1,900, blocks over 50 faults 81-86 -> 3-6 of
180. loop302: three P100 legs and a P90 with 32 build threads.

### 10.49 Defect 25 on the fleet (loop302): the median root faults nothing; one root in five still faults its append

| leg | win1 | cycle mean / median | roots median / p90 | root faults median / p90 | append faults | twig misses | sealed_at / p90 | follower fields | imports > 600 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F100 (slow kind, gate 22 ms) | 1,088,945 | 149 / 136 | 32 / 67 | 17 / 1,610 | 11 | 0 | 84 / 148 | 103 | 15 |
| F100b | 1,166,082 | 140 / 132 | 32 / 59 | 11 / 1,553 | 6 | 0 | 83 / 131 | 95 | 7 |
| F100c | 1,121,981 | 145 / 136 | 33 / 71 | 23 / 1,866 | 7 | 0 | 87 / 156 | 101 | 19 |
| F90 | 1,171,063 | 138 / 127 | 32-33 / 70 | 12 / 1,569 | 5 | 0 | 84 / 135 | 97 | 2 |

The twig pool never misses and the median root faults 11-23 times, but the p90 is 1,550-1,870: on F100b, 148 of
750 roots fault ~1,456 times, 1,070 of them in the append (`root_append_faults` 7 -> 1,070), and those roots
take 44 against 31 (`root_apply` 15 -> 20). ~1,070 faults is a block's entries (163k x ~26 bytes = 4.2 MB of
4 KiB pages): in those blocks the append region was not populated ahead -- the faulting blocks come in bursts
(gaps of 1-2 blocks), which reads as the populate falling behind: it shares a thread with the twig refills
(80 trees a block) and the undo lists' cleaning, and after a chunk seal the window starts again. The fix is
the populate on its own thread with a wider margin (populate 64 MiB when under 32 MiB remain, before the
append, never after), and a counter for "the append ran past the populated window". The windows (1,089-1,171k)
are within the noise of the plateau; the cycle's mean 138-149 is the tail as before.

The follow-up (9a384bed4): the append buffer is anonymous heap memory (a 256 MiB jemalloc `Vec` reused for every
chunk) and the populate never restarts after the first chunk -- so ~1,070 faults in a root after block 44 mean
the pages were *taken back*, not outrun. **The host's swap is full** (`/swap.img` 8 GB, 116 KiB free, swappiness
60; the "swap empty" host rule of the campaign is broken), so anonymous pages are swapped out under the thp:always
heaps' pressure and a swap-cache hit is a minor fault -- which fits `root_majflt` 0 and the bursts without a
period. `mlock` is out (`ulimit -l` 8 MiB). The populate now runs on its own thread with a 64 MiB window, and
`root_append_behind` / `populate_lag_mb` on the root lines tell "outrun" from "taken back" (behind 0 with
append faults = taken back). The swap needs emptying on the host (`swapoff -a`, root) before the next legs are
comparable to the plateau's.

### 10.50 The pages are taken back (loop303): the append never outruns the populate; the host's swap is the tail

| leg | win1 | cycle mean / median | root faults median / p90 | append faults | append behind / populate lag MB | roots median / p90 | sealed_at / p90 / over 130 | swap used |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F100 | 1,148,746 | 142 / 125 | 13 / 1,561 | 7 | 0 / 0 | 32-33 / 62 | 84 / 150 / 155 | 7 G |
| F100b | 1,121,363 | 145 / 138 | 18 / 1,709 | 7 | 0 / 0 | 33 / 62 | 83 / 134 / 128 | 7 G |
| F100c | 1,162,787 | 140 / 128 | 36 / 1,728 | 5 | 0 / 4 | 34 / 63 | 84 / 138 / 140 | 7 G |
| F90 | 1,136,075 | 143 / 129 | 235 / 1,973 | 7 | 0 / 0 | 34 / 64 | 89 / 167 / 214 | 7 G |

`root_append_behind` is 0 on every root and the populate's lag 0-4 MB: the append never writes past the
populated window, and the root's p90 still faults 1,560-1,970 times. The pages are taken back between the
populate and the append: the host's swap is full (7 of 8 GB used through all four legs), so anonymous pages
are the reclaim's prey. **The tail of the root -- and with it the seal's and the cycle's -- is the host's
memory state, not the code's**; the runs since the swap filled (which of the campaign's legs it was is not
known -- the counters only started reading it here) are all under it. The next legs need the swap emptied on
the host (`swapoff -a`) and the "swap empty" rule enforced in the launcher's quiet check (a leg with used swap
is void, like one with a small huge-page pool).

### 10.51 Design B, stages 1-2 off the fleet (branch `designB/dense-ids`): falsified on the bench

Stage 1 (a node-local id table: 64 shards, id = position << 6 | shard, ids resolved at admission and carried
by the frames, `N42_DENSE_IDS=1`): a held id resolves in 216-222 ns on 16 threads (50-84 alone), a new one in
1.15-1.32 us including the table's growth -- all on the ingest's threads, 0 on the chain; 2.006M ids and ~110
MB after 1,000 blocks of this flood. Stage 2 (each batch keeps its accounts by first touch; a process-wide
claims table indexed by id, one `AtomicU64` an id claimed by CAS, is the block's account -> batch index, built
during the execution; the 6,119 accounts another batch claimed, the beneficiary and id-less accounts in a small
map) gives bundles identical to the address path. On `bench_build_real_path` (163k transfers, 16 threads, 10
rounds): `par_exec` 11-17 -> 12-22, the batch max / median 6-11 / 5-6 -> 6-15 / 5-7, the read a transfer
778-805 -> 764-777 ns, the close 96-155 -> 191-358 (the address map built at the close costs more than the
probes it saves). **The batch max did not fall at all; the plan is falsified on the bench** -- its read is
one QMDB view read a transfer (the fresh recipient), which no id removes, and the map probes the design
targets are a small share. The fleet's reads are mostly the batch's own map and the parent's index (10.25),
so a fleet leg with the ids wired into the builder (not done: `payload.rs` and the follower path do not pass
the frames' ids) could still read differently; but the per-account term is the account's own cache lines,
which an index does not touch. The branch stays unmerged (its last commit, the beneficiary fast path, is
uncompiled). Where the campaign stands: the plateau of ~1.2M/s is the memory system's per-account cost on
three nodes of this box, and the tail is the host's swap (10.50).

### 10.52 Steps 7a and 7b, off the fleet: the leader's start and prep, the follower's copy aside

7a (c2a9a9138..69918dfc5): the seal-chain gaps named (`gap_before_exec_ms`, `gap_after_exec_ms`,
`gap_before_seal_ms`, `index_ms`; the hand-off's `queue_taken_len` / `queue_first_miss` to read why the whole
hand-over never matched); the prep's keys straight into a Vec (1.3-2.2 -> 0.36-0.47 ms), the sender partition
skipping the hash within a sender run (1.3-1.7 -> 0.8-1.3), the frame plan's hashes by reference (the walk's 5 MB
copy gone: 1.4-2.2 -> 0.95-1.3 beside the 2.7-4.3 check), the result slots (~75 MB) made on the pool (the call's
entry to the batches' start 5.4-5.9 -> 2.4-3.2; the whole call 19-21 -> 16-17). The plan-ahead cursor (the 3
ms check) and the lock-free hand-off are not done. Expected on the fleet: start -1, prep -1..2, the gap before
the execution -3..4.

7b (52734209a, 73441a6e3): the follower's build-path execution runs on the described block's transactions by
reference (a `BuildPathTx` seam over the queue's Arcs) and `N42_FOLLOWER_COPY_ASIDE=1` builds the owned block
beside the import, the road and the post-execution waiting for it only where they read it: the execution starts
0.1 ms after the frames' take (3.7 before, on the bench). The vote still needs the owned block for the
pre-execution, seal and includability checks, so the road's end is expected ~11-14 (21-24 now), the fields
~82-85. Both wait for the host's swap to be emptied (loop304, then loop305 with the copy aside).

### 10.53 The swap off, steps 7a and 7b on the fleet (loop305): the swap reading is falsified; the proposal waits for the pacing tick

Tip a944a2e8b (steps 7a and 7b, five bug fixes), the host's swap empty (`swap_used_g=0`), 100 ms pacing, three nodes. C and Cb run
`N42_FOLLOWER_COPY_ASIDE=1`. Stage columns are the median / p90 of the leader's (node0) full blocks of the whole leg (~750 blocks) and of
the followers' direct imports of the same blocks; `root faults` and the dissection below read the same blocks (the dissection, window 1 only).

| leg | win1 | cycle mean / median | leader: start / prep / exec / sealed_at / p90 | follower: road end / exec start / fields | root faults median / p90 | win2 |
| --- | --- | --- | --- | --- | --- | --- |
| A | 1,165,684 | 139 / 127 | 11 / 6 / 29 / 75 / 129 | 22 / 22 / 91 | 15 / 1,570 | 830,154 |
| C | 1,159,095 | 140 / 133 | 12 / 6 / 29 / 76 / 101 | 28 / 10 / 81 | 8 / 1,113 | 874,685 |
| Cb | 1,172,189 | 138 / 130 | 12 / 6 / 30 / 77 / 105 | 28 / 11 / 82 | 7 / 1,045 | 911,128 |
| Ab | 1,171,357 | 139 / 131 | 11 / 6 / 29 / 75 / 120 | 22 / 22 / 91 | 13 / 1,548 | 836,687 |

The record stays 1,226,047 (loop293); the four win1 values are within 1.1% of each other, inside the 4% spread of one configuration. 7a
moved the seal median 84 -> 75-77 (the start, prep and execution read 11-12 / 6 / 29-30). 7b did what it was built for on the execution
start (22 -> 10-11) and the fields (91 -> 81-82), and the seal's p90 fell 120-129 -> 101-105; but the road's end went the other way, 22 ->
28 (not the 11-14 expected in 10.52): the vote waits for the copy aside (`copy_aside_ms` 16, `copy_wait_ms` 18-19 on the road, against 10
for the inline `copy_ms` on A), so a follower's receipt -> vote reads 36 ms (p75 52) on Cb against 26 (p75 42) on A, and the leg's win1 does not move.
**The swap reading of 10.50 is falsified**: with the swap empty the root's tail is still there (p90 1,045-1,570) and `root_append_faults`
carry 98% of the faults of a faulting root. The faults are minor ones (`root_majflt` max 20 on Cb; one block with 7,822 on A), so no page was
read back from disk.

Which roots fault (Cb, 749 full blocks; faulting = `root_faults` >= 500, 158 blocks = 21%; A: 29%): not the chunk seal (`root_seals` > 0 on 3
of 158 faulting roots and on 14 of 591 others; within the three blocks before 13/158 against 55/591), not the twig pool (`root_twig_pool_misses`
0 on every block; refills on 20 of 158, none of the others' median), not a period (gaps between faulting blocks 1, 2, 4, 5, ... with no
fixed value, median 2), not memory of the previous block (a faulting root follows a faulting one in 20% of cases, the base rate 21%), and none
of the log lines in the 300 ms before the root is enriched (`compacted the QMDB log` 37% of faulting vs 51% of the others, `freed the QMDB
records` 11% vs 14%, `forest lock held compute_operations` 88% vs 85%; the two that are over-represented, a lock wait on `on_persisted` and
`sync_entries_if_file`, precede only 12 and 19 of the 158 faulting roots). The faulting share does grow with the chain
(blocks 300-399: 14%, 500-599: 21%, 800-899: 27%, 900-999: 35%). **Not determined**: the cause stays unnamed; what is ruled out is the swap, the
seal, the pool, a period and the neighbouring log events, and the growth with depth is the lead (the next legs need the faults per root
against the tail of the append's file, not a rule from these counts).

The cycle (Cb window 1, 213 full blocks, medians / p75): proposal to proposal 129 / 166 ms; `R1_collect` (B) 49 / 85; quorum of the parent
to the proposal 59 / 87; the proposal's quorum comes 60 / 96 ms after it (A: 47 / 83). 73% of the proposals are `tick_bound` (A: 77%): the
builder declined the view for the 100 ms pacing and the proposal went out at the tick, which lies 99.0 ms after the previous proposal
(p90 99.3), `tick_late_us` 0.8 / 1.4 ms. After the tick the proposal still waited for its own seal in 34% of the cases (A: 39%): `take_sealed_us`
0 / 44 ms (p90 65), the tick-to-send 10 / 53. The 27% not tick-bound (A: 23%) are the ones whose quorum came after the tick: 7 sent within 3 ms of
the quorum, 51 later, the gap quorum -> proposal 6 / 43. The followers' receipt -> vote is 36 / 52 ms on both (`vote road` total 29 / 35, `copy_wait`
18-19, `parent_fields_wait` and `parent_output_wait` 0); the votes are not what the proposal waits for in the median. **The proposal waits for the
pacing tick (99 ms after the previous proposal) in three of four views, then for its own seal in a third of them, and for the quorum when the
quorum lands after the tick (a quarter of the views, the 60 / 96 ms R1 tail)**: the median chain (seal 76, fields 82) is under the tick, the
cycle median 130 is the tick plus the tails of the seal (p90 101-129) and of the quorum. A pacing below 100 ms moves the first term only; the
seal's and the quorum's tails are the terms behind it.

### 10.54 Defect 27 on the fleet (loop306): the root's faults were its per-block temporaries, and the scratch set removes them

Tip 1b331d714 (the root's per-block temporaries reused from one scratch set; `root_faults_*` split), the copy-aside configuration of 10.53 (C),
100 ms pacing, three nodes. S, Sb and Sc run the default (scratch on); OFF runs `N42_QMDB_APPLY_SCRATCH=0`. The split columns are the p90 of the
leader's full blocks (`txs=163000`, ~745 per leg, window 1 and later); every other split key (entries, offsets, index, undo) reads 0 / 0 on S and OFF.

| leg | win1 | cycle mean / median | sealed_at median / p90 | root faults median / p90 | split p90 (bits / twigs / tmp) | share >= 500 |
| --- | --- | --- | --- | --- | --- | --- |
| S | 1,161,427 | 140 / 134 | 79 / 126 | 7 / 519 | 5 / 7 / 0 | 5.1% |
| Sb | 1,165,520 | 139 / 126 | 77 / 120 | 4 / 377 | - | 5.4% |
| Sc | 1,164,363 | 138 / 122 | 79 / 120 | 7 / 610 | - | 7.6% |
| OFF | 1,174,405 | 138 / 131 | 80 / 129 | 17 / 1,548 | 5 / 30 / 896 | 22.8% |

The faults of a faulting root were in the per-block temporaries (`root_faults_tmp` p90 896 on OFF, 0 on S; `root_append_faults` median 4 on OFF, 0 on
all three scratch legs); the twig structure adds a few (p90 30 on OFF, 7 on S) and the bit vectors 5 on both. With the scratch set the root's fault
p90 fell 1,548 -> 377-610 and the share of roots with >= 500 faults 22.8% -> 5.1-7.6% (the 10.53 reading was 21% on Cb). The seal's p90 moved
129 -> 120-126 (`sealed_at_over_130` 111 on OFF, 84-101 on the scratch legs), the median not (77-80). The window did not follow: win1 reads
1.161-1.166M on S legs and 1.174M on OFF, a spread of 1.1%, inside the 4% of one configuration, and the cycle mean is 138-140 ms on all four (the
medians 122-134 differ more than the means, so the tail of the cycle is not the root's). The record stays 1,226,047 (loop293). Not determined:
why the remaining 5-8% of roots still fault (the p90 of the split is 7 on twigs and 5 on bits, so those roots' faults lie in a key not in the split).

### 10.55 Step 8 on the fleet (loop307): the build starts earlier, the window does not follow

Tip e55bdb9a6 (step 8: `N42_BUILD_AHEAD_AT_SEAL`, the build-start fields on the `proposal sent` line), the copy-aside configuration of 10.54, 100 ms
pacing, three nodes. ON and ONb set `N42_BUILD_AHEAD_AT_SEAL=1`, OFF does not, ONP90 is ON at 90 ms pacing. Proposal-to-proposal is over window 1 (30 s
from the first full build) on node 0's and the other nodes' `proposal sent` lines taken together; `build start` is `build_start_after_prev_send_us`
(negative: the build began before the previous block's send), over all proposals of the leg (~2,400 per leg). The runner's own `build_start_*` and
`take_sealed_us_*` counters read `-` because it greps the unstripped `v.log` (the field names carry ANSI codes); the numbers here are from the stripped logs.

| leg | win1 | win2 | cycle mean / median | proposal-to-proposal median / p75 / mean | build start median / p75 (ms) | trigger send / seal | take_sealed median / p75 (us), share > 3000 us | sealed_at median / p90 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ON | 1,166,653 | 863,856 | 135 / 111 | 118 / 159 / 139 | -100.3 / -99.3 | 83% / 16% | 4 / 8, 17.0% | 91 / 205 |
| ONb | 1,208,663 | 724,321 | 131 / 112 | 118 / 150 / 133 | -100.3 / -99.3 | 83% / 17% | 4 / 8, 15.6% | 93 / 192 |
| OFF | 1,173,888 | 863,075 | 137 / 127 | 129 / 160 / 137 | -79.5 / +0.3 | 44% / 55% | 4 / 9, 22.3% | 80 / 125 |
| ONP90 | 1,190,069 | 880,146 | 132 / 122 | 129 / 161 / 136 | -90.7 / -90.0 | 81% / 19% | 1 / 9, 19.6% | 101 / 199 |

The build start moved as designed: on OFF the p75 of the start is +0.3 ms after the previous send (the late half of 10.54) and 55% of the starts
are triggered by the seal; on ON the p75 is -99 ms and the median -100 ms, the whole distribution lies before the previous send. The own-seal waits did
not fall on the median (4 us on all legs); the share of takes over 3 ms fell from 22.3% to 15.6-17.0% (30.1% to 14.6-19.0% in window 1), which is
within what two legs of one configuration differ by. The cycle median fell 127 -> 111-112 ms and the proposal-to-proposal median 129 -> 118 ms, but the
cycle mean (131-135 against 137) and the proposal mean (133-139 against 137) did not move, so the early half of the distribution shortened and the tail
did not. `sealed_at` rose (median 80 -> 91-93, p90 125 -> 192-205): with the build started earlier its seal is later after the proposal it is measured
from, and the window did not gain from it. Window 1 reads 1.167 / 1.209M on ON against 1.174M on OFF (ON mean 1.188M, spread 3.6%, inside the 4% of
one configuration); ONP90 reads 1.190M, and at pacing 90 the proposal median is the pacing-100 OFF value, not a shorter one. No ON leg reaches the
record 1,226,047. Window 2 is not a metric (ONb 724k on a 76.8% occupancy; the other three 863-880k). Correctness: `own block at this height was not
the one committed` 0, `Encountered invalid block` 0, `no gov5 header variant` 0 on all four legs; `TC formed` 1 per leg; `superseded` 1 per leg on the
three ON legs and 7 on OFF. Not determined: why the early start shortens the cycle's lower half and leaves its mean.

### 10.56 The reth v2.7.0 upgrade on the fleet (loop308): correct, and the follower's execution is three times slower

BASE is the tip e96377cc3 (reth v2.5.1), UP is branch `upgrade/reth-v2.7.0` at d50328c0c (reth v2.7.0), both built native; the configuration is that of
10.54 S (copy-aside, scratch on, 100 ms pacing, three nodes). The first UP and UPb legs did not start: v2.7.0 validates `--engine.num-state-masking-blocks`
(default 30) + `--engine.memory-block-buffer-target` (6) < `--engine.persistence-threshold` (8, the bench's) and the execution layer exits at launch
(`loop308.out`). The UP legs in the table were rerun in `loop308b.out` with `RETH_ENGINE_NUM_STATE_MASKING_BLOCKS=0` (masking off), so the order is BASE,
BASEb, UP, UPb, BASEc (BASEc added as a drift check), not the planned interleave. All five legs read `verify` pass, one commitment hash across the three nodes.

| leg | win1 | win2 | cycle mean / median | sealed_at median / p90 | par_exec / roots (ms) | follower exec / root / fields ready (ms) | imports > 600 ms | root faults p90 | peak el max (G) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASE | 1,128,341 | 828,415 | 142 / 126 | 80 / 148 | 30 / 34 | 43 / 30 / 93 | 13 | 371 | 30.5 |
| BASEb | 1,164,397 | 922,953 | 138 / 119 | 80 / 129 | 30 / 34 | 41 / 30 / 86 | 8 | 482 | 32.0 |
| BASEc | 1,158,268 | 809,488 | 138 / 132 | 79 / 146 | 30 / 33 | 43 / 30 / 90 | 5 | 496 | 29.5 |
| UP | 573,396 | 565,048 | 282 / 229 | 171 / 404 | 25 / 29 | 121 / 28 / 229 | 83 | 821 | 21.5 |
| UPb | 562,228 | 554,181 | 281 / 259 | 167 / 402 | 25 / 29 | 112 / 28 / 219 | 64 | 931 | 21.3 |

Correctness is unchanged: on all five legs `invalid_blocks`, `no_variant`, `own_not_committed`, `unanswered_reads`, `direct_imports_failed`, `incomplete`,
`gas_mismatch` and `proposals_given_up` are 0 and `tc` is 1 (the genesis timeout); no `ERROR` or `panicked` line appears on any. The only warning message
that occurs on UP legs and not on BASE legs is `foreign body refused; sending the payload` (3 on UP, 1 on UPb, 0 on the three BASE legs: a compact body
whose transactions this node did not hold, answered by sending the payload); the `forest lock` warnings are 4-5 times fewer on UP, as the legs carry half the
load. Performance is not unchanged: win1 reads 562-573k on UP against 1.128-1.164M on BASE (-50%), far outside the ~4% spread of one configuration (BASE legs
span 3.2%), and the cycle mean doubles 138-142 -> 281-282 ms. The follower's batched execution is the difference that is measured: `imp_exec_batches_ms`
33-34 -> 107-114 and the batch median 13 -> 75-79 ms (54 batches, 32 threads on both), so a block's fields are ready at 219-229 ms instead of 86-93, and
`sealed_at` moves 80 -> 167-171 ms with it; the leader's own `par_exec` (25 against 30 ms) and the follower's root (28 against 30 ms) did not slow. Window 2 and 3
hold at 554-565k on UP, where BASE's window 2 falls to 809-923k and window 3 reads 0 (the supply is spent), because UP spends fewer transactions per window. Not
determined: why the follower's execution batches are slower on v2.7.0 (revm, the execution-layer crates or the masking-off setting are all untested here); the
leg ran with masking off, so the default masking was not measured at all.

### 10.57 The v2.7.0 upgrade with the per-read overlay (loop309): within the spread of the current code, and the upstream path reproduces the slowdown

loop309 ran the `upgrade/reth-v2.7.0` branch with the per-read overlay fix (`9ce4e2830`) against the same branch with `N42_OVERLAY_READS=upstream` (the upstream
flattening) and against the current code, interleaved UPFIX, BASE, UPFIXb, UPUP, all with `RETH_ENGINE_NUM_STATE_MASKING_BLOCKS=0` on the upgrade legs.

| leg | win1 TPS | win2 TPS | win1 cycle | sealed_at median / p90 | par_exec | follower imp_exec / batches | imp_fields_ready | imports >600 ms | el_max_peak |
|---|---|---|---|---|---|---|---|---|---|
| UPFIX | 1,039,868 | 858,431 | 0.156 s | 88 / 163 ms | 33 ms | 46 / 36 ms | 96 ms | 8 | 37.6 G |
| BASE | 1,161,874 | 836,294 | 0.140 s | 82 / 153 ms | 31 ms | 43 / 34 ms | 91 ms | 10 | 31.4 G |
| UPFIXb | 1,037,543 | 798,033 | 0.156 s | 89 / 160 ms | 33 ms | 46 / 37 ms | 95 ms | 6 | 34.8 G |
| UPUP | 534,270 | 428,980 | 0.303 s | 201 / 579 ms | 43 ms | 111 / 104 ms | 259 ms | 165 | 14.6 G |

Correctness holds on all four legs: the verify line passes at three nodes with quorum 3 (common heights 2112, 2265, 2026, 1153), `invalid_blocks`, `no_variant`,
`own_not_committed`, `unanswered_reads`, `direct_imports_failed`, `incomplete`, `gas_mismatch` and the `foreign body refused`, ERROR and panicked counts are all 0;
`tc` is 1-2 per leg. The fix restores the follower: its batch time is 36-37 ms against BASE's 34 (loop308's UP read 104-107 on the same counter) and `imp_fields_ready`
is 95-96 ms against 91, and UPUP reproduces loop308's slow path exactly (104 ms batches, window 1 at 534k), so the overlay setting is what separates the two.
UPFIX is not within the ~4% spread of BASE on window 1: 1.04M against 1.16M is 10.5% lower (UPFIXb agrees at 1.038M, so the gap repeats), while window 2 is within
the spread (858k / 798k against 836k). What still differs from the current code is a follower execution 3 ms slower, a leader `par_exec` 2 ms longer, a sealed_at
median 6-7 ms later and a 10% longer cycle, and about 3-6 G more peak resident memory per node; the cause of that remainder was not isolated here. Each leg is one
round, BASE is a single leg, and the box load at leg start was 2.6, 37, 22 and 38 (the first leg alone started quiet), so the 10% is a measured difference of two
upgrade legs against one current-code leg, not a conclusion about a cause. The `exec_pre_ms` counter reads `-` on every leg (the build-path import line it greps does
not carry it in this configuration).

### 10.58 What still costs the v2.7.0 upgrade 10% (loop310): the sender cache and txpool prewarming are not it; upstream's state-trie overlay pool is the extra CPU

loop309's UPFIX and BASE logs show no new per-block INFO/WARN template on the upgrade (the only UPFIX-only lines are a handful of `build on own block refused`,
`a parallel step skipped`, `a frame has been held at the ingest gate` events, 1-5 per leg, plus 5% fewer blocks), so the extra work is silent. Field by field (medians
over `txs=163000` blocks) the upgrade is uniformly 5-10% slower rather than slow in one place: `par_exec` 33 against 31 ms, `sealed_at` 88 / 82, `state_ready` 154 / 142,
`finish` 162 / 148, build `total` 275 / 257, `shard_append` 277 / 236 ms, follower `exec` 46 / 43, `root` 32 / 30, `fields_ready` 96 / 91, `engine` 35 / 31 ms. The per-thread
CPU sampler (`threadcpu-loop309*.tsv`) names the difference: a `state-ovly` worker pool (reth's `OverlayManager` for state-trie overlays, 4 threads by default,
`DEFAULT_STATE_TRIE_OVERLAY_WORKER_THREADS`, no CLI flag) burns 22,800 units on UPFIX and 0 on BASE, which is the whole of the 262.5k against 243.8k total gap, and
`txpool-prewarm` 1,063 against 27, `payload-builder` 104 against 3.5. Switches (`engine.rs`, v2.5.1 -> v2.7.0): `--engine.sender-recovery-cache` (env
`RETH_ENGINE_SENDER_RECOVERY_CACHE`) default false -> true, but the bench passes the flag on both sides so BASE had it on; `--engine.txpool-prewarming` default false, bench
passes it; block prewarming off (`--engine.disable-prewarming`), persistence threshold 8, buffer target 6, backpressure 1024 all set by `fleet7-env.sh`;
`--engine.persistence-threshold` default 7 -> 50 and `--engine.num-state-masking-blocks` 0 -> 30 (leg env sets masking 0). loop310 turned the cache and txpool prewarming
off (`RETH_ENGINE_SENDER_RECOVERY_CACHE=false F7_NO_SENDER_CACHE=1 F7_NO_TXPOOL_PREWARM=1`; `F7_NO_SENDER_CACHE` alone would not disable the cache on v2.7.0).

| leg | win1 TPS | win2 TPS | win1 cycle | sealed_at median / p90 | par_exec | follower imp_exec / batches | imp_fields_ready | imports >600 ms | el_max_peak |
|---|---|---|---|---|---|---|---|---|---|
| UPNC | 874,595 | 710,933 | 0.186 s | 85 / 150 ms | 32 ms | 45 / 36 ms | 94 ms | 22 | 32.0 G |
| BASE | 1,151,104 | 955,483 | 0.141 s | 78 / 115 ms | 30 ms | 40 / 33 ms | 85 ms | 15 | 31.8 G |
| UPNCb | 900,324 | 608,475 | 0.180 s | 88 / 151 ms | 32 ms | 44 / 35 ms | 91 ms | 20 | 30.6 G |
| UPFIX | 892,752 | 971,350 | 0.182 s | 87 / 148 ms | 32 ms | 44 / 36 ms | 93 ms | 6 | 36.6 G |

Correctness holds on all four legs (verify written, `invalid_blocks`, `no_variant`, `own_not_committed`, `unanswered_reads`, `direct_imports_failed`, `gas_mismatch`
0; `tc` 4, 1, 3, 2). The two switches took `txpool-prewarm` CPU to 0 and the peak resident memory to BASE's level (32.0 / 30.6 G against 31.8, UPFIX 36.6 in the same
round and 37.6 / 34.8 in loop309), but not the throughput: UPNC and UPNCb read 875k / 900k against UPFIX's 893k, so they did not close the window-1 gap; the whole upgrade side
read 21-24% under BASE this round (loop309: 10%), a larger gap than the 10% that motivated the round and a reminder that single legs move by that much. What remains is the
`state-ovly` pool: 21.3-21.6k CPU units on every upgrade leg (UPNC 21,615, UPNCb 21,410, UPFIX 21,278) against 0 on BASE, a sealed_at p90 of 148-151 against 115 ms and
`state_ready` 150-153 against 129 ms, which is upstream's `OverlayManager` computing a trie overlay per in-memory tip on the workers the leader and followers share the cores
with; N42's QMDB root does not use it, so the next step is a vendored switch that keeps the engine from asking for it (not a flag today) and a leg with it off.

### 10.59 The v2.7.0 upgrade with the overlay manager off (loop311): UPOFF 1.123M / 1.162M against BASE 1.181M, the pool is gone

loop311 ran the v2.7.0 branch at `71d4da172` (`709b861eb`: the engine's state-trie overlay manager is off by default on a QMDB chain) with the loop310 UPFIX environment
(masking 0, cache and txpool prewarming as in loop309), interleaved UPOFF, BASE, UPOFFb, UPON (UPON = `RETH_ENGINE_STATE_TRIE_OVERLAY=true`, the A/B). The runner counts
`Overlay manager created state_trie_overlay=` per leg and sums the `state-ovly` thread CPU (units of `threadcpu4.py`; loop310: ~21-22k on upgrade legs, 0 on BASE). Correctness
is clean on all four legs (verify pass, invalid_blocks 0, no_variant 0, own_not_committed 0, unanswered_reads 0, direct_imports_failed 0, incomplete 0, gas_mismatch 0, ERROR/panicked 0);
UPON had tc=2 and proposals_given_up=1 against tc=1 on the others.

| leg | win1 TPS | win2 TPS | win1 cycle (mean) | sealed_at median / p90 | par_exec | follower imp_exec / batches | imp_fields_ready | imports >600 ms | el_max_peak | overlay manager | state-ovly CPU |
|---|---|---|---|---|---|---|---|---|---|---|---|
| UPOFF | 1,123,219 | 890,982 | 0.144 s | 84 / 167 ms | 30 ms | 44 / 36 ms | 91 ms | 7 | 34.1 G | false | 0 |
| BASE | 1,180,769 | 889,078 | 0.138 s | 80 / 128 ms | 30 ms | 41 / 33 ms | 87 ms | 9 | 30.8 G | - | 0 |
| UPOFFb | 1,161,988 | 916,914 | 0.139 s | 79 / 141 ms | 30 ms | 43 / 35 ms | 91 ms | 8 | 34.6 G | false | 0 |
| UPON | 1,036,911 | 825,826 | 0.157 s | 93 / 197 ms | 32 ms | 45 / 36 ms | 95 ms | 7 | 35.9 G | true | 25,569 |

The `state-ovly` pool is at 0 with the manager off, and window 1 is 1.123M / 1.162M against BASE 1.181M (-4.9% and -1.6%; UPON, same binary with the manager on, 1.037M, -12%), so the manager
accounts for most of the loop309/loop310 gap. The first UPOFF leg is outside the 4% merge bound; the second is inside; win2 is equal to BASE on both. Peak el_max RSS is still 3.3-3.8 G above BASE
(34.1 / 34.6 against 30.8 G) and sealed_at p90 is higher on UPOFF (167 / 141 against 128 ms); this loop does not say what causes either. Two legs per arm do not separate a 2-5% difference (window 1 repeats within ~4%).

#### 10.59 addendum (2026-10-03): merged

The reth v2.7.0 upgrade (upgrade/reth-v2.7.0) was merged into feat/native-fleet7 at 8b4704f4c (tag reth-v2.7.0-merged-20261003). Decision: correct on four fleet rounds (12 upgrade legs, every error counter 0) and window-1 throughput is within the one-configuration spread (-4.9% / -1.6% on loop311).
Open items: the remaining ~3% window-1 gap and the ~3.5 GB higher peak RSS.
The record 1,226,047 was set on v2.5.1; the next legs re-baseline on v2.7.0.

### 10.60 The new baseline on reth v2.7.0 (loop312): B1-B3 1.186M / 1.146M / 1.197M, mean 1.176M; AHEAD 1.216M but with a 40.7 G peak

Tip d859eb00f (reth v2.7.0, ed25519-dalek 3.0), native build, overlay manager off (the default since 709b861eb). Legs interleaved B1, AHEAD, B2, B3; B1-B3 are identical, AHEAD adds `N42_BUILD_AHEAD_AT_SEAL=1`. All four legs: verify pass, invalid_blocks, no_variant, own_not_committed, unanswered_reads, direct_imports_failed, incomplete, gas_mismatch all 0, tc=1, 0 ERROR/panicked lines, `state_trie_overlay=false` on 3 nodes, `state-ovly` CPU 0. (The runner's `node3` grep/traceback noise is the 3-node fleet having no node3, as in loop311.)

| leg | win1 | win2 | cycle w1 | sealed_at med | par_exec | imp_exec / total | imports >600 ms | el_max peak | min avail |
|---|---|---|---|---|---|---|---|---|---|
| B1 | 1,185,656 | 901,431 | 0.137 s | 80 ms | 30 ms | 43 / 144 ms | 6 | 33.0 G | 40.6 G |
| AHEAD | 1,215,559 | 624,244 (53% occupancy) | 0.130 s | 99 ms | 32 ms | 45 / 155 ms | 9 | 40.7 G | 27.7 G |
| B2 | 1,145,671 | 926,945 | 0.142 s | 84 ms | 31 ms | 44 / 143 ms | 3 | 32.1 G | 42.2 G |
| B3 | 1,196,982 | 912,669 | 0.135 s | 82 ms | 31 ms | 43 / 141 ms | 6 | 33.2 G | 38.0 G |

The baseline on v2.7.0 is the mean of B1-B3, 1,176,103 TPS in window 1 (range 1,145,671-1,196,982, spread 4.4% of the mean), against 1,180,769 for loop311's BASE on v2.5.1: -0.4%, inside the round-to-round spread, so the upgrade's earlier ~3% window-1 gap is not visible at this resolution. The B legs' el_max peak is 32-33 G (v2.5.1 BASE 31.4 G in loop309). No leg exceeds the record 1,226,047 (AHEAD is 0.9% below it). AHEAD read +3.4% over the B mean in window 1, within about the spread of the B legs themselves (one leg, so not a conclusion); it moved sealed_at median from 80-84 to 99 ms, raised el_max peak to 40.7 G and cut min available memory to 27.7 G, and its window 2 fell to 624k at 53% occupancy against 901-927k. The per-leg root_faults p90 is not printed by this runner.

### 10.61 Step 9, the core layout (loop313): isolation did not flatten the tails and did not move the mean; BASE is the fastest leg at 1.186M

Tip 7d2e5d0cf (step 9: `N42_CORE_LAYOUT=isolate`, three commits on 23f8512ab), native build, the loop312 B1 configuration as BASE. Legs ISO (build pool on 16 physical cores with both siblings, critical pools on 4 cores, everything else confined to the rest), BASE, ISONICE (ISO plus `N42_BACKGROUND_NICE=10`), ISO16 (`N42_PARALLEL_BUILD_THREADS=16`, siblings idle, layout tag `b16/c4/bg34`). Single round per leg, so differences under about 10% are not distinguishable. Correctness is clean on all four legs (verify: no disagreements, all three nodes advanced; invalid_blocks, tc=1 as in loop312, no_variant, own_not_committed, unanswered_reads, direct_imports_failed, incomplete, gas_mismatch all 0 or at baseline; no panics). The layout was applied on every ISO leg: one `core layout:` startup line per node (in v.log, none a fallback) and the `core_layout="b16x2/c4/bg34"` tag on the import lines (`off` on BASE).

| leg | win1 | win2 | cycle w1 mean / median | sealed_at med / p90 | par_exec | imp_exec / batches | fields_ready med / p90 | B p75 | imports >600 ms | el_max peak |
|---|---|---|---|---|---|---|---|---|---|---|
| ISO | 1,085,337 | 814,917 | 149 / 144 ms | 92 / 190 ms | 27 ms | 42 / 54 | 90 / 161 ms | 54 ms | 6 | 31.5 G |
| BASE | 1,186,239 | 884,959 | 135 / 119 ms | 79 / 138 ms | 30 ms | 42 / 54 | 89 / 143 ms | 47 ms | 8 | 31.9 G |
| ISONICE | 1,130,090 | 852,998 | 143 / 136 ms | 90 / 177 ms | 27 ms | 41 / 54 | 88 / 137 ms | 51 ms | 4 | 30.1 G |
| ISO16 | 1,144,627 | 911,254 | 141 / 132 ms | 92 / 149 ms | 29 ms | 39 / 30 | 85 / 111 ms | 49 ms | 5 | 31.9 G |

The tails did not move in the direction the layout was meant to move them. Seal p90 is 149-190 ms on the layout legs against 138 ms on BASE (the reference range was 125-150), the fields p90 is 111-161 ms against 143 on BASE (ISO16 is the one leg below the 140-175 range, ISO is above it), and B p75 is 49-54 ms against 47 on BASE (reference 85 from an earlier loop, so BASE itself is already below it). The cycle mean is 141-149 ms on the layout legs against 135 on BASE (reference 137), and window 1 is 1.085-1.145M against 1.186M, i.e. 3.5-8.5% below BASE; with one round per leg only the ISO deficit (8.5%) approaches the noise limit. Among the layout legs, ISONICE and ISO16 read higher than ISO (1.130M and 1.145M against 1.085M) and ISO16 has the lowest fields p90 and the fewest import batches (30 against 54, from the 16-thread build pool), but the ordering rests on single runs. What this round does show is that confining the other threads and pinning the pools did not reduce the nodes' tail latencies on this host; it does not show why. Tags and the startup tally are in `core_layout=`/`startup_lines=` of `scripts/fleet7-runs/results/loop313.out` (the runner counted `core_layout` with a regex that does not match the quoted value and read the startup line from el.log, so those two columns there are empty/0; the numbers above were taken from the logs directly).

### 10.62 The tail under perf (loop314, diagnostic): a quarter to a third of the on-CPU samples are kernel, mostly syscalls (futex, madvise, sched_yield) and not page faults; no memory-system counter marks the slow blocks

Loop314 is one diagnostic leg of the loop313 BASE configuration with symbols (`cargo build --profile profiling`, frame pointers, `target/native-prof`) and the instruments of `scripts/fleet7-runs/prof314.sh` (a 0.5 s `/proc/vmstat` + meminfo + PSI sampler, `perf stat -I 1000` on each EL for 60 s, `perf record -F 499 -g --call-graph fp` on the leader node0 and on follower node1 from 5 s to 35 s after the funding mined), then a plain BASE leg. The first profiled leg (PROF) produced empty perf data: the default per-thread mmap exhausted the unprivileged mlock budget (`perf_event_mlock_kb` 516); the script now retries with `-m 16..1` and PROF2 repeated the leg (node1 recorded at 16 pages, node0 fell to 1 page and perf reported 2,517 lost chunks, so node0's shares are slightly less certain). Window 1: BASE 1,188,982 (cycle mean 122 ms, sealed_at median 79 ms), PROF 1,108,976, PROF2 1,096,217 (-7% to -8%: perf's cost, so the profiled legs' tails are perturbed). Not available on this host (`perf_event_paranoid` 1, `kptr_restrict` 1, no sudo): kernel symbol names (`/proc/kallsyms` is zeros, `/boot/System.map*` is root-only), tracefs (`perf sched` refused), `stalled-cycles-backend` (unsupported) and, in PROF2, the HW counters of node2's `perf stat` (`cycles` not supported while two `perf record`s ran; node2 is from PROF). Kernel samples therefore appear as raw addresses; `scripts/fleet7-runs/kernshare314.py` groups them by the outermost kernel frame (the entry into the kernel) and by the first user frame, which says who asked for the kernel work but not which kernel function ran.

**A. Where the cycles go (PROF2, share of all samples; `--no-inline`).**

| | leader node0 | follower node1 |
|---|---|---|
| samples | 298,919 | 320,070 |
| kernel-leaf samples | 29.5% | 25.8% |
| entered by a syscall (`entry_SYSCALL_64` path) | 21.0% | 17.8% |
| entered by a page fault (the `asm_exc_page_fault` path) | 7.0% | 6.7% |
| entered by other paths (interrupts, other exceptions) | ~1.3% | ~1.0% |
| first user frame of the syscall entries | libc `syscall` 43%, `__madvise` 24%, `__sched_yield` 3% | `syscall` 50%, `__madvise` 22%, `__sched_yield` 6% |
| the hottest kernel address (one instruction, `0xffffffffa5d34f11`) | 8.3% | 6.1% |
| the same address's callers | `__madvise` 41%, rayon collect/unzip frames (page faults) 7%+, unknown | `__madvise` 41%, rayon collect 17%, unknown 17% |
| `jemalloc_bg_thd` | 5.3% of samples, 97% kernel | 4.1% of samples, 96% kernel |

The kernel share by thread family (kernel-leaf / family samples, node0 / node1): tokio runtime 28% / 24% (the family is 34% / 32% of all samples), `n42-build-*` 23% / 19% (22% / 28%), `storage-*` 23% / 19% (16% / 18%), the unnamed `n42` threads (QMDB and merge workers) 23% / 33% (14% / 12%), `jemalloc_bg_thd` 97% / 96%, `build-on-own` 36% on the leader, `vote-check` 85% on the follower (0.3% of samples), `n42-queue-forge` 54% (0.8%). The libc `syscall` wrapper is how Rust's std reaches `futex`; I did not see the syscall number, so "futex" is the reading of the wrapper, not a measurement.

Top user-space leaf symbols per family (share of the family's samples; the `[kernel]` row is the share above):

| family | top 5 user leaf symbols (node0; node1 within a few points unless marked) |
|---|---|
| tokio runtime (ingest, queue) | `keccak::backends::soft::keccak_p<u64,24>` 24% (node1 26%), `TxQueue::index_and_stage` 4.5%, `HashMap<FixedBytes<32>, Arc<ValidPoolTransaction>>` 3.8%, `sha3::Keccak256::finalize_into` 1.9% (2.5%), unresolved 3% |
| `n42-build-*` | `BundleState::account` 10.6% (9.5%), `bytes::shallow_clone_vec` 8.0%, `execute_for_build_opts` 7.3% (6.4%), `TxEnvBuilder::build` 4.5% (4.2%), `BatchState` closure 4.5% |
| `storage-*` | unresolved 8.8%, `metrics_util ... Generational<Atomic<u64>>` 6.4% (6.1%), `RocksDBProvider::write_account_history` 5.6% (4.5%), `rocksdb::BlockBasedTable::Get` 1.9%, prometheus `AtomicBucketInstant::record` 1.9% (2.5%) |
| unnamed `n42` (QMDB, merge) | `twig_core::Shard::get<QmdbReadView::step_back>` 8.4% (9.5%), `FileEntries::record` 6.3% (3.4% on node1), `_blake3_compress_in_place_avx512` 5.9%, `Shard::get<held_slots>` 5.1%; node1 also `bytes::shallow_clone_vec` 10% |
| `jemalloc_bg_thd` | the kernel (97%); user code is `pthread_mutex_trylock/unlock` and `_rjem_je_edata_heap_remove` under 1% each |

Overall (all families) the top user symbols are `keccak_p` soft backend 11.7% / 11.4% (two instantiations, 8.8% + 2.9% and 8.4% + 3.0%), `BundleState::account` 2.7% / 2.9%, `execute_for_build_opts` 1.3% / 1.3%, `TxAltSig::fields_len` 1.3% / 2.1%, blake3 compress 1.2% / 1.35%, `alt_sig_tx_env` 1.2% / 1.4%. The software Keccak sits in the tokio ingest threads and is a CPU cost outside the block cycle's critical pools; I did not trace which call computes the hashes.

**B. perf stat (60 s from the funding, 1 s rows; PROF2 for nodes 0-1, PROF for node 2).**

| node | IPC | cache-miss / 1k instr | dTLB-miss / 1k instr | CPUs busy | ctx-switch /s | migrations /s | page faults /s |
|---|---|---|---|---|---|---|---|
| node0 (leader) | 0.84 (PROF 0.84) | 5.18 (5.22) | 0.46 (0.47) | 22.4 | 51.8k | 2.2k | 440k |
| node1 | 0.84 (0.84) | 5.12 (5.05) | 0.50 (0.51) | 22.0 | 59.0k | 2.5k | 455k |
| node2 (PROF) | 0.85 | 5.02 | 0.50 | 22.2 | 62.5k | 2.6k | 487k |

IPC by second ranges 0.62-1.03 on every node. A "slow block" (sealed_at > 120 ms on a leader line, fields_ready > 130 ms on a follower line) overlaps 53-56 of the 60 seconds, so a second cannot be classified: IPC in the seconds with a slow block against the others is 0.838 / 0.822 (node0), 0.839 / 0.779 (node1) in PROF2 and 0.835 / 0.854, 0.830 / 0.847, 0.842 / 0.898 in PROF (no consistent direction); the six worst-IPC seconds of each node are all seconds that contain a slow block, which every second does. Stalled-backend share is not available.

**C. vmstat against slow blocks (0.5 s intervals, deltas; slow = an interval overlapping the span from the road's start to the seal, or to the follower's fields_ready, of a block over the threshold; PROF2, 199 intervals).**

| counter (mean delta per 0.5 s) | slow (166 intervals) | other (33) | ratio | very slow, > 160 / 170 ms (128) vs other (71) |
|---|---|---|---|---|
| `compact_stall` | 14.2 | 15.9 | 0.89 | 1.02 |
| `pgscan_direct` / `allocstall_movable` | 2,484 / 7.7 | 2,960 / 8.8 | 0.84 / 0.88 | 0.95 / 1.01 |
| `pgscan_kswapd` | 175k | 153k | 1.15 | 1.15 |
| `thp_fault_alloc` / `thp_fault_fallback` | 731 / 1,028 | 974 / 1,065 | 0.75 / 0.96 | 0.72 / 1.06 |
| `thp_split_page` | 82 | 27 | 2.99 | 1.03 |
| `nr_dirty` / `nr_writeback` | 80.6k / 5.2k | 82.0k / 8.6k | 0.98 / 0.60 | 0.98 / 0.69 |
| `pgmajfault` | 9,264 | 2,736 | 3.39 | 3.70 |
| `pgfault` | 791k | 786k | 1.01 | 1.06 |
| memory PSI some avg10 | 0.3 | 0.5 | 0.63 | 0.99 |

The only counters over 2x are `pgmajfault` (3.4x and 3.7x here, 6.0x and 5.3x in PROF) and, once, `thp_split_page` (3.0x in the broad PROF2 classification, 1.03x in the strict one, 1.6x in PROF). `pgmajfault` is a ramp: its per-10 s totals are 43k, 70k, 128k, 427k, 181k, 135k, 225k, 172k, 142k, 105k in PROF2 (89, 114k, 502k, 404k, 216k, ... in PROF) while the slow blocks also become more frequent as the leg goes on (the cycle by 15 s bin rises 0.13 to 0.17 s in `loop314PROF`, `loop314BASE` and the earlier legs), so the ratio measures time, not cause; it did not separate within a stretch because the slow-marked intervals cover 64-83% of the leg. Compaction stalls (~30/s), direct reclaim, writeback, dirty pages and memory pressure (some avg10 0.3-0.5) do not differ between slow and other intervals.

**What the evidence supports and what it rules out.** The nodes spend 26-30% of their on-CPU samples in the kernel, and three quarters of that arrives through system calls whose first user frame is libc `syscall` (Rust's futex path), `madvise` (jemalloc's purge, 41% of the hottest kernel address and the whole of `jemalloc_bg_thd`, 4-5% of samples) and `sched_yield`, against 7% through page faults; one kernel instruction takes 6-8% of all samples and is reached from both `madvise` and page faults, which fits lock or atomic contention in the memory-management path, but without symbols that remains a reading and not a measurement. IPC 0.84, 5 cache misses and 0.5 dTLB misses per 1k instructions are the same on all three nodes and in every leg. What the leg rules out as the cause of the tail: THP compaction and direct reclaim (flat between slow and other intervals), page-cache writeback (flat), memory pressure (PSI under 0.5), a per-second IPC or cache-miss change (no consistent direction), and a node-specific effect (leader and followers look alike). What it does not show is why a particular block is slow: the profile is an average over 30 s, perf's own cost moved window 1 by 7-8%, a perf timestamp could not be aligned to a block within the needed ~50 ms (perf's clock is monotonic, the logs are wall time), and the 0.5 s slow classification marks most intervals. The tail's cause is not determined. The next measurements this suggests, each a new leg: kernel symbols under `sudo` (`perf record -a` with kallsyms and `perf trace -s` for the futex/madvise counts), `MALLOC_CONF` with `background_thread:false` or a longer `dirty_decay_ms` to see whether the 4-5% jemalloc purge thread and the madvise share move the seal p90, and the soft Keccak in the ingest threads (11% of samples) against an asm backend.

### 10.63 jemalloc's decay (loop315): a longer decay halves the page faults and the legs read 1.16-1.19M against a BASE leg that read 836k; the 30 s decay costs 41-51 G of resident memory and nearly exhausted the host once

Tip 381c858f5, native build, loop313 BASE configuration; the legs differ only in the last `MALLOC_CONF` token (confirmed from the nodes' environment on every leg): BASE `dirty_decay_ms:2000,background_thread:true`; D30 `dirty_decay_ms:30000,muzzy_decay_ms:30000,background_thread:true`; D30NB the same with `background_thread:false`; D10 `10000/10000`, background thread on. Page faults a second are the median of a `perf stat -I 5000` run of 60 s from the flood's first funding, per node (node0/1/2). One round per leg. Correctness: verify clean (all three nodes answering), invalid_blocks, no_variant, unanswered_reads, direct_imports_failed, incomplete, gas_mismatch 0 and no ERROR/panicked lines on all four legs; tc and own_not_committed are 1/0 on BASE and D30NB, 3/3 on D30 (one proposal given up) and 2/3 on D10.

| leg | win1 | win2 | cycle w1 mean / median | sealed_at med / p90 | par_exec | imp_exec / total | fields med / p90 | B p75 | imports >600 ms | page faults/s (k) | el_max peak | min avail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| BASE | 835,986 | 841,654 | 191 / 183 ms | 118 / 210 ms | 40 ms | 53 / 182 ms | 131 / 215 ms | 72 ms | 5 | 407 / 446 / 455 | 32.7 G | 36.0 G |
| D30 | 1,158,373 | 363,853 | 140 / 130 ms | 78 / 205 ms | 28 ms | 38 / 124 ms | 84 / 172 ms | 59 ms | 49 | 211 / 232 / 239 | 51.0 G | 2.1 G |
| D30NB | 1,192,253 | 960,436 | 136 / 131 ms | 115 / 176 ms | 28 ms | 39 / 147 ms | 82 / 121 ms | 43 ms | 6 | 220 / 219 / 221 | 41.6 G | 9.0 G |
| D10 | 1,168,972 | 434,480 | 138 / 130 ms | 74 / 145 ms | 29 ms | 38 / 124 ms | 83 / 139 ms | 55 ms | 6 | 305 / 351 / 357 | 43.7 G | 22.0 G |

The runner's `MEMORY FLOOR` fired on D30 (2.1 G available at its lowest, el_max peak 51.0 G) and D30NB (9.0 G); D10 stayed at 22 G. The page faults a second fell from 407-455k on BASE to 211-239k with a 30 s decay (-48%) and to 305-357k with 10 s (-21 to -25%), and the memory peak rose in the same order (32.7 G, 41.6-51.0 G, 43.7 G). All three decay legs read 1.158-1.192M in window 1 with a 130-131 ms cycle median, but the BASE leg of this round read 836k with a 183 ms cycle median, 118 ms sealed_at and 40 ms par_exec, whereas the same configuration read 1.186M in loop313 and 1.176M (mean of three) in loop312; one slow BASE round does not say whether the decay or the round-to-round state of the box (BASE ran first, after the build and the tests) explains the 28% gap, so the decay legs' gain over BASE is not established by this round and the comparison with the earlier BASE results (cycle 135 ms) is flat to slightly better (136-140 ms). The tails did not clearly move against the earlier BASE legs (sealed_at p90 145-205 ms against 138; fields p90 121-172 against 143; B p75 43-59 against 47), except that D10 and D30NB have the lowest sealed_at p90 and fields p90 respectively. D30 had 49 imports over 600 ms and its window 2 and 3 collapsed (364k, 170k, cycles 0.45 and 0.36 s) while the host was at 2.1 G available; D30NB's window 2 held at 960k and D10's windows 2 and 3 were half-occupied (46-48%). Window 3 of BASE and D30NB had no transactions (the flood had finished). None exceeds the record 1,226,047.

### 10.64 The profile's cuts and the overlay filter (loop316): no leg moved; NEW and FOFF read the same 1.1995M, the filter skips 90% of its probes and the cycle stays 135-136 ms

Loop316 is the merge of `step10/profile-cuts` (assembly Keccak, the build loop's clone and TxEnv cuts, `N42_STORAGE_OP_METRICS`, the QMDB lookup prefetch) and `step11/overlay-filter` (a per-block address filter for the in-memory overlay reads, `N42_OVERLAY_FILTER`, default on) onto `feat/native-fleet7` (tip 559bbf8e8 + tree), three nodes, the loop313 BASE configuration. WARM is the throwaway first leg after the build. NEW has `N42_STORAGE_OP_METRICS=0`; FOFF adds `N42_OVERLAY_FILTER=0`; NEWb is NEW with `N42_PHASE_TIMERS=1` (the overlay counters); NEWP90 is NEW with `F7_BLOCK_INTERVAL_MS=90`. All legs ran 01:09-01:37 in one claim; there is no leg on the old code, the comparison is loop312's B1-B3 (mean 1,176,103, cycle mean about 137) and loop313 BASE (1,186,239, cycle 135/119, sealed_at 79/138, par_exec 30, imp_exec 43 / 54 batches, imports >600 ms: 8, el_max 31.9 G).

| leg | win1 | win2 | cycle mean / median | sealed_at median / p90 | par_exec | imp_exec / batches | fields median / p90 | B p75 | imports >600 | el_max peak |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (not judged) | 1,138,898 | - | 142 / 140 ms | 80 / 158 ms | 30 ms | 44 / 54 | 92 / - | - | 5 | - |
| NEW | 1,199,549 | 831,219 | 136 / 125 ms | 78 / 145 ms | 30 ms | 43 / 54 | 89 / 160 ms | 51 | 10 | 29.8 G |
| FOFF | 1,199,503 | 912,758 | 135 / 125 ms | 80 / 151 ms | 30 ms | 43 / 54 | 88 / 147 ms | 47 | 1 | 32.9 G |
| NEWb | 1,183,493 | 738,347 | 136 / 123 ms | 78 / 139 ms | 30 ms | 43 / 54 | 91 / 188 ms | 54 | 15 | 28.2 G |
| NEWP90 | 1,210,360 | 889,912 | 135 / 128 ms | 83 / 190 ms | 30 ms | 41 / 54 | 89 / 143 ms | 50 | 8 | 29.6 G |

Correctness on every judged leg: verify passes (commitments agree, every node advanced), invalid_blocks, no_variant, own_not_committed, unanswered_reads, direct_imports_failed, incomplete and gas_mismatch all 0, no ERROR or panic in the three node logs; tc=1 on NEW, FOFF and NEWb, tc=2 with one proposal given up on NEWP90. The runner's per-leg `node3` greps and a python snippet over it print errors (the fleet has three nodes; the same in loop313); they touch no counter above. The overlay counters, summed over the leader's phases lines on NEWb: 3,413,598,178 skips against 371,188,222 probes, a skip ratio of 0.902 of the lookups. Page faults a second (median per node) were 396-468k on NEW, 393-424k on FOFF, 433-437k on NEWb and 388-465k on NEWP90, in the 407-455k range of loop315's BASE. Window 1: NEW +2.0% against loop312's mean and +1.1% against loop313 BASE; FOFF equals NEW to 46 transactions a second, so the filter's A/B reads zero on window 1 (the cut it makes, 90% of the overlay probes, is not on the critical path at this shape); par_exec (30 ms) and imp_exec (43 ms, 54 batches) are exactly the baseline's. Pacing 90 ms reads 1,210,360 with sealed_at p90 190 ms and one proposal given up, within the spread of one round (the repeat rule: a difference under about 10% between single rounds is invisible). Window 2 spans 738k-913k and is not a metric. No judged leg passed the record of 1,226,047.

### 10.65 Kernel counters and persistence beside the chain (loop317): slow blocks do not line up with IPI or fault bursts; P32 reads -2.4% on window 1 and collapses windows 2-3, NOSYNC +1.7%

Loop317 is measurement only (no code change; tip 539952574, three nodes, the loop316 NEW configuration, one claim 02:01-02:35). `scripts/fleet7-runs/kernsample.py` runs beside every leg and appends once a second to `strip-<tag>/kern.log` the `CAL` and `TLB` rows of `/proc/interrupts` summed over CPUs and nine `/proc/vmstat` counters (cumulative; `nr_tlb_remote_flush` and `nr_tlb_remote_flush_received` are NOT exported by this kernel, which has no CONFIG_DEBUG_TLBFLUSH, so the TLB evidence is the `TLB` interrupt row only). `analyze317.py` assigns each window-1 block (leader node0, gap between consecutive full blocks) to the one-second interval it ends in. P32 = `F7_PERSIST_THRESHOLD=32 F7_BLOCK_BUFFER_TARGET=24` (masking 0); NOSYNC = `N42_ROCKSDB_NOSYNC=1` (the switch exists, `crates/storage/provider/src/providers/rocksdb/provider.rs`). WARM is the throwaway first leg.

| leg | win1 | win2 | cycle mean / median | sealed_at median / p90 | fields median / p90 | imports >600 | el_max peak | persist batches (blocks each, wall each) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (not judged) | 1,203,237 | 885,409 | 135 / 126 ms | 79 / 149 ms | 88 / 155 ms | 7 | 29.6 G | 311 (6.3, 0.67 s) |
| BASE | 1,199,059 | 839,419 | 136 / 125 ms | 78 / 151 ms | 88 / 159 ms | 4 | 29.8 G | 304 (6.4, 0.69 s) |
| P32 | 1,170,848 | 352,652 | 139 / 128 ms | 81 / 148 ms | 88 / 207 ms | 91 | 40.3 G | 79 (13.7, 2.48 s) |
| NOSYNC | 1,220,503 | 884,167 | 133 / 121 ms | 80 / 152 ms | 88 / 152 ms | 12 | 28.9 G | 318 (6.2, 0.66 s) |
| TRACE (not judged) | 1,188,420 | 874,132 | 137 / 128 ms | 79 / 142 ms | 89 / 163 ms | 8 | 29.0 G | 310 (6.3, 0.68 s) |
| BASEb | 1,200,692 | 908,320 | 136 / 128 ms | 85 / 180 ms | 89 / 156 ms | 7 | 28.5 G | 322 (6.1, 0.67 s) |

Correctness on every leg: verify passes (three nodes, commitments agree), invalid_blocks, no_variant, own_not_committed, unanswered_reads, direct_imports_failed, incomplete, gas_mismatch and proposals_given_up all 0, tc=1, no ERROR or panic in the node logs; engine_idles_over_5s is 1 (3 on BASEb). The runner's `node3` cp/grep errors are the three-node fleet, as in loop313 and loop316.

Judging. BASE and BASEb differ by 0.14% on window 1, so the noise floor of this pair is small. P32 is below both by 2.4% and NOSYNC is above both by 1.7%; both meet the stated rule (same direction against both bookends by more than their gap) but both are well under the 10% single-round spread of earlier rounds, so neither is called a win or a loss here. What P32 does outside window 1 is not a metric but is large and consistent with its mechanism: batches of 13.7 blocks take 2.48 s instead of 0.67 s, 91 imports exceed 600 ms (4-7 on BASE legs), the follower fields_ready p90 is 207 ms against 156-159, el_max peaks at 40.3 G against 28.5-29.8, and windows 2 and 3 read 352,652 and 200,831 (0.46 s and 0.81 s cycles) against 839k-908k and 0. Batch wall scales faster than batch size (3.7x the wall for 2.1x the blocks): the persistence cost is superlinear in what one batch holds, so a larger threshold moves the pain from every sixth block to a long stall. NOSYNC leaves the batch unchanged (6.2 blocks, 0.66 s against 0.67-0.69), so the WAL sync is not what a persistence batch waits on.

Slow blocks against kernel counters (window 1 of BASE and BASEb, the slowest 10% of blocks by cycle, 22 blocks each, mean 215 and 206 ms against 128 ms for the rest; box-wide rates a second, slow-block intervals against the rest):

| counter | BASE slow / rest (ratio) | BASEb slow / rest (ratio) | Spearman, cycle vs rate (BASE, BASEb) |
| --- | --- | --- | --- |
| CAL (function-call IPIs) | 107,853 / 105,353 (1.02) | 102,992 / 109,419 (0.94) | 0.04, 0.10 |
| TLB row | 4 / 4 (1.17) | 4 / 3 (1.08) | 0.04, 0.06 |
| pgfault | 1.107M / 1.060M (1.04) | 0.897M / 0.919M (0.98) | 0.13, 0.11 |
| pgmajfault | 7,156 / 1,469 (4.87) | 166 / 159 (1.04) | 0.00, 0.03 |
| thp_fault_fallback | 1,154 / 1,175 (0.98) | 750 / 843 (0.89) | 0.12, 0.10 |
| compact_stall | 12 / 11 (1.09) | 8 / 7 (1.06) | 0.17, 0.17 |
| pgsteal_kswapd | 238,930 / 184,507 (1.29) | 180,335 / 182,768 (0.99) | 0.16, 0.14 |

Slow blocks do not coincide with IPI or fault bursts: CAL and TLB ratios are 0.94-1.17 in both legs, page faults 0.98-1.04, and every rank correlation is under 0.2. The two ratios above 1.2 (BASE's pgmajfault 4.87 and kswapd steal 1.29) do not repeat on BASEb (1.04 and 0.99) and BASE's pgmajfault Spearman is 0.00, so they are a few early seconds, not a pattern. The box-wide IPI rate is about 105,000 a second over 256 CPUs (roughly 400 a CPU a second) and the TLB row is 3-4 a second; page faults are 0.9-1.1M a second over three nodes. The limit of this evidence is the one-second sampling against 136 ms blocks (about seven blocks share an interval), so a burst shorter than a second is diluted; a finer sampler or per-thread data would be needed to exclude it. Lacking `nr_tlb_remote_flush`, the TLB shootdown count that jemalloc purges cause cannot be read directly; the CAL row, which carries them on this kernel, does not move with slow blocks.

Syscall table. `perf trace -s` is not possible here: `perf trace` fails with "No permissions to read /sys/kernel/tracing/events/raw_syscalls" (tracefs is root-only), `strace -p` fails under `kernel.yama.ptrace_scope=1` for a process the sampler did not start, `/proc/<pid>/syscall` is EPERM and `kptr_restrict=1` leaves perf without kernel symbols. There is therefore no per-syscall count or time. The TRACE leg instead ran `wchansample.py`: 200 sweeps at 10 Hz over every thread of the leader's execution layer from +2 s to +22 s of window 1, reading state and `wchan`. Of 313 threads on average, 289.5 sat in `futex_do_wait` (idle pool workers), 20.5 were running, 2.0 in `hrtimer_nanosleep`, 0.44 in `ep_poll`, and the only disk waits (state D) were 0.2 threads in all (`folio_wait_bit_common` 0.10, `rq_qos_wait` 0.07, `xlog_wait_on_iclog` 0.05). Runnable threads by family: tokio-rt 6.6, n42-build 4.4, the validator-path `n` threads 4.2, storage 3.0, build-on-own 0.6, shard-merge 0.4, jemalloc_bg_thd 0.3, persistence 0.2. No thread was sampled in `madvise`, `munmap`, `mmap` or `sched_yield` waits (none of these block; a sampler of blocked threads cannot count them), and the table cannot tell how often they are called or how long they spend on CPU. A syscall table needs root (tracefs permission) or launching the leader under `strace -c -f` from the launcher.

Persistence. The EL carries no per-batch log line, but the node's Prometheus metrics (summed over the leg, in the runner's `save stages` line) give `batch_size` and `duration_seconds` per batch: BASE 304 batches of 6.4 blocks at 0.69 s (total 211 s), BASEb 322 of 6.1 at 0.67 s, P32 79 of 13.7 at 2.48 s (total 196 s), NOSYNC 318 of 6.2 at 0.66 s (total 209 s). The summed persistence time is nearly the same (196-216 s a leg) in all four: raising the threshold makes fewer, longer batches, not less work, and the work that remains is roughly 0.1 s a block of save time of which RocksDB is 141 s of 164 s on BASE.

No judged leg passed the record of 1,226,047 (NOSYNC is 0.5% below it, within noise).

### 10.66 The elided answer (loop318): N42_TAKE_COMPACT=1 reads +6.9% / +4.6% on window 1 against the two BASE legs, both COMPACT legs above the record, but window 2 collapsed on one of two COMPACT legs and on COMPACTP90

Loop318 is measurement only (tip 8ead2883b, three nodes, one claim 03:27-04:00, the loop317 BASE configuration; derived with `scripts/fleet7-runs/derive318.py`; kernel sampler and TRACE dropped). Finding 11.7 said a third of blocks pay about 168 ms because the leader's execution layer encodes and writes a ~26 MB answer to its own proposer. Commit 206cc817e adds `N42_TAKE_COMPACT=1`: the answer carries no transaction bytes. The loop317 BASE line already set `N42_BODY_ONCE=1` and the bench exports `F7_DIRECT_PUSH=1`; the COMPACT legs add only `N42_TAKE_COMPACT=1 N42_COMPACT_BODY=1`. Legs: WARM (throwaway), BASE, COMPACT, BASEb, COMPACTb, COMPACTP90 (COMPACT at 90 ms pacing).

| leg | win1 | win2 | cycle mean / median / p90 | sealed_at median / p90 | fields median / p90 | imports >600 | el_max peak |
| --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (not judged) | 1,227,340 | 831,059 | 132.7 / 122.3 / 178.8 | 81 / 142 | 87 / 133 | 6 | 29.3 G |
| BASE | 1,177,180 | 906,348 | 138.0 / 122.2 / 199.9 | 78 / 146 | 88 / 150 | 4 | 30.1 G |
| COMPACT | 1,258,012 | 233,046 | 124.2 / 115.2 / 158.0 | 113 / 202 | 91 / 169 | 113 | 42.4 G |
| BASEb | 1,210,048 | 874,204 | 134.0 / 122.9 / 180.8 | 85 / 181 | 88 / 150 | 11 | 29.5 G |
| COMPACTb | 1,266,189 | 835,583 | 119.6 / 108.0 / 158.1 | 112 / 187 | 94 / 231 | 27 | 30.1 G |
| COMPACTP90 | 1,232,527 | 260,511 | 128.4 / 120.8 / 171.6 | 137 / 196 | 90 / 165 | 94 | 44.0 G |

(cycle, sealed_at and the answer split are window 1 of the leader; fields_ready is every follower import of the leg; sealed_at is the whole leg.) Correctness on every leg: verify passes, invalid_blocks, no_variant, own_not_committed, unanswered_reads, direct_imports_failed, incomplete, gas_mismatch and proposals_given_up all 0, tc=1, no ERROR or panic line in any node log. The `node3` cp/grep errors are the three-node fleet as before.

Judging. BASE and BASEb differ by 2.8% on window 1; both COMPACT legs are above both BASE legs by at least 4.0% (COMPACT +6.9% / +4.0%, COMPACTb +7.6% / +4.6%), so by the stated rule window 1 is a change upward. Window 1 on both COMPACT legs beats 1,226,047 (and COMPACTP90, 1,232,527, and also the WARM leg, 1,227,340, which ran the baseline configuration, so the margin over the record of the baseline itself is thin). No tag, `main` untouched. Window 2 is not a metric, but it fails the rule in the other direction: COMPACT 233k and COMPACTP90 261k against 874-906k on BASE, COMPACTb 836k (below both BASE legs). Imports over 600 ms are 113 and 94 on the two legs that collapsed, 27 on COMPACTb, 4-11 on BASE; el_max peaks 42-44 G on the collapsed legs against 30 G. Round totals: BASE 62.5M, BASEb 62.5M, COMPACTb 63.1M, but COMPACT 50.0M and COMPACTP90 49.4M. Two of three compact legs therefore lose most of window 2 and the cause is not identified here (the collapse starts about 135 s in, with the cycle median rising to 0.28-0.32 s); the fields_ready p90 is also higher on every COMPACT leg (165-231 ms against 150). A configuration that raises window 1 and loses window 2 on two of three runs is not adopted.

The answer split (window 1, median / p90 ms, from `answer_*_us` stamps; read = proposer read end minus write start, decode = decode end minus read end):

| leg | encode | write | read | decode | answer MB |
| --- | --- | --- | --- | --- | --- |
| BASE | 34.2 / 47.4 | 18.0 / 53.1 | 19.5 / 53.9 | 13.7 / 19.9 | 31.3 |
| BASEb | 33.9 / 46.1 | 15.4 / 42.6 | 16.4 / 43.6 | 13.7 / 20.6 | 31.3 |
| COMPACT | 4.3 / 7.1 | 1.9 / 9.1 | 2.0 / 8.7 | 0.7 / 1.8 | 5.2 |
| COMPACTb | 4.7 / 8.0 | 1.6 / 8.2 | 1.7 / 8.2 | 0.7 / 1.9 | 5.2 |
| COMPACTP90 | 4.9 / 8.0 | 1.8 / 7.1 | 1.8 / 6.7 | 0.7 / 1.7 | 5.2 |

The old "delivery" of 11.7 is write 15-18 ms plus decode 14 ms (read is the write seen from the other end); the answer was 31.3 MB with hashes, not 26. The elided answer is 5.2 MB (hashes and frame layout, no transactions) and encode falls 34 to 4.5 ms, write 16 to 1.7 ms, decode 14 to 0.7 ms. Every window-1 block on the COMPACT legs was elided.

Two modes (`scripts/fleet7-excess-anatomy.py`, fixed: since 206cc817e the EL line is logged after the write and `answer_write_start_us` marks the old boundary; `fleet7-depth-replay.py` now also accepts an elided body, `compact_bytes` over 5,000, as a full block when it finds the leader):

| leg | seal-trigger share / mean cycle | send-trigger share / mean cycle |
| --- | --- | --- |
| BASE | 63% / 115.1 ms | 37% / 177.7 ms |
| BASEb | 69% / 119.3 | 31% / 166.5 |
| COMPACT | 93% / 124.7 | 7% / 117.1 |
| COMPACTb | 92% / 120.4 | 8% / 110.5 |

The send-trigger mode (a build that starts at the previous send) is the slow one on BASE (167-178 ms) and nearly disappears on COMPACT (7-8% of blocks, 111-117 ms): the leader's own answer is back early enough that the next build starts at the seal. The cost moved: the seal-trigger blocks are slower (120-125 ms against 115-119) and `build` is now a segment of 6-7 ms mean (BASE 0.8), and sealed_at rises from 78-85 to 112-113 ms median. The mean excess over the tick falls from 34-38 to 20-24 ms, which is the window-1 gain; what is not explained is why the followers' check and the window 2 behave worse.

On-demand path (COMPACT / COMPACTb / COMPACTP90; grepped in the execution layers' logs for "own block's body served on demand" (OWN_BODY), "compact body: asking for the transactions" (the follower's fill, NEED_TXNS) and "compact body refused", and in the validators' logs for "elided block's body fetched from the execution layer"; the `block_by_hash` serving and miss lines are debug level and are not in the logs): OWN_BODY served 3 / 0 / 4, fill requests 3 / 0 / 4, refused 1 / 0 / 1, bodies fetched by a validator 3 / 0 / 4, against about 1,700-1,850 follower imports a leg. Followers do not ask the leader for full bodies on a meaningful share of blocks (under 0.3%); the one refusal in two legs was a follower that held 500 of 82,000 transactions of a block (the start of the leg, 81,500 missing). The `block_by_hash` misses cannot be counted from these logs.

#### 10.66 addendum (offline, loop318 logs): the collapse is node 0 as the ex-leader after the view-1024 handover, with its unpersisted blocks and its execution cost growing together

Method: `scripts/fleet7-runs/timeline318.py <tag>` (per 10 s since the first full build: blocks a node, leader, leader sealed_at / par_ms / state_ready_ms, import total_ms median/max per node, lag, `reader_lag` = canonical minus QMDB view head, `on_persisted` forest-lock warnings, RSS max, queue) and `segments318.py`; tables in `results/timeline-loop318.txt`. The persistence metrics, the in-memory block count and the RSS exist only as end-of-leg values or the runner's 5 s total (per-node RSS and a per-second unpersisted count are not logged; `reader_lag` every 64 blocks and the slow `on_persisted` lock warnings are the proxies).

1. Handover. In every leg node 0 leads views up to 1023 and node 1 takes over at view 1024: +110 s (COMPACT, P90), +107 s (COMPACTb), +119 s (BASEb) after the first full build. Window 2 therefore contains the handover on every leg; it is not what separates the legs.
2. What moves first (COMPACT, against BASEb and COMPACTb). The leader's build: node 0's `par_ms` / sealed_at is 159 / 163 ms in the bucket +100 s, 10 s before the handover (COMPACTb 119 / 122, BASEb 100 / 98); on COMPACTP90 it drifts up earlier (sealed_at 138 at +40 s, 164 at +70 s). After the handover node 0 is a follower and its import time departs at once and then grows steadily: median total_ms 260, 342, 350, 414, 578, 667, 812, 969 ... 1191 ms (every 10 s from +110 s), while node 2 stays at 140-200 ms; `exec_ms` of node 0's imports goes 70 to 565 ms and root 51 to 110 ms (COMPACTb and BASEb: 47-56 and 30-34, flat for the whole tail). The blocks a 10 s bucket fall 47, 41, 42, 38, 20, 17, 13 ... 9, i.e. the cycle follows node 0's import time (about 0.75 s at +170 s against node 0's 812 ms). The QMDB view lag of node 0 is 68 / 58 / 46 in +110..+130 against 28-37 on the other two, and 102 at the end; `on_persisted` lock warnings on node 0 are 11 / 10 / 8 per bucket after the handover against 1-4 elsewhere. Nothing else leads: RSS max rises 26 to 30 G at +107 s and to 42 G at the end while the minimum falls to 11 G (one node holds the memory; node 0 by the in-memory count below), queues are equal, node 2 and node 1 import times stay flat. So the collapse begins at none of "handover alone", "a memory level" or "a fixed unpersisted count": it starts as node 0's slower build and persistence in the last seconds of its tenure, and the handover turns node 0 into the slowest voter, whose import cost keeps growing.
   End-of-leg state per node (metrics): persisted batches, blocks a batch, wall a batch, blocks still in memory. COMPACT: node0 134 / 8.6 / 1.40 s / 157, node1 182 / 7.1 / 1.09 s / 8, node2 184 / 7.1 / 1.07 s / 8. COMPACTP90: node0 146 / 7.7 / 1.03 s / 171, others 190 / 6.8 / 1.0 s / 8-9. COMPACTb: 310 / 6.3 / 0.68 s / 8, 314 / 6.3 / 0.65 s / 6, 294 / 6.7 / 0.70 s / 8. BASEb 297 / 6.5 / 0.72 s / 8, 311 / 6.2 / 0.67 s / 7, 313 / 6.2 / 0.67 s / 7. Node 0 ends the two bad legs with 157 and 171 unpersisted blocks (backpressure is at its 1024 default, so nothing bounds this), the others and every other leg with 6-9.
3. COMPACTb against COMPACT. COMPACTb never grew: node 0's import stayed at 155-180 ms (exec 47-56 ms) after the handover, its view lag 16-46 like the others, 8 blocks in memory at the end, persistence 0.68 s a batch, RSS max 24-29 G and falling back. It had the same elided answers (5.2 MB), the same sealed_at (112 ms) and the same handover. What differed is only node 0's state at the handover; the logs do not show why (the per-node persistence time series is not logged), so the "grow and recover" case does not exist: it never grew.
4. The window-1 side effects (leader node 0, medians, ms; BASE / BASEb / COMPACT / COMPACTb): par_ms 74 / 77 / 102 / 100; of it `par_exec_ms` 29 / 29 / 31 / 30 (unchanged), `par_fold_ms` 15 / 13 / 9 / 9, and two segments that are zero on BASE appear: `parent_fields_ms` 0 / 0 / 30 / 28 and `sealed_ms` 7 / 8 / 38 / 37. `sealed_at_ms` 74 / 79 / 107 / 104, `state_ready_ms` 131 / 156 / 168 / 165, `total_ms` 229 / 262 / 295 / 289; roots, shard append and merge are unchanged. So the growth is the wait for the parent's fields (about 30 ms), not build exec, root or the parent's state. It overlaps the previous block's own import: `own block imported by header` has a median total of 91-106 ms on BASE and 111-114 ms on COMPACT (handoff 41 ms in both), and with 93% of builds now starting at the previous seal the build begins while that import is still running; the fields it waits for are the import's.
5. Most likely cause: node 0, the leader of the first 1024 views, is left with the unpersisted blocks and the state backlog of its own tenure; the elided leader finishes its tenure faster (cycle 124 against 138 ms) and carries more unpersisted blocks into the handover, and the unbounded in-memory depth (persistence backpressure 1024, `F7_PERSIST_BACKPRESSURE`) lets its follower execution cost grow without limit; the leader's straggler grace (`F7_STRAGGLER_GRACE_MS=600`) makes the new leader wait for that vote, so the cycle becomes node 0's import time. Evidence: only node 0 degrades (import, exec, root, view lag, lock warnings, 157/171 blocks in memory), on both legs that collapsed and on neither that did not, from the handover on; the first sign is node 0's slower build 10 s before it. What the logs do not prove is the mechanism (that exec cost grows with the in-memory depth) or why COMPACTb's node 0 was spared. Test on the fleet: COMPACT with `F7_PERSIST_BACKPRESSURE=32` (existing switch, `scripts/fleet7-env.sh`; the engine then stalls the leader's build instead of letting node 0 fall behind), two legs, bookended by BASEb-style legs; if node 0's in-memory count then stays under 40 and window 2 holds, the cause stands. A second discriminator that exists: `F7_STRAGGLER_GRACE_MS=0` shows whether the cycle was following node 0's vote. A per-node 5 s sampler of RSS and of `reth_blockchain_tree_in_mem_state_num_blocks` (scrape the metrics port during the leg) would need to be written and would settle the timing.

### 10.67 A bound on unpersisted blocks (loop319): the bound holds the count and prevents the collapse, but stalls the engine, forms timeout certificates and costs window 1

Loop319 is measurement only (tip a9a206408, three nodes, claim 04:26-05:00; derived with `derive319.py`). It tests the 10.66 addendum: COMPACT (`N42_TAKE_COMPACT=1 N42_COMPACT_BODY=1`) with `F7_PERSIST_BACKPRESSURE=32` and `=16` against the unbounded default of 1024. New sampler `memsample.py`: every 2 s, per execution-layer process, RSS from `/proc/<pid>/status` and, from the node's metrics port, `reth_blockchain_tree_in_mem_state_num_blocks` (in-memory blocks), `..._latest_block` and `..._earliest_block` (earliest minus 1 is the persisted height), `reth_consensus_engine_beacon_backpressure_active` and the stall histogram, into `strip-<tag>/mem.log`. Confirmed on the WARM leg: the names exist, the endpoints answer on 19300 + i, 126 samples a node.

How the bound works. `F7_PERSIST_BACKPRESSURE` becomes `--engine.persistence-backpressure-threshold`; in reth's engine loop (`should_backpressure`, tree/mod.rs) while a persistence cycle is running and the in-memory blocks minus the buffer target (6) reach the threshold, the loop stops draining the engine-message channel and waits for persistence only, so newPayload and forkchoiceUpdated (the leader's own-block import and the commit) are delayed instead of the builder being slowed; the only trace is the `backpressure_active` gauge and the stall histogram (no log line). A bound that stalls consensus messages shows up as timeouts, so `tc`, `proposals_given_up`, `own_not_committed` and idle engines are the counters to read, and the unbounded default was set to 1024 for this reason (loop146-147: 8-10 s stalls and a TC at a tenure change).

| leg | win1 | win2 | round txs | cycle mean / median / p90 | sealed_at median / p90 | fields median / p90 | imports >600 | peak RSS n0 / n1 / n2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (baseline, not judged) | 1,177,029 | 846,237 | 60.7M | 138.0 / 127.8 / 197.0 | 79 / 144 | 89 / 152 | 5 | 27.3 / 29.0 / 27.2 G |
| CBP32 | 1,038,438 | 950,761 | 84.0M | 127.4 / 115.9 / 171.7 | 105 / 159 | 87 / 115 | 13 | 26.5 / 25.4 / 24.8 G |
| COMPACT (control) | 1,263,755 | 184,416 | 47.7M | 120.8 / 111.4 / 153.9 | 112 / 195 | 92 / 179 | 130 | 47.1 / 26.5 / 26.3 G |
| CBP32b | 1,217,709 | 689,904 | 76.6M | 131.4 / 115.7 / 191.9 | 107 / 174 | 88 / 130 | 34 | 26.7 / 26.0 / 23.9 G |
| CBP16 | 979,795 | 613,912 | 72.8M | 130.4 / 108.1 / 204.0 | 77 / 118 | 84 / 135 | 14 | 24.2 / 24.6 / 23.8 G |
| COMPACTb (control) | 1,256,354 | 661,505 | 57.6M | 127.6 / 117.7 / 171.1 | 114 / 191 | 92 / 169 | 29 | 30.2 / 29.3 / 27.7 G |

(cycle, sealed_at in window 1 of the leader; the CBP16 window-1 anatomy has only 89 blocks because of its timeout certificates.) Correctness (verify passes on all legs; invalid_blocks, no_variant, direct_imports_failed, incomplete, gas_mismatch, unanswered_reads 0; no ERROR or panic line): tc / proposals_given_up / own_not_committed: WARM 1 / 0 / 0, CBP32 6 / 2 / 8, COMPACT 1 / 0 / 0, CBP32b 4 / 3 / 0, CBP16 7 / 3 / 7, COMPACTb 1 / 0 / 0; engine_idles_over_5s is 3 on CBP32 and CBP16.

In-memory blocks per node from `mem.log` (+t is seconds after the first full build; the handover is node 1's first proposal at view 1024: WARM +121 s, CBP32 +142, COMPACT +108, CBP32b +136, CBP16 +148, COMPACTb +110):

| leg | node 0: +60 s / handover / +150 s / end / max | node 1 | node 2 | backpressure stalls (total s) n0 / n1 / n2 |
| --- | --- | --- | --- | --- |
| WARM | 25 / 44 / 64 / 59 / 86 | 26 / 46 / 48 / 58 / 72 | 20 / 28 / 44 / 57 / 96 | 0 |
| CBP32 | 18 / 20 / 18 / 31 / 38 | 19 / 20 / 27 / 34 / 38 | 24 / 20 / 13 / 31 / 38 | 30 (15.5) / 22 (11.2) / 16 (6.4) |
| COMPACT | 42 / 56 / 77 / 176 / 176 | 40 / 66 / 8 / 9 / 66 | 29 / 37 / 10 / 10 / 59 | 0 |
| CBP32b | 37 / 12 / 6 / 16 / 38 | 38 / 12 / 6 / 18 / 38 | 38 / 11 / 6 / 16 / 38 | 30 (28.9) / 28 (13.0) / 31 (13.9) |
| CBP16 | 9 / 6 / 11 / 22 / 22 | 9 / 6 / 12 / 21 / 22 | 8 / 7 / 10 / 22 / 22 | 56 (28.0) / 33 (9.2) / 34 (10.1) |
| COMPACTb | 49 / 67 / 60 / 77 / 105 | 50 / 73 / 42 / 32 / 75 | 50 / 35 / 55 / 30 / 62 | 0 |

Answers.
- Did every bounded leg hold window 2? It avoided the collapse on all three (951k, 690k, 614k against the control's 184k), but only CBP32 matches the baseline (WARM 846k, loop318 BASE 874-906k); CBP32b and CBP16 are 18-27% below it, and the round totals (84.0M, 76.6M, 72.8M) are above every unbounded leg this round (47.7-60.7M).
- Did the unbounded control collapse? COMPACT did, as in loop318 (window 2 184k, 130 imports over 600 ms, node 0 at 176 blocks and 47.1 G, node 0's follower import after the handover 502 to 1274 ms, exec 178 to 734 ms; the same shape as loop318). COMPACTb did not collapse but started the same drift (node 0 import 179 to 448 ms, exec 49 to 131 ms, node 0 max 105 blocks, window 2 661k, 29 imports over 600 ms). Across both rounds 3 of the 5 unbounded COMPACT-type legs collapsed fully (loop318 COMPACT and COMPACTP90, loop319 COMPACT), one drifted (loop319 COMPACTb) and one was clean (loop318 COMPACTb).
- Did node 0's count stay under the bound? Yes, exactly: the maximum is 38 (= 32 + the buffer target 6) on every node of both CBP32 legs and 22 (= 16 + 6) on CBP16. The unbounded counts are not small even without a collapse: the baseline WARM leg reaches 86 / 72 / 96 blocks and does not collapse, so a large count by itself is not the failure; node 0 above about 100 with the follower import growing is (COMPACT 176, COMPACTb 105 and the loop318 legs 157 and 171).
- What did the bound cost on window 1? Both-legs rule against this round's controls (gap 7.4k, 1,256,354 / 1,263,755) and against loop318's COMPACT legs (1,258,012 / 1,266,189): CBP32 (1,038,438 / 1,217,709) is below both controls by 17.7% / 3.2% and CBP16 (979,795) by 22%, so the bound costs window 1 in the stated direction (CBP32 -3% to -18%, CBP16 -22%), and the record 1,226,047 is not reached by any bounded leg. The cost is not free elsewhere either: the bound stalled the engine 16-56 times a node, 6-29 s a leg, and the consensus counters moved (tc 4-7, proposals given up 2-3, own_not_committed 7-8 on CBP32 and CBP16, engine idle over 5 s on both), which is the failure the unbounded default was introduced to avoid. A tighter bound is worse (CBP16 below CBP32 on window 1 and on every counter).

Conclusion. The 10.66 cause is supported: bounding the unpersisted count removes the node-0 growth and the collapse, which an unbounded count does 3 of 5 times (a smaller drift on a fourth). But the bound as implemented is the wrong instrument (it stalls newPayload and forkchoiceUpdated for seconds, forms timeout certificates and costs 3-18% of window 1); the lever that is missing is one that slows the builder or the persistence lag at the source (persist earlier or in parallel on the ex-leader, or throttle the build when the count passes about 60) instead of stopping the engine loop. `F7_PERSIST_THRESHOLD` and `F7_BLOCK_BUFFER_TARGET` (8 and 6 now) are the existing switches for the persistence side; an in-node build throttle on `in_mem_state_num_blocks` would have to be written. Nothing here is a recommendation to change a default; no tag and `main` untouched.

### 10.68 Fields published at the seal (loop320): the wait is gone and the 80 ms is measured, window 1 does not gain, and FAS breaks the tenure handover

Loop320 is measurement only (claim 05:47-06:21; the first launch, 05:08, was aborted by the runner's "source file newer than the binary" gate because another session was editing `crates/storage/provider`; relaunched 05:27). Builds: the native binary the legs ran was built at 05:30 from the tree at about c861cdfa6, the test and deferred build at e81c44067; both contain 889ebfa80 (`N42_FIELDS_AT_SEAL`), and what came after it is the provider persistence modes (default off), the build throttle (not enabled, no `N42_BUILD_THROTTLE_*` set) and docs. Legs: WARM (baseline, throwaway), COMPACT (loop318 COMPACT, unbounded), FVERIFY (COMPACT + `N42_FIELDS_AT_SEAL=verify`), FAS (`=1`), COMPACTb, FASb; `memsample.py` on every leg. The leg header of each leg shows the variable in the execution layer's process environment (`FIELDS_AT_SEAL=verify` / `1`, `TAKE_COMPACT`, `COMPACT_BODY`).

| leg | win1 | win2 | round txs | cycle mean / median / p90 | sealed_at median / p90 | fields median / p90 | imports >600 | peak RSS n0 / n1 / n2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (baseline, not judged) | 1,137,482 | 857,267 | 59.9M | 142.3 / 128.2 / 201.3 | 78 / 154 | 89 / 154 | 6 | 28.4 / 29.4 / 26.0 G |
| COMPACT | 1,254,176 | 244,216 | 50.2M | 122.6 / 108.6 / 153.9 | 106 / 189 | 92 / 178 | 112 | 44.3 / 25.3 / 26.3 G |
| FVERIFY | 1,273,049 | 689,270 | 58.9M | 120.7 / 104.4 / 174.5 | 83 / 192 | 92 / 233 | 33 | 29.3 / 29.9 / 29.8 G |
| FAS | 1,221,215 | 191,294 | 47.1M | 130.7 / 110.5 / 201.9 | 85 / 202 | 94 / 190 | 5 | 29.8 / 30.4 / 30.3 G |
| COMPACTb | 1,234,480 | 352,734 | 53.2M | 130.2 / 118.7 / 181.8 | 111 / 196 | 93 / 178 | 99 | 42.7 / 27.3 / 28.2 G |
| FASb | 1,189,237 | 0 | 35.7M | 133.9 / 109.5 / 195.5 | 85 / 198 | 93 / 179 | 2 | 28.5 / 25.4 / 27.6 G |

Correctness (verify passes, no ERROR or panic line, invalid_blocks, no_variant, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads 0 on every leg). Consensus counters tc / own_not_committed / proposals_given_up / engine idles over 5 s: WARM 1 / 0 / 0 / 1, COMPACT 1 / 0 / 0 / 1, FVERIFY 1 / 0 / 0 / 1, FAS 9 / 18 / 0 / 9, COMPACTb 1 / 0 / 0 / 1, FASb 6 / 0 / 6 / 6. FVERIFY: `fields_verified` 1192, `fields_unchecked` 0, `fields_mismatches` 0 and no "published at the seal differ" line; the guard to stop the round did not fire.

Leader window 1, median / p90 (node 0; the first 30 s of full builds):

| leg | parent_fields_ms | sealed_ms | par_ms | par_exec_ms | roots_ms | rename_early | rename_wait_us |
| --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 0 / 47 | 8 / 57 | 73 / 133 | 29 / 35 | 35 / 65 | 0% | 29,082 / 62,823 |
| COMPACT | 19 / 49 | 28 / 56 | 96 / 137 | 31 / 38 | 35 / 57 | 0% | 43,407 / 62,325 |
| FVERIFY | 0 / 9 | 8 / 19 | 72 / 164 | 30 / 36 | 40 / 65 | 83% | 0 / 0 |
| FAS | 0 / 22 | 8 / 33 | 77 / 175 | 32 / 40 | 42 / 76 | 90% | 0 / 0 |
| COMPACTb | 20 / 55 | 29 / 64 | 100 / 150 | 32 / 39 | 37 / 60 | 0% | 45,614 / 68,253 |
| FASb | 0 / 13 | 8 / 22 | 79 / 182 | 32 / 39 | 41 / 72 | 88% | 0 / 0 |

`seal_to_*_us` (microseconds after the block's seal, median / p90):

| leg | finish | bundle | view | rename | root_start | root_end | fields |
| --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 16,004 / 22,116 | 16,252 / 22,448 | 17,085 / 23,562 | 51,447 / 94,989 | 51,596 / 95,157 | 83,408 / 134,072 | 85,634 / 147,863 |
| COMPACT | 12,131 / 15,496 | 12,511 / 16,073 | 13,251 / 16,683 | 59,304 / 83,172 | 59,778 / 83,340 | 95,812 / 120,999 | 98,304 / 130,808 |
| FVERIFY | 12,466 / 17,175 | 12,673 / 17,461 | 13,363 / 18,560 | 15,183 / 22,273 | 15,289 / 22,866 | 57,197 / 80,755 | 58,620 / 82,717 |
| FAS | 12,319 / 16,768 | 12,623 / 17,029 | 13,316 / 18,055 | 15,399 / 27,958 | 15,677 / 28,057 | 58,398 / 90,573 | 60,321 / 117,331 |
| COMPACTb | 11,948 / 15,816 | 12,340 / 16,254 | 13,140 / 17,333 | 63,352 / 95,819 | 63,858 / 96,498 | 100,504 / 130,893 | 103,846 / 134,704 |
| FASb | 12,424 / 17,402 | 12,718 / 17,707 | 13,460 / 18,665 | 15,467 / 24,534 | 15,660 / 24,639 | 56,716 / 79,649 | 59,144 / 101,250 |

What the 80 ms is made of (COMPACT, the direct measurement of what 11.8 inferred; fields are published 98 ms after the seal): 12 ms until the finish starts (the finish waits behind the seal's own work), under 1 ms for the bundle and 1 ms for the shard view, then the rename of the parent's tree at 59 ms, of which 43 ms is `rename_wait_us`, the wait for the parent's `Complete` and the rename itself about 3 ms; the QMDB root job starts at once and runs 36 ms (59.8 to 95.8) and publishing the fields takes 2.5 ms. So the gap is 12 ms of finish start, 43 ms of waiting for the parent's `Complete`, 36 ms of root job and a few ms of bookkeeping. With the switch on the wait is 0 and the rename is done 15 ms after the seal (90% of blocks early); the root job then runs 15.7 to 58.4 ms (43 ms, 7 ms longer than on COMPACT because it overlaps the bundle's merge) and the fields are published 60 ms after the seal on FAS and 58 ms on FVERIFY: 38-40 ms earlier. The build sees it: `parent_fields_ms` 19 / 20 to 0, `sealed_ms` 28 / 29 to 8, `par_ms` 96 / 100 to 77 / 79, sealed_at median 106 / 111 to 85 / 85 ms.

Judging window 1 (both-legs rule, FAS and FASb against COMPACT and COMPACTb; the controls differ by 19.7k, 1.6%): FAS 1,221,215 and FASb 1,189,237 are both below both controls, but FAS is only 12.3k (1.0%) below COMPACTb, inside the control gap, so the rule is not met: no change on window 1, and not an improvement in any reading (the direction is down, 2.6% to 5.2%). FVERIFY (single leg, early path plus the late derivation behind Complete) reads 1,273,049, above both controls by 1.5% / 3.1%, and the controls and FVERIFY are above the record 1,226,047; FAS and FASb are not. The cycle did not follow the 21 ms earlier seal: the median stays 109-111 ms (the 100 ms tick plus the same sends) and the p90 is worse on FAS (202 against 154 / 182).

Window 2 (reported, not judged): the unbounded COMPACT legs collapsed again (244k and 353k; node 0 ends at 154 and 150 in-memory blocks and 44.3 / 42.7 G, 112 and 99 imports over 600 ms; with the earlier rounds 5 of 7 unbounded COMPACT-type legs have collapsed). The FAS legs did not grow node 0's count (in-memory blocks +60 s / handover / +150 s / end / max: FAS 59 / 46 / 8 / 11 / 59, FASb 46 / 33 / 6 / 33 / 65; FVERIFY 46 / 45 / 26 / 41 / 69; COMPACT 43 / 56 / 84 / 154 / 154; COMPACTb 33 / 44 / 80 / 150 / 150; WARM 44 / 35 / 69 / 66 / 91) and have 5 and 2 imports over 600 ms, but they fail in a different way, at the tenure handover: both FAS legs form timeout certificates on node 1 from its first views as leader (FAS: views 1026, 1052, 1075, 1103, ... 9 TCs and 18 own blocks not committed; FASb: views 1029, 1030, 1031, 1032, 1033, one every 30 s, node 1 never gets a block committed after the handover, window 2 is 0, 6 proposals given up). The first lines on node 1 in FASb, within 0.6 s of the handover: "forkchoice to a committed block failed ... Too deep reorg", "our own execution layer would not take the block we built ... no longer holds own block 1025", "the build prepared ahead failed; building now ... build on the sealed block refused", then "forkchoiceUpdated returned no payload id (status Syncing)" for every view; the execution layer logs "Sidechain block not found in TreeState". COMPACT and FVERIFY, with the same wait removed in verify's early path, handed over without a TC (tc 1). The cause of the FAS handover failure is not established here; FVERIFY (which also renames early) did not show it, so the difference between `1` and `verify` (the late derivation behind Complete) is the first place to look, and the node-1 execution layer's tree state at the handover (the follower's filed parents against the early rename) is the second.

Conclusion. The gap is what 11.8 inferred (the wait for the parent's `Complete`, 43 ms, plus a 36 ms root job); `N42_FIELDS_AT_SEAL=1` removes the wait and publishes the fields about 38 ms earlier, which shortens the leader's seal by 21 ms and removes node 0's count growth, but does not shorten the cycle on this configuration, and it breaks the handover to the next leader on both FAS legs. It is not a candidate for a default; `verify` ran clean on 1,192 blocks with no mismatch, so the early values are right and the defect is in how the handover consumes them.

### 10.69 The leader build throttle (loop321): it keeps the leader's count under HARD and costs nothing at 48/80, but the collapse moves to the follower side, and the first per-phase persistence measurement points at the QMDB persist

Loop321 is measurement only (tip 2e4b29db9 at launch, one launch, claim 06:43-07:16; derived with `derive321.py`). The throttle (commits 35c9d1155..f5fbbf42b, default off) runs in the validator: it polls its execution layer's `n42Engine_inMemoryBlocks` every 50 ms and defers its proposal by `pacing * (n - SOFT) / (HARD - SOFT)` in the soft band and holds it up to 2 s at HARD. The variables reach the validator the way `N42_TAKE_COMPACT` did: the leg line's environment is inherited by every process the fleet script starts (nothing in `fleet7-env.sh` passes them); each leg header now prints the validator process's environment, which shows `N42_BUILD_THROTTLE_SOFT/HARD` on the throttled legs and only `N42_COMPACT_BODY` and `N42_TAKE_COMPACT` on the controls, and the validators log "build throttle: soft 48 hard 80 max hold 2000 ms". No fields-at-seal, no reth backpressure, no persistence switches. Legs: WARM (baseline, throwaway), T4880 (COMPACT + SOFT 48 HARD 80), COMPACT (control), T4880b, T3264 (SOFT 32 HARD 64), COMPACTb. All six fit in the claim.

| leg | win1 | win2 | win3 | round txs | cycle mean / median / p90 | sealed_at | fields | imports >600 | peak RSS n0 / n1 / n2 | tc / own_not_committed / given_up | idles >5 s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 1,188,176 | 906,397 | 0 | 62.9M | 137.3 / 125.6 / 192.3 | 79 / 148 | 88 / 149 | 12 | 26.9 / 29.7 / 26.8 G | 1 / 0 / 0 | 1 |
| T4880 | 1,266,012 | 749,318 | 0 | 60.5M | 125.6 / 115.6 / 159.6 | 111.5 / 183 | 91 / 211 | 16 | 28.0 / 28.4 / 29.8 G | 1 / 0 / 0 | 1 |
| COMPACT | 1,254,361 | 814,348 | 0 | 62.1M | 127.7 / 119.7 / 172.1 | 114 / 190 | 92 / 174 | 10 | 27.9 / 38.9 / 27.8 G | 1 / 0 / 0 | 1 |
| T4880b | 1,280,039 | 367,190 | 173,599 | 54.7M | 125.2 / 114.5 / 167.3 | 110 / 186 | 90 / 156 | 93 | 44.1 / 26.6 / 25.4 G | 1 / 0 / 0 | 1 |
| T3264 | 1,219,064 | 868,467 | 0 | 62.7M | 132.2 / 117.4 / 175.9 | 103 / 187 | 93 / 153 | 7 | 29.0 / 27.9 / 27.0 G | 1 / 0 / 0 | 1 |
| COMPACTb | 1,254,091 | 265,926 | 189,426 | 51.3M | 120.5 / 105.7 / 167.5 | 113 / 192 | 93 / 182 | 102 | 42.8 / 28.2 / 26.6 G | 1 / 0 / 0 | 1 |

(Window 3 is 0 where the flood had ended, and non-zero only on the two legs whose chain was still behind; cycle and sealed_at are window 1 of the leader.) Correctness on every leg: verify passes, invalid_blocks, no_variant, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads 0, no ERROR or panic line.

Throttle per leg (leader tenures only; node 2 never leads, with 29-115 proposals in the empty tail):

| leg | leader | proposals | delayed | delay when applied median / p90 | total delay | hard holds | max-hold WARN | in_mem at proposals median / p90 / max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T4880 | node 0 | 1023 | 143 (14%) | 17 / 41 ms | 2.9 s | 0 | 0 | 34 / 51 / 68 |
| T4880 | node 1 | 1024 | 118 (12%) | 17 / 48 ms | 2.5 s | 0 | 0 | 8 / 49 / 69 |
| T4880b | node 0 | 1023 | 195 (19%) | 26 / 61 ms | 5.9 s | 0 | 0 | 34 / 55 / 75 |
| T4880b | node 1 | 406 | 55 (14%) | 22 / 42 ms | 1.2 s | 0 | 0 | 31 / 51 / 65 |
| T3264 | node 0 | 1023 | 425 (42%) | 29 / 67 ms | 14.9 s | 1 | 0 | 29 / 47 / 63 |
| T3264 | node 1 | 1024 | 448 (44%) | 51 / 88 ms | 24.4 s | 6 | 0 | 8 / 55 / 63 |

In-memory blocks per node from `mem.log` (+60 s / handover / +150 s / end / max; handover at +120 / +110 / +111 / +106 / +111 / +108 s):

| leg | node 0 | node 1 | node 2 |
| --- | --- | --- | --- |
| WARM | 34 / 47 / 44 / 62 / 66 | 27 / 33 / 40 / 58 / 79 | 27 / 41 / 43 / 35 / 63 |
| T4880 | 48 / 40 / 38 / 41 / 68 | 28 / 38 / 45 / 42 / 67 | 45 / 40 / 78 / 78 / 86 |
| COMPACT | 39 / 28 / 35 / 15 / 66 | 44 / 53 / 76 / 85 / 139 | 46 / 57 / 47 / 17 / 68 |
| T4880b | 55 / 70 / 65 / 159 / 159 | 32 / 48 / 31 / 8 / 56 | 51 / 44 / 27 / 8 / 58 |
| T3264 | 32 / 57 / 65 / 44 / 69 | 42 / 38 / 44 / 50 / 63 | 34 / 38 / 61 / 31 / 67 |
| COMPACTb | 33 / 69 / 88 / 148 / 148 | 36 / 43 / 18 / 10 / 64 | 35 / 52 / 25 / 10 / 63 |

Answers.
- Did every throttled leg hold windows 2 and 3 without TCs or given-up proposals? No TCs and no given-up proposals on any leg (tc 1 everywhere, given_up 0, own_not_committed 0, idles over 5 s 1), but T4880b collapsed anyway (window 2 367k, window 3 174k, 93 imports over 600 ms, node 0 ends at 159 in-memory blocks and 44.1 G); T4880 (749k) and T3264 (868k) held, T3264 with 7 imports over 600 ms. Of the controls COMPACTb collapsed (266k / 189k, node 0 at 148) and COMPACT did not (814k), so the unbounded legs have collapsed 5 of 8 times over the four rounds and the 48/80 throttle 1 of 2.
- Did the count stay under HARD? At every proposal, yes: the largest in-memory count a leader proposed at is 69 (T4880 against 80), 75 (T4880b against 80) and 63 (T3264 against 64; 7 hard holds, none reaching the 2 s cap). It did not stay under HARD on the node that was not proposing: T4880b node 0 climbs to 159 after the handover, when it is a follower and the throttle has nothing to defer, and T4880's node 2, which never leads, ends at 78 and peaks at 86. The throttle bounds the leader's production, not a follower's backlog, and the collapse is a follower-side effect (node 0's follower import after the handover: T4880b 188 to 1197 ms, exec 49 to 613 ms, root 34 to 121 ms; T3264 flat at 146-162 ms).
- What did the throttle cost on window 1? T4880 (1,266,012) and T4880b (1,280,039) are above both of this round's controls (1,254,361 / 1,254,091, a gap of 0.3k) by 0.9% to 2.1%: same direction, more than the control gap, so by the stated rule the 48/80 throttle did not cost window 1 and read slightly higher; against the earlier unbounded COMPACT legs (loop318 1,258,012 / 1,266,189; loop319 1,263,755 / 1,256,354; loop320 1,254,176 / 1,234,480) T4880 is not outside their spread (it is below 1,266,189), so no gain is claimed. T4880b is the highest window 1 so far and above 1,226,047 by 4.4%. T3264 (1,219,064, 14.9 s and 24.4 s of delay in a 1,024-block tenure) is 2.8% below both controls: the tighter band costs window 1 in the stated direction and is below the record.
- Does the round total beat the unbounded and the reth-backpressure legs? No. T4880 60.5M, T4880b 54.7M and T3264 62.7M are about the baseline's 62.9M and the healthy control's 62.1M and above the collapsed controls (51.3M), but below loop319's backpressure legs (84.0M, 76.6M, 72.8M), which paid for their totals with engine stalls and timeout certificates (loop319's windows 2 and 3 were still producing at the end; here, on a leg that does not collapse, window 3 is 0 because the flood has ended).

The first per-phase persistence measurement (`save_blocks_*` from each node's metrics file at the end of the leg; every phase is in `results/analysis-loop321.txt`; ms per batch / ms per persisted block, the batch counting every block it wrote including the idle tail):

| phase | COMPACT node 0 (healthy) | COMPACT node 1 | COMPACTb node 0 (collapsed) | COMPACTb node 1 |
| --- | --- | --- | --- | --- |
| engine `save_blocks` total | 729 / 113 | 833 / 115 | 1,394 / 158 | 1,115 / 153 |
| database total | 573 / 89 | n/a | 1,175 / 133 | 908 / 124 |
| scope (backend writes) | 503 / 78 | n/a | 867 / 99 | 765 / 105 |
| RocksDB write | 500 / 78 | n/a | 784 / 89 | 763 / 104 |
| static files (all) | 301 / 47 | n/a | 426 / 48 | 483 / 66 |
| static files, transactions | 212 / 33 | n/a | 396 / 45 | 302 / 41 |
| account-history map (reads + batch) | 195 / 30 | n/a | 377 / 43 | 240 / 33 |
| commit RocksDB (2 commits a batch) | 109 / 17 | n/a | 170 / 19 | 182 / 25 |
| account changesets (static file) | 74 / 11 | n/a | 143 / 16 | 104 / 14 |
| receipts (static file) | 70 / 11 | n/a | 131 / 15 | 104 / 14 |
| post scope = QMDB persisted | 61 / 9.5 | 167 / n/a | 373 / 42 | 129 / 18 |
| senders (static file) | 42 / 6.6 | n/a | 77 / 8.8 | 62 / 8.4 |

The dominant phases are the RocksDB write (500-785 ms of a 729-1,394 ms batch, of which the account-history map is 195-377 ms and the transactions' static file 212-396 ms) and, on the nodes that drift, the QMDB persist after the scope. `post_scope` (= `qmdb_persisted`) in ms a batch per node: WARM 65 / 63 / 61, T4880 61 / 58 / 90, COMPACT 61 / 167 / 72, T4880b 226 / 130 / 132, T3264 53 / 55 / 56, COMPACTb 373 / 129 / 122, and 407 on the collapsed node 0 of loop320's COMPACT and 373-407 in loop319's. The nodes that ended with 148-159 blocks in memory (node 0 of T4880b, COMPACTb, loop320 COMPACT) are exactly the ones whose QMDB persist runs at 226-407 ms a batch against 53-72 on a healthy node; COMPACT's node 1 (167 ms, 139 blocks at its peak, no collapse) sits in between. So the follower import's growth after a handover tracks a QMDB persist that has become 4-7 times slower on that node, which the bound on the leader's count (T3264: 53-56 ms on every node, no collapse) keeps from happening but a 48/80 band does only some of the time.

Conclusion. The throttle does what it was written to: no timeout certificate, no given-up proposal, the leader never proposes above HARD, no max hold reached, and at 48/80 it costs no window 1. It does not remove the collapse by itself at 48/80 (T4880b), because the node that collapses is the follower after the handover, whose in-memory count the leader's throttle does not govern; at 32/64 it held every window but cost 2.8% of window 1 and about 40 s of delay. The next measurement this points at is the QMDB persist (`post_scope`, 61 ms a batch healthy against 226-407 ms on the drifting node): what slows it on a node that carries 100+ unpersisted blocks (its state-trie overlay depth against the backend commit) is not shown by these counters. No default is changed; no tag, `main` untouched.

### 10.70 The persistence switches (loop322): account-history off removes the RocksDB write and puts window 1 on the tick; the QMDB-in-scope switch alone does nothing visible

Loop322 is measurement only (tip cfcf8e38b at launch; the native binary built 07:22, the test build 6584e49ec 07:37; one launch, claim 07:38-08:16; derived with `derive322.py`). CTRL is loop321's T4880 line (COMPACT + build throttle SOFT 48 HARD 80). The switches are read by the execution layer; the leg header shows them in the EL process environment: `N42_PERSIST_QMDB_IN_SCOPE=1` on QSCOPE, BOTH and BOTHb, `N42_ACCOUNT_HISTORY=off` on AHOFF, BOTH and BOTHb (the validator header shows only the throttle and compact variables). Legs: WARM (baseline, throwaway), CTRL, QSCOPE (+ `N42_PERSIST_QMDB_IN_SCOPE=1`), AHOFF (+ `N42_ACCOUNT_HISTORY=off`), BOTH, CTRLb, BOTHb; all seven fit in the claim.

| leg | win1 | win2 | win3 | round txs | cycle mean / median / p90 | sealed_at | fields | imports >600 | peak RSS n0 / n1 / n2 | tc / own_not_committed / given_up | idles >5 s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 1,219,762 | 911,378 | 0 | 64.0M | 133.2 / 120.5 / 181.8 | 79.5 / 132 | 87 / 150 | 6 | 26.9 / 29.2 / 28.3 G | 1 / 0 / 0 | 1 |
| CTRL | 1,271,975 | 297,157 | 281,740 | 55.5M | 120.0 / 110.1 / 152.8 | 109 / 192 | 89 / 154 | 2 | 28.3 / 28.0 / 27.9 G | 7 / 17 / 0 | 6 |
| QSCOPE | 1,261,727 | 912,741 | 0 | 65.2M | 127.7 / 116.8 / 175.6 | 106 / 196 | 96 / 171 | 10 | 30.8 / 28.9 / 27.1 G | 1 / 0 / 0 | 1 |
| AHOFF | 1,290,474 | 1,108,337 | 0 | 72.0M | 102.5 / 101.5 / 109.1 | 63 / 108 | 77 / 126 | 0 | 35.8 / 29.3 / 28.1 G | 1 / 0 / 0 | 1 |
| BOTH | 1,292,375 | 1,070,323 | 0 | 70.9M | 103.3 / 101.7 / 111.7 | 74 / 167 | 82 / 167 | 0 | 24.5 / 24.5 / 23.3 G | 1 / 0 / 0 | 1 |
| CTRLb | 1,260,774 | 471,947 | 276,146 | 60.3M | 127.4 / 118.2 / 168.6 | 114 / 191 | 92 / 172 | 105 | 39.6 / 26.0 / 24.9 G | 1 / 0 / 0 | 1 |
| BOTHb | 1,290,541 | 1,135,509 | 0 | 72.8M | 103.3 / 101.6 / 109.2 | 70 / 125 | 79 / 143 | 2 | 26.4 / 26.5 / 25.0 G | 1 / 0 / 0 | 1 |

Correctness on every leg: verify passes (the AHOFF, BOTH and BOTHb verify files: three nodes, no disagreements, all advanced, pass true), invalid_blocks, no_variant, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads, proposals_given_up 0, no ERROR or panic line. Throttle (leader tenures, delayed share / total delay / hard holds): CTRL node 0 15% / 4.3 s / 0, node 1 2% / 5.0 s / 0; QSCOPE 2% / 0.3 s and 14% / 3.8 s; AHOFF 0% and 0.0 s; BOTH 0% and 0.3 s (one 345 ms delay); CTRLb 9% / 2.6 s and 1% / 0.0 s; BOTHb 0% and 0.1 s; no hard hold and no max-hold WARN on any leg.

In-memory blocks per node (+60 s / handover / +150 s / end / max; handover at +121 / +105 / +109 / +79 / +86 / +110 / +80 s):

| leg | node 0 | node 1 | node 2 |
| --- | --- | --- | --- |
| WARM | 48 / 6 / 45 / 47 / 63 | 28 / 6 / 54 / 33 / 72 | 41 / 6 / 50 / 52 / 79 |
| CTRL | 32 / 50 / 11 / 41 / 72 | 33 / 55 / 11 / 38 / 68 | 36 / 55 / 12 / 20 / 65 |
| QSCOPE | 28 / 43 / 39 / 44 / 74 | 33 / 31 / 44 / 63 / 64 | 24 / 30 / 26 / 52 / 60 |
| AHOFF | 9 / 11 / 11 / 14 / 14 | 10 / 9 / 9 / 9 / 11 | 10 / 9 / 10 / 13 / 13 |
| BOTH | 9 / 10 / 10 / 9 / 13 | 9 / 9 / 9 / 9 / 11 | 8 / 9 / 10 / 9 / 11 |
| CTRLb | 44 / 53 / 86 / 135 / 135 | 47 / 34 / 31 / 8 / 60 | 34 / 40 / 19 / 8 / 55 |
| BOTHb | 8 / 9 / 8 / 7 / 12 | 10 / 8 / 8 / 8 / 11 | 10 / 9 / 9 / 9 / 11 |

(The WARM handover column reads 6 on every node, a sample taken just after a persistence batch; the other legs' values are as in earlier rounds.)

Persistence phases per leg and node (metrics files; the batches, then ms per batch / ms per FULL block for the phases that matter; "full" = a persisted block that carried transactions, counted as the node's "Block added to canonical chain" lines with txs > 0, unique numbers, below the metrics' earliest in-memory block, i.e. those already written; empty blocks of the idle tail are in the batches but not in the divisor). Every phase is in `results/analysis-loop322.txt`.

| leg, node | batches (blocks / full per batch) | engine total | db total | scope | RocksDB write | account-history map | static files | commit RocksDB | post_scope | `qmdb_persisted` call |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM n0 | 302 (6.3 / 3.9) | 690 / 175 | 535 / 136 | 465 / 118 | 463 / 118 | 167 / 42 | 307 / 78 | 112 / 29 | 61 / 15.6 | 61 / 15.6 |
| CTRL n0 | 251 (5.9 / 4.7) | 642 / 136 | 504 / 106 | 446 / 94 | 445 / 94 | 170 / 36 | 277 / 59 | 113 / 24 | 48 / 10.1 | 48 / 10.1 |
| CTRL n1 | 254 (5.8 / 4.7) | 634 / 134 | 503 / 106 | 443 / 93 | 442 / 93 | 171 / 36 | 255 / 54 | 116 / 24 | 52 / 10.9 | 52 / 10.9 |
| CTRL n2 | 257 (5.7 / 4.7) | 621 / 132 | 490 / 104 | 430 / 92 | 429 / 91 | 158 / 34 | 256 / 54 | 116 / 25 | 52 / 11.1 | 52 / 11.1 |
| QSCOPE n0 | 348 (5.9 / 3.4) | 576 / 168 | 418 / 122 | 410 / 120 | 407 / 119 | 156 / 46 | 246 / 72 | 100 / 29 | 0 | 87 / 25.3 |
| QSCOPE n1 | 348 (5.9 / 3.4) | 554 / 162 | 432 / 126 | 425 / 124 | 422 / 123 | 154 / 45 | 267 / 78 | 105 / 31 | 0 | 90 / 26.2 |
| QSCOPE n2 | 361 (5.7 / 3.3) | 534 / 162 | 413 / 125 | 406 / 123 | 403 / 122 | 136 / 41 | 248 / 75 | 103 / 31 | 0 | 86 / 25.9 |
| AHOFF n0 | 710 (3.1 / 1.9) | 182 / 97 | 131 / 69 | 84 / 44.5 | 0 / 0.2 | 0 | 84 / 44.5 | 0 / 0.2 | 41 / 21.8 | 41 / 21.8 |
| AHOFF n1 | 729 (3.0 / 1.8) | 135 / 73 | 125 / 68 | 84 / 45.6 | 0 / 0.3 | 0 | 84 / 45.6 | 0 / 0.1 | 35 / 19.0 | 35 / 19.0 |
| AHOFF n2 | 725 (3.0 / 1.8) | 135 / 73 | 126 / 68 | 82 / 44.7 | 0 / 0.2 | 0 | 82 / 44.6 | 0 / 0.2 | 37 / 20.1 | 37 / 20.1 |
| BOTH n0 | 691 (3.0 / 1.9) | 181 / 97 | 123 / 66 | 117 / 62.6 | 1 / 0.4 | 0 | 91 / 48.8 | 0 / 0.2 | 0 | 71 / 37.9 |
| BOTH n1 | 699 (3.0 / 1.8) | 136 / 74 | 125 / 68 | 118 / 64.0 | 1 / 0.4 | 0 | 92 / 49.7 | 0 / 0.2 | 0 | 71 / 38.6 |
| BOTH n2 | 698 (3.0 / 1.8) | 136 / 73 | 127 / 69 | 120 / 64.8 | 1 / 0.4 | 0 | 90 / 49.0 | 0 / 0.2 | 0 | 73 / 39.7 |
| CTRLb n0 | 138 (9.4 / 7.5) | 1508 / 200 | 1268 / 169 | 940 / 125 | 874 / 116 | 395 / 52 | 496 / 66 | 179 / 24 | 378 / 50.2 | 378 / 50.2 |
| CTRLb n1 | 209 (6.8 / 5.6) | 1111 / 199 | 909 / 163 | 769 / 138 | 768 / 138 | 217 / 39 | 512 / 92 | 177 / 32 | 126 / 22.6 | 126 / 22.6 |
| CTRLb n2 | 212 (6.7 / 5.5) | 1090 / 198 | 896 / 163 | 759 / 138 | 757 / 138 | 212 / 39 | 498 / 90 | 172 / 31 | 124 / 22.5 | 124 / 22.5 |
| BOTHb n0 | 717 (3.0 / 1.9) | 168 / 91 | 114 / 62 | 108 / 58 | 1 / 0.4 | 0 | 86 / 47 | 0 / 0.2 | 0 | 60 / 32 |
| BOTHb n1 | 723 (3.0 / 1.8) | 124 / 68 | 114 / 62 | 107 / 58 | 0 / 0.3 | 0 | 86 / 47 | 0 / 0.2 | 0 | 58 / 32 |
| BOTHb n2 | 724 (3.0 / 1.8) | 119 / 65 | 110 / 60 | 103 / 56 | 0 / 0.2 | 0 | 87 / 48 | 0 / 0.1 | 0 | 54 / 29 |

Answers.
- What does each switch remove? `N42_ACCOUNT_HISTORY=off` removes the whole RocksDB write from the batch: 442 ms a batch (93 ms a full block) of RocksDB write, of which the account-history map was 171 ms (36 ms a full block), and the RocksDB commit (116 ms a batch, 24 ms a full block); the scope's critical path then becomes the static files, 84 ms a batch against 443, and the database total falls from 503 ms a batch (106 per full block) to 125 (68), the engine's `save_blocks` from 634 ms a batch (134 per full block) to 135 (73) on nodes 1 and 2 (node 0: 182 and 97). That is 38 ms a full block off the database time and 61 off the engine's, against the study's estimate of ~78 for the index: the index's own write (map plus commit, 60 ms a full block) is smaller than the study's figure and what is left behind it is the static files (46 ms a full block, mostly transactions), which were hidden under the longer RocksDB task. `N42_PERSIST_QMDB_IN_SCOPE=1` alone removes the 52 ms a batch of `post_scope` (11 ms a full block, close to the study's up to 19) from the end of the batch, but the callback now runs in the scope beside the writes and takes 86-90 ms (26 ms a full block) instead of 52, the database total falls by about 70 ms a batch (503 to 413-432) and the engine's by 60-90 (634 to 534-576); the batches are also more numerous (348 against 251-254) and smaller, so the persistence wall a full block does not fall (162-168 against 132-136, a count of full blocks that is an artefact of how many blocks each batch holds): no visible effect from this switch alone. With both, the callback (71 ms a batch) still runs inside the scope but behind nothing: the scope is 117 ms a batch.
- Is persistence per full block now under the chain's cycle? Yes with `ACCOUNT_HISTORY=off`: 73 ms a full block on nodes 1 and 2 and 91-97 on node 0 (engine total), against a cycle of 102 ms; with the history index on it is 132-200 against a cycle of 110-127, which is the unbounded growth of the earlier rounds.
- Drift and collapse: no count passes 100 on any switch leg (maxima: AHOFF 14, BOTH 13, BOTHb 12, QSCOPE 74); the unbounded-style control CTRLb collapsed (window 2 472k, window 3 276k, 105 imports over 600 ms, node 0 at 135 in-memory blocks and 39.6 G), with `post_scope` 378 ms a batch on node 0 against 126 and 124 on nodes 1 and 2: the signature of loop321 again. CTRL (with the throttle) held its count (max 72) and its window 2 and 3 are low (297k, 282k) for a different reason, see below. `post_scope`, ms a batch, per node 0 / 1 / 2: WARM 61 / 70 / 63, CTRL 48 / 52 / 52, CTRLb 378 / 126 / 124, AHOFF 41 / 35 / 37, `qmdb_persisted` call on BOTH 71 / 71 / 73 and BOTHb 60 / 58 / 54 (no node near 4-7 times slower). Switch legs: windows 2 at 1.07-1.14M, window 3 0, 0-2 imports over 600 ms.
- Window 1 (both-legs rule against CTRL 1,271,975 and CTRLb 1,260,774, gap 11.2k): BOTH 1,292,375 and BOTHb 1,290,541 are above both by 1.6% / 2.5% and 1.5% / 2.4%, and AHOFF 1,290,474 likewise: a change upward, and the highest window 1 so far (above loop321's 1,280,039 and the record 1,226,047 by 5.3%). The blocks per 30 s window are 291-293 and the cycle median 101.5-101.7 ms: window 1 is now bounded by the 100 ms pacing tick, not by the chain's work (sealed_at 63-74 ms, fields 77-82 ms). QSCOPE (1,261,727) is below CTRL by 0.8% and above CTRLb by 0.1%: no change.
- Sanity for AHOFF (logs only, nothing started): every node logs, once at start, "N42_ACCOUNT_HISTORY=off: the AccountsHistory index is not written; account changesets are, and historical account reads above the gap scan them" and "AccountsHistory index missing from this block on first_block=1"; no ERROR or panic line on any leg, no error from a historical read or a healing step (the only "Healing static file inconsistencies" line is the normal startup `check_consistency`, three times on every leg including the controls, and three "Failed to build global thread pool" WARN lines at start on every leg), the verify check passes, and the marker name `N42AccountHistoryGap` appears in no log (it is a stage-checkpoint row, written without a log line). The datadirs were not opened.

A finding for the handover defect of 10.68: CTRL, which has the throttle and no fields-at-seal, formed seven timeout certificates from node 1's first views as leader (views 1027, 1058, 1063, then 1301, 1359, 1362 later), with 17 own blocks not committed and 6 engine idles over 5 s, and node 1's validator logs the same "Too deep reorg" forkchoice failure and "build on the sealed block refused" lines as the FAS legs of loop320. So the handover failure is not specific to `N42_FIELDS_AT_SEAL=1`; it shows up on a COMPACT leg with the throttle (one of three CTRL-type legs of the last two rounds), so loop320's two FAS failures need re-reading against that base rate. It did not occur on any of the three AHOFF/BOTH legs, whose handovers came at +79-86 s.

### 10.71 The offer above the tick (loop323): full blocks at 1.40-1.42M on window 1, the chain's cycle for a 163k block is ~110 ms whatever the pacing

Loop323 is measurement only (launcher started at tip 5158351bb, which has a504b9fdf and cfcf8e38b; the binaries were built from the tree at 08:27 (native) and 08:43 (`beed93504+tree`); the test gate ran `-p n42 --lib` among 849 tests, all passed; claim 08:45-09:21, one launch). Base line A is loop322's AHOFF (COMPACT, build throttle 48/80, `N42_ACCOUNT_HISTORY=off`), no `N42_PERSIST_QMDB_IN_SCOPE`; the validator header shows the throttle, compact and account-history variables on the six A legs.

What bounds the flood. Loop322's AHOFF legs were offer-limited: the flood printed 1,249,970 sent a second at its `--rate` cap of 1,250,000 (`F7_FLOOD_RATE`, the limiter in `tx_flood` shared by 64 workers), and the leader's queue at its builds held 63,000-98,000 transactions, so a block held 132k transactions (occupancy 81%, 155 of 293 blocks at 95% or more). The gas ceiling caps a block at exactly 163,000 transfers (3,423,000,000 / 21,000; 326 frames of 500), not a frame or count limit; the pool is 1M slots with the ingest gate at 5/6 (833,000); the generator's own limit is signing: at 1.25M a second the flood's `sign` time is 121 worker-seconds per 5 s on its 34 logical cores (24 busy), so a live flood cannot offer 2.0M (10.46 measured the ceiling at ~1.2M, Ed25519 on 17 physical cores). So every leg of this round replays the pre-generated attested set `/data/n42-pregen/g900000` (192M frames, offset 900000, the same arguments as the bench line: `F7_FLOOD_REPLAY`, `F7_OFFSET_ARG=900000`; the replay refuses a set made for other arguments and the WARM leg is guarded: it ran, 64 files, every first sender at nonce 0, the round stops otherwise) at the offer in `F7_FLOOD_RATE`.

| leg | offer | win1 | win2 | win3 | round txs | blocks in win1 / txs per block mean / share >= 95% | cycle mean / median / p90 | sealed_at | fields | imports >600 | peak RSS n0 / n1 / n2 | in-mem max n0 / n1 / n2 | tc / own_not_comm / given_up | idles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (baseline) | 1.25M | 1,165,984 | 955,694 | 0 | 63.7M | 215 / 163,000 / 100% | 138.9 / 131.0 / 192.5 | 78 / 127 | 87 / 140 | 3 | 34.2 / 34.1 / 34.0 G | 93 / 90 / 98 | 1 / 0 / 0 | 1 |
| A | 1.25M | 1,289,584 | 1,021,410 | 0 | 69.3M | 290 / 133,981 / 54% | 104.5 / 101.6 / 111.9 | 69 / 148 | 81 / 160 | 0 | 26.3 / 26.2 / 24.1 G | 14 / 15 / 14 | 1 / 0 / 0 | 1 |
| A16 | 1.6M | 1,418,036 | 1,026,394 | 0 | 73.3M | 261 / 163,000 / 100% | 115.4 / 109.8 / 141.5 | 98 / 159 | 80 / 116 | 0 | 23.5 / 22.0 / 20.4 G | 18 / 12 / 13 | 1 / 0 / 0 | 1 |
| A20 | 2.0M | 1,423,235 | 989,128 | 0 | 72.4M | 262 / 162,912 / 100% | 114.5 / 109.7 / 140.7 | 96 / 158 | 81 / 125 | 0 | 21.8 / 22.0 / 21.3 G | 13 / 13 / 13 | 1 / 0 / 0 | 1 |
| A20P90 | 2.0M | 1,406,824 | 1,023,111 | 0 | 72.9M | 259 / 162,751 / 100% | 116.1 / 113.4 / 141.0 | 96 / 150 | 79 / 118 | 0 | 23.2 / 22.4 / 20.9 G | 16 / 11 / 15 | 1 / 0 / 0 | 1 |
| A20P80 | 2.0M | 1,401,745 | 1,048,027 | 0 | 73.5M | 258 / 163,000 / 100% | 116.4 / 113.7 / 142.8 | 97 / 148 | 79 / 111 | 0 | 23.3 / 22.6 / 21.4 G | 14 / 13 / 13 | 1 / 0 / 0 | 1 |
| Ab | 1.25M | 1,287,994 | 1,200,731 | 0 | 74.7M | 291 / 133,509 / 52% | 103.8 / 101.6 / 111.4 | 65 / 119 | 78 / 159 | 0 | 25.9 / 25.0 / 22.0 G | 17 / 11 / 13 | 2 / 0 / 1 | 1 |

Correctness on every leg: verify passes, invalid_blocks, no_variant, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads 0, no ERROR or panic line; the throttle delayed none of the proposals (A16 and A20P80 one each, 46 and 97 ms), no hard hold. Window 3 is 0 where the flood ended before it; the pacing legs show more blocks in it (329 and 368 empty blocks).

What the flood actually delivered (flood.log's per-5 s lines, the final line of round.txt, node 0's queue after each canonical prune, median per 20 s from the first full build): rejected 0 and 192,000,000 accepted on every leg; A: median 1,183,342 a second, final 1,156,476 (166 s), queue 240k, 70k, 72k, then 534k and the gate line (844-860k) after +60 s (the flood outran the chain only once window 1 was over); A16: median 1,280,266, final 1,278,491 (150 s), queue 410k, 392k, 535k, 535k, 574k, then 858k; A20: 1,300,562, final 1,262,072, queue 414k, 411k, 503k, 551k, 570k, 869k; A20P90 1,308,868 / 1,265,831, queue 409k, 409k, 408k, 584k, 646k, 866k; A20P80 1,272,164 / 1,269,044, queue 414k, 361k, 538k, 597k, 859k; Ab 1,249,966 / 1,142,015 (168 s), queue 213k, 63k, 95k, 150k, 839k. So at offers of 1.6M and 2.0M the replay's median delivery is 1.27-1.31M a second (the first five seconds read 1.46-1.51M) and the workers wait at the ingest gate for 147 of 150 seconds (9,400 of 9,600 worker-seconds), but the queue never runs dry: it holds 360-410k, two to three blocks, through window 1, which is what fills the blocks (100% occupancy, 258-262 of 262 blocks at 95%); at 1.25M it holds 63-98k and the blocks are 52-54% full. The offered 2.0M is therefore not delivered as a rate (the gate and the chain's consumption set it), but the supply is no longer the limit of window 1.

Window 1 by the both-legs rule against A (1,289,584) and Ab (1,287,994; gap 1.6k): A16 (1,418,036), A20 (1,423,235), A20P90 (1,406,824) and A20P80 (1,401,745) are all above both by 8.7% to 10.5%, a change upward with occupancy 100%, and all above the previous best 1,292,375 (loop322) and the record 1,226,047; the highest is 1,423,235 (A20), 10.1% above 1,292,375 with 262 of 262 blocks full. Tightening the pacing does not help once blocks are full: the cycle median is 109.7-109.8 ms at 100 ms pacing (A16, A20), 113.4 ms at 90 and 113.7 ms at 80, window 1 1,406,824 and 1,401,745 against 1,423,235 (-1.2% and -1.5%, inside the A16/A20 spread of 0.4% but in one direction): the 163k block's chain cycle is about 110 ms (sealed_at 96-98 ms against 69 at the half-empty blocks, fields 79-81 ms), and the tick is no longer the term.

Persistence against the cycle (engine `save_blocks`, ms per batch / ms per full block, full = blocks that carried transactions and are already written; batches are 3.0-3.1 blocks): A 205 / 109, 154 / 84, 152 / 82 (nodes 0, 1, 2); A16 191 / 114, 147 / 89, 141 / 86; A20 194 / 114, 151 / 90, 148 / 88; A20P90 182 / 113, 141 / 89, 137 / 86; A20P80 172 / 114, 132 / 89, 126 / 85; Ab 197 / 103, 146 / 79, 153 / 83; WARM (index on, no throttle) 650 / 175, 613 / 170, 603 / 171. With full blocks node 0's persistence per full block (113-114 ms) equals the cycle (110-116 ms) and the other nodes' (85-90 ms) is under it; the in-memory counts show it keeps up, at every tick (maxima 11-18, no node above 18 on any A leg). The RocksDB write is 0-1 ms a batch on every A leg; the static files are 83-90 ms a batch (the critical path), the `qmdb_persisted` call 36-58.

Overlay filter cache (a504b9fdf). `overlay_filter_builds` per leader block is 1.76 (WARM), 1.80 (A), 1.96, 1.94, 1.95, 1.94 (A16, A20, P90, P80), 1.80 (Ab): about two a block, not one, and `overlay_filter_cached` at the end is 14-17 on the A legs (the in-memory blocks) and 70 on WARM. The step at 64 in-memory blocks is testable only on WARM (the account-history index on, no throttle: nodes at 64 / 37 / 35 at the handover and up to 93 / 90 / 98): follower imports with the node's in-memory count above 64 (417 imports) have a median `exec_ms` of 43 against 42 and 42 for counts of 41-64 (475) and up to 40 (1,464), so no step in execution; their `total_ms` is 154 against 139 and 133 (+15 to +21 ms, not explained by these counters). No A leg got deeper than 18 blocks, so the cache is not tested there.

The handover. No A leg formed a timeout certificate at the handover except Ab (tc 2, one proposal given up): node 1's first leader views at 1024-1025: `13:18:59.17 WARN the build prepared ahead failed; building now err=build on the sealed block refused`, `13:19:04.48 WARN could not build a block to propose err=no payload build for id ... view=1025`, `13:19:05.09 WARN view timed out view=1025 leader=true proposed=true`, `13:19:05.10 INFO TC formed, I am the new leader for view 1026`. The new instrumentation (5158351bb) names the cause: at 13:19:04.46 node 1's execution layer logs `the queue's lock was held or waited for a second or more held_ms=4866 caller=crates/n42/tx-queue/src/lib.rs:2724` and a dozen callers at `lib.rs:1194` waiting 4,866-4,872 ms. Line 2724 is `QueueBest::drop`, which untakes a build's unused buffer back into the lanes under the queue's lock; a build abandoned at the handover (the "build on the sealed block refused" lines) gives back a buffer of up to 163,000 transactions and holds the lock for 4.9 s, in which nothing builds or votes. That is the only slow lock event in the round (one in seven legs, 0 on the other 18 execution layers), and the same shape as loop322 CTRL's TCs and loop320's FAS legs (Too deep reorg, build refused, then a timeout at the first leader views): the handover defect is a multi-second untake under the queue lock after a refused build, not the fields mode. The isolated "forkchoice to a committed block failed ... Too deep reorg" INFO/WARN lines also appear on legs without any TC (A, A20 and others, 2-4 a leg, before and after the handover) and are not by themselves the failure.

Conclusion. With the offer above the block (the replay set) window 1 reads 1.40-1.42M with every block full; the account-history-off persistence keeps up (in-memory max 18); the 90 and 80 ms ticks buy nothing because the full block's chain cycle is ~110 ms; the next terms are the sealed_at of a full block (96-98 ms against 65-69) and the follower's fields (79-81 ms) that set that cycle. No tag, `main` untouched.

### 10.72 Fields at the seal on the full-block base (loop324): `sealed_at` falls 20-30 ms, the cycle does not; loop323's 1.42M is not confirmed; 200k blocks scale linearly

Loop324 is measurement only (launcher started at tip 2698da454; claim 09:44-10:21, one launch; derived with `derive324.py`). Build caveat: the legs ran the native binary built at 09:28:35, and `crates/n42/tx-queue/src/lib.rs` was last written at 09:29:26 (the untake fix 34f742662 and its test commit 3ef4c629f are dated 09:29); the runner's own test and deferred build at 09:43 (`3ef4c629f+tree`) includes the fix. The execution layers and validators of every leg therefore did NOT carry the untake fix (an intermediate state of that file at most), and the handover results below are not a test of it. Base F is loop323's A20 line exactly (AHOFF + COMPACT + throttle 48/80, replay set `g900000`, offer 2.0M, pacing 100); the leg headers show `N42_FIELDS_AT_SEAL=verify` on FV and `=1` on FS, FSb and FSG in the execution layers' environment and in the validators'. FSG is FS with `F7_GASCEIL_ARG=4200000000` (200,000 transfers a block; the runner derives the genesis and the gossip cap from it; loop300 used the same variable with the same replay set), so no new variable was needed.

| leg | win1 | win2 | win3 | round txs | blocks in win1 / txs per block / full share | cycle mean / median / p90 | sealed_at | fields | imports >600 | peak RSS n0 / n1 / n2 | in-mem max | tc / own_not_comm / given_up | idles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (baseline) | 1,151,787 | 928,844 | 0 | 62.4M | 212 / 162,521 / 100% | 141.0 / 127.7 / 201.4 | 81 / 167 | 87 / 145 | 14 | 35.0 / 34.1 / 29.8 G | 94 / 93 / 87 | 1 / 0 / 0 | 1 |
| F | 1,390,610 | 1,070,322 | 0 | 73.8M | 256 / 163,000 / 100% | 117.1 / 111.7 / 140.8 | 104 / 145 | 80 / 120 | 2 | 22.0 / 22.2 / 20.9 G | 15 / 12 / 13 | 1 / 0 / 0 | 1 |
| FV | 1,379,997 | 1,173,087 | 0 | 76.6M | 254 / 163,000 / 100% | 118.1 / 113.2 / 144.8 | 76 / 175 | 80 / 116 | 3 | 24.1 / 22.5 / 21.4 G | 15 / 12 / 13 | 1 / 0 / 0 | 1 |
| FS | 1,396,311 | 1,070,088 | 0 | 74.0M | 257 / 163,000 / 100% | 115.7 / 110.7 / 137.9 | 75 / 195 | 80 / 127 | 0 | 22.4 / 22.3 / 20.8 G | 13 / 13 / 13 | 1 / 0 / 0 | 1 |
| Fb | 1,385,450 | 1,167,784 | 0 | 76.6M | 255 / 163,000 / 100% | 117.6 / 112.4 / 140.9 | 93 / 147 | 78 / 112 | 2 | 22.2 / 21.9 / 20.7 G | 14 / 11 / 12 | 1 / 0 / 0 | 1 |
| FSb | 1,396,244 | 1,020,962 | 0 | 72.5M | 257 / 163,000 / 100% | 116.2 / 111.7 / 138.0 | 77 / 183 | 80 / 126 | 0 | 23.0 / 22.8 / 21.7 G | 14 / 12 / 16 | 1 / 0 / 0 | 1 |
| FSG (200k) | 1,446,368 | 651,561 | 0 | 62.9M | 217 / 199,320 / 100% | 137.5 / 134.0 / 173.2 | 95 / 220 | n/a (counter filter is 163,000) | 0 | 23.5 / 21.6 / 21.8 G | 16 / 11 / 12 | 1 / 0 / 0 | 1 |

Correctness on every leg: verify passes, invalid_blocks, no_variant, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads 0, no ERROR or panic line. The throttle delayed at most two proposals a leg (never more than 0.4 s in total), no hard hold. FV: `fields_verified` 1,178, `fields_unchecked` 0, `fields_mismatches` 0, no "published at the seal differ" line, so FS ran.

Leader window 1, median / p90:

| leg | parent_fields_ms | sealed_ms | par_ms | par_exec_ms | roots_ms | seal_to_fields_us | rename_early |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F | 7 / 43 | 17 / 52 | 79 / 113 | 29 / 36 | 34 / 45 | 91,637 / 113,183 | 0% |
| FV | 0 / 4 | 7 / 15 | 65 / 83 | 28 / 34 | 40 / 57 | 55,502 / 72,737 | 73% |
| FS | 0 / 2 | 7 / 13 | 64 / 78 | 28 / 33 | 38 / 54 | 52,769 / 69,666 | 74% |
| Fb | 0 / 38 | 9 / 45 | 69 / 104 | 28 / 35 | 36 / 47 | 80,796 / 104,311 | 0% |
| FSb | 0 / 1 | 7 / 15 | 65 / 84 | 28 / 34 | 37 / 57 | 52,923 / 73,050 | 75% |
| FSG | 0 / 1 | 9 / 18 | 79 / 97 | 33 / 40 | 48 / 66 | 65,281 / 83,544 | 78% |

Flood delivery (every leg replays the set at the offer; rejected 0, 192,000,000 accepted): median per 5 s / final / queue at node 0 through window 1 (first 40 s, median per 20 s): F 1,264,360 / 1,211,500 (158 s) / 411k, 411k, 535k; FV 1,302,363 / 1,245,249 / 412k, 413k, 504k; FS 1,283,761 / 1,236,222 / 413k, 413k, 515k; Fb 1,296,466 / 1,248,969 / 413k, 410k, 413k; FSb 1,316,758 / 1,268,386 / 412k, 413k, 525k; FSG 1,335,353 / 1,317,031 (146 s) / 266k, 215k, 330k (the 200k block empties the queue faster; the blocks still averaged 199,320 and were all full). The workers sit at the ingest gate for about 145-150 s of the flood, as in loop323: the offer of 2.0M is not delivered as a rate, the queue is.

Persistence per full block (engine `save_blocks`, ms per batch / ms per full block), nodes 0 / 1 / 2, against the cycle median: F 200 / 115, 156 / 92, 152 / 90 (cycle 112); FV 191 / 114, 143 / 87, 140 / 85 (113); FS 200 / 118, 156 / 93, 147 / 88 (111); Fb 182 / 109, 140 / 85, 138 / 84 (112); FSb 195 / 115, 145 / 88, 145 / 86 (112); FSG 213 / 137, 154 / 101, 152 / 99 (cycle 134). Node 0 sits at the cycle in every leg and the other nodes under it; the in-memory maxima (11-16) show persistence keeping up at 163k and at 200k.

Queue-lock lines: no "the queue's lock was held or waited for a second or more" line appeared on any execution layer of any leg (0 of 7 legs, 21 nodes; loop323 had the one 4.87 s line). Handover per leg (node 1's first leader views at about +91 s, +110 s for FSG): clean on all seven: tc 1 (the start-up view-1 certificate), given_up 0, own_not_committed 0; FV and FSG show a "build prepared ahead failed; building now ... refused" line on node 1 and several isolated "forkchoice to a committed block failed ... Too deep reorg" lines (1-4 a leg on F, FS, Fb, FSb, 8 and 10 lines of all kinds on FV and FSG) with no timeout.

Does F confirm loop323? No. F (1,390,610) and Fb (1,385,450) agree with each other (0.4%) but are 2.3% and 2.7% below loop323's A20 (1,423,235) and 1.9% / 2.3% below its A16 (1,418,036); the loop323 pair differed by 0.4%, so the gap is outside either spread. The same line on the same replay set read 1.42M in one round and 1.39M in the next; what changed in between is the build (loop323: beed93504 + a clean tree; loop324: the native binary of a tree with the tx-queue edit in progress, an intermediate state of the queue's lock timing and untake). The best confirmed pair of one configuration is FS / FSb, 1,396,311 and 1,396,244 (67 apart), then F / Fb at 1.39M. No configuration has two legs above 1,423,235; FSG has one (1,446,368).

Judging window 1 (both-legs rule, FS and FSb against F and Fb; the controls differ by 5.2k): FS (1,396,311) and FSb (1,396,244) are above F by 0.4% and 0.4% and above Fb by 0.8% and 0.8%; both exceed the control gap (the smaller margin is 5.6k against 5.2k), so by the stated rule the early fields are a change upward, of 0.4% to 0.8%, which is within what one round of the same configuration varies. What the switch does is exactly what loop320 measured: `sealed_at` 104 / 93 to 75 / 77 ms, `parent_fields_ms` 7 / 0 to 0, fields published 91.6 / 80.8 ms after the seal against 52.8 / 52.9 (38-39 ms earlier); the cycle moves from 111.7 / 112.4 ms median to 110.7 / 111.7 ms, because a 163k block's cycle (110-112 ms) is bounded by the followers' fields (80 ms from the road's start plus the vote and commit path) and the persistence of node 0 (109-118 ms a full block), not by the leader's seal. FV (1,379,997) reads like the controls, as a verify leg should.

FSG, 200,000 transfers a block: window 1 1,446,368, the highest of any leg (1.6% above 1,423,235 and 3.6% above FS) with 217 blocks of 199,320 and a cycle median of 134.0 ms (mean 137.5). The cycle scales with the block: 110.7 ms at 163,000 and 134.0 ms at about 199,000 is 0.65 us a transaction plus about 5 ms, the same linear shape earlier rounds found before the compact answer and the history mode; the leader's chain scales with it (par_ms 64 to 79, roots 38 to 48, seal_to_fields 52.8 to 65.3 ms, sealed_at 75 to 86-95 ms) and so does persistence (99-137 ms a full block against a 134 ms cycle). So the block-size lever still buys only the fixed part (3.6%). Window 2 of FSG is poor (651,561, occupancy 40%, 98 of 247 blocks at 95%) with tc 1: the replay set (192M frames) is consumed in 146 s at 1.32M a second and the second window runs into its end; the leg's cause is the supply, not the chain (queue 440-566k before it, 847k after), but it was not isolated further.

Conclusion. Early fields work as designed (the seal 20-30 ms earlier, no mismatch on 1,178 blocks, handovers clean in this round) but do not move the cycle at 163k; the tick, the fields and node 0's persistence all sit at 110-118 ms, so the next term needs two of them cut at once. The 1.42M of loop323 is not reproduced (1.39-1.40M here). No tag, `main` untouched.

### 10.73 The follower import slot (loop325): a third slot and the vote ahead of the slot move the wait, not the cycle; node 2's engine cost follows the node, not the cores

Loop325 is measurement only (launcher at tip a808a453c, which holds ed66c7d01, 34f742662 (the queue untake fix), 5d6d6bec8 and 9e7c70a2c; `derive325.py` derives the runner from loop324's; the test gate ran `-p n42 --lib` among 888 tests, all passed; claim 11:25-12:07, one claim, eight legs). Build record: the native binary was built 11:09:08 (`h2_validator` 11:07:23) and the last `.rs` source write is 11:05:15, so every leg ran a binary newer than every source file, and it carries the untake fix (loop324's did not). The runner now refuses to start legs when a source file is newer than the native binary and prints the commit and the times. Base line F is loop324's F exactly. D3 adds `N42_DEFERRED_IN_FLIGHT=3`, VBS adds `N42_VOTE_BEFORE_SLOT=1`, VBSFS is VBS plus `N42_FIELDS_AT_SEAL=1`; the leg headers show each variable in the validator's and the execution layer's environment. SWAP is F with `F7_PIN_SWAP=1:2`, a new variable in `f7_pin` (default unset, today's layout) that gives node 1 the CPU list of node 2 and the reverse for both the execution layer and the validator; the layout function was tested standalone and the variable is in both processes' environment, but the legs do not log the `taskset` lines, so the swap's effect on affinity is not independently recorded.

| leg | win1 | win2 | win3 | round txs | blocks in win1 / txs per block / full | cycle mean / median / p90 | sealed_at | fields | imports >600 | peak RSS n0 / n1 / n2 | in-mem max n0 / n1 / n2 | tc / own_not_comm / given_up | idles |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 1,200,698 | 938,268 | 0 | 64.2M | 221 / 163,000 / 100% | 134.8 / 124.2 / 186.0 | 80 / 147 | 86 / 135 | 3 | 35.6 / 34.6 / 32.3 G | 94 / 92 / 81 | 1 / 0 / 0 | 1 |
| F | 1,407,166 | 999,319 | 0 | 72.2M | 259 / 163,000 / 100% | 115.7 / 110.2 / 136.2 | 96 / 154 | 80 / 143 | 4 | 21.7 / 21.4 / 20.5 G | 15 / 11 / 15 | 1 / 0 / 0 | 1 |
| D3 | 1,427,354 | 863,409 | 0 | 68.8M | 263 / 163,000 / 100% | 114.1 / 107.7 / 137.8 | 98 / 145 | 80 / 120 | 0 | 22.2 / 22.5 / 20.6 G | 15 / 11 / 14 | 1 / 0 / 0 | 1 |
| VBS | 1,407,181 | 1,123,041 | 0 | 75.9M | 259 / 162,502 / 100% | 115.5 / 109.1 / 137.4 | 103 / 151 | 85 / 185 | 0 | 21.5 / 21.9 / 19.6 G | 13 / 12 / 13 | 1 / 0 / 0 | 1 |
| Fb | 1,401,251 | 1,069,858 | 0 | 74.2M | 258 / 163,000 / 100% | 116.4 / 111.5 / 137.9 | 91 / 146 | 79 / 128 | 0 | 22.6 / 22.1 / 21.1 G | 13 / 11 / 15 | 1 / 0 / 0 | 1 |
| VBSb | 1,418,040 | 1,010,096 | 0 | 72.8M | 261 / 163,000 / 100% | 114.8 / 112.9 / 133.1 | 99 / 153 | 86 / 187 | 0 | 22.1 / 22.3 / 20.4 G | 14 / 12 / 13 | 1 / 0 / 0 | 1 |
| SWAP | 1,407,176 | 977,499 | 0 | 71.5M | 259 / 163,000 / 100% | 115.9 / 111.6 / 137.2 | 95 / 155 | 80 / 125 | 0 | 22.1 / 22.9 / 20.6 G | 14 / 12 / 13 | 1 / 0 / 0 | 1 |
| VBSFS | 1,423,460 | 868,836 | 0 | 68.8M | 262 / 163,000 / 100% | 114.5 / 109.1 / 134.7 | 76 / 170 | 114 / 205 | 1 | 23.1 / 22.1 / 21.2 G | 13 / 11 / 13 | 1 / 0 / 0 | 1 |

Window 1 is a count of whole blocks in 30 s (1 block = 5.4k); F, VBS and SWAP all hold 259 blocks, which is why three legs read 1,407,166 / 1,407,181 / 1,407,176. Correctness on every leg: verify passes with 0 disagreements, invalid_blocks, no_variant, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads, given_up and own_not_committed all 0, no ERROR or panic line. The throttle delayed 0-2 proposals a leg (0%, at most 0.3 s in total), no hard hold. Window 3 is 0 on every leg (the flood ended).

Flood delivery (rejected 0 and 192,000,000 accepted on every leg): median per 5 s / final per second: WARM 976k / 1.00M, F 1,253,768 / 1,200,684, D3 1,311,866 / 1,284,401, VBS 1,293,263 / 1,252,546, Fb 1,310,065 / 1,260,807, VBSb 1,274,054 / 1,271,146, SWAP 1,292,263 / 1,252,697, VBSFS 1,331,810 / 1,241,524.

Persistence (`save_blocks`, ms per full block, nodes 0 / 1 / 2) against the cycle median: F 117 / 94 / 92 (110.2), D3 113 / 86 / 86 (107.7), VBS 111 / 89 / 90 (109.1), Fb 115 / 89 / 86 (111.5), VBSb 113 / 88 / 84 (112.9), SWAP 116 / 88 / 88 (111.6), VBSFS 113 / 89 / 90 (109.1); WARM 173 / 167 / 167. Node 0 sits at the cycle as in loop324, the others under it; no leg got deeper than 15 in-memory blocks.

Judging window 1 by the both-legs rule against F (1,407,166) and Fb (1,401,251), which differ by 5,915. VBS (1,407,181) is above F by 15 and above Fb by 5,930, so it does not clear the controls' own gap against F; VBSb (1,418,040) is above F by 10,874 and Fb by 16,789. A leg counts only if both VBS legs clear both controls, and VBS does not: the switch is not a change in window 1. D3 (1,427,354), SWAP (1,407,176) and VBSFS (1,423,460) are single legs: reported, not concluded. No configuration has two legs above 1,423,235 (VBSFS exceeds it by 225 and D3 by 4,119, one leg each) and none exceeds 1,500,000. The cycle means (114.1-116.4 ms) differ by 2 ms across all seven legs, inside the F/Fb gap of 0.7 ms plus leg noise.

Follower vote road per leg, window 1 (node 1 / node 2; medians, p90 in brackets). Two of the requested fields are not available: the validator's `imported a block` line, which should carry `vote_before_slot`, `slot_wait_ms` and `held_at_arrival`, was not printed once in any leg. Its print is gated by `BlockSize::worth_logging` (10,000 transactions or 1 MB), and the held import of a compact body reaches it with neither (no decoded payload, a body of a few KB), so on this path the line never fires; that is an instrumentation defect to fix before the next round (log it for compact imports). The stand-ins used below are the execution layer's `checked: answered before the execution` line (`held=true` is a vote sent before the slot), the execution start in the `direct import` line (`exec_start_ms`, after the body's arrival) for the slot wait, and the count of blocks that had arrived and not landed when a block arrived for `held_at_arrival`.

| leg | held=true (n1 / n2) | arrival to vote | arrival to landing | exec_start after arrival | in flight at arrival (0 / 1 / 2 / 3), node 2 |
| --- | --- | --- | --- | --- | --- |
| F | 0 / 0 | 25.7 (39.6) / 96.1 (126.0) | 131 (161) / 289 (319) | 8 / 11 | 25 / 8 / 230 / 0 |
| D3 | 0 / 0 | 26.3 (39.7) / 85.3 (122.3) | 132 (256) / 381 (426) | 8 / 11 | 25 / 8 / 41 / 193 |
| VBS | 20 of 238 / 225 of 238 | 28.4 (43.2) / 90.4 (125.7) | 130 (195) / 359 (399) | 9 / **108** (141) | 27 / 11 / 65 / 161 |
| Fb | 0 / 0 | 25.4 (35.4) / 98.1 (129.8) | 115 (150) / 296 (324) | 8 / 10 | 25 / 7 / 229 / 0 |
| VBSb | 19 of 241 / 207 of 240 | 27.1 (40.8) / 90.7 (120.7) | 123 (194) / 357 (391) | 9 / 104 (142) | 25 / 32 / 58 / 150 |
| SWAP | 0 / 0 | 25.0 (49.2) / 99.7 (126.1) | 117 (204) / 288 (325) | 8 / 10.5 | 25 / 17 / 221 / 0 |
| VBSFS | 17 of 241 / 228 of 241 | 29.5 (43.5) / 92.7 (122.2) | 136 (197) / 357 (392) | 9 / 105 (144) | 25 / 13 / 64 / 163 |

What the knobs did on the last voter (node 2), from the binding-wait script (F, D3, VBS, Fb, VBSb): the wait before the compact-body assembly (`wait_for_engine`, mean) is 67.8 (F), 51.6 (D3), 29.8 (VBS), 73.7 (Fb), 27.6 (VBSb) ms; the assemble-plus-check step is 30.4, 32.4, **62.0**, 27.7, **60.4** ms; the proposal-to-commit time `Qc - P` is 105.2, 90.2, 98.4, 108.0, 94.8 ms (means); and node 2 is the last voter in 231 / 223 / 222 / 229 / 217 of about 237 blocks. Under VBS the assembly starts at once (wait 30 ms against 68, the slot is no longer waited for), but the vote road now spends the time waiting for the parent: its `vote road` line on node 2 shows `parent_wait_ms` 32, `parent_fields_wait_ms` 15 and `parent_output_wait_ms` 32 (all 0 in F), and the whole road is 60 ms against 27. The reason is in the dependency, not the slot: a block's vote checks the header against the parent's own result, so it needs block n-1's published output and fields, and n-1's execution is itself held for a slot, which node 2 now gets about 100 ms after arrival (`exec_start_ms` 108 against 11; `fields_ready` 172 against 77). The vote of n therefore still follows the execution of n-1, which follows the landing of n-3 (the slot frees on landing, 290-360 ms after arrival on node 2); the 6 ms by which arrival-to-vote falls (96.1 to 90.4 / 90.7 / 92.7) is all the gain, and it is inside the leg-to-leg spread. D3 behaves the same one slot later: the standing backlog on node 2 grows to fill the larger cap (blocks in flight at arrival: 2 in 230 of 263 blocks in F, 3 in 193 of 267 in D3; landing 289 to 381 ms after arrival, `parent_engine_wait_ms` 40 to 145), the gate binds again at three, and arrival-to-vote falls only 10 ms (96.1 to 85.3).

Binding-wait shares (quorum / tick / seal, with the mean cycle of each class), F 53.6% (124.5) / 44.7% (105.2) / 1.7% (113.7); D3 31.7% (126.0) / 55.4% (105.0) / 12.9% (123.7); VBS 47.0% (126.7) / 49.6% (104.2) / 3.4% (126.4); Fb 60.4% (123.8) / 36.6% (104.3) / 3.0% (113.7); VBSb 48.1% (122.7) / 39.7% (105.3) / 12.1% (114.7). Quorum share is lower on D3 (31.7%) and on VBS / VBSb (47.0 / 48.1) than on F / Fb (53.6 / 60.4), and the seal share rises where the quorum falls (D3 12.9%, VBSb 12.1%), but the mean cycle of a quorum-bound block is the same 123-127 ms on every leg and the whole-leg cycle moves 1-2 ms: blocks move from the quorum class to the tick class, not to a shorter cycle. The counterfactual of the script (every follower's vote path as fast as node 1's) reads 102.0 / 104.9 / 102.8 / 101.7 / 103.5 ms.

Cost side. Followers voting before executing hold no growing backlog: node 2's voted-and-not-landed blocks in window 1 are median 2 (p90 3, max 3) on VBS, VBSb and VBSFS against 1 / 2 / 2 on F and Fb, falling back to 1 after window 1 (mean per 15 s: VBS 1.8, 2.4, 2.4, 1.3, 1.1, 0.9, ...); peak RSS is 19.6-21.2 G on node 2 against 20.5-21.1 G on F and Fb; in-memory blocks of persistence peak at 13-15; windows 2-3 hold: window 2 is 1,123,041 / 1,010,096 on VBS / VBSb against 999,319 / 1,069,858 on F / Fb (round totals 75.9M / 72.8M against 72.2M / 74.2M). D3 (863,409, occupancy 67%) and VBSFS (868,836, 79%) read low in window 2 as single legs; the cause of window 2's supply was not isolated, and the three controls and VBS legs span 977k-1,123k, so a 100k+ difference is within what the other legs show only for D3 and VBSFS at the low end. The follower vote path is unchanged in correctness: verify passes on all legs, no invalid blocks.

The engine thread's CPU per node (percent of one core, window 1; `threadcpu-<leg>.tsv`; whole sampled leg in brackets about 21 / 21 / 36 on every leg): WARM 28.1 / 30.4 / 46.6; F 28.9 / 31.7 / 52.2; D3 31.3 / 31.0 / 53.1; VBS 29.8 / 30.5 / 55.0; Fb 26.7 / 29.3 / 52.8; VBSb 32.2 / 32.5 / 55.7; SWAP 28.9 / 29.5 / 50.9; VBSFS 31.7 / 30.4 / 56.3. Node 2 reads 1.7-1.8 times node 1 on F and Fb, and still 1.72 times on SWAP, where node 1 ran on node 2's CPUs: 29.5% for node 1 and 50.9% for node 2. Node 2 also keeps its gate in SWAP (two blocks in flight at 221 of 263 arrivals against 230 of 263 in F), its `parent_engine_wait_ms` 40 and its landing 288 ms after arrival (289 in F), and node 1 keeps 117 ms (131). So the extra cost follows the node index and not the cores, to the extent that the swap was in force (the caveat above). What differs by index and not by cores is the feed order (node 2 receives each frame last), the start order, and the per-node state; the previous note's L3-alignment fix is not supported by this leg. One leg, so not a conclusion; a repeat with the ingest list order reversed would separate the feed.

Queue-lock lines: none. No "the queue's lock was held or waited for a second or more" line appeared on any execution layer of any leg (0 of 8 legs, 24 nodes), with the untake fix in the binary. Handovers (node 1's first leader views at about +90 s): clean on all eight legs: tc 1 (the start-up certificate of view 1), given_up 0, own_not_committed 0. D3 shows one "build prepared ahead failed; building now ... build on the sealed block refused" line on node 1 at the handover and no timeout; the isolated "forkchoice to a committed block failed ... Too deep reorg" lines (2-14 a leg, 14 more on VBSFS) occurred without a timeout, as in loop324.

Conclusion. Neither switch moves window 1 by the both-legs rule (VBS +15 against F, so the rule fails; VBSb +10.9k) and neither moves the cycle (114.1-116.4 ms on all seven legs): the wait on node 2 is a chain (vote of n needs the execution of n-1, which needs a slot, which frees on the landing of n-3 about 290-360 ms after arrival), and each switch moves it to another link of that chain without shortening it. The two-slot cap and the late vote are symptoms of the engine landing latency on node 2 (1.7x the engine-thread CPU of node 1, follows the node index), which the switches do not touch. The candidates the data leaves are a slot that frees when the block's execution fields are published (not when the engine answers, so the vote chain depends on executions only) and the per-node engine cost itself (feed order is the next suspect); the `imported a block` line needs to be printed for compact imports before the next round. No tag, `main` untouched.

### 10.74 The execution-cache write skipped (loop326): window 1 and the mean cycle both move up 1-2%, node 2 stops being the slow follower, the gate moves to whichever follower falls behind

Loop326 is measurement only (launcher at tip aca15fb1e: 7a0c7b551 skips reth's cross-block execution-cache write on QMDB chains by default, `N42_ENGINE_EXEC_CACHE=on` restores it; 4214db67e fixes the log gate; the settlement-tag work 87c6212ef..aca15fb1e is in the build; `derive326.py` derives the runner from loop325's; the gate ran `-p n42 --lib` among the 888+ tests, all passed; one claim 13:08-14:07, eleven legs). Build record: native `n42` built 12:51:22, `h2_validator` 12:49:36, last `.rs` write 12:44:16 (binary newer than every source file; the runner checks it). Base line N is loop325's F exactly on the new default. Because the settlement tags are in the build, every leg except SPLIT passes `N42_SETTLEMENT_TAGS=legacy` and SPLIT passes `split`; the variable is read by the validator (`driver.rs`, `h2_validator.rs`) and the execution layer (`payload_serve.rs`), both inherit the leg's environment, and both headers print it. O = N plus `N42_ENGINE_EXEC_CACHE=on`; NFS = N plus `N42_FIELDS_AT_SEAL=1`; NP90 = N at 90 ms pacing; HT = N plus `N42_HASHED_TABLES=on` (the hashed tables are written again, reads stay on; the bench uses `off`); QR = N plus `N42_QMDB_READS=verify` and `N42_HASHED_TABLES=on` (verify cannot run with the tables off: `check_hashed_tables_setting` refuses `off` unless reads are `on`, so the two were changed together); STRACE = N with `strace -c -f -p <node 0's execution layer>` for 20 s from 12 s after the funding (`ptrace_scope` is 0).

| leg | win1 | win2 | round txs | blocks / txs per block / full | cycle mean / median / p90 | sealed_at | fields | imports >600 | peak RSS n0 / n1 / n2 | in-mem max n0 / n1 / n2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 1,124,380 | 907,313 | 61.0M | 207 / 161,711 / 99% | 143.4 / 134.7 / 210.5 | 78 / 131 | 88 / 145 | 4 | 34.8 / 35.0 / 32.0 G | 88 / 96 / 82 |
| N | 1,401,634 | 988,364 | 71.7M | 258 / 163,000 / 100% | 116.2 / 109.7 / 141.9 | 101 / 159 | 81 / 110 | 0 | 22.6 / 22.2 / 20.9 | 14 / 11 / 15 |
| O | 1,385,444 | 988,618 | 71.2M | 255 / 163,000 / 100% | 117.6 / 110.9 / 145.1 | 92 / 145 | 80 / 136 | 0 | 22.4 / 21.9 / 20.9 | 20 / 13 / 17 |
| Nb | 1,423,419 | 972,510 | 71.9M | 262 / 162,921 / 100% | 114.8 / 108.8 / 139.9 | 98 / 164 | 82 / 134 | 2 | 22.1 / 22.5 / 21.0 | 12 / 13 / 14 |
| Ob | 1,390,873 | 1,010,565 | 72.0M | 256 / 162,504 / 100% | 117.3 / 110.6 / 143.3 | 95 / 156 | 79 / 122 | 0 | 22.6 / 22.2 / 20.9 | 17 / 12 / 16 |
| NFS | 1,401,741 | 860,971 | 67.9M | 258 / 162,654 / 100% | 115.7 / 107.6 / 142.6 | 77 / 189 | 80 / 110 | 0 | 23.8 / 22.8 / 21.3 | 14 / 15 / 14 |
| SPLIT | 1,412,603 | 1,125,369 | 76.1M | 260 / 162,865 / 100% | 115.8 / 108.7 / 145.5 | 99 / 158 | 81 / 123 | 1 | 21.8 / 21.7 / 19.9 | 16 / 12 / 12 |
| NP90 | 1,423,479 | 993,633 | 72.5M | 262 / 163,000 / 100% | 114.5 / 108.7 / 144.1 | 96 / 143 | 80 / 120 | 0 | 23.0 / 22.7 / 20.9 | 16 / 12 / 13 |
| HT | 1,026,675 | 907,320 | 83.6M | 189 / 163,000 / 100% | 158.0 / 160.2 / 178.3 | 68 / 111 | 245 / 290 | 5 | 22.9 / 26.9 / 22.4 | 55 / 60 / 62 |
| QR | 1,015,746 | 918,208 | 75.1M | 187 / 163,000 / 100% | 159.6 / 160.1 / 182.0 | 72 / 120 | 255 / 359 | 95 | 20.0 / 20.2 / 19.3 | 13 / 16 / 12 |
| STRACE (not judged) | 886,839 | 1,260,437 | 64.4M | 165 / 160,652 / 93% | 173.0 / 137.5 / 279.3 | 103 / 215 | 79 / 110 | 0 | 27.7 / 23.4 / 21.8 | 80 / 12 / 13 |

(Cycle columns are the anatomy window, 159-241 blocks; `blocks` is the round's window-1 count.) Every leg: tc 1 / own_not_committed 0 / given_up 0, engine idles over 5 s 1, verify 0 disagreements, invalid_blocks, no_variant, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads 0, no ERROR or panic line, no "the queue's lock was held or waited for a second or more" line on any of the 33 execution layers. Handovers clean: no timeout beyond the start-up certificate, "Too deep reorg" lines 0-4 a leg (O legs 2 and 4, N legs 0), none with a timeout. Flood: 192,000,000 accepted, 0 rejected on every leg; median per 5 s 1.27-1.33M/s on the 163k legs (WARM 0.93M, HT and QR 0.88M). Persistence per full block (nodes 0 / 1 / 2, ms): N 112 / 85 / 87, O 118 / 93 / 89, Nb 119 / 95 / 94, Ob 115 / 90 / 87, NFS 112 / 85 / 83, SPLIT 117 / 88 / 89, NP90 113 / 87 / 88, HT 161 / 146 / 142, QR 148 / 130 / 129, WARM 179 / 176 / 176. The throttle delayed 0-2 proposals on the 163k legs and engaged (delayed 50 and 67 proposals) only on HT (node 1) and STRACE (node 0), whose in-memory counts passed 48.

The cache. `reth_sync_caching_account_cache_size` / storage at the end of the leg (nodes 0 / 1 / 2): O 4 / 4 / 32,768 and 2 / 2 / 6,235; Ob the same shape (6,263); every leg without the switch 0 / 0 / 0 on all three nodes, including WARM (where node 2 therefore read the same as the others). So on both O legs the cache was live on node 2 only, as 11.11 predicted, and the new default removes it. Median `elapsed` of the executed insert (`Block added to canonical chain`, blocks of 10,000+ transactions in window 1), nodes 0 / 1 / 2: O 0.03 / 0.03 / **25.4** ms, Ob 0.03 / 0.03 / **26.7**; N, Nb, NFS, SPLIT, WARM 0.03 on all three nodes. `engine_new_payload_ms` median node 1 / node 2: O 8 / 24, Ob 7 / 24; N 8 / 9, Nb 9 / 7, NFS 9 / 8, SPLIT 10 / 9. Engine-thread CPU in window 1 (percent of one core, nodes 0 / 1 / 2): O 27.0 / 32.4 / **53.2**, Ob 28.3 / 29.8 / **51.6**; N 31.7 / 36.1 / 34.4, Nb 31.0 / 34.9 / 32.8, NFS 30.4 / 36.7 / 30.7, SPLIT 29.5 / 35.7 / 34.8, NP90 29.2 / 36.9 / 30.0, WARM 25.6 / 27.9 / 26.4; node 2's 1.7x is gone and the followers read alike.

Judging window 1 (both-legs rule, N and Nb against O and Ob; the controls differ by 5,429). N (1,401,634) is above O by 16,190 and above Ob by 10,761; Nb (1,423,419) above O by 37,975 and Ob by 32,546; both clear the controls' gap against both, so the change is upward, +1.2% to +2.7% (mean of N and Nb 1,412,527 against 1,388,159 for O and Ob, +1.8%). Mean cycle, same rule: N 116.2 and Nb 114.8 against O 117.6 and Ob 117.3 (controls differ by 0.3 ms); N is lower than O by 1.4 and Ob by 1.1, Nb by 2.8 and 2.5, so the cycle falls 1.1-2.8 ms (1.0-2.4%), the rule is met. The median cycle is 109.7 / 108.8 against 110.9 / 110.6. N and Nb do not both exceed 1,423,235 (Nb exceeds it by 184, N does not), nothing exceeds 1,500,000. NP90 (1,423,479), NFS (1,401,741), SPLIT (1,412,603), HT and QR are single legs and are reported, not concluded: pacing at 90 ms and fields at the seal gave nothing beyond N's spread (NFS moved `sealed_at` to 77 ms, the seal share of the binding wait below did not matter).

Follower vote road (window 1; arrival to vote, arrival to landing, median / p90 ms; node 1 | node 2): N 73.9 / 117.1, 240 / 290 | 56.2 / 106.7, 220 / 264; O 35.0 / 80.7, 171 / 246 | 96.8 / 131.1, 296 / 331; Nb 86.9 / 125.6, 252 / 301 | 40.8 / 95.3, 189 / 261; Ob 24.8 / 51.6, 146 / 210 | 97.5 / 130.7, 292 / 331; NFS 92.2 | 28.6; SPLIT 75.8 | 51.1; NP90 94.0 | 26.7. Blocks with two in flight at arrival (gated on a slot; node 1 | node 2, of 258-268): N 150 | 98, O 43 | 222, Nb 185 | 78, Ob 16 | 229, NFS 203 | 13, SPLIT 158 | 104, NP90 225 | 6. Last voter of the previous block (binding-wait script): N node 2 90 / node 1 146, O 211 / 22, Nb 54 / 187, Ob 229 / 6. So with the cache write gone the slot gate has not gone away: it binds on one follower, but not the same one on every leg (node 1 in N, Nb, NFS and NP90, node 2 in O and Ob), and when one follower is gated the other votes within 25-55 ms. The gate is the two-slot closed loop of 10.73 on whichever follower falls behind first; the cache made it deterministic (node 2, 211-229 of 236 blocks last) and its removal makes it a coin flip with a lower average cost.

Binding-wait shares (quorum / tick / seal; mean cycle of each class, ms): N 39.8% (123.7) / 47.9% (106.1) / 12.3% (130.9); O 57.5% (126.5) / 40.8% (105.4) / 1.7% (111.8); Nb 48.5% (125.0) / 48.1% (104.5) / 3.3% (114.7); Ob 57.4% (125.8) / 41.7% (105.7) / 0.9% (113.7). The quorum share falls from 57.5 / 57.4 to 39.8 / 48.5 and the tick share rises from 40.8 / 41.7 to 47.9 / 48.1; the last voter's wait before the assembly (`wait_for_engine`, mean) is 51.1 (N), 61.5 (Nb) against 72.0 (O), 71.2 (Ob). The seal binds in 12.3% of N's blocks (3.3% in Nb): with a prompt last vote the seal starts to show, but NFS, which moves it earlier, did not move window 1 (1,401,741 against N's 1,401,634), so on this evidence the seal is not yet the limit. The script's counterfactual (both followers as fast as the faster) reads 109.0 and 104.5 ms for N and Nb, 102.8 and 101.7 for O and Ob.

The `imported a block` line now prints on the validators (210-243 lines a follower and leg in window 1) with `vote_before_slot=false`, as no leg sets that switch; the `slot_wait_ms` and `held_at_arrival` fields are on the same line.

SPLIT (settlement tags `split`; single leg). Logs only, no code change: each node logs "persisted block: first reading number=0" once (the legacy legs log it too); the `commit forkchoice answered` lines of node 1 and node 2 carry `safe=Some(15) finalized=Some(9)`, then `31 / 24`, `47 / 39`, ..., `safe=Some(2319) finalized=Some(2313)` at the end, so safe is one behind the committed tip and finalized trails safe by 6-8 blocks (the persisted block); no -38002 / -38006 and no "forkchoice ... refused" line on any node (the 7 "refused" lines that match a loose grep are `build on own block refused no state found`, which the legs without split also show). Node 0's answered lines read `safe=Some(0) finalized=Some(0)` for its whole tenure as leader (view 1-1023, about 90 s) and follow the tip only after the handover (`safe=Some(1407) finalized=Some(1398)` and later); node 1 and node 2 carry values from the start. That is an observation, not a judgement: the leader's commit path may not carry the split tags in its own tenure, or the line may report something else there; the code was not read. One `eth_getBlockByNumber` each on node 1 mid-leg (50 s after the funding): `latest` 0x2b2 (690), `safe` 0x2b3 (691), `finalized` 0x2ac (684); the three calls were sequential, so `safe` one above `latest` is a block landing between them; finalized is 6 behind. Window 1 was 1,412,603 (cycle 115.8 mean), 260 blocks; in-memory maxima 16 / 12 / 12 and peak RSS 21.8 / 21.7 / 19.9 G against N's 14 / 11 / 15 and 22.6 / 22.2 / 20.9; "Too deep reorg" lines 0 against N's 0.

HT and QR (single legs; the combinations that the bench does not use today, supported but slow). HT writes the hashed tables again with reads `on`: window 1 1,026,675 (cycle 158 / 160 ms), persistence 161 / 146 / 142 ms per full block against 85-112 on N, in-memory blocks 55 / 60 / 62 (the throttle engaged), `reader_lag_max` 48 with 70 warnings, followers' execution starting 190 ms after the body (`exec_start_ms` 189-194; `vote road` `parent_wait_ms` 72-73 against 0). QR (`verify` plus tables written): window 1 1,015,746, cycle 160 ms, 95 imports over 600 ms, persistence 148 / 130 / 129; the verification counter reads `checks=67,108,864 mismatches=0 declines=0` on all three nodes, so the QMDB reader agrees with the tables on 67M reads. Neither is a candidate for the fleet: writing the hashed tables costs 25-30% of window 1 and puts persistence above the cycle.

STRACE (node 0's execution layer, `strace -c -f`, 20 s from 12 s after the funding, attached to 315 threads; window 1 of this leg, 886,839, is not judged: ptrace slows the process). Summed over the threads (`seconds` are blocking time, so futex waits dominate): total 1,447,973 calls; by time: futex 86.97% (1,561 s, 343,706 calls, 59,284 errors, 4.5 ms mean), sched_yield 8.57% (153.8 s, 868,313 calls), clock_nanosleep 1.41% (12 calls), write 0.82% (14.8 s, 85,894 calls), madvise 0.59% (10.5 s, 51,557 calls), sendto 0.51% (47,439), restart_syscall 0.42%, epoll_wait 0.25% (14,866), clock_gettime 0.13% (10,672), recvfrom 0.07% (5,617); by calls: sched_yield 868,313 (60% of all calls), futex 343,706, write 85,894, madvise 51,557, sendto 47,439, epoll_wait 14,866, clock_gettime 10,672, recvfrom 5,617, getrusage 3,904, rt_sigprocmask 3,219. Called out: futex 343,706 (59,284 errors, EAGAIN-type wakeups), madvise 51,557 (2,578 a second, 204 us each), munmap 796 (0.14 s), mmap 1,003 (0.28 s), sched_yield 868,313 (43,400 a second, 177 us each as traced), write 85,894 (14.8 s), read 205 (0.09 s). The reading: the process spends its syscalls in thread parking (futex) and spinning-yielding (sched_yield, probably rayon and tokio workers looking for work), the heap's `madvise` (51k calls in 20 s with `dirty_decay_ms:2000`) is about 1 in 28 calls, and mmap, munmap and read are negligible; times are inflated by tracing and not comparable with untraced CPU shares.

Conclusion. The execution-cache write was the whole of node 2's extra engine cost: on the O legs node 2 alone holds a full cache (32,768 accounts), inserts at 25-27 ms and runs the engine thread at 52-53% against 30-32%; with the write skipped all three nodes insert in 0.03 ms and the followers read alike. Window 1 moves up 1.2-2.7% and the mean cycle down 1.1-2.8 ms by the both-legs rule, which is smaller than the 20 ms of engine time suggested because the two-slot loop re-forms on whichever follower falls behind: the quorum share falls (57% to 40-49%), the tick and seal shares rise, but a quorum-bound block still costs 124-127 ms. The next lever is the slot itself (free it at publication, 10.73), not the engine. HT and QR show the tables-off configuration is worth 30% and the QMDB reader is exact on 67M verified reads. No tag, `main` untouched.

### 10.75 The follower hand-off and the shards merge (loop327): the merge is 57-71 ms and its state half is the floor; the woken hand-off removes the 20/40/60 ms steps; together +1.4-2.2% on window 1, but the quorum wait turns into seal binding

Loop327 is measurement only, on the three-node fleet with independent execution (`fleet3-env.sh`), base N = loop326 N (history index off, compact take, throttle 48/80, execution-cache skip by default, replayed attested set, offer 2.0M, pacing 100, settlement tags `legacy`, no `N42_IMPORT_ONCE`). Launcher at tip f2d18cdbb (d42ab2e82, f206dfaae and 13d1959e0 in the tree; `derive327.py` derives the runners from loop326's and adds the free-space gate: a leg is refused under 250 G free on `/data` and prints its free space; the test gate ran 964 tests including `n42 --lib`). Two claims: claim 1 23:38-00:14 (WARM, N, H, HMV, HM, Nb, HMb), claim 2 00:30-00:56 (WARM2, Hb, HMS, HMP90, HMFS). An earlier launch of the first claim released the box without a leg because a source file was newer than the binary. The switches: `N42_HANDOFF_ON_LANDED` and `N42_SHARDS_MERGE_OFF_PATH` are read in `bin/n42/src/follower_import.rs`, i.e. by the execution layer (the validator ignores them); `N42_SETTLEMENT_TAGS` is read by both the validator driver and the execution layer; every header prints each variable for both processes. H = N + `N42_HANDOFF_ON_LANDED=1`; HMV = H + `N42_SHARDS_MERGE_OFF_PATH=verify`; HM = H + `=1` (the two halves on two threads); HMS = HM + `N42_SETTLEMENT_TAGS=split`; HMP90 = HM at 90 ms pacing; HMFS = HM + `N42_FIELDS_AT_SEAL=1`.

| leg | win1 | win2 | round txs | blocks w1 / txs per block / full | cycle mean (anatomy) | sealed_at median | imports >600 ms | persist ms per block | peak RSS (max layer) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| N | 1,417,306 | 955,769 | 71.2M | 261 / 163,000 / 100% | 114.9 | 103 | 2 | 63 | 21.3 G |
| Nb | 1,419,955 | 825,353 | 67.5M | 262 / 163,000 / 100% | 114.1 | 105 | 0 | 69 | 21.2 G |
| H | 1,434,258 | 847,101 | 68.4M | 264 / 163,000 / 100% | 113.1 | 103 | 0 | 67 | 20.7 G |
| Hb | 1,428,698 | 1,020,959 | 73.5M | 263 / 163,000 / 100% | 113.6 | 105 | 0 | 69 | 20.5 G |
| HMV (verify) | 1,217,009 | 1,021,427 | 67.2M | 224 / 163,000 / 100% | 133.6 | 77 | 13 | 79 | 19.3 G |
| HM | 1,448,763 | 1,042,115 | 74.8M | 267 / 163,000 / 100% | 112.1 | 106 | 1 | 70 | 20.3 G |
| HMb | 1,439,561 | 944,898 | 71.5M | 265 / 163,000 / 100% | 112.5 | 108 | 0 | 68 | 20.8 G |
| HMS | 1,427,765 | 923,165 | 70.6M | 263 / 163,000 / 100% | 113.9 | 105 | 0 | 66 | 20.9 G |
| HMP90 | 1,422,017 | 1,092,680 | 75.5M | 262 / 163,000 / 100% | 114.0 | 112 | 2 | 61 | 21.8 G |
| HMFS | 1,437,767 | 705,844 | 64.4M | 265 / 163,000 / 100% | 112.9 | 85 | 2 | 66 | 23.2 G |

(Window 3 is empty on every leg: the 192M replay set runs out. WARM and WARM2 are throwaway. HMP90's tick is 90 ms and its cycle still reads 114.0: the tick does not bind.) Every leg: tc 1 (the start-up certificate), own_not_committed 0, given_up 0, invalid_blocks 0, "Sidechain block not found" 0, every direct import answered `Valid` (status counts only Valid), engine idles over 5 s 1, no_variant 0, gas_mismatch 0, verify 0 disagreements, flood 192,000,000 accepted 0 rejected (median delivery 1.22-1.27M/s). The hand-off order changed and nothing failed: no invalid block, no other answer than VALID on any direct import, no timeout certificate beyond the start-up one, "Too deep reorg" lines 0-10 a leg (N 4 and 2, H 6, HM 4 and 4, HMFS 10, none with a timeout).

HMV: `merge_verified` 1,013 / 1,947 on the two followers and `merge_mismatches` 0 on every execution layer, so the runner did not stop; verify costs a second merge (`merge_ms` 43 but `merge_wait_ms` 152-154), so HMV's 1.22M is the price of checking, not a result.

The hand-off, per follower in window 1 (node 1 | node 2, median / p90):
- `handoff_wait_us`: N 18,399 / 84,145 us | 33 / 40,206 (polled); H 36 / 19,468 | 32 / 66; HM 34 / 63 | 32 / 52; Hb 33 / 63 | 34 / 67.
- `handoff_before_canonical=true` (the block was handed off before its parent was canonical, i.e. woken instead of polled): H 79 of 243 (33%) | 71 of 242 (29%); HM 82 of 246 (33%) | 36 of 245 (15%); Hb 50 of 242 (21%) | 64 of 241 (27%); HMFS 91 / 111 of 243 (37-46%); N 0 on both.
- `parent_engine_wait_ms`: N 18 / 84 | 0 / 40 with 125 and 47 of 238-239 blocks nonzero and exact 20 ms multiples 60 and 36 (distribution 20: 28, 40: 22, 60: 38, 80: 27 on node 1); H 0 / 19 | 0 / 0 with 30 and 15 nonzero and 0 multiples of 20; HM 0 / 0 | 0 / 0 with 15 and 5 nonzero, 2 and 0 multiples. The 20 / 40 / 60 ms steps are gone on every H leg.
- Body arrival to vote / to engine landing (node 1 | node 2): N 80 / 122, 238 | 28 / 46, 127; H 44 / 92, 162 | 38 / 73, 146; HM 41 / 80, 130 | 35 / 56, 113 (landing medians; p90 of landing N 290 | 192, H 230 | 201, HM 209 | 148).
- Slot hold (vote-road start to slot release, median / p90 ms): N 213.6 / 255.5 | 148.1 / 210.4; Nb 190.2 / 248.8 | 155.2 / 208.1; H 175.8 / 229.4 | 166.0 / 210.6; Hb 160.9 / 211.5 | 161.0 / 215.0; HM 160.5 / 206.4 | 140.4 / 173.7; HMb 164.8 / 216.2 | 145.9 / 183.6. So the hold falls 35-55 ms on node 1 and 8-10 ms on node 2 with HM; the slot is still held about 1.4 cycles.
- Blocks gated on a slot (`slot_wait_ms` median/p90, node 1 | node 2): N 37 / 83 | 0 / 0; H 0 / 39 | 0 / 8; HM 0 / 16 | 0 / 0. Last voter of the previous block (node 2 : node 1 of ~240): N 19 : 220; H 104 : 138; HM 108 : 136 (HMb the same shape): in N node 1 cast the last vote on 92% of blocks, with the hand-off the two followers share it.

The merge, median / p90 ms, on-path (N, Nb, H, Hb legs) against two threads (HM, HMb, HMS, HMP90, HMFS), node 1 | node 2: `merge_ms` N 71.5 / 89.0 | 57.0 / 76.0, Nb 63 / 87 | 60 / 81, H 65 / 85 | 62.5 / 82, Hb 60 / 85 | 57 / 83; HM 51 / 68 | 49 / 62, HMb 57 / 76 | 50 / 64, HMS 50 / 67 | 50 / 63. The halves: `merge_state_ms` 40-48 (p90 50-61), `merge_reverts_ms` 11-17 (p90 20-32), `merge_append_ms` 2-7 (p90 6-17). `merge_wait_ms` (what the import waits for the merge) N 61 / 83 | 42 / 60, Nb 54 / 78 | 47 / 68, H 53 / 74 | 51 / 72, HM 36 / 57 | 31 / 46, HMb 43 / 64 | 33 / 47. So the merge is not 58 ms by a measurement of one number but 57-71 ms median on the path (the inference stands, within the node spread), and it divides about 40-48 state, 11-17 reverts, 2-7 append: the state half is the floor. Two threads cut `merge_ms` to 49-57 and `merge_wait_ms` by 17-23 ms (about 30%), not to the state half alone, because the reverts and append halves run beside it on a thread of their own that the state half still waits to join.

Binding-wait shares (tick / quorum / seal; mean cycle of the class ms): N 48.1 (105.7) / 35.1 (124.5) / 16.7 (121.0); Nb 47.5 / 22.9 / 29.6; H 50.0 / 12.0 / 38.0; HM 36.5 (103.6) / 4.5 (117.0) / 59.0 (117.0); HMb 45.1 / 3.3 / 51.6; Hb 46.5 / 3.7 / 49.8; HMS 32.4 / 0.8 / 66.8; HMP90 22.4 / 5.0 / 72.6; HMFS 69.1 / 4.5 / 26.3; HMV 22.0 / 78.0 / 0. The `wait_for_engine` of the last voter falls from 44.4 (N, median) to 13.8 (H) and 4.6 ms (HM); the quorum's share of the binding drops from 35% to 3-5%, and the seal takes it over (17% to 52-59%): the hand-off removed the follower wait, and the leader's seal (`sealed_at` median 103-108 ms in every non-FS leg) is what the cycle waits for now. HMFS moves `sealed_at` to 85 ms and the seal share to 26%, the tick takes 69%, but window 2 reads 705,844 (130 of 253 blocks full), a single leg.

Judging, both-legs rule (controls N and Nb differ by 2,649 on window 1 and 0.8 ms on the mean cycle). HM and HMb against N and Nb: window 1 1,448,763 and 1,439,561 against 1,417,306 and 1,419,955, +19,606 to +31,457 (+1.4% to +2.2%), both differ from both controls upward by more than their spread: met; mean cycle 112.1 and 112.5 against 114.9 and 114.1, 1.6 to 2.8 ms lower, more than the controls' 0.8: met. H and Hb against N and Nb (different claims: treat with care): window 1 1,434,258 and 1,428,698 against the controls, +8,743 to +16,952 (+0.6% to +1.2%), both above both: met; mean cycle 113.1 and 113.6 against 114.9 and 114.1: H is 0.2-1.8 below, Hb is 0.5 below Nb (inside the 0.8 spread): not met for the cycle. HM against H: the merge change adds +1.0% (HM 1,448,763 / 1,439,561 against H 1,434,258 / 1,428,698), which is within the cross-claim noise. Two legs of one configuration above 1,427,354: HM and HMb (both exceed it), H and Hb (both exceed it by 1,344 and 7,000: yes). Nothing exceeds 1,500,000 (best 1,448,763). Single legs, reported and not concluded: HMS 1,427,765 (-1.4% against HM, the same as Hb), HMP90 1,422,017 (the 90 ms tick does not bind, so pacing does not help while the seal binds), HMFS 1,437,767 with a weak window 2.

Settlement tags (HMS). Node 0's `commit forkchoice answered` lines (the validator's log) carry from view 1 `safe=Some(15) finalized=Some(9)` first and `safe=Some(2301) finalized=Some(2294)` last (190 lines); node 1 `15 / 9` and `2291 / 2283` (165 lines); node 2 `15 / 9` and `2303 / 2296` (144 lines): safe is the committed tip less one on every node including the leader (loop326's SPLIT showed node 0 stuck at 0 for its whole tenure; 13d1959e0 fixes that), finalized trails safe by 6-8 blocks (the persisted block). No -38002 / -38006 and no forkchoice refusal on any node (the lines that match a loose grep are `build on own block refused no state found`, which every leg shows).

Conclusion. The merge costs 57-71 ms on the follower's path and the state half (40-48 ms) is the floor of what two threads can recover (17-23 ms of `merge_wait_ms`); the woken hand-off removes the 20 / 40 / 60 ms polling steps and 40-50 ms of the slot hold on node 1. Together they move window 1 +1.4% to +2.2% and the mean cycle 1.6-2.8 ms, and they turn the binding from the quorum wait into the leader's seal: the next lever on this fleet is the seal (`sealed_at` 103-108 ms), not the follower. All the correctness counters stayed clean with the new hand-off order. No tag, `main` untouched.

### 10.76 Seven validator keys on one execution layer (loop328): 1.11-1.14M on E=1, full blocks in every window, one execution per block; the leader's seal binds, not the feed or the votes

**Every figure below is an E=1 figure: one host, one execution layer, seven validator keys, seven signatures per vote round. It is not the three-node independent-execution record (loop326, 1.40-1.42M, three layers each executing every block) and the two are not comparable as the same thing.** Loop328 is measurement only (tip b1676594f, which holds the import-once registry f2dcc92a8 / a9dccb3b5; `N42_IMPORT_ONCE=1` on the execution layer; claim 17:22-18:16, one claim, ten legs; native `n42` built 17:06:54, last `.rs` write 16:10:39, binary newer than every source file; the gate ran `-p n42 --lib` among 962 tests, all passed). Runner review: `derive328.py` was written by another agent and had never run; I checked it against the loop326 conventions (gates, binary-newer-than-source, `n42 --lib`, 75-minute cap, memsample per layer through `F7_EL_MAP`, both environment headers) and changed only: an `E1G` leg, a per-leg line counting the `import_once=true` start-up line and printing the last `once_*` counters, a per-leg `/data` free-space gate (120G; the E7 leg 450G) with the figure in each leg's header, the seven-node control moved last, the WARM leg made an E=1 warm-up, and a wipe of the round's own node datadirs (`$B/node{0..6}/{el,consensus}`, the two directories `fleet7.sh up --fresh` removes) at the end of the round. `N42_BUILD_ON_SEAL=1` and `N42_TENURE_FIRST_ON_OUTPUT=1` were already in the base line. A first attempt at this round hit ENOSPC on `/data` during its seven-node leg (all of `/data` was full, not only this run's directories) and was aborted; its E7 round had exited 0 at 683,571 in window 1 but its logs were lost. Layout (`fleet7.sh plan`): one layer on `0-103,128-231` (208 CPUs), the seven validators on `104-111,232-239` (16 CPUs), the flood on `112-127,240-255`; base line is loop326's N on the seven-validator bench genesis, replay set `g900000`, offer 2.0M, pacing 100 ms, tenure 1024, settlement tags `legacy`.

| leg (E=1 unless noted) | win1 | win2 | win3 | round txs | blocks win1 / txs per block / full | cycle mean / median / p90 | sealed_at | par_ms | par_exec | roots | parent_fields | sealed_ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (E=1 warm-up) | 1,102,921 | 1,086,630 | 1,086,627 | 116.1M | 203 / 163,000 / 100% | 144.9 / 135.5 / 236.4 | 158.5 / 235 | 155 / 232 | 35 / 46 | 87 / 147 | 69 / 170 | 79.5 / 178 |
| E1 | 1,140,951 | 1,097,497 | 946,169 | 95.5M | 210 / 162,818 / 100% | 141.1 / 134.8 / 235.9 | 143 / 233 | 140 / 227 | 33 / 46 | 77 / 139 | 0 / 168 | 14 / 175 |
| E1b | 1,108,184 | 1,119,228 | 1,070,048 | 98.9M | 204 / 162,973 / 99.5% | 144.7 / 136.0 / 238.4 | 142 / 237 | 139 / 231 | 34 / 46 | 85 / 144 | 0 / 171 | 12 / 179 |
| E1P80 | 1,124,236 | 1,091,356 | 1,042,697 | 97.8M | 208 / 163,000 / 99% | 141.5 / 142.2 / 235.0 | 141 / 234 | 138 / 230 | 37 / 50 | 74 / 145 | 0 / 166 | 11 / 174 |
| E1P70 | 1,119,232 | 1,075,746 | 1,037,269 | 97.0M | 206 / 163,000 / 100% | 140.8 / 143.2 / 238.6 | 154 / 237 | 151 / 231 | 36 / 44 | 87 / 145 | 59 / 171 | 69 / 180 |
| E1T (build 64, rayon 32) | **1,222,462** | 1,195,299 | 477,652 | 86.9M | 225 / 163,000 / 100% | 131.7 / 128.6 / 178.1 | 139 / 183 | 134 / 178 | 27 / 46 | 37 / 133 | 0 / 121 | 11 / 130 |
| E1G (200,000 a block) | 1,179,891 | 1,139,271 | 574,734 | 86.8M | 177 / 199,760 / 100% | 166.2 / 170.3 / 274.8 | 184 / 273 | 182 / 269 | 43 / 56 | 97 / 165 | 97 / 196 | 107 / 205 |
| E1FS (fields at seal) | 1,135,526 | 1,059,464 | 1,086,630 | 98.5M | 209 / 163,000 / 100% | 141.9 / 135.7 / 236.7 | 140 / 236 | 137 / 231 | 35 / 46 | 72 / 144 | 0 / 169 | 11 / 177 |
| E1C74 (layer capped at 74 CPUs) | 1,026,844 | 988,505 | 983,402 | 90.0M | 189 / 163,000 / 100% | 155.3 / 146.9 / 250.3 | 159 / 249 | 157.5 / 246 | 40 / 49 | 91 / 155 | 61 / 174 | 74 / 182 |
| E7 (seven layers, 32 CPUs each, control) | 650,554 | 483,551 | 499,839 | 100.3M | 120 / 162,683 / 99% | 242.4 / 232.3 / 359.4 | 221 / 392 | 225 / 384 | 50.5 / 70 | 71 / 161 | 55.5 / 233 | 71 / 243 |

(Windows 1-3 as `round.txt`; the cycle columns are validator 0's proposal intervals in the 30 s after the first full build; the phase columns are the leader's `seal-first build phases` medians / p90 on layer 0, `par_ms` the parallel build, `roots_ms` the QMDB root. The E7 round exited at 683,571 in window 1 in the aborted attempt and 650,554 here.) Execution layer / validators in window 1, cores busy: E1 16.7 / 0.6, E1b 16.6 / 0.5, E1P80 17.5 / 0.5, E1P70 16.9 / 0.5, **E1T 26.5** / 0.6, E1G 16.9 / 0.5, E1FS 17.3 / 0.6, E1C74 17.3 / 0.5 (of 74), WARM 17.1 / 0.5, E7 104.9 over seven layers / 0.8: the layer is given 208 CPUs and uses 17 of them, which is the 16 rayon threads plus the pools around them; the seven validators together use half a core. Execution layer peak RSS 28.7-30.4 G (E7 22.9 G a layer). In-memory blocks maximum 11-12 on every E=1 leg (E7 17). Persistence (node 0, ms a batch of about three blocks, against three cycles of 400-450 ms): E1 176, E1b 176, P80 169, P70 154, T 187, G 204, FS 176, C74 225, E7 712; persistence keeps up on every E=1 leg and does not on E7 (712 ms a batch against 700-1,000 ms of three cycles). tc 1 (the start-up certificate), own_not_committed 0, proposals_given_up 0, engine idles over 5 s 1, imports over 600 ms 0 (E7: 151), invalid_blocks, incomplete, gas_mismatch, direct_imports_failed, unanswered_reads 0, no queue-lock line, on every leg.

Feed. Every E=1 leg fills its blocks in window 1 (99-100% of blocks at 95% or more) and in window 2 (100%): the feed is not what bounds E=1. The replay delivered 192,000,000 accepted, 0 rejected on every leg, at a median 1.07-1.08M a second per 5 s (the single layer is offered 2.0M and the ingest gate holds the queue at 870,000 throughout window 1: the workers wait at the gate), finishing in 169-179 s (E1T and E1G in 170 s, E7 294 s). Windows 3 of E1T and E1G read 478k and 575k (88 of 267 and 87 of 232 blocks full) because the replay set ran out first, not because the chain slowed; the other E=1 windows 3 read 946k-1.09M. A leg whose blocks are not full measures the feed; none of these legs is that.

Single execution (the proof). `once_imports` equals `once_blocks` on every leg and at every sample (E1: 2 / 2, 252 / 252, ..., 2,006 / 2,006), `once_takeovers` 0, `direct import` lines 1,875 against 1,880 `Block added to canonical chain` lines (the five fewer are blocks the leader built itself), the start-up line `import_once=true` once. `once_reqs` per block is 7 on 1,988 of 2,001 lines (6 on 13): every key asks, one executes. `once_served` reads 0 on those lines because the line is printed when the import returns, before the six waiters are served; the six serves are not in this counter at that moment, so "6 per block" is not observed here, only the requests (7) and the single import.

What bounds the cycle at E=1 (binding wait from validator 0's log; the anatomy script pairs a validator index with a layer index and was not used). Tick / quorum / seal, share of blocks with the mean cycle: E1 35.2% (100.6) / 0.5% / **64.3% (165.4)**; E1b 30.9% / 0% / 69.1% (167.6); E1P80 27.2% / 0% / 72.8% (168.6); E1P70 22.8% / 0% / 77.2% (167.0); E1T 35.4% / 0.4% / 64.2% (150.6); E1G 30.3% / 0% / 69.7% (198.6); E1FS 36.8% / 0.5% / 62.7%; E1C74 31.4% / 0.5% / 68.1% (183.6); E7 9.2% / 0% / 90.8% (254.2). The quorum never binds: the slowest of the seven keys votes 19-27 ms after the proposal (median; p90 27-37 ms) and is within 0.2-1.7 ms of the median key, and the last key is spread over keys 1-6 (24-46 each of about 205 blocks): one execution answers all seven, so there is no straggler. What binds is the leader's own seal: `sealed_at` 142 ms median (the three-node leader seals at 96-101) with `par_ms` 138-140 ms, `roots_ms` 74-87 and `parent_fields_ms` 0 median but 166-171 at p90, so the build chain of a 163k block on this layer costs about 140 ms against a 100 ms tick; pacing at 80 and 70 ms only makes the seal bind more often (72.8%, 77.2%), as expected, and gains nothing (1,124,236 and 1,119,232 against 1,140,951 and 1,108,184). Fields at the seal (E1FS) moved `sealed_ms` from 12-14 to 11 and window 1 not at all (1,135,526). Doubling the pools (E1T) is the one that moves the seal: `roots_ms` 77 to 37, `par_ms` 140 to 134, `sealed_at` 143 to 139 / 183 p90 (233 before), cycle 141.1 to 131.7 mean and 134.8 to 128.6 median, the layer's CPU 16.7 to 26.5 cores, window 1 to 1,222,462 and window 2 to 1,195,299. Capping the layer at 74 CPUs (E1C74, one three-node node's budget) costs 9.2% (1,026,844): `roots_ms` 91, cycle 155.3, so the 208 CPUs are not idle ballast: the pools need more than 74.

E1 and E1b, the pair: 1,140,951 and 1,108,184, 2.9% apart (cycle means 141.1 and 144.7, medians 134.8 and 136.0; window 2 1,097,497 and 1,119,228, so the second leg is higher there): they agree to about 3%, not better; E1P80, E1P70, E1FS and WARM (1,124,236, 1,119,232, 1,135,526, 1,102,921) fall between them, so the configuration reads about 1.10-1.14M on window 1 and 1.06-1.12M on window 2 at 163,000 transactions a block. The best single leg is E1T (1,222,462 in window 1, 1,195,299 in window 2, cycle median 128.6 ms), +7% to +10% over the pair; single leg, not concluded. E1G (200,000 transfers a block) reads 1,179,891 / 1,139,271 with a 170 ms median cycle: 199,760 transactions a block at a 170 ms cycle, linear in the block as in 10.72, and still below E1T. These are E=1 numbers; the three-node record is a different thing.

Handover. Tenure is 1,024 views and the legs are about 1,800 blocks long, so one handover occurs in every leg, after window 2, at view 1024: key 0 proposes views 1-1023 and key 1 views 1024 onward (E1: 1,023 and 983 proposals, key 2 none). It was clean on every leg: tc 1 (the start-up certificate only), no timeout, no given-up proposal, `own_not_committed` 0, `once_takeovers` 0; key 1's first two proposals are 465 ms apart (the build chain restarts) and the cycle then returns to the leg's level.

The seven-node warm-up that formed four timeout certificates in the first attempt: it does not look like the mapping refactor. The identity-map control (E7, the same code path as that WARM) formed none in this round (tc 1, given_up 0, 650,554 and 683,571 in window 1 on two runs, cycle 232-250 ms, in-memory 17, persistence 712 ms a batch) and its figures are the CPU-starved shape: each node executes every block on 32 CPUs (105 cores busy over the seven layers against 17 for the single layer) and persistence runs at the cycle. The four certificates of that first WARM were its first leg after a build, started while the box was loaded (load 32 at the next leg's start) and `/data` was running out of space; the E7 control here ran with a cold start, free disk and no certificate, so the better explanation is a cold, starved, disturbed first leg of seven nodes on 32 CPUs each, not the refactor. I did not find a seven-node figure at this exact tier and settings in `docs/NATIVE_FLEET7.md` to compare numerically (its seven-node rounds are on other tiers and builds), so this is a judgement from the in-round control, not a comparison with that table.

Conclusion (E=1, one host). Seven keys sharing one execution layer run at 1.10-1.14M on window 1 with the 163k-transaction block and 1.22M with the pools doubled, every block full, one import per block, no quorum wait and a clean handover; the limit is the leader's own seal (140 ms of build chain, `roots_ms` and `par_ms`), which the extra CPUs of the layer shorten only when the pools are raised (E1T) and the tick, the fields mode and the pacing do not touch. No tag, `main` untouched.

### 10.77 E=1 tuning (loop330): the knobs are already the three-node leader's; the layer executes every block it builds a second time; threads lift E=1 to 1.23-1.28M

**Every figure is an E=1 figure: one host, one execution layer, seven validator keys, `N42_IMPORT_ONCE=1`. It is not the three-node record.** Loop330 is measurement only (tip 79fb07832, which adds `once_served_total` to the import lines; claim 19:55-20:40, one claim after a 100-minute wait behind a gov5 claim; native `n42` built 19:39:03, last `.rs` write 18:22:54, binary newer than every source file; the gate ran `-p n42 --lib`, all passed). Derived from loop328's runner by `derive330.py`; the free-space gate stayed (1,441G free at the first leg, 120G needed); the round's datadirs were wiped at its end.

**1. The environment and arguments, three-node node 0 against the E=1 layer.** Both command lines come from `fleet7.sh plan` with the exact environment of loop326 leg N (`F7_NODES=3`, `F7_CORES_PER_NODE=74`, `fleet3` genesis and root) and of loop328 leg E1 (`F7_EL_MAP=0,0,0,0,0,0,0`, `fleet7` genesis); the plan does not include the exports that `fleet7-bench.sh` adds, which are common to both. The two execution-layer lines are identical in 104 of 105 words:

| item | three-node node 0 (loop326 N) | E=1 layer (loop328 E1) |
| --- | --- | --- |
| CPU list | `0-36,128-164` (74 CPUs, 37 physical cores) | `0-103,128-231` (208 CPUs, 104 physical cores) |
| `RAYON_NUM_THREADS`, `N42_PARALLEL_BUILD_THREADS`, `TOKIO_WORKER_THREADS`, `MALLOC_CONF`, ingest recover threads (`N42_TX_INGEST_RECOVER_PARALLEL=12`), `N42_OUTPUT_SHARDS=16` | 16, 32, 16, `thp:always,oversize_threshold:0,dirty_decay_ms:2000,background_thread:true`, 12, 16 | the same |
| builder path (`N42_PARALLEL_BUILD`, `N42_BUILD_CHAIN`, `N42_BUILD_ON_SEAL`, `N42_FOLLOWER_*`, `N42_OUTPUT_INDEX*`, `N42_FRAME_BLOCKS`, ...), state masking 0, persistence threshold 8 / buffer target 6 / backpressure 1024, pool sizes (`--txpool.*-max-count 1000000`, slots 652,000 / 1,000,000), `--builder.interval 60`, pacing 100 ms, tenure 1024, `N42_SENDER_CACHE_MULT`, `--engine.cross-block-cache-size 128` | one set | the same |
| `N42_INGEST_SHARD` | not set | `0/1` (read only by `N42_INGEST_VERIFY=shard`, not set: no effect) |
| `N42_IMPORT_ONCE` | not set | `1` (the layer's registry) |
| genesis | `n42_fleet3_bench.json` | `n42_fleet7_bench.json`: identical except `hotstuff.validators` (3 against 7 entries; chain id 1143, 14-account alloc, gas limit, no committee pool: the bench genesis carries none, so there is no per-block committee or 512-signer work; only the vote count differs, 3 of 3 against 5-of-7 quorum with the grace waiting for all seven) |
| validator command line | `0-36,128-164` (shares node 0's CPUs), 2 peers | `104-111,232-239` (16 CPUs of their own), 6 peers; seven validators send one request each (`once_reqs` 7 a block) and seven forkchoices |

So no knob differs where the layout does not force it: the base line already is "the three-node leader's knobs", and leg A (74 CPUs laid out as node 0, which loop328's E1C74 also was) is the control for that statement, not a change.

| leg (E=1) | win1 | win2 | win3 | round txs | blocks win1 / txs per block / full | cycle mean / median / p90 | persistence ms a batch | layer cores busy | RSS peak | in-mem max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (E=1, 208 CPUs) | 1,113,262 | 1,075,760 | 1,037,728 | 96.8M | 205 / 162,934 / 100% | 144.4 / 136.4 / 236.8 | 186 | 16.6 | 29.2 G | 12 |
| A (74 CPUs as node 0, build 32 rayon 16) | 1,032,300 | 994,264 | 1,010,221 | 91.1M | 190 / 163,000 / 100% | 155.2 / 149.4 / 247.9 | 225 | 17.0 | 28.4 G | 12 |
| Ab | 1,053,973 | 1,010,554 | 988,827 | 91.6M | 196 / 163,000 / 98.5% | 151.7 / 152.4 / 244.2 | 236 | 17.6 | 29.0 G | 12 |
| A208 (same knobs, 208 CPUs) | 1,135,531 | 1,054,028 | 1,081,193 | 98.1M | 209 / 162,898 / 100% | 140.3 / 133.3 / 230.3 | 185 | 17.2 | 29.0 G | 11 |
| T64 (build 64, rayon 32) | 1,233,322 | 1,140,489 | 428,753 | 84.1M | 227 / 163,000 / 100% | 130.8 / 125.0 / 194.8 | 189 | 26.2 | 29.5 G | 12 |
| T64R64 (build 64, rayon 64) | 1,233,329 | 1,206,163 | 244,026 | 80.5M | 227 / 163,000 / 100% | 130.2 / 125.8 / 179.2 | 190 | 30.9 | 30.0 G | 12 |
| T96 (build 96, rayon 48) | 1,265,913 | 1,173,450 | 97,330 | 76.1M | 233 / 163,000 / 100% | 127.2 / 122.3 / 166.7 | 186 | 36.2 | 30.2 G | 12 |
| BG (T96 at 200,000 a block) | 1,246,618 | 1,193,264 | 93,330 | 76.0M | 187 / 200,000 / 100% | 157.8 / 153.8 / 266.0 | 219 | 31.6 | 31.1 G | 12 |
| BR (T96 again) | 1,276,674 | 1,189,628 | 108,197 | 77.2M | 235 / 163,000 / 100% | 126.6 / 119.8 / 164.8 | 189 | 35.3 | 30.1 G | 12 |

Judge on windows 1 and 2 (the replay set ran out in window 3 on the faster legs). Every leg: tc 1, own_not_committed 0, proposals_given_up 0, engine idles over 5 s 1, imports over 600 ms 0, invalid_blocks, gas_mismatch, direct_imports_failed, unanswered_reads 0, no queue-lock line; windows 1 and 2 full on every leg (the feed does not bind); flood 192M accepted, 0 rejected, median 0.98-1.17M a second. `BP90` and `BP80` were skipped: the best leg's median `sealed_at` over its full builds is 154 ms, not under 100.

Leader phases, median / p90 (ms; `sealed_at`, `par_ms`, `par_exec_ms`, `roots_ms`, `parent_fields_ms`, `sealed_ms`), with the three-node leader of loop326 N and Nb (for node 0 as leader, the first line of each) beside them:

| leg | sealed_at | par_ms | par_exec | roots | parent_fields | sealed_ms | binding tick / quorum / seal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| three-node N (not E=1) | 97 / 117 | 91 / 113 | 30 / 39 | 36 / 54 | 18 / 41 | 26 / 50 | |
| three-node Nb (not E=1) | 97 / 116 | 91 / 113 | 30 / 37 | 35 / 48 | 19 / 40 | 27 / 50 | |
| WARM | 141 / 235 | 138 / 231 | 35 / 56 | 84 / 146 | 0 / 168 | 11 / 176 | 36.1 / 0.5 / 63.4% |
| A | 155 / 244 | 152.5 / 239 | 40.5 / 50 | 87.5 / 148 | 22.5 / 169 | 36.5 / 179 | 28.4 / 0 / 71.6% |
| Ab | 156.5 / 241 | 151.5 / 238 | 40 / 50 | 86 / 153 | 35.5 / 166 | 47.5 / 176 | 30.8 / 0.5 / 68.7% |
| A208 | 138.5 / 229 | 134.5 / 226 | 34 / 44 | 75 / 143 | 0 / 162 | 11 / 170 | 39.3 / 0.5 / 60.2% |
| T64 | 138 / 212 | 133 / 207 | 25.5 / 43 | 42 / 138 | 27.5 / 142 | 44.5 / 152 | 41.0 / 0 / 59.0% |
| T64R64 | 133 / 184 | 128.5 / 182 | 26.5 / 44 | 35.5 / 133 | 0 / 130 | 12 / 138 | 38.4 / 0 / 61.6% |
| T96 | 137 / 177 | 132 / 173 | 24 / 44 | 35 / 93 | 0 / 113 | 13 / 123 | 44.3 / 0.4 / 55.3% |
| BG (200k) | 162 / 265 | 158 / 261 | 31 / 52 | 88 / 163 | 0 / 192 | 13 / 202 | 34.2 / 0 / 65.8% |
| BR | 130.5 / 176 | 126.5 / 170 | 23 / 49 | 33 / 93 | 0 / 116 | 14.5 / 126 | 46.4 / 0 / 53.6% |

The quorum never binds (0-0.5% of blocks); the slowest of the seven keys votes 18-28 ms after the proposal, and the last key is spread over keys 1-6. The seal binds 53-72% of blocks.

**2. The gap, and what it is.** With identical knobs and identical pins, A's leader is 58 ms slower to seal than the three-node leader (`sealed_at` 155 against 97; `par_ms` 152 against 91; `roots_ms` 87 against 36, 2.4 times; `par_exec_ms` 40 against 30; `parent_fields_ms` p90 169 against 41). The CPUs do not explain it (A208 gets 208 CPUs, +9% and `sealed_at` 139: the extra CPUs help a little, the pins and knobs are the same), nor the knobs, nor the genesis (no committee pool). What differs is the work the layer does: the layer builds a block and then executes it again as an import. In loop328 E1, 1,175 of the 1,179 blocks the layer built have a `direct import: executed here` line for the same block number (with the build line's `number` taken as the parent's, as `fleet7-depth-replay.py` does), against 2 of 750 on the three-node leader (loop326 N node 0); in loop330 the figure is 1,167-1,176 of 1,178 on every leg. Those imports are real executions: `exec_ms` 29-38, `root_ms` 73-83 and `total_ms` 126-151 median (BG 35 / 96 / 151), so every block is executed twice and rooted twice on the one layer, and the QMDB root of the import (76 ms) shares the layer's root pool and its static root mutex (11.12) with the next block's build: the build's `roots_ms` is 77-87 where the three-node leader's is 35, and its `parent_fields_ms` tail (p90 166-171) is the build waiting behind the import's root. The import-once registry makes the six other keys' requests free (`once_served_total` 11,995 over 2,001 blocks: 5.99 a block, the figure the old `once_served` could not show) but it does not stop the layer re-executing a block it has just built; the three-node leader skips that because its own block reaches the engine as executed (`own block handed to the engine as executed`, logged 1,023 times for the three-node leader's 1,023 blocks, 5 times at E=1). This is the remaining gap named in the log; the remedy is in code, not in a knob (answer the keys' requests for a block the layer built from the built block, as the one-to-one path does), and it is untested here. Not measured here: how much of the 58 ms the import accounts for (a leg with the import elided is needed); the seven keys' requests and forkchoices add 5.99 registry hits and 7 commit forkchoices a block (`Canonical chain committed` 28-36 ms, as on followers) which the engine thread absorbs at 26-36% CPU.

**3. Tuning.** On windows 1 and 2, leg by leg (E=1): pinning to 74 CPUs costs 9-10% (A 1,032,300 and Ab 1,053,973, 2.1% apart, the pair; against A208 1,135,531 and loop328 E1 / E1b 1,140,951 / 1,108,184). Raising the build pool to 64 and rayon to 32 gives +8.6% (T64 1,233,322, window 2 1,140,489), the same configuration as loop328 E1T (1,222,462 / 1,195,299): two legs of one configuration in two rounds, 0.9% apart in window 1 and none above 1,423,235. Rayon 64 beside build 64 changes window 1 by +7 transactions a second and window 2 to 1,206,163 (T64R64): no gain in window 1 for 4.7 more cores. Build 96 with rayon 48 (T96) is the best static leg, 1,265,913 and 1,173,450 (+2.6% over T64, 36.2 cores busy): `roots_ms` 35 (p90 93), `par_exec_ms` 24, cycle median 122.3 ms. Its repeat BR reads 1,276,674 and 1,189,628, 0.8% above and 1.4% above in window 2, so T96 is confirmed by a second leg of the same configuration: **1.266M and 1.277M in window 1, 1.173M and 1.190M in window 2 (E=1)**; neither exceeds 1,423,235 or 1,500,000. T96 at 200,000 transfers a block (BG) reads 1,246,618 / 1,193,264 with a 153.8 ms median cycle, 2.5% below T96's 163k blocks in window 1. `par_ms` stays at 126-133 ms on every thread leg although `roots_ms` falls 87 to 33 and `par_exec_ms` 40 to 23; the roots and the execution together are 56 ms, so about 70 ms of the build's 126 are something else (the wait for the parent's fields and output, and the import's competing root, per section 2); the threads reach the point where more of them do not help, which is the second reason the doubled execution matters. Single legs T64R64, T96 and BG are reported, not concluded; the T96 pair is the best-confirmed configuration.

**4. The counter.** `once_served` on the import lines is the block's own served count taken when the line is printed, before the six waiters are served, and read 0. The cumulative `once_served_total` (already in the registry's counts) is now printed beside it at the five sites in `payload_serve.rs` (commit 79fb07832, five added lines; the gate passed): 11,995 served over 2,001 blocks in WARM, 12,811 over 2,137 in T96 (5.99 and 5.99 a block).

Conclusion (E=1, one host). The base line's knobs are the three-node leader's, so mis-sizing is not the cause of E=1's slow build; the cause found is that the single layer builds each block and then executes and roots it again for the keys' import requests (1,175 of 1,179 blocks against 2 of 750 at three nodes), which doubles the roots and serialises the build behind the import's root. Threads still help (+8.6% at build 64, +11-12% at build 96 with rayon 48, confirmed by two legs: 1.27-1.28M in window 1), but the seal still binds 53-72% of blocks and `sealed_at` (130-137 ms) stays above the three-node leader's 97. Eliding the self-import is the next change; no knob in this round moves it. No tag, `main` untouched.

### 10.78 E=1 with the re-execution fix (loop331): the chain is tick-bound at 1.59-1.61M on 163k blocks; pacing alone reaches 2.0M at 80 ms; at 70 ms the feed gives out

Loop331 is measurement only (launcher at tip dc091ad74, which holds 625bceb1a (a layer never executes a block it built under `N42_IMPORT_ONCE`) and 1fa8abd0b; `derive331.py` derives the runner from loop330's; the gate ran 964 tests including `n42 --lib`; claim 21:18-22:09, one claim, ten legs; free space 1.36-1.42 TB). Every figure is E=1: seven validator keys on ONE execution layer (`F7_EL_MAP=0,0,0,0,0,0,0`, `N42_IMPORT_ONCE=1`, the seven-validator bench genesis), and is not comparable with the three-node independent-execution record. R is loop330's T96 line exactly (build pool 96, rayon 48, all 208 CPUs, pacing 100); B32 is loop330's A208 knobs (build pool 32, rayon 16); RP90/80/70 are R at that pacing (run only because the best leg so far sealed under the pacing plus 10 ms, median 48-51 ms); RFS is R plus `N42_FIELDS_AT_SEAL=1`; RG is R at 200,000 transfers a block; BESTb repeats the highest single leg by window 1 (RP70). The first launch attempt of loop327 released the box without a leg (a source file was newer than its binary), so loop331 ran first.

| leg | win1 | win2 | win3 | round txs | blocks w1 / txs per block / full | cycle mean / median / p90 | sealed_at med / p90 | layer cores | persist ms/block | peak RSS | in-mem max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 1,613,647 | 1,346,954 | 0 | 88.8M | 297 / 163,000 / 100% | 101.3 | - | - | 38 | 27.5 G | - |
| R | 1,613,653 | 1,238,297 | 0 | 85.6M | 297 / 163,000 / 100% | 101.3 / 101.4 / 102.0 | 49 / 59 | 24.1 | 39 | 27.5 G | 12 |
| Rb | 1,591,921 | 1,314,355 | 0 | 87.2M | 295 / 162,000 / 99% (292 of 295 full) | 101.4 / 101.4 / 102.0 | 47 / 58 | 24.3 | 39 | 28.0 G | 11 |
| B32 | 1,597,033 | 1,428,455 | 0 | 90.8M | 296 / 162,000 / 99% (293 of 296) | 101.3 / 101.3 / 101.9 | 43 / 49 | 15.3 | 38 | 27.1 G | 11 |
| RP90 | 1,787,492 | 108,197 | 0 | 56.9M | 329 / 163,000 / 100% | 91.3 / 91.4 / 92.3 | 50 / 60 | 26.3 | 37 | 28.1 G | 11 |
| RP80 | 2,004,395 | 0 | 0 | 60.1M | 369 / 163,000 / 100% | 81.3 / 81.3 / 87.2 | 49 / 61 | 29.9 | 32 | 29.4 G | 12 |
| RP70 | 2,053,895 | 0 | 0 | 61.6M | 417 / 153,924 / 77% (289 of 417) | 71.8 / 71.3 / 73.6 | 49 / 60 | 30.7 | 30 | 31.8 G | 13 |
| RFS | 1,613,239 | 1,303,498 | 0 | 87.5M | 297 / 163,000 / 100% | 101.3 / 101.3 / 102.0 | 49 / 61 | 24.1 | 40 | 27.8 G | 12 |
| RG | 1,964,647 | 0 | 0 | 59.0M | 295 / 200,000 / 100% | 101.4 / 101.4 / 109.4 | 60 / 73 | 28.9 | 41 | 29.4 G | 11 |
| BESTb (RP70) | 2,060,263 | 0 | 0 | 61.8M | 416 / 154,603 / 77% (289 of 416) | 72.0 / 71.4 / 78.2 | 48 / 61 | 30.8 | 30 | 32.7 G | 13 |

(Window 3 is empty on every leg, and window 2 is empty from RP80 on: the replay set is 192M transactions and a fast chain consumes it inside window 1 plus part of window 2; judge on windows 1 and 2 and read window 2 as feed-limited. "Layer cores" is the layer's CPU in window 1 in cores busy; the seven validators together use 0.8-1.1.)

The fix. The proofs, on every leg at the end of the leg: `own_executed_again` 0, `own_from_build` equal to `once_blocks` and `once_imports` (R 2,548 of 2,548, Rb 2,542, B32 2,533, RP90 2,830, RP80 3,178, RP70 3,589, RFS 2,548, RG 2,532, BESTb 3,599), no `direct import: executed here` line for any block the layer built (0 on all legs; analyze328 reports "none also directly imported"), no warn line, `once_served_total` 15,181-21,583 (six waiters per block, as designed). The leader's seal moved from loop330's 130-155 ms to 43-50 ms at 163k (60 at 200k): the phase medians for R are `par_ms` 46, `par_exec_ms` 22, `roots_ms` 19, `parent_fields_ms` 0, `sealed_ms` 4 (p90 50 / 23 / 22 / 0 / 5); the three-node leader of loop326 N sealed at 101 / 159 (median / p90) on an independent execution.

Judging, R and Rb against loop330's T96 / BR (same knobs, new binary): window 1 1,613,653 and 1,591,921 against 1,265,913 and 1,276,674, +26% to +27% (the pair differs by 21,732, the controls T96/BR by 10,761; both legs differ from both controls in the same direction by 315,000+, the rule is met); mean cycle 101.3 / 101.4 against 127.2 / 126.6 ms, 25 ms lower; `sealed_at` 49 / 47 against 186 / 189 as loop330 printed it. B32 (build 32, rayon 16) reads 1,597,033 with 15.3 cores against R's 24.1: the extra threads are no longer needed (R, Rb and B32 are within 1.4% on window 1, inside the controls' spread; B32 has the best window 2, 1,428,455, with a fuller feed). Two legs of one configuration above 1,427,354: R and Rb (window 1), and above 1,500,000: R and Rb both exceed it (1.61M and 1.59M), so was B32 (1.60M); RP80 and RP70 exceed 2.0M. Say it first: the 1.5M goal is passed on E=1 windows by three configurations, each with its pair (R/Rb, and B32 near them), at 100 ms pacing.

What binds. At 100, 90 and 80 ms pacing the tick binds every block (binding-wait script: tick 99.7-100%, quorum 0, seal 0-0.3%); the slowest key votes 2.7-2.9 ms after the proposal (p90 3.5-14 ms), so the votes and the seal are not in the way; the cycle equals the pacing plus 1.3 ms and window 1 is 163,000 / pacing. So R, Rb, B32 and RFS (fields at the seal: 1,613,239, no change, parent_fields is already 0) measure the pacing, not the chain's capacity; the persistence time per full block (37-41 ms) is far under the cycle and the in-memory maximum stays 11-13. RP90 gives 1,787,492 (11.1% over R, the pacing ratio), RP80 2,004,395 with 369 of 369 full blocks (cycle 81.3, p90 87.2, queue 800-850k, flood 1.99M/s). RG (200,000 transfers a block at 100 ms) reads 1,964,647 with every block full, sealed_at 60 and 28.9 cores busy.

The feed. At 70 ms the chain outruns the feed: RP70 and BESTb have 77% full blocks in window 1 (289 of 417 and 289 of 416; mean 153,924 and 154,603 transactions), the queue falls from 674,500 to 96,500 within 20 s (BESTb 705,250 to 110,250) and the seal binds 1.4-2.6% of blocks; their window 1 (2,053,895 and 2,060,263; the pair differs by 6,368) is therefore bounded by the feed, which the offer of 2.0M a second to one layer sets (flood median 2.0M/s, the ingest gate sits at 870k queued), not by the chain: the 70 ms legs cannot be quoted as the chain's capacity, and at 163k a block 70 ms needs 2.33M a second. The pacing legs' window 2 is nearly empty because the 192M set is consumed (RP90 56.9M in the round, RP80 60.1M). A second claim with a higher offer and a longer set is needed to find where the chain itself stops (layer cores 30.7 of 208 at RP70, sealed_at 49 ms, so there is room); no variable was changed in this round.

Correctness on every leg: no_variant 0, own_not_committed 0, tc 1 (the start-up certificate), invalid_blocks 0, gas_mismatch 0, direct_imports_failed 0, proposals_given_up 0, engine idles over 5 s 1, imports over 600 ms 0 (R, RP80, RP70; the others print the same), flood 192,000,000 accepted 0 rejected on every leg (97-122 s). Last key to vote: spread over the six non-leader keys (40-101 of 295-415 blocks), no key dominant.

Conclusion. The second execution was the whole of the E=1 shortfall: with the layer's own build recognised the leader seals at 43-50 ms, the layer uses 15-24 cores at 100 ms pacing, and window 1 is set by the pacing alone: 1.59-1.61M at 100 ms, 1.79M at 90, 2.00M at 80 (every block full). Window 1 above 2.0M needs a feed above 2.0M a second; the next round is the feed (flood workers, replay readers, the ingest gate, `F7_FLOOD_RATE`) with pacing 80, 70 and 60 ms. E=1 figures only, not compared with the three-node record. No tag, `main` untouched.

### 10.79 The E=1 peak (loop332): the feed was a rate setting, not the chain; with it raised the chain reads 2.00M at 80 ms, 2.28M at 70, 2.41M at 60 (163k blocks) and 2.45M at 80 ms with 200,000-transfer blocks, every block full; the seal starts to bind at 60 ms

Loop332 is measurement only (launcher at tip 66b9e0238 with the loop331 fix 625bceb1a / 1fa8abd0b in it; `derive332.py` derives the runner from loop331's, `analyze332.py` adds the feed figures; the gate ran the full test list including `n42 --lib`; claim 22:30-23:18, one claim, nine legs; free space 1.36-1.42 TB, datadirs wiped at the end). Every figure is E=1: seven validator keys on ONE execution layer, `N42_IMPORT_ONCE=1`, one host, seven signatures; none is compared with the three-node record. Base B is loop331 B32 (build pool 32, rayon 16, all 208 CPUs, tick pacing) with the feed raised: `F7_FLOOD_RATE=4000000` and `F7_BENCH_POOL_SLOTS=2000000` (the ingest gate follows the pool at 5/6, 1.667M). WARM and B80/B80b are at 80 ms; B70, B60 at 70 and 60 ms; G80/G100 at 200,000 transfers a block (`F7_GASCEIL_ARG=4200000000`) at 80 and 100 ms; X and Xb repeat the leg the runner picked (best window 1 among legs with >= 95% full blocks and the seal under a third: G80, so X and Xb are G80's configuration, three legs of one configuration in all). B50 was skipped by the rule (B60 showed the seal binding 35.2% of blocks).

1. What bounded the feed in loop331: the limiter. The flood's `--rate` was 2,000,000 and every 5 s sample of RP70 read 1,999,748-2,000,556 per second (the first sample 2.37M is the limiter's burst), so delivery was the setting, not a stage. Stage ceilings from the RP70 logs where the queue drained: the layer's ingest line reads rate 2.000M/s with `slots_busy_pct` 15 (the ingest's worker slots were 15% busy: a ceiling near 13M/s), `busy_us_per_tx` 0, `recover_us_per_tx` 0 (attested frames are admitted without per-transaction verification), `reply_us_per_frame` about 1 ms; the flood's 64 workers hold 32 frames of 500 each (about 1.0M transactions in flight) at an 80 ms reply, a ceiling above 12M/s; the flood process burned 0.15-0.55 cores of its 32 (so the flood is nowhere near CPU-bound and no layer CPUs were taken for it); the replay reads 64 files sequentially (30 GB for 192M, 0.3 GB/s). So the only binding element was `F7_FLOOD_RATE` and, at 70 ms, the pool: the gate sat at its limit (833k pending, `deepest pool 833,500`) on the legs where the chain consumed less than the offer, and at 70 ms the queue fell from 674k to 96k. What I changed (variables only): rate 4.0M (not separately tried at 3.0M), pool 2.0M and gate 1.667M. Result, from the ingest lines of the loop332 legs: the queue stays at 1.50-1.70M (the gate) through window 1 on every leg including B60 and G80, so the pool never drained; delivery is then set by the gate's backpressure (`gate_us_per_frame` 6-11 ms, `reply_us_per_frame` 13-16 ms, i.e. frames wait for room, the opposite of starvation) and equals the chain's consumption: delivered median per 5 s 1.93-1.96M (80 ms), 2.21M (70), 2.23M (60), 2.28-2.34M (G80, X, Xb). The feed is not the limit up to 2.46M/s, the highest rate read; the ingest's `slots_busy_pct` is 16-20, `busy_us_per_tx` 0-1.

2. The replay set. 192M transactions run out at +65 s (G80, X, Xb, B60), +70 s (B70) and +80 s (80 ms legs) of delivery, so window 2 is empty on every leg and the judgement is window 1. Seconds of full blocks sustained (first full build to the first short block, or to the last build when none was short): 99 / 98 s (B80 / B80b), 88 (B70), 84 (B60), 84 / 83 / 83 s (G80, X, Xb), 100 s (G100): every leg held 100% full blocks for as long as the set lasted (the end of the set, not a starved queue, ended each run). A 400M set would take two to three times the generation of the 192M one (that time was not measured in this round), about 63 GB (the 192M set is 30 GB in `/data/n42-pregen/g900000`; the directory holds 58 GB of sets; `/data` has 1.4 TB free), and 6,000 senders at 32,000 per sender hold only 192M: 400M needs about 12,500 senders at the same depth (or 67,000 per sender, which the replay's fixed 64-file / 64-worker layout and the funding step bound). Not done here.

| leg | win1 | blocks w1 / txs per block / full | cycle mean / median / p90 | sealed_at med / p90 | layer cores | persist ms/block | peak RSS | in-mem max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (80) | 2,004,824 | 369 / 163,000 / 100% | 81.3 / 81.4 / 85.6 | 50 / 62 | 19.8 | 32 | 29.8 G | 11 |
| B80 | 2,004,840 | 369 / 163,000 / 100% | 81.3 / 81.3 / 84.4 | 50 / 62 | 19.4 | 32 | 29.8 G | 12 |
| B80b | 2,003,926 | 369 / 163,000 / 100% | 81.3 / 81.3 / 82.2 | 50 / 61 | 19.1 | 32 | 29.9 G | 11 |
| B70 | 2,276,160 | 419 / 163,000 / 100% | 71.8 / 71.3 / 73.7 | 56 / 71 | 22.5 | 31 | 30.6 G | 13 |
| B60 | 2,412,079 | 444 / 163,000 / 100% | 67.5 / 62.1 / 84.5 | 61 / 85 | 24.0 | 33 | 30.9 G | 14 |
| G80 (200k) | 2,449,405 | 368 / 200,000 / 100% | 81.8 / 81.4 / 87.8 | 66 / 82 | 23.9 | 41 | 32.2 G | 16 |
| G100 (200k) | 1,979,938 | 297 / 200,000 / 100% | 101.3 / 101.3 / 104.5 | 57 / 70 | 18.8 | 41 | 30.6 G | 12 |
| X (= G80) | 2,451,724 | 368 / 200,000 / 100% | 81.9 / 81.4 / 86.4 | 69 / 93 | 23.6 | 41 | 31.4 G | 14 |
| Xb | 2,452,761 | 368 / 200,000 / 100% | 81.7 / 81.4 / 86.4 | 70 / 110 | 23.2 | 39 | 31.1 G | 13 |

Leader phases, median / p90 ms (par / par_exec / roots / parent_fields / sealed): B80 43 / 21 / 22 / 0 / 4 (p90 52 / 25 / 26 / 7 / 11); B70 46 / 22 / 23 / 0 / 4 (68 / 25 / 27 / 17 / 21); B60 52 / 21 / 24 / 3 / 8 (83 / 25 / 28 / 20 / 25); G80 55 / 26 / 28 / 0 / 6 (76 / 29 / 33 / 16 / 22); Xb 57 / 26 / 29 / 0 / 6 (106 / 29 / 34 / 21 / 27). The flood used 0.15-0.55 cores of its 32; validators 0.8-1.2 cores together.

Binding-wait shares (tick / quorum / seal, mean cycle of the class ms): B80 100% / 0 / 0; B80b 100 / 0 / 0; B70 96.4% (71.4) / 0 / 3.6% (81.6); B60 64.8% (62.2) / 0 / 35.2% (77.8); G80 97.0% (81.4) / 0 / 3.0% (95.9); G100 100 / 0 / 0; X 96.2 / 0.3 / 3.6; Xb 97.0 / 0 / 3.0. A feed-short block count is 0 on every leg (all blocks full, queue at the gate), so "feed" binds nothing. The tick binds to 70 ms; at 60 ms the seal binds 35% of blocks (the tick-bound cycle median is 62.1 ms, the mean 67.5, p90 84.5 ms): the cycle then follows the seal (`sealed_at` p90 85 ms against a 60 ms tick), so the chain itself starts to bind between 70 and 60 ms for 163k blocks, and at 200k blocks at 80 ms the seal binds 3% (p90 `sealed_at` 82-110 ms).

Strain as the cycle shortens: the slowest key's vote delay median 2.8 ms (80 ms), 4.3 (70), 9.6 (60) and p90 14.7-16.8 ms (80), 15.6 (70), 29.9 (60), 25-29 (G80 / X / Xb, 8-10 median) against a tick of 60-80 ms: still well inside the tick, quorum binds 0-0.3%. `tick_late` median 1.0 ms, p90 1.5-1.6 ms on every leg. The build throttle (soft 48 / hard 80 unpersisted blocks) delayed 0-2 proposals a leg (B70 once, 316 ms; B60 twice, max 231 ms; G80 once 383 ms; X twice, 394 ms; Xb once, 174 ms), hard holds 0, the maximum unpersisted blocks 13-16 (so persistence keeps up: 31-33 ms per full block of 163k at 60-80 ms, 39-41 ms per block of 200k at 80-100 ms, always below the cycle). Timeout certificates: 1 on every leg (the start-up certificate); given-up proposals 0; own_not_committed 0; invalid_blocks 0; gas_mismatch 0; direct_imports_failed 0; imports over 600 ms 0; engine idles over 5 s 1; flood 192,000,000 accepted, 0 rejected on every leg. The proofs: `own_executed_again` 0, `once_imports` = `once_blocks` = `own_from_build` (B80 3,169, B80b 3,167, B70 3,610, B60 4,002, G80 3,109, G100 2,528, X 3,102, Xb 3,120) and no `direct import: executed here` line for an own-built block on any leg.

Judging (pairs only; E=1). Pair B80 / B80b: 2,004,840 and 2,003,926 against loop331's single RP80 2,004,395: the three agree within 914 (0.05%), the pair confirms it. Pair G80 / X / Xb (one configuration, three legs): 2,449,405 / 2,451,724 / 2,452,761, spread 3,356 (0.14%), so 200,000-transfer blocks at 80 ms read 2.45M, +22.2% over 163k blocks at 80 ms; against G100 (1,979,938, single leg, loop331 RG 1,964,647) the gain is the pacing ratio. Both pairs exceed 1,427,354 and 1,500,000 (say it first: 2.00M and 2.45M, each with its pair, every block full in window 1). Best confirmed pair: G80 / X / Xb at 2.45M (transactions per block 200,000, cycle 81.7-81.9 ms). Best single leg: B60 at 2,412,079 (163k blocks, 100% full, cycle mean 67.5) is below G80's 2.45M; B70 2,276,160 (single) lies between B80 and B60; no single leg exceeds the G80 trio. Reported, not concluded: B70 and B60 are single legs; B60's gain over B70 (+6.0%) is smaller than the pacing ratio (+16.7%) because the seal binds 35% of its blocks.

What this says. At E=1 the chain, with the feed no longer a limit, is bound by the tick down to 70 ms, and from 60 ms by the leader's seal (par_ms p90 83 ms at 163k; 76-106 ms at 200k); the layer uses 19-24 of 208 cores, the votes, the persistence (31-41 ms) and the ingest (16-20% busy) all have room. The limit to move next is the seal's tail (par_ms p90, parent_fields_ms p90 17-22 ms at 70 ms and below), not the feed. B50 and a 200k leg at 70 or 60 ms were not run (rule); a replay set above 192M is needed to read window 2 at these rates. No tag, `main` untouched.

### 10.80 A 400M replay set and the E=1 peak (loop333): 2.45M on every full-block configuration in window 1, 2.15-2.29M in windows 2-3; the chain's capacity is about 2.5M, the cost of the first minute is a state-wait tail in the seal

Loop333 is measurement only, E=1 (seven validator keys on ONE execution layer, `N42_IMPORT_ONCE=1`, one host, seven signatures; none of the figures is compared with the three-node record). Launcher at tip 79f20617a (loop331's fix in it; `derive333.py` derives the runner from loop332's, `analyze333.py` adds the per-window and tail figures; the gate ran the full test list including `n42 --lib`; claim 01:14-02:26, one claim, eleven legs run).

Item A, the set. Generated under the claim, before the first leg, with the old set untouched: `tx_flood --pregen-out /data/n42-pregen/g900000-400m --pregen-txs 400000000 --alg ed25519 --chain-id 1143 --senders 12500 --pertx 32000 --offset 900000 --gasprice 1000000000000000000000000 --gas 21000 --recipients 2000000 --rpcbatch 500 --conc 64 --gateway-key seed:n42-bench-gateway`. 400,000,000 transactions in 800,000 frames, 64 files, 64.88 GB (162.2 bytes a transaction; 61 G by `du`), 49 s wall (8.16M transactions a second); `/data` free 1,247 G before and 1,187 G after. The genesis alloc does not limit the sender set: the senders are derived from `--offset` and funded at run time by the flood's own funding step from the faucet (12,500 funded in 1.4 s; the round needs 8.4e36 wei against the faucet's 7.7e75), so no genesis was touched; the runner passes `--senders 12500` through a new `F7_SENDERS_ARG` (6,000 for the old set), and the replay refuses any argument mismatch. The flood then runs 175-186 s and delivers all 400M on every leg.

Legs. Base G = loop332 G80 (200,000 transfers a block, 80 ms, feed `F7_FLOOD_RATE=4000000`, pool 2.0M, build pool 32, rayon 16); G70 at 70 ms; H100 and H80 at 250,000 a block (gas ceiling 250,000 x 21,000 = 5,250,000,000, `F7_GASCEIL_ARG=5250000000`) at 100 and 80 ms; B70b is loop332's B70 (163k at 70 ms) again. G60 was skipped by the rule (G70's seal binds 42.6% of its blocks). X and Xb were meant to repeat the best single leg by window 1 with full blocks and the seal under a third: the runner picked H100 and ran the pair (X1 / Xb1 below). A defect in `derive333.py`, now fixed, left loop332's own X selection in the runner, which then ran a second X and Xb with G80's configuration (X2 / Xb2; this is G80 twice more: four legs of one configuration). The bench dirs `bench-loop333X` and `Xb` hold the second pair; the first pair's logs were copied before they were overwritten (`bench-loop333X1`, `Xb1`; X1's flood.log and metrics were overwritten, its node logs are intact).

The harness note. `fleet7-measure.py` reads the window's blocks over RPC after the window; its window 3 reads zero transactions on every leg (the node's RPC refuses under load: `basefee 7->7`), although the canonical chain shows full blocks to the end of the flood (2,000 builds, 400.0M transactions in canonical blocks on every leg). Windows below are therefore 30 s slices from the first full build counted from the layer's `Block added to canonical chain` lines (`analyze333.py`); the bench's own windows 1 and 2 agree with them within 3% (window 1: G80 2,446,307, G80b 2,445,726, G70 2,524,846, H100 2,449,389, H80 2,515,522, B70b 2,281,926, X1 2,455,100, Xb1 2,449,910, X2 2,452,985, Xb2 2,445,948).

| leg | win1 | win2 | win3 | blocks w1 / txs per block / full | cycle mean w1 (median / p90) | sealed_at med / p90 / p99 w1 | layer cores | persist ms/block | peak RSS | in-mem max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (G80) | 2,446,667 | 2,206,667 | 2,226,667 | 367 / 200,000 / 100% | 81.8 / 81.4 / 87.5 | 69 / 85 / 132 | 23.0 | 58 | 43.9 G | 13 |
| G80 | 2,446,667 | 2,240,000 | 2,200,000 | 367 / 200,000 / 100% | 81.8 / 81.4 / 87.0 | 67 / 85 / 132 | 23.5 | 59 | 43.4 G | 16 |
| G80b | 2,446,667 | 2,233,333 | 2,233,333 | 367 / 200,000 / 100% | 81.9 / 81.3 / 87.9 | 71 / 93 / 144 | 23.0 | 57 | 47.2 G | 14 |
| X2 (G80) | 2,446,667 | 2,220,000 | 2,220,000 | 367 / 200,000 / 100% | 81.8 / 81.3 / 84.5 | 73 / 91 / 135 | 23.2 | 59 | 46.1 G | 15 |
| Xb2 (G80) | 2,440,000 | 2,226,667 | 2,246,667 | 366 / 200,000 / 100% | 82.0 / 81.5 / 86.9 | 73 / 89 / 127 | 24.1 | 58 | 47.3 G | 14 |
| G70 | 2,511,633 | 2,220,000 | 2,273,333 | 377 / 199,865 / 100% | 79.1 / 72.8 / 99.3 | 70 / 91 / 142 | 24.2 | 58 | 46.2 G | 13 |
| H100 | 2,450,000 | 2,291,667 | 2,141,667 | 294 / 250,000 / 100% | 102.2 / 101.4 / 106.7 | 88 / 107 / 177 | 23.3 | 75 | 46.2 G | 13 |
| X1 (H100) | 2,450,000 | 2,291,667 | 2,166,667 | 294 / 250,000 / 100% | 101.9 / 101.4 / 106.7 | 91 / 106 / 163 | - | 75 | 46.1 G | 15 |
| Xb1 (H100) | 2,441,667 | 2,266,667 | 2,141,667 | 293 / 250,000 / 100% | 102.4 / 101.5 / 111.3 | 88 / 112 / 177 | 23.3 | 75 | 44.6 G | 13 |
| H80 | 2,508,333 | 2,250,000 | 2,108,333 | 301 / 250,000 / 100% | 99.0 / 95.9 / 119.7 | 84.5 / 106 / 164 | 23.6 | 72 | 45.1 G | 13 |
| B70b (163k) | 2,282,000 | 2,129,867 | 2,151,600 | 420 / 163,000 / 100% | 71.5 / 71.3 / 74.7 | 57 / 70 / 114 | 22.5 | 43 | 45.8 G | 17 |

(Cores are the layer's CPU in window 1; the validators together use 0.8-1.1; X1's threadcpu was not carried over.) The feed check: on every leg the queue at the leader's builds (`queued`) sits at the gate (median 1.56-1.64M) in all three windows, minimum 1.07-1.5M after the first seconds (window 1 minimum 0.5M on G70 at the very start); delivered median per 5 s 2.15-2.24M (p10 1.99-2.13M) against an offered 4.0M, `reply_us_per_frame` 12.6-13.9 ms and `gate_us_per_frame` 5.1-8.4 ms (the gate makes the frames wait), ingest `slots_busy_pct` 18-20, `busy_us_per_tx` 0-1: no leg drained the queue, so neither pool nor rate was raised, and the feed bounded nothing. Seconds of full blocks sustained: 175-187 s on every leg (the set lasted the whole of 177 s; B70b 187 s), 100% full in every window of every leg except G70's window 2 (337 of 364 full by the bench; all full by the canonical count: the bench reads RPC).

Correctness on every leg (11 legs): tc 1 (the start-up certificate), own_not_committed 0, given_up 0, invalid_blocks 0, gas_mismatch 0, direct_imports_failed 0, no_variant 0, unanswered_reads 0, imports over 600 ms 0, engine idles over 5 s 1, flood 400,000,000 accepted 0 rejected. The proofs: `own_executed_again` 0 and `once_imports` = `once_blocks` on every leg; `own_from_build` equals them except B70b (4,588 against 4,589 with one `direct import: executed here` line: one block this layer imported directly, never an own block executed again). The throttle delayed 0-3 proposals a leg (longest 374 ms), hard holds 0, at most 14-16 unpersisted blocks; the slowest key's vote delay median 6.5-12.4 ms, p90 27-41 ms against a tick of 70-100 ms, quorum binds 0%; `tick_late` median 1.0 ms, p90 1.5-1.6 ms.

Binding-wait shares (tick / quorum / seal; mean cycle of the class): G80 95.6 / 0 / 4.4 (81.3 / 91.1), G80b 94.0 / 0 / 6.0, X2 96.5 / 0 / 3.5, Xb2 95.4 / 0 / 4.6, G70 57.4 (72.0) / 0 / 42.6 (89.4), H100 96.6 / 0 / 3.4, Xb1 92.8 / 0 / 7.2, H80 18.5 (82.0) / 0 / 81.5 (103.5), B70b 98.6 / 0 / 1.4. Leader phases window 1, median / p90 (par / par_exec / roots / parent_fields / sealed ms): G80 58 / 26 / 29 / 0 / 5 (78 / 31 / 35 / 16 / 22); G70 60 / 26 / 29 / 0 / 6 (81 / 30 / 33 / 15 / 20); H100 76 / 35 / 35 / 0 / 7 (99 / 41 / 40 / 16 / 24); H80 73 / 35 / 35 / 0 / 7 (97 / 40 / 41 / 13 / 21); B70b 46 / 22 / 24 / 0 / 4 (65 / 25 / 29 / 16 / 20).

Windows 2 and 3 do not hold the window-1 rate. All full-block legs read 2.45M in window 1 and 2.14-2.29M afterwards (88-94% of window 1; H80 84% by window 3): in window 2 the cycle stretches because the seal does (G80 `sealed_at` median / p90 / p99 75 / 133 / 225 in window 2 and 76 / 142 / 236 in window 3, against 67 / 85 / 132 in window 1; `par_ms` p90 130-138 against 78), while the layer's RSS climbs 13 -> 21 -> 27 -> 33 G through the three windows (peak 43-47 G over the leg, against 30-32 G for loop332's shorter legs), in-memory blocks stay 10-17 and the throttle is silent, and persistence per full block stays below the cycle (57-59 ms at 200k, 72-75 ms at 250k, 43 ms at 163k). So the throttle and the persistence keep up; what degrades is the leader's seal as the state grows.

The leader's tail (window 1; p90 / p99 ms): `sealed_at` G80 85 / 132, G70 91 / 142, H100 107 / 177, H80 106 / 164, B70b 70 / 114; `par_ms` 78 / 126, 81 / 133, 99 / 172, 97 / 159, 65 / 111; `parent_fields_ms` p90 13-18, p99 25-36. In windows 2-3 `sealed_at` p90 / p99 climb to 128-183 / 207-299 ms. What the slow blocks have in common (top 5% of `sealed_at` in the first 90 s, 42-63 blocks a leg, slow mean 148-222 ms against 61-95 ms for the rest, identical across all eleven legs): the build's execution starts late: `gap_before_exec_ms` 75-114 against 6-11 and `state_wait_ms` 73-112 against 4-9 (the build waited about 90 ms for the parent's state), the root faults 3-5x (`root_faults` 198-445 against 55-111; `root_faults_undo` and `root_append_faults` 2-3x), the execution itself about twice as slow (`par_exec_ms` 47-76 against 25-38, `par_run_ms` 121-182 against 30-49, page-fault bound), `batch_max_ms` 46-57 against 19-24. They are isolated: at most 2 of 42-63 slow blocks follow a slow block, and they show no number pattern modulo 8. So the tail is about 5% of blocks that start about 90 ms late on the parent's state and fault their way through the root; it is what stretches the cycle in the later windows and what makes G70 and H80 seal-bound.

Judging by pairs (E=1). G80 / G80b: window 1 2,446,307 / 2,445,726 (bench), 2,446,667 both (canonical): a pair within 0.02%; with X2 / Xb2 (2,452,985 / 2,445,948) four legs of the configuration read 2.446-2.453M. H100 / X1 / Xb1: 2,449,389 / 2,455,100 / 2,449,910, the pair of the best single leg: 2.449-2.455M. B70b 2,281,926 with loop332's B70 2,276,160: a pair within 0.25% (163k at 70 ms: 2.28M). Both full-block pairs read the same 2.45M (80 ms x 200k and 100 ms x 250k are both a 2.5M tick), so 2.45M is the tick-bound value of both and not a difference between them. Single legs, reported and not concluded: G70 2,524,846 (the highest window 1; its seal binds 42.6%, cycle mean 79.1 against a 70 ms tick) and H80 2,515,522 (seal binds 81.5%, mean cycle 99.0 against 80 ms): both sit at about 2.5-2.52M although their ticks allow 2.86M and 3.1M. Best confirmed pair: G80 / G80b (and H100 / X1 / Xb1) at 2.45M in window 1 with all blocks full; best single leg: G70 at 2.52M. Two legs of one configuration above 1,427,354 and above 1,500,000: every pair (say it first: 2.45M and 2.28M, all blocks full, every window). The chain's capacity at E=1 is about 2.5M in the first minute (the seal binds when the tick allows more) and 2.1-2.3M once the state has grown for 60-90 s; the next limit is the seal's state-wait tail (about 5% of blocks, about 90 ms each), not the feed, the votes or persistence. No tag, `main` untouched.

### 10.81 The decay was the harness (loop334): with windows from the layer's log, windows 2-3 hold 97-100% of window 1; a third kept layer removes the opener's wait; fields at the seal cuts the seal 10 ms; 70 and 60 ms pacing read 2.65M on a 72 ms floor

All figures are E=1 (seven validator keys on one execution layer, `F7_EL_MAP=0,0,0,0,0,0,0`, `N42_IMPORT_ONCE=1`, validators on their own 16 CPUs), 200,000 transfers a block, the 400M replay set (12,500 senders), feed 4.0M, pool 2.0M, build pool 32. They are not comparable with the three-node independent-execution record. Rates are transactions in the layer's `Block added to canonical chain` lines per second.

**S0 (commit 17fb31cfe, scripts only).** `F7_MEASURE_FROM_LOG=1` (set by the loop334 runners) makes `fleet7-bench.sh` take its three 30 s windows from the layer's canonical-block lines: contiguous, the first starting at the flood's first full block (>= 100,000 transactions). Nothing reads a block over RPC while the flood runs; the shape line is read once after the flood is killed and the chain idles, for a block number taken from the log. What still touches RPC in a leg: the funding transactions and nonce reads before the first window, the decay's `eth_getBlockByNumber(latest)` before the flood, and after the flood: the shape read, `fleet7-verify.py`. `memsample.py` reads the metrics endpoint (not RPC), the sampler and threadcpu read `/proc`.

Binaries. Claim 1 (WARM, G80, G80b, FV, FS, FSb) ran binaries frozen from loop333's build (tip 79f20617a; `crates/` and `bin/` are identical through 17fb31cfe, sha256 n42 bfd51f11f2c92ab1), because the working tree was already carrying another agent's uncommitted leader-layers change; so the control pair carries the script fix only and nothing was rebuilt (the loop333 test gate, 964 tests including `n42 --lib`, ran on these sources). Claim 2 (WARM2, G80n, L3, L3b, L3FS, L3FS70, L3FS60, Q) ran the tip 5a4163ec9 built and tested under its own gate (`n42-engine-types --lib direct_build` added), which contains `N42_LEADER_LAYERS` (default 2) and the opener's woken wait. G80n is a control on that binary (default layers), which separates the fallback fix from the third layer.

| leg | win1 | win2 | win3 | round | blocks w1 | cycle w1 mean / med / p90 | sealed_at w1 med / p90 / p99 | binding tick / seal % w1 | layer cores w1 | peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 2,440,000 | 2,420,000 | 2,433,333 | 218.8M | 366 | 82.1 / 81.5 / 88.6 | 71 / 93 / 137 | 94 / 6 | 23.6 | 33.2 G |
| G80 | 2,453,333 | 2,380,000 | 2,406,667 | 217.2M | 368 | 81.7 / 81.3 / 84.2 | 71 / 88 / 127 | 98 / 2 | 23.1 | 33.2 G |
| G80b | 2,440,000 | 2,406,667 | 2,433,333 | 218.4M | 366 | 82.1 / 81.4 / 89.0 | 71 / 87 / 128 | 95 / 5 | 23.6 | 33.4 G |
| FV | 2,440,000 | 2,386,667 | 2,426,667 | 217.6M | 366 | 82.1 / 81.4 / 87.7 | 62 / 97 / 139 | 95 / 5 | 24.1 | 33.2 G |
| FS | 2,446,667 | 2,393,333 | 2,433,333 | 218.2M | 367 | 82.0 / 81.4 / 89.8 | 59 / 83 / 135 | 96 / 4 | 23.6 | 32.6 G |
| FSb | 2,440,000 | 2,386,667 | 2,433,333 | 217.8M | 366 | 82.1 / 81.4 / 89.6 | 61 / 82 / 126 | 94 / 6 | 23.4 | 33.0 G |
| WARM2 | 2,460,000 | 2,413,333 | 2,446,667 | 219.6M | 369 | 81.7 / 81.4 / 88.9 | 68 / 80 / 89 | 98 / 2 | 23.6 | 33.5 G |
| G80n | 2,453,333 | 2,386,667 | 2,460,000 | 219.0M | 368 | 81.6 / 81.3 / 88.2 | 72 / 81 / 92 | 98 / 2 | 24.0 | 33.5 G |
| L3 | 2,446,667 | 2,393,333 | 2,460,000 | 219.0M | 367 | 81.8 / 81.4 / 87.3 | 71 / 82 / 95 | 97 / 3 | 23.4 | 33.5 G |
| L3b | 2,446,667 | 2,426,667 | 2,433,333 | 219.2M | 367 | 81.8 / 81.4 / 88.1 | 70 / 82 / 92 | 96 / 4 | 23.4 | 33.6 G |
| L3FS | 2,431,367 | 2,400,000 | 2,440,000 | 218.1M | 365 | 82.4 / 81.4 / 88.3 | 59 / 75 / 97 | 94 / 6 | 23.3 | 33.8 G |
| L3FS70 (70 ms) | 2,646,667 | 2,573,333 | 2,613,333 | 235.0M | 397 | 75.6 / 71.9 / 87.6 | 62 / 74 / 96 | 74 / 26 | 25.9 | 34.3 G |
| L3FS60 (60 ms) | 2,653,333 | 2,646,667 | 2,600,000 | 237.0M | 398 | 74.9 / 71.9 / 94.9 | 59 / 69 / 86 | 41 / 57 | 26.3 | 35.4 G |
| Q | 2,446,667 | 2,386,667 | 2,446,667 | 218.4M | 367 | 81.9 / 81.4 / 88.1 | 71 / 82 / 96 | 96 / 4 | 23.6 | 34.0 G |

(WARM and WARM2 are throwaways, shown because they are as good as any leg. Every window is 100% full blocks but one or two; blocks per window 330-398.)

**S0 worked, and almost all of the decay is gone.** The controls' windows 2-3 are 97.0-99.7% of window 1 (G80 97.0 / 98.1, G80b 98.6 / 99.7); loop333's G80 read 91.8 / 89.9 on the same configuration and binary. The RPC window reads were the cause of the 88-94% in 10.80: no `state_wait_on="open"` > 20 ms remains in any leg (loop333 G80 window 2: 45 opens, window 3: 43; loop334 G80: 3 / 1 / 1). The remainder is a 1-3% dip in window 2 only (`sealed_at` median 68-75 across the windows, `roots_ms` 29 -> 32, `parent_fields` p90 rising in window 3), not a monotone decay; RSS grows 3.7 -> 21 -> 27 -> 33 G through the three windows on every leg, in-memory blocks max 10-11, persistence 49 ms per full block (73.8 s over 1,500 blocks in 500 batches; unchanged by any switch), the layer 23-24 cores, the validators 1.0.

**The opener.** G80 (two layers, old fallback) had 25-47 builds a window waiting 60-90 ms on the grandparent (`state_wait_on="grandparent"`, `ggp_missing` 1; window 1: 30 of 367, window 3 of G80b: 47 of 364), p90 `sealed_at` 87-92, p99 127-149. G80n (the fallback fix, two layers): the open still falls back on 12-16% of builds (`open_fallback` true 45 / 50 / 57) but the woken wait is 20.2 ms at p90 (max 40) instead of 60-90, and no build waits over 20 ms (`state_wait` p90 0 in all windows; `sealed_at` p90/p99 81 / 92 in window 1, 82 / 90, 85 / 95). L3 and L3b (three layers): `open_layers` 3 on every build, `open_fallback` never true in 2,200 builds (0 `open_engine_us`), `state_wait_on` = none, with `layer_release` (the wait for a released layer) on 1-3 builds a window and `state_wait_us` median 140 / p90 180-185 / max 5-7 ms; `sealed_at` p99 92-96 in all windows. Neither moves window 1 or the sustained rate at 80 ms pacing, because the tick binds (96-99% of blocks) and the tail it removes was never the cycle's limit.

**Fields at the seal.** FV: `fields_verified` 1,125, `fields_mismatches` 0, `fields_unchecked` 0, `own_executed_again` 0, fleet verify pass (commitments agree, every node advanced). FS / FSb / L3FS: `sealed_at` median 59-61 against 70-71 (-10 ms), p90 75-83 against 82-88 (but a median change: `parent_fields_ms` 0/0 against 0/17-22 and `sealed_ms` 5/7 against 6/23), `rename_wait` gone from the chain; `roots_ms` grows 29 -> 31-33 (the root now races the build). At 80 ms the tick binds either way: window 1 identical.

**Pacing.** L3FS70 reads 2,646,667 / 2,573,333 / 2,613,333 (235.0M), L3FS60 2,653,333 / 2,646,667 / 2,600,000 (237.0M). The seal binds 26% of blocks at 70 ms (so the runner's rule ran L3FS60) and 57% at 60 ms, and the two read the same: the cycle median is 71.9 ms on both (mean 75.6 / 74.9). The floor is the seal (59-62 ms median) plus the commit and vote path after it (~12 ms), not the tick; below ~72 ms pacing buys nothing. Sustained: windows 2-3 are 97.2 / 98.7% of window 1 at 70 ms and 99.7 / 98.0% at 60 ms.

**Q (prefault sizes).** `N42_QMDB_APPEND_AHEAD_MB=256 N42_QMDB_APPEND_REWALK=1 N42_QMDB_UNDO_POOL=128 N42_TWIG_POOL_FLOOR=1024` (all four exist in `crates/n42/twig-core/src/prefault.rs`, defaults 64 / 0 / 64 / 512): 2,446,667 / 2,386,667 / 2,446,667, inside the controls' spread; window-3 `sealed_at` 75 / 84 against G80's 73 / 92; peak RSS 34.0 against 33.2-33.4 G. One leg, no pair, no effect to claim.

**Correctness (all 14 legs).** tc 1 (the start-up certificate), own_not_committed 0, given_up 0, invalid_blocks 0, gas_mismatch 0, direct_imports_failed 0, no_variant 0, unanswered_reads 0, `own_executed_again` 0 of ~1,125 built blocks each; the engine's own-import time per block 30-36 ms median (p90 41-54) in every window of every 80 ms leg, flat across the leg (G80 30 / 32 / 33); the slowest key's vote delay median 5.5-10.3 ms, p90 26-36 ms (identical across legs); the queue at the builds 1.25-1.65M (never under 1.2M); the flood delivered 2.2M/s median.

**Judging by pairs** (a configuration counts when both its legs differ from both controls in the same direction by more than the controls differ from each other). Controls: window 1 2,453,333 / 2,440,000 (spread 13,333); windows 2-3 mean 2,393,333 / 2,420,000 (spread 26,667). Window 1: FS / FSb 2,446,667 / 2,440,000, L3 / L3b 2,446,667 both: inside the controls, nothing confirmed. Windows 2-3: FS / FSb 2,413,333 / 2,410,000 (inside), L3 / L3b 2,426,667 / 2,430,000: both above both controls, but by 6,667-10,000, under the controls' own spread, so not confirmed; Q has no pair; G80n is a single leg (2,453,333 / 2,423,333). The 70 and 60 ms legs are single legs (the round's claim cap allowed one each): no pair. **Best confirmed pair for the peak: G80 / G80b at 80 ms, 2.44-2.45M (tick-bound). Best confirmed pair for the sustained rate: the same pair, windows 2-3 2.39-2.42M (97-99% of window 1).** Unconfirmed single legs: 2.65M peak (L3FS60 and L3FS70, 2.65 / 2.65M) and 2.59-2.62M sustained. Whether a pair's sustained rate reaches its window-1 rate: it does within 1-3% for every 80 ms pair (G80b windows 2 / 3 at 98.6 / 99.7%, L3b 99.2 / 99.5%, FS 97.8 / 99.5%, G80n 97.3 / 100.3%, L3 97.8 / 100.5%): the sustained rate is the peak rate at this resolution (differences under about 3% between single windows are invisible here).

What this changes. The E=1 chain at 200,000-transfer blocks sustains what it peaks at; nothing left on the opener or the harness limits it at 80 ms; the next limit is the ~72 ms cycle floor (seal 59-62 ms + 12 ms of commit and vote), so the next gain is in the build chain itself (8.3: the batch start skew, the execution's 26-27 ms) and a pair at 70 ms and below before anything is claimed.

Files: `scripts/fleet7-runs/{derive334.py,analyze334.py,results/loop334.out}`; the runners are derived by `derive334.py` from loop333's.

### 10.82 The E=1 cycle floor (loop335): pairs at 70 and 75 ms read 2.58-2.65M, the cycle is the seal chain plus 10 ms and consensus is 100 ms off it; block size moves the rate by under 4%; layers 4 and a build pool of 64 add nothing

Every figure is E=1 (seven keys on one execution layer, windows from the layer's canonical log, 400M replay set, no RPC block reads during a flood); not comparable with the three-node record. Base P = loop334 L3FS (`N42_LEADER_LAYERS=3`, `N42_FIELDS_AT_SEAL=1`, 200,000 transfers a block). Tip fa12c4c0b, built and tested under the full gate (1,001 tests) in a git worktree (`/data/n42-build/wt335`, the main tree carried another agent's uncommitted edit that broke `payload.rs` at the first attempt; the same worktree and target dir serve loop336). Claim 2's legs (WARM2, S250, S300, L4, T64) ran first by a launcher mix-up and are labelled "plain feed" (rate 4.0M, pool 2.0M); claim 1 (WARM, P70, P70b, P75, P75b, S163, S163b) ran with the feed raised from the start (rate 6.0M, pool 3.0M). A leg is rerun once when its feed bound (`feedcheck335.py`: under 97% full blocks, or a median queue under 2.5 blocks, in a window); reruns carry `r`.

**Feed.** Loop334's plain feed (rate 4.0M, pool 2.0M, gate 1.67M) held at 70 ms (WARM2 and S250 passed the check) but not above ~2.7M/s: S300 (300k at 105 ms) had 92% full blocks in windows 1 and 2 (queue median 426k in window 2), L4 fell to 95% in window 3 (queue median 285k), and S163 at 60 ms bound in window 3 even with 6.0M / 3.0M (queue median 302k); each rerun with 6.0M / 3.0M (8.0M / 4.0M for S163) passed with the queue at 2.0-3.2M. The raised legs' numbers are the ones reported; S163b (6.0M / 3.0M) passed without a rerun. Delivery median 2.61M/s on P70 (the gate throttles it to consumption).

| leg | win1 | win2 | win3 | round | blocks w1 | cycle w1 mean / med / p90 | sealed_at w1 med / p90 / p99 | tick / seal % | layer cores | peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM (70 ms) | 2,606,667 | 2,566,667 | 2,593,333 | 233.0M | 391 | 76.5/72.6/91.0 | 62/76/91 | 67/32 | 25.9 | 36.8 G |
| P70 | 2,613,333 | 2,566,667 | 2,580,000 | 232.8M | 392 | 76.6/72.2/88.7 | 61/77/102 | 68/31 | 25.7 | 37.0 G |
| P70b | 2,646,667 | 2,546,667 | 2,580,000 | 233.2M | 397 | 75.5/72.0/87.5 | 62/75/90 | 74/25 | 26.2 | 36.3 G |
| P75 (75 ms) | 2,573,333 | 2,540,000 | 2,566,667 | 230.4M | 386 | 77.7/76.4/85.3 | 61/75/89 | 93/7 | 25.9 | 36.4 G |
| P75b | 2,580,000 | 2,573,333 | 2,573,333 | 231.8M | 387 | 77.7/76.4/83.6 | 60/77/93 | 92/8 | 25.1 | 35.9 G |
| S163 (163k, 60 ms; feed-bound) | 2,445,000 | 2,417,833 | 2,386,183 | 217.5M | 450 | 66.5/62.0/78.4 | 51/59/71 | 72/27 | 24.4 | 33.6 G |
| S163r (rerun, feed 8M/4M) | 2,553,667 | 2,483,033 | 2,499,333 | 226.1M | 470 | 63.9/61.5/71.7 | 52/62/82 | 85/15 | 26.0 | 36.2 G |
| S163b | 2,559,100 | 2,493,900 | 2,542,800 | 227.9M | 471 | 63.7/61.5/71.0 | 50/61/75 | 87/12 | 25.7 | 35.4 G |
| WARM2 (70 ms) | 2,630,883 | 2,586,667 | 2,573,333 | 233.7M | 395 | 75.8/71.9/89.2 | 61/76/95 | 73/26 | 25.7 | 34.7 G |
| S250 (250k, 90 ms) | 2,625,000 | 2,600,000 | 2,583,333 | 234.2M | 315 | 95.3/91.9/108.8 | 80/99/117 | 71/28 | 25.6 | 37.0 G |
| S300 (300k, 105 ms; feed-bound) | 2,644,583 | 2,608,233 | 2,500,000 | 232.6M | 269 | 111.7/107.0/131.2 | 93/112/130 | 70/29 | 25.5 | 38.2 G |
| S300r (rerun, feed 6M/3M) | 2,690,000 | 2,620,000 | 2,610,000 | 237.6M | 269 | 111.6/106.7/130.4 | 93/104/142 | 76/21 | 25.3 | 40.0 G |
| L4 (4 layers; feed-bound w3) | 2,632,533 | 2,566,667 | 2,500,567 | 231.0M | 395 | 75.9/71.8/90.2 | 61/68/87 | 78/22 | 26.2 | 35.2 G |
| L4r (rerun, 6M/3M) | 2,646,667 | 2,580,000 | 2,586,667 | 234.4M | 397 | 75.7/71.7/89.5 | 62/72/91 | 73/26 | 25.6 | 36.9 G |
| T64 (build pool 64) | 2,606,667 | 2,466,667 | 2,553,333 | 228.8M | 391 | 76.6/73.0/90.2 | 63/70/89 | 64/35 | 32.1 | 34.6 G |
(Binding shares are window 1, tick / seal %. Every window of every leg is >= 99% full blocks except S300 and L4 plain. Layer cores 24-26 (32 on T64), validators 1.0. RSS 3.7 -> 21 -> 27 -> 33-37 G across the windows on every leg; in-memory blocks max 10-12. Persistence ~49 ms a full block at 200k. `own_executed_again` 0, tc 1, own_not_committed 0, given_up 0, invalid_blocks 0 on every leg. Engine own-import 30-36 ms median per 200k block.)

**The floor, taken apart (`cycle335.py`, P70 and P75, windows 1-3, leader = validator 0; median / p90 ms).** The cycle is the leader's build chain; consensus is not on it.

| piece | P70 | P75 |
| --- | --- | --- |
| chain start -> frame build sealed | 62.5 / 76.4 | 63.0 / 76.2 |
| frame sealed -> early-seal answered | 3.4 / 4.5 | 3.4 / 4.7 |
| early-seal answered -> next chain start (the release) | 2.3 / 18.3 | 2.1 / 19.0 |
| seal-to-seal cadence (chain start -> next chain start) | 72.5 / 92.4 | 73.6 / 93.0 |
| cycle (proposal -> proposal) | 72.1 / 91.2 | 76.4 / 85.7 |
| early-seal answered -> proposal sent | 25.5 / 56.3 | 45.5 / 71.7 (the tick waits) |
| proposal -> each key's vote | 9.7-11.1 per key, slowest key 12.7 / 47.2 | 9.1-11.3, slowest 13.0 / 41.0 |
| proposal -> commit (R1 13, R2 5 at the leader) | 19.5 / 53.9 | 19.9 / 48.5 |
| commit minus the release of the build two on | -109 / -63 (off the chain) | -92 / -56 |
| commit -> Decide at a key | 1.1 | 1.1 |

So the ~12 ms after the seal in the seal-to-seal cadence are not commit and vote (the commit of block H lands 90-110 ms before the build two on is released): they are the frame seal and its answer (3.4), the release (2.3 median, a tail to 18-19 ms at p90 that carries the mean: the one-ahead rule defers the child's start until the proposal path has taken the parent's chained build, scope 9.3) and the remaining 4 ms of the chain start before the first frame is sealed; the mean cycle (75.5-77.7) is the median 72 plus that release tail. At 75 ms the tick binds 92-93% of blocks (proposals tick-bound 635 of 651) and the cycle reads 76.4 (tick + 1.4); at 70 ms the seal binds 25-31% of blocks and the cycle median stays 72.0-72.2.

Repeated per key (what seven keys on one layer cost, over 3 windows of ~620 views): each key syncs its vote log on 148-211 of 623-651 views (6-8 ms median, 24-33% of views; a vote's own path, off the chain unless the proposal waits for it: `body prepared -> proposal sent` 0.6 / 7.6); `commit forkchoice answered` lines are logged only when slow (73-109 per key over the windows, 21-24 ms median, p90 37-62) while the layer's own log shows 1,252-1,294 `Forkchoice updated` lines for 1,152-1,164 canonical blocks (about one reaches the engine per block, the other six are coalesced or answered syncing); `forest lock held` 864-897 lines, 24 ms median (p90 30), i.e. on about 75% of blocks. Of the 3,738 votes in P70, 3,175 waited for execution validation and 563 found the block already validated.

**Judging by pairs** (a configuration counts when both its legs differ from both control legs in the same direction by more than the controls differ from each other; for P70 against P75 each pair serves as the other's control). Window 1: P70 / P70b 2,613,333 / 2,646,667 (spread 33,333); P75 / P75b 2,573,333 / 2,580,000 (spread 6,667): P70's smaller leg beats P75's larger by 33,333 > 6,667: confirmed, P70 +1.3-2.8% over P75. Windows 2-3 mean: P70 2,573,333, P70b 2,563,333, P75 2,553,333, P75b 2,573,333: overlap, nothing confirmed; sustained is 2.55-2.57M at both pacings. Steadier at 75? Windows 2 / 3 as a share of window 1: P75 98.7 / 99.7%, P75b 99.7 / 99.7%; P70 98.2 / 98.7%, P70b 96.2 / 97.5%: yes, a pair at 75 holds its window-1 rate to within 1.3%, at 70 to within 3.8%, but at a lower rate; the sustained means are equal. **Best confirmed pair for the peak: P70 / P70b, 2.61-2.65M in window 1 (confirmed over P75 and over loop334's 80 ms controls, +7%). Best confirmed pair for the sustained rate: none separates; P70, P70b, P75, P75b all read 2.55-2.57M in windows 2-3.** Every window of every full-block pair above (P70, P70b, P75, P75b, S163r, S163b) exceeds 2,452,761 (lowest: S163r window 2, 2,483,033; P70b window 2, 2,546,667).

**Block size** (seal and cycle against size; leader medians in window 1, rate with the feed not binding): 163k: `sealed_at` 50-52, cycle 61.5 median (63.7-63.9 mean), 2.554 / 2.559M in window 1 and 2.49 / 2.52M in windows 2-3 (S163r, S163b; two legs, no control pair at this size); 200k: 61-62, 72.0 (75.5-76.6), 2.61-2.65M and 2.56-2.58M; 250k at 90 ms (S250, plain feed ok, single leg): 80, 91.9 (95.3), 2.625 / 2.600 / 2.583M; 300k at 105 ms (S300r, feed raised, single leg): 93, 106.7 (111.6), 2.690 / 2.620 / 2.610M. The floor is cycle median = `sealed_at` + 10 to 14 ms at every size (163k +11, 200k +10, 250k +12, 300k +14), so the seal chain is linear in the block (~0.31 ms per 1,000 transfers) and the rate is nearly flat: 2.55M at 163k, 2.6-2.65M at 200k, 2.6M at 250k, 2.6-2.7M at 300k; block size moves it by under 4% and the best is the biggest block, by a margin the single legs cannot confirm. Nothing but the seal caps 300k: its blocks are 300,000 transfers (820 of them in the leg, gas 6.3G), gossip 105 MB, frames 600 of 16,384, the gas limit is the genesis value (no climb); the feed is the only limit that appeared (S300 plain).

**L4 and T64.** L4 (four layers) with the feed raised: 2,646,667 / 2,580,000 / 2,586,667, `sealed_at` 62 / 72 / 91, no difference from P70 (three layers already never fall back, 10.81). T64 (build pool 64, rayon 32): 2,606,667 / 2,466,667 / 2,553,333, layer 32.1 cores against 25.7, `sealed_at` 63 / 70 / 89, seal binds 35% against 25-31%: more threads do not shorten the seal (the batches are fewer and larger per thread; 10.81 section 8.3's stagger is dispatch, not thread count) and window 2 is 5% lower; single legs, nothing confirmed.

Files: `scripts/fleet7-runs/{derive335.py,feedcheck335.py,cycle335.py,results/loop335.out,results/loop335-set-b.out}` (the runners were patched in place after the launcher mix-up; `derive335.py` carries the intended text).

### 10.83 One wave and the road runtime (loop336): the road runtime cuts the cycle by 7-10 ms (pair confirmed, 2.72-2.76M peak); one wave is dispatch-clean but 5 ms slower; both together hold 2.59-2.67M in every window; the feed caps at ~2.6M/s

Every figure E=1 (one layer, windows from the layer's canonical log, 400M set). Tip f340aaf9c = ba8c595ee (default-off `N42_BUILD_ONE_WAVE`, `N42_ROAD_RUNTIME`, new phase fields) plus scripts, built and tested under the full gate (1,001 tests) in the worktree `/data/n42-build/wt335`. Base P60 = loop334 L3FS60 (three layers, fields at seal, 200k a block, 60 ms). `N42_ROAD_RUNTIME=1` (`bin/n42/src/road_runtime.rs`, `payload_serve.rs`) gives the layer's accept loop and every vote-road connection its own tokio runtime (4 workers, `N42_ROAD_RUNTIME_WORKERS`) instead of the layer's main runtime. Claim 1 (WARM, P60, P60b, W, Wb, WR) ran the feed raised (6.0M / 3.0M) with one rerun at 8.0M / 4.0M when it bound; claim 2 (WARM2 and the F legs) added `N42_TX_INGEST_RECOVER_PARALLEL=24` ("F") on every leg with its own control pair and no reruns, after claim 1 showed the feed capping.

**The feed caps at ~2.6M/s, and the faster legs hit it.** The flood's delivery reads 2.5-2.6M/s on every leg whatever the knobs (rate 8.0M, pool 4.0M, recovery slots 12 or 24): P60r (8.0M / 4.0M) was still short in windows 2-3 (89% / 84% full blocks), W (one wave) bound in windows 1-2 (96% / 95%), WR and its rerun WRr collapsed (78 / 80 / 77% and 68 / 77 / 48% full, queue median 87-450k), RF (road runtime alone) bound in windows 2-3 (68% / 71%). The legs whose feed check passed (the numbers below are for them): P60b, Wb, Wr (a rerun), P60F, P60Fb, RFb, WRF, WRFb, WRT64F, WR250F. Claim 1's plain P60, W, WR, WRr and RF are feed-bound and shown only for their phase fields.

| leg | win1 | win2 | win3 | full % | blocks w1 | cycle w1 mean / med / p90 | sealed_at med / p90 / p99 | par_exec med / p90 | tick / seal % | layer cores | peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WARM | 2,658,933 | 2,540,783 | 2,504,100 | 99/92/87 | 399 | 74.8/72.0/92.2 | 60/72/87 | 26/29 | 34/65 | - | 33.5 |
| P60 | 2,673,333 | 2,500,267 | 2,580,000 | 100/90/100 | 401 | 74.5/70.4/95.3 | 59/72/95 | 26/29 | 43/55 | - | 34.9 |
| P60r (rerun 8M/4M) | 2,626,667 | 2,570,983 | 2,506,350 | 100/89/84 | 394 | 75.7/70.8/97.8 | 58/70/97 | 25/28 | 39/58 | - | 34.7 |
| P60b | 2,646,667 | 2,531,783 | 2,586,667 | 100/97/100 | 397 | 75.4/71.8/94.8 | 60/75/93 | 26/29 | 39/58 | - | 35.3 |
| W | 2,648,517 | 2,502,750 | 2,586,667 | 96/95/100 | 400 | 74.7/71.4/92.5 | 63/74/103 | 30/33 | 24/74 | - | 34.9 |
| Wr (rerun 6M/3M) | 2,633,333 | 2,533,333 | 2,573,333 | 100/100/100 | 395 | 75.6/73.8/91.8 | 64/73/90 | 30/33 | 21/79 | - | 36.6 |
| Wb | 2,646,667 | 2,586,667 | 2,600,000 | 100/100/100 | 397 | 75.3/72.9/92.9 | 64/77/117 | 30/33 | 19/80 | - | 35.1 |
| WR | 2,564,950 | 2,543,900 | 2,535,100 | 78/80/77 | 411 | 72.8/71.2/86.6 | 69/83/116 | 31/35 | 35/64 | - | 33.2 |
| WRr (rerun 8M/4M) | 2,577,633 | 2,583,050 | 2,475,983 | 68/77/48 | 429 | 69.6/67.3/83.7 | 65/81/97 | 29/33 | 50/50 | - | 35.0 |
| WARM2 (F) | 2,606,367 | 2,540,000 | 2,520,000 | 100/100/100 | 391 | 76.4/75.5/90.6 | 62/71/87 | 26/28 | 23/76 | 24.4 | 36.4 |
| P60F | 2,626,667 | 2,546,667 | 2,573,333 | 100/100/100 | 394 | 75.8/73.2/92.9 | 59/74/85 | 26/29 | 33/66 | 24.7 | 36.2 |
| P60Fb | 2,640,000 | 2,506,667 | 2,540,000 | 100/100/100 | 396 | 75.6/73.2/91.7 | 61/70/82 | 25/28 | 37/61 | 25.2 | 36.3 |
| RF | 2,723,767 | 2,566,150 | 2,577,817 | 81/68/71 | 431 | 69.6/62.9/88.5 | 61/82/115 | 25/30 | 79/18 | 27.4 | 37.5 |
| RFb | 2,760,000 | 2,713,333 | 2,666,667 | 100/100/100 | 414 | 72.1/65.9/92.1 | 64/85/109 | 26/30 | 72/23 | 27.6 | 38.1 |
| WRF | 2,640,000 | 2,640,000 | 2,673,333 | 100/100/100 | 396 | 75.4/70.6/95.8 | 69/86/127 | 31/34 | 37/58 | 26.5 | 37.4 |
| WRFb | 2,666,667 | 2,646,667 | 2,593,333 | 100/100/100 | 400 | 74.7/70.9/93.2 | 68/83/134 | 31/35 | 38/58 | 26.7 | 37.4 |
| WRT64F (build pool 64) | 2,660,000 | 2,646,667 | 2,573,333 | 100/100/100 | 399 | 74.8/66.8/98.6 | 66/87/134 | 28/31 | 66/26 | 34.1 | 37.4 |
| WR250F (250k, 91 ms) | 2,641,667 | 2,616,667 | 2,533,333 | 100/100/100 | 317 | 94.6/92.5/105.5 | 89/106/138 | 40/46 | 89/11 | 26.0 | 39.4 |

(Feed-bound legs are those with a full % under 97 in any window. All correctness counters on every leg: tc 1, own_not_committed 0, given_up 0, invalid_blocks 0, gas_mismatch 0, `own_executed_again` 0. Engine own-import 33 ms median on the 2-wave P60F against 39-41 on RFb / WRF (p90 58-64): the faster chain leaves the engine less slack, and `state_wait_on="grandparent"` returns on 12-14% of builds (26-30 over 20 ms) at three layers.)

**One wave: confirmed in the fields, a loss in the time.** `one_wave` true on every build, `batches` equal to `batch_threads` (32 / 32, 64 / 64 on WRT64F) on 100% of builds, last minus first batch start 0.02 ms median (0.05 p90; under 2 ms on 99.9% of builds) against 13.7-14.3 ms with two waves, `batch_dispatch_us` 31 against 25 (so the stagger is gone). `par_exec_ms` however goes **up**, 25 / 28 to 30 / 33-34 (W, Wb, WR, WRF), `batch_median_ms` 11 to 19-20 and `batch_max_ms` 16 to 29-30, `sealed_at_ms` 60 to 63-64 (W legs) and 67-69 with the road runtime: the 200,000 transfers are throughput-bound on 32 threads (6,250 a thread takes 29 ms, 3,500 takes 16): the two waves were not idle time but the pool's work, and starting them together only makes each batch run alongside the others. With 64 threads (WRT64F, 64 batches of 3,100) `par_exec` 28 / 30 and batch median 16, still above the 2-wave 25 on 32 threads; layer cores 34 against 26.5.

**The road runtime** (`prev_seal_to_*`, median / p90 ms, P60F against RF / RFb): `prev_seal_to_header` 1.5 / 8.4 to 0.17-0.18 / 0.25; `prev_seal_to_request` 14.4 / 24.3 to 0.9 / 1.2; `prev_seal_to_start` (the child build's start at the layer) 14.7 / 24.5 to 1.2 / 1.5; `prev_seal_to_answer` 8.7 / 22.9 to 6.0-6.7 / 8.8-9.4; the 9-13 ms the loop335 scope note (section 9.3) attributed to the road is gone. The seal itself does not move (`sealed_at` 59 / 74 against 61-64 / 82-85, p90 worse by 10: the road's 4 workers share cores with the build), so the cycle is `sealed_at` + the road: P60F 59 + 14.7 = cycle median 73.2; RFb 63 + 1.2, cycle median 65.9 (RF 62.9); W (road shared) 63 + 8.9, 72-73; WRF 67 + 1.2, 70.6. Chain of RFb (`cycle335.py`): chain start to frame sealed 59.9, seal answer 3.5, release 0.8 (p90 1.1, against 2.1 / 10.2), cycle median 67.8 (p90 104: a vote-side tail appears: slowest key's vote delay median 23 / p90 79 ms against 11 / 58 on P60F, and the engine's own-import 41 / 64 ms). Window 1 also keeps the 12-14 ms for the frame seal and answer (3.5) and the first 4 ms of the chain start.

**Judging by pairs** (against the F controls P60F / P60Fb, window 1 2,626,667 / 2,640,000, spread 13,333; windows 2-3 mean 2,560,000 / 2,523,333, spread 36,667). R (RF / RFb): window 1 2,723,767 / 2,760,000: **confirmed**, +3.2-5.1% (both legs 84-133k above both controls); windows 2-3 means 2,571,983 (RF, feed-bound) / 2,690,000: RF is only 12k above the better control, not confirmed. W (claim 1, against P60 / P60b, window 1 2,673,333 / 2,646,667): W 2,648,517 (feed-bound) / Wb 2,646,667 / Wr 2,633,333: inside the controls, no gain; windows 2-3 (P60 2,540,133, P60b 2,559,225; W 2,544,833, Wb 2,593,333, Wr 2,553,333): not confirmed. WR (WRF / WRFb against P60F / P60Fb): window 1 2,640,000 / 2,666,667: inside / +1% (not confirmed); windows 2-3 means 2,656,667 / 2,620,000: **confirmed** (60-133k above both controls, over the 36,667 spread): the pair holds its rate across the three windows (WRF 2.640 / 2.640 / 2.673, WRFb 2.667 / 2.647 / 2.593 against P60F 2.627 / 2.547 / 2.573) while the controls decay 2-3%. **Best confirmed pair for the peak: RF / RFb, 2.72-2.76M (window 1; RF's windows 2-3 are feed-bound). Best confirmed pair for the sustained rate: WRF / WRFb, 2.62-2.66M in windows 2-3.** No pair has all three windows above 2,653,000; the single leg RFb does (2,760,000 / 2,713,333 / 2,666,667, full blocks in every window), and WRF's windows 1-2 and WRFb's window 1 equal or exceed it.

**WR50 skipped** (WRF's cycle median 71.2 ms, not under 66; RFb's 65.9 is the only leg that is). **WR250F** (250k a block, 91 ms = loop335 S250's `sealed_at` 79 + 12; single leg): 2,641,667 / 2,616,667 / 2,533,333, `sealed_at` 89 / 106 (S250 plain, loop335: 80 / 99), `par_exec` 39 / 44, cycle median 92.5: the one-wave seal is 9 ms worse at 250k (+11%), against S250's 2.625 / 2.600 / 2.583M. **WRT64F** (single): 2,660,000 / 2,646,667 / 2,573,333, cycle median 66.8, seal binds 26%.

What this says. The road runtime is the confirmed gain: the chain's cycle drops to `sealed_at` + ~1 ms and the chain then outruns the feed (the faster the chain the more of the run is feed-bound at ~2.6M/s). One wave should be dropped as a default candidate: it removes a stagger that was work, and costs 5 ms of seal. The next limits are the feed (~2.6M/s through one ingest at E=1; every number above 2.6M needs RF-like legs with the feed exactly at the edge), the 32-thread execution (25 ms at 6,250 transfers a thread-batch of 3,500), and the engine's own-import (41 ms) once the cycle is 66 ms.

Files: `scripts/fleet7-runs/{derive336.py,cycmed336.py,fields336.py,results/loop336.out,results/loop336-set-b.out}`.

### 10.84 The feed with 64 recovery permits (loop337): the semaphore wait is gone (0.45 ms on every sample) and delivery is still ~2.7M/s; the rate did not move, and the stage that holds it is not the semaphore, not a saturated tokio thread, not the flood

Every figure E=1 (one layer, windows from the layer's canonical log, 400M set, 12,500 senders). Binaries: commit 0573e6c28 = f340aaf9c's sources (loop336's binary, `crates/` and `bin/` identical) plus scripts, built and tested under the full gate (1,001 tests, clippy) in the worktree `/data/n42-build/wt335`. The commits that other work pushed meanwhile (the gate's lock-free depth mirror, the one-pass prune, `N42_INGEST_RUNTIME`, `N42_QUEUE_PRUNE_THREAD`) are NOT in these binaries, so this round tests the permits and nothing else. Base RF = loop336 RF (three leader layers, fields at seal, `N42_ROAD_RUNTIME=1`, 200k a block, 60 ms, rate 6.0M / pool 3.0M); `N42_TX_INGEST_RECOVER_PARALLEL` unset means unbounded (`recovery_slot_count()` returns `None`), so 64 is a bound that never binds (2.6 slots busy). Legs: claim 1 WARM, RF64, RF64b, RF24; claim 2 WARM2, RF64S250, RF64S300, RF64T64 (RF64P55 and RF64P50 were skipped by their own rule: RF64 / RF64b cycle medians 67.0 / 66.9 ms are not within 3 ms of 60); claim 4 WARM4, BEST, BESTb (= RF64T64 twice, the only single leg with every block full in all three windows). Claim 2's runner was killed with the session's background shell during RF64T64's post-processing (its logs were intact; the analysis was redone by hand from them, `results/loop337-set-b.out`), claim 3 ran a stale `best337.py` from the worktree and found no BEST leg (WARM3 only), claim 4 ran BEST / BESTb. WARM legs are not read; WARM4 followed 16 idle minutes and read 2,580,100 / 2,408,917 / 2,387,783 with 90 / 68 / 63% full blocks on RF64's own configuration: the box-state effect, not a result.

| leg | win1 | win2 | win3 | round txs | blocks w1/w2/w3 | full % | cycle w1 mean / med / p90 | sealed_at med / p90 / p99 | par_exec med / p90 | tick / seal % | layer cores | peak RSS G | persistence ms / full block |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RF64 | 2,706,667 | 2,700,000 | 2,643,267 | 241.5M | 406/405/398 | 100/100/98 | 73.3/67.2/93.2 | 63/85/122 | 26/30 | 66/27 | 27.4 | 38.0 | 47.0 |
| RF64b | 2,733,333 | 2,705,917 | 2,700,000 | 244.2M | 410/412/405 | 100/95/100 | 72.8/66.6/94.9 | 63/84/111 | 26/29 | 66/28 | 26.8 | 37.7 | 48.4 |
| RF24 (control) | 2,733,333 | 2,700,000 | 2,686,667 | 243.6M | 410/405/403 | 100/100/100 | 72.7/67.7/93.2 | 65/82/118 | 27/31 | 61/34 | 27.1 | 37.7 | 48.4 |
| RF64S250 (80 ms) | 2,741,667 | 2,716,667 | 2,635,767 | 242.8M | 329/326/319 | 100/100/97 | 90.6/82.0/109.5 | 82/111/153 | 36/40 | 72/17 | 26.8 | 40.3 | 61.3 |
| RF64S300 (93 ms) | 2,749,950 | 2,684,967 | 2,684,617 | 243.6M | 283/272/274 | 91/95/92 | 106.0/97.4/122.5 | 95/122/169 | 41/47 | 58/29 | 26.6 | 41.0 | 71.2 |
| RF64T64 | 2,700,000 | 2,613,333 | 2,626,667 | 238.2M | 405/392/394 | 100/100/100 | 73.6/65.5/97.7 | 63/83/130 | 27/29 | 69/24 | 33.5 | 37.5 | 45.6 |
| BEST (= T64) | 2,770,617 | 2,602,267 | 2,633,333 | 240.2M | 419/393/395 | 96/97/100 | 71.2/63.2/91.6 | 63/83/107 | 26/29 | 75/20 | 34.8 | 36.9 | 45.9 |
| BESTb (= T64) | 2,713,333 | 2,653,333 | 2,620,000 | 239.6M | 407/398/393 | 100/100/100 | 73.4/66.8/92.1 | 64/85/128 | 26/29 | 68/28 | 34.4 | 37.6 | 47.6 |

(Warm-ups, not read: WARM 2,753,333 / 2,722,633 / 2,631,583; WARM2 2,713,333 / 2,665,600 / 2,644,983, 95% full in window 2; WARM3 2,693,333 / 2,687,800 / 2,646,667.) Phases at the leader, window-1 medians: `par_ms` 55-57 (S250 74, S300 86, all p90 75-80 at 200k), `roots_ms` 34-36 (T64 30), `parent_fields_ms` 0, `sealed_ms` 5-6; `prev_seal_to_header` 0.18 ms, `_request` 0.91-0.93, `_start` 1.17-1.23, `_answer` 5.8-6.7 (RF24 5.8, RF64 6.2, RF64b 5.9, T64 6.7; S250 7.9, S300 9.6), exactly loop336's road. RSS 4.8 -> 25 -> 30-32 -> 37.7-38.0 G at the window boundaries on the 200k legs (40.3 / 41.0 at 250k / 300k), in-memory blocks max 11-14, the throttle never spoke (no line), engine own-import median 41-47 ms (p90 62-83; S300 57-62 / 88-92), slowest key's vote delay median 20-28 ms (S250 36, S300 31-37), p90 74-110. Open: `open_layers` 3 on every build, `open_fallback` true on 8-14% of builds (RF24 8%). Correctness on every leg and the warm-ups: tc 1, own_not_committed 0, given_up 0, invalid_blocks 0, gas_mismatch 0, direct_imports_failed 0, `own_executed_again` 0 of ~1,230-1,265 built blocks. Persistence: 46-48 ms a full block at 200k against a mean cycle of 71-73 ms (it keeps up; engine idles over 5 s 1 as always); 61 ms at 250k against a 91 ms cycle and 71 ms at 300k against 106; a 60 ms cycle was not reached (the cycle never fell below a 63 ms median), so whether 47 ms still keeps up at 60 and below is open.

**The feed check (the point of the round).** Per window, from the layer's `ingest` lines (acquire = `acq_us_per_frame`, which includes the 500-transaction decode) and the flood log:

| leg | acq ms | gate ms (w1/w2/w3) | reply ms (w1/w2/w3) | delivered per 5 s median (max), w1 / w2 / w3 | queue at builds median; min, w1 / w2 / w3 | flood reply latency ms | what bound it |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RF64 | 0.45 | 2.5/2.0/1.4 | 3.1/2.6/2.1 | 2.710M (2.842) / 2.698 (2.719) / 2.715 (2.751) | 2.21M; 507k / 2.09M; 988k / 1.35M; 15.5k | 71.5 | tick (feed dipped in w3: 98% full) |
| RF64b | 0.44-0.45 | 2.8/1.4/1.3 | 3.4/2.0/1.9 | 2.738M (2.773) / 2.667 (2.765) / 2.731 (2.904) | 2.29M; 995k / 546k; 45k / 1.47M; 609k | 71.0 | tick; feed in w2 (95% full, gate open from t+30 s) |
| RF24 | 0.46 (one 1.9 sample) | 2.7/1.6/2.2 | 3.3/2.2/2.8 | 2.712M (2.880) / 2.682 (2.831) / 2.659 (2.774) | 2.13M; 628k / 1.44M; 275k / 2.13M; 1.39M | 70.7 | tick |
| RF64S250 | 0.44-0.45 | 2.1/1.6/1.6 | 2.7/2.2/2.3 | 2.769M (2.816) / 2.671 (2.762) / 2.685 (2.873) | 1.95M; 846k / 1.75M; 341k / 1.14M; 45k | 70.6 | tick; feed in w3 (97%) |
| RF64S300 | 0.44-0.45 | 1.3/1.8/1.3 | 1.9/2.4/1.9 | 2.720M (2.869) / 2.634 (2.796) / 2.715 (2.854) | 1.19M; 0 / 1.58M; 0 / 1.18M; 0 | 71.3 | feed (91 / 95 / 92% full; queue empties to 0) |
| RF64T64 | 0.45 | 1.9/1.7/2.5 | 2.5/2.3/3.2 | 2.723M (2.820) / 2.645 (2.751) / 2.614 (2.658) | 2.20M; 435k / 1.95M; 932k / 2.15M; 1.21M | 72.5 | tick |
| BEST | 0.45-0.48 | 1.3/2.4/1.9 | 1.9/3.0/2.5 | 2.690M (2.834) / 2.676 (2.771) / 2.637 (2.751) | 875k; 32k / 1.93M; 0 / 1.83M; 912k | 72.2 | feed in w1 (96%) and w2 (97%) |
| BESTb | 0.45-0.47 | 2.4/1.9/1.7 | 3.0/2.5/2.3 | 2.723M (2.776) / 2.642 (2.672) / 2.664 (2.753) | 2.02M; 619k / 1.94M; 744k / 1.77M; 425k | 71.6 | tick |

1. **The convoy is gone and nothing moved.** `acq_us_per_frame` is 0.44-0.48 ms on every one of the 6 samples of every window of all eight legs with 64 permits (against 9.4-11.1 ms in loop336's convoy legs), slots 4% busy (11% at 24). The delivered rate per 5 s is 2.61-2.74M/s at the median and 2.75-2.90M at the maximum, the same band as with 12, 24 or 64 permits. Section 10's confirming test (RF's configuration with 64 slots twice, both legs >= 97% full in every window and acquire under 1 ms): the acquire part passes, the full-block part does not (RF64 98 / 100 / 100 passes, RF64b 100 / 95 / 100 fails with a window-2 queue median of 546k and a gate open from t+30 s). RF24, the control with the permits as they were, did not fall into the convoy either (acq 0.46 ms, one 1.9 ms sample): the convoy formed on 1 of 9 24-slot legs in loop336, so one clean RF24 says nothing about whether 64 is a cure; 64 only shows that the part of the problem the semaphore was is not what limits the rate.
2. **Where the rate is held.** Whenever the chain consumes more than the ingest delivers, the queue falls and the gate opens (gate wait 1.3-1.4 ms against 2.1-2.8 with the gate shut) and delivery then sits at ~2.7M/s: RF64 w3, RF64b w2, BEST w1-w2, S250 w3 and S300 throughout (queue min 0). The flood side is the same on every leg: 64 connections, 6 frames in flight each, reply latency 70.6-72.5 ms, i.e. ~11.7 ms per frame per connection and 5,400-5,500 frames a second. The layer's own clocks cover 2-3.4 ms of that (`reply_us` contains the acquire and the gate); ~8-9 ms is the unclocked read-and-poll part. What it is NOT: the flood (0.28 cores, 98.7% of its worker time waits for the reply), the semaphore (0.45 ms), the decode (inside the 0.45), the attested check (4% of 64 slots), CPU on the main runtime: `threadcpu337.py` (new, per thread id) shows on every leg 24-25 `tokio-rt` threads alive through the flood each at **0.47-0.50 of a core**, none over 0.7 (group 7.7 cores over them, 10.4-10.5 with the short-lived blocking threads), so no runtime worker is saturated. What is left, and what the logs support but cannot isolate: workers parked on the queue's lanes `Mutex` while a connection's gate or reply waits for it, and a runtime that polls late behind a worker held by the prune. The pruner (`prune337.py`): `prune_ms` 48-51 median / 70-99 p90 per 200k block on a main-runtime worker = **65-68% of one worker**, `remove_us` 22-23 ms (p90 34-46) under the lanes lock = **the lock held 34-37% of the wall time for removal alone** (drains are not logged and come on top), and the same 32-36% at 250k and 300k blocks (`remove_us` 28 / 31 ms, 62 / 69 ms prune): the lock duty is proportional to transactions per second, which is what a delivery capped by it would also be. A 5 s sample cannot separate the two (cause and effect are the same rate), so this is the next suspect with evidence, not a finding: loop338's `lock_*` and `drain_*` fields on the ingest line are the instrument.
3. **Nothing else shows either.** The delivered median is the same 2.64-2.77M/s at 200k, 250k and 300k blocks and at 60, 80 and 93 ms pacing, so it is not tied to the seal or the tick; S300 at 93 ms pacing would consume 3.2M/s (its real cycle is 97-101 ms, 3.0M/s) and gets 2.72M with empty-queue builds (91 / 95 / 92% full) while S250 at 80 ms is just fed (100 / 100 / 97%). The next leg that can move the rate is therefore the ingest side, not the chain: the chain's cycle at 200k (63-67 ms median, 71-74 mean) wants 2.7-3.0M/s and the feed gives 2.7M.

**Judging by pairs** (control RF24, ONE control leg here: treat with care; loop336's RFb is the same configuration on the same sources and is quoted as a second control, across loops). Window 1: RF64 / RF64b 2,706,667 / 2,733,333 against RF24 2,733,333 (RFb 2,760,000): not the same direction, inside the pair's own 26,667 spread: **no effect of 64 permits**. Windows 2-3 mean: RF64 2,671,634, RF64b 2,702,959 against RF24 2,693,334: **no effect**. T64 (RF64T64 and BEST / BESTb, three legs): window 1 2,700,000 / 2,770,617 / 2,713,333 against 2,733,333: no; windows 2-3 means 2,620,000 / 2,617,800 / 2,636,667 against 2,693,334: **confirmed loss**, -2.1 to -2.8% (all three below the control by 57-75k, over the group's 19k spread), layer cores 34-35 against 27. S250 and S300 are single legs: window 1 2,741,667 / 2,749,950 inside the control's noise, S300 not full. P55 / P50 were not run (the gate was right: the cycle median is 63-68 ms at 60 ms pacing, so pacing does not bind and a lower tick cannot help).

**Verdict.** No pair of this round improves on the control. The best confirmed pair is still the RF configuration at 24 permits: RFb (loop336) / RF24 (loop337), the same configuration twice, window 1 **2,760,000 / 2,733,333**, windows 2-3 means 2,690,000 / 2,693,334 (peak and sustained). **A pair with all three windows above 2,653,000 and every block full exists only across the two loops**: RFb 2.760 / 2.713 / 2.667 and RF24 2.733 / 2.700 / 2.687, 100% full in every window; inside loop337 no pair does (RF64 w3 2,643,267 and 98%; RF64b w2 95%; BESTb w3 2,620,000). Nothing is above 3,000,000; the highest single reading is BEST's window 1, 2,770,617 (96% full, feed-bound).

Next: loop338's instrumentation (lanes lock duty and holder, drain time) on the new binary is what decides between the lock and the main runtime's polling; 64 permits are not worth keeping over 24 (no gain, and the convoy risk at 24 is a property of a runtime the next round changes), and build pool 64 is dropped (it costs 7 cores and 2-3% in windows 2-3).

Files: `scripts/fleet7-runs/{derive337.py,feed337.py,best337.py,prune337.py,threadcpu337.py,results/loop337.out,results/loop337-set-b.out,results/loop337-set-c.out,results/loop337-prune.out}`.

### 10.85 The feed path built (loop338): the gate mirror and the one-pass prune lift the E=1 rate from 2.73M to 2.95-3.02M in window 1 and the feed is no longer the bound; the ingest runtime and the prune thread add nothing measurable on top, and the lanes lock is still held 50-59% of the time

Every figure E=1 (one layer, windows from the layer's canonical log, 400M set). Binaries: commit d092e1589 (the pushed tip: loop337's sources plus scope section 11, `crates/` and `bin/` as committed, scripts copied in), built and tested under the full gate (1,016 tests, `n42 --lib` included) in the fresh worktree `/data/n42-build/wt338`. Two changes are in every leg with no switch: the gate and the reply's `pending` read the queue depth from an atomic (no lanes lock), and a committed block is pruned in one pass with the frees on their own thread. Switches: I = `N42_INGEST_RUNTIME=1`, Q = `N42_QUEUE_PRUNE_THREAD=1`. Base B = RF at 24 recovery permits (loop337's best): three leader layers, fields at seal, `N42_ROAD_RUNTIME=1`, 200k a block, 60 ms. Claim 1 (WARM, WARMb, B, IQ, Bb, IQb, Q, Qb, I, Ib, IQ12, 12:00-12:54) and claim 2 (WARM, WARMb, IQS250, IQS300, BEST, BESTb, 12:50-13:34; two warm-ups at the start of each claim, the test gate before a claim leaves the box cold; claim 2's warm-ups were relabelled W2 in the stored output because the tags repeat). IQP55 / IQP50 were skipped by their own rule: the IQ / IQb cycle medians are 66.0 / 64.0 ms, the lower is not within 3 ms of 60. The first claim ran from a launcher started with `setsid`; nothing was killed.

| leg | win1 | win2 | win3 | round txs | blocks | full % | cycle w1 mean / med / p90 | sealed_at med / p90 / p99 | par_exec | tick / seal % | layer cores | peak RSS G | own-import med / p90 | slowest key vote med / p90 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B | 2,993,333 | 3,020,000 | 2,906,667 | 267.6M | 449/453/436 | 100/100/100 | 66.7/63.4/79.0 | 63/69/89 | 29/32 | 69/31 | 31.7 | 44.4 | 30/58 | 22.2/52.1 |
| Bb | 2,953,333 | 2,973,333 | 2,893,333 | 264.6M | 443/446/434 | 100/100/100 | 67.7/61.8/82.3 | 62/70/87 | 28/31 | 81/17 | 31.6 | 41.0 | 32/59 | 18.2/52.4 |
| I | 3,006,667 | 2,926,667 | 2,866,667 | 264.0M | 451/439/430 | 100/100/100 | 66.2/64.3/77.7 | 63/71/91 | 28/31 | 59/41 | 30.5 | 42.6 | 28/35 | 10.9/23.1 |
| Ib | 3,013,333 | 2,966,667 | 2,926,667 | 267.2M | 452/445/439 | 100/100/100 | 66.4/63.0/78.0 | 62/70/97 | 27/31 | 71/29 | 30.1 | 41.7 | 32/56 | 12.3/46.2 |
| Q | 2,946,667 | 2,933,333 | 2,786,667 | 260.0M | 442/440/418 | 100/100/100 | 67.8/64.1/80.0 | 64/73/92 | 30/34 | 67/32 | 31.8 | 42.5 | 32/61 | 21.0/52.2 |
| Qb | 2,933,333 | 2,920,000 | 2,906,667 | 262.8M | 440/438/436 | 100/100/100 | 67.8/62.3/78.9 | 63/70/81 | 28/32 | 71/28 | 30.9 | 42.5 | 29/54 | 19.2/50.9 |
| IQ | 2,952,867 | 2,940,000 | 2,900,000 | 263.8M | 443/441/435 | 100/100/100 | 67.6/66.3/77.9 | 65/72/94 | 29/34 | 32/68 | 29.9 | 45.5 | 28/38 | 7.1/20.3 |
| IQb | 3,019,600 | 3,013,333 | 2,873,333 | 267.2M | 453/452/431 | 100/100/100 | 66.1/63.9/76.5 | 63/70/104 | 28/32 | 59/41 | 30.2 | 45.0 | 29/37 | 8.6/20.3 |
| IQ12 (12 permits) | 2,973,333 | 2,993,333 | 2,873,333 | 265.2M | 446/449/431 | 100/100/100 | 66.9/62.5/82.5 | 63/72/98 | 28/32 | 70/30 | 29.6 | 42.2 | 30/53 | 11.3/47.9 |
| IQS250 (82 ms) | 2,966,667 | 2,958,333 | 2,866,667 | 263.8M | 356/355/344 | 100/100/100 | 84.2/83.4/91.4 | 81/89/108 | 38/43 | 93/7 | 29.3 | 42.4 | 36/53 | 3.0/23.8 |
| IQS300 (97 ms) | 2,990,000 | 3,010,000 | 2,830,000 | 264.9M | 299/301/283 | 100/100/100 | 100.4/98.5/113.0 | 94/103/127 | 43/47 | 92/8 | 28.0 | 48.2 | 42/67 | 2.9/20.2 |
| BEST (= IQS300) | 3,000,000 | 2,990,000 | 2,870,000 | 265.8M | 300/299/287 | 100/100/100 | 99.8/98.5/108.3 | 97/105/126 | 44/51 | 87/12 | 29.0 | 47.8 | 42/57 | 2.9/20.4 |
| BESTb | 2,950,000 | 2,980,000 | 2,920,000 | 265.5M | 295/298/292 | 100/100/100 | 101.4/98.5/114.8 | 96/106/129 | 44/48 | 89/9 | 28.2 | 48.5 | 44/71 | 4.5/45.3 |

(Warm-ups, not read: WARM 2,966,667 / 2,926,667 / 2,820,000; WARMb 2,953,333 / 3,000,000 / 2,886,667; claim 2's 2,960,000 / 2,886,667 / 2,900,000 and 3,000,000 / 2,973,333 / 2,820,000: with two warm-ups the claims start at the level of the legs, against loop337's WARM4 at 12% low. Every window of every leg is >= 99.7% full blocks.) Phases (window-2 medians, 200k): `par_ms` 56-59, `par_exec` 27-30, `roots_ms` 38-39 (34-36 in loop337), `parent_fields_ms` 0, `sealed_ms` 5-6; the road is unchanged (`prev_seal_to_header` 0.17 ms, `_request` 0.89, `_start` 1.15-1.21, `_answer` 6.1-7.7). RSS 4.8 -> ~25 -> ~32 -> 41-45 G at the window boundaries (47-48 at 300k). Persistence 49.6-50.3 ms a full block at 200k (63.9 at 250k, 76.9-79.5 at 300k) against a 66-68 ms mean cycle: it keeps up, but the in-memory blocks max is now 23-36 (11-14 in loop337) and RSS is 6-7 G higher, so the margin is smaller; the throttle never spoke. `open_fallback` on 0.1-0.6% of builds (8-14% in loop337: the open's fallback has gone with the chain's pace). Correctness on all 17 legs including warm-ups: tc 1, own_not_committed 0, given_up 0, invalid_blocks 0, incomplete 0, gas_mismatch 0, direct_imports_failed 0, `own_executed_again` 0.

**Feed and lock, per leg** (from the `ingest` lines and the prune lines in the three windows; delivered rate per 5 s median (max), window 1 / 2 / 3; gate wait with the gate shut is the queue holding at its 2.5M gate; lock duty = `lock_duty_pct` per window; drain = per drain; the holder is `lock_hold_max_at`):

| leg | acq ms | gate ms | delivered (max), w1 / w2 / w3 | queue at builds median; min (w1) | flood reply ms | lock duty % | longest hold ms (holder) | lock wait ms / 5 s | drain tx / mean us / max ms | prune_ms med | prune hold ms | pruner busy % | lock held by prune % | bound |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B | 0.47-0.49 | 7.6-8.0 | 3.022M (3.055) / 2.999 (3.140) / 2.938 (2.986) | 2.50M; 1.98M | 64.1 | 55 / 57 / 58 | 30-35 (drain_now) | 2,060-2,200 | 70,000 / 4,570 / 22.5 | 27-32 | 5.6-7.3 | 43-48 | 2.2-2.3 | tick (seal 31%) |
| Bb | 0.47-0.48 | 7.8-8.2 | 2.969M (3.089) / 2.993 (3.041) / 2.888 (2.978) | 2.51M; 2.01M | 64.9 | 53 / 56 / 55 | 31-33 (drain_now) | 1,960-2,260 | 73,000 / 4,650 / 26.2 | 28-33 | 5.5-6.9 | 42-47 | 1.9-2.6 | tick |
| I | 0.45-0.47 | 6.6-7.1 | 2.996M (3.079) / 2.989 (3.043) / 2.852 (2.999) | 2.42M; 831k | 64.2 | 56 / 59 / 55 | 11-19 (prune_block) | 1,380-1,820 | 18,100 / 1,190 / 6.5 | 26-29 | 6.0-6.5 | 38-42 | 2.6-3.1 | tick |
| Ib | 0.45-0.45 | 6.4-6.8 | 3.030M (3.133) / 3.040 (3.062) / 2.953 (3.001) | 2.42M; 1.05M | 64.0 | 58 / 59 / 59 | 13-19 | 1,600-1,740 | 17,400 / 1,190 / 5.4 | 26-28 | 6.3-6.6 | 40-42 | 2.5-3.0 | tick |
| Q | 0.48-0.68 | 7.8-8.5 | 2.941M (2.999) / 3.012 (3.080) / 2.812 (2.958) | 2.51M; 2.06M | 64.8 | 50 / 57 / 50 | 24-27 (drain_now) | 1,550-1,900 | 67,200 / 4,190 / 17.7 | 24-26 | 5.2-5.8 | 35-39 | 1.3-1.4 | tick (seal 32%) |
| Qb | 0.48-0.51 | 7.8-7.9 | 2.950M (2.996) / 2.983 (3.104) / 2.904 (3.020) | 2.51M; 1.24M | 65.1 | 50 / 54 / 52 | 26-34 (drain_now) | 1,620-1,850 | 68,100 / 4,270 / 22.3 | 22-25 | 4.8-5.5 | 34-36 | 1.0-1.4 | tick |
| IQ | 0.45-0.46 | 6.7-7.0 | 2.930M (3.012) / 2.991 (3.080) / 2.912 (2.993) | 2.42M; 489k | 64.7 | 54 / 58 / 53 | 14-21 (prune_block) | 1,180-1,500 | 17,500 / 1,130 / 6.8 | 22-26 | 6.0-6.1 | 33-37 | 2.1-2.6 | seal (68%) |
| IQb | 0.45 | 6.4-7.1 | 3.042M (3.064) / 3.023 (3.053) / 2.879 (2.968) | 2.42M; 452k | 63.8 | 55 / 54 / 55 | 11-20 | 1,160-1,400 | 17,100 / 1,090 / 5.2 | 20-24 | 5.7-6.3 | 32-35 | 2.1-2.5 | tick (seal 41%) |
| IQ12 | 0.45-0.46 | 6.6-7.2 | 2.982M (3.018) / 3.001 (3.084) / 2.873 (2.957) | 2.43M; 426k | 64.5 | 54 / 54 / 54 | 11-18 | 1,250-1,260 | 17,300 / 1,120 / 5.9 | 20-22 | 5.5-5.9 | 31-34 | 2.1-2.3 | tick |
| IQS250 | 0.45-0.46 | 6.1-6.4 | 2.964M (3.016) / 2.983 (3.014) / 2.883 (2.932) | 2.40M; 1.16M | 64.7 | 50 / 58 / 55 | 12-20 | 990-1,270 | 18,300 / 1,100 / 5.9 | 23-30 | 5.9-7.3 | 28-35 | 2.2-2.5 | tick |
| IQS300 | 0.45-0.46 | 5.4-6.1 | 3.016M (3.035) / 3.018 (3.039) / 2.833 (2.963) | 2.39M; 1.03M | 64.2 | 51 / 57 / 50 | 17-24 | 920-1,320 | 19,400 / 1,190 / 6.4 | 29-35 | 7.2-8.7 | 28-36 | 1.9-2.5 | tick |

1. **B against loop337's RF24 (B differs from it only by the gate mirror and the one-pass prune): delivery moved.** Delivered per 5 s median 3.02 / 3.00 / 2.94M (max 3.14M) against 2.71 / 2.68 / 2.66M (max 2.88M); the flood's reply latency fell from 70.7 to 64.1-64.9 ms; the chain followed: window 1 2,993,333 / 2,953,333 against 2,733,333 (+8.1-9.5%), windows 2-3 mean 2,963,334 / 2,933,333 against 2,693,334 (+8.9-10.0%); the cycle mean 72.7 -> 66.7-67.7 ms (median 67.7 -> 61.8-63.4, `sealed_at` 65 -> 62-63, own-import 41-47 -> 30-32 ms). **Confirmed** (two legs against one control from the previous loop, the same configuration otherwise; both legs above it by 220k+ with 40k of spread). The queue now holds at the gate: median 2.5M (the 2.5M gate), minimum 1.98M in window 1 and 2.3M after, `gate_us` 7.6-8.2 ms (the gate is shut and the feed waits for the consumption), acquire 0.47 ms: **the feed is no longer the bound on any B-family leg**; with the gate shut delivery equals consumption, so the ingest's own ceiling is above 3.14M/s (the highest 5 s read) and unmeasured.
2. **The lanes lock is NOT down to a few percent.** `lock_duty_pct` is 50-59% on every leg including B and Bb, 1,400-2,000 holds a 5 s line, lock wait 1.0-2.2 s per 5 s summed over callers. What changed is the prune: it holds the lock 5.0-7.3 ms a block (22-23 before) = 1.0-3.1% of the time (34-37% before), `prune_ms` 27-32 median (48-51), 20-26 with Q, the pruner busy 43-48% of a thread in B (65-68%) and 31-42% elsewhere, `free_us` 0-6 (on its own thread), `fold_us` 0.4-0.5 ms. The rest of the duty is the drain and the build: in B and Q the drain is 215 drains a 5 s line of ~70,000 transactions, 4.2-5.2 ms mean (70 ns a transaction) and up to 17-26 ms, ~20% of the time, and the longest hold of every window is `drain_now` (`lib.rs:2090`) at 25-35 ms; the builder's frame plan (`frames_for_build_in`, `lib.rs:2150`) and `usable` are the other named holders. With the ingest runtime (I, IQ) the drains are 17-19k transactions, 1.1-1.2 ms mean, max 5-7 ms (~1,000 a line: the drainer's 5 ms tick is no longer starved), the longest hold falls to 11-21 ms and its holder becomes `prune_block` (`lib.rs:1765`), and the lock wait falls 25-40%; the total duty stays 53-59% because the same ~3M transactions a second are drained (~20%) either way. Prunes never coalesced (`coalesced` 1 on every line), `prune_wait_ms` max 8-28 ms (zero on B).
3. **What I, Q and IQ add.** Judging by pairs against B / Bb (window 1 2,993,333 / 2,953,333, spread 40,000; windows 2-3 mean 2,963,334 / 2,933,333, spread 30,001): I 3,006,667 / 3,013,333 and mean 2,896,667 / 2,946,667: window 1 above both controls by 13-60k, not past the spread, windows 2-3 inside: **not confirmed**. Q 2,946,667 / 2,933,333, means 2,860,000 / 2,913,334: both below, by less than the spread: **not confirmed**. IQ 2,952,867 / 3,019,600, means 2,920,000 / 2,943,333: **not confirmed**. IQ12 (single, 12 permits) 2,973,333, mean 2,933,333: the 12-permit convoy did not form (acquire 0.45 ms with the separate runtime's blocking-side slot, every sample), so the runtime removes the convoy by itself; the rate is the same. The ingest runtime is visible elsewhere: the slowest key's vote delay median 7-12 ms (18-22 on B, Q) and p90 20-46, own-import 28-29 ms (30-32), at the price of 8 `n42-ingest` workers at 0.68 core each (5.4 cores; the main runtime's workers at 0.5-0.55 either way). It does not move the rate because the rate is no longer the feed's. The prune thread is silent (Q is 1-2% under B in windows 2-3, inside noise).
4. **What binds now.** The chain: the tick binds 59-81% of blocks on B-family legs, the seal 17-41% (IQ 68%: a leg whose cycle median is 66.3 against 61.8-63.4 for the others and whose rate is the same), quorum under 10%; the cycle median is 62-66 ms against a 60 ms pacing, which is why IQP55 / IQP50 did not run. 250k and 300k blocks hold the same 2.87-3.01M (IQS250 at 82 ms 2,966,667 / 2,958,333 / 2,866,667; IQS300 at 97 ms 2,990,000 / 3,010,000 / 2,830,000, `sealed_at` 81 and 94 ms, cycle medians 83 and 98.5, persistence 64 and 77-80 ms a block at 100% full): the rate is flat in block size, as in loop335-337, now at 3.0M instead of 2.7M. Window 3 is 2-4% below windows 1-2 on every leg (RSS 41-48 G, in-memory blocks up to 36).

**Judging.** Against loop337's control the whole B family is confirmed (item 1); inside the family no switch is confirmed (item 3). **No pair has all three windows above 3,000,000.** The closest: IQb 3,019,600 / 3,013,333 / 2,873,333, Ib 3,013,333 / 2,966,667 / 2,926,667, B 2,993,333 / 3,020,000 / 2,906,667, and the BEST pair (IQS300 twice: 3,000,000 / 2,990,000 / 2,870,000 and 2,950,000 / 2,980,000 / 2,920,000). Every pair has all three windows above 2,653,000 with every block full (lowest window 2,786,667, Q). Best confirmed pair for the peak: B / Bb, window 1 2,993,333 / 2,953,333 (I / Ib read 3,006,667 / 3,013,333 and IQ / IQb 2,952,867 / 3,019,600 but are inside the spread of B / Bb); the highest single windows are B window 2 3,020,000 and IQb window 1 3,019,600. Best for the sustained rate: B / Bb, windows 2-3 mean 2,963,334 / 2,933,333, round totals 267.6M / 264.6M (I / Ib 264.0M / 267.2M, IQ / IQb 263.8M / 267.2M: equal within the spread).

Next: the chain is the bound at ~3.0M: the cycle is 62-66 ms against `sealed_at` 62-65 (the seal chain, `par_exec` 27-30 ms on 32 threads, `roots` 38) and the slowest key's votes are well inside it; the window-3 sag (2-4%) goes with the in-memory blocks (23-36) and the persistence (50 ms a block against a 67 ms cycle) and is the next thing to read; the feed has room above 3.14M/s, so raising the block's work (the seal) is the lever. The lanes lock's 20% drain duty is worth batching only if a later round shows the feed binding again.

Files: `scripts/fleet7-runs/{derive338.py,feed338.py,table338.py,results/loop338.out,results/loop338-set-b.out}`.
