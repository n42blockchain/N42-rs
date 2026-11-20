# State layout for the transfer read path (6M plan)

Status: design, 2026-11-19. Nothing here is built. Plan: `docs/PLAN_6M_2026_11.md`.

## 1. What the measurements say

6M at 200k transactions a block is a 33.3 ms cycle. Today: par_exec 27-30 ms, sealed_at 36-38 ms,
roots 30-34 ms (25-27 ms with `N42_LEADER_ROOT_POOL=16`), cycle 38-41 ms.

- The ceiling legs (plan log 2026-11-17) skipped every execution read: par_exec 29 -> 12.5 ms. About
  16 ms of par_exec is the parent read. TPS did not move then because the root job bound; the root
  job has since been cut to 25-27 ms.
- On a control leg the parent read is 518 ms of thread time a block, 2.6 us a transfer
  (`evm2_batch_reads_us`). Issuing the same reads as a prefetched batch left 460-480 ms
  (`perf/exec-read-prefetch`, flat): the cost is a chain of dependent DRAM misses, about twenty a
  cold account (19.5 fills a transfer in the 2026-10-18 builder profile), not how they are issued.
- The misses are in the in-memory stack, not in QMDB. A cold recipient read walks, in order: the
  batch map; six kept layers, each a residual overlay probe and a shard-index probe with its own
  address hash; the engine overlay's filters; a changeset scan when the anchor is behind the
  database tip; the view's reader slot and shard lock; the view journals; one index bucket; the
  entry record (one or two lines, unaligned); a decode; two `AccountInfo` clones into a 264-byte
  `BundleAccount`. The QMDB view itself is 3% of the fills.
- The state the bench touches is small: 2.03M live accounts, 33.5 MB of index. The cost is the
  number of structures between the transfer and the account, not the size of the state.
- Earlier attempts each removed one structure and were flat: dense ids (design B), the read set
  (design A), the changeset skip, the bulk read. None removed the stack.

## 2. The proposal: one line per account, in front of the stack

A **flat account table**: an address-keyed array of 64-byte slots, one cache line an account, on
2 MB pages. A direct transfer's account read becomes one hash and one line. The existing stack
stays as the fallback and as the source of truth; the table is a cache whose every answer the
stack would also give.

### 2.1 Slot

```
tag        u32   address fingerprint; 0 = empty
seq        u32   seqlock word (odd while a writer holds the slot)
cur_h      u32   block height from which `cur` holds
prev_h     u32   block height from which `prev` holds; u32::MAX = none
cur_nonce  u64
cur_bal    u128
prev_nonce u64
prev_bal   u128
```

64 bytes. Two versions inline, because a builder reads at a parent one or two blocks behind the
newest block that has written the slot (depth 2). A reader anchored at height `h` on the table's
lineage takes `cur` if `cur_h <= h`, else `prev` if `prev_h <= h`, else it falls back to the stack.

Not representable in a slot, and therefore always a fallback: an account with code or storage, a
balance above 2^128, a fingerprint collision in the bucket (two-way set: the slot index and its
neighbour). An absent account is representable (a flag bit in `tag`'s spare bits with nonce and
balance zero): creating recipients must not fall through every time.

### 2.2 Lineage

Heights identify blocks only on one chain. The table carries a lineage: the hash at each height
it has absorbed, a short ring. A reader whose anchor is not on the lineage does not use the table
at all for that build. When a block on the lineage is abandoned (a view change discards an
uncommitted own block, or a reorg), the table rolls back with that block's reverts, which every
block already has, and the lineage is cut to the parent. Under HotStuff-2 this is a view-change
event, not a steady-state path; correctness there rests on the fallback, performance does not
matter.

### 2.3 Writes

One writer pass a block, where the block's output is frozen (`freeze_live`): that is the first
point at which an account's value for the block is final, since ~8k of ~190k accounts are credited
by more than one batch and summed there. The pass replaces nothing in the first stage; it adds
~190k line writes spread over the shard threads. `enter_part` does the same number of random
writes today (3.7% of fills), so the target is to fold the two in a later stage.

Every node writes, leader or not, from the same point for an imported block, so a member is warm
when its tenure starts. After a restart the table is empty and fills from the fallback.

A fill (a fallback answer installed into an empty or evicted slot) is a compare-and-swap on `seq`
taken before the fallback read: a writer pass that ran in between wins. A fill for anchor `h`
installs `cur_h = h`, which is conservative: older anchors fall back.

### 2.4 Size

Bench: 2.03M accounts at a load factor of 1/2 is 256 MB. In production the table is a bounded
cache (a knob, in slots); eviction is always safe. It is node-local memory: no root, no wire
format, no gov5 contract is touched. The QMDB value bytes, the keys and the tree are unchanged.

## 3. What it should buy, and what it cannot

- Target: parent read 518 -> about 100 ms of thread time a block (one or two misses instead of
  twenty for a table hit; senders are already hot in the batch map), par_exec 28 -> 17-19 ms. The
  floor from the ceiling legs is 12.5 ms.
- It does not touch the batch map (six probes a transfer, 264 bytes an account), `take_bundle`
  (13% of fills), the memmove (10%) or the root job. With par_exec under 20 ms the root job
  (25-27 ms with the pool) binds again: the expected cycle is 33-35 ms, so 5.7-6.0M, and 6M needs
  the second stage as well.

## 4. Stages

Each stage is behind a knob, default off, and is kept only if a fleet pair shows it.

- **Stage 0, shadow table (days).** Build the table and the writer pass; reads still go to the
  stack, and a sampled share of them is also answered from the table and compared. Output: hit
  rate, fallback reasons (older than `prev`, off lineage, not representable, collision), the
  writer pass's cost on the freeze path, and zero mismatches over full legs and over devnet rounds
  with view changes. Stop if the hit rate on recipients is under 90% or the writer pass costs more
  than 1.5 ms on the path the child build waits on.
- **Stage 1, read through the table (days after stage 0).** The direct-transfer path reads the
  table first. `verify` mode (table and stack, compare, fail loudly) for the devnet and for one
  fleet leg; then a pair with the root pool on both sides. Keep if par_exec falls by 5 ms or more;
  otherwise stop and record.
- **Stage 2, the root side reads the table's neighbours (a week).** Two side arrays indexed by the
  slot: the account's 32-byte QMDB key (saves a blake3 an account in the op encoding, ~9 ms of
  thread-summed encode) and its tree slot (saves the held-slot index lookup, root_index 4.2 ms).
  Only worth starting if stage 1 makes the root job bind.
- **Stage 3, a lean batch output for transfers (weeks, design to be written then).** A batch of
  direct transfers emits a compact delta vector (address, old and new nonce and balance, 80 bytes)
  instead of a `BundleAccount` map; the shards, the root ops and the reverts read it. This is the
  batch map, `take_bundle` and the memmove: 40% of the fills. It changes every consumer of a
  batch's output, so it waits for stages 1-2 to show the floor it would move.

## 5. Risks

- **A wrong answer is a wrong block.** The table is on the builder's path; a stale slot gives a
  bad nonce or balance and the block fails on every follower. Mitigations: shadow and verify modes
  before any unverified read; the lineage check; rollback by the block's own reverts; a fleet
  gate that already catches a divergent block (`invalid_blocks`, `fields_mismatches`).
- **The freeze path.** The writer pass sits between a block's seal and its child's first read.
  If it cannot be made cheap it moves the wait instead of removing it; stage 0 measures this
  before anything reads the table.
- **Memory bandwidth.** par_exec has been called memory-bound before; the ceiling legs say the
  bound is latency on dependent misses, which this removes. If stage 1 shows the reads gone and
  par_exec unchanged, that diagnosis is wrong and the line of work stops.
- **Assumptions to confirm in stage 0, from reading rather than from running:** that leader and
  follower outputs freeze at one common point; that an abandoned block is always signalled to the
  code that would roll the table back; that no read on the direct path needs fields a slot lacks.

## 6. Not proposed

- Changing the QMDB entry, key or index layout: the view is 3% of the fills.
- Storing balances in the QMDB index bucket: same reason, and the index is rebuilt from the
  entry file, which the table need not be.
- Dense account ids: measured flat (design B); the table needs no id.
