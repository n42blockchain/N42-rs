# Two-ahead builds: the orphan path audited

Scope: `N42_BUILD_AHEAD_GATE=seal` (with `N42_BUILD_AHEAD_AT_SEAL=1`), the leader building N+1 on sealed N before N
is proposed (docs/BUILD_AHEAD_AND_VOTE_PACE.md sections 5 and 8, option 4). Evidence: stage w's leg
`bench-loop351D2S12P40T64X7AG` (BREAKTHROUGH_DESIGN 10.104), kept under `/data/blockchain/rust-fleet7-bench/`.

## 1. Who holds what when N+1 was sealed on N and N is not committed

| structure | what it holds of N / N+1 | who releases it |
| --- | --- | --- |
| validator, `h2-el-rpc/src/engine.rs` `ChainState` | `slot` = N's chained build, `next` = N+1 (started at N's seal, `ChainStart::Behind`), `deferred` = N+2's start (owner N+1, waits for N's take) | the next request names another parent (or attributes, or the generation moved): `take_chained` -> `abandon_branch` (generation +1, `slot` and `next` taken out, `deferred` cleared) and both answers drained (`CHAIN_DRAIN` 3 s); an EL refusal -> `abandon_chain`; `CHAIN_STALE` 20 s |
| EL queue, `tx-queue` `Inner::held` | N's transactions, forgotten from the build's taken list and **held at (N, sealed hash) by the BUILD_ON_OWN request for N+1** (`payload_serve.rs` "own block's transactions forgotten by the queue ahead of / beside the build") | the canonical pruner's settle of height N (`prune_block` -> `settle_own_block`): another hash gives back what it does not carry and logs "an own block at this height was not the one committed"; the `OWN_HOLD_BLOCKS` bound evicts (lost) |
| EL queue, `last_build` taken list | N+1's transactions (the build on N's sealed hash) | the next build's `begin_build` on another parent gives them back |
| EL built store, `built_executions.rs` | N and N+1 entries (Sealed -> Complete), pinned at consensus seal (`pin_sealed`) | `release_passed_pins` once the canonical head reaches their number; `max_pinned` = 4 x keep; then count eviction (`N42_BUILT_KEEP`, default 3). The identity is (parent, number, roots, gas, tx root), so an orphan is never found for its replacement |
| QMDB trees (`chain_alias::rename` built -> sealed) | N's and N+1's trees | the forest's own pruning past the canonical head (not changed here) |
| frame index / plan ahead | `handed` names N as the block a plan prepared ahead is accepted against | a plan on another parent is discarded (`discard_prepared`, `AheadDiscard`) |

The followers never see N+1: only a proposed block is published (proposal, block-body gossip, hand-off), and
followers vote by import height (`holds_far_ahead`, `DEFERRED_IN_FLIGHT`). The h2 driver proposes on the parent the
core names (the high-QC block); the EL is not told of the orphan explicitly: the mismatched parent at
`take_chained` is the signal, and forkchoice moves to the committed block.

The sequence: (1) N sealed -> N+1 starts behind the slot, and its BUILD_ON_OWN request holds N's transactions in the
queue; (2) N is not proposed (tenure end) or fails its QC (timeout / TC), the next request names the committed tip,
the client discards and drains N and N+1, the leader builds height N again; (3) the canonical prune settles N with
the other hash and gives N's transactions back -- after the replacement was built without them.

## 2. Where stage w's `own_not_committed=3` came from

`own_not_committed` is `grep -c 'was not the one committed'` over node0's EL log (`queue_prune.rs:88`): the settle of
a height that holds an own block under another hash. It is the queue's correct recovery, but the runner's BODYGATE
stops on any. The leg had **tc=0**: none came from a failed QC.

* **1024** (tenure handover, view 1024, key 0 -> key 1, one shared EL): key 0's chain built 1024 and, behind it,
  1025; the 1025 request held 1024's 200,000 transactions. Key 1 built its own 1024 on 1023, which was committed;
  the settle gave back 200,000. Under the default gate nothing builds on the tenure's last chained block, so it is
  never held and this line never appears: two-ahead makes it one per tenure.
* **2164, 2184** (end of the flood, queue empty): the build behind the slot (2165 on sealed 2164) was refused by the
  EL ("no QMDB tree for parent block", the parent's tree not filed yet). `abandon_chain` then **bumped the generation**,
  which abandoned the slot's 2164 as well, though it stood on the right parent: its take read "its branch was
  abandoned" with `started_on == asked_for`. The refused 2165 request had already held 2164's 127,500 transactions,
  so the rebuilt 2164 had 0, was committed, and the settle gave the 127,500 back. Same for 2184 / 2185.

What should have happened: 2164 taken and proposed (only the build behind dropped), and 1024's transactions back in
the lanes when key 1's build at 1024 started.

## 3. Fixed (all behind `N42_BUILD_AHEAD_GATE=seal`; the default gate never has a build behind or an early hold)

1. `h2-el-rpc` `abandon_chain`: a failure of the build behind the slot clears `next` and a start its own seal
   deferred, and leaves the generation, so the slot's build is still taken. Tests:
   `abandoning_the_build_behind_keeps_the_slot` (now asserts the generation), `a_failed_build_behind_takes_only_its_own_deferred_start`.
2. `tx-queue` `release_own_blocks_from(number)` + `engine-types` `release_replaced_own_blocks` before every build's
   selection (payload service and build-on-own): a build at height h gives back the own blocks held at h or above at
   once, exactly once (the later settle finds nothing), lowering only the build-side watermark so a nonce the chain
   mined stays filtered. Tests: `a_replaced_own_block_is_released_once_and_its_height_settles_clean`,
   `a_release_keeps_what_the_chain_mined_filtered`.
3. `built_executions`: no change needed; `an_orphaned_two_ahead_pair_is_released_and_the_replacement_is_found` pins the
   behaviour (orphan pair kept apart from the replacement, released when the chain passes, then evicted).

## 4. Not fixed, to watch on the leg

* The pruner fell behind on the AG leg only: 996 "still held when the bound was reached" lines, every one 16 blocks
  old (`let_go_warns=452`, `held_evicted`), `prune_ms` up to 137 with `lock_us` 71-76 ms (two builds on the queue's
  lock) and `settle_us` up to 13.6 ms. Those blocks were committed, so nothing was lost, but the bound is too small
  for the earlier holds: run two-ahead with `N42_OWN_HOLD_BLOCKS=32` and read the line count.
* The build behind refused for "no QMDB tree for parent block" (3 on the leg, all on empty, fast blocks): with fix 1
  it costs one build behind (that block falls back to one ahead), not the slot.
* `N42_BUILT_KEEP=5`: sealed-unanswered blocks rise to ~4.7 (section 5 of the pace doc); pins are exempt from keep.

## 5. The leg

Env on top of the X16 set: `N42_BUILD_AHEAD_GATE=seal N42_BUILD_AHEAD_AT_SEAL=1 N42_BUILT_KEEP=5 N42_OWN_HOLD_BLOCKS=32`
(gate read by both the validators and the EL). Proof counters: `own_not_committed=0`, no BODYGATE stop, tc 1,
"still held when the bound" 0, "own blocks held at or above this build's height were replaced" only at handovers,
chain discards with reason "its branch was abandoned" and `started_on == asked_for` 0, hand-off evictions / direct
imports of own blocks 0, start delay (`sd.py`) gated share < 10% and < 2 ms mean, mean gap ~40 ms, EL peak RSS.
