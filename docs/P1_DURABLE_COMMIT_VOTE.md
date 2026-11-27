# Profile 1: a commit vote means a durable block (AM35)

Plan item E4 (`docs/PLAN_P1_REMAINING_2026_11.md`), standard amendment AM35
(`docs/MIXED_PRODUCTION_STANDARD.md`). Branch `fix/p1-durable-commit-vote`.

## The finding

An all-Rust profile-1 set (4 validators, 4 execution layers, main `d8a5e54d2`) killed with SIGKILL all
at once halted for good. The execution layer kept up to 8 canonical blocks in memory
(`QMDB_PERSISTENCE_THRESHOLD = 8`): the set had committed 35, every layer had persisted 28, blocks 29..35
existed nowhere, and every member's highest QC named block 35 ("the block our highest QC certifies is not
imported; asking for it", for ever). With `--engine.persistence-threshold 0
--engine.memory-block-buffer-target 0` the same kill recovered, but reth saves asynchronously after the
forkchoice update, so the window does not close: the threshold alone is not the fix.

## The rule

A member sends its commit (R2) vote for block B only once (a) its lock, B's PrepareQC, and (b) B's block
data, and every ancestor's, are durable. Then a commit QC, or a lock held by f+1 members, always names a
block those members can serve after any of them restart together. The leader's own commit vote waits the
same way. No profile-1 mode may defer or skip the durable write.

## Why a journal and not the execution layer's write

The vote is for a block that is not canonical yet. This client's execution layer persists only canonical
blocks, and a block becomes canonical when consensus commits it (`ExecutionDriver::commit`, the forkchoice
`head`), which is after its commit QC -- under deferred execution and without it. Waiting for the execution
layer's persisted height would deadlock: the commit QC needs the vote, the vote needs the persist, the
persist needs the forkchoice, the forkchoice needs the commit QC.

Two ways out were weighed:

1. **Forkchoice the block before its commit** (head only, at import), so reth persists it, and gate the
   vote on a "persisted by hash" reading from the layer. Costs a forkchoice and a full execution-layer
   save (MDBX, static files, QMDB) on the commit-vote path of every block (n42-26 measured 15-20 ms empty,
   0.1-0.5 s full for that route), makes the execution layer's head run ahead of consensus, and turns
   every block that is voted but not committed (a timeout, a re-proposal) into a disk reorg through
   `remove_blocks_above` and a QMDB rewind. It also has to be ordered against the asynchronous commit
   forkchoices, or a late commit for the parent arrives after the child's forkchoice.
2. **A node-local block journal** (chosen). The validator already holds B's wire body (gov5's RLP, what
   peers are served) when it votes. It appends that body to `<datadir>/block-journal/<number>-<hash>.blk`
   (written to a temporary name, fsync, rename, directory fsync), then the vote log writes and syncs the
   lock as it already did before every signature, then the vote goes out. Nothing in the execution layer
   changes, nothing is made canonical early, and the cost is one small file write per block.

The journal is not a second chain database: it holds only blocks above the execution layer's persisted
height (pruned on every commit at `n42Engine_persistedBlock`), normally one or two files.

## How it works

- **Engine** (`n42-h2-consensus`). `VoteRules::commit_vote_needs_durable_block()` (profile 1). A
  follower's commit vote, already held until the own import (A13), is also held until
  `ConsensusEvent::BlockDurable(B)`; the leader's own commit vote, cast when it forms the PrepareQC, is
  held the same way (`held_leader_commit`). When it holds a vote for this reason the engine emits
  `EngineOutput::DurabilityWanted(B)`. The lock is in the vote log record written before the signature
  (`record_commit_vote(view, locked_qc)`), and the PrepareQC raises the lock before that write, so (a) was
  already true.
- **Service** (`n42-h2-node`, `H2Service::make_durable`). On `DurabilityWanted(B)` it walks from B down
  the parent links it holds: a block already journalled, the genesis block, or one at or below the
  execution layer's persisted height ends the walk; every other block on the way is journalled, ancestors
  first, from the body store (or, for an own block taken elided, from the layer). Then it reports
  `BlockDurable(B)`. A body or header not here yet leaves B pending, tried again on the next drain; a
  failed write keeps the vote held (and says so at error level). A node without a datadir keeps no vote
  log either and answers at once.
- **Restart** (`H2Service::restore_block_journal`, run by `h2_validator` before its loop). Every
  journalled block the execution layer does not hold is imported again, lowest first, as a pulled block
  (newPayload, then a head-only forkchoice: neither safe nor finalized), and its body, header and parent
  are remembered so it is served and built on. This happens before the node serves, votes or builds.
- **Execution layer** (`bin/n42`, vendored `reth-node-builder`). On a profile-1 genesis the engine tree
  runs at persistence threshold 0 and buffer target 0 (`profile1_tree_config`), so committed blocks reach
  disk as soon as they are canonical and the journal stays short. The start-up check
  (`n42_qmdb_reth::profile1`) refuses, on a profile-1 chain, `--engine.persistence-threshold` or
  `--engine.memory-block-buffer-target` above 0, `RETH_ENGINE_PERSISTENCE_THRESHOLD` above 0, a
  `--db.sync-mode` / `RETH_DB_SYNC_MODE` other than `durable`, and `N42_ROCKSDB_NOSYNC`. Refused rather
  than silently overridden: an operator who set them meant something, and AM35 item 5 says no profile-1
  mode may defer the write. The tree config applies 0 anyway, whatever reached it.

The ancestor check reads the persisted height by number. The execution layer makes canonical only what
consensus committed (or what a verified catch-up pulled), so the block at a persisted height is the one
on the chain the walk follows; the walk itself goes by hash.

## Cost

One journal append (two fsyncs) on the commit-vote path per block; measured figures are in the gate
record below. Off profile 1 nothing changes: the engine never asks, the journal is not opened, and the
tree defaults are the QMDB ones (8 / 6).

## Gate

See the gate record appended below (whole-set SIGKILL, kills timed right after a commit and right after
a PrepareQC, at least five each, and one at old main with the same timing).
