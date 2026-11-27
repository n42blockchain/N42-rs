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
  `EngineOutput::DurabilityWanted(B)`.
- **The lock on disk** (n42-26's pitfall (a)). The lock reaches disk in two places: the vote log record
  written before every signature (`record_vote` / `record_commit_vote(view, lock)`) and the checkpoint
  written at each commit (`checkpoint_from`). gov5's V6 lock rule raises the in-memory lock as soon as a
  valid PrepareQC arrives, before this node has made the block durable, and a later R1 vote (next view)
  would then have written that lock. Both writers now take `ConsensusEngine::persistable_lock()`: the lock
  when its block is durable here (or the lock is genesis), else the higher of the highest lock that was
  (`durable_lock`, seeded from the restored lock at start-up) and the committed QC -- never below the
  committed QC (AM35 item 6). A timeout certificate's high QC raises only the in-memory lock and so
  reaches disk the same way. So a restart never holds a lock on a block
  it cannot serve. Writing the lower lock is safe because only a commit vote has to survive a restart with
  its lock, and this node commit-votes only on a durable block -- whose lock is then the persistable one.
  Off profile 1 `persistable_lock()` is the lock. Tests:
  `profile1_the_vote_log_never_carries_a_lock_on_a_block_not_durable_here`, and the persistable-lock
  assertions in `profile1_commit_vote_waits_for_the_durable_block`.
- **Service** (`n42-h2-node`, `H2Service::make_durable`). On `DurabilityWanted(B)` it walks from B down
  the parent links it holds: a block already journalled, the genesis block, or one at or below the
  execution layer's persisted height ends the walk; every other block on the way is journalled, ancestors
  first, from the body store (or, for an own block taken elided, from the layer). Then it reports
  `BlockDurable(B)`. A body or header not here yet leaves B pending, tried again on the next drain; a
  failed write keeps the vote held (and says so at error level). A node without a datadir keeps no vote
  log either and answers at once.
- **Restart** (`H2Service::restore_block_journal`, run by `h2_validator` before its loop). Replay is
  keyed by hash (n42-26's pitfall (b)): every journalled block the execution layer does not hold *by hash*
  is executed again, lowest first. One above the layer's head is imported as a pulled block (newPayload,
  then a head-only forkchoice: neither safe nor finalized); one at or below the head -- a block that lost
  its height to the committed chain, or one the layer dropped -- is executed back in with newPayload
  only, no forkchoice, which would move the head back. Either way its body, header and parent are
  remembered so it is served and built on. This happens before the node serves, votes or builds. Test:
  `a_restart_replays_a_journalled_block_by_hash_when_the_layer_has_another_at_its_height`.
- **Pruning** (on every `BlockCommitted(C)`), also by hash: the walk from C by parent hash names the
  committed chain; its journalled blocks at or below the layer's persisted height go (the layer holds
  them), and so do journalled blocks at or below C's height that are not on it (siblings no certificate
  can commit any more). A journalled block above C stays.
- **Execution layer** (`bin/n42`, vendored `reth-node-builder`). On a profile-1 genesis the engine tree
  runs at persistence threshold 0 and buffer target 0 (`profile1_tree_config`), so committed blocks reach
  disk as soon as they are canonical and the journal stays short. The start-up check
  (`n42_qmdb_reth::profile1`) refuses, on a profile-1 chain, `--engine.persistence-threshold` or
  `--engine.memory-block-buffer-target` above 0, `RETH_ENGINE_PERSISTENCE_THRESHOLD` above 0, a
  `--db.sync-mode` / `RETH_DB_SYNC_MODE` other than `durable`, and `N42_ROCKSDB_NOSYNC`. Refused rather
  than silently overridden: an operator who set them meant something, and AM35 item 5 says no profile-1
  mode may defer the write. The tree config applies 0 anyway, whatever reached it.

The make-durable walk stops at an ancestor at or below the persisted height. That one check reads a
height: the walk itself goes by parent hash, and the layer makes canonical only what consensus committed
(or a verified catch-up pulled), so the persisted block at that height is on the chain the walk follows
whenever the walked block can still be committed.

Also by hash (AM35 item 6): the make-durable walk ends at a persisted ancestor only when the layer's
canonical block at that number *is* that ancestor (`block_by_number(n).hash == ancestor`), and reads
a header it lacks from the layer. At restart every replayed journal block is reported imported and
durable to the engine, and the restored lock's and commit's blocks are reported imported when the layer
holds them by hash -- so no vote gate waits forever on a block the node already holds (gov5's "halt one
block higher"). The leader's parent is the highest QC's block by hash (`proposal_parent`), its header
read by hash; the one height comparison there (`stale_build_parent`) only refuses a parent below the
committed height.

Trigger line for the cross-client timed-kill gate (T2): on profile 1, after the block is durable and
the lock is written, right before the commit vote is signed, target `n42::am35` logs
`commit vote released after durable lock view=<v> block_hash=<hash>` (the same text n42-26 logs).

## Cost

One journal append (two fsyncs) on the commit-vote path per block; measured figures are in the gate
record below. Off profile 1 nothing changes: the engine never asks, the journal is not opened, and the
tree defaults are the QMDB ones (8 / 6).

## Gate

See the gate record appended below (whole-set SIGKILL, kills timed right after a commit and right after
a PrepareQC, at least five each, and one at old main with the same timing).
