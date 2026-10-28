# Local faults that stop a validator

Two faults are this node's own and are not something a peer can cause. A
HotStuff-2 validator (`crates/n42/h2-node`, run as `h2_validator`) reacts to
each without operator input; the operator's part is the restart or the resync
below. Design item 6.5 of `docs/MATURITY_HARDENING_2026_10.md`.

## 1. The vote log cannot be written

Before every vote (R1 vote, R2 commit vote, the leader's self-votes) the
validator writes and fsyncs its vote log under the consensus datadir. A failed
write already aborts that one vote. The engine counts failures **in a row**
(a successful write resets the run); after `N42_VOTE_LOG_FATAL_AFTER`
consecutive failures (default 3) it is fatal:

- the engine stops voting at once and returns `ConsensusError::Fatal { reason: "vote_log" }`;
- the service logs it at `error` with the last I/O error and the operator
  action, sets `n42_h2_fatal{reason="vote_log"} = 1`, and ends its loop with
  `ServiceError::Fatal`;
- `h2_validator` prints `FATAL vote_log: ...` and exits with code **3**.

Why stop: a validator that cannot record what it signed would not know after a
restart, and could sign a conflicting vote in a view it already voted in
(equivocation). Not voting is always safe; voting unrecorded is not.

Operator: fix the disk (space, permissions, I/O errors on the consensus
datadir), then restart the validator — systemd's `Restart=on-failure`, or
`scripts/fleet7.sh roll <i>` on the fleet. The vote log replays on start, so the
restarted validator knows every vote it recorded. No resync is needed.

## 2. The execution layer refuses a committed block

When the forkchoice that commits a block (a quorum-certified one) is answered
`Invalid`, this node's execution layer will not follow the chain consensus
decided: they have diverged. With `N42_HALT_ON_COMMIT_INVALID` on (the
default) the node:

- logs at `error` the block hash, its number when known, and the execution
  layer's validation error (the first refusal is kept by the driver as
  `CommitRefusal`);
- stops voting, proposing and broadcasting timeouts for the rest of the
  process (`n42_h2_voting_halted{reason="commit_invalid"} = 1`);
- keeps running: it still imports, processes certificates and commits, and
  sends the forkchoices, so its logs and RPC show where it diverged.

A `Syncing` answer is not a fault: the block's body has not arrived yet and the
commit waits for its import. Transport errors are retried as before.

Operator: keep the logs (they name the first refused block) and resync the node
with a fresh execution layer — on the fleet `scripts/fleet7.sh roll <i> --fresh`
(keeps the consensus state, re-initialises the execution layer from the genesis
and pulls the chain by range); on the devnet the `LATE_VALIDATOR=<i>` path of
`scripts/devnet-fleet.sh`, which starts that member with its own fresh execution
layer. If the fresh layer refuses the same block, the block (or this client) is
the problem, not the node's state: report it before restarting the fleet.

## 3. A crash before the execution layer's first persistence (not a fault)

The QMDB forest settles canonical blocks before reth's database commits them
(item 6.3), and reth persists in batches: reth 2.8.1's defaults hold up to 50
canonical blocks in memory (minus a 5-block buffer), which a QMDB chain now
lowers to 8 and 6 unless `--engine.persistence-threshold` /
`--engine.memory-block-buffer-target` are given. Either way a node killed in its
first blocks has an MDBX database still at genesis while `el/qmdb/` already
holds deltas past it. A restart in
that state is normal: the genesis seed writes the forest's checkpoint at
genesis (`forest.bin` in heap mode, `forest.ckpt` in entry-file mode), so the
delta log starts there, the replay stops at genesis, the restored root is
checked against the genesis header, and the blocks past it arrive again through
the engine. Before this, the first checkpoint was written at block 1 and such a
restart failed with `QMDB snapshot is at block 1 ... but the database head is
block 0`; a datadir left in that state by an older binary has to be
re-initialised (`roll <i> --fresh`). The validator's log says how far its
execution layer has persisted: `persisted block advanced` at most every 10 s,
and `persistence lagging: head=.. persisted=.. unpersisted=..` while more than
16 blocks have stood unpersisted for over 10 s.

The same lead applies to every later checkpoint: a fold (the background
compaction that rotates `forest.log` into `forest.log.sealed` and folds it into
a new checkpoint) writes the checkpoint at the forest's head, up to the
persistence lag past MDBX's. Each fold therefore first keeps the checkpoint it
replaces and the segment it folds as a pair under
`el/qmdb/recovery-archive/fold-<block, 20 digits>-<hash>-<pid>-<n>/` (hard
links, so no copy is made): `forest.bin` + `forest.log` in heap mode,
`forest.ckpt` + `forest.log` in entry-file mode. The live-forest rewrite
(`N42_QMDB_CHECKPOINT_SYNC=1`) keeps the same pair under the same name: the
checkpoint it replaces and the log the new checkpoint supersedes. A restart whose MDBX head lies
below the live checkpoint replays the archive up to that head; in entry-file
mode it also cuts `entries.log` back to that head's cursor, drops the live log
and rewrites `forest.ckpt` at the head, logging `restored the QMDB forest from a
fold archive`. An archive is removed at a later fold once MDBX's durable head
(its `Finish` stage checkpoint) is past the fold head's child, so a running
node normally holds the archives of the last few folds only. Without a
readable durable head nothing is removed. Heap-mode restarts below a fold head
also leave `rollback-<block>-<hash>-*` directories (the future log they
discarded); they retire by the same rule, once the durable head is past the
child of the block they rolled back to. A `SnapshotMismatch` at
startup with no fold archive covering the head is a datadir from before this
change or one whose archives were deleted by hand: re-initialise it.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `n42_h2_vote_log_failures_total` | counter | Vote-log write/fsync failures since start. |
| `n42_h2_fatal{reason}` | gauge | 1 once a fatal fault stopped the validator (`reason="vote_log"`). |
| `n42_h2_voting_halted{reason}` | gauge | 1 once the node stopped voting and keeps following (`reason="commit_invalid"`). |

They go through the `metrics` facade; a process without an installed recorder
(`h2_validator` today installs none) exports nothing, and the log lines and the
exit code are the signal there.

## Knobs

| Knob | Default | Effect |
|---|---|---|
| `N42_VOTE_LOG_FATAL_AFTER` | 3 | Consecutive vote-log failures that stop the validator; `0` never stops (each failure only aborts its vote). |
| `N42_HALT_ON_COMMIT_INVALID` | on | `0` keeps voting after a commit forkchoice is refused (benches only). |

Both are read once at service construction.
