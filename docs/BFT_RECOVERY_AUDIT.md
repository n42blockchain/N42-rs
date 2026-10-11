# BFT recovery audit: vote and lock state across a restart

Scope: `crates/n42/h2-consensus` (engine), `crates/n42/h2-node` (`persistence.rs`).
Trigger: arXiv 2610.07759, "When Can Stateless Recovery Defeat Byzantine Quorum Safety?".

## What the paper claims

A correct node that keeps its signing key but loses its vote and lock state on
recovery behaves like a Byzantine node for safety purposes. With n nodes,
quorum q, b truly Byzantine nodes and c such amnesiac recoveries, two
conflicting certificates become possible once b + c >= 2q - n. A fleet sized to
tolerate f Byzantine nodes therefore tolerates only f - c of them while c nodes
can restart without their state. The recommended check is fault injection at
every boundary of "record vote -> persist -> sign -> send".

## Signatures and the state they depend on

| Signature | Signs | State it needs durable |
| --- | --- | --- |
| R1 vote | view, block hash | R1 watermark (`last_voted_view`) and the lock it votes under |
| R2 commit vote | view, block hash, changes hash | R2 watermark (`last_commit_voted_view`) and the lock (raised by the PrepareQC just before) |
| Timeout | view only | none that is safety relevant (a timeout carries the high QC, it does not bind a block) |
| NewView | next view only | none beyond the timeout |

A vote is a promise: never vote twice in a view, and never support a proposal
the lock forbids. Both halves must survive a crash that happens after the
signature leaves the process.

## Before f24c85ac5

The watermarks were written (and fsynced) before signing, so double-voting in a
view was already closed. The lock was not: it lived only in the in-memory round
state and reached disk with the checkpoint, which is written at commit.

Crash window: the node receives a PrepareQC (lock raised to view v), signs the
R2 commit vote under it, and the commit vote is sent. The process dies before
the block commits, so the checkpoint still holds the older lock. After restart
the node accepts a proposal justified by a QC older than v that it had promised
to refuse. Counted as in the paper, that node is Byzantine for lock safety
although its key and watermarks were intact.

## What is durable now

`FileVoteLog` is one small file, `<datadir>/vote-log.bin`, rewritten in place and
fsynced (file and directory) before each signature:

    [last R1 view u64 LE][last R2 view u64 LE][qc_len u32 LE][locked QC][crc32]

The engine calls `record_vote` / `record_commit_vote` with `locked_qc()` at the
four signing sites (follower R1, leader self R1, follower R2, leader self R2),
after the in-memory watermark moves and before the signature is produced. A call
that changes neither a watermark nor the lock is skipped without a syscall. A log
written before the lock was recorded decodes with `locked_qc = None`.

## Recovery rule

`ConsensusStore::load` reads the checkpoint (`consensus-checkpoint.json`) and the
vote log and takes the higher of each: both watermarks, and the lock with the
higher view. The view is advanced to at least the log's. A corrupt vote log
(bad crc, truncated) returns `StoreError::CorruptVoteLog` and the node refuses to
start; it does not fall back to the checkpoint. `h2_validator` restores through
`with_recovered_state_and_vote_log`, and the log is attached on a fresh start too,
so it is durable before the first signature.

`N42_VOTE_LOG_NOSYNC=1` skips the fsync. It is a bench knob. With it set none of
the guarantees here hold; do not use it on a fleet that restarts.

## Test matrix

Unit, `h2-consensus` `state_machine_gap_tests.rs`
(`every_persist_boundary_of_a_vote_is_safe_for_both_rounds`), a follower driven
through view 1 against a fault-injecting log, then rebuilt from the durable
records only:

| Round | Boundary | Engine result | Rebuilt engine |
| --- | --- | --- | --- |
| R1 | write lost (fsync error) | `VoteLogFsync` error, no vote sent | nothing durable, nothing signed: may vote |
| R1 | durable, crash before sign | error, no vote sent | refuses to vote in that view |
| R1 | durable and sent | vote sent | refuses a second vote in that view |
| R2 | write lost | error, no commit vote sent; lock raised in memory only | old lock, may commit-vote |
| R2 | durable, crash before sign | error, no commit vote sent | refuses; raised lock is durable |
| R2 | durable and sent | commit vote sent | refuses; lock kept |

Also `a_lock_raised_before_a_crash_still_refuses_an_older_justification_after_it`
(stale checkpoint, log lock wins, older justification refused with
`SafetyViolation`), and the 14 tests of `h2-node/tests/persistence.rs`.

Since e21c76dbb a failed log write rolls the in-memory watermark back, so the
same view can be retried once the disk recovers (the test asserts the retry is
signed after a fault, refused after a success, and that the node rebuilt after the
retry will not vote that view again).

Recovery bound, same file, one choreography, n = 7, q = 5, validators 0 and 1
Byzantine (the test holds their keys and signs for them; no Byzantine engine
code), 2-6 real engines. Views 7 and 8 (the leaders of both are Byzantine). The
leader shows block A to members 2, 3, 4 only; 5 votes (3 honest + 2) give a
PrepareQC and a commit QC for A. Member 4 then restarts (engine dropped with no
flush) and the leader of view 8 proposes a conflicting B, justified by genesis,
to 4, 5, 6. No Decide is delivered; the commit QC is the commit.

| Test | b | c | Restored 4 | Result |
| --- | --- | --- | --- | --- |
| `two_byzantine_and_one_amnesiac_member_can_commit_conflicting_blocks` | 2 | 1 | genesis lock, zero watermarks | B gets 5 votes, PrepareQC and commit QC; both commit QCs verify, hashes differ, views 7 and 8: the bound is reached |
| `two_byzantine_members_cannot_when_the_restarted_member_kept_its_vote_log` | 2 | 0 | lock = QC_A, watermarks 7 from its log | 4 returns `SafetyViolation { qc_view: 0, locked_view: 7 }`, signs nothing and logs nothing; B has 4 votes, `InsufficientVotes { have: 4, need: 5 }`, no QC |

The first test shows the harness has teeth; the second is the guarantee of
f24c85ac5.

Live, `h2-node/tests/four_node_fleet.rs`
(`a_member_restarted_from_its_store_rejoins_and_never_revotes_a_logged_view`):
four members over real gossip, each with a `ConsensusStore`. After member 3
commits it is stopped and rebuilt from its directory (real `FileVoteLog`, same
checkpoint writer as `h2_validator`) and rejoins. Asserted: the engine starts at
or above the persisted watermark and lock; every R1 view it asks the log to record
afterwards is above the persisted `last_voted_view`; it commits a later view.
Passes in about 1 s. The restarted member has a fresh mock execution layer, so
it also pulls the chain by range.

## Remaining gaps

- Remote signers: none exist. The validator signs with an in-process
  `BlsSecretKey`, so there is no second place that holds a key and a watermark.
  Any future remote signer must apply the same rule on its side: persist the
  watermark and lock before it signs.
- Power cut: the engine-level crash tests drop the engine with no flush, which
  is the state a SIGKILL or power cut leaves given the fsync before each
  signature. The operator-level SIGKILL restart is `scripts/fleet7.sh roll <i>
  --kill`. Torn sector writes and an fsync that lies are covered only by the crc
  and the single-sector record; they are not injected.
- A live 7-node run with 2 Byzantine members is not done. It adds little over
  the engine-level test: the transport cannot change what an engine signs, and
  the test already plays the network and the Byzantine keys exactly.
- A snapshot restore (`LATE_SNAPSHOT`, `n42-init-snapshot`) restores only the
  execution layer. The consensus store (`vote-log.bin`, checkpoint) is a separate
  directory and is not part of it. Restoring a validator onto a fresh consensus
  directory loses its watermarks and lock, which is exactly the amnesiac case
  above; keep the old store or do not reuse the key.

## Tracked, no action

- EIP-8288 / PQ-proof ISA: no ZK light-client work in this repo.
- EIP-7906 transaction assertions: N42's parallel builder is not Block-STM.
- ATMACA threshold Falcon: no implementation to measure; FIPS 206 is still in development.

## Operator-level SIGKILL restart, 2026-10-10

Shape: all-Rust seven-node fleet (`scripts/fleet7.sh up --fresh`, chain 1143 genesis, 3000 ms pacing, one execution layer per validator, QMDB). All seven agreed from height 50 on and advanced steadily.

Kill: `scripts/fleet7.sh roll 3 --kill` at member 3's committed height 63 (fleet common height ~62-63). Checkpoint values at the kill: `last_voted_view` 64, `last_commit_voted_view` 64, `locked_qc.view` 64 (checkpoint `view` 65). Validator and execution layer were both SIGKILLed.

Vote log: the validator reached the point of loading it. Its first lines were "resuming at view 65 (last voted 64)", so the restored state equalled the checkpoint; it was not ahead. No "already voted" / "suppressed duplicate commit vote" line appeared (the script's grep reported none), because the member never got far enough to vote again.

Result: member 3 did NOT rejoin. Its execution layer failed to start: on open, reth's consistency check found "partial state trie" (QMDB ahead of or inconsistent with MDBX), scheduled an unwind from 46 to 16, and the `MerkleUnwind` stage failed with "Failed to verify block state root" (Invalid state root on stage verification). The validator then exited with `ElError(transport ... 127.0.0.1:8603)` because the EL was down. Member 3 therefore never committed again (seconds to re-commit: not reached; the roll script's wait loop ran out).

Other six: kept committing through and after the kill (common height of the others 62 at the kill, 108 about two minutes later, 111 at teardown), as expected with n=7, f=2.

Finding: the BFT side of a SIGKILL restart (checkpoint and vote log restore) is fine; the gap is execution-layer crash recovery on a QMDB chain. After SIGKILL the consistency heal unwinds through the stock `MerkleUnwind` stage, which cannot verify the root for a QMDB-scheme chain. Next step: make `check_consistency` heal the QMDB forest to the MDBX tip (or roll MDBX forward) instead of unwinding, then rerun this test. The datadir of member 3 was left in the failed state under /data/blockchain/rust-fleet7/node3 until the next `up --fresh`.

## Execution-layer recovery fixed, 2026-10-11

Root cause: since the reth 2.7.0 upgrade of 2026-10-02, `DEFAULT_NUM_STATE_MASKING_BLOCKS` is 30, so the hashed-state frontier trails the database tip by up to 30 blocks. A graceful stop catches the frontier up; a SIGKILL does not. On the next start reth's consistency check unwound the frontier through `MerkleUnwind`, which cannot verify a QMDB root and failed with "mismatched block state root".

Fix: commit 4ab22608b forces the masking suffix to 0 on a QMDB chain (log line "State masking suffix is off on a QMDB chain"). Commit 8e3e20154 also tried to heal a lagging frontier forward from plain state; that was wrong in principle and has been replaced.

Why the heal cannot work: with storage v2 the hashed tables are the state, and `save_blocks_inner` writes the masking suffix's blocks with only their bytecodes and changesets (`write_state` short-circuits; `disjointed_merge_batch` even withholds batch keys the suffix changes). The post-state of the masked blocks lives only in memory, so a SIGKILL loses it, and rewriting hashed state from plain state cannot restore it. Reth's own recovery is an unwind to the frontier plus a re-sync, and on a QMDB chain the unwind needs the QMDB forest to step back below its checkpoint, which `QmdbNodeState::initialize_file_mode` does not support.

Replacement: the heal is removed. A QMDB datadir whose frontier lags the tip (only an older binary can write one) is refused at startup with the numbers and the instruction to re-initialise the execution layer; `scripts/fleet7.sh roll <i> --fresh` does exactly that (it deletes only `el` and `el.pid`, never `consensus`, which holds the vote log and checkpoint).

Rerun: seven members, `scripts/fleet7.sh roll 3 --kill` after the fleet agreed past height 60.

| Leg | Binary at up / at restart | Height at kill (member 3 / others) | Frontier handling | Rejoined | +60 s (member 3 / member 0) | +120 s (member 3 / member 0) |
| --- | --- | --- | --- | --- | --- | --- |
| A, upgrade, with the heal (8e3e20154) | pre-fix / heal build | 64 / ~64 | healed, frontier=16 tip=46 | NO | 46 / 82 | 46 / 99 |
| B, fixed end to end | fixed / fixed | 68 / ~68 | none (masking suffix off) | yes | 91 / 91 | 111 / 111 |
| C, upgrade, refusal then `roll 3 --fresh` | pre-fix / refusing build | 62 / ~62 | refused (see below) | `--kill` leg: no, by design; `--fresh` leg: yes (block 203 of 203 at the first check, ~35 s after the restart) | 237 / 237 (at +50 s; the fleet was at 203 at +35 s) | 255 / 255 (at +105 s; 276 views by +160 s) |

Leg B passes: no unwind, the execution layer stays up, the validator logs "resuming at view 70 (last voted 69)" and commits alongside the others within 60 s.

Leg A: the heal ran (no unwind, no "Failed to verify block state root") but member 3 did not rejoin: the first pulled block (47) was rejected with "block's state root does not match its QMDB root", because the masked blocks' state had never been written. That is the observation that led to dropping the heal.

Leg C, `roll 3 --kill` half: the new binary on the pre-fix datadir exits with `the hashed-state frontier #16 lags the database tip #46; on a QMDB chain this cannot be unwound (...) or healed (...); re-initialise this member's execution layer: scripts/fleet7.sh roll <i> --fresh, or delete the datadir and resync`, and the validator does not rejoin, as intended.

Leg C, `roll 3 --fresh` half (2026-10-11, rerun on a quiet box): passes. Seven members up on the pre-fix binary, agreed past height 80; `roll 3 --kill` with the fixed binary was refused with `the hashed-state frontier #48 lags the database tip #78` (an earlier identical rerun read #32 / #62), checkpoint `{"last_voted_view":85,"last_commit_voted_view":85,"locked_qc_view":85}`. `roll 3 --fresh` printed "execution layer re-initialised; consensus state kept", the new execution layer seeded the QMDB forest from the genesis alloc, the validator logged "resuming at view 86 (last voted 85)" and pulled the chain by range: member 3 read 203 against the fleet's 203 about 35 s after the restart, then 237 / 237 at +50 s, 255 / 255 at +105 s. The checkpoint afterwards read last_voted_view 276 (never below the 85 before). The new `node3/el.log` has one ERROR, the known harmless "N42_TX_INGEST is not an address". Two harness notes: `roll <i> --fresh` aborts at once on `set -e` when member `<i>` is already down (`before=$(f7_height ...)` fails; the run above used a scratch copy of the script with `|| true` on that line, repo script unchanged), and a tool call that times out kills the fleet it started.

Remaining gap: `roll <i> --fresh` should tolerate a member that is already down (`before=$(f7_height "$i" || true)`).
