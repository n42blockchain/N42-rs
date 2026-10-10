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
