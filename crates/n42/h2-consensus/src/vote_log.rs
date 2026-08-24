//! Persistent vote log: durable last-voted-view storage.
//!
//! HotStuff-2 safety requires that a validator never votes twice in the same
//! view. The in-memory `RoundState::last_voted_view` enforces this within one
//! process lifetime, but a crash before the snapshot is written would let a
//! recovered node re-vote in the view it had already advanced into. The
//! `VoteLogWriter` trait lets the `ConsensusEngine` request a synchronous
//! durable record of the last R1 and R2 vote views immediately *before*
//! signing. The orchestrator owns the file handle so the engine itself stays
//! pure / event-driven and unit tests can plug a `NoopVoteLog`.
//!
//! See `Plan #1` in `~/.claude/plans/atomic-dreaming-hare.md`.

use crate::error::{ConsensusError, ConsensusResult};

/// A sink that durably records the highest R1 and R2 views this validator has
/// signed. Implementations must `fsync` (or equivalent) before returning
/// `Ok(())`; on `Err`, the engine aborts the corresponding vote.
pub trait VoteLogWriter: Send + Sync + std::fmt::Debug {
    /// Record `view` as the latest signed R1 vote view. MUST `fsync` before
    /// returning so a power loss after this call cannot lose the record.
    fn record_vote(&self, view: u64) -> ConsensusResult<()>;

    /// Record `view` as the latest signed R2 CommitVote view. MUST `fsync`
    /// before returning.
    fn record_commit_vote(&self, view: u64) -> ConsensusResult<()>;
}

/// No-op writer used by tests, single-validator dev mode, and any path where
/// crash-safe vote persistence is not required.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopVoteLog;

impl VoteLogWriter for NoopVoteLog {
    fn record_vote(&self, _view: u64) -> ConsensusResult<()> {
        Ok(())
    }

    fn record_commit_vote(&self, _view: u64) -> ConsensusResult<()> {
        Ok(())
    }
}

/// Helper used by orchestrators that own a `std::fs::File`-backed vote log.
/// Wraps an `io::Error` into the consensus error variant so the engine can
/// surface it through `ConsensusResult`.
pub fn map_io_err(err: std::io::Error) -> ConsensusError {
    ConsensusError::VoteLogFsync(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_vote_log_always_succeeds() {
        let log = NoopVoteLog;
        for view in [0, 1, 100, u64::MAX] {
            log.record_vote(view).expect("noop must always succeed");
            log.record_commit_vote(view)
                .expect("noop must always succeed");
        }
    }
}
