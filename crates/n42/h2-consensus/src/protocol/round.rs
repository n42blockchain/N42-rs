use n42_h2_primitives::consensus::{QuorumCertificate, ViewNumber};

/// The phase within a consensus round (view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for the leader to propose a block.
    WaitingForProposal,
    /// Leader has proposed; collecting Round 1 (Prepare) votes.
    Voting,
    /// QC formed from Round 1 votes; collecting Round 2 (Commit) votes.
    PreCommit,
    /// Block is committed (terminal state for this view).
    Committed,
    /// View has timed out; collecting timeout messages for ViewChange.
    TimedOut,
}

/// Tracks the state of the current consensus round.
///
/// Each view progresses through phases:
/// `WaitingForProposal → Voting → PreCommit → Committed`
///
/// A timeout at any point transitions to `TimedOut`, triggering view change.
#[derive(Debug, Clone)]
pub struct RoundState {
    current_view: ViewNumber,
    phase: Phase,
    /// The highest QC this node has seen (safety lock).
    /// Nodes only vote for proposals that extend this QC (justify_qc.view >= locked_qc.view).
    locked_qc: QuorumCertificate,
    last_committed_qc: QuorumCertificate,
    consecutive_timeouts: u32,
    /// The last view in which this node cast a Round-1 vote.
    ///
    /// Persisted to disk so that after a crash the node will not vote twice
    /// in the same view (fundamental BFT safety invariant).
    last_voted_view: ViewNumber,
    /// The last view in which this node cast a Round-2 commit vote.
    /// Persisted independently from R1 because a validator may crash between
    /// the two phases and must not sign a conflicting CommitVote after restart.
    last_commit_voted_view: ViewNumber,
}

impl RoundState {
    pub fn new() -> Self {
        let genesis_qc = QuorumCertificate::genesis();
        Self {
            current_view: 1,
            phase: Phase::WaitingForProposal,
            locked_qc: genesis_qc.clone(),
            last_committed_qc: genesis_qc,
            consecutive_timeouts: 0,
            last_voted_view: 0,
            last_commit_voted_view: 0,
        }
    }

    /// Restores state from a persisted snapshot (crash recovery).
    ///
    /// Preserves safety invariants (locked_qc, last_committed_qc, last_voted_view)
    /// across restarts.
    pub fn from_snapshot(
        view: ViewNumber,
        locked_qc: QuorumCertificate,
        last_committed_qc: QuorumCertificate,
        consecutive_timeouts: u32,
        last_voted_view: ViewNumber,
        last_commit_voted_view: ViewNumber,
    ) -> Self {
        Self {
            current_view: view,
            phase: Phase::WaitingForProposal,
            locked_qc,
            last_committed_qc,
            consecutive_timeouts,
            last_voted_view,
            last_commit_voted_view,
        }
    }

    pub fn current_view(&self) -> ViewNumber {
        self.current_view
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn locked_qc(&self) -> &QuorumCertificate {
        &self.locked_qc
    }

    pub fn last_committed_qc(&self) -> &QuorumCertificate {
        &self.last_committed_qc
    }

    pub fn consecutive_timeouts(&self) -> u32 {
        self.consecutive_timeouts
    }

    pub fn last_voted_view(&self) -> ViewNumber {
        self.last_voted_view
    }

    pub fn last_commit_voted_view(&self) -> ViewNumber {
        self.last_commit_voted_view
    }

    /// Returns `true` if this node has NOT yet voted in the given view.
    /// After returning `true`, the caller MUST call `record_vote(view)` before
    /// actually broadcasting the vote, to prevent double-voting after a crash.
    pub fn may_vote_in(&self, view: ViewNumber) -> bool {
        view > self.last_voted_view
    }

    /// Records that this node has voted in `view`. Must be called immediately
    /// after `may_vote_in()` returns `true` and before the vote is broadcast.
    pub fn record_vote(&mut self, view: ViewNumber) {
        debug_assert!(
            view > self.last_voted_view,
            "record_vote called without may_vote_in guard"
        );
        self.last_voted_view = view;
    }

    /// Returns `true` if this node has not cast an R2 commit vote in `view`.
    pub fn may_commit_vote_in(&self, view: ViewNumber) -> bool {
        view > self.last_commit_voted_view
    }

    /// Records an R2 commit vote before its signature is produced.
    pub fn record_commit_vote(&mut self, view: ViewNumber) {
        debug_assert!(
            view > self.last_commit_voted_view,
            "record_commit_vote called without may_commit_vote_in guard"
        );
        self.last_commit_voted_view = view;
    }

    pub fn enter_voting(&mut self) {
        self.phase = Phase::Voting;
    }

    pub fn enter_pre_commit(&mut self) {
        self.phase = Phase::PreCommit;
    }

    /// Marks the current view as committed and updates QC state.
    pub fn commit(&mut self, commit_qc: QuorumCertificate) {
        self.phase = Phase::Committed;
        if commit_qc.view > self.locked_qc.view {
            self.locked_qc = commit_qc.clone();
        }
        // Enforce monotonicity: last_committed_qc should never regress.
        if commit_qc.view >= self.last_committed_qc.view {
            self.last_committed_qc = commit_qc;
        }
        self.consecutive_timeouts = 0;
    }

    /// Advances to a new view, resetting the phase.
    /// Enforces monotonicity: the view can only move forward.
    pub fn advance_view(&mut self, new_view: ViewNumber) {
        if new_view <= self.current_view {
            return;
        }
        self.current_view = new_view;
        self.phase = Phase::WaitingForProposal;
    }

    /// Transitions to timed-out phase and increments the backoff counter.
    pub fn timeout(&mut self) {
        self.phase = Phase::TimedOut;
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
    }

    /// Resets the consecutive timeout counter after a QC-based view jump.
    pub fn reset_consecutive_timeouts(&mut self) {
        self.consecutive_timeouts = 0;
    }

    /// Updates the locked QC if the given QC has a higher view.
    pub fn update_locked_qc(&mut self, qc: &QuorumCertificate) {
        if qc.view > self.locked_qc.view {
            self.locked_qc = qc.clone();
        }
    }

    /// HotStuff-2 safety rule: a proposal is safe to vote on if its
    /// justify_qc extends the locked QC (justify_qc.view >= locked_qc.view).
    pub fn is_safe_to_vote(&self, justify_qc: &QuorumCertificate) -> bool {
        justify_qc.view >= self.locked_qc.view
    }
}

impl Default for RoundState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use bitvec::prelude::*;
    use n42_h2_primitives::BlsSecretKey;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
    }

    fn make_qc(view: ViewNumber) -> QuorumCertificate {
        let sk = test_key(view as u8 + 0x11);
        let sig = sk.sign(b"test-qc");
        QuorumCertificate {
            view,
            block_hash: B256::repeat_byte(view as u8),
            aggregate_signature: sig,
            signers: bitvec![u8, Msb0; 1, 1, 0, 1],
        }
    }

    #[test]
    fn test_initial_state() {
        let state = RoundState::new();
        assert_eq!(state.current_view(), 1);
        assert_eq!(state.phase(), Phase::WaitingForProposal);
        assert_eq!(state.consecutive_timeouts(), 0);
        assert_eq!(state.locked_qc().view, 0);
        assert_eq!(state.last_committed_qc().view, 0);
    }

    #[test]
    fn test_phase_transitions() {
        let mut state = RoundState::new();

        state.enter_voting();
        assert_eq!(state.phase(), Phase::Voting);

        state.enter_pre_commit();
        assert_eq!(state.phase(), Phase::PreCommit);

        state.commit(make_qc(1));
        assert_eq!(state.phase(), Phase::Committed);
    }

    #[test]
    fn test_timeout() {
        let mut state = RoundState::new();

        state.timeout();
        assert_eq!(state.phase(), Phase::TimedOut);
        assert_eq!(state.consecutive_timeouts(), 1);

        state.timeout();
        assert_eq!(state.consecutive_timeouts(), 2);

        state.timeout();
        assert_eq!(state.consecutive_timeouts(), 3);
    }

    #[test]
    fn test_advance_view() {
        let mut state = RoundState::new();

        state.timeout();
        state.advance_view(2);
        assert_eq!(state.current_view(), 2);
        assert_eq!(state.phase(), Phase::WaitingForProposal);

        state.advance_view(10);
        assert_eq!(state.current_view(), 10);
        assert_eq!(state.phase(), Phase::WaitingForProposal);
    }

    #[test]
    fn test_safety_rule() {
        let mut state = RoundState::new();

        assert!(state.is_safe_to_vote(&QuorumCertificate::genesis()));

        state.update_locked_qc(&make_qc(5));
        assert_eq!(state.locked_qc().view, 5);

        assert!(state.is_safe_to_vote(&make_qc(5)));
        assert!(state.is_safe_to_vote(&make_qc(7)));
        assert!(!state.is_safe_to_vote(&make_qc(3)));
    }

    #[test]
    fn test_commit_resets_consecutive_timeouts() {
        let mut state = RoundState::new();

        state.timeout();
        state.timeout();
        assert_eq!(state.consecutive_timeouts(), 2);

        state.advance_view(2);
        state.enter_voting();
        state.enter_pre_commit();
        state.commit(make_qc(2));
        assert_eq!(state.consecutive_timeouts(), 0);
    }

    #[test]
    fn test_commit_updates_locked_qc() {
        let mut state = RoundState::new();

        state.commit(make_qc(5));
        assert_eq!(state.locked_qc().view, 5);
        assert_eq!(state.last_committed_qc().view, 5);

        // Lower commit should not downgrade locked_qc or last_committed_qc
        state.commit(make_qc(3));
        assert_eq!(state.locked_qc().view, 5);
        assert_eq!(state.last_committed_qc().view, 5);

        // Higher commit should update both
        state.commit(make_qc(7));
        assert_eq!(state.locked_qc().view, 7);
        assert_eq!(state.last_committed_qc().view, 7);
    }

    #[test]
    fn test_reset_consecutive_timeouts() {
        let mut state = RoundState::new();

        state.timeout();
        state.timeout();
        state.timeout();
        assert_eq!(state.consecutive_timeouts(), 3);

        state.reset_consecutive_timeouts();
        assert_eq!(state.consecutive_timeouts(), 0);

        state.timeout();
        assert_eq!(state.consecutive_timeouts(), 1);
    }

    #[test]
    fn test_default() {
        let state = RoundState::default();
        assert_eq!(state.current_view(), 1);
        assert_eq!(state.phase(), Phase::WaitingForProposal);
    }

    #[test]
    fn test_update_locked_qc_no_downgrade() {
        let mut state = RoundState::new();

        state.update_locked_qc(&make_qc(10));
        assert_eq!(state.locked_qc().view, 10);

        // Lower view — no-op
        state.update_locked_qc(&make_qc(5));
        assert_eq!(state.locked_qc().view, 10);

        // Same view — no-op
        state.update_locked_qc(&make_qc(10));
        assert_eq!(state.locked_qc().view, 10);

        // Higher view — updates
        state.update_locked_qc(&make_qc(15));
        assert_eq!(state.locked_qc().view, 15);
    }

    #[test]
    fn test_advance_view_resets_phase() {
        let mut state = RoundState::new();

        state.enter_voting();
        state.timeout();
        assert_eq!(state.phase(), Phase::TimedOut);

        state.advance_view(2);
        assert_eq!(state.phase(), Phase::WaitingForProposal);
        assert_eq!(state.current_view(), 2);

        state.enter_voting();
        state.enter_pre_commit();
        state.advance_view(3);
        assert_eq!(state.phase(), Phase::WaitingForProposal);
    }
}
