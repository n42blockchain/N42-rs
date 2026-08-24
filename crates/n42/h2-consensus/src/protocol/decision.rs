use n42_h2_primitives::consensus::Decide;

use super::state_machine::{ConsensusEngine, EngineOutput};
use crate::error::{ConsensusError, ConsensusResult};

impl ConsensusEngine {
    /// Processes a Decide message from the leader.
    ///
    /// Verifies the CommitQC and advances the follower to the next view.
    /// If the Decide's view is more than 3 views ahead, emits `SyncRequired`
    /// so the orchestrator can initiate block sync.
    pub(super) fn process_decide(&mut self, decide: Decide) -> ConsensusResult<()> {
        let current_view = self.round_state.current_view();

        if decide.view < current_view {
            tracing::debug!(target: "n42::cl::decision", decide_view = decide.view, current_view, "ignoring stale Decide");
            return Ok(());
        }

        let commit_set = self.resolve_qc_validator_set(&decide.commit_qc)?;
        let quorum_size = commit_set.quorum_size();
        if decide.commit_qc.signer_count() < quorum_size {
            return Err(ConsensusError::InsufficientVotes {
                view: decide.view,
                have: decide.commit_qc.signer_count(),
                need: quorum_size,
            });
        }

        if decide.commit_qc.view != decide.view {
            return Err(ConsensusError::ViewMismatch {
                current: decide.view,
                received: decide.commit_qc.view,
            });
        }

        if decide.commit_qc.block_hash != decide.block_hash {
            return Err(ConsensusError::BlockHashMismatch {
                expected: decide.block_hash,
                got: decide.commit_qc.block_hash,
            });
        }

        // Verify CommitQC aggregate BLS signature. Without this, a Byzantine leader
        // could forge a Decide with a valid signer bitmap but invalid signature.
        // The `validator_changes_hash` is part of the signed message (Plan #2 in
        // the HotStuff-2 audit), so a Byzantine leader cannot substitute a
        // different changes_hash after collecting commit votes.
        super::quorum::verify_commit_qc_with_profile(
            &decide.commit_qc,
            commit_set,
            &decide.validator_changes_hash,
            self.signing_profile,
        )?;

        // Cache the committed block's changes hash so a late Proposal for the same
        // block can still recover validator_changes after this Decide advances the view.
        self.pending_changes_hashes
            .insert(decide.block_hash, decide.validator_changes_hash);

        const SYNC_GAP_THRESHOLD: u64 = 3;
        if decide.view > current_view + SYNC_GAP_THRESHOLD {
            tracing::warn!(target: "n42::cl::decision",
                current_view,
                decide_view = decide.view,
                gap = decide.view - current_view,
                "large view gap detected, requesting state sync"
            );
            self.emit(EngineOutput::SyncRequired {
                local_view: current_view,
                target_view: decide.view,
            })?;
        }

        tracing::info!(target: "n42::cl::decision", view = decide.view, %decide.block_hash, "received Decide, committing block");

        // Record the moment the follower learned the block is committed.
        // Without this, advance_to_view() skips saving view_timing (it requires
        // commit_qc_formed to be set), causing the orchestrator's consensus_timing
        // log to show stale data from this node's last leader view.
        self.view_timing.commit_qc_formed = Some(std::time::Instant::now());

        self.round_state.update_locked_qc(&decide.commit_qc);
        self.round_state.commit(decide.commit_qc.clone());

        // Commit-then-Activate: only commit/stage validator changes when the decided
        // block actually carried them (hash != ZERO).  Gating on the Decide hash
        // prevents a node that has locally-queued pending_adds (from an RPC call)
        // from prematurely staging when *another* leader commits a block with no
        // changes — which would cause epoch divergence with nodes that never had
        // those pending_adds.
        let committed_changes = if decide.validator_changes_hash != alloy_primitives::B256::ZERO {
            // Capture changes before commit clears them.
            let changes = self.epoch_manager.pending_changes_for_proposal();
            if self.epoch_manager.has_pending_changes() {
                self.epoch_manager.commit_pending_changes()?;
            } else {
                // The committed Proposal carried validator changes but this follower
                // missed it.  Log prominently so the operator notices; the node will
                // need to resync (or receive the changes in a subsequent Proposal
                // before the epoch boundary) to avoid validator-set divergence.
                tracing::error!(
                    target: "n42::cl::decision",
                    view = decide.view,
                    expected_hash = %decide.validator_changes_hash,
                    "MISSED validator changes from Proposal — epoch transition may diverge; \
                     requesting resync"
                );
                // Sync API requests the inclusive range (local_view + 1)..=target_view.
                // We need to re-fetch the committed block at `decide.view`, so report
                // the local committed view as the block immediately before it.
                self.emit(EngineOutput::SyncRequired {
                    local_view: decide.view.saturating_sub(1),
                    target_view: decide.view,
                })?;
            }
            changes
        } else {
            // No validator changes in this block.  If this node has local pending_adds
            // queued from an RPC call, keep them — they will be included in the next
            // Proposal when this node becomes leader.
            None
        };

        // Clean up pending tx_root_hash for the committed block.
        self.pending_tx_roots.remove(&decide.block_hash);

        self.emit(EngineOutput::BlockCommitted {
            view: decide.view,
            block_hash: decide.block_hash,
            commit_qc: decide.commit_qc,
            validator_changes: committed_changes,
        })?;

        let next_view = decide.view.saturating_add(1);
        self.advance_to_view(next_view)?;

        // Notify the orchestrator that the view has advanced so the next leader
        // can start building immediately instead of waiting for a pacemaker timeout.
        let actual_view = self.round_state.current_view();
        self.emit(EngineOutput::ViewChanged {
            new_view: actual_view,
        })
    }
}
