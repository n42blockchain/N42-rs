use super::set::ValidatorSet;
use crate::error::{ConsensusError, ConsensusResult};
use alloy_primitives::Address;
use crate::ValidatorInfo;
use n42_h2_primitives::consensus::ValidatorChange;
use std::collections::BTreeMap;

/// Default upper bound on retained historical epoch validator sets.
///
/// Needed for verifying QCs whose `view` belongs to a past epoch — this happens
/// during block sync, late Decide/NewView replays, or any code path that resolves
/// a QC by looking up the validator set for a historical view. With epoch_length
/// = 30 this covers ~32 minutes of history (~960 views), which is enough for
/// short partitions and rolling restarts. Beyond that the resolver falls back to
/// `current_set` and logs a warning; callers (e.g. `verify_qc`) will then surface
/// a verification error rather than silently accept the wrong set.
///
/// The actual bound is configurable per-EpochManager (see `max_historical_epochs`
/// field) so deployments with longer expected partitions can raise it.
pub const DEFAULT_MAX_HISTORICAL_EPOCHS: usize = 32;

/// Hard upper bound enforced by `ConsensusConfig::validate` and constructors.
/// Each historical set is `validators × ~144 bytes`; 256 epochs × 500 validators
/// ≈ 18 MB which is the most we want to keep around purely for replay support.
pub const MAX_HISTORICAL_EPOCHS_LIMIT: usize = 256;

/// Clamps a configured `max_historical_epochs` value into `[1, LIMIT]`. A
/// caller passing 0 likely means "default" but we treat it as "disable history",
/// so we promote to 1 to keep the resolver from immediately falling back; values
/// above LIMIT are silently capped to avoid OOM from a misconfigured chainspec.
fn clamp_max_historical(value: usize) -> usize {
    value.clamp(1, MAX_HISTORICAL_EPOCHS_LIMIT)
}

/// Minimum number of validators required for BFT safety (f ≥ 1).
pub const MIN_VALIDATOR_COUNT: usize = 4;

/// Manages validator set transitions across epochs.
///
/// When `epoch_length = 0`, epochs are disabled and the manager acts as
/// a simple wrapper around a single ValidatorSet (backward compatible).
///
/// When `epoch_length > 0`, every `epoch_length` views constitute one epoch.
/// The manager tracks the current, next (staged), and historical validator sets
/// to support cross-epoch QC verification.
///
/// Dynamic validator set changes follow the commit-then-activate protocol:
/// - `propose_add_validator` / `propose_remove_validator` queue changes in-memory.
/// - `commit_pending_changes` is called at CommitQC time; it validates safety
///   constraints and calls `stage_next_epoch` to schedule activation.
/// - `advance_epoch` activates the staged set at the next epoch boundary.
/// - `carry_epoch_forward` advances an empty boundary while retaining the
///   active set. Epoch numbers still follow view ranges even when membership
///   does not change.
#[derive(Debug, Clone)]
pub struct EpochManager {
    /// Number of views per epoch (0 = epochs disabled).
    epoch_length: u64,
    /// Current epoch number (starts at 0).
    current_epoch: u64,
    /// Active validator set for the current epoch.
    current_set: ValidatorSet,
    /// Staged validator set for the next epoch (if any).
    next_set: Option<ValidatorSet>,
    /// Raw validator info for the staged set (kept for persistence).
    staged_info: Option<(Vec<ValidatorInfo>, u32)>,
    /// Historical validator sets keyed by epoch number.
    /// Trimmed to at most `max_historical_epochs` entries on every advance.
    historical_sets: BTreeMap<u64, ValidatorSet>,
    /// Maximum number of past validator sets to keep (configurable per chain).
    max_historical_epochs: usize,
    /// Validators proposed for addition at the next CommitQC.
    pending_adds: Vec<ValidatorInfo>,
    /// Validator addresses proposed for removal at the next CommitQC.
    pending_removes: Vec<Address>,
}

impl EpochManager {
    /// Creates an EpochManager with epochs disabled (single static validator set).
    pub fn new(validator_set: ValidatorSet) -> Self {
        Self {
            epoch_length: 0,
            current_epoch: 0,
            current_set: validator_set,
            next_set: None,
            staged_info: None,
            historical_sets: BTreeMap::new(),
            max_historical_epochs: DEFAULT_MAX_HISTORICAL_EPOCHS,
            pending_adds: Vec::new(),
            pending_removes: Vec::new(),
        }
    }

    /// Creates an EpochManager with epoch transitions enabled, using the
    /// default historical bound. Tests / dev paths.
    pub fn with_epoch_length(validator_set: ValidatorSet, epoch_length: u64) -> Self {
        Self::with_epoch_length_and_history(
            validator_set,
            epoch_length,
            DEFAULT_MAX_HISTORICAL_EPOCHS,
        )
    }

    /// Like [`Self::with_epoch_length`] but with an explicit historical-set bound.
    /// `max_historical_epochs` is clamped to `[1, MAX_HISTORICAL_EPOCHS_LIMIT]`.
    pub fn with_epoch_length_and_history(
        validator_set: ValidatorSet,
        epoch_length: u64,
        max_historical_epochs: usize,
    ) -> Self {
        Self {
            epoch_length,
            current_epoch: 0,
            current_set: validator_set,
            next_set: None,
            staged_info: None,
            historical_sets: BTreeMap::new(),
            max_historical_epochs: clamp_max_historical(max_historical_epochs),
            pending_adds: Vec::new(),
            pending_removes: Vec::new(),
        }
    }

    /// Creates an EpochManager starting from a specific epoch.
    /// Used when a node starts from a snapshot at a non-genesis epoch.
    pub fn from_epoch(validator_set: ValidatorSet, epoch_length: u64, starting_epoch: u64) -> Self {
        Self::from_epoch_with_history(
            validator_set,
            epoch_length,
            starting_epoch,
            DEFAULT_MAX_HISTORICAL_EPOCHS,
        )
    }

    /// Like [`Self::from_epoch`] but with an explicit historical-set bound.
    pub fn from_epoch_with_history(
        validator_set: ValidatorSet,
        epoch_length: u64,
        starting_epoch: u64,
        max_historical_epochs: usize,
    ) -> Self {
        Self {
            epoch_length,
            current_epoch: starting_epoch,
            current_set: validator_set,
            next_set: None,
            staged_info: None,
            historical_sets: BTreeMap::new(),
            max_historical_epochs: clamp_max_historical(max_historical_epochs),
            pending_adds: Vec::new(),
            pending_removes: Vec::new(),
        }
    }

    /// Creates an EpochManager from a predefined schedule of validator sets.
    /// Each entry in the schedule is (epoch, validators, fault_tolerance).
    /// The last entry's validator set becomes the current set.
    ///
    /// Returns `Err(ConsensusError::EpochScheduleEmpty)` if the schedule is empty.
    pub fn from_schedule(
        epoch_length: u64,
        schedule: &[(u64, Vec<ValidatorInfo>, u32)],
    ) -> ConsensusResult<Self> {
        Self::from_schedule_with_history(epoch_length, schedule, DEFAULT_MAX_HISTORICAL_EPOCHS)
    }

    /// Like [`Self::from_schedule`] but with an explicit historical-set bound.
    pub fn from_schedule_with_history(
        epoch_length: u64,
        schedule: &[(u64, Vec<ValidatorInfo>, u32)],
        max_historical_epochs: usize,
    ) -> ConsensusResult<Self> {
        if schedule.is_empty() {
            return Err(ConsensusError::EpochScheduleEmpty);
        }

        let max_historical_epochs = clamp_max_historical(max_historical_epochs);
        let mut historical = BTreeMap::new();

        // Add all but the last entry to historical
        for (epoch, validators, f) in &schedule[..schedule.len() - 1] {
            let set = ValidatorSet::try_new(validators, *f)?;
            historical.insert(*epoch, set);
        }

        // Trim historical to the configured bound
        while historical.len() > max_historical_epochs {
            if let Some(oldest) = historical.keys().next().copied() {
                historical.remove(&oldest);
            }
        }

        // Use the last entry as current
        let (current_epoch, validators, f) = &schedule[schedule.len() - 1];
        let current_set = ValidatorSet::try_new(validators, *f)?;

        Ok(Self {
            epoch_length,
            current_epoch: *current_epoch,
            current_set,
            next_set: None,
            staged_info: None,
            historical_sets: historical,
            max_historical_epochs,
            pending_adds: Vec::new(),
            pending_removes: Vec::new(),
        })
    }

    /// Returns the configured upper bound on retained historical sets.
    pub fn max_historical_epochs(&self) -> usize {
        self.max_historical_epochs
    }

    /// Returns the epoch length (0 = disabled).
    pub fn epoch_length(&self) -> u64 {
        self.epoch_length
    }

    /// Returns the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Returns a reference to the current validator set.
    pub fn current_validator_set(&self) -> &ValidatorSet {
        &self.current_set
    }

    /// Returns whether epochs are enabled.
    pub fn epochs_enabled(&self) -> bool {
        self.epoch_length > 0
    }

    /// Computes which epoch a given view belongs to.
    /// Returns 0 when epochs are disabled.
    pub fn epoch_for_view(&self, view: u64) -> u64 {
        // Views start at 1, so view 1..=epoch_length → epoch 0,
        // view (epoch_length+1)..=(2*epoch_length) → epoch 1, etc.
        // `checked_div` returns None when epochs are disabled (epoch_length == 0),
        // matching the original "epochs disabled → epoch 0" semantics.
        view.saturating_sub(1)
            .checked_div(self.epoch_length)
            .unwrap_or(0)
    }

    /// Checks if a given view is the first view of a new epoch.
    pub fn is_epoch_boundary(&self, view: u64) -> bool {
        if self.epoch_length == 0 || view <= 1 {
            return false;
        }
        (view.saturating_sub(1)).is_multiple_of(self.epoch_length)
    }

    /// Returns the validator set that should be used for verifying a QC at the given view.
    /// Falls back to the current set if the historical set is unavailable.
    pub fn validator_set_for_view(&self, view: u64) -> &ValidatorSet {
        if self.epoch_length == 0 {
            return &self.current_set;
        }

        let epoch = self.epoch_for_view(view);

        if epoch == self.current_epoch {
            return &self.current_set;
        }

        // edition-2021: N42-26 writes this as a let-chain. A `None` next_set
        // still falls through to the historical lookup below, as before.
        if epoch == self.current_epoch + 1 {
            if let Some(next_set) = self.next_set.as_ref() {
                return next_set;
            }
        }

        // Look up historical set
        if let Some(set) = self.historical_sets.get(&epoch) {
            return set;
        }

        // Historical set unavailable (epoch too old, beyond max_historical_epochs).
        // Log a warning so operators can detect sync/verification issues.
        // Falling back to current_set is a best-effort measure; callers that need
        // strict correctness should treat this as an error.
        tracing::warn!(
            target: "n42::cl::epoch",
            view,
            epoch,
            current_epoch = self.current_epoch,
            max_historical = self.max_historical_epochs,
            "validator set for epoch not in history (too old); falling back to current set — \
             QC verification for this view may be incorrect"
        );
        &self.current_set
    }

    /// Returns the validator set for `view` only when it is known exactly.
    ///
    /// Unlike [`Self::validator_set_for_view`], this never falls back to the
    /// current set. Safety-critical recovery paths use it before aggregating
    /// signatures for a future view: accepting a quorum under a guessed set at
    /// an unstaged epoch boundary could manufacture an invalid certificate.
    pub fn known_validator_set_for_view(&self, view: u64) -> Option<&ValidatorSet> {
        if self.epoch_length == 0 {
            return Some(&self.current_set);
        }

        let epoch = self.epoch_for_view(view);
        if epoch == self.current_epoch {
            return Some(&self.current_set);
        }
        if epoch == self.current_epoch + 1 {
            return self.next_set.as_ref();
        }
        self.historical_sets.get(&epoch)
    }

    /// Stages a new validator set for the next epoch.
    /// The set will be activated when `advance_epoch()` is called.
    pub fn stage_next_epoch(
        &mut self,
        validators: &[ValidatorInfo],
        fault_tolerance: u32,
    ) -> ConsensusResult<()> {
        self.next_set = Some(ValidatorSet::try_new(validators, fault_tolerance)?);
        self.staged_info = Some((validators.to_vec(), fault_tolerance));
        Ok(())
    }

    /// Returns the staged epoch transition info for persistence.
    /// Returns `(next_epoch_number, validators, fault_tolerance)`.
    pub fn staged_epoch_info(&self) -> Option<(u64, &[ValidatorInfo], u32)> {
        self.staged_info
            .as_ref()
            .map(|(validators, f)| (self.current_epoch + 1, validators.as_slice(), *f))
    }

    /// Advances to the next epoch, activating the staged validator set.
    /// The current set moves to historical storage.
    /// Returns true if an epoch transition occurred, false if no staged set was available.
    pub fn advance_epoch(&mut self) -> bool {
        let Some(next_set) = self.next_set.take() else {
            return false;
        };

        self.staged_info = None;
        self.historical_sets
            .insert(self.current_epoch, self.current_set.clone());
        self.trim_historical();

        self.current_epoch += 1;
        self.current_set = next_set;

        tracing::info!(
            epoch = self.current_epoch,
            validators = self.current_set.len(),
            "epoch advanced to new validator set"
        );

        true
    }

    /// Advances one epoch boundary without changing validator membership.
    ///
    /// Epochs are view ranges, not merely validator-set version numbers. A
    /// boundary with no staged reconfiguration must therefore still advance
    /// `current_epoch`; otherwise live nodes stay at epoch 0 forever while a
    /// restarted node reconstructs epoch N from its view. That disagreement is
    /// normally hidden by the legacy validator-set fallback, but prevents the
    /// strict future-timeout recovery path from forming a TC.
    ///
    /// Returns false when a staged set exists: callers must activate that set
    /// with [`Self::advance_epoch`] instead of silently carrying the old set.
    pub fn carry_epoch_forward(&mut self) -> bool {
        if self.next_set.is_some() || self.epoch_length == 0 {
            return false;
        }

        self.historical_sets
            .insert(self.current_epoch, self.current_set.clone());
        self.trim_historical();
        self.current_epoch += 1;

        tracing::info!(
            target: "n42::cl::epoch",
            epoch = self.current_epoch,
            validators = self.current_set.len(),
            "epoch advanced with unchanged validator set"
        );
        true
    }

    /// Returns the number of historical epoch sets stored.
    pub fn historical_epoch_count(&self) -> usize {
        self.historical_sets.len()
    }

    /// Returns whether a next epoch validator set has been staged.
    pub fn has_staged_next(&self) -> bool {
        self.next_set.is_some()
    }

    /// Trims historical sets to maintain the configured max_historical_epochs limit.
    fn trim_historical(&mut self) {
        while self.historical_sets.len() > self.max_historical_epochs {
            if let Some(oldest) = self.historical_sets.keys().next().copied() {
                self.historical_sets.remove(&oldest);
            }
        }
    }

    // ── Commit-then-Activate: dynamic validator set changes ──────────────

    /// Checks that proposals are allowed: epochs must be enabled and
    /// no epoch transition may be staged yet.
    fn check_proposals_allowed(&self) -> ConsensusResult<()> {
        if self.epoch_length == 0 {
            return Err(ConsensusError::EpochsDisabled);
        }
        if self.has_staged_next() {
            return Err(ConsensusError::EpochTransitionAlreadyStaged);
        }
        Ok(())
    }

    /// Proposes adding a new validator at the next CommitQC.
    ///
    /// Fails if:
    /// - A validator set transition is already staged (wait for epoch boundary first).
    /// - The address already exists in the current set or pending additions.
    pub fn propose_add_validator(&mut self, info: ValidatorInfo) -> ConsensusResult<()> {
        self.check_proposals_allowed()?;

        let addr = info.address;

        // Check not in current set (O(n) scan over ValidatorEntry, no Vec alloc)
        if self.current_set.contains_address(&addr) {
            return Err(ConsensusError::ValidatorAlreadyExists { address: addr });
        }

        // Check not already pending add
        if self.pending_adds.iter().any(|v| v.address == addr) {
            return Err(ConsensusError::ValidatorAlreadyExists { address: addr });
        }

        self.pending_adds.push(info);
        tracing::info!(
            target: "n42::cl::epoch",
            %addr,
            "validator queued for addition at next CommitQC"
        );
        Ok(())
    }

    /// Proposes removing a validator at the next CommitQC.
    ///
    /// Fails if:
    /// - A validator set transition is already staged (wait for epoch boundary first).
    /// - The address is not in the current set.
    /// - The address is already pending removal.
    /// - The resulting count would drop below MIN_VALIDATOR_COUNT.
    pub fn propose_remove_validator(&mut self, addr: Address) -> ConsensusResult<()> {
        self.check_proposals_allowed()?;

        // Must exist in current set (O(n) scan, no Vec alloc)
        if !self.current_set.contains_address(&addr) {
            return Err(ConsensusError::ValidatorNotFound { address: addr });
        }

        // Already pending removal?
        if self.pending_removes.contains(&addr) {
            return Err(ConsensusError::ValidatorAlreadyPendingRemoval { address: addr });
        }

        // Check resulting size ≥ MIN_VALIDATOR_COUNT.
        // Uses saturating arithmetic to avoid usize underflow on pathological input.
        let future_count = (self.current_set.len() as usize)
            .saturating_add(self.pending_adds.len())
            .saturating_sub(self.pending_removes.len())
            .saturating_sub(1); // this removal
        if future_count < MIN_VALIDATOR_COUNT {
            return Err(ConsensusError::InsufficientValidators {
                have: future_count,
                need: MIN_VALIDATOR_COUNT,
            });
        }

        self.pending_removes.push(addr);
        tracing::info!(
            target: "n42::cl::epoch",
            %addr,
            "validator queued for removal at next CommitQC"
        );
        Ok(())
    }

    /// Returns whether there are any pending validator changes.
    pub fn has_pending_changes(&self) -> bool {
        !self.pending_adds.is_empty() || !self.pending_removes.is_empty()
    }

    /// Returns the total number of pending add + remove changes (zero-alloc).
    pub fn pending_change_count(&self) -> usize {
        self.pending_adds.len() + self.pending_removes.len()
    }

    /// Validates and commits pending changes by staging the new validator set.
    ///
    /// Called at CommitQC time by the protocol layer (voting.rs / decision.rs).
    /// Validates safety constraints (minimum count, quorum overlap), then calls
    /// `stage_next_epoch`. Clears the pending queues on success.
    ///
    /// # Idempotency
    /// No-op when called with an empty pending queue.
    pub(crate) fn commit_pending_changes(&mut self) -> ConsensusResult<()> {
        if !self.has_pending_changes() {
            return Ok(());
        }

        let current_infos = self.current_set.validator_infos();
        let remove_set: std::collections::HashSet<Address> =
            self.pending_removes.iter().copied().collect();

        // Build new validator list: current - removes + adds, sorted by address.
        let mut new_validators: Vec<ValidatorInfo> = current_infos
            .into_iter()
            .filter(|v| !remove_set.contains(&v.address))
            .chain(self.pending_adds.iter().cloned())
            .collect();
        new_validators.sort_by_key(|v| v.address);
        // Reject duplicate addresses (could happen with crafted Add+Remove of same addr).
        new_validators.dedup_by_key(|v| v.address);

        // Capture counts before staging so the log is accurate even if stage fails.
        let adds_count = self.pending_adds.len();
        let removes_count = self.pending_removes.len();

        // Validate transition safety.
        self.validate_transition(&new_validators)?;

        // Derive new f = (n - 1) / 3, reusing the shared formula from ValidatorSet.
        let new_f = ValidatorSet::max_fault_tolerance_for_len(new_validators.len());

        self.stage_next_epoch(&new_validators, new_f)?;

        tracing::info!(
            target: "n42::cl::epoch",
            adds = adds_count,
            removes = removes_count,
            new_count = new_validators.len(),
            new_f,
            "pending validator changes committed; staged for next epoch boundary"
        );

        self.pending_adds.clear();
        self.pending_removes.clear();

        Ok(())
    }

    /// Returns the Blake3 hash of pending changes, or `B256::ZERO` if none.
    /// Used by the leader to populate `Decide.validator_changes_hash`.
    pub fn pending_changes_hash(&self) -> alloy_primitives::B256 {
        match self.pending_changes_for_proposal() {
            Some(ref changes) if !changes.is_empty() => Self::hash_changes(changes),
            _ => alloy_primitives::B256::ZERO,
        }
    }

    /// Computes the Blake3 hash of an already-captured change list.
    /// Use this instead of `pending_changes_hash()` when you already hold the Vec
    /// to avoid a redundant allocation.
    pub fn hash_changes(changes: &[ValidatorChange]) -> alloy_primitives::B256 {
        if changes.is_empty() {
            return alloy_primitives::B256::ZERO;
        }
        let encoded =
            bincode::serialize(changes).expect("ValidatorChange serialization cannot fail");
        alloy_primitives::B256::from(*blake3::hash(&encoded).as_bytes())
    }

    /// Returns pending validator changes for inclusion in a [`Proposal`] message.
    ///
    /// Returns `None` if there are no pending changes.  Does **not** drain the
    /// pending queues — the leader keeps them so that `commit_pending_changes()`
    /// still finds them at CommitQC time.
    pub fn pending_changes_for_proposal(&self) -> Option<Vec<ValidatorChange>> {
        if !self.has_pending_changes() {
            return None;
        }
        let mut changes = Vec::with_capacity(self.pending_adds.len() + self.pending_removes.len());
        for info in &self.pending_adds {
            changes.push(ValidatorChange::Add {
                address: info.address,
                bls_public_key: info.bls_public_key.clone(),
                p2p_peer_id: info.p2p_peer_id.clone(),
            });
        }
        for &addr in &self.pending_removes {
            changes.push(ValidatorChange::Remove { address: addr });
        }
        Some(changes)
    }

    /// Replaces local pending queues with the leader's proposed changes.
    ///
    /// Called by followers in `process_proposal()` so that every validator
    /// applies the **same** changes at CommitQC time, preventing split-brain.
    pub fn replace_pending_from_proposal(&mut self, changes: &[ValidatorChange]) {
        self.pending_adds.clear();
        self.pending_removes.clear();
        for change in changes {
            match change {
                ValidatorChange::Add {
                    address,
                    bls_public_key,
                    p2p_peer_id,
                } => {
                    self.pending_adds.push(ValidatorInfo {
                        address: *address,
                        bls_public_key: bls_public_key.clone(),
                        p2p_peer_id: p2p_peer_id.clone(),
                    });
                }
                ValidatorChange::Remove { address } => {
                    self.pending_removes.push(*address);
                }
            }
        }
    }

    /// Applies validator changes recovered from a committed/synced block.
    ///
    /// This is narrower than exposing `commit_pending_changes()` publicly:
    /// callers can only provide the already-committed change set, which we
    /// stage for the next epoch boundary using the same validation path as the
    /// normal Proposal -> CommitQC flow.
    pub fn apply_committed_changes_from_sync(
        &mut self,
        changes: &[ValidatorChange],
    ) -> ConsensusResult<()> {
        self.replace_pending_from_proposal(changes);
        self.commit_pending_changes()
    }

    /// Clears all pending validator changes without committing them.
    ///
    /// Called when a follower receives a proposal with no `validator_changes`
    /// — any locally queued changes must be discarded to stay consistent
    /// with the leader (which chose not to include changes).
    pub fn clear_pending_changes(&mut self) {
        if self.has_pending_changes() {
            let adds = self.pending_adds.len();
            let removes = self.pending_removes.len();
            self.pending_adds.clear();
            self.pending_removes.clear();
            tracing::warn!(
                target: "n42::cl::epoch",
                adds,
                removes,
                "discarded local pending validator changes (leader proposal had none)"
            );
        }
    }

    /// Returns a reference to the staged next validator set, if any.
    ///
    /// Used to pre-check whether the local validator key will be present
    /// in the next set *before* calling `advance_epoch()`, preventing the
    /// irrecoverable state where the epoch advances but `sync_local_validator_index`
    /// fails.
    pub fn peek_next_set(&self) -> Option<&ValidatorSet> {
        self.next_set.as_ref()
    }

    /// Validates that a proposed new validator set satisfies safety invariants:
    /// - At least MIN_VALIDATOR_COUNT validators.
    /// - The intersection of current and new address sets is ≥ current quorum_size (n-f),
    ///   ensuring the Jolteon §4.3 quorum-overlap liveness property.
    ///
    /// Accepts the pre-built `new_validators` slice to avoid a redundant
    /// `validator_infos()` allocation (the caller already holds current_infos).
    fn validate_transition(&self, new_validators: &[ValidatorInfo]) -> ConsensusResult<()> {
        // Minimum size check.
        if new_validators.len() < MIN_VALIDATOR_COUNT {
            return Err(ConsensusError::InsufficientValidators {
                have: new_validators.len(),
                need: MIN_VALIDATOR_COUNT,
            });
        }

        // Quorum overlap check (Jolteon §4.3 liveness).
        // Build a HashSet of new addresses, then check each current validator via
        // `contains_address` — avoids the Vec<ValidatorInfo> allocation from `validator_infos()`.
        let new_addrs: std::collections::HashSet<Address> =
            new_validators.iter().map(|v| v.address).collect();
        let mut overlap = 0usize;
        for i in 0..self.current_set.len() {
            // edition-2021: N42-26 writes this as a let-chain.
            if let Ok(addr) = self.current_set.get_address(i) {
                if new_addrs.contains(addr) {
                    overlap += 1;
                }
            }
        }
        let required = self.current_set.quorum_size(); // n-f of the active set
        if overlap < required {
            return Err(ConsensusError::InsufficientQuorumOverlap {
                have: overlap,
                need: required,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use n42_h2_primitives::BlsSecretKey;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
    }

    fn make_validator_infos(count: usize) -> Vec<ValidatorInfo> {
        (0..count)
            .map(|i| {
                let sk = test_key(0x50 + i as u8);
                ValidatorInfo {
                    address: Address::with_last_byte(i as u8),
                    bls_public_key: sk.public_key(),
                    p2p_peer_id: None,
                }
            })
            .collect()
    }

    #[test]
    fn test_epochs_disabled() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let em = EpochManager::new(vs.clone());

        assert!(!em.epochs_enabled());
        assert_eq!(em.epoch_length(), 0);
        assert_eq!(em.current_epoch(), 0);
        assert_eq!(em.epoch_for_view(1), 0);
        assert_eq!(em.epoch_for_view(100), 0);
        assert!(!em.is_epoch_boundary(1));
        assert!(!em.is_epoch_boundary(100));
        assert_eq!(em.current_validator_set().len(), 4);
    }

    #[test]
    fn test_epoch_for_view() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let em = EpochManager::with_epoch_length(vs, 10);

        assert!(em.epochs_enabled());
        assert_eq!(em.epoch_for_view(1), 0); // views 1-10 → epoch 0
        assert_eq!(em.epoch_for_view(10), 0);
        assert_eq!(em.epoch_for_view(11), 1); // views 11-20 → epoch 1
        assert_eq!(em.epoch_for_view(20), 1);
        assert_eq!(em.epoch_for_view(21), 2); // views 21-30 → epoch 2
    }

    #[test]
    fn test_is_epoch_boundary() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let em = EpochManager::with_epoch_length(vs, 10);

        assert!(!em.is_epoch_boundary(1)); // first view, not a boundary
        assert!(!em.is_epoch_boundary(10)); // last view of epoch 0
        assert!(em.is_epoch_boundary(11)); // first view of epoch 1
        assert!(!em.is_epoch_boundary(12));
        assert!(em.is_epoch_boundary(21)); // first view of epoch 2
    }

    #[test]
    fn test_advance_epoch() {
        let infos1 = make_validator_infos(4);
        let infos2 = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos1, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        assert_eq!(em.current_epoch(), 0);
        assert_eq!(em.current_validator_set().len(), 4);

        // Stage next epoch
        em.stage_next_epoch(&infos2, 1).unwrap();
        assert!(em.has_staged_next());

        // Advance
        assert!(em.advance_epoch());
        assert_eq!(em.current_epoch(), 1);
        assert_eq!(em.current_validator_set().len(), 5);
        assert!(!em.has_staged_next());
        assert_eq!(em.historical_epoch_count(), 1);
    }

    #[test]
    fn test_advance_epoch_no_staged() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // No staged set → advance fails
        assert!(!em.advance_epoch());
        assert_eq!(em.current_epoch(), 0);
    }

    #[test]
    fn test_carry_epoch_forward_retains_set_and_records_history() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        assert!(em.carry_epoch_forward());
        assert_eq!(em.current_epoch(), 1);
        assert_eq!(em.current_validator_set().len(), infos.len() as u32);
        for (index, info) in infos.iter().enumerate() {
            assert_eq!(
                em.current_validator_set()
                    .get_public_key(index as u32)
                    .unwrap(),
                &info.bls_public_key
            );
        }
        assert_eq!(em.historical_epoch_count(), 1);
        assert_eq!(em.known_validator_set_for_view(5).unwrap().len(), 4);
        assert_eq!(em.known_validator_set_for_view(15).unwrap().len(), 4);
    }

    #[test]
    fn test_carry_epoch_forward_refuses_to_skip_staged_change() {
        let infos = make_validator_infos(4);
        let next_infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);
        em.stage_next_epoch(&next_infos, 1).unwrap();

        assert!(!em.carry_epoch_forward());
        assert_eq!(em.current_epoch(), 0);
        assert!(em.has_staged_next());
    }

    #[test]
    fn test_validator_set_for_view() {
        let infos1 = make_validator_infos(4);
        let infos2 = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos1, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        em.stage_next_epoch(&infos2, 1).unwrap();
        em.advance_epoch();

        // Current epoch (1) should use new set
        assert_eq!(em.validator_set_for_view(11).len(), 5);

        // Historical epoch (0) should use old set
        assert_eq!(em.validator_set_for_view(5).len(), 4);
    }

    #[test]
    fn test_historical_qc_uses_historical_n_minus_f_quorum() {
        use crate::protocol::quorum::{VoteCollector, signing_message, verify_qc};

        let old_infos = make_validator_infos(5);
        let new_infos = old_infos[..4].to_vec();
        let old_set = ValidatorSet::new(&old_infos, 1);
        let mut em = EpochManager::with_epoch_length(old_set, 10);
        em.stage_next_epoch(&new_infos, 1).unwrap();
        assert!(em.advance_epoch());

        let historical_set = em.validator_set_for_view(5);
        assert_eq!(historical_set.len(), 5);
        assert_eq!(historical_set.quorum_size(), 4);
        assert_eq!(em.validator_set_for_view(11).quorum_size(), 3);

        let block_hash = alloy_primitives::B256::repeat_byte(0xE5);
        let msg = signing_message(5, &block_hash);
        let mut collector = VoteCollector::new(5, block_hash, historical_set.len());
        for i in 0..4u32 {
            collector
                .add_vote(i, test_key(0x50 + i as u8).sign(&msg))
                .unwrap();
        }

        let qc = collector.build_qc(historical_set).unwrap();
        verify_qc(&qc, em.validator_set_for_view(qc.view)).unwrap();
    }

    #[test]
    fn test_validator_set_for_view_uses_staged_next_epoch_before_advance() {
        let infos1 = make_validator_infos(4);
        let infos2 = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos1, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        em.stage_next_epoch(&infos2, 1).unwrap();

        // View 11 is the first view of epoch 1; it should resolve to the staged set
        // even before advance_epoch() is called.
        assert_eq!(em.validator_set_for_view(11).len(), 5);
        assert_eq!(em.validator_set_for_view(5).len(), 4);
    }

    #[test]
    fn test_historical_limit() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // Advance through 5 epochs
        for i in 0..5 {
            let new_infos = make_validator_infos(4 + i);
            em.stage_next_epoch(&new_infos, 1).unwrap();
            em.advance_epoch();
        }

        // Should only keep at most the configured max_historical_epochs entries.
        assert!(em.historical_epoch_count() <= em.max_historical_epochs());
        assert_eq!(em.current_epoch(), 5);
    }

    /// Verifies the configurable historical bound: a manager with max=2 must
    /// drop the oldest entries after enough advances.
    #[test]
    fn test_configurable_historical_limit() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length_and_history(vs, 10, 2);
        assert_eq!(em.max_historical_epochs(), 2);

        for i in 0..5 {
            let new_infos = make_validator_infos(4 + i);
            em.stage_next_epoch(&new_infos, 1).unwrap();
            em.advance_epoch();
        }

        // 5 advances → 5 historical entries → trimmed down to 2.
        assert_eq!(em.historical_epoch_count(), 2);
        assert_eq!(em.current_epoch(), 5);
    }

    /// 0 must clamp to 1, oversize must clamp to MAX_HISTORICAL_EPOCHS_LIMIT.
    #[test]
    fn test_max_historical_clamping() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        assert_eq!(
            EpochManager::with_epoch_length_and_history(vs.clone(), 10, 0).max_historical_epochs(),
            1
        );
        assert_eq!(
            EpochManager::with_epoch_length_and_history(vs, 10, 10_000).max_historical_epochs(),
            MAX_HISTORICAL_EPOCHS_LIMIT
        );
    }

    #[test]
    fn test_from_epoch() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let em = EpochManager::from_epoch(vs, 10, 5);

        assert_eq!(em.current_epoch(), 5);
        assert_eq!(em.epoch_length(), 10);
        assert_eq!(em.current_validator_set().len(), 4);
    }

    #[test]
    fn test_from_schedule() {
        let infos1 = make_validator_infos(4);
        let infos2 = make_validator_infos(5);
        let infos3 = make_validator_infos(6);

        let schedule = vec![
            (0, infos1.clone(), 1),
            (1, infos2.clone(), 1),
            (2, infos3.clone(), 1),
        ];

        let em = EpochManager::from_schedule(10, &schedule).unwrap();

        assert_eq!(em.current_epoch(), 2);
        assert_eq!(em.current_validator_set().len(), 6);
        // epochs 0 and 1 should be in history
        assert_eq!(em.historical_epoch_count(), 2);
        assert_eq!(em.validator_set_for_view(5).len(), 4); // epoch 0
        assert_eq!(em.validator_set_for_view(15).len(), 5); // epoch 1
        assert_eq!(em.validator_set_for_view(25).len(), 6); // epoch 2 (current)
    }

    // ── Commit-then-Activate tests ───────────────────────────────────────

    #[test]
    fn test_propose_add_validator_success() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // Address 0x10 is not in the set (make_validator_infos uses 0x00..0x03)
        let sk = test_key(0x20);
        let new_validator = ValidatorInfo {
            address: Address::with_last_byte(0x10),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };

        assert!(!em.has_pending_changes());
        em.propose_add_validator(new_validator).unwrap();
        assert!(em.has_pending_changes());
        assert_eq!(em.pending_adds.len(), 1);
    }

    #[test]
    fn test_propose_remove_validator_success() {
        let infos = make_validator_infos(5); // 5 validators so removal stays ≥ 4
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        em.propose_remove_validator(Address::with_last_byte(0))
            .unwrap();
        assert!(em.has_pending_changes());
        assert_eq!(em.pending_removes.len(), 1);
    }

    #[test]
    fn test_reject_below_minimum_validators() {
        let infos = make_validator_infos(4); // exactly 4 = minimum
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        let err = em
            .propose_remove_validator(Address::with_last_byte(0))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::InsufficientValidators { have: 3, need: 4 }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_reject_duplicate_add() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // Address 0x00 already exists in current set
        let sk = test_key(0x50);
        let dup = ValidatorInfo {
            address: Address::with_last_byte(0),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };
        let err = em.propose_add_validator(dup).unwrap_err();
        assert!(
            matches!(err, ConsensusError::ValidatorAlreadyExists { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_simultaneous_add_and_remove() {
        // Start with 5 validators (0x00..0x04), remove 0x00, add 0x10
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        let sk = test_key(0x30);
        let new_v = ValidatorInfo {
            address: Address::with_last_byte(0x10),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };
        em.propose_add_validator(new_v).unwrap();
        em.propose_remove_validator(Address::with_last_byte(0))
            .unwrap();

        em.commit_pending_changes().unwrap();

        assert!(!em.has_pending_changes());
        assert!(em.has_staged_next());

        // Advance epoch and verify new set
        em.advance_epoch();
        let new_infos = em.current_validator_set().validator_infos();
        assert_eq!(new_infos.len(), 5); // 5 - 1 + 1 = 5
        // 0x00 should be gone, 0x10 should be present
        assert!(
            !new_infos
                .iter()
                .any(|v| v.address == Address::with_last_byte(0))
        );
        assert!(
            new_infos
                .iter()
                .any(|v| v.address == Address::with_last_byte(0x10))
        );
    }

    #[test]
    fn test_validate_transition_quorum_overlap() {
        // 5 validators (f=1, quorum=n-f=4). This specifically guards against
        // the old 2f+1 threshold, which would have accepted only 3 overlaps.
        let infos = make_validator_infos(5); // addresses 0x00..0x04
        let vs = ValidatorSet::new(&infos, 1);
        let em = EpochManager::with_epoch_length(vs, 10);

        // New set: keep 0x00..0x02 (overlap=3 < 4) — should fail.
        let sk0 = test_key(0x60);
        let sk1 = test_key(0x61);
        let completely_new: Vec<ValidatorInfo> = vec![
            ValidatorInfo {
                address: Address::with_last_byte(0),
                bls_public_key: infos[0].bls_public_key.clone(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(1),
                bls_public_key: infos[1].bls_public_key.clone(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(2),
                bls_public_key: infos[2].bls_public_key.clone(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(0x20),
                bls_public_key: sk0.public_key(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(0x21),
                bls_public_key: sk1.public_key(),
                p2p_peer_id: None,
            },
        ];
        let err = em.validate_transition(&completely_new).unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::InsufficientQuorumOverlap { have: 3, need: 4 }
            ),
            "unexpected error: {err}"
        );

        // New set: keep 0x00..0x03 (overlap=4 == 4) — should succeed.
        let sk3 = test_key(0x63);
        let valid_new: Vec<ValidatorInfo> = vec![
            ValidatorInfo {
                address: Address::with_last_byte(0),
                bls_public_key: infos[0].bls_public_key.clone(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(1),
                bls_public_key: infos[1].bls_public_key.clone(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(2),
                bls_public_key: infos[2].bls_public_key.clone(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(3),
                bls_public_key: infos[3].bls_public_key.clone(),
                p2p_peer_id: None,
            },
            ValidatorInfo {
                address: Address::with_last_byte(0x30),
                bls_public_key: sk3.public_key(),
                p2p_peer_id: None,
            },
        ];
        em.validate_transition(&valid_new).unwrap();
    }

    #[test]
    fn test_deterministic_ordering() {
        // 5 validators; add one with address < existing addresses to verify sorting
        let infos = make_validator_infos(5); // 0x00..0x04
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // We'll add a validator with a high address and check it ends up at the end
        let sk = test_key(0x70);
        let high_addr_v = ValidatorInfo {
            address: Address::with_last_byte(0xFF),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };
        em.propose_add_validator(high_addr_v).unwrap();
        em.commit_pending_changes().unwrap();
        em.advance_epoch();

        let new_infos = em.current_validator_set().validator_infos();
        // Verify ascending address order
        for w in new_infos.windows(2) {
            assert!(
                w[0].address <= w[1].address,
                "validators not sorted by address"
            );
        }
        // Last element should be 0xFF
        assert_eq!(
            new_infos.last().unwrap().address,
            Address::with_last_byte(0xFF)
        );
    }

    #[test]
    fn test_full_epoch_flow() {
        // 5 validators, epoch_length=10. Propose add, commit, advance at boundary.
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        assert_eq!(em.current_validator_set().len(), 5);
        assert!(!em.has_pending_changes());

        // Stage a new validator
        let sk = test_key(0x80);
        let new_v = ValidatorInfo {
            address: Address::with_last_byte(0x50),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };
        em.propose_add_validator(new_v).unwrap();
        assert!(em.has_pending_changes());

        // Simulate CommitQC: commit_pending_changes stages the new set
        em.commit_pending_changes().unwrap();
        assert!(!em.has_pending_changes());
        assert!(em.has_staged_next());
        // Current set unchanged yet
        assert_eq!(em.current_validator_set().len(), 5);

        // Simulate epoch boundary: advance_epoch activates the staged set
        assert!(em.advance_epoch());
        assert_eq!(em.current_epoch(), 1);
        assert_eq!(em.current_validator_set().len(), 6);
        assert!(!em.has_staged_next());
    }

    #[test]
    fn test_propose_remove_nonexistent() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // Address 0xAB is not in the set
        let err = em
            .propose_remove_validator(Address::with_last_byte(0xAB))
            .unwrap_err();
        assert!(
            matches!(err, ConsensusError::ValidatorNotFound { .. }),
            "unexpected error: {err}"
        );
        assert!(!em.has_pending_changes());
    }

    #[test]
    fn test_reject_duplicate_removal() {
        // 5 validators so first removal is allowed; second removal of same address must fail.
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        em.propose_remove_validator(Address::with_last_byte(0))
            .unwrap();
        assert_eq!(em.pending_removes.len(), 1);

        let err = em
            .propose_remove_validator(Address::with_last_byte(0))
            .unwrap_err();
        assert!(
            matches!(err, ConsensusError::ValidatorAlreadyPendingRemoval { .. }),
            "unexpected error: {err}"
        );
        // Queue length must stay at 1
        assert_eq!(em.pending_removes.len(), 1);
    }

    #[test]
    fn test_reject_proposal_when_already_staged() {
        // After commit_pending_changes stages a new set, further proposals must be blocked
        // until the staged set is activated at the next epoch boundary.
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // Stage a transition via the dynamic path
        let sk = test_key(0x90);
        let new_v = ValidatorInfo {
            address: Address::with_last_byte(0x40),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };
        em.propose_add_validator(new_v).unwrap();
        em.commit_pending_changes().unwrap();
        assert!(em.has_staged_next());

        // Attempting to propose another add must fail
        let sk2 = test_key(0x91);
        let new_v2 = ValidatorInfo {
            address: Address::with_last_byte(0x41),
            bls_public_key: sk2.public_key(),
            p2p_peer_id: None,
        };
        let err_add = em.propose_add_validator(new_v2).unwrap_err();
        assert!(
            matches!(err_add, ConsensusError::EpochTransitionAlreadyStaged),
            "unexpected error: {err_add}"
        );

        // Attempting to propose a remove must also fail
        let err_rm = em
            .propose_remove_validator(Address::with_last_byte(0))
            .unwrap_err();
        assert!(
            matches!(err_rm, ConsensusError::EpochTransitionAlreadyStaged),
            "unexpected error: {err_rm}"
        );

        // After epoch advance, proposals are allowed again
        em.advance_epoch();
        assert!(!em.has_staged_next());

        let sk3 = test_key(0x92);
        let new_v3 = ValidatorInfo {
            address: Address::with_last_byte(0x42),
            bls_public_key: sk3.public_key(),
            p2p_peer_id: None,
        };
        em.propose_add_validator(new_v3).unwrap();
        assert!(em.has_pending_changes());
    }

    #[test]
    fn test_commit_pending_changes_noop() {
        // commit_pending_changes with no pending changes is a safe no-op.
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        assert!(!em.has_pending_changes());
        em.commit_pending_changes().unwrap(); // must not panic or error
        assert!(!em.has_staged_next());
        assert_eq!(em.current_validator_set().len(), 4);
    }

    #[test]
    fn test_apply_committed_changes_from_sync_stages_next_epoch() {
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos, 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        let sk = test_key(0x93);
        let changes = vec![ValidatorChange::Add {
            address: Address::with_last_byte(0x40),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        }];

        em.apply_committed_changes_from_sync(&changes).unwrap();

        assert!(em.has_staged_next());
        assert!(!em.has_pending_changes());
        assert_eq!(em.validator_set_for_view(11).len(), 6);
        assert!(
            em.validator_set_for_view(11)
                .validator_infos()
                .iter()
                .any(|v| v.address == Address::with_last_byte(0x40))
        );
    }

    #[test]
    fn test_7_to_4_validator_reduction_chain() {
        // Verify the safety table from the design doc:
        // 7→6 ok, 6→5 ok, 5→4 ok (minimum), attempt 4→3 rejected.
        let infos = make_validator_infos(7);
        let vs = ValidatorSet::new(&infos, 2); // f=2, quorum=5

        // Each reduction is a separate epoch to ensure quorum overlap is satisfied.
        // overlap required = current quorum_size = n-f
        // After 7→6: f=1, quorum=5; after 6→5: f=1, quorum=4; after 5→4: f=1, quorum=3.

        // ── Epoch 0: 7 validators → remove one → stage 6 ──
        let mut em = EpochManager::with_epoch_length(vs, 10);
        assert_eq!(em.current_validator_set().len(), 7);

        em.propose_remove_validator(Address::with_last_byte(6))
            .unwrap();
        em.commit_pending_changes().unwrap();
        em.advance_epoch(); // epoch 1: 6 validators

        assert_eq!(em.current_validator_set().len(), 6);
        assert_eq!(em.current_validator_set().fault_tolerance(), 1);

        // ── Epoch 1 → 2: 6 → 5 ──
        em.propose_remove_validator(Address::with_last_byte(5))
            .unwrap();
        em.commit_pending_changes().unwrap();
        em.advance_epoch(); // epoch 2: 5 validators

        assert_eq!(em.current_validator_set().len(), 5);

        // ── Epoch 2 → 3: 5 → 4 (minimum) ──
        em.propose_remove_validator(Address::with_last_byte(4))
            .unwrap();
        em.commit_pending_changes().unwrap();
        em.advance_epoch(); // epoch 3: 4 validators

        assert_eq!(em.current_validator_set().len(), 4);
        assert_eq!(em.current_validator_set().fault_tolerance(), 1); // f=(4-1)/3=1

        // ── Attempt 4 → 3: must be rejected ──
        let err = em
            .propose_remove_validator(Address::with_last_byte(3))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::InsufficientValidators { have: 3, need: 4 }
            ),
            "unexpected error: {err}"
        );
        // Set is still intact at 4 validators
        assert_eq!(em.current_validator_set().len(), 4);
        assert!(!em.has_pending_changes());
    }

    // ── New method tests ──────────────────────────────────────────

    #[test]
    fn test_pending_changes_for_proposal_empty() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let em = EpochManager::with_epoch_length(vs, 10);
        assert!(em.pending_changes_for_proposal().is_none());
    }

    #[test]
    fn test_pending_changes_for_proposal_roundtrip() {
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos[..4], 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);
        em.propose_add_validator(infos[4].clone()).unwrap();
        em.propose_remove_validator(infos[0].address).unwrap();

        let changes = em.pending_changes_for_proposal().unwrap();
        assert_eq!(changes.len(), 2);

        // Simulate follower receiving the changes
        let vs2 = ValidatorSet::new(&infos[..4], 1);
        let mut em2 = EpochManager::with_epoch_length(vs2, 10);
        em2.replace_pending_from_proposal(&changes);
        assert!(em2.has_pending_changes());

        // Both should produce the same staged set
        em.commit_pending_changes().unwrap();
        em2.commit_pending_changes().unwrap();
        assert_eq!(
            em.peek_next_set().unwrap().len(),
            em2.peek_next_set().unwrap().len()
        );
    }

    #[test]
    fn test_clear_pending_changes() {
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos[..4], 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);
        em.propose_add_validator(infos[4].clone()).unwrap();
        assert!(em.has_pending_changes());

        em.clear_pending_changes();
        assert!(!em.has_pending_changes());
        assert!(em.pending_changes_for_proposal().is_none());
    }

    #[test]
    fn test_pending_changes_hash_deterministic() {
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos[..4], 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);
        em.propose_add_validator(infos[4].clone()).unwrap();

        let h1 = em.pending_changes_hash();
        let h2 = em.pending_changes_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, alloy_primitives::B256::ZERO);
    }

    #[test]
    fn test_pending_changes_hash_zero_when_empty() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        let em = EpochManager::with_epoch_length(vs, 10);
        assert_eq!(em.pending_changes_hash(), alloy_primitives::B256::ZERO);
    }

    #[test]
    fn test_peek_next_set() {
        let infos = make_validator_infos(5);
        let vs = ValidatorSet::new(&infos[..4], 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);
        assert!(em.peek_next_set().is_none());

        em.propose_add_validator(infos[4].clone()).unwrap();
        em.commit_pending_changes().unwrap();
        assert!(em.peek_next_set().is_some());
        assert_eq!(em.peek_next_set().unwrap().len(), 5);
    }

    #[test]
    fn test_replace_clears_and_overwrites() {
        let infos = make_validator_infos(6);
        let vs = ValidatorSet::new(&infos[..4], 1);
        let mut em = EpochManager::with_epoch_length(vs, 10);

        // Local pending: add validator 4
        em.propose_add_validator(infos[4].clone()).unwrap();
        assert_eq!(em.pending_changes_for_proposal().unwrap().len(), 1);

        // Leader sends different changes: add validator 5
        let leader_changes = vec![ValidatorChange::Add {
            address: infos[5].address,
            bls_public_key: infos[5].bls_public_key.clone(),
            p2p_peer_id: None,
        }];
        em.replace_pending_from_proposal(&leader_changes);

        let changes = em.pending_changes_for_proposal().unwrap();
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            ValidatorChange::Add { address, .. } => assert_eq!(*address, infos[5].address),
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn test_reject_proposals_when_epochs_disabled() {
        let infos = make_validator_infos(4);
        let vs = ValidatorSet::new(&infos, 1);
        // epoch_length = 0 → epochs disabled
        let mut em = EpochManager::new(vs);

        let sk = test_key(0x20);
        let new_v = ValidatorInfo {
            address: Address::with_last_byte(0x10),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        };
        let err = em.propose_add_validator(new_v).unwrap_err();
        assert!(
            matches!(err, ConsensusError::EpochsDisabled),
            "expected EpochsDisabled, got: {err}"
        );

        let err = em
            .propose_remove_validator(Address::with_last_byte(0))
            .unwrap_err();
        assert!(
            matches!(err, ConsensusError::EpochsDisabled),
            "expected EpochsDisabled, got: {err}"
        );
    }
}
