use n42_h2_primitives::consensus::ViewNumber;
use thiserror::Error;

/// Errors specific to the N42 HotStuff-2 consensus protocol.
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// BLS signature verification failed.
    #[error("invalid BLS signature from validator {validator_index} in view {view}")]
    InvalidSignature {
        view: ViewNumber,
        validator_index: u32,
    },

    /// The message sender is not the expected leader for this view.
    #[error("invalid proposer: expected validator {expected}, got {actual} in view {view}")]
    InvalidProposer {
        view: ViewNumber,
        expected: u32,
        actual: u32,
    },

    /// Not enough votes to form a quorum certificate.
    #[error("insufficient votes: have {have}, need {need} in view {view}")]
    InsufficientVotes {
        view: ViewNumber,
        have: usize,
        need: usize,
    },

    /// Message view does not match the current view.
    #[error("view mismatch: current view is {current}, message view is {received}")]
    ViewMismatch {
        current: ViewNumber,
        received: ViewNumber,
    },

    /// Duplicate vote from the same validator in the same view.
    #[error("duplicate vote from validator {validator_index} in view {view}")]
    DuplicateVote {
        view: ViewNumber,
        validator_index: u32,
    },

    /// The quorum certificate is invalid (bad signature or insufficient signers).
    #[error("invalid quorum certificate for view {view}: {reason}")]
    InvalidQC { view: ViewNumber, reason: String },

    /// The timeout certificate is invalid.
    #[error("invalid timeout certificate for view {view}: {reason}")]
    InvalidTC { view: ViewNumber, reason: String },

    /// The validator index is out of bounds.
    #[error("unknown validator index {index}, set size is {set_size}")]
    UnknownValidator { index: u32, set_size: u32 },

    /// The proposal's justify_qc does not extend the locked QC.
    #[error(
        "safety violation: proposal QC view {qc_view} does not extend locked QC view {locked_view}"
    )]
    SafetyViolation {
        qc_view: ViewNumber,
        locked_view: ViewNumber,
    },

    /// Block hash in QC does not match expected block hash (e.g., in Decide message).
    #[error("block hash mismatch: expected {expected}, got {got}")]
    BlockHashMismatch {
        expected: alloy_primitives::B256,
        got: alloy_primitives::B256,
    },

    /// Internal BLS cryptographic error.
    #[error("BLS error: {0}")]
    Bls(#[from] n42_h2_primitives::bls::BlsError),

    /// The consensus output channel is full or closed.
    #[error("consensus output channel full or closed")]
    OutputChannelClosed,

    /// Epoch schedule is empty (cannot create EpochManager).
    #[error("epoch schedule must not be empty")]
    EpochScheduleEmpty,

    /// Validator-set parameters do not satisfy the BFT fault-tolerance bound.
    #[error(
        "invalid validator set parameters: fault_tolerance ({fault_tolerance}) exceeds max ({max_fault_tolerance}) for {validator_count} validators"
    )]
    InvalidValidatorSetParams {
        validator_count: u32,
        fault_tolerance: u32,
        max_fault_tolerance: u32,
    },

    /// The local validator key is not present in the active epoch's validator set.
    #[error("local validator key is not present in validator set for epoch {epoch}")]
    LocalValidatorNotInSet { epoch: u64 },

    /// Batch verification input exceeds the maximum allowed size.
    #[error("batch verification size {size} exceeds maximum {max}")]
    BatchTooLarge { size: usize, max: usize },

    /// Validator set would fall below the minimum required size.
    #[error("insufficient validators: have {have}, need at least {need}")]
    InsufficientValidators { have: usize, need: usize },

    /// New and old validator sets do not have sufficient quorum overlap for safe transition.
    #[error(
        "insufficient quorum overlap between old and new validator sets: have {have}, need {need}"
    )]
    InsufficientQuorumOverlap { have: usize, need: usize },

    /// Validator already exists in the current set or pending additions.
    #[error("validator {address} already exists in the validator set")]
    ValidatorAlreadyExists { address: alloy_primitives::Address },

    /// Validator not found in the current set.
    #[error("validator {address} not found in the validator set")]
    ValidatorNotFound { address: alloy_primitives::Address },

    /// Validator is already queued for removal and cannot be removed again.
    #[error("validator {address} is already pending removal")]
    ValidatorAlreadyPendingRemoval { address: alloy_primitives::Address },

    /// A validator set transition is already staged for the next epoch.
    /// No further proposals are accepted until the staged transition is activated
    /// at the next epoch boundary.
    #[error(
        "epoch transition already staged; wait for the current staged set to be activated before proposing further changes"
    )]
    EpochTransitionAlreadyStaged,

    /// A proposal contained too many validator changes (DoS protection).
    #[error("proposal contains {count} validator changes, max allowed is {max}")]
    TooManyValidatorChanges { count: usize, max: usize },

    /// Dynamic validator changes require epochs to be enabled (epoch_length > 0).
    #[error(
        "epochs are disabled (epoch_length=0); dynamic validator changes require epoch_length > 0 in consensus config"
    )]
    EpochsDisabled,

    /// gov5 H2-v4 currently commits a static validator-set hash of zero.
    #[error("H2-v4 participant mode does not support dynamic validator changes")]
    H2V4ValidatorChangesUnsupported,

    /// A validator's BLS public key failed subgroup / non-infinity validation.
    /// Detected at `ValidatorSet::try_new` so all subsequent verifications can
    /// safely skip the per-call subgroup check.
    #[error("validator at index {index} has an invalid BLS public key (failed subgroup check)")]
    InvalidValidatorPubkey { index: u32 },

    /// Persistent vote-log fsync failed; the vote MUST be aborted to avoid
    /// double-voting after a crash. The IO error message is captured as a
    /// `String` so this enum stays free of the rest of `io::Error`'s API
    /// surface (notably its `kind()` is rarely useful past logging).
    #[error("vote log fsync failed: {0}")]
    VoteLogFsync(String),
}

/// Result type for consensus operations.
pub type ConsensusResult<T> = Result<T, ConsensusError>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn test_error_display_formats() {
        let cases: Vec<(ConsensusError, &[&str])> = vec![
            (
                ConsensusError::InvalidSignature {
                    view: 5,
                    validator_index: 3,
                },
                &["invalid BLS signature", "3", "5"],
            ),
            (
                ConsensusError::InvalidProposer {
                    view: 10,
                    expected: 1,
                    actual: 2,
                },
                &["invalid proposer", "1", "2", "10"],
            ),
            (
                ConsensusError::InsufficientVotes {
                    view: 1,
                    have: 2,
                    need: 3,
                },
                &["insufficient votes", "2", "3"],
            ),
            (
                ConsensusError::ViewMismatch {
                    current: 5,
                    received: 10,
                },
                &["view mismatch", "5", "10"],
            ),
            (
                ConsensusError::DuplicateVote {
                    view: 1,
                    validator_index: 0,
                },
                &["duplicate vote", "0"],
            ),
            (
                ConsensusError::InvalidQC {
                    view: 3,
                    reason: "bad sig".into(),
                },
                &["invalid quorum certificate", "bad sig", "3"],
            ),
            (
                ConsensusError::InvalidTC {
                    view: 7,
                    reason: "too few".into(),
                },
                &["invalid timeout certificate", "too few", "7"],
            ),
            (
                ConsensusError::UnknownValidator {
                    index: 99,
                    set_size: 4,
                },
                &["unknown validator", "99", "4"],
            ),
            (
                ConsensusError::SafetyViolation {
                    qc_view: 1,
                    locked_view: 5,
                },
                &["safety violation", "1", "5"],
            ),
            (
                ConsensusError::BlockHashMismatch {
                    expected: B256::ZERO,
                    got: B256::repeat_byte(0xFF),
                },
                &["block hash mismatch"],
            ),
            (
                ConsensusError::InsufficientValidators { have: 3, need: 4 },
                &["insufficient validators", "3", "4"],
            ),
            (
                ConsensusError::InsufficientQuorumOverlap { have: 2, need: 3 },
                &["quorum overlap", "2", "3"],
            ),
            (
                ConsensusError::ValidatorAlreadyExists {
                    address: alloy_primitives::Address::ZERO,
                },
                &["already exists"],
            ),
            (
                ConsensusError::ValidatorNotFound {
                    address: alloy_primitives::Address::ZERO,
                },
                &["not found"],
            ),
            (
                ConsensusError::ValidatorAlreadyPendingRemoval {
                    address: alloy_primitives::Address::ZERO,
                },
                &["already pending removal"],
            ),
            (
                ConsensusError::EpochTransitionAlreadyStaged,
                &["already staged"],
            ),
        ];

        for (err, keywords) in &cases {
            let s = err.to_string();
            for kw in *keywords {
                assert!(
                    s.contains(kw),
                    "Display for {:?} should contain '{}'",
                    err,
                    kw
                );
            }
        }
    }

    #[test]
    fn test_bls_error_from_conversion() {
        let bls_err = n42_h2_primitives::bls::BlsError::SigningFailed;
        let consensus_err: ConsensusError = bls_err.into();
        let display = consensus_err.to_string();
        assert!(display.contains("BLS"));
    }

    #[test]
    fn test_consensus_result_ok_and_err() {
        let ok: ConsensusResult<u32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: ConsensusResult<u32> = Err(ConsensusError::ViewMismatch {
            current: 1,
            received: 2,
        });
        assert!(err.is_err());
    }
}
