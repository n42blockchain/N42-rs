#[derive(Debug, PartialEq, Clone)]
pub enum BlockProcessingError {
    /// Logic error indicating that the wrong state type was provided.
    IncorrectStateType,
    RandaoSignatureInvalid,
    BulkSignatureVerificationFailed,
    StateRootMismatch,
    DepositCountInvalid {
        expected: usize,
        found: usize,
    },
    HeaderInvalid {
        reason: HeaderInvalid,
    },
    ProposerSlashingInvalid {
        index: usize,
        reason: ProposerSlashingInvalid,
    },
    AttesterSlashingInvalid {
        index: usize,
        reason: AttesterSlashingInvalid,
    },
    IndexedAttestationInvalid {
        index: usize,
        reason: IndexedAttestationInvalid,
    },
    AttestationInvalid {
        index: usize,
        reason: AttestationInvalid,
    },
    DepositInvalid {
        index: usize,
        reason: DepositInvalid,
    },
    ExitInvalid {
        index: usize,
        reason: ExitInvalid,
    },
    BlsExecutionChangeInvalid {
        index: usize,
        reason: BlsExecutionChangeInvalid,
    },
    SyncAggregateInvalid {
        reason: SyncAggregateInvalid,
    },
    BeaconStateError(BeaconStateError),
    SignatureSetError(SignatureSetError),
    SszTypesError(ssz_types::Error),
    SszDecodeError(DecodeError),
    MerkleTreeError(MerkleTreeError),
    ArithError(ArithError),
    InconsistentBlockFork(InconsistentFork),
    InconsistentStateFork(InconsistentFork),
    ExecutionHashChainIncontiguous {
        expected: ExecutionBlockHash,
        found: ExecutionBlockHash,
    },
    ExecutionRandaoMismatch {
        expected: Hash256,
        found: Hash256,
    },
    ExecutionInvalidTimestamp {
        expected: u64,
        found: u64,
    },
    ExecutionInvalidBlobsLen {
        max: usize,
        actual: usize,
    },
    ExecutionInvalid,
    ConsensusContext(ContextError),
    MilhouseError(milhouse::Error),
    EpochCacheError(EpochCacheError),
    WithdrawalsRootMismatch {
        expected: Hash256,
        found: Hash256,
    },
    WithdrawalCredentialsInvalid,
    PendingAttestationInElectra,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    NonExecutionAddressWithdrawalCredential,
    BalancesOutOfBounds(usize),

}