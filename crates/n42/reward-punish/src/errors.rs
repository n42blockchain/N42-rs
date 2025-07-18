use ssz::DecodeError;
use crate::arith;
use crate::beaconstate::Error as BeaconstateError;
use crate::common::epoch_cache::EpochCacheError;

#[derive( PartialEq)]
pub enum EpochProcessingError {
    UnableToDetermineProducer,
    NoBlockRoots,
    BaseRewardQuotientIsZero,
    NoRandaoSeed,
    PreviousTotalBalanceIsZero,
    InclusionDistanceZero,
    ValidatorStatusesInconsistent,
    DeltasInconsistent,
    DeltaOutOfBounds(usize),
    /// Unable to get the inclusion distance for a validator that should have an inclusion
    /// distance. This indicates an internal inconsistency.
    ///
    /// (validator_index)
    InclusionSlotsInconsistent(usize),
    BeaconStateError(BeaconstateError),
    InclusionError(InclusionError),
    SszTypesError(ssz_types::Error),
    ArithError(arith::ArithError),
    // InconsistentStateFork(InconsistentFork),
    InvalidJustificationBit(ssz_types::Error),
    InvalidFlagIndex(usize),
    MilhouseError(milhouse::Error),
    EpochCache(EpochCacheError),
    SinglePassMissingActivationQueue,
    MissingEarliestExitEpoch,
    MissingExitBalanceToConsume,
    PendingDepositsLogicError,
    SszDecodeError(ssz::DecodeError),
}

impl From<EpochCacheError> for EpochProcessingError {
    fn from(e: EpochCacheError) -> Self {
        EpochProcessingError::EpochCache(e)
    }
}

impl From<InclusionError> for EpochProcessingError {
    fn from(e: InclusionError) -> EpochProcessingError {
        EpochProcessingError::InclusionError(e)
    }
}

impl From<BeaconstateError> for EpochProcessingError {
    fn from(e: BeaconstateError) -> EpochProcessingError {
        EpochProcessingError::BeaconStateError(e)
    }
}

impl From<ssz_types::Error> for EpochProcessingError {
    fn from(e: ssz_types::Error) -> EpochProcessingError {
        EpochProcessingError::SszTypesError(e)
    }
}

impl From<arith::ArithError> for EpochProcessingError {
    fn from(e: arith::ArithError) -> EpochProcessingError {
        EpochProcessingError::ArithError(e)
    }
}

impl From<milhouse::Error> for EpochProcessingError {
    fn from(e: milhouse::Error) -> Self {
        Self::MilhouseError(e)
    }
}

impl From<DecodeError> for EpochProcessingError{
    fn from(e: DecodeError) -> EpochProcessingError {
        EpochProcessingError::SszDecodeError(e)
    }
}


// impl From<EpochCacheError> for EpochProcessingError {
//     fn from(e: EpochCacheError) -> Self {
//         EpochProcessingError::EpochCache(e)
//     }
// }

#[derive(PartialEq)]
pub enum InclusionError {
    /// The validator did not participate in an attestation in this period.
    NoAttestationsForValidator,
    BeaconStateError(BeaconstateError),
}

impl From<BeaconstateError> for InclusionError {
    fn from(e: BeaconstateError) -> InclusionError {
        InclusionError::BeaconStateError(e)
    }
}
