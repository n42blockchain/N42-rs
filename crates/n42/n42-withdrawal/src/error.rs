use crate::Hash256;
use crate::beacon_state::{Error as BeaconStateError};
use crate::safe_aitrh::ArithError;
#[cfg(feature = "supranational")]
use blst::BLST_ERROR as BlstError;
use crate::slot_epoch::Epoch;
use crate::signature_set::Error as SignatureSetError;

#[derive(Debug, PartialEq, Clone)]
pub enum BlockProcessingError {
    WithdrawalsRootMismatch {
        expected: Hash256,
        found: Hash256,
    },
    WithdrawalCredentialsInvalid,
    BeaconStateError(BeaconStateError),
    ArithError(ArithError),
    MilhouseError(milhouse::Error),
    DepositCountInvalid {
        expected: usize,
        found: usize,
    },
    DepositInvalid {
        index: usize,
        reason: DepositInvalid,
    },
    ExitInvalid {
        index: usize,
        reason: ExitInvalid,
    },
    BulkSignatureVerificationFailed,
    SignatureSetError(SignatureSetError),
    SszTypesError(ssz_types::Error),

}

impl From<BeaconStateError> for BlockProcessingError {
    fn from(e: BeaconStateError) -> Self {
        BlockProcessingError::BeaconStateError(e)
    }
}
impl From<ArithError> for BlockProcessingError {
    fn from(e: ArithError) -> Self {
        BlockProcessingError::ArithError(e)
    }
}

impl From<milhouse::Error> for BlockProcessingError {
    fn from(e: milhouse::Error) -> Self {
        Self::MilhouseError(e)
    }
}


#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// An error was raised from the Supranational BLST BLS library.
    #[cfg(feature = "supranational")]
    BlstError(BlstError),
    /// The provided bytes were an incorrect length.
    InvalidByteLength { got: usize, expected: usize },
    /// The provided secret key bytes were an incorrect length.
    InvalidSecretKeyLength { got: usize, expected: usize },
    /// The public key represents the point at infinity, which is invalid.
    InvalidInfinityPublicKey,
    /// The secret key is all zero bytes, which is invalid.
    InvalidZeroSecretKey,
}
#[cfg(feature = "supranational")]
impl From<BlstError> for Error {
    fn from(e: BlstError) -> Error {
        Error::BlstError(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum EpochProcessingError {
    BeaconStateError(BeaconStateError),
    ArithError(ArithError),
    EpochCache(EpochCacheError),

}

impl From<BeaconStateError> for EpochProcessingError {
    fn from(e: BeaconStateError) -> EpochProcessingError {
        EpochProcessingError::BeaconStateError(e)
    }
}

impl From<ArithError> for EpochProcessingError {
    fn from(e: ArithError) -> EpochProcessingError {
        EpochProcessingError::ArithError(e)
    }
}

impl From<EpochCacheError> for EpochProcessingError {
    fn from(e: EpochCacheError) -> Self {
        EpochProcessingError::EpochCache(e)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum EpochCacheError {
    CacheNotInitialized,
}

/// Describes why an object is invalid.
#[derive(Debug, PartialEq, Clone)]
pub enum AttestationInvalid {

}

#[derive(Debug, PartialEq, Clone)]
pub enum BlockOperationError<T> {
    Invalid(T),
    BeaconStateError(BeaconStateError),
    SignatureSetError(SignatureSetError),
    SszTypesError(ssz_types::Error),
    ArithError(ArithError),
}
impl<T> BlockOperationError<T> {
    pub fn invalid(reason: T) -> BlockOperationError<T> {
        BlockOperationError::Invalid(reason)
    }
}
impl<T> From<BeaconStateError> for BlockOperationError<T> {
    fn from(e: BeaconStateError) -> Self {
        BlockOperationError::BeaconStateError(e)
    }
}
impl<T> From<SignatureSetError> for BlockOperationError<T> {
    fn from(e: SignatureSetError) -> Self {
        BlockOperationError::SignatureSetError(e)
    }
}

impl<T> From<ssz_types::Error> for BlockOperationError<T> {
    fn from(error: ssz_types::Error) -> Self {
        BlockOperationError::SszTypesError(error)
    }
}
impl<T> From<ArithError> for BlockOperationError<T> {
    fn from(e: ArithError) -> Self {
        BlockOperationError::ArithError(e)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum DepositInvalid {
    /// The signature (proof-of-possession) does not match the given pubkey.
    BadSignature,
    /// The signature or pubkey does not represent a valid BLS point.
    BadBlsBytes,
    /// The specified `branch` and `index` did not form a valid proof that the deposit is included
    /// in the eth1 deposit root.
    BadMerkleProof,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ExitInvalid {
    /// The specified validator is not active.
    NotActive(u64),
    /// The specified validator is not in the state's validator registry.
    ValidatorUnknown(u64),
    /// The specified validator has a non-maximum exit epoch.
    AlreadyExited(u64),
    /// The exit is for a future epoch.
    FutureEpoch {
        state: Epoch,
        exit: Epoch,
    },
    /// The validator has not been active for long enough.
    TooYoungToExit {
        current_epoch: Epoch,
        earliest_exit_epoch: Epoch,
    },
    /// The exit signature was not signed by the validator.
    BadSignature,
    PendingWithdrawalInQueue(u64),

}

pub trait IntoWithIndex<T>: Sized {
    fn into_with_index(self, index: usize) -> T;
}

macro_rules! impl_into_block_processing_error_with_index {
    ($($type: ident),*) => {
        $(
            impl IntoWithIndex<BlockProcessingError> for BlockOperationError<$type> {
                fn into_with_index(self, index: usize) -> BlockProcessingError {
                    match self {
                        BlockOperationError::Invalid(reason) => BlockProcessingError::$type {
                            index,
                            reason
                        },
                        BlockOperationError::BeaconStateError(e) => BlockProcessingError::BeaconStateError(e),
                        BlockOperationError::SignatureSetError(e) => BlockProcessingError::SignatureSetError(e),
                        BlockOperationError::SszTypesError(e) => BlockProcessingError::SszTypesError(e),
                        BlockOperationError::ArithError(e) => BlockProcessingError::ArithError(e),
                    }
                }
            }
        )*
    };
}

impl_into_block_processing_error_with_index!(
    DepositInvalid,
    ExitInvalid
);