use crate::Hash256;
use crate::beacon_state::Error as BeaconStateError;
use crate::safe_aitrh::ArithError;

#[cfg(feature = "supranational")]
use blst::BLST_ERROR as BlstError;

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