use crate::Hash256;
use crate::beacon_state::Error as BeaconStateError;
use crate::safe_aitrh::ArithError;

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