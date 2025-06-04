use crate::Hash256;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    NonExecutionAddressWithdrawalCredential,
    BalancesOutOfBounds(usize),
    UnknownValidator(usize),
}
#[derive(Debug, PartialEq, Clone)]
pub enum BlockProcessingError {
    WithdrawalsRootMismatch {
        expected: Hash256,
        found: Hash256,
    },
    WithdrawalCredentialsInvalid,
}