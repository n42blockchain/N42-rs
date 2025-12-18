use std::fmt::{Display, Error as FmtError, Formatter};

#[derive(Debug, PartialEq, Clone)]
pub enum SubscribeError {
    /// Failed to send subscribe request to router
    SendFailed,

    /// Router dropped before replying
    RouterDropped,
}

impl Display for SubscribeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SubscribeError {}
