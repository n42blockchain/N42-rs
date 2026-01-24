// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// Network Errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// Indicates that the sender has been dropped.
    #[error("sender has been dropped")]
    ChannelClosed,
}

impl<T> From<mpsc::error::SendError<T>> for NetworkError {
    fn from(_: mpsc::error::SendError<T>) -> Self {
        Self::ChannelClosed
    }
}

impl From<oneshot::error::RecvError> for NetworkError {
    fn from(_: oneshot::error::RecvError) -> Self {
        Self::ChannelClosed
    }
}
