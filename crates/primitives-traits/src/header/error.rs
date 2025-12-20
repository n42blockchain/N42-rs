// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

/// Errors that can occur during header sanity checks.
#[derive(Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Represents an error when the block difficulty is too large.
    LargeDifficulty,
    /// Represents an error when the block extra data is too large.
    LargeExtraData,
}
