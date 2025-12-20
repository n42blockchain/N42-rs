// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sealed;
pub use sealed::{Header, SealedHeader, SealedHeaderFor};

mod error;
pub use error::HeaderError;

#[cfg(any(test, feature = "test-utils", feature = "arbitrary"))]
pub mod test_utils;

pub mod clique_utils;

#[cfg(test)]
mod clique_utils_tests;

/// Bincode-compatible header type serde implementations.
#[cfg(feature = "serde-bincode-compat")]
pub mod serde_bincode_compat {
    pub use super::sealed::serde_bincode_compat::SealedHeader;
}
