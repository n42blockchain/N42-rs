// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sealed;
pub use sealed::{Header, SealedHeader, SealedHeaderFor};

mod error;
pub use error::HeaderError;

mod header_mut;
pub use header_mut::HeaderMut;

#[cfg(any(test, feature = "test-utils", feature = "arbitrary"))]
pub mod test_utils;

/// Clique consensus utilities for header manipulation and validation.
pub mod clique_utils;

#[cfg(test)]
mod clique_utils_tests;

/// Bincode-compatible header type serde implementations.
#[cfg(feature = "serde-bincode-compat")]
pub mod serde_bincode_compat {
    pub use super::sealed::serde_bincode_compat::SealedHeader;
}
