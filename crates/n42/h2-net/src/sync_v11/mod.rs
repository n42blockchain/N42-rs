// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The v1.1 sync protocols of the N42 common sync standard (§5), byte for
//! byte with gov5's `internal/sync/syncwire` and `internal/sync/v11`.
//!
//! - [`frame`]: the §3 / §5.0 framing every v1.1 protocol shares (result
//!   codes, context bytes, chunk framing, the END trailer, error chunks).
//!
//! The golden vectors gov5 generated live in `testdata/sync-v11/`.

pub mod frame;

#[cfg(test)]
pub(crate) mod vectors;
