// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! clique consensus

mod apos;
pub use apos::*;

mod unverifiedblock;
pub use unverifiedblock::*;

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod fuzz_tests;
