// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clique/APoS header signature recovery and seal hashing.
//!
//! This is the signature-recovery core of N42's APoS consensus: recovering the
//! signer address from a block header's extra-data seal, and computing the seal
//! hash that signature covers.
//!
//! It previously lived inside a vendored fork of `reth-primitives-traits`
//! (`crates/primitives-traits/src/header/clique_utils.rs`). That fork existed
//! *only* to carry these files — it modified nothing upstream — so keeping it
//! meant re-applying a patch on every reth bump, and it broke outright when reth
//! moved `reth-primitives-traits` out of its repo. As a standalone crate over
//! the public `Header` / `BlockHeader` API, it survives reth upgrades untouched.
//! See `docs/RETH_2_4_1_UPGRADE.md`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;

mod clique;
pub use clique::*;

#[cfg(test)]
mod tests;
