// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 APoS Consensus Trait Extensions
//!
//! This crate provides trait extensions for the N42 APoS (Authority Proof of Stake)
//! consensus mechanism. It separates N42-specific functionality from the upstream
//! reth consensus traits, improving modularity and upgrade compatibility.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │           reth_consensus::Consensus          │
//! │              (upstream trait)                │
//! └─────────────────────────────────────────────┘
//!                       │
//!                       │ extends
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │           n42_consensus_traits               │
//! │  ┌───────────────┬──────────────────────┐   │
//! │  │ AposConsensus │ SignerManager        │   │
//! │  │ (block ops)   │ (key management)     │   │
//! │  ├───────────────┼──────────────────────┤   │
//! │  │ SnapshotMgr   │ DifficultyCalculator │   │
//! │  │ (state snap)  │ (timing/difficulty)  │   │
//! │  └───────────────┴──────────────────────┘   │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use n42_consensus_traits::{AposConsensus, SignerManager};
//!
//! // Implement for your consensus type
//! impl AposConsensus for MyConsensus {
//!     fn prepare(&self, parent: &SealedHeader) -> Result<Header, AposError> {
//!         // ...
//!     }
//!     // ...
//! }
//! ```

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod error;
mod traits;

pub use error::*;
pub use traits::*;

// Re-export for convenience
pub use reth_consensus as _;

#[cfg(test)]
mod tests;

