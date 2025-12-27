// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 Consensus Core
//!
//! This crate provides the core consensus logic for the N42 beacon chain,
//! including state transition functions and block validation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │           Consensus Client                   │
//! │  (miner, network, storage orchestration)    │
//! └─────────────────────────────────────────────┘
//!                       │
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │           n42-consensus-core                 │
//! │  ┌─────────────┬──────────────────────┐     │
//! │  │   state     │    validation        │     │
//! │  │ transition  │   (block/header)     │     │
//! │  └─────────────┴──────────────────────┘     │
//! └─────────────────────────────────────────────┘
//!                       │
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │           n42-primitives                     │
//! │        (BeaconState, BeaconBlock)           │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - [`state`]: State transition functions
//! - [`validation`]: Block and header validation
//! - [`error`]: Consensus error types

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod error;
pub mod state;
pub mod validation;

pub use error::*;
pub use state::*;
pub use validation::*;

#[cfg(test)]
mod tests;
