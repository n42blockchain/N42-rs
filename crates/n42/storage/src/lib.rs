// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 Storage Layer
//!
//! This crate provides storage types and table definitions for the N42 beacon chain.
//! It separates N42-specific storage concerns from the upstream reth storage layer.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              Application Layer               │
//! └─────────────────────────────────────────────┘
//!                       │
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │              n42-storage                     │
//! │  ┌─────────────┬──────────────────────┐     │
//! │  │   tables    │     codecs           │     │
//! │  │ (beacon/    │  (compress/          │     │
//! │  │  validator) │   decompress)        │     │
//! │  └─────────────┴──────────────────────┘     │
//! └─────────────────────────────────────────────┘
//!                       │
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │              reth-db-api                     │
//! │           (database interface)              │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - [`tables`]: N42 beacon chain table definitions
//! - [`codecs`]: Compression/decompression implementations
//! - [`error`]: Storage error types

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod codecs;
pub mod error;
pub mod tables;

pub use codecs::*;
pub use error::*;
pub use tables::*;

#[cfg(test)]
mod tests;
