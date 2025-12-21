// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 Fusaka Hardfork Support
//!
//! Fusaka = Prague (EL) + Osaka (CL)
//!
//! This crate provides:
//! - Fusaka hardfork configuration and constants
//! - BLS12-381 precompile support verification (EIP-2537)
//! - PeerDAS support verification (EIP-7594)
//! - Comprehensive test coverage for Fusaka features
//!
//! # Fusaka EIPs
//!
//! ## Execution Layer (Prague)
//! - EIP-7702: Set EOA account code
//! - EIP-7685: General purpose execution layer requests
//! - EIP-6110: Supply validator deposits on chain
//! - EIP-7002: Execution layer triggerable exits
//! - EIP-7251: Increase the MAX_EFFECTIVE_BALANCE
//!
//! ## Consensus Layer (Osaka)
//! - EIP-2537: BLS12-381 curve operations precompiles
//! - EIP-7594: PeerDAS - Peer Data Availability Sampling
//!
//! # BLS12-381 Precompile Addresses (EIP-2537)
//!
//! | Address | Operation |
//! |---------|-----------|
//! | 0x0b    | BLS12_G1ADD |
//! | 0x0c    | BLS12_G1MUL |
//! | 0x0d    | BLS12_G1MULTIEXP |
//! | 0x0e    | BLS12_G2ADD |
//! | 0x0f    | BLS12_G2MUL |
//! | 0x10    | BLS12_G2MULTIEXP |
//! | 0x11    | BLS12_PAIRING |
//! | 0x12    | BLS12_MAP_FP_TO_G1 |
//! | 0x13    | BLS12_MAP_FP2_TO_G2 |

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod bls;
pub mod constants;
pub mod peerdas;

pub use bls::*;
pub use constants::*;
pub use peerdas::*;

#[cfg(test)]
mod tests;

