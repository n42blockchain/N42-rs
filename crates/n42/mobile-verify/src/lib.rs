// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mobile verification formats.
//!
//! The wire formats a mobile verifier speaks: BLS-signed verification receipts,
//! their aggregation into attestations, the state proofs a phone checks against
//! a block's state root, and the code cache that keeps a phone from re-fetching
//! hot contract bytecode.
//!
//! Everything here is execution-stack free — proof verification runs on the
//! pure-blake3 [`n42_bmt_core`] / [`n42_twig_core`] engines, so a phone verifies
//! without an EVM, an MDBX handle, or a networking stack. The re-execution
//! verifier (`verifier.rs` in N42-26) is deliberately NOT ported: it pulls
//! reth-revm and belongs with the node, not the format.

pub mod attestation;
pub mod code_cache;
pub mod receipt;
pub(crate) mod serde_helpers;
pub mod state_proof;
pub mod verification;
pub mod wire;

pub use attestation::{
    AggregatedAttestation, AttestationBuilder, AttestationError, VerifierRegistry,
};
pub use code_cache::{CacheSyncMessage, CodeCache, HotContractTracker};
pub use receipt::{sign_receipt, ReceiptError, VerificationReceipt};
pub use verification::{BlockVerificationStatus, ReceiptAggregator};

/// Derives an ETH address via `keccak256(pubkey_bytes)[12..]`.
pub fn bls_pubkey_to_address(pubkey: &[u8; 48]) -> alloy_primitives::Address {
    let hash = alloy_primitives::keccak256(pubkey);
    alloy_primitives::Address::from_slice(&hash[12..])
}
