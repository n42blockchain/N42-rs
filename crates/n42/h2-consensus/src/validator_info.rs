// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal validator descriptor.
//!
//! N42-26 sources this from its `n42-chainspec` crate, which pulls in
//! reth-chainspec and libp2p. The finality-verification path needs only these
//! three fields, so this crate defines them locally and stays free of both the
//! execution stack and the networking stack. The serde field names match gov5's
//! genesis `validators` entries so chainspec JSON deserializes unchanged.

use alloy_primitives::Address;
use n42_h2_primitives::BlsPublicKey;
use serde::{Deserialize, Serialize};

/// A single validator's consensus identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator's execution layer address (for rewards).
    pub address: Address,
    /// Validator's BLS public key (for consensus signing).
    pub bls_public_key: BlsPublicKey,
    /// Optional libp2p `PeerId` bound to this validator for direct P2P traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p2p_peer_id: Option<String>,
}
