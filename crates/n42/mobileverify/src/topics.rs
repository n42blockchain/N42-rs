// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gossip topic names (`internal/node/node.go`):
//! `/n42/<genesis4 hex>/<name>/ssz_snappy`, `genesis4` = the first four bytes
//! of the chain's genesis hash. Payloads are raw despite the suffix.

use alloy_primitives::B256;

use crate::bls::{PUBKEY_LEN, SIGNATURE_LEN};

/// `StreamPacket` gossip.
pub const PACKET: &str = "mobileverify_packet";
/// Registration gossip (`pubkey48 ‖ pop96`).
pub const REGISTRATION: &str = "mobileverify_registration";
/// Cohort index commitments.
pub const COHORT_INDEX: &str = "mobileverify_cohort_index";
/// Cohort signature reveals.
pub const COHORT_REVEAL: &str = "mobileverify_cohort_reveal";
/// Cohort certificates.
pub const COHORT_CERT: &str = "mobileverify_cohort_cert";

/// The encoder suffix gov5 appends to every topic.
pub const ENCODER_SUFFIX: &str = "/ssz_snappy";

/// The full topic string for `name` on the chain with `genesis_hash`.
pub fn topic(genesis_hash: &B256, name: &str) -> String {
    format!("/n42/{}/{name}{ENCODER_SUFFIX}", hex::encode(&genesis_hash[..4]))
}

/// A registration gossip payload: `pubkey48 ‖ pop96`.
pub fn registration_payload(pubkey: &[u8; PUBKEY_LEN], pop: &[u8; SIGNATURE_LEN]) -> [u8; PUBKEY_LEN + SIGNATURE_LEN] {
    let mut out = [0u8; PUBKEY_LEN + SIGNATURE_LEN];
    out[..PUBKEY_LEN].copy_from_slice(pubkey);
    out[PUBKEY_LEN..].copy_from_slice(pop);
    out
}

/// Splits a registration gossip payload; `None` unless exactly 144 bytes.
pub fn parse_registration_payload(data: &[u8]) -> Option<([u8; PUBKEY_LEN], [u8; SIGNATURE_LEN])> {
    if data.len() != PUBKEY_LEN + SIGNATURE_LEN {
        return None;
    }
    let mut pk = [0u8; PUBKEY_LEN];
    let mut pop = [0u8; SIGNATURE_LEN];
    pk.copy_from_slice(&data[..PUBKEY_LEN]);
    pop.copy_from_slice(&data[PUBKEY_LEN..]);
    Some((pk, pop))
}
