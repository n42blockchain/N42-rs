// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HotStuff-2 cross-client wire codec.
//!
//! This crate is the Go<->Rust interop contract and nothing else: the legacy H2
//! message codec ([`h2_wire`]) and the chain-bound v4 envelope + signing domains
//! ([`h2_v4`]). It deliberately carries no networking stack, so a node — or a
//! mobile verifier — can check the wire contract against the pinned gov5
//! fixtures in `testdata/` without pulling libp2p/QUIC.
//!
//! Fixtures are byte-exact contracts shared with gov5
//! (`internal/consensus/hotstuff/testdata/`). Compare them by SHA-256 of raw
//! bytes, never text-mode content — see the `.gitattributes` `-text` pin.

pub mod h2_v4;
pub mod h2_wire;

pub use h2_v4::*;
pub use h2_wire::{decode_message, encode_message, H2Message, H2WireError};
