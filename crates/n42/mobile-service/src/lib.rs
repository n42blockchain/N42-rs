// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node side of mobile verification.
//!
//! [`n42_mobile_verify`] is the format and the phone's half: receipts,
//! attestations, state proofs. This is the node's half — what it publishes for
//! phones to check, and what it does with what they send back.
//!
//! A phone never has to trust this service. The finality it serves is the
//! committed `Decide` in gov5's v4 wire format, verifiable against a validator
//! set on the phone; the attestations it produces are BLS aggregates anyone can
//! check with two pairings. What the service supplies is availability and
//! aggregation, not authority.
//!
//! Not covered: state proofs. Serving one means holding the QMDB twig forest the
//! proof is cut from, and this node keeps its state in reth's MDBX instead. The
//! verifier side is ready ([`n42_mobile_verify::state_proof`]) and so is the
//! engine ([`n42_twig_core`](https://docs.rs/n42-twig-core)); the missing piece
//! is the node maintaining that state. See `docs/N42_26_PORT.md`.

pub mod http;
pub mod rpc;
pub mod service;

pub use http::serve;
pub use rpc::{dispatch, RpcError};
pub use service::{
    FinalityReport, MobileService, RecordError, SubmitError, SubmitOutcome,
};
