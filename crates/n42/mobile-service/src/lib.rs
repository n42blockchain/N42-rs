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
//! State proofs come from [`n42_qmdb_state`], which is the same tree a QMDB
//! chain's block header takes its state root from. That is what makes the chain
//! of trust close: the phone verifies the `Decide`'s signatures, those commit to
//! a state root, and the proof is checked against that same root. Hand
//! [`MobileService::with_state`] the tree the node applies blocks to; without it
//! the node serves finality and collects receipts but cannot prove state.

pub mod http;
pub mod rpc;
pub mod service;

pub use http::serve;
pub use rpc::{dispatch, RpcError};
pub use service::{
    StateProofReport,
    FinalityReport, MobileService, RecordError, SubmitError, SubmitOutcome,
};
