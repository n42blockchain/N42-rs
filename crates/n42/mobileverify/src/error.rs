// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The registry, collector and certificate errors. `Display` is gov5's
//! `err.Error()` text byte for byte: the HTTP surface returns it as
//! `{"error":"…"}` and the Go SDK and app match on it.

use thiserror::Error;

/// An error from the registry, the receipt intake or certificate handling.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MobileVerifyError {
    /// `ErrBadPoP`.
    #[error("mobileverify: invalid proof of possession")]
    BadPop,
    /// `ErrBadPoP` wrapping a public-key decode failure.
    #[error("mobileverify: invalid proof of possession: pubkey decode: {0}")]
    BadPopPubkey(&'static str),
    /// `ErrBadPoP` wrapping a signature decode failure.
    #[error("mobileverify: invalid proof of possession: signature decode: {0}")]
    BadPopSignature(&'static str),
    /// `ErrUnknownIndex`.
    #[error("mobileverify: unknown mobile index")]
    UnknownIndex,
    /// `ErrUnknownIndex` naming the index (`PublicKeys`).
    #[error("mobileverify: unknown mobile index: {0}")]
    UnknownIndexAt(u64),
    /// `ErrKeyPreviouslyRegistered`: a revoked key asked for a second index.
    #[error("mobileverify: key was already registered; rotate to a fresh key")]
    KeyPreviouslyRegistered,
    /// `ErrPoWRequired`.
    #[error("mobileverify: registration proof-of-work required")]
    PowRequired,
    /// `ErrWrongBlock` as the window intake reports it (the node's number
    /// for the hash differs from the receipt's).
    #[error("mobileverify: receipt is for a different block: receipt number {receipt}, block is {block}")]
    WrongBlockNumber {
        /// The number the receipt claims.
        receipt: u64,
        /// The number the node has for the hash.
        block: u64,
    },
    /// `ErrWrongBlock` as `Collector.Add` reports it; the hashes are the
    /// first eight bytes in lowercase hex (Go `%x` of `hash[:8]`).
    #[error("mobileverify: receipt is for a different block: got {got_number}/{got_hash8} want {want_number}/{want_hash8}")]
    WrongBlock {
        /// The receipt's number.
        got_number: u64,
        /// The receipt's hash prefix.
        got_hash8: String,
        /// The window's number.
        want_number: u64,
        /// The window's hash prefix.
        want_hash8: String,
    },
    /// `ErrNotRegistered`: pending, revoked and unknown keys alike.
    #[error("mobileverify: verifier not registered")]
    NotRegistered,
    /// `ErrBadReceiptSignature`.
    #[error("mobileverify: invalid receipt signature")]
    BadReceiptSignature,
    /// `ErrBadReceiptSignature` wrapping a public-key decode failure.
    #[error("mobileverify: invalid receipt signature: pubkey decode: {0}")]
    BadReceiptPubkey(&'static str),
    /// `ErrBadReceiptSignature` wrapping a signature decode failure.
    #[error("mobileverify: invalid receipt signature: signature decode: {0}")]
    BadReceiptSigDecode(&'static str),
    /// `ErrWindowClosed`.
    #[error("mobileverify: collection window closed")]
    WindowClosed,
    /// `ErrUnknownBlock`: the node has no header for the receipt's hash.
    #[error("mobileverify: unknown block")]
    UnknownBlock,
    /// `ErrTooManyWindows`.
    #[error("mobileverify: too many open collection windows")]
    TooManyWindows,
    /// `ErrBadMask` with gov5's detail.
    #[error("mobileverify: malformed signer mask: {0}")]
    BadMask(String),
    /// `ErrBadCert`.
    #[error("mobileverify: certificate verification failed")]
    BadCert,
    /// `ErrBadCert` with detail.
    #[error("mobileverify: certificate verification failed: {0}")]
    BadCertDetail(String),
    /// `ErrCertMismatch`.
    #[error("mobileverify: certs are for a different block or receipts root")]
    CertMismatch,
    /// `ErrEmptyCertSet`.
    #[error("mobileverify: no certificates to combine")]
    EmptyCertSet,
    /// `ErrAllCertsConflicted`.
    #[error("mobileverify: every certificate conflicted, nothing to merge")]
    AllCertsConflicted,
    /// Any other gov5 error (snapshot import, mask decode in selection).
    #[error("mobileverify: {0}")]
    Other(String),
}
