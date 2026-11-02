// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's `/mobileverify` phone surface ("mining v3"), in Rust.
//!
//! The specification is `docs/MOBILEVERIFY_V3_PARITY.md`; the contract is
//! N42-gov5's Go code (`internal/mobileverify`, `lib/bmt`,
//! `cmd/evmsdk/{stream_packet,read_log,wire}.go`, `common/block/header.go`),
//! and the cross-client fixtures under `testdata/gov5_cross_client_v1/` pin
//! the bytes.
//!
//! - [`keys`], [`pop`], [`pow`]: a device's BLS key (blst min-pk, IKM
//!   `KeyGen`), the proof of possession and the registration proof of work,
//!   all under the standard [`bls::DST`].
//! - [`accumulator`]: gov5's Blake3 binary Merkle tree, the registry root a
//!   leader stamps into `MobileRegistryRoot`.
//! - [`registry`]: pending → committed registrations, indices, snapshots.
//! - [`mask`], [`receipt`], [`cert`]: the signer mask, the 72-byte receipt
//!   message and its JSON body, cohort certificates, merge and storage.
//! - [`collector`], [`cohort`]: one block's intake and the height-driven
//!   1/2/3/5-block schedule that turns receipts into stored certificates.
//! - [`packet`]: `StreamPacket` V2, gov5's header `Marshal` and transaction
//!   protobuf codecs, the read log, and the packet cache.
//! - [`receipts_root`]: the native receipts root a phone recomputes.
//! - [`topics`]: gossip topic names and the registration payload.
//! - [`http`]: the hyper server with gov5's exact routes, status codes,
//!   bodies and headers, plus a loopback-only `PUT /mobileverify/packet`
//!   ingest for a packet-building sidecar.
//!
//! Nothing here is wired into a node; `n42-h2-node` mounts it (stage 2).

pub mod accumulator;
pub mod bls;
pub mod cert;
pub mod cohort;
pub mod collector;
mod deadline_io;
pub mod error;
pub mod gojson;
pub mod http;
pub mod keys;
pub mod mask;
pub mod packet;
pub mod pop;
pub mod pow;
pub mod receipt;
pub mod receipts_root;
pub mod registry;
pub mod topics;

pub use cert::{CertStore, MobileAttestationCert};
pub use cohort::{AlarmBuffer, Clock, CohortConfig, CohortCoordinator, DivergenceAlarm, HeadSource};
pub use error::MobileVerifyError;
pub use http::{OnIngest, Service, ServiceConfig, serve};
pub use keys::DeviceKey;
pub use packet::{PacketCache, StreamPacket};
pub use receipt::Receipt;
pub use registry::{MobileIndex, Registry};
