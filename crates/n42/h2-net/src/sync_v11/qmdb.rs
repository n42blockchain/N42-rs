// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! QMDB state sync (N42 sync standard §5.3): `qmdb_status/1`,
//! `qmdb_manifest/1` and `qmdb_twigs/1`.
//!
//! Byte layouts, the QMDB hashing the verifier needs (§1.5), the manifest
//! range proof, twig verification, the portable `0x03` snapshot split into
//! twigs and reassembled, and the server core over one pivot's
//! [`Snapshot`]. No libp2p and no database: the node wires these to its
//! streams and its state. Every layout and every reply matches gov5's
//! `internal/sync/syncwire` and `internal/sync/v11` byte for byte (golden
//! vectors under `testdata/sync-v11`).

use alloy_primitives::B256;
use std::sync::Mutex;

/// `qmdb_status/1`.
pub const QMDB_STATUS_PROTOCOL: &str = "/rpc/qmdb_status/1/ssz_snappy";
/// `qmdb_manifest/1`.
pub const QMDB_MANIFEST_PROTOCOL: &str = "/rpc/qmdb_manifest/1/ssz_snappy";
/// `qmdb_twigs/1`.
pub const QMDB_TWIGS_PROTOCOL: &str = "/rpc/qmdb_twigs/1/ssz_snappy";

/// Result code: data chunk.
pub const CODE_SUCCESS: u8 = 0x00;
/// Result code: malformed or out-of-bounds request.
pub const CODE_INVALID_REQUEST: u8 = 0x01;
/// Result code: internal failure.
pub const CODE_SERVER_ERROR: u8 = 0x02;
/// Result code: pivot not servable, unknown hash.
pub const CODE_RESOURCE_UNAVAILABLE: u8 = 0x03;
/// Result code: over quota; the message is decimal `retry_after_ms`.
pub const CODE_RATE_LIMITED: u8 = 0x04;
/// Result code: the terminal END trailer of a twig stream.
pub const CODE_END: u8 = 0x10;

/// END reason: everything asked for was sent.
pub const REASON_COMPLETE: u8 = 0;
/// END reason: the byte budget stopped the reply.
pub const REASON_BYTE_BUDGET: u8 = 1;
/// END reason: the count cap stopped the reply.
pub const REASON_COUNT_CAP: u8 = 2;
/// END reason: the server's committed head was reached.
pub const REASON_CANONICAL_END: u8 = 3;
/// END reason: the rest is not available.
pub const REASON_NOT_AVAILABLE: u8 = 4;
/// END reason: rate limited.
pub const REASON_RATE_LIMITED: u8 = 5;
/// END reason: shutting down.
pub const REASON_SHUTTING_DOWN: u8 = 6;
const MAX_REASON: u8 = 6;

/// Slots per twig.
pub const TWIG_SIZE: u64 = 2048;
/// Bytes of a twig's active bitmap.
pub const TWIG_BITS_LEN: usize = 256;
/// Twigs per manifest page.
pub const MAX_MANIFEST_TWIGS: u32 = 16384;
/// Twigs per `qmdb_twigs/1` request.
pub const MAX_TWIGS_PER_REQUEST: u32 = 256;
/// A twig reply's budget when the request says 0.
pub const DEFAULT_TWIG_BYTES: u64 = 16 << 20;
/// A twig reply's budget cap.
pub const MAX_TWIG_REPLY_BYTES: u64 = 64 << 20;
/// A record value's cap.
pub const MAX_RECORD_VALUE: u32 = 16 << 20;
/// The `qmdb_status/1` response length.
pub const QMDB_STATUS_LEN: usize = 57;
/// Status flag: the server serves twigs.
pub const STATUS_FLAG_TWIGS: u8 = 1;
/// Status flag: the server serves code.
pub const STATUS_FLAG_CODE: u8 = 2;
/// The `qmdb_manifest/1` request length.
pub const MANIFEST_REQUEST_LEN: usize = 48;
/// The `qmdb_twigs/1` request length.
pub const TWIGS_REQUEST_LEN: usize = 60;
/// The END trailer length.
pub const END_LEN: usize = 17;
/// `BITS_ONLY`.
pub const FLAG_BITS_ONLY: u32 = 1;
/// The largest manifest page payload.
pub const MAX_MANIFEST_PAYLOAD: usize = 8 + 32 + 32 + 8 + 8 + 8 + 4 + MAX_MANIFEST_TWIGS as usize * 64 + 4 + 2 * 64 * 32;
/// The largest twig chunk payload.
pub const MAX_TWIG_CHUNK_PAYLOAD: usize = (MAX_TWIG_REPLY_BYTES + MAX_RECORD_VALUE as u64) as usize;

/// Wire record kind: live slot, key hash only (portable form; on the wire
/// only for a live leaf whose preimage the server lacks).
pub const KIND_LIVE: u8 = 1;
/// Wire record kind: dead slot, its leaf hash.
pub const KIND_DEAD: u8 = 2;
/// Wire record kind: a whole all-dead twig, its leaf root.
pub const KIND_HOLLOW: u8 = 3;
/// Wire record kind: live slot with its key preimage (20 or 52 bytes).
pub const KIND_LIVE_P: u8 = 4;

/// A malformed message, or data that does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// A fixed-layout message of the wrong length.
    #[error("syncwire: wrong message length")]
    Length,
    /// A message shorter than its fields.
    #[error("syncwire: truncated")]
    Truncated,
    /// A manifest page that does not fold to its root.
    #[error("syncwire: manifest range proof does not verify")]
    Proof,
    /// Anything else, gov5's wording.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> WireError {
    WireError::Invalid(msg.into())
}

// ---------------------------------------------------------------------------
// Byte reading

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| WireError::Truncated)?))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| WireError::Truncated)?))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| WireError::Truncated)?))
    }
    fn hash(&mut self) -> Result<B256, WireError> {
        Ok(B256::from_slice(self.take(32)?))
    }
    fn value(&mut self) -> Result<Vec<u8>, WireError> {
        let n = self.u32()?;
        if n > MAX_RECORD_VALUE {
            return Err(invalid(format!("syncwire: value of {n} bytes")));
        }
        Ok(self.take(n as usize)?.to_vec())
    }
    const fn done(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// qmdb_status/1 (§5.3.2)

/// The 57-byte `qmdb_status/1` response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QmdbStatus {
    /// The lowest block the server range-serves.
    pub earliest_body: u64,
    /// The lowest servable pivot.
    pub pivot_lo: u64,
    /// The highest servable pivot.
    pub pivot_hi: u64,
    /// Its hash.
    pub pivot_hi_hash: B256,
    /// Bit 0 twigs, bit 1 code.
    pub flags: u8,
}

impl QmdbStatus {
    /// The wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(QMDB_STATUS_LEN);
        b.extend_from_slice(&self.earliest_body.to_le_bytes());
        b.extend_from_slice(&self.pivot_lo.to_le_bytes());
        b.extend_from_slice(&self.pivot_hi.to_le_bytes());
        b.extend_from_slice(self.pivot_hi_hash.as_slice());
        b.push(self.flags);
        b
    }

    /// Decodes and checks `pivot_lo <= pivot_hi`.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != QMDB_STATUS_LEN {
            return Err(WireError::Length);
        }
        let mut r = Reader(b);
        let s = Self {
            earliest_body: r.u64()?,
            pivot_lo: r.u64()?,
            pivot_hi: r.u64()?,
            pivot_hi_hash: r.hash()?,
            flags: r.u8()?,
        };
        if s.pivot_lo > s.pivot_hi {
            return Err(invalid(format!("syncwire: pivot_lo {} > pivot_hi {}", s.pivot_lo, s.pivot_hi)));
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// qmdb_manifest/1 (§5.3.3)

/// The 48-byte `qmdb_manifest/1` request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManifestRequest {
    /// The pivot.
    pub pivot_hash: B256,
    /// The first twig of the page.
    pub first_twig: u64,
    /// 1..16384.
    pub count: u32,
    /// Zero.
    pub reserved: u32,
}

impl ManifestRequest {
    /// The wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MANIFEST_REQUEST_LEN);
        b.extend_from_slice(self.pivot_hash.as_slice());
        b.extend_from_slice(&self.first_twig.to_le_bytes());
        b.extend_from_slice(&self.count.to_le_bytes());
        b.extend_from_slice(&self.reserved.to_le_bytes());
        b
    }

    /// Decodes and validates.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != MANIFEST_REQUEST_LEN {
            return Err(WireError::Length);
        }
        let mut r = Reader(b);
        let req = Self { pivot_hash: r.hash()?, first_twig: r.u64()?, count: r.u32()?, reserved: r.u32()? };
        if req.count == 0 || req.count > MAX_MANIFEST_TWIGS {
            return Err(invalid(format!("syncwire: manifest count {} outside 1..{MAX_MANIFEST_TWIGS}", req.count)));
        }
        if req.reserved != 0 {
            return Err(invalid("syncwire: manifest reserved field is not zero"));
        }
        Ok(req)
    }
}

/// One manifest entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TwigRoots {
    /// The root of the twig's 2048 leaves.
    pub leaf_root: B256,
    /// `BLAKE3(0x03 ‖ bits)`.
    pub bits_root: B256,
}

/// The `qmdb_manifest/1` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestPage {
    /// P.
    pub pivot_number: u64,
    /// hash(P).
    pub pivot_hash: B256,
    /// The state root after P (header(P+1).Root).
    pub root: B256,
    /// The first unappended slot at P.
    pub next_slot: u64,
    /// `ceil(next_slot / 2048)`.
    pub twig_count: u64,
    /// The page's first twig.
    pub first_twig: u64,
    /// The page's twigs.
    pub twigs: Vec<TwigRoots>,
    /// The range proof ([`range_proof`]).
    pub proof: Vec<B256>,
}

impl ManifestPage {
    /// The wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(100 + self.twigs.len() * 64 + 4 + self.proof.len() * 32);
        b.extend_from_slice(&self.pivot_number.to_le_bytes());
        b.extend_from_slice(self.pivot_hash.as_slice());
        b.extend_from_slice(self.root.as_slice());
        b.extend_from_slice(&self.next_slot.to_le_bytes());
        b.extend_from_slice(&self.twig_count.to_le_bytes());
        b.extend_from_slice(&self.first_twig.to_le_bytes());
        b.extend_from_slice(&(self.twigs.len() as u32).to_le_bytes());
        for t in &self.twigs {
            b.extend_from_slice(t.leaf_root.as_slice());
            b.extend_from_slice(t.bits_root.as_slice());
        }
        b.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        for h in &self.proof {
            b.extend_from_slice(h.as_slice());
        }
        b
    }

    /// Decodes the shape ([`verify_manifest_page`] checks it).
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader(b);
        let mut p = Self {
            pivot_number: r.u64()?,
            pivot_hash: r.hash()?,
            root: r.hash()?,
            next_slot: r.u64()?,
            twig_count: r.u64()?,
            first_twig: r.u64()?,
            ..Default::default()
        };
        let n = r.u32()?;
        if n > MAX_MANIFEST_TWIGS || (n as usize) * 64 > r.0.len() {
            return Err(invalid(format!("syncwire: manifest page of {n} twigs")));
        }
        p.twigs = (0..n).map(|_| Ok(TwigRoots { leaf_root: r.hash()?, bits_root: r.hash()? })).collect::<Result<_, WireError>>()?;
        let m = r.u32()?;
        if m > 128 || (m as usize) * 32 != r.0.len() {
            return Err(invalid(format!("syncwire: manifest proof of {m} nodes over {} bytes", r.0.len())));
        }
        p.proof = (0..m).map(|_| r.hash()).collect::<Result<_, _>>()?;
        Ok(p)
    }
}

// ---------------------------------------------------------------------------
// qmdb_twigs/1 (§5.3.4)

/// The 60-byte `qmdb_twigs/1` request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TwigsRequest {
    /// The pivot.
    pub pivot_hash: B256,
    /// The first twig.
    pub first_twig: u64,
    /// 1..256.
    pub twig_count: u32,
    /// Records start at `max(twig_id * 2048, from_slot)`.
    pub from_slot: u64,
    /// Bit 0 `BITS_ONLY`.
    pub flags: u32,
    /// 0 = 16 MiB; the server caps it at 64 MiB.
    pub max_bytes: u32,
}

impl TwigsRequest {
    /// The wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(TWIGS_REQUEST_LEN);
        b.extend_from_slice(self.pivot_hash.as_slice());
        b.extend_from_slice(&self.first_twig.to_le_bytes());
        b.extend_from_slice(&self.twig_count.to_le_bytes());
        b.extend_from_slice(&self.from_slot.to_le_bytes());
        b.extend_from_slice(&self.flags.to_le_bytes());
        b.extend_from_slice(&self.max_bytes.to_le_bytes());
        b
    }

    /// Decodes and validates.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != TWIGS_REQUEST_LEN {
            return Err(WireError::Length);
        }
        let mut r = Reader(b);
        let req = Self {
            pivot_hash: r.hash()?,
            first_twig: r.u64()?,
            twig_count: r.u32()?,
            from_slot: r.u64()?,
            flags: r.u32()?,
            max_bytes: r.u32()?,
        };
        if req.twig_count == 0 || req.twig_count > MAX_TWIGS_PER_REQUEST {
            return Err(invalid(format!(
                "syncwire: twig count {} outside 1..{MAX_TWIGS_PER_REQUEST}",
                req.twig_count
            )));
        }
        if req.flags & !FLAG_BITS_ONLY != 0 {
            return Err(invalid(format!("syncwire: reserved twig flag bits {:#x} set", req.flags & !FLAG_BITS_ONLY)));
        }
        Ok(req)
    }

    /// Whether `BITS_ONLY` is set.
    pub const fn bits_only(&self) -> bool {
        self.flags & FLAG_BITS_ONLY != 0
    }

    /// The reply's byte budget: `max_bytes` or 16 MiB, at most 64 MiB.
    pub const fn budget(&self) -> u64 {
        let b = if self.max_bytes == 0 { DEFAULT_TWIG_BYTES } else { self.max_bytes as u64 };
        if b > MAX_TWIG_REPLY_BYTES {
            MAX_TWIG_REPLY_BYTES
        } else {
            b
        }
    }
}

/// One twig record, its slot implicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Kind 1: a live slot, key hash only.
    Live {
        /// The key hash.
        key_hash: B256,
        /// The value.
        value: Vec<u8>,
    },
    /// Kind 4: a live slot with its preimage (20-byte address or 52-byte
    /// address ‖ slot), whose BLAKE3 is the key hash.
    LiveP {
        /// The preimage.
        preimage: Vec<u8>,
        /// The value.
        value: Vec<u8>,
    },
    /// Kind 2: a dead slot, its leaf hash.
    Dead {
        /// The leaf hash.
        leaf_hash: B256,
    },
    /// Kind 3: the sole record of a full, all-dead twig.
    Hollow {
        /// The twig's leaf root.
        leaf_root: B256,
    },
}

impl Record {
    /// The wire kind byte.
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Live { .. } => KIND_LIVE,
            Self::LiveP { .. } => KIND_LIVE_P,
            Self::Dead { .. } => KIND_DEAD,
            Self::Hollow { .. } => KIND_HOLLOW,
        }
    }

    /// The key hash of a live record.
    pub fn key_hash(&self) -> Option<B256> {
        match self {
            Self::Live { key_hash, .. } => Some(*key_hash),
            Self::LiveP { preimage, .. } => Some(key_hash(preimage)),
            _ => None,
        }
    }

    /// The value of a live record.
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            Self::Live { value, .. } | Self::LiveP { value, .. } => Some(value),
            _ => None,
        }
    }
}

/// One SUCCESS chunk of `qmdb_twigs/1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwigChunk {
    /// The twig.
    pub twig_id: u64,
    /// Its active bits at the pivot.
    pub bits: [u8; TWIG_BITS_LEN],
    /// Its records from the request's start slot (none for `BITS_ONLY`).
    pub records: Vec<Record>,
}

impl TwigChunk {
    /// The wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut b = Vec::with_capacity(8 + TWIG_BITS_LEN + 4 + self.records.len() * 40);
        b.extend_from_slice(&self.twig_id.to_le_bytes());
        b.extend_from_slice(&self.bits);
        b.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for r in &self.records {
            b.push(r.kind());
            match r {
                Record::Live { key_hash, value } => {
                    if value.len() > MAX_RECORD_VALUE as usize {
                        return Err(invalid("syncwire: record value too large"));
                    }
                    b.extend_from_slice(key_hash.as_slice());
                    b.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    b.extend_from_slice(value);
                }
                Record::LiveP { preimage, value } => {
                    if preimage.len() != 20 && preimage.len() != 52 {
                        return Err(invalid(format!("syncwire: preimage of {} bytes", preimage.len())));
                    }
                    if value.len() > MAX_RECORD_VALUE as usize {
                        return Err(invalid("syncwire: record value too large"));
                    }
                    b.push(preimage.len() as u8);
                    b.extend_from_slice(preimage);
                    b.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    b.extend_from_slice(value);
                }
                Record::Dead { leaf_hash } => b.extend_from_slice(leaf_hash.as_slice()),
                Record::Hollow { leaf_root } => {
                    b.extend_from_slice(&(TWIG_SIZE as u16).to_le_bytes());
                    b.extend_from_slice(leaf_root.as_slice());
                }
            }
        }
        Ok(b)
    }

    /// Decodes the shape ([`verify_twig`] checks it).
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader(b);
        let twig_id = r.u64()?;
        let mut bits = [0u8; TWIG_BITS_LEN];
        bits.copy_from_slice(r.take(TWIG_BITS_LEN)?);
        let k = r.u32()?;
        if u64::from(k) > TWIG_SIZE || k as usize > r.0.len() {
            return Err(invalid(format!("syncwire: {k} records")));
        }
        let mut records = Vec::with_capacity(k as usize);
        for _ in 0..k {
            let kind = r.u8()?;
            records.push(match kind {
                KIND_LIVE => Record::Live { key_hash: r.hash()?, value: r.value()? },
                KIND_LIVE_P => {
                    let len = r.u8()?;
                    if len != 20 && len != 52 {
                        return Err(invalid(format!("syncwire: preimage length {len}")));
                    }
                    Record::LiveP { preimage: r.take(len as usize)?.to_vec(), value: r.value()? }
                }
                KIND_DEAD => Record::Dead { leaf_hash: r.hash()? },
                KIND_HOLLOW => {
                    let n = r.u16()?;
                    if u64::from(n) != TWIG_SIZE {
                        return Err(invalid(format!("syncwire: hollow count {n}")));
                    }
                    Record::Hollow { leaf_root: r.hash()? }
                }
                other => return Err(invalid(format!("syncwire: record kind {other}"))),
            });
        }
        if !r.done() {
            return Err(invalid(format!("syncwire: {} trailing bytes", r.0.len())));
        }
        Ok(Self { twig_id, bits, records })
    }
}

/// The 17-byte END trailer of `qmdb_twigs/1`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TwigsEnd {
    /// The first twig not served.
    pub next_twig: u64,
    /// The first slot not covered by the records sent.
    pub next_slot: u64,
    /// The END reason.
    pub reason: u8,
}

impl TwigsEnd {
    /// The wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(END_LEN);
        b.extend_from_slice(&self.next_twig.to_le_bytes());
        b.extend_from_slice(&self.next_slot.to_le_bytes());
        b.push(self.reason);
        b
    }

    /// Decodes.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != END_LEN {
            return Err(WireError::Length);
        }
        let mut r = Reader(b);
        let e = Self { next_twig: r.u64()?, next_slot: r.u64()?, reason: r.u8()? };
        if e.reason > MAX_REASON {
            return Err(invalid(format!("syncwire: unknown END reason {}", e.reason)));
        }
        Ok(e)
    }
}

// ---------------------------------------------------------------------------
// Hashing (§1.5)

/// `BLAKE3(preimage)`: an account key (20 bytes) or a storage key (52).
pub fn key_hash(preimage: &[u8]) -> B256 {
    B256::from(*blake3::hash(preimage).as_bytes())
}

/// `BLAKE3(0x01 ‖ keyHash ‖ value)`.
pub fn leaf_hash(key_hash: &B256, value: &[u8]) -> B256 {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(key_hash.as_slice());
    h.update(value);
    B256::from(*h.finalize().as_bytes())
}

/// `BLAKE3(left ‖ right)`.
pub fn node_hash(l: &B256, r: &B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(l.as_slice());
    buf[32..].copy_from_slice(r.as_slice());
    B256::from(*blake3::hash(&buf).as_bytes())
}

/// `BLAKE3(0x03 ‖ bits)`.
pub fn bits_root(bits: &[u8; TWIG_BITS_LEN]) -> B256 {
    let mut buf = [0u8; 1 + TWIG_BITS_LEN];
    buf[0] = 0x03;
    buf[1..].copy_from_slice(bits);
    B256::from(*blake3::hash(&buf).as_bytes())
}

/// `node(leafRoot, bitsRoot)`.
pub fn twig_root(t: &TwigRoots) -> B256 {
    node_hash(&t.leaf_root, &t.bits_root)
}

/// Folds up to 2048 leaf hashes (the rest null, 32 zero bytes) over a twig's
/// 11 levels.
pub fn fold_twig_leaves(leaves: &[B256]) -> B256 {
    let mut level = vec![B256::ZERO; TWIG_SIZE as usize];
    level[..leaves.len()].copy_from_slice(leaves);
    let mut w = TWIG_SIZE as usize;
    while w > 1 {
        for i in 0..w / 2 {
            level[i] = node_hash(&level[2 * i], &level[2 * i + 1]);
        }
        w /= 2;
    }
    level[0]
}

/// `next_pow2(twig_count)`, 1 for 0 or 1.
pub const fn upper_width(twig_count: u64) -> u64 {
    let mut w = 1u64;
    while w < twig_count {
        w <<= 1;
    }
    w
}

/// Folds twig roots padded with zero leaves to the next power of two; one
/// twig is its own root, none is zero.
pub fn upper_root(twig_roots: &[B256]) -> B256 {
    if twig_roots.is_empty() {
        return B256::ZERO;
    }
    let mut w = upper_width(twig_roots.len() as u64) as usize;
    let mut level = vec![B256::ZERO; w];
    level[..twig_roots.len()].copy_from_slice(twig_roots);
    while w > 1 {
        for i in 0..w / 2 {
            level[i] = node_hash(&level[2 * i], &level[2 * i + 1]);
        }
        w /= 2;
    }
    level[0]
}

/// The manifest range proof for leaves `[first, first+n)` of the upper tree
/// over `twig_roots`: bottom-up, at each level the left boundary's outside
/// sibling (if any) before the right boundary's.
pub fn range_proof(twig_roots: &[B256], first: u64, n: u64) -> Result<Vec<B256>, WireError> {
    let total = twig_roots.len() as u64;
    if n == 0 || first >= total || n > total - first {
        return Err(invalid(format!("syncwire: range [{first},+{n}) outside {total} twigs")));
    }
    let mut w = upper_width(total) as usize;
    let mut level = vec![B256::ZERO; w];
    level[..twig_roots.len()].copy_from_slice(twig_roots);
    let (mut lo, mut hi) = (first as usize, (first + n - 1) as usize);
    let mut proof = Vec::new();
    while w > 1 {
        if lo % 2 == 1 {
            proof.push(level[lo - 1]);
        }
        if hi % 2 == 0 {
            proof.push(level[hi + 1]);
        }
        let next: Vec<B256> = (0..w / 2).map(|i| node_hash(&level[2 * i], &level[2 * i + 1])).collect();
        level = next;
        lo /= 2;
        hi /= 2;
        w /= 2;
    }
    Ok(proof)
}

/// Folds the twig roots of `[first, first + roots.len())` with `proof`
/// ([`range_proof`]'s order) and compares with `root`. Every proof node must
/// be used.
pub fn verify_range(root: &B256, twig_count: u64, first: u64, roots: &[B256], proof: &[B256]) -> Result<(), WireError> {
    let n = roots.len() as u64;
    if n == 0 || first >= twig_count || n > twig_count - first {
        return Err(invalid(format!("syncwire: range [{first},+{n}) outside {twig_count} twigs")));
    }
    let mut w = upper_width(twig_count);
    let (mut lo, mut hi) = (first, first + n - 1);
    let mut cur: Vec<B256> = roots.to_vec();
    let mut proof = proof.iter();
    while w > 1 {
        if lo % 2 == 1 {
            cur.insert(0, *proof.next().ok_or(WireError::Proof)?);
            lo -= 1;
        }
        if hi % 2 == 0 {
            cur.push(*proof.next().ok_or(WireError::Proof)?);
            hi += 1;
        }
        cur = cur.chunks(2).map(|pair| node_hash(&pair[0], &pair[1])).collect();
        lo /= 2;
        hi /= 2;
        w /= 2;
    }
    if proof.next().is_some() || cur.len() != 1 || cur[0] != *root {
        return Err(WireError::Proof);
    }
    Ok(())
}

/// Checks a page against the anchored root and the twig count its
/// `next_slot` implies.
pub fn verify_manifest_page(p: &ManifestPage, want_root: &B256) -> Result<(), WireError> {
    if p.root != *want_root {
        return Err(invalid(format!("syncwire: manifest root {:x} is not the anchored root {want_root:x}", p.root)));
    }
    let want = p.next_slot.div_ceil(TWIG_SIZE);
    if p.twig_count != want {
        return Err(invalid(format!(
            "syncwire: twig_count {} for next_slot {} (want {want})",
            p.twig_count, p.next_slot
        )));
    }
    if p.twig_count == 0 {
        if !p.twigs.is_empty() || !p.proof.is_empty() || !p.root.is_zero() {
            return Err(WireError::Proof);
        }
        return Ok(());
    }
    let roots: Vec<B256> = p.twigs.iter().map(twig_root).collect();
    verify_range(&p.root, p.twig_count, p.first_twig, &roots, &p.proof)
}

/// The slots `[start, end)` a chunk for twig `id` covers at a pivot with
/// `next_slot`, asked from `from_slot` (`end <= start`: none).
pub const fn twig_slots(id: u64, next_slot: u64, from_slot: u64) -> (u64, u64) {
    let base = id * TWIG_SIZE;
    let start = if from_slot > base { from_slot } else { base };
    let end = if next_slot < base + TWIG_SIZE { next_slot } else { base + TWIG_SIZE };
    (start, end)
}

fn bit(bits: &[u8; TWIG_BITS_LEN], local: usize) -> bool {
    bits[local / 8] & (1 << (local % 8)) != 0
}

/// Checks one full twig chunk (records from the twig's first slot) against
/// its manifest entry: the bits hash to `bits_root`; the records fold to
/// `leaf_root` with null padding; the tag rule holds (LIVE / LIVE_P iff the
/// slot's bit is set; HOLLOW only as the sole record of a full all-dead
/// twig); no bit is set past the appended slots.
pub fn verify_twig(c: &TwigChunk, want: &TwigRoots, next_slot: u64) -> Result<(), WireError> {
    let id = c.twig_id;
    if bits_root(&c.bits) != want.bits_root {
        return Err(invalid(format!("syncwire: twig {id} bits do not hash to bits_root")));
    }
    let (start, end) = twig_slots(id, next_slot, 0);
    if end <= start {
        return Err(invalid(format!("syncwire: twig {id} is past next_slot {next_slot}")));
    }
    if let [Record::Hollow { leaf_root }] = c.records.as_slice() {
        if end - start != TWIG_SIZE {
            return Err(invalid(format!("syncwire: hollow record for the partial twig {id}")));
        }
        if c.bits.iter().any(|b| *b != 0) {
            return Err(invalid(format!("syncwire: hollow record for twig {id} with live bits")));
        }
        if *leaf_root != want.leaf_root {
            return Err(invalid(format!("syncwire: twig {id} hollow leaf_root mismatch")));
        }
        return Ok(());
    }
    if c.records.len() as u64 != end - start {
        return Err(invalid(format!(
            "syncwire: twig {id} carries {} records for {} slots",
            c.records.len(),
            end - start
        )));
    }
    let mut leaves = Vec::with_capacity(c.records.len());
    for (local, r) in c.records.iter().enumerate() {
        let live = bit(&c.bits, local);
        match r {
            Record::Live { .. } | Record::LiveP { .. } => {
                if !live {
                    return Err(invalid(format!("syncwire: twig {id} slot {local} LIVE with a clear bit")));
                }
                let key = r.key_hash().unwrap_or_default();
                leaves.push(leaf_hash(&key, r.value().unwrap_or_default()));
            }
            Record::Dead { leaf_hash } => {
                if live {
                    return Err(invalid(format!("syncwire: twig {id} slot {local} DEAD with a set bit")));
                }
                leaves.push(*leaf_hash);
            }
            Record::Hollow { .. } => {
                return Err(invalid(format!("syncwire: twig {id} slot {local} record kind {KIND_HOLLOW}")))
            }
        }
    }
    for local in (end - start) as usize..TWIG_SIZE as usize {
        if bit(&c.bits, local) {
            return Err(invalid(format!("syncwire: twig {id} bit {local} set past next_slot")));
        }
    }
    if fold_twig_leaves(&leaves) != want.leaf_root {
        return Err(invalid(format!("syncwire: twig {id} records do not fold to leaf_root")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The portable 0x03 snapshot, by twig

const PORTABLE_MAGIC_03: [u8; 8] = *b"N42QMDB\x03";
const PORTABLE_KIND_DEAD: u8 = 0;
const PORTABLE_KIND_LIVE: u8 = 1;
const PORTABLE_KIND_TOMB: u8 = 2;
const PORTABLE_KIND_DEAD_TWIG: u8 = 3;

/// The `0x03` header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortableHeader {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis hash.
    pub genesis_hash: B256,
    /// P.
    pub block_number: u64,
    /// hash(P).
    pub block_hash: B256,
    /// The state root after P.
    pub root: B256,
    /// The first unappended slot.
    pub next_slot: u64,
}

/// One twig of a pivot in wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedTwig {
    /// The twig.
    pub id: u64,
    /// Its active bits.
    pub bits: [u8; TWIG_BITS_LEN],
    /// Its records from the twig's first slot (or one HOLLOW record).
    pub records: Vec<Record>,
    /// Its manifest entry.
    pub roots: TwigRoots,
}

/// Parses a `0x03` snapshot into twigs and checks they fold to the header's
/// root and the trailing BLAKE3 digest.
pub fn twigs_from_portable(encoded: &[u8]) -> Result<(PortableHeader, Vec<ServedTwig>), WireError> {
    if encoded.len() < 144 + 32 {
        return Err(invalid("syncwire: portable snapshot truncated"));
    }
    let (payload, digest) = encoded.split_at(encoded.len() - 32);
    if blake3::hash(payload).as_bytes() != digest {
        return Err(invalid("syncwire: portable snapshot digest mismatch"));
    }
    if payload[..8] != PORTABLE_MAGIC_03 {
        return Err(invalid("syncwire: not a 0x03 portable snapshot"));
    }
    let mut r = Reader(&payload[8..]);
    let h = PortableHeader {
        chain_id: r.u64()?,
        genesis_hash: r.hash()?,
        block_number: r.u64()?,
        block_hash: r.hash()?,
        root: r.hash()?,
        next_slot: r.u64()?,
    };
    let entries = r.u64()?;
    let _tombstones = r.u64()?;
    if entries != h.next_slot {
        return Err(invalid(format!("syncwire: entry_count {entries} != next_slot {}", h.next_slot)));
    }
    let twig_count = h.next_slot.div_ceil(TWIG_SIZE);
    let mut twigs: Vec<ServedTwig> = (0..twig_count)
        .map(|id| ServedTwig { id, bits: [0; TWIG_BITS_LEN], records: Vec::new(), roots: TwigRoots::default() })
        .collect();
    let mut leaves = vec![B256::ZERO; TWIG_SIZE as usize];
    let mut slot = 0u64;
    while slot < h.next_slot {
        let s = r.u64()?;
        if s != slot {
            return Err(invalid(format!("syncwire: record for slot {s}, expected {slot}")));
        }
        let kind = r.u8()?;
        let tw = &mut twigs[(slot / TWIG_SIZE) as usize];
        let local = (slot % TWIG_SIZE) as usize;
        match kind {
            PORTABLE_KIND_LIVE | PORTABLE_KIND_DEAD => {
                let key = r.hash()?;
                let value = r.value()?;
                let leaf = leaf_hash(&key, &value);
                leaves[local] = leaf;
                if kind == PORTABLE_KIND_LIVE {
                    tw.bits[local / 8] |= 1 << (local % 8);
                    tw.records.push(Record::Live { key_hash: key, value });
                } else {
                    tw.records.push(Record::Dead { leaf_hash: leaf });
                }
                slot += 1;
            }
            PORTABLE_KIND_TOMB => {
                let leaf = r.hash()?;
                leaves[local] = leaf;
                tw.records.push(Record::Dead { leaf_hash: leaf });
                slot += 1;
            }
            PORTABLE_KIND_DEAD_TWIG => {
                let n = r.u16()?;
                if u64::from(n) != TWIG_SIZE || local != 0 || slot + TWIG_SIZE > h.next_slot {
                    return Err(invalid(format!("syncwire: dead-twig record at slot {slot} count {n}")));
                }
                let leaf_root = r.hash()?;
                tw.records = vec![Record::Hollow { leaf_root }];
                tw.roots.leaf_root = leaf_root;
                slot += TWIG_SIZE;
            }
            other => return Err(invalid(format!("syncwire: portable record kind {other}"))),
        }
        if slot.is_multiple_of(TWIG_SIZE) || slot == h.next_slot {
            let id = (slot - 1) / TWIG_SIZE;
            let tw = &mut twigs[id as usize];
            if !matches!(tw.records.as_slice(), [Record::Hollow { .. }]) {
                let n = (slot - id * TWIG_SIZE) as usize;
                tw.roots.leaf_root = fold_twig_leaves(&leaves[..n]);
            }
            tw.roots.bits_root = bits_root(&tw.bits);
            leaves.iter_mut().for_each(|l| *l = B256::ZERO);
        }
    }
    if !r.done() {
        return Err(invalid(format!("syncwire: {} bytes after the last record", r.0.len())));
    }
    let roots: Vec<B256> = twigs.iter().map(|t| twig_root(&t.roots)).collect();
    let got = upper_root(&roots);
    if got != h.root {
        return Err(invalid(format!("syncwire: twigs fold to {got:x}, header root {:x}", h.root)));
    }
    Ok((h, twigs))
}

/// Writes the `0x03` snapshot of verified twigs (ascending, complete, each
/// from its first slot). LIVE_P records become kind 1: the portable file
/// carries the key hash only.
pub fn assemble_portable(h: &PortableHeader, twigs: &[ServedTwig]) -> Result<Vec<u8>, WireError> {
    let mut tombstones = 0u64;
    let mut body = Vec::new();
    let mut slot = 0u64;
    for (i, tw) in twigs.iter().enumerate() {
        if tw.id != i as u64 {
            return Err(invalid(format!("syncwire: twig {} at position {i}", tw.id)));
        }
        let (start, end) = twig_slots(tw.id, h.next_slot, 0);
        if let [Record::Hollow { leaf_root }] = tw.records.as_slice() {
            body.extend_from_slice(&start.to_le_bytes());
            body.push(PORTABLE_KIND_DEAD_TWIG);
            body.extend_from_slice(&(TWIG_SIZE as u16).to_le_bytes());
            body.extend_from_slice(leaf_root.as_slice());
            tombstones += 1;
            slot = end;
            continue;
        }
        if tw.records.len() as u64 != end.saturating_sub(start) {
            return Err(invalid(format!(
                "syncwire: twig {} has {} records for {} slots",
                tw.id,
                tw.records.len(),
                end.saturating_sub(start)
            )));
        }
        for r in &tw.records {
            body.extend_from_slice(&slot.to_le_bytes());
            match r {
                Record::Live { .. } | Record::LiveP { .. } => {
                    let value = r.value().unwrap_or_default();
                    body.push(PORTABLE_KIND_LIVE);
                    body.extend_from_slice(r.key_hash().unwrap_or_default().as_slice());
                    body.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    body.extend_from_slice(value);
                }
                Record::Dead { leaf_hash } => {
                    body.push(PORTABLE_KIND_TOMB);
                    body.extend_from_slice(leaf_hash.as_slice());
                    tombstones += 1;
                }
                Record::Hollow { .. } => {
                    return Err(invalid(format!("syncwire: record kind {KIND_HOLLOW} inside twig {}", tw.id)))
                }
            }
            slot += 1;
        }
    }
    if slot != h.next_slot {
        return Err(invalid(format!("syncwire: twigs cover {slot} slots, next_slot {}", h.next_slot)));
    }
    let mut out = Vec::with_capacity(176 + body.len() + 32);
    out.extend_from_slice(&PORTABLE_MAGIC_03);
    out.extend_from_slice(&h.chain_id.to_le_bytes());
    out.extend_from_slice(h.genesis_hash.as_slice());
    out.extend_from_slice(&h.block_number.to_le_bytes());
    out.extend_from_slice(h.block_hash.as_slice());
    out.extend_from_slice(h.root.as_slice());
    out.extend_from_slice(&h.next_slot.to_le_bytes());
    out.extend_from_slice(&h.next_slot.to_le_bytes());
    out.extend_from_slice(&tombstones.to_le_bytes());
    out.extend_from_slice(&body);
    let digest = *blake3::hash(&out).as_bytes();
    out.extend_from_slice(&digest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Server core

/// One reply chunk before framing: a result code and its payload (an error
/// chunk's payload is its UTF-8 message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyChunk {
    /// The result code.
    pub code: u8,
    /// The payload.
    pub payload: Vec<u8>,
}

impl ReplyChunk {
    /// A SUCCESS chunk.
    pub const fn success(payload: Vec<u8>) -> Self {
        Self { code: CODE_SUCCESS, payload }
    }

    /// An error chunk; the message is cut at 256 bytes.
    pub fn error(code: u8, msg: impl Into<String>) -> Self {
        let mut msg: String = msg.into();
        if msg.len() > 256 {
            let mut cut = 256;
            while !msg.is_char_boundary(cut) {
                cut -= 1;
            }
            msg.truncate(cut);
        }
        Self { code, payload: msg.into_bytes() }
    }

    /// The message of an error chunk.
    pub fn message(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
}

/// Where a pivot's twigs come from, one twig at a time: a server never
/// materialises a pivot's whole state, only the twig a request is serving
/// (at most 2048 records). A node backs it with a pinned view of its QMDB
/// store; tests with [`MemTwigs`].
pub trait TwigSource: Send + Sync + std::fmt::Debug {
    /// Twig `id` at the pivot: its bits and its records from the twig's
    /// first slot (one HOLLOW record for a hollow twig). `Err` is a twig the
    /// source can no longer reconstruct (served as `0x02`).
    fn twig(&self, id: u64) -> Result<ServedTwig, String>;
}

/// A [`TwigSource`] holding every twig in memory (tests, small chains).
#[derive(Debug, Clone, Default)]
pub struct MemTwigs(pub Vec<ServedTwig>);

impl TwigSource for MemTwigs {
    fn twig(&self, id: u64) -> Result<ServedTwig, String> {
        self.0.get(id as usize).cloned().ok_or_else(|| format!("twig {id} absent"))
    }
}

/// One servable pivot: its header fields, every twig's manifest entry (96
/// bytes a twig with its root), and the source of its twigs.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// P.
    pub pivot: u64,
    /// hash(P).
    pub pivot_hash: B256,
    /// The state root after P (header(P+1).Root).
    pub root: B256,
    /// The first unappended slot at P.
    pub next_slot: u64,
    /// Every twig's manifest entry.
    pub entries: Vec<TwigRoots>,
    roots: Vec<B256>,
    source: std::sync::Arc<dyn TwigSource>,
}

impl Snapshot {
    /// Pivot `(number, hash)` with its manifest entries and twig source;
    /// refused when the entries do not fold to `root` or miscount
    /// `next_slot`.
    pub fn new(
        pivot: u64,
        pivot_hash: B256,
        root: B256,
        next_slot: u64,
        entries: Vec<TwigRoots>,
        source: std::sync::Arc<dyn TwigSource>,
    ) -> Result<Self, WireError> {
        if entries.len() as u64 != next_slot.div_ceil(TWIG_SIZE) {
            return Err(invalid(format!("syncwire: {} twigs for next_slot {next_slot}", entries.len())));
        }
        let roots: Vec<B256> = entries.iter().map(twig_root).collect();
        let got = upper_root(&roots);
        if got != root {
            return Err(invalid(format!("syncwire: twigs fold to {got:x}, root {root:x}")));
        }
        Ok(Self { pivot, pivot_hash, root, next_slot, entries, roots, source })
    }

    /// A snapshot over in-memory twigs.
    pub fn from_twigs(
        pivot: u64,
        pivot_hash: B256,
        root: B256,
        next_slot: u64,
        twigs: Vec<ServedTwig>,
    ) -> Result<Self, WireError> {
        let entries = twigs.iter().map(|t| t.roots).collect();
        Self::new(pivot, pivot_hash, root, next_slot, entries, std::sync::Arc::new(MemTwigs(twigs)))
    }

    /// Twig `id` from the source, checked against its manifest entry: a
    /// source that drifted from its pinned pivot is caught by the server,
    /// not left to the client.
    pub fn twig(&self, id: u64) -> Result<ServedTwig, String> {
        let want = self.entries.get(id as usize).ok_or_else(|| format!("twig {id} absent"))?;
        let tw = self.source.twig(id)?;
        let chunk = TwigChunk { twig_id: id, bits: tw.bits, records: tw.records };
        verify_twig(&chunk, want, self.next_slot).map_err(|e| format!("twig {id} no longer reconstructs: {e}"))?;
        Ok(ServedTwig { id, bits: chunk.bits, records: chunk.records, roots: *want })
    }

    /// A snapshot from a portable `0x03` file (checked to fold to its root),
    /// held in memory (tests, small chains), with every live key's preimage
    /// looked up by its key hash: a live record whose preimage is known goes
    /// on the wire as LIVE_P, the others as LIVE.
    pub fn from_portable(encoded: &[u8], mut preimage: impl FnMut(&B256) -> Option<Vec<u8>>) -> Result<Self, WireError> {
        let (h, mut twigs) = twigs_from_portable(encoded)?;
        for tw in &mut twigs {
            for r in &mut tw.records {
                if let Record::Live { key_hash, value } = r
                    && let Some(p) = preimage(key_hash).filter(|p| p.len() == 20 || p.len() == 52)
                {
                    *r = Record::LiveP { preimage: p, value: std::mem::take(value) };
                }
            }
        }
        Self::from_twigs(h.block_number, h.block_hash, h.root, h.next_slot, twigs)
    }

    /// `ceil(next_slot / 2048)`.
    pub fn twig_count(&self) -> u64 {
        self.entries.len() as u64
    }
}

/// How many published pivots a server keeps servable by default.
pub const KEPT_PIVOTS: usize = 3;

/// The servable snapshots of one node: the newest and the `keep - 1` before
/// it, so a client mid-transfer is not cut off by refreshes.
#[derive(Debug)]
pub struct StateServer {
    keep: usize,
    snaps: Mutex<std::collections::VecDeque<std::sync::Arc<Snapshot>>>,
}

impl Default for StateServer {
    fn default() -> Self {
        Self::new(KEPT_PIVOTS)
    }
}

impl StateServer {
    /// A server keeping `keep` (at least 2) pivots servable.
    pub fn new(keep: usize) -> Self {
        Self { keep: keep.max(2), snaps: Mutex::new(std::collections::VecDeque::new()) }
    }

    /// Installs `snap` as the current snapshot; the oldest beyond `keep` is
    /// dropped (with whatever its source pins). The same pivot again is a
    /// no-op.
    pub fn publish(&self, snap: Snapshot) {
        let mut g = self.snaps.lock().unwrap_or_else(|p| p.into_inner());
        if g.front().is_some_and(|cur| cur.pivot_hash == snap.pivot_hash) {
            return;
        }
        g.push_front(std::sync::Arc::new(snap));
        g.truncate(self.keep);
    }

    /// The newest published snapshot.
    pub fn current(&self) -> Option<std::sync::Arc<Snapshot>> {
        self.snaps.lock().unwrap_or_else(|p| p.into_inner()).front().cloned()
    }

    /// Every kept snapshot, newest first.
    pub fn kept(&self) -> Vec<std::sync::Arc<Snapshot>> {
        self.snaps.lock().unwrap_or_else(|p| p.into_inner()).iter().cloned().collect()
    }

    /// A kept snapshot with pivot hash `h`.
    pub fn lookup(&self, h: &B256) -> Option<std::sync::Arc<Snapshot>> {
        self.snaps.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|s| s.pivot_hash == *h).cloned()
    }

    /// The `qmdb_status/1` answer: the newest pivot as both ends, as gov5
    /// advertises (older kept pivots stay servable by hash but are not a
    /// contiguous window).
    pub fn status(&self, earliest_body: u64) -> QmdbStatus {
        let mut st = QmdbStatus { earliest_body, flags: STATUS_FLAG_CODE, ..Default::default() };
        if let Some(cur) = self.current() {
            st.pivot_lo = cur.pivot;
            st.pivot_hi = cur.pivot;
            st.pivot_hi_hash = cur.pivot_hash;
            st.flags |= STATUS_FLAG_TWIGS;
        }
        st
    }
}

/// The reply to a `qmdb_status/1` request payload.
pub fn serve_status(server: Option<&StateServer>, earliest_body: u64, request: &[u8]) -> ReplyChunk {
    if !request.is_empty() {
        return ReplyChunk::error(CODE_INVALID_REQUEST, "qmdb_status takes an empty request");
    }
    let st = server.map_or(QmdbStatus { earliest_body, ..Default::default() }, |s| s.status(earliest_body));
    ReplyChunk::success(st.encode())
}

/// The reply to one `qmdb_manifest/1` request.
pub fn serve_manifest(snap: Option<&Snapshot>, req: &ManifestRequest) -> ReplyChunk {
    let Some(snap) = snap else {
        return ReplyChunk::error(CODE_RESOURCE_UNAVAILABLE, "pivot not servable");
    };
    let mut page = ManifestPage {
        pivot_number: snap.pivot,
        pivot_hash: snap.pivot_hash,
        root: snap.root,
        next_slot: snap.next_slot,
        twig_count: snap.twig_count(),
        first_twig: req.first_twig,
        ..Default::default()
    };
    let total = snap.twig_count();
    if total == 0 && req.first_twig == 0 {
        return ReplyChunk::success(page.encode());
    }
    if req.first_twig >= total {
        return ReplyChunk::error(CODE_INVALID_REQUEST, format!("first_twig {} >= twig_count {total}", req.first_twig));
    }
    let n = u64::from(req.count).min(total - req.first_twig);
    let range = req.first_twig as usize..(req.first_twig + n) as usize;
    page.twigs = snap.entries[range].to_vec();
    match range_proof(&snap.roots, req.first_twig, n) {
        Ok(proof) => page.proof = proof,
        Err(e) => return ReplyChunk::error(CODE_SERVER_ERROR, e.to_string()),
    }
    ReplyChunk::success(page.encode())
}

/// The records of `tw` from slot `max(base, from_slot)`. A hollow twig is
/// served whole when the request starts at its first slot, else without
/// records.
fn twig_records_from(tw: &ServedTwig, next_slot: u64, from_slot: u64) -> Vec<Record> {
    let (start, end) = twig_slots(tw.id, next_slot, from_slot);
    if end <= start {
        return Vec::new();
    }
    let base = tw.id * TWIG_SIZE;
    if matches!(tw.records.as_slice(), [Record::Hollow { .. }]) {
        return if start == base { tw.records.clone() } else { Vec::new() };
    }
    tw.records.get((start - base) as usize..(end - base) as usize).map(<[Record]>::to_vec).unwrap_or_default()
}

/// The reply to one `qmdb_twigs/1` request: one chunk per twig then END, or
/// one error chunk. `write` takes each chunk as it is made and returns false
/// when the stream is gone.
pub fn serve_twigs(snap: Option<&Snapshot>, req: &TwigsRequest, mut write: impl FnMut(ReplyChunk) -> bool) {
    let Some(snap) = snap else {
        write(ReplyChunk::error(CODE_RESOURCE_UNAVAILABLE, "pivot not servable"));
        return;
    };
    let total = snap.twig_count();
    if req.first_twig >= total {
        write(ReplyChunk::error(CODE_INVALID_REQUEST, format!("first_twig {} >= twig_count {total}", req.first_twig)));
        return;
    }
    let budget = req.budget();
    let mut served = 0u64;
    let mut end = TwigsEnd { next_twig: req.first_twig, next_slot: 0, reason: REASON_COMPLETE };
    let last = req.first_twig + u64::from(req.twig_count);
    for id in req.first_twig..last {
        if id >= total {
            end.reason = REASON_NOT_AVAILABLE;
            break;
        }
        let tw = match snap.twig(id) {
            Ok(tw) => tw,
            Err(e) => {
                write(ReplyChunk::error(CODE_SERVER_ERROR, e));
                return;
            }
        };
        let records = if req.bits_only() { Vec::new() } else { twig_records_from(&tw, snap.next_slot, req.from_slot) };
        let payload = match (TwigChunk { twig_id: id, bits: tw.bits, records }).encode() {
            Ok(p) => p,
            Err(e) => {
                write(ReplyChunk::error(CODE_SERVER_ERROR, e.to_string()));
                return;
            }
        };
        if id > req.first_twig && served + payload.len() as u64 > budget {
            end.reason = REASON_BYTE_BUDGET;
            break;
        }
        served += payload.len() as u64;
        if !write(ReplyChunk::success(payload)) {
            return;
        }
        end.next_twig = id + 1;
    }
    end.next_slot = (end.next_twig * TWIG_SIZE).min(snap.next_slot).max(req.from_slot);
    write(ReplyChunk { code: CODE_END, payload: end.encode() });
}

/// A `qmdb_twigs/1` reply that contradicts its request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("qmdb_twigs: provable fault: {0}")]
pub struct TwigsFault(pub String);

/// Reads one `qmdb_twigs/1` reply (its chunks, in order): the twig chunks
/// from `req.first_twig`, and the END (`None` when the stream ended without
/// one). An error chunk before any twig is returned as `Err` with its code.
pub fn read_twigs(
    chunks: &[ReplyChunk],
    req: &TwigsRequest,
) -> Result<(Vec<TwigChunk>, Option<TwigsEnd>), ReadError> {
    let mut out = Vec::new();
    for c in chunks {
        match c.code {
            CODE_SUCCESS => {
                let tc = TwigChunk::decode(&c.payload).map_err(|e| ReadError::Fault(e.to_string()))?;
                let want = req.first_twig + out.len() as u64;
                if tc.twig_id != want || out.len() >= req.twig_count as usize {
                    return Err(ReadError::Fault(format!("chunk {} is twig {}", out.len(), tc.twig_id)));
                }
                if req.bits_only() && !tc.records.is_empty() {
                    return Err(ReadError::Fault("records in a BITS_ONLY reply".into()));
                }
                out.push(tc);
            }
            CODE_END => {
                let e = TwigsEnd::decode(&c.payload).map_err(|e| ReadError::Fault(format!("END: {e}")))?;
                let next = req.first_twig + out.len() as u64;
                if e.next_twig != next {
                    return Err(ReadError::Fault(format!(
                        "END next_twig {} after {} chunks from {}",
                        e.next_twig,
                        out.len(),
                        req.first_twig
                    )));
                }
                if (e.reason == REASON_COMPLETE) != (e.next_twig == req.first_twig + u64::from(req.twig_count)) {
                    return Err(ReadError::Fault(format!("END reason {} at twig {}", e.reason, e.next_twig)));
                }
                return Ok((out, Some(e)));
            }
            code => {
                if !out.is_empty() {
                    return Ok((out, None));
                }
                return Err(ReadError::Code { code, message: c.message() });
            }
        }
    }
    Ok((out, None))
}

/// A reply that could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The server answered an error code.
    #[error("remote returned code {code:#04x}: {message}")]
    Code {
        /// The code.
        code: u8,
        /// Its message.
        message: String,
    },
    /// The reply contradicts the request (a provable fault).
    #[error("provable fault: {0}")]
    Fault(String),
}

/// Reads the single chunk of a `qmdb_status/1` or `qmdb_manifest/1` reply.
pub fn read_single(chunks: &[ReplyChunk]) -> Result<&[u8], ReadError> {
    match chunks.first() {
        Some(c) if c.code == CODE_SUCCESS => Ok(&c.payload),
        Some(c) => Err(ReadError::Code { code: c.code, message: c.message() }),
        None => Err(ReadError::Fault("empty reply".into())),
    }
}

#[cfg(test)]
#[path = "qmdb_tests.rs"]
mod tests;
