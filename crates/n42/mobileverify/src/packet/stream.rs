// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `StreamPacket` V2 (`cmd/evmsdk/stream_packet.go:50-183`, header in
//! `wire.go`). Every length and count is u32 little-endian:
//!
//! ```text
//! "N2" ‖ 0x01 ‖ flags (0x01 iff bytecodes) ‖ block_hash 32
//! ‖ header_len ‖ header ‖ tx_count ‖ { tx_len ‖ tx }*
//! ‖ read_log_len ‖ read_log ‖ bytecode_count ‖ { code_hash 32 ‖ code_len ‖ code }*
//! ```
//!
//! The decoder caps transactions at 100 000 and bytecodes at 10 000,
//! accepts a packet that ends before `bytecode_count` when the flag is
//! clear, and ignores bytes after the last bytecode, as gov5's does.

use alloy_primitives::B256;
use bytes::Bytes;

/// Magic `"N2"`.
pub const WIRE_MAGIC: [u8; 2] = [0x4E, 0x32];
/// The only wire version.
pub const WIRE_VERSION: u8 = 0x01;
/// Flag: the packet carries bytecodes.
pub const FLAG_HAS_BYTECODES: u8 = 0x01;
/// Decoder cap on transactions.
pub const MAX_TX_COUNT: u32 = 100_000;
/// Decoder cap on bytecodes.
pub const MAX_BYTECODE_COUNT: u32 = 10_000;

/// A decoded packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamPacket {
    /// The sealed block's hash; must equal the hash of `header`.
    pub block_hash: B256,
    /// gov5 `Header.Marshal()` bytes (see [`super::header`]).
    pub header: Bytes,
    /// gov5 protobuf transactions with `from` set (see [`super::tx`]).
    pub transactions: Vec<Bytes>,
    /// The encoded read log (see [`super::read_log`]).
    pub read_log: Bytes,
    /// `(code_hash, code)`, ascending by hash.
    pub bytecodes: Vec<(B256, Bytes)>,
}

/// A packet that does not decode; texts follow gov5's errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// Shorter than the 4-byte wire header.
    #[error("stream_packet: wire: data too short for V2 header")]
    TooShort,
    /// Not `"N2"`.
    #[error("stream_packet: wire: invalid magic bytes, expected 0x4E32 (\"N2\")")]
    BadMagic,
    /// A version other than 1.
    #[error("stream_packet: wire: unsupported wire version: got {0}, expected 1")]
    BadVersion(u8),
    /// Data ended inside a field.
    #[error("stream_packet: reading {0}: stream_packet: data truncated")]
    Truncated(String),
    /// More than [`MAX_TX_COUNT`] transactions.
    #[error("stream_packet: transaction count exceeds limit: {0}")]
    TooManyTxs(u32),
    /// More than [`MAX_BYTECODE_COUNT`] bytecodes.
    #[error("stream_packet: bytecode count exceeds limit: {0}")]
    TooManyBytecodes(u32),
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn n(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        self.n(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn prefixed(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.n(len)
    }
}

impl StreamPacket {
    /// The wire flags this packet encodes with.
    pub const fn flags(&self) -> u8 {
        if self.bytecodes.is_empty() { 0 } else { FLAG_HAS_BYTECODES }
    }

    /// Encodes (gov5 `EncodeStreamPacket`); the bytecode count is always written.
    pub fn encode(&self) -> Vec<u8> {
        let size = 4 +
            32 +
            4 +
            self.header.len() +
            4 +
            self.transactions.iter().map(|t| 4 + t.len()).sum::<usize>() +
            4 +
            self.read_log.len() +
            4 +
            self.bytecodes.iter().map(|(_, c)| 36 + c.len()).sum::<usize>();
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&WIRE_MAGIC);
        out.push(WIRE_VERSION);
        out.push(self.flags());
        out.extend_from_slice(self.block_hash.as_slice());
        let put = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        };
        put(&mut out, &self.header);
        out.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());
        for tx in &self.transactions {
            put(&mut out, tx);
        }
        put(&mut out, &self.read_log);
        out.extend_from_slice(&(self.bytecodes.len() as u32).to_le_bytes());
        for (hash, code) in &self.bytecodes {
            out.extend_from_slice(hash.as_slice());
            put(&mut out, code);
        }
        out
    }

    /// Decodes (gov5 `DecodeStreamPacket`).
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::TooShort);
        }
        if data[..2] != WIRE_MAGIC {
            return Err(PacketError::BadMagic);
        }
        if data[2] != WIRE_VERSION {
            return Err(PacketError::BadVersion(data[2]));
        }
        let flags = data[3];
        let mut r = Reader { data: &data[4..], pos: 0 };
        let t = |what: &str| PacketError::Truncated(what.to_string());
        let block_hash = B256::from_slice(r.n(32).ok_or_else(|| t("block hash"))?);
        let header = Bytes::copy_from_slice(r.prefixed().ok_or_else(|| t("header"))?);
        let tx_count = r.u32().ok_or_else(|| t("tx count"))?;
        if tx_count > MAX_TX_COUNT {
            return Err(PacketError::TooManyTxs(tx_count));
        }
        let mut transactions = Vec::with_capacity(tx_count as usize);
        for i in 0..tx_count {
            transactions.push(Bytes::copy_from_slice(r.prefixed().ok_or_else(|| t(&format!("tx {i}")))?));
        }
        let read_log = Bytes::copy_from_slice(r.prefixed().ok_or_else(|| t("read log"))?);
        let mut pkt = Self { block_hash, header, transactions, read_log, bytecodes: Vec::new() };
        let Some(bc_count) = r.u32() else {
            if flags & FLAG_HAS_BYTECODES != 0 {
                return Err(t("bytecode count"));
            }
            return Ok(pkt);
        };
        if bc_count > MAX_BYTECODE_COUNT {
            return Err(PacketError::TooManyBytecodes(bc_count));
        }
        pkt.bytecodes.reserve(bc_count as usize);
        for i in 0..bc_count {
            let hash = B256::from_slice(r.n(32).ok_or_else(|| t(&format!("bytecode hash {i}")))?);
            let code = Bytes::copy_from_slice(r.prefixed().ok_or_else(|| t(&format!("bytecode {i}")))?);
            pkt.bytecodes.push((hash, code));
        }
        Ok(pkt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StreamPacket {
        StreamPacket {
            block_hash: B256::repeat_byte(0x11),
            header: Bytes::from_static(b"hdr"),
            transactions: vec![Bytes::from_static(b"t1"), Bytes::from_static(b"tx2")],
            read_log: Bytes::from_static(&[0, 0, 0, 0]),
            bytecodes: vec![(B256::repeat_byte(1), Bytes::from_static(b"\x60\x00"))],
        }
    }

    #[test]
    fn round_trip_and_layout() {
        let p = sample();
        let enc = p.encode();
        assert_eq!(&enc[..4], &[0x4E, 0x32, 0x01, 0x01]);
        assert_eq!(&enc[36..40], &3u32.to_le_bytes());
        assert_eq!(StreamPacket::decode(&enc).unwrap(), p);

        let mut empty = sample();
        empty.bytecodes.clear();
        let enc = empty.encode();
        assert_eq!(enc[3], 0);
        assert_eq!(&enc[enc.len() - 4..], &[0, 0, 0, 0]);
        assert_eq!(StreamPacket::decode(&enc).unwrap(), empty);
        // Without the trailing count and with the flag clear: accepted.
        assert_eq!(StreamPacket::decode(&enc[..enc.len() - 4]).unwrap(), empty);
    }

    #[test]
    fn rejections() {
        let enc = sample().encode();
        assert_eq!(StreamPacket::decode(&enc[..3]).unwrap_err(), PacketError::TooShort);
        assert_eq!(StreamPacket::decode(b"N3\x01\x00").unwrap_err(), PacketError::BadMagic);
        assert_eq!(
            StreamPacket::decode(b"N2\x02\x00").unwrap_err().to_string(),
            "stream_packet: wire: unsupported wire version: got 2, expected 1"
        );
        // Flag set but the bytecode section cut off.
        let mut no_bc = sample();
        no_bc.bytecodes.clear();
        let mut e = no_bc.encode();
        e.truncate(e.len() - 4);
        e[3] = 1;
        assert_eq!(
            StreamPacket::decode(&e).unwrap_err().to_string(),
            "stream_packet: reading bytecode count: stream_packet: data truncated"
        );
        let mut big = Vec::from(&enc[..36 + 4 + 3]);
        big.extend_from_slice(&100_001u32.to_le_bytes());
        assert_eq!(StreamPacket::decode(&big).unwrap_err(), PacketError::TooManyTxs(100_001));
        assert!(StreamPacket::decode(&enc[..enc.len() - 1]).is_err());
    }
}
