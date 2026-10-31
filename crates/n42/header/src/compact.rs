// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage encoding of [`N42Header`] (`docs/HEADER_FIELD_PARITY.md` 8.3).
//!
//! Additive over reth-codecs' alloy `Compact`, so every header a database
//! holds today still decodes:
//!
//! - no root: exactly alloy's `Compact` bytes (old headers decode as root
//!   `None`, and new root-less headers are byte-identical to before);
//! - a root: [`N42_HEADER_COMPACT_MARKER`], a version byte, the 32-byte root,
//!   then alloy's `Compact` bytes.
//!
//! The marker cannot start an alloy `Compact` header: that layout begins with
//! its flag bits, where bit 0 is `withdrawals_root`'s presence and bits 1-6
//! hold the byte length of `difficulty` (at most 32), so a first byte with
//! bits 1-6 all set (length 63) never occurs. A suffix would not do: the
//! alloy layout ends with `extra_data`, which takes the rest of the buffer
//! and is chosen by the block's producer.

use crate::N42Header;
use alloy_consensus::Header;
use alloy_primitives::B256;
use reth_codecs::Compact;

/// First byte of a stored header that carries a `mobile_registry_root`.
pub const N42_HEADER_COMPACT_MARKER: u8 = 0xFF;
/// Layout version after the marker.
const VERSION: u8 = 1;
/// Marker, version, root.
const PREFIX_LEN: usize = 2 + 32;

impl Compact for N42Header {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        match self.mobile_registry_root {
            None => self.inner.to_compact(buf),
            Some(root) => {
                buf.put_u8(N42_HEADER_COMPACT_MARKER);
                buf.put_u8(VERSION);
                buf.put_slice(root.as_slice());
                PREFIX_LEN + self.inner.to_compact(buf)
            }
        }
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        if len == 0 || buf.first() != Some(&N42_HEADER_COMPACT_MARKER) {
            let (inner, rest) = Header::from_compact(buf, len);
            return (Self { inner, mobile_registry_root: None }, rest);
        }
        // Compact decoding is infallible by contract; a corrupt prefix is a
        // corrupt database.
        assert!(len >= PREFIX_LEN && buf.len() >= PREFIX_LEN, "n42 header: truncated compact prefix");
        assert_eq!(buf[1], VERSION, "n42 header: unknown compact version");
        let root = B256::from_slice(&buf[2..PREFIX_LEN]);
        let (inner, rest) = Header::from_compact(&buf[PREFIX_LEN..], len - PREFIX_LEN);
        (Self { inner, mobile_registry_root: Some(root) }, rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, U256};

    fn headers() -> Vec<Header> {
        let mut out = Vec::new();
        for difficulty in [U256::ZERO, U256::from(1), U256::from(u64::MAX), U256::MAX] {
            for number in [0u64, 1001, u64::MAX] {
                for full in [false, true] {
                    out.push(Header {
                        difficulty,
                        number,
                        gas_limit: 30_000_000,
                        timestamp: 1_790_000_000,
                        extra_data: Bytes::from(vec![0xff; 140]),
                        nonce: alloy_primitives::B64::repeat_byte(0xff),
                        base_fee_per_gas: full.then_some(u64::MAX),
                        withdrawals_root: full.then_some(B256::repeat_byte(0xff)),
                        blob_gas_used: full.then_some(u64::MAX),
                        excess_blob_gas: full.then_some(u64::MAX),
                        parent_beacon_block_root: full.then_some(B256::repeat_byte(0xff)),
                        requests_hash: full.then_some(B256::repeat_byte(0xff)),
                        block_access_list_hash: full.then_some(B256::repeat_byte(0xff)),
                        slot_number: full.then_some(u64::MAX),
                        ..Default::default()
                    });
                }
            }
        }
        out
    }

    #[test]
    fn no_alloy_compact_header_starts_with_the_marker() {
        for h in headers() {
            let mut buf = Vec::new();
            h.to_compact(&mut buf);
            assert_ne!(buf[0], N42_HEADER_COMPACT_MARKER, "{h:?}");
            // The difficulty length sits in bits 1-6 of the first byte.
            let difficulty_len = (buf[0] >> 1) & 0x3f;
            assert_eq!(usize::from(difficulty_len), h.difficulty.byte_len(), "{h:?}");
        }
    }

    #[test]
    fn a_header_stored_before_the_change_decodes_as_root_none() {
        for h in headers() {
            let mut old = Vec::new();
            h.to_compact(&mut old);
            let (back, rest) = N42Header::from_compact(&old, old.len());
            assert!(rest.is_empty());
            assert_eq!(back, N42Header::from(h.clone()));
            // And a root-less N42Header stores exactly those bytes.
            let mut new = Vec::new();
            N42Header::from(h).to_compact(&mut new);
            assert_eq!(new, old);
        }
    }

    #[test]
    fn a_root_round_trips() {
        for h in headers() {
            let n42 = N42Header { inner: h, mobile_registry_root: Some(B256::repeat_byte(0x42)) };
            let mut buf = Vec::new();
            let len = n42.to_compact(&mut buf);
            assert_eq!(len, buf.len());
            assert_eq!(buf[0], N42_HEADER_COMPACT_MARKER);
            let (back, rest) = N42Header::from_compact(&buf, len);
            assert!(rest.is_empty());
            assert_eq!(back, n42);
        }
    }
}
