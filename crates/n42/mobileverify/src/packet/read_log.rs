// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The positional read log (`cmd/evmsdk/read_log.go:109-198`): `count u32 LE`,
//! then per entry
//!
//! - `0x00`: account not found;
//! - account header `< 0x80` with bit `0x01` set: bits 1-3 nonce length
//!   (0..7), `0x40` an 8-byte nonce, `0x10` a balance, `0x20` a code hash;
//!   then the nonce BE stripped, `len1 ‖ balance BE stripped` if `0x10`,
//!   `codeHash32` if `0x20` (set iff the code hash is not keccak of empty);
//! - `0x80 + len` (len 0..=32): a storage value BE stripped;
//! - `0xC0 ‖ hash32`: a block hash (never produced by gov5's recorder).
//!
//! At most 500 000 entries. Decoding ignores bytes after the last entry,
//! as Go does.

use alloy_primitives::{B256, KECCAK256_EMPTY, U256};

/// keccak256 of empty code, the code hash of an account without code.
pub const EMPTY_CODE_HASH: B256 = KECCAK256_EMPTY;

/// The most entries a log may hold.
pub const MAX_READ_LOG_ENTRIES: u32 = 500_000;

const ACCOUNT_NOT_FOUND: u8 = 0x00;
const STORAGE_BASE: u8 = 0x80;
const BLOCK_HASH: u8 = 0xC0;
const EXISTS: u8 = 0x01;
const NONCE_LEN_MASK: u8 = 0x0E;
const BALANCE: u8 = 0x10;
const CODE_HASH: u8 = 0x20;
const NONCE_8: u8 = 0x40;

/// One recorded read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadLogEntry {
    /// The account does not exist.
    AccountNotFound,
    /// The account exists.
    Account {
        /// Its nonce.
        nonce: u64,
        /// Its balance.
        balance: U256,
        /// Its code hash ([`EMPTY_CODE_HASH`] for an account without code).
        code_hash: B256,
    },
    /// A storage slot's value (slot implicit from position).
    Storage(U256),
    /// A block hash (number implicit from position).
    BlockHash(B256),
}

/// A malformed read log; the text follows gov5's `ErrInvalidReadLog`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("read_log: invalid encoding: {0}")]
pub struct ReadLogError(pub String);

fn stripped_be(v: &U256) -> Vec<u8> {
    let be = v.to_be_bytes::<32>();
    let start = be.iter().position(|b| *b != 0).unwrap_or(32);
    be[start..].to_vec()
}

/// Encodes a log (gov5 `EncodeReadLog`).
pub fn encode_read_log(entries: &[ReadLogEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + entries.len() * 4);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        match e {
            ReadLogEntry::AccountNotFound => out.push(ACCOUNT_NOT_FOUND),
            ReadLogEntry::Account { nonce, balance, code_hash } => {
                let contract = *code_hash != EMPTY_CODE_HASH;
                let nonce_len = (8 - nonce.leading_zeros() / 8) as usize;
                let nonce_len = if *nonce == 0 { 0 } else { nonce_len };
                let bal = stripped_be(balance);
                let mut header = EXISTS;
                if nonce_len <= 7 {
                    header |= (nonce_len as u8) << 1;
                } else {
                    header |= NONCE_8;
                }
                if !bal.is_empty() {
                    header |= BALANCE;
                }
                if contract {
                    header |= CODE_HASH;
                }
                out.push(header);
                if nonce_len > 0 {
                    out.extend_from_slice(&nonce.to_be_bytes()[8 - nonce_len..]);
                }
                if !bal.is_empty() {
                    out.push(bal.len() as u8);
                    out.extend_from_slice(&bal);
                }
                if contract {
                    out.extend_from_slice(code_hash.as_slice());
                }
            }
            ReadLogEntry::Storage(v) => {
                let b = stripped_be(v);
                out.push(STORAGE_BASE + b.len() as u8);
                out.extend_from_slice(&b);
            }
            ReadLogEntry::BlockHash(h) => {
                out.push(BLOCK_HASH);
                out.extend_from_slice(h.as_slice());
            }
        }
    }
    out
}

/// Decodes a log (gov5 `DecodeReadLog`).
pub fn decode_read_log(data: &[u8]) -> Result<Vec<ReadLogEntry>, ReadLogError> {
    if data.len() < 4 {
        return Err(ReadLogError("short header".into()));
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if count > MAX_READ_LOG_ENTRIES {
        return Err(ReadLogError(format!("entry count {count} exceeds max {MAX_READ_LOG_ENTRIES}")));
    }
    // Every entry takes at least one byte, so the data bounds the count an
    // honest log can carry; never reserve from the untrusted count alone.
    let mut out = Vec::with_capacity((count as usize).min(data.len() - 4));
    let mut pos = 4usize;
    let take = |pos: &mut usize, n: usize| -> Result<&[u8], ReadLogError> {
        if *pos + n > data.len() {
            return Err(ReadLogError(format!(
                "truncated at offset {} (need {n}, have {})",
                *pos,
                data.len() - *pos
            )));
        }
        let s = &data[*pos..*pos + n];
        *pos += n;
        Ok(s)
    };
    for _ in 0..count {
        let header = take(&mut pos, 1)?[0];
        let entry = match header {
            ACCOUNT_NOT_FOUND => ReadLogEntry::AccountNotFound,
            h if h < STORAGE_BASE => {
                if h & EXISTS == 0 {
                    return Err(ReadLogError(format!("invalid account header 0x{h:02x} at offset {}", pos - 1)));
                }
                let nonce_len = if h & NONCE_8 != 0 { 8 } else { usize::from((h & NONCE_LEN_MASK) >> 1) };
                let nonce = if nonce_len > 0 {
                    let mut buf = [0u8; 8];
                    buf[8 - nonce_len..].copy_from_slice(take(&mut pos, nonce_len)?);
                    u64::from_be_bytes(buf)
                } else {
                    0
                };
                let balance = if h & BALANCE != 0 {
                    let len = usize::from(take(&mut pos, 1)?[0]);
                    if len > 32 {
                        return Err(ReadLogError(format!("balance length {len} > 32")));
                    }
                    U256::from_be_slice(take(&mut pos, len)?)
                } else {
                    U256::ZERO
                };
                let code_hash =
                    if h & CODE_HASH != 0 { B256::from_slice(take(&mut pos, 32)?) } else { EMPTY_CODE_HASH };
                ReadLogEntry::Account { nonce, balance, code_hash }
            }
            h if h <= STORAGE_BASE + 32 => {
                let len = usize::from(h - STORAGE_BASE);
                ReadLogEntry::Storage(U256::from_be_slice(take(&mut pos, len)?))
            }
            BLOCK_HASH => ReadLogEntry::BlockHash(B256::from_slice(take(&mut pos, 32)?)),
            h => return Err(ReadLogError(format!("unknown header byte 0x{h:02x} at offset {}", pos - 1))),
        };
        out.push(entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_kinds() {
        let entries = vec![
            ReadLogEntry::AccountNotFound,
            ReadLogEntry::Account { nonce: 0, balance: U256::ZERO, code_hash: EMPTY_CODE_HASH },
            ReadLogEntry::Account { nonce: 0x0102, balance: U256::from(1_000_000u64), code_hash: EMPTY_CODE_HASH },
            ReadLogEntry::Account { nonce: u64::MAX, balance: U256::MAX, code_hash: B256::repeat_byte(7) },
            ReadLogEntry::Account { nonce: 1 << 56, balance: U256::from(1u64), code_hash: EMPTY_CODE_HASH },
            ReadLogEntry::Storage(U256::ZERO),
            ReadLogEntry::Storage(U256::from(0xABCDu64)),
            ReadLogEntry::Storage(U256::MAX),
            ReadLogEntry::BlockHash(B256::repeat_byte(9)),
        ];
        let enc = encode_read_log(&entries);
        assert_eq!(decode_read_log(&enc).unwrap(), entries);
        // Header bytes: EOA with zero nonce/balance is just 0x01; 2-byte
        // nonce + balance = 0x01 | 2<<1 | 0x10 = 0x15; 8-byte nonce +
        // balance + code = 0x71; 8-byte nonce 1<<56 + balance = 0x51.
        assert_eq!(enc[4], 0x00);
        assert_eq!(enc[5], 0x01);
        assert_eq!(enc[6], 0x15);
    }

    #[test]
    fn account_header_bits() {
        // exists 0x01 | nonce length 1 << 1 | balance 0x10 = 0x13 (the bit
        // constants read_log_test.go:196 pins).
        let enc = encode_read_log(&[ReadLogEntry::Account {
            nonce: 1,
            balance: U256::from(1u64),
            code_hash: EMPTY_CODE_HASH,
        }]);
        assert_eq!(&enc[4..], &[0x13, 0x01, 0x01, 0x01]);
    }

    #[test]
    fn rejections() {
        assert!(decode_read_log(&[1, 0, 0]).is_err());
        assert!(decode_read_log(&[0x21, 0xA1, 0x07, 0x00]).is_err()); // > max
        assert!(decode_read_log(&[1, 0, 0, 0, 0x02]).is_err()); // account without exists bit
        assert!(decode_read_log(&[1, 0, 0, 0, 0xA1]).is_err()); // 0xA1 > 0x80+32, != 0xC0
        assert!(decode_read_log(&[1, 0, 0, 0, 0x82, 0x01]).is_err()); // truncated
        assert!(decode_read_log(&[1, 0, 0, 0, 0x11, 33]).is_err()); // balance len > 32
        // A maximal count over four bytes of data fails on the data, without
        // trusting the count.
        let err = decode_read_log(&[0x20, 0xA1, 0x07, 0x00, 0, 0, 0, 0]).unwrap_err();
        assert!(err.0.contains("truncated at offset 8"), "{}", err.0);
        assert_eq!(decode_read_log(&[0x20, 0xA1, 0x07, 0x00, 0, 0, 0, 0][..4]).unwrap_err().0, "truncated at offset 4 (need 1, have 0)");
        // Trailing bytes are ignored.
        assert_eq!(decode_read_log(&[1, 0, 0, 0, 0x00, 0xEE]).unwrap(), vec![ReadLogEntry::AccountNotFound]);
    }
}
