// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `code_by_hash/1` (N42 sync standard §5.3.5): contract bytecode by its
//! keccak hash, for a state-sync client whose accounts name code hashes.
//! Request `n u16 (1..256) ‖ n × hash`; one reply chunk per hash, in order:
//! SUCCESS with the code, or `0x03 "missing"`. The requester checks keccak.

use super::qmdb::{ReadError, ReplyChunk, CODE_RESOURCE_UNAVAILABLE, CODE_SUCCESS, WireError};
use alloy_primitives::B256;

/// `code_by_hash/1`.
pub const CODE_BY_HASH_PROTOCOL: &str = "/rpc/code_by_hash/1/ssz_snappy";
/// Hashes per request.
pub const MAX_CODE_HASHES: usize = 256;
/// A served code's cap (twice EIP-170).
pub const MAX_CODE_BYTES: usize = 24576 * 2;
/// The largest request payload.
pub const MAX_CODE_REQUEST: usize = 2 + MAX_CODE_HASHES * 32;

/// Encodes a request.
pub fn encode_code_request(hashes: &[B256]) -> Result<Vec<u8>, WireError> {
    if hashes.is_empty() || hashes.len() > MAX_CODE_HASHES {
        return Err(WireError::Invalid(format!("syncwire: {} code hashes", hashes.len())));
    }
    let mut b = Vec::with_capacity(2 + 32 * hashes.len());
    b.extend_from_slice(&(hashes.len() as u16).to_le_bytes());
    for h in hashes {
        b.extend_from_slice(h.as_slice());
    }
    Ok(b)
}

/// Decodes a request.
pub fn decode_code_request(b: &[u8]) -> Result<Vec<B256>, WireError> {
    if b.len() < 2 {
        return Err(WireError::Length);
    }
    let n = u16::from_le_bytes([b[0], b[1]]) as usize;
    if n == 0 || n > MAX_CODE_HASHES {
        return Err(WireError::Invalid(format!("syncwire: {n} code hashes outside 1..{MAX_CODE_HASHES}")));
    }
    if b.len() != 2 + 32 * n {
        return Err(WireError::Length);
    }
    Ok(b[2..].as_chunks::<32>().0.iter().map(|h| B256::from(*h)).collect())
}

/// The reply chunks for `hashes`, from `get` (empty or oversized code is
/// "missing"). `write` returns false when the stream is gone.
pub fn serve_code(mut get: impl FnMut(&B256) -> Option<Vec<u8>>, hashes: &[B256], mut write: impl FnMut(ReplyChunk) -> bool) {
    for h in hashes {
        let chunk = match get(h) {
            Some(code) if !code.is_empty() && code.len() <= MAX_CODE_BYTES => ReplyChunk::success(code),
            _ => ReplyChunk::error(CODE_RESOURCE_UNAVAILABLE, "missing"),
        };
        if !write(chunk) {
            return;
        }
    }
}

/// Reads a reply to `n` hashes: one entry per hash, `None` when the server
/// lacks it (or the reply stopped early). The bytes are unverified.
pub fn read_code(chunks: &[ReplyChunk], n: usize) -> Result<Vec<Option<Vec<u8>>>, ReadError> {
    let mut out = Vec::with_capacity(n);
    for c in chunks.iter().take(n) {
        match c.code {
            CODE_SUCCESS => out.push(Some(c.payload.clone())),
            CODE_RESOURCE_UNAVAILABLE => out.push(None),
            code => return Err(ReadError::Code { code, message: c.message() }),
        }
    }
    out.resize(n, None);
    Ok(out)
}

/// Checks fetched code against the hashes asked for: every present entry
/// must hash to its key.
pub fn verify_code(hashes: &[B256], got: &[Option<Vec<u8>>]) -> Result<(), String> {
    for (h, code) in hashes.iter().zip(got) {
        if let Some(code) = code
            && alloy_primitives::keccak256(code) != *h
        {
            return Err(format!("code {h} does not hash to its key"));
        }
    }
    Ok(())
}
