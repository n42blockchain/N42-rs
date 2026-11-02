// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registration proof of work (`internal/mobileverify/sybil.go:35-116`):
//! Keccak256(`"n42/mobileverify/pow/v1"` ‖ pubkey48 ‖ nonce u64 BE) must have
//! at least `bits` leading zero bits, MSB first; `bits` is capped at 32.

use alloy_primitives::keccak256;

use crate::bls::PUBKEY_LEN;

/// The tag that prefixes a proof-of-work message (23 bytes, no NUL).
pub const POW_TAG: &[u8; 23] = b"n42/mobileverify/pow/v1";

/// The highest difficulty a server demands (`MaxRegisterPoWBits`).
pub const MAX_POW_BITS: u32 = 32;

/// Length of a proof-of-work message: tag ‖ pubkey ‖ nonce.
pub const POW_MESSAGE_LEN: usize = POW_TAG.len() + PUBKEY_LEN + 8;

/// The exact bytes hashed for a registration proof of work.
pub fn pow_message(pubkey: &[u8; PUBKEY_LEN], nonce: u64) -> [u8; POW_MESSAGE_LEN] {
    let mut out = [0u8; POW_MESSAGE_LEN];
    out[..POW_TAG.len()].copy_from_slice(POW_TAG);
    out[POW_TAG.len()..POW_TAG.len() + PUBKEY_LEN].copy_from_slice(pubkey);
    out[POW_TAG.len() + PUBKEY_LEN..].copy_from_slice(&nonce.to_be_bytes());
    out
}

/// Leading zero bits of `bytes`, MSB first.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0;
    for b in bytes {
        if *b == 0 {
            n += 8;
            continue;
        }
        return n + b.leading_zeros();
    }
    n
}

/// Whether `nonce` solves the puzzle for `pubkey` at `bits` (0 always does).
pub fn verify_pow(pubkey: &[u8; PUBKEY_LEN], nonce: u64, bits: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let bits = bits.min(MAX_POW_BITS);
    leading_zero_bits(keccak256(pow_message(pubkey, nonce)).as_slice()) >= bits
}

/// Grinds nonces from 0 up to `max_iters` (0 means `1 << (bits + 4)`, gov5's
/// client budget). `None` when the budget runs out.
pub fn solve_pow(pubkey: &[u8; PUBKEY_LEN], bits: u32, max_iters: u64) -> Option<u64> {
    if bits == 0 {
        return Some(0);
    }
    let bits = bits.min(MAX_POW_BITS);
    let max_iters = if max_iters == 0 { 1u64 << (bits + 4) } else { max_iters };
    (0..max_iters).find(|nonce| verify_pow(pubkey, *nonce, bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout() {
        let m = pow_message(&[0x11; 48], 0x0102_0304_0506_0708);
        assert_eq!(m.len(), 79);
        assert_eq!(&m[..23], b"n42/mobileverify/pow/v1");
        assert_eq!(&m[71..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn leading_zeros() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x10]), 19);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
    }

    #[test]
    fn solve_then_verify() {
        let pk = [0x42u8; 48];
        for bits in [1u32, 4, 8, 12] {
            let nonce = solve_pow(&pk, bits, 0).unwrap();
            assert!(verify_pow(&pk, nonce, bits));
            // The first solution: every smaller nonce fails.
            assert!((0..nonce).all(|n| !verify_pow(&pk, n, bits)));
        }
        assert!(verify_pow(&pk, 12345, 0));
        assert_eq!(solve_pow(&pk, 0, 0), Some(0));
    }
}
