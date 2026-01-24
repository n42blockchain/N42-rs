// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! BLS12-381 precompile support (EIP-2537)
//!
//! This module provides utilities for verifying BLS12-381 precompile support
//! in the revm execution environment.

use crate::constants::*;
use alloy_primitives::Address;
use thiserror::Error;

/// BLS precompile errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// Invalid input length
    #[error("invalid input length: expected {expected}, got {actual}")]
    InvalidInputLength { expected: usize, actual: usize },

    /// Invalid G1 point
    #[error("invalid G1 point")]
    InvalidG1Point,

    /// Invalid G2 point
    #[error("invalid G2 point")]
    InvalidG2Point,

    /// Point not on curve
    #[error("point not on curve")]
    PointNotOnCurve,

    /// Pairing check failed
    #[error("pairing check failed")]
    PairingCheckFailed,

    /// Precompile not available
    #[error("BLS precompile not available at address {0}")]
    PrecompileNotAvailable(Address),

    /// Execution failed
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
}

/// Result type for BLS operations
pub type BlsResult<T> = Result<T, BlsError>;

/// Check if an address is a BLS precompile
pub fn is_bls_precompile(address: &Address) -> bool {
    BLS_PRECOMPILE_ADDRESSES.contains(address)
}

/// Get the name of a BLS precompile by address
pub fn bls_precompile_name(address: &Address) -> Option<&'static str> {
    match address {
        a if *a == BLS12_G1ADD => Some("BLS12_G1ADD"),
        a if *a == BLS12_G1MUL => Some("BLS12_G1MUL"),
        a if *a == BLS12_G1MULTIEXP => Some("BLS12_G1MULTIEXP"),
        a if *a == BLS12_G2ADD => Some("BLS12_G2ADD"),
        a if *a == BLS12_G2MUL => Some("BLS12_G2MUL"),
        a if *a == BLS12_G2MULTIEXP => Some("BLS12_G2MULTIEXP"),
        a if *a == BLS12_PAIRING => Some("BLS12_PAIRING"),
        a if *a == BLS12_MAP_FP_TO_G1 => Some("BLS12_MAP_FP_TO_G1"),
        a if *a == BLS12_MAP_FP2_TO_G2 => Some("BLS12_MAP_FP2_TO_G2"),
        _ => None,
    }
}

/// Validate G1ADD input
pub fn validate_g1add_input(input: &[u8]) -> BlsResult<()> {
    let expected = G1_POINT_SIZE * 2;
    if input.len() != expected {
        return Err(BlsError::InvalidInputLength {
            expected,
            actual: input.len(),
        });
    }
    Ok(())
}

/// Validate G1MUL input
pub fn validate_g1mul_input(input: &[u8]) -> BlsResult<()> {
    let expected = G1_POINT_SIZE + SCALAR_SIZE;
    if input.len() != expected {
        return Err(BlsError::InvalidInputLength {
            expected,
            actual: input.len(),
        });
    }
    Ok(())
}

/// Validate G2ADD input
pub fn validate_g2add_input(input: &[u8]) -> BlsResult<()> {
    let expected = G2_POINT_SIZE * 2;
    if input.len() != expected {
        return Err(BlsError::InvalidInputLength {
            expected,
            actual: input.len(),
        });
    }
    Ok(())
}

/// Validate G2MUL input
pub fn validate_g2mul_input(input: &[u8]) -> BlsResult<()> {
    let expected = G2_POINT_SIZE + SCALAR_SIZE;
    if input.len() != expected {
        return Err(BlsError::InvalidInputLength {
            expected,
            actual: input.len(),
        });
    }
    Ok(())
}

/// Validate pairing input (must be multiple of pair size)
pub fn validate_pairing_input(input: &[u8]) -> BlsResult<()> {
    let pair_size = G1_POINT_SIZE + G2_POINT_SIZE;
    if input.is_empty() || input.len() % pair_size != 0 {
        return Err(BlsError::InvalidInputLength {
            expected: pair_size,
            actual: input.len(),
        });
    }
    Ok(())
}

/// Validate MAP_FP_TO_G1 input
pub fn validate_map_fp_to_g1_input(input: &[u8]) -> BlsResult<()> {
    if input.len() != FP_SIZE {
        return Err(BlsError::InvalidInputLength {
            expected: FP_SIZE,
            actual: input.len(),
        });
    }
    Ok(())
}

/// Validate MAP_FP2_TO_G2 input
pub fn validate_map_fp2_to_g2_input(input: &[u8]) -> BlsResult<()> {
    if input.len() != FP2_SIZE {
        return Err(BlsError::InvalidInputLength {
            expected: FP2_SIZE,
            actual: input.len(),
        });
    }
    Ok(())
}

/// Calculate gas for G1 multiexp operation
pub fn g1_multiexp_gas(num_pairs: usize) -> u64 {
    if num_pairs == 0 {
        return 0;
    }
    // Discount factor based on number of pairs (simplified)
    let multiplier = match num_pairs {
        1 => 1200,
        2..=3 => 888,
        4..=7 => 764,
        8..=15 => 641,
        16..=31 => 594,
        32..=63 => 547,
        64..=127 => 500,
        _ => 453,
    };
    (BLS12_G1MULTIEXP_BASE_GAS * num_pairs as u64 * multiplier) / 1000
}

/// Calculate gas for G2 multiexp operation
pub fn g2_multiexp_gas(num_pairs: usize) -> u64 {
    if num_pairs == 0 {
        return 0;
    }
    // Discount factor based on number of pairs (simplified)
    let multiplier = match num_pairs {
        1 => 1200,
        2..=3 => 888,
        4..=7 => 764,
        8..=15 => 641,
        16..=31 => 594,
        32..=63 => 547,
        64..=127 => 500,
        _ => 453,
    };
    (BLS12_G2MULTIEXP_BASE_GAS * num_pairs as u64 * multiplier) / 1000
}

/// Calculate gas for pairing operation
pub fn pairing_gas(num_pairs: usize) -> u64 {
    BLS12_PAIRING_BASE_GAS + (num_pairs as u64 * BLS12_PAIRING_PAIR_GAS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bls_precompile() {
        assert!(is_bls_precompile(&BLS12_G1ADD));
        assert!(is_bls_precompile(&BLS12_PAIRING));
        assert!(!is_bls_precompile(&Address::ZERO));
    }

    #[test]
    fn test_bls_precompile_names() {
        assert_eq!(bls_precompile_name(&BLS12_G1ADD), Some("BLS12_G1ADD"));
        assert_eq!(bls_precompile_name(&BLS12_PAIRING), Some("BLS12_PAIRING"));
        assert_eq!(bls_precompile_name(&Address::ZERO), None);
    }

    #[test]
    fn test_validate_g1add_input() {
        let valid_input = vec![0u8; G1_POINT_SIZE * 2];
        assert!(validate_g1add_input(&valid_input).is_ok());

        let invalid_input = vec![0u8; G1_POINT_SIZE];
        assert!(validate_g1add_input(&invalid_input).is_err());
    }

    #[test]
    fn test_validate_g1mul_input() {
        let valid_input = vec![0u8; G1_POINT_SIZE + SCALAR_SIZE];
        assert!(validate_g1mul_input(&valid_input).is_ok());

        let invalid_input = vec![0u8; G1_POINT_SIZE];
        assert!(validate_g1mul_input(&invalid_input).is_err());
    }

    #[test]
    fn test_validate_pairing_input() {
        let pair_size = G1_POINT_SIZE + G2_POINT_SIZE;

        let valid_input = vec![0u8; pair_size];
        assert!(validate_pairing_input(&valid_input).is_ok());

        let valid_input_2pairs = vec![0u8; pair_size * 2];
        assert!(validate_pairing_input(&valid_input_2pairs).is_ok());

        let invalid_input = vec![0u8; pair_size + 1];
        assert!(validate_pairing_input(&invalid_input).is_err());

        let empty_input: Vec<u8> = vec![];
        assert!(validate_pairing_input(&empty_input).is_err());
    }

    #[test]
    fn test_g1_multiexp_gas() {
        assert_eq!(g1_multiexp_gas(0), 0);
        assert_eq!(g1_multiexp_gas(1), 14400); // 12000 * 1 * 1200 / 1000
        assert!(g1_multiexp_gas(2) < g1_multiexp_gas(1) * 2); // Discount applies
    }

    #[test]
    fn test_pairing_gas() {
        assert_eq!(
            pairing_gas(1),
            BLS12_PAIRING_BASE_GAS + BLS12_PAIRING_PAIR_GAS
        );
        assert_eq!(
            pairing_gas(2),
            BLS12_PAIRING_BASE_GAS + 2 * BLS12_PAIRING_PAIR_GAS
        );
    }
}
