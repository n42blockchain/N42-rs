// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fusaka constants and hardfork timestamps

use alloy_primitives::Address;

/// N42 Mainnet Osaka (Fusaka CL) activation timestamp
/// 2025-07-01 00:00:00 UTC
pub const N42_OSAKA_TIMESTAMP: u64 = 1751328000;

/// N42 Mainnet Prague (Fusaka EL) activation timestamp
/// 2025-06-03 06:00:00 UTC
pub const N42_PRAGUE_TIMESTAMP: u64 = 1748930400;

// ============================================================================
// BLS12-381 Precompile Addresses (EIP-2537)
// ============================================================================

/// BLS12_G1ADD precompile address
pub const BLS12_G1ADD: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b,
]);

/// BLS12_G1MUL precompile address
pub const BLS12_G1MUL: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c,
]);

/// BLS12_G1MULTIEXP precompile address
pub const BLS12_G1MULTIEXP: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d,
]);

/// BLS12_G2ADD precompile address
pub const BLS12_G2ADD: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e,
]);

/// BLS12_G2MUL precompile address
pub const BLS12_G2MUL: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f,
]);

/// BLS12_G2MULTIEXP precompile address
pub const BLS12_G2MULTIEXP: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
]);

/// BLS12_PAIRING precompile address
pub const BLS12_PAIRING: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11,
]);

/// BLS12_MAP_FP_TO_G1 precompile address
pub const BLS12_MAP_FP_TO_G1: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12,
]);

/// BLS12_MAP_FP2_TO_G2 precompile address
pub const BLS12_MAP_FP2_TO_G2: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13,
]);

/// All BLS12-381 precompile addresses
pub const BLS_PRECOMPILE_ADDRESSES: [Address; 9] = [
    BLS12_G1ADD,
    BLS12_G1MUL,
    BLS12_G1MULTIEXP,
    BLS12_G2ADD,
    BLS12_G2MUL,
    BLS12_G2MULTIEXP,
    BLS12_PAIRING,
    BLS12_MAP_FP_TO_G1,
    BLS12_MAP_FP2_TO_G2,
];

// ============================================================================
// PeerDAS Constants (EIP-7594)
// ============================================================================

/// Number of cells per extended blob (EIP-7594)
pub const CELLS_PER_EXT_BLOB: usize = 128;

/// Number of columns in the data availability matrix
pub const NUMBER_OF_COLUMNS: usize = 128;

/// Target number of blobs per block (Osaka)
pub const OSAKA_TARGET_BLOB_COUNT: u64 = 6;

/// Maximum number of blobs per block (Osaka)
pub const OSAKA_MAX_BLOB_COUNT: u64 = 9;

/// Maximum blobs per transaction (Osaka)
pub const OSAKA_MAX_BLOBS_PER_TX: u64 = 6;

// ============================================================================
// Gas Costs (EIP-2537)
// ============================================================================

/// Gas cost for BLS12_G1ADD
pub const BLS12_G1ADD_GAS: u64 = 500;

/// Gas cost for BLS12_G1MUL
pub const BLS12_G1MUL_GAS: u64 = 12000;

/// Base gas cost for BLS12_G1MULTIEXP
pub const BLS12_G1MULTIEXP_BASE_GAS: u64 = 12000;

/// Gas cost for BLS12_G2ADD
pub const BLS12_G2ADD_GAS: u64 = 800;

/// Gas cost for BLS12_G2MUL
pub const BLS12_G2MUL_GAS: u64 = 45000;

/// Base gas cost for BLS12_G2MULTIEXP
pub const BLS12_G2MULTIEXP_BASE_GAS: u64 = 45000;

/// Base gas cost for BLS12_PAIRING
pub const BLS12_PAIRING_BASE_GAS: u64 = 65000;

/// Per-pair gas cost for BLS12_PAIRING
pub const BLS12_PAIRING_PAIR_GAS: u64 = 43000;

/// Gas cost for BLS12_MAP_FP_TO_G1
pub const BLS12_MAP_FP_TO_G1_GAS: u64 = 5500;

/// Gas cost for BLS12_MAP_FP2_TO_G2
pub const BLS12_MAP_FP2_TO_G2_GAS: u64 = 75000;

// ============================================================================
// Input/Output Sizes (EIP-2537)
// ============================================================================

/// Size of a G1 point (compressed)
pub const G1_POINT_SIZE: usize = 128;

/// Size of a G2 point (compressed)
pub const G2_POINT_SIZE: usize = 256;

/// Size of a scalar (for mul operations)
pub const SCALAR_SIZE: usize = 32;

/// Size of Fp element
pub const FP_SIZE: usize = 64;

/// Size of Fp2 element
pub const FP2_SIZE: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_precompile_addresses() {
        assert_eq!(BLS12_G1ADD.as_slice()[19], 0x0b);
        assert_eq!(BLS12_G1MUL.as_slice()[19], 0x0c);
        assert_eq!(BLS12_G1MULTIEXP.as_slice()[19], 0x0d);
        assert_eq!(BLS12_G2ADD.as_slice()[19], 0x0e);
        assert_eq!(BLS12_G2MUL.as_slice()[19], 0x0f);
        assert_eq!(BLS12_G2MULTIEXP.as_slice()[19], 0x10);
        assert_eq!(BLS12_PAIRING.as_slice()[19], 0x11);
        assert_eq!(BLS12_MAP_FP_TO_G1.as_slice()[19], 0x12);
        assert_eq!(BLS12_MAP_FP2_TO_G2.as_slice()[19], 0x13);
    }

    #[test]
    fn test_bls_precompile_count() {
        assert_eq!(BLS_PRECOMPILE_ADDRESSES.len(), 9);
    }

    #[test]
    fn test_osaka_timestamps() {
        // Osaka should be after Prague
        assert!(N42_OSAKA_TIMESTAMP > N42_PRAGUE_TIMESTAMP);
    }

    #[test]
    fn test_osaka_blob_params() {
        assert!(OSAKA_TARGET_BLOB_COUNT < OSAKA_MAX_BLOB_COUNT);
        assert!(OSAKA_MAX_BLOBS_PER_TX <= OSAKA_MAX_BLOB_COUNT);
    }

    #[test]
    fn test_peerdas_constants() {
        assert_eq!(CELLS_PER_EXT_BLOB, 128);
        assert_eq!(NUMBER_OF_COLUMNS, 128);
    }
}

