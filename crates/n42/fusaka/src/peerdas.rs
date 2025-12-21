// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! PeerDAS support (EIP-7594)
//!
//! Peer Data Availability Sampling (PeerDAS) is a mechanism for efficiently
//! sampling data availability across the network.
//!
//! # Overview
//!
//! PeerDAS extends the blob transaction model from EIP-4844 with:
//! - Extended blobs with additional cell commitments
//! - Data column-based sampling
//! - Peer-to-peer data availability verification

use crate::constants::*;
use alloy_primitives::B256;
use thiserror::Error;

/// PeerDAS errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PeerDasError {
    /// Invalid column index
    #[error("invalid column index: {0}, max is 127")]
    InvalidColumnIndex(usize),

    /// Invalid cell index
    #[error("invalid cell index: {0}, max is 127")]
    InvalidCellIndex(usize),

    /// Cell proof verification failed
    #[error("cell proof verification failed")]
    CellProofVerificationFailed,

    /// Column sampling failed
    #[error("column sampling failed: insufficient samples")]
    ColumnSamplingFailed,

    /// Data not available
    #[error("data not available for column {0}")]
    DataNotAvailable(usize),
}

/// Result type for PeerDAS operations
pub type PeerDasResult<T> = Result<T, PeerDasError>;

/// Data column index type
pub type ColumnIndex = usize;

/// Cell index type
pub type CellIndex = usize;

/// Represents a data column in PeerDAS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataColumn {
    /// Column index (0 to NUMBER_OF_COLUMNS - 1)
    pub index: ColumnIndex,
    /// Cell data for this column
    pub cells: Vec<Vec<u8>>,
    /// KZG proofs for cells
    pub proofs: Vec<B256>,
}

impl DataColumn {
    /// Create a new data column
    pub fn new(index: ColumnIndex) -> PeerDasResult<Self> {
        if index >= NUMBER_OF_COLUMNS {
            return Err(PeerDasError::InvalidColumnIndex(index));
        }
        Ok(Self {
            index,
            cells: Vec::new(),
            proofs: Vec::new(),
        })
    }

    /// Check if the column is valid
    pub fn is_valid(&self) -> bool {
        self.index < NUMBER_OF_COLUMNS && self.cells.len() == self.proofs.len()
    }
}

/// Calculate required custody columns for a node
///
/// Nodes are responsible for storing and serving a subset of columns
/// based on their node ID.
pub fn custody_columns(node_id: &B256, custody_subnet_count: usize) -> Vec<ColumnIndex> {
    let mut columns = Vec::new();
    
    // Simplified column assignment based on node ID
    // In production, this would use more sophisticated selection
    let start_column = (node_id.as_slice()[0] as usize) % NUMBER_OF_COLUMNS;
    
    for i in 0..custody_subnet_count {
        let column = (start_column + i * (NUMBER_OF_COLUMNS / custody_subnet_count)) % NUMBER_OF_COLUMNS;
        columns.push(column);
    }
    
    columns
}

/// Calculate the number of samples needed for data availability
pub fn samples_needed_for_availability(blob_count: usize) -> usize {
    // Simplified calculation
    // In production, this depends on the security parameters
    if blob_count == 0 {
        return 0;
    }
    // At least 50% of cells per blob should be sampled
    (blob_count * CELLS_PER_EXT_BLOB) / 2
}

/// Verify that a column index is valid
pub fn verify_column_index(index: ColumnIndex) -> PeerDasResult<()> {
    if index >= NUMBER_OF_COLUMNS {
        return Err(PeerDasError::InvalidColumnIndex(index));
    }
    Ok(())
}

/// Verify that a cell index is valid
pub fn verify_cell_index(index: CellIndex) -> PeerDasResult<()> {
    if index >= CELLS_PER_EXT_BLOB {
        return Err(PeerDasError::InvalidCellIndex(index));
    }
    Ok(())
}

/// Get the column indices that a cell belongs to
pub fn cell_to_columns(cell_index: CellIndex) -> PeerDasResult<ColumnIndex> {
    verify_cell_index(cell_index)?;
    // Each cell maps to a specific column
    Ok(cell_index % NUMBER_OF_COLUMNS)
}

/// Osaka blob parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsakaBlobParams {
    /// Target number of blobs per block
    pub target_blob_count: u64,
    /// Maximum number of blobs per block
    pub max_blob_count: u64,
    /// Maximum blobs per transaction
    pub max_blobs_per_tx: u64,
}

impl Default for OsakaBlobParams {
    fn default() -> Self {
        Self {
            target_blob_count: OSAKA_TARGET_BLOB_COUNT,
            max_blob_count: OSAKA_MAX_BLOB_COUNT,
            max_blobs_per_tx: OSAKA_MAX_BLOBS_PER_TX,
        }
    }
}

impl OsakaBlobParams {
    /// Create new Osaka blob parameters
    pub const fn new() -> Self {
        Self {
            target_blob_count: OSAKA_TARGET_BLOB_COUNT,
            max_blob_count: OSAKA_MAX_BLOB_COUNT,
            max_blobs_per_tx: OSAKA_MAX_BLOBS_PER_TX,
        }
    }

    /// Check if a block with the given blob count is valid
    pub fn is_valid_blob_count(&self, count: u64) -> bool {
        count <= self.max_blob_count
    }

    /// Check if a transaction with the given blob count is valid
    pub fn is_valid_tx_blob_count(&self, count: u64) -> bool {
        count <= self.max_blobs_per_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_column_new() {
        let column = DataColumn::new(0);
        assert!(column.is_ok());
        
        let column = DataColumn::new(NUMBER_OF_COLUMNS - 1);
        assert!(column.is_ok());
        
        let column = DataColumn::new(NUMBER_OF_COLUMNS);
        assert!(matches!(column, Err(PeerDasError::InvalidColumnIndex(_))));
    }

    #[test]
    fn test_verify_column_index() {
        assert!(verify_column_index(0).is_ok());
        assert!(verify_column_index(NUMBER_OF_COLUMNS - 1).is_ok());
        assert!(verify_column_index(NUMBER_OF_COLUMNS).is_err());
    }

    #[test]
    fn test_verify_cell_index() {
        assert!(verify_cell_index(0).is_ok());
        assert!(verify_cell_index(CELLS_PER_EXT_BLOB - 1).is_ok());
        assert!(verify_cell_index(CELLS_PER_EXT_BLOB).is_err());
    }

    #[test]
    fn test_cell_to_columns() {
        assert_eq!(cell_to_columns(0).unwrap(), 0);
        assert_eq!(cell_to_columns(1).unwrap(), 1);
        assert_eq!(cell_to_columns(127).unwrap(), 127);
        // Cell index 128 is out of range
        assert!(cell_to_columns(128).is_err());
    }

    #[test]
    fn test_custody_columns() {
        let node_id = B256::from([1u8; 32]);
        let columns = custody_columns(&node_id, 4);
        assert_eq!(columns.len(), 4);
        
        // All columns should be unique
        let mut unique = columns.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn test_samples_needed() {
        assert_eq!(samples_needed_for_availability(0), 0);
        assert_eq!(samples_needed_for_availability(1), CELLS_PER_EXT_BLOB / 2);
        assert_eq!(samples_needed_for_availability(2), CELLS_PER_EXT_BLOB);
    }

    #[test]
    fn test_osaka_blob_params() {
        let params = OsakaBlobParams::default();
        
        assert!(params.is_valid_blob_count(0));
        assert!(params.is_valid_blob_count(OSAKA_MAX_BLOB_COUNT));
        assert!(!params.is_valid_blob_count(OSAKA_MAX_BLOB_COUNT + 1));
        
        assert!(params.is_valid_tx_blob_count(0));
        assert!(params.is_valid_tx_blob_count(OSAKA_MAX_BLOBS_PER_TX));
        assert!(!params.is_valid_tx_blob_count(OSAKA_MAX_BLOBS_PER_TX + 1));
    }
}

