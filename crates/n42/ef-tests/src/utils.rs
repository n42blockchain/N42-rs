//! Utility functions for EF tests

use crate::error::{EfTestError, EfTestResult};
use crate::models::Account;
use alloy_primitives::{keccak256, Address, B256, U256};
use hashbrown::HashMap;

/// Compute the logs hash from encoded logs
pub fn logs_hash(logs: &[alloy_primitives::Log]) -> B256 {
    let mut buf = Vec::new();
    alloy_rlp::encode_list(logs, &mut buf);
    keccak256(&buf)
}

/// Empty logs hash (hash of empty RLP list)
pub fn empty_logs_hash() -> B256 {
    // Hash of RLP-encoded empty list: keccak256([0xc0])
    keccak256(&[0xc0])
}

/// Compute the state root from a map of accounts
/// Note: This is a simplified implementation. For production use,
/// a proper Merkle Patricia Trie implementation is needed.
pub fn compute_state_root(_accounts: &HashMap<Address, Account>) -> B256 {
    // This would need a proper MPT implementation
    // For now, return a placeholder
    B256::ZERO
}

/// Decode a hex string to bytes, handling the 0x prefix
pub fn decode_hex(s: &str) -> EfTestResult<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| EfTestError::InvalidTestData(e.to_string()))
}

/// Encode bytes to a hex string with 0x prefix
pub fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Parse a U256 from a hex string
pub fn parse_u256(s: &str) -> EfTestResult<U256> {
    U256::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .map_err(|e| EfTestError::InvalidTestData(e.to_string()))
}

/// Parse a u64 from a hex string
pub fn parse_u64(s: &str) -> EfTestResult<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| EfTestError::InvalidTestData(e.to_string()))
}

/// Parse a B256 from a hex string
pub fn parse_b256(s: &str) -> EfTestResult<B256> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        return Err(EfTestError::InvalidTestData(format!(
            "Expected 32 bytes for B256, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

/// Parse an Address from a hex string
pub fn parse_address(s: &str) -> EfTestResult<Address> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 20 {
        return Err(EfTestError::InvalidTestData(format!(
            "Expected 20 bytes for Address, got {}",
            bytes.len()
        )));
    }
    Ok(Address::from_slice(&bytes))
}

/// Trim leading zeros from a byte slice
pub fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

/// Pad bytes to a fixed length with leading zeros
pub fn pad_left(bytes: &[u8], len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        bytes.to_vec()
    } else {
        let mut result = vec![0u8; len - bytes.len()];
        result.extend_from_slice(bytes);
        result
    }
}

/// Convert U256 to 32-byte big-endian representation
pub fn u256_to_be_bytes(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

/// Check if two storage maps are equivalent
pub fn storage_eq(a: &HashMap<U256, U256>, b: &HashMap<U256, U256>) -> bool {
    // Filter out zero values
    let a_nonzero: HashMap<_, _> = a.iter().filter(|(_, v)| !v.is_zero()).collect();
    let b_nonzero: HashMap<_, _> = b.iter().filter(|(_, v)| !v.is_zero()).collect();

    if a_nonzero.len() != b_nonzero.len() {
        return false;
    }

    a_nonzero.iter().all(|(k, v)| b_nonzero.get(k) == Some(v))
}

/// Check if two accounts are equivalent
pub fn accounts_eq(a: &Account, b: &Account) -> bool {
    a.nonce == b.nonce && a.balance == b.balance && a.code == b.code && storage_eq(&a.storage, &b.storage)
}

/// Compare two account maps and return the differences
pub fn compare_accounts(
    expected: &HashMap<Address, Account>,
    actual: &HashMap<Address, Account>,
) -> Vec<AccountDiff> {
    let mut diffs = Vec::new();

    // Check all expected accounts
    for (addr, expected_acc) in expected {
        match actual.get(addr) {
            Some(actual_acc) => {
                if !accounts_eq(expected_acc, actual_acc) {
                    diffs.push(AccountDiff {
                        address: *addr,
                        expected: Some(expected_acc.clone()),
                        actual: Some(actual_acc.clone()),
                    });
                }
            }
            None => {
                if !expected_acc.is_empty() {
                    diffs.push(AccountDiff {
                        address: *addr,
                        expected: Some(expected_acc.clone()),
                        actual: None,
                    });
                }
            }
        }
    }

    // Check for unexpected accounts in actual
    for (addr, actual_acc) in actual {
        if !expected.contains_key(addr) && !actual_acc.is_empty() {
            diffs.push(AccountDiff {
                address: *addr,
                expected: None,
                actual: Some(actual_acc.clone()),
            });
        }
    }

    diffs
}

/// Represents a difference between expected and actual account state
#[derive(Debug, Clone)]
pub struct AccountDiff {
    /// Account address
    pub address: Address,
    /// Expected account state
    pub expected: Option<Account>,
    /// Actual account state
    pub actual: Option<Account>,
}

impl std::fmt::Display for AccountDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.expected, &self.actual) {
            (Some(exp), Some(act)) => {
                write!(f, "Account {} mismatch:\n", self.address)?;
                if exp.nonce != act.nonce {
                    write!(f, "  nonce: expected {}, got {}\n", exp.nonce, act.nonce)?;
                }
                if exp.balance != act.balance {
                    write!(f, "  balance: expected {}, got {}\n", exp.balance, act.balance)?;
                }
                if exp.code != act.code {
                    write!(f, "  code: expected {} bytes, got {} bytes\n", exp.code.len(), act.code.len())?;
                }
                // Storage diffs
                for (key, exp_val) in &exp.storage {
                    let act_val = act.storage.get(key).copied().unwrap_or_default();
                    if *exp_val != act_val {
                        write!(f, "  storage[{}]: expected {}, got {}\n", key, exp_val, act_val)?;
                    }
                }
                for (key, act_val) in &act.storage {
                    if !exp.storage.contains_key(key) && !act_val.is_zero() {
                        write!(f, "  storage[{}]: unexpected value {}\n", key, act_val)?;
                    }
                }
                Ok(())
            }
            (Some(exp), None) => {
                write!(f, "Account {} missing (expected nonce={}, balance={})", self.address, exp.nonce, exp.balance)
            }
            (None, Some(act)) => {
                write!(f, "Account {} unexpected (nonce={}, balance={})", self.address, act.nonce, act.balance)
            }
            (None, None) => write!(f, "Account {} (both None?)", self.address),
        }
    }
}

/// Filter patterns for skipping tests
#[derive(Debug, Clone, Default)]
pub struct TestFilter {
    /// Patterns to include (if empty, include all)
    pub include: Vec<String>,
    /// Patterns to exclude
    pub exclude: Vec<String>,
    /// Forks to include (if empty, include all)
    pub forks: Vec<String>,
}

impl TestFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an include pattern
    pub fn include(mut self, pattern: &str) -> Self {
        self.include.push(pattern.to_string());
        self
    }

    /// Add an exclude pattern
    pub fn exclude(mut self, pattern: &str) -> Self {
        self.exclude.push(pattern.to_string());
        self
    }

    /// Add a fork filter
    pub fn fork(mut self, fork: &str) -> Self {
        self.forks.push(fork.to_string());
        self
    }

    /// Check if a test name matches the filter
    pub fn matches(&self, name: &str) -> bool {
        // Check excludes first
        for pattern in &self.exclude {
            if name.contains(pattern) {
                return false;
            }
        }

        // If no includes, match all
        if self.include.is_empty() {
            return true;
        }

        // Check includes
        self.include.iter().any(|pattern| name.contains(pattern))
    }

    /// Check if a fork matches the filter
    pub fn matches_fork(&self, fork: &str) -> bool {
        if self.forks.is_empty() {
            return true;
        }
        self.forks
            .iter()
            .any(|f| f.eq_ignore_ascii_case(fork))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("0x1234").unwrap(), vec![0x12u8, 0x34u8]);
        assert_eq!(decode_hex("1234").unwrap(), vec![0x12u8, 0x34u8]);
        let empty: Vec<u8> = vec![];
        assert_eq!(decode_hex("0x").unwrap(), empty);
    }

    #[test]
    fn test_parse_u64() {
        assert_eq!(parse_u64("0x10").unwrap(), 16);
        assert_eq!(parse_u64("0x0186a0").unwrap(), 100000);
    }

    #[test]
    fn test_trim_leading_zeros() {
        assert_eq!(trim_leading_zeros(&[0u8, 0u8, 1u8, 2u8]), &[1u8, 2u8]);
        assert_eq!(trim_leading_zeros(&[1u8, 2u8, 3u8]), &[1u8, 2u8, 3u8]);
        let empty: &[u8] = &[];
        assert_eq!(trim_leading_zeros(&[0u8, 0u8, 0u8]), empty);
    }

    #[test]
    fn test_storage_eq() {
        let mut a = HashMap::new();
        let mut b = HashMap::new();

        a.insert(U256::from(1), U256::from(100));
        b.insert(U256::from(1), U256::from(100));

        assert!(storage_eq(&a, &b));

        // Zero values should be ignored
        a.insert(U256::from(2), U256::ZERO);
        assert!(storage_eq(&a, &b));

        b.insert(U256::from(2), U256::ZERO);
        assert!(storage_eq(&a, &b));
    }

    #[test]
    fn test_filter() {
        let filter = TestFilter::new()
            .include("test_")
            .exclude("skip_this");

        assert!(filter.matches("test_example"));
        assert!(!filter.matches("skip_this_test"));
        assert!(!filter.matches("other"));
    }
}
