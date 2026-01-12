//! Transaction test model for EF tests
//!
//! Transaction tests validate that transactions are correctly decoded and
//! that intrinsic gas calculations match expected values.

use super::deserialize_bytes;
use alloy_primitives::Bytes;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

/// A complete transaction test fixture file
pub type TransactionTestFile = HashMap<String, TransactionTest>;

/// A single transaction test case
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionTest {
    /// Expected results per fork
    pub result: HashMap<String, TransactionTestResult>,

    /// Raw transaction bytes
    #[serde(deserialize_with = "deserialize_bytes")]
    pub txbytes: Bytes,

    /// Test metadata
    #[serde(rename = "_info", default)]
    pub info: Option<TransactionTestInfo>,
}

/// Expected result for a transaction test
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionTestResult {
    /// Intrinsic gas cost
    #[serde(default)]
    pub intrinsic_gas: Option<String>,

    /// Expected exception/error
    #[serde(default)]
    pub exception: Option<String>,

    /// Transaction sender address (if valid)
    #[serde(default)]
    pub sender: Option<String>,

    /// Transaction hash (if valid)
    #[serde(default)]
    pub hash: Option<String>,
}

/// Transaction test metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransactionTestInfo {
    /// Test hash
    #[serde(default)]
    pub hash: Option<String>,

    /// Comment/description
    #[serde(default)]
    pub comment: Option<String>,

    /// Filling tool version
    #[serde(rename = "filling-transition-tool", default)]
    pub filling_tool: Option<String>,

    /// Test description
    #[serde(default)]
    pub description: Option<String>,

    /// Source URL
    #[serde(default)]
    pub url: Option<String>,

    /// Fixture format
    #[serde(rename = "fixture-format", default)]
    pub fixture_format: Option<String>,

    /// Reference spec
    #[serde(rename = "reference-spec", default)]
    pub reference_spec: Option<String>,

    /// Reference spec version
    #[serde(rename = "reference-spec-version", default)]
    pub reference_spec_version: Option<String>,
}

impl TransactionTest {
    /// Get the list of forks this test covers
    pub fn forks(&self) -> Vec<&str> {
        self.result.keys().map(|s| s.as_str()).collect()
    }

    /// Check if the test expects an error for the given fork
    pub fn expects_exception(&self, fork: &str) -> bool {
        self.result
            .get(fork)
            .map(|r| r.exception.is_some())
            .unwrap_or(false)
    }

    /// Get the expected exception for the given fork
    pub fn expected_exception(&self, fork: &str) -> Option<&str> {
        self.result
            .get(fork)
            .and_then(|r| r.exception.as_deref())
    }

    /// Get the expected intrinsic gas for the given fork
    pub fn expected_intrinsic_gas(&self, fork: &str) -> Option<u64> {
        self.result
            .get(fork)
            .and_then(|r| r.intrinsic_gas.as_ref())
            .and_then(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                u64::from_str_radix(s, 16).ok()
            })
    }
}

impl TransactionTestResult {
    /// Check if this result expects an error
    pub fn expects_error(&self) -> bool {
        self.exception.is_some()
    }

    /// Check if the transaction is expected to be valid
    pub fn is_valid(&self) -> bool {
        self.exception.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_transaction_test() {
        let json = r#"{
            "result": {
                "Prague": {
                    "intrinsicGas": "0x00",
                    "exception": "TransactionException.TYPE_4_INVALID_AUTHORIZATION_FORMAT"
                }
            },
            "txbytes": "0x04f8c301808007830186a09400000000000000000000000000000000000000008080c0f85ef85c8094000000000000000000000000000000000000000182000080a083fa55138a74c229c5508173575054bff977155da0d708b6c8c1150b4c140238a0605878ffcbcbc76fa46a7ff477c865eccda27bf4dc44a6a4f4857e35ede15a9080a0701eb8238974d2c76e721b42b5d667cbf3b9b5756006c472c562c7c8ada19333a0030861b06c15251b166ebca7a2a03c307a5bcccd1ae0a77d344bbb77de796c10"
        }"#;

        let test: TransactionTest = serde_json::from_str(json).unwrap();
        assert!(test.expects_exception("Prague"));
        assert_eq!(test.forks(), vec!["Prague"]);
    }
}
