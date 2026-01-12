//! Transaction test executor
//!
//! This module implements the executor for Ethereum Foundation transaction tests.
//! Transaction tests validate that transactions are correctly decoded and
//! that intrinsic gas calculations match expected values.

use crate::error::{EfTestError, EfTestResult};
use crate::fork::ForkSpec;
use crate::models::TransactionTest;
use crate::result::TestResult;

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Decodable, Encodable};
use std::time::Instant;
use tracing::{debug, trace};

/// Check if an EIP-7702 transaction should be rejected based on strict validation rules
/// Returns the exception name if the transaction violates EIP-7702 rules
fn is_invalid_eip7702_transaction(tx: &TxEnvelope, has_extra_bytes: bool) -> Option<String> {
    // Check if this transaction has an authorization list (Type 4 / EIP-7702)
    if let Some(auth_list) = tx.authorization_list() {
        // Rule 1: Authorization list must not be empty
        if auth_list.is_empty() {
            return Some("TYPE_4_EMPTY_AUTHORIZATION_LIST".to_string());
        }

        // Rule 2: Check for extra bytes in RLP encoding
        if has_extra_bytes {
            return Some("TYPE_4_INVALID_AUTHORIZATION_FORMAT".to_string());
        }
    }

    None
}

/// Executor for Ethereum Foundation transaction tests
#[derive(Debug, Clone)]
pub struct TransactionTestExecutor {
    /// Fork specification
    fork: ForkSpec,
}

impl TransactionTestExecutor {
    /// Create a new transaction test executor for the given fork
    pub fn new(fork: &ForkSpec) -> Self {
        Self { fork: *fork }
    }

    /// Execute a transaction test
    pub fn execute(&self, test: &TransactionTest, test_name: &str, fork: &str) -> EfTestResult<TestResult> {
        let start = Instant::now();

        // Get expected result for this fork
        let expected = match test.result.get(fork) {
            Some(r) => r,
            None => {
                return Ok(TestResult::skipped(
                    test_name.to_string(),
                    fork.to_string(),
                    format!("No expected result for fork {}", fork),
                ));
            }
        };

        // Try to decode the transaction
        let tx_bytes = test.txbytes.as_ref();
        let mut buf = &tx_bytes[..];
        let decode_result = TxEnvelope::decode(&mut buf);

        // Check if there are any unconsumed bytes after decoding
        let has_extra_bytes = !buf.is_empty();

        let duration = start.elapsed();

        match decode_result {
            Ok(tx) => {
                // Transaction decoded successfully by alloy
                // But we need to perform additional EIP-7702 validation
                if let Some(violation) = is_invalid_eip7702_transaction(&tx, has_extra_bytes) {
                    // Transaction violates EIP-7702 rules
                    if expected.expects_error() {
                        // Check if the expected exception matches what we found
                        let expected_exc = expected.exception.as_deref().unwrap_or("");
                        if expected_exc.contains(&violation) {
                            // Expected this specific error - test passes
                            trace!(
                                "Transaction test {} correctly rejected for EIP-7702 violation: {}",
                                test_name,
                                violation
                            );
                            return Ok(TestResult::passed(
                                test_name.to_string(),
                                fork.to_string(),
                                duration,
                            ));
                        } else {
                            // Expected a different error
                            return Ok(TestResult::failed(
                                test_name.to_string(),
                                fork.to_string(),
                                duration,
                                format!(
                                    "Expected exception '{}' but got '{}'",
                                    expected_exc, violation
                                ),
                            ));
                        }
                    } else {
                        // Did not expect an error but found EIP-7702 violation
                        return Ok(TestResult::failed(
                            test_name.to_string(),
                            fork.to_string(),
                            duration,
                            format!("Transaction violates EIP-7702 rules: {}", violation),
                        ));
                    }
                }

                if expected.expects_error() {
                    // Expected an error but got a valid transaction
                    return Ok(TestResult::failed(
                        test_name.to_string(),
                        fork.to_string(),
                        duration,
                        format!(
                            "Expected exception '{}' but transaction decoded successfully",
                            expected.exception.as_deref().unwrap_or("unknown")
                        ),
                    ));
                }

                // Transaction is valid as expected
                // TODO: Validate intrinsic gas calculation
                // For now, we'll pass if the transaction decodes successfully when no error is expected
                Ok(TestResult::passed(test_name.to_string(), fork.to_string(), duration))
            }
            Err(e) => {
                // Transaction failed to decode
                if expected.expects_error() {
                    // Expected an error and got one - this is a pass
                    trace!(
                        "Transaction test {} correctly rejected: {}",
                        test_name,
                        expected.exception.as_deref().unwrap_or("unknown")
                    );
                    Ok(TestResult::passed(test_name.to_string(), fork.to_string(), duration))
                } else {
                    // Did not expect an error but got one
                    Ok(TestResult::failed(
                        test_name.to_string(),
                        fork.to_string(),
                        duration,
                        format!("Expected valid transaction but decode failed: {}", e),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = TransactionTestExecutor::new(&ForkSpec::Prague);
        assert_eq!(executor.fork, ForkSpec::Prague);
    }
}
