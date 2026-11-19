// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RPC methods an N42-native chain answers with a refusal rather than with
//! an answer that would mislead (`docs/RPC_SURFACE_NATIVE.md`).
//!
//! - `eth_config` (EIP-7910): a native chain schedules forks the EIP's model
//!   cannot express (gov5's `glamsterdamTime`, the N42 precompiles), and
//!   reth's handler would report a fork id and system contracts from before
//!   the Amsterdam execution next to evm2's Amsterdam precompiles. gov5
//!   refuses the method on a native chain with the same message
//!   (`internal/api/eth_config.go`, `errEthConfigNativeChain`); an Ethereum
//!   chain gets reth's handler.
//! - `debug_executionWitness` / `debug_executionWitnessByBlockHash` on a
//!   QMDB chain: the witness is built from the Merkle-Patricia trie and the
//!   hashed tables, which a QMDB chain does not maintain, so its nodes would
//!   not verify against the header's state root (as `eth_getProof`, refused
//!   in [`crate::qmdb_proof_ext::eth_get_proof_refusal`]).

use jsonrpsee::types::ErrorObjectOwned;

/// gov5's `errEthConfigNativeChain`, word for word.
pub const ETH_CONFIG_NATIVE_CHAIN: &str = "eth_config is only defined for Ethereum fork schedules";

/// The error code of both refusals: JSON-RPC "method not supported"
/// (`n42_getProof`'s refusal uses it too).
pub const UNSUPPORTED_CODE: i32 = -32004;

/// The `eth_config` a native chain answers with.
pub fn eth_config_refusal() -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("eth_config", |_, _, _| -> Result<(), ErrorObjectOwned> {
            Err(ErrorObjectOwned::owned(UNSUPPORTED_CODE, ETH_CONFIG_NATIVE_CHAIN, None::<()>))
        })
        .expect("one method on a fresh module");
    module
}

/// The execution-witness methods a QMDB chain answers with.
pub fn execution_witness_refusal() -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    for name in ["debug_executionWitness", "debug_executionWitnessByBlockHash"] {
        module
            .register_method(name, |_, _, _| -> Result<(), ErrorObjectOwned> {
                Err(ErrorObjectOwned::owned(
                    UNSUPPORTED_CODE,
                    "execution witnesses are not served on a QMDB chain: they are built from the \
                     Merkle-Patricia trie, which is not maintained, and would not verify against the \
                     header's state root",
                    None::<()>,
                ))
            })
            .expect("distinct methods on a fresh module");
    }
    module
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn error_of(module: &jsonrpsee::RpcModule<()>, method: &str) -> (i32, String) {
        let request = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":[]}}"#);
        let (response, _) = module.raw_json_request(&request, 1).await.expect("a response");
        let value: serde_json::Value = serde_json::from_str(response.get()).expect("json");
        let error = &value["error"];
        (error["code"].as_i64().expect("a code") as i32, error["message"].as_str().expect("a message").to_owned())
    }

    #[tokio::test]
    async fn eth_config_is_refused_with_gov5s_message() {
        let (code, message) = error_of(&eth_config_refusal(), "eth_config").await;
        assert_eq!(code, UNSUPPORTED_CODE);
        assert_eq!(message, ETH_CONFIG_NATIVE_CHAIN);
    }

    #[tokio::test]
    async fn both_witness_methods_are_refused() {
        let module = execution_witness_refusal();
        for method in ["debug_executionWitness", "debug_executionWitnessByBlockHash"] {
            let (code, message) = error_of(&module, method).await;
            assert_eq!(code, UNSUPPORTED_CODE, "{method}");
            assert!(message.contains("QMDB"), "{method}: {message}");
        }
    }
}
