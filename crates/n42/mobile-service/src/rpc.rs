// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `mobile_*` JSON-RPC surface, without a transport.
//!
//! [`dispatch`] takes a method name and params and returns a result or a
//! JSON-RPC error. Wrapping it in HTTP, IPC, or a mobile FFI bridge is the
//! caller's business; what lives here is the part that has to be exactly right
//! either way — method names, parameter shapes, and which failures are the
//! caller's fault rather than the server's.
//!
//! Receipts cross this boundary in [`n42_mobile_verify`]'s binary encoding,
//! hex-wrapped. That is the format the phone already produces, so it is not
//! re-serialised into JSON on the way — a phone that signs one representation
//! and sends another is a phone whose signatures do not verify.
//!
//! ## Methods
//!
//! | method | params | returns |
//! | --- | --- | --- |
//! | `mobile_finality` | — | [`FinalityReport`], or `null` before the first commit |
//! | `mobile_registerVerifier` | `[pubkey_hex, pop_hex]` | the verifier's registry index (a known key needs no `pop_hex`) |
//! | `mobile_submitReceipt` | `[receipt_hex]` | [`SubmitOutcome`] |
//! | `mobile_attestation` | `[block_hash]` | the aggregate, or `null` |
//! | `mobile_getProof` | `[address]` or `[address, slot]` | [`crate::StateProofReport`], or `null` |

use alloy_primitives::{Address, B256};
use n42_mobile_verify::receipt::decode_receipt;
use serde_json::{json, Value};

use crate::service::{MobileService, SubmitError};

/// Standard JSON-RPC error codes, plus the ones this surface adds.
pub mod codes {
    /// The method name is not one of the `mobile_*` methods.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// The params are missing, the wrong shape, or undecodable.
    pub const INVALID_PARAMS: i64 = -32602;
    /// The receipt's signature does not verify.
    pub const INVALID_SIGNATURE: i64 = -32001;
    /// The verifier has not registered.
    pub const UNKNOWN_VERIFIER: i64 = -32002;
    /// The block is not one this node is collecting receipts for.
    pub const UNKNOWN_BLOCK: i64 = -32003;
    /// The commit could not be encoded for phones.
    pub const INTERNAL: i64 = -32603;
    /// The verifier registry holds as many keys as it may.
    pub const REGISTRY_FULL: i64 = -32004;
}

/// A JSON-RPC error: a code the caller can branch on and a message for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// The error code.
    pub code: i64,
    /// What went wrong.
    pub message: String,
}

impl RpcError {
    fn new(code: i64, message: impl std::fmt::Display) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }

    /// The `{code, message}` object a JSON-RPC response carries.
    pub fn to_json(&self) -> Value {
        json!({ "code": self.code, "message": self.message })
    }
}

impl From<SubmitError> for RpcError {
    fn from(error: SubmitError) -> Self {
        // Codes, not just text: a phone has to tell "register first" apart from
        // "your clock is wrong and you signed the wrong block" without parsing
        // English.
        let code = match error {
            SubmitError::InvalidSignature => codes::INVALID_SIGNATURE,
            SubmitError::UnknownVerifier => codes::UNKNOWN_VERIFIER,
            SubmitError::UnknownBlock(_) => codes::UNKNOWN_BLOCK,
        };
        Self::new(code, error)
    }
}

/// Handles one `mobile_*` call.
pub fn dispatch(
    service: &mut MobileService,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    match method {
        "mobile_finality" => Ok(match service.finality() {
            // Null rather than an error: a node that has committed nothing yet
            // is starting up, not broken, and a phone should back off rather
            // than treat it as a fault.
            None => Value::Null,
            Some(report) => serde_json::to_value(report)
                .map_err(|e| RpcError::new(codes::INTERNAL, e))?,
        }),

        "mobile_registerVerifier" => {
            let pubkey = hex_param(params, 0, "pubkey")?;
            let pubkey: [u8; 48] = pubkey.try_into().map_err(|_| {
                RpcError::new(codes::INVALID_PARAMS, "a BLS public key is 48 bytes")
            })?;
            // A known key keeps its index (public: it is the key's bit in
            // every attestation). A new one proves its holder signed it
            // (R3-P6), checked only once the registry has room for it.
            if let Some(index) = service.registry().index_of(&pubkey) {
                return Ok(json!(index));
            }
            if service.registry().len() as usize >= crate::service::MAX_VERIFIERS {
                return Err(RpcError::new(codes::REGISTRY_FULL, "the verifier registry is full"));
            }
            let pop = hex_param(params, 1, "proof of possession")?;
            let pop: [u8; 96] = pop.try_into().map_err(|_| {
                RpcError::new(codes::INVALID_PARAMS, "a proof of possession is a 96-byte BLS signature")
            })?;
            let pop = n42_h2_primitives::BlsSignature::from_bytes(&pop)
                .map_err(|_| RpcError::new(codes::INVALID_SIGNATURE, "the proof of possession is not a signature"))?;
            if !n42_mobile_verify::verify_proof_of_possession(&pubkey, &pop) {
                return Err(RpcError::new(codes::INVALID_SIGNATURE, "the proof of possession does not verify"));
            }
            service
                .try_register_verifier(pubkey)
                .map(|index| json!(index))
                .ok_or_else(|| RpcError::new(codes::REGISTRY_FULL, "the verifier registry is full"))
        }

        "mobile_submitReceipt" => {
            let encoded = hex_param(params, 0, "receipt")?;
            let receipt = decode_receipt(&encoded)
                .map_err(|e| RpcError::new(codes::INVALID_PARAMS, e))?;
            let outcome = service.submit_receipt(&receipt)?;
            serde_json::to_value(outcome).map_err(|e| RpcError::new(codes::INTERNAL, e))
        }

        "mobile_attestation" => {
            let raw = str_param(params, 0, "block hash")?;
            let block_hash: B256 = raw
                .trim_start_matches("0x")
                .parse()
                .map_err(|e| RpcError::new(codes::INVALID_PARAMS, e))?;
            Ok(match service.attestation(&block_hash) {
                None => Value::Null,
                Some(attestation) => serde_json::to_value(attestation)
                    .map_err(|e| RpcError::new(codes::INTERNAL, e))?,
            })
        }

        "mobile_getProof" => {
            let address: Address = str_param(params, 0, "address")?
                .parse()
                .map_err(|e| RpcError::new(codes::INVALID_PARAMS, e))?;
            // Absent second param means the account itself; a present one means
            // that storage slot.
            let slot = match params.get(1) {
                None | Some(Value::Null) => None,
                Some(_) => Some(
                    str_param(params, 1, "slot")?
                        .parse::<B256>()
                        .map_err(|e| RpcError::new(codes::INVALID_PARAMS, e))?,
                ),
            };
            Ok(match service.prove(address, slot) {
                // Null, not an error: a node with no state tree and a key with
                // no leaf are both "nothing to prove", and QMDB membership
                // proofs cannot tell a caller which.
                None => Value::Null,
                Some(report) => serde_json::to_value(report)
                    .map_err(|e| RpcError::new(codes::INTERNAL, e))?,
            })
        }

        other => Err(RpcError::new(
            codes::METHOD_NOT_FOUND,
            format!("no such method: {other}"),
        )),
    }
}

fn str_param<'a>(params: &'a Value, index: usize, what: &str) -> Result<&'a str, RpcError> {
    params
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(codes::INVALID_PARAMS, format!("expected {what} at [{index}]")))
}

fn hex_param(params: &Value, index: usize, what: &str) -> Result<Vec<u8>, RpcError> {
    let raw = str_param(params, index, what)?;
    hex::decode(raw.trim_start_matches("0x"))
        .map_err(|e| RpcError::new(codes::INVALID_PARAMS, format!("{what}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_h2_primitives::bls::BlsSecretKey;
    use n42_h2_primitives::consensus::{H2V4ChainIdentity, QuorumCertificate};
    use n42_mobile_verify::receipt::encode_receipt;
    use n42_mobile_verify::sign_receipt;

    fn service() -> MobileService {
        MobileService::new(
            H2V4ChainIdentity {
                chain_id: 96,
                genesis_hash: B256::repeat_byte(0x42),
            },
            1,
        )
    }

    #[test]
    fn finality_is_null_before_the_first_commit_rather_than_an_error() {
        let mut service = service();
        assert_eq!(
            dispatch(&mut service, "mobile_finality", &json!([])).unwrap(),
            Value::Null
        );
    }

    /// Audit 2026-10 round 3 (R3-P6): the registry took every key anyone
    /// sent and never let one go. Past its bound a new key is refused; a
    /// known one still gets its index.
    #[test]
    fn the_verifier_registry_is_bounded() {
        let mut service = service();
        let key = |i: u64| {
            let mut key = [0u8; 48];
            key[..8].copy_from_slice(&i.to_le_bytes());
            key
        };
        for i in 0..crate::service::MAX_VERIFIERS as u64 {
            service.register_verifier(key(i));
        }
        let register = |service: &mut MobileService, key: [u8; 48]| {
            dispatch(service, "mobile_registerVerifier", &json!([format!("0x{}", hex::encode(key))]))
        };
        register(&mut service, [0xff; 48]).expect_err("the registry is full");
        assert_eq!(register(&mut service, key(5)).expect("a known key"), json!(5));
    }

    /// Audit 2026-10 round 3 (R3-P6): a key was registered on its bytes
    /// alone, so a party could register a key derived from others' (a rogue
    /// key) and, with the attestation aggregating one message, forge a
    /// participant's signature. A new key comes with a proof that its holder
    /// signed it; a known key still gets its index.
    #[test]
    fn a_new_verifier_proves_it_holds_its_key() {
        let mut service = service();
        let key = BlsSecretKey::random().unwrap();
        let pubkey = format!("0x{}", hex::encode(key.public_key().to_bytes()));
        let err = dispatch(&mut service, "mobile_registerVerifier", &json!([pubkey])).unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS, "no proof");
        let other = BlsSecretKey::random().unwrap();
        let wrong = format!("0x{}", hex::encode(n42_mobile_verify::proof_of_possession(&other).to_bytes()));
        let err = dispatch(&mut service, "mobile_registerVerifier", &json!([pubkey, wrong])).unwrap_err();
        assert_eq!(err.code, codes::INVALID_SIGNATURE, "another key's proof");
        let pop = format!("0x{}", hex::encode(n42_mobile_verify::proof_of_possession(&key).to_bytes()));
        assert_eq!(dispatch(&mut service, "mobile_registerVerifier", &json!([pubkey, pop])).unwrap(), json!(0));
        assert_eq!(dispatch(&mut service, "mobile_registerVerifier", &json!([pubkey])).unwrap(), json!(0), "known");
    }

    #[test]
    fn a_receipt_makes_the_round_trip_in_the_encoding_the_phone_signed() {
        let block_hash = B256::repeat_byte(0x11);
        let root = B256::repeat_byte(0x22);
        let mut service = service();
        service
            .record_commit(1, block_hash, 1, QuorumCertificate::genesis(), Some(root))
            .unwrap();

        let key = BlsSecretKey::random().unwrap();
        let index = dispatch(
            &mut service,
            "mobile_registerVerifier",
            &json!([
                format!("0x{}", hex::encode(key.public_key().to_bytes())),
                format!("0x{}", hex::encode(n42_mobile_verify::proof_of_possession(&key).to_bytes())),
            ]),
        )
        .unwrap();
        assert_eq!(index, json!(0));

        let receipt = sign_receipt(block_hash, 1, root, 0, &key);
        let encoded = format!("0x{}", hex::encode(encode_receipt(&receipt)));
        let outcome =
            dispatch(&mut service, "mobile_submitReceipt", &json!([encoded])).unwrap();
        assert_eq!(outcome["accepted"], json!(true));
        assert_eq!(outcome["attested"], json!(true));

        let attestation = dispatch(
            &mut service,
            "mobile_attestation",
            &json!([block_hash.to_string()]),
        )
        .unwrap();
        assert_eq!(attestation["participant_count"], json!(1));
    }

    /// A phone branches on these. Text would force it to parse English, and the
    /// three cases call for three different responses: register, re-sign, or
    /// give up on this block.
    #[test]
    fn each_refusal_carries_a_code_the_caller_can_branch_on() {
        let block_hash = B256::repeat_byte(0x11);
        let mut service = service();
        service
            .record_commit(1, block_hash, 1, QuorumCertificate::genesis(), None)
            .unwrap();

        let key = BlsSecretKey::random().unwrap();
        let receipt = sign_receipt(block_hash, 1, B256::repeat_byte(0x22), 0, &key);
        let encoded = format!("0x{}", hex::encode(encode_receipt(&receipt)));

        // Unregistered.
        let err = dispatch(&mut service, "mobile_submitReceipt", &json!([encoded]))
            .unwrap_err();
        assert_eq!(err.code, codes::UNKNOWN_VERIFIER);

        // Registered, but the block is not tracked.
        dispatch(
            &mut service,
            "mobile_registerVerifier",
            &json!([
                format!("0x{}", hex::encode(key.public_key().to_bytes())),
                format!("0x{}", hex::encode(n42_mobile_verify::proof_of_possession(&key).to_bytes())),
            ]),
        )
        .unwrap();
        let stranger = sign_receipt(B256::repeat_byte(0x99), 1, B256::ZERO, 0, &key);
        let err = dispatch(
            &mut service,
            "mobile_submitReceipt",
            &json!([format!("0x{}", hex::encode(encode_receipt(&stranger)))]),
        )
        .unwrap_err();
        assert_eq!(err.code, codes::UNKNOWN_BLOCK);

        // A forgery.
        let attacker = BlsSecretKey::random().unwrap();
        let mut forged = sign_receipt(block_hash, 1, B256::repeat_byte(0x22), 0, &attacker);
        forged.verifier_pubkey = key.public_key().to_bytes();
        let err = dispatch(
            &mut service,
            "mobile_submitReceipt",
            &json!([format!("0x{}", hex::encode(encode_receipt(&forged)))]),
        )
        .unwrap_err();
        assert_eq!(err.code, codes::INVALID_SIGNATURE);
    }

    #[test]
    fn malformed_params_are_the_callers_fault_not_the_servers() {
        let mut service = service();
        for (method, params) in [
            ("mobile_registerVerifier", json!([])),
            ("mobile_registerVerifier", json!(["0xnothex"])),
            // 47 bytes: a plausible-looking key of the wrong length.
            ("mobile_registerVerifier", json!([format!("0x{}", "ab".repeat(47))])),
            ("mobile_submitReceipt", json!(["0x00"])),
            ("mobile_attestation", json!([])),
            ("mobile_attestation", json!(["not a hash"])),
        ] {
            let err = dispatch(&mut service, method, &params).unwrap_err();
            assert_eq!(
                err.code,
                codes::INVALID_PARAMS,
                "{method} with {params} should be a caller error",
            );
        }
    }

    #[test]
    fn an_unknown_method_says_so() {
        let mut service = service();
        let err = dispatch(&mut service, "mobile_nope", &json!([])).unwrap_err();
        assert_eq!(err.code, codes::METHOD_NOT_FOUND);
    }
}
