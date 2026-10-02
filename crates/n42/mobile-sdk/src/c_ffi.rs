// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use ethers::types::U256;

use crate::blst_utils::generate_bls12_381_keypair;
use crate::{
    deposit_exit::{
        create_deposit_unsigned_tx, create_exit_unsigned_tx, create_get_exit_fee_unsigned_tx,
    },
    run_client,
};

// ---------------- Helpers ----------------
fn cstr_to_string(c: *const c_char) -> Result<String, String> {
    if c.is_null() {
        return Err("null pointer".into());
    }
    unsafe {
        CStr::from_ptr(c)
            .to_str()
            .map(|s| s.to_owned())
            .map_err(|e| format!("utf8 error: {}", e))
    }
}

/// Parses an amount in wei passed across the C boundary.
///
/// A string with a `0x`/`0X` prefix is hex; a string without a prefix is decimal.
/// Anything else (empty, a bare prefix, other characters, a value above `U256::MAX`)
/// is an error, never a silently different amount.
fn parse_wei(s: &str) -> Result<U256, ()> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(());
        }
        let digits = hex.trim_start_matches('0');
        if digits.len() > 64 {
            return Err(());
        }
        if digits.is_empty() {
            return Ok(U256::zero());
        }
        U256::from_str_radix(digits, 16).map_err(|_| ())
    } else {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(());
        }
        U256::from_dec_str(s).map_err(|_| ())
    }
}

fn make_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => {
            // String contains null byte, replace with error message
            CString::new("string contains null byte")
                .expect("static string is valid")
                .into_raw()
        }
    }
}

/// # Safety
///
/// Every pointer must be null or valid for the whole call: `*const c_char`
/// arguments point at NUL-terminated strings, `out_error` (when not null) at a
/// writable slot that receives a string the caller frees with
/// `rust_free_string`, and strings passed to `rust_free_string` must have come
/// from this library and not been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

// ---------------- run_client ----------------
/// # Safety
///
/// Every pointer must be null or valid for the whole call: `*const c_char`
/// arguments point at NUL-terminated strings, `out_error` (when not null) at a
/// writable slot that receives a string the caller frees with
/// `rust_free_string`, and strings passed to `rust_free_string` must have come
/// from this library and not been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn run_client_c(
    ws_url: *const c_char,
    validator_private_key: *const c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    let ws = match cstr_to_string(ws_url) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    let pk = match cstr_to_string(validator_private_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };

    // run the async function blocking
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_error(format!("failed to create runtime: {}", e));
            return -1;
        }
    };

    match runtime.block_on(run_client(&ws, &pk)) {
        Ok(()) => 0, // success
        Err(e) => {
            set_error(format!("{}", e));
            -1
        }
    }
}

// ---------------- generate_bls12_381_keypair ----------------
/// # Safety
///
/// Every pointer must be null or valid for the whole call: `*const c_char`
/// arguments point at NUL-terminated strings, `out_error` (when not null) at a
/// writable slot that receives a string the caller frees with
/// `rust_free_string`, and strings passed to `rust_free_string` must have come
/// from this library and not been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generate_bls12_381_keypair_c(out_error: *mut *mut c_char) -> *mut c_char {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    match generate_bls12_381_keypair() {
        Ok(tx) => {
            let json_string = match serde_json::to_string(&tx) {
                Ok(v) => v,
                Err(e) => {
                    set_error(format!("{}", e));
                    return ptr::null_mut();
                }
            };

            make_c_string(json_string)
        }
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

// ---------------- create_deposit_unsigned_tx ----------------
/// Builds an unsigned deposit transaction as JSON.
///
/// `deposit_value_in_wei` is decimal (`"32000000000000000000"`) or `0x`-prefixed hex
/// (`"0x1bc16d674ec800000"`); a bare string is always decimal, and anything else is
/// reported through `out_error`.
///
/// # Safety
///
/// Every pointer must be null or valid for the whole call: `*const c_char`
/// arguments point at NUL-terminated strings, `out_error` (when not null) at a
/// writable slot that receives a string the caller frees with
/// `rust_free_string`, and strings passed to `rust_free_string` must have come
/// from this library and not been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_deposit_unsigned_tx_c(
    deposit_contract_address: *const c_char,
    validator_private_key: *const c_char,
    withdrawal_address: *const c_char,
    deposit_value_in_wei: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    let addr = match cstr_to_string(deposit_contract_address) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };
    let pk = match cstr_to_string(validator_private_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };
    let wd = match cstr_to_string(withdrawal_address) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };
    let val_str = match cstr_to_string(deposit_value_in_wei) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };
    let value = match parse_wei(&val_str) {
        Ok(v) => v,
        Err(_) => {
            set_error("invalid deposit value".into());
            return ptr::null_mut();
        }
    };

    match create_deposit_unsigned_tx(&addr, &pk, &wd, &value) {
        Ok(tx) => {
            let json_string = match serde_json::to_string(&tx) {
                Ok(v) => v,
                Err(e) => {
                    set_error(format!("{}", e));
                    return ptr::null_mut();
                }
            };

            make_c_string(json_string)
        }
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

// ---------------- create_get_exit_fee_unsigned_tx ----------------
/// # Safety
///
/// Every pointer must be null or valid for the whole call: `*const c_char`
/// arguments point at NUL-terminated strings, `out_error` (when not null) at a
/// writable slot that receives a string the caller frees with
/// `rust_free_string`, and strings passed to `rust_free_string` must have come
/// from this library and not been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_get_exit_fee_unsigned_tx_c(out_error: *mut *mut c_char) -> *mut c_char {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    match create_get_exit_fee_unsigned_tx() {
        Ok(tx) => {
            let json_string = match serde_json::to_string(&tx) {
                Ok(v) => v,
                Err(e) => {
                    set_error(format!("{}", e));
                    return ptr::null_mut();
                }
            };

            make_c_string(json_string)
        }
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

// ---------------- create_exit_unsigned_tx ----------------
/// Builds an unsigned exit transaction as JSON.
///
/// `fee_in_wei_or_empty` is null or empty for the default fee (1 wei), otherwise decimal
/// or `0x`-prefixed hex; a bare string is always decimal, and anything else is reported
/// through `out_error`.
///
/// # Safety
///
/// Every pointer must be null or valid for the whole call: `*const c_char`
/// arguments point at NUL-terminated strings, `out_error` (when not null) at a
/// writable slot that receives a string the caller frees with
/// `rust_free_string`, and strings passed to `rust_free_string` must have come
/// from this library and not been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_exit_unsigned_tx_c(
    validator_public_key: *const c_char,
    fee_in_wei_or_empty: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    let pubkey = match cstr_to_string(validator_public_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    let fee_opt = if fee_in_wei_or_empty.is_null() {
        None
    } else {
        match cstr_to_string(fee_in_wei_or_empty) {
            Ok(s) if s.is_empty() => None,
            Ok(s) => match parse_wei(&s) {
                Ok(v) => Some(v),
                Err(_) => {
                    set_error("invalid fee".into());
                    return ptr::null_mut();
                }
            },
            Err(e) => {
                set_error(e);
                return ptr::null_mut();
            }
        }
    };

    match create_exit_unsigned_tx(&pubkey, &fee_opt) {
        Ok(tx) => {
            let json_string = match serde_json::to_string(&tx) {
                Ok(v) => v,
                Err(e) => {
                    set_error(format!("{}", e));
                    return ptr::null_mut();
                }
            };

            make_c_string(json_string)
        }
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SK: &str = "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
    const WITHDRAWAL: &str = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";
    const CONTRACT: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    const PUBKEY: &str = "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";

    fn c(s: &str) -> CString {
        CString::new(s).expect("no interior nul")
    }

    /// Reads and frees a string the library returned.
    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null(), "expected a string, got null");
        let s = unsafe { CStr::from_ptr(p) }.to_str().expect("utf8").to_owned();
        unsafe { rust_free_string(p) };
        s
    }

    /// Calls `f` with an error slot and returns (result, error message if any).
    fn with_error<R>(f: impl FnOnce(*mut *mut c_char) -> R) -> (R, Option<String>) {
        let mut slot: *mut c_char = ptr::null_mut();
        let result = f(&raw mut slot);
        let message = if slot.is_null() { None } else { Some(unsafe { take(slot) }) };
        (result, message)
    }

    // ---- helpers ----

    #[test]
    fn cstr_to_string_rejects_null_and_bad_utf8_and_reads_valid_strings() {
        assert_eq!(cstr_to_string(ptr::null()), Err("null pointer".to_string()));
        let bad = c"\xff\xfe";
        let err = cstr_to_string(bad.as_ptr()).expect_err("invalid utf8");
        assert!(err.starts_with("utf8 error"), "{err}");
        let ok = c("héllo");
        assert_eq!(cstr_to_string(ok.as_ptr()).as_deref(), Ok("héllo"));
        let empty = c("");
        assert_eq!(cstr_to_string(empty.as_ptr()).as_deref(), Ok(""));
    }

    #[test]
    fn make_c_string_round_trips_and_replaces_interior_nuls_with_a_message() {
        assert_eq!(unsafe { take(make_c_string("abc".into())) }, "abc");
        assert_eq!(unsafe { take(make_c_string("a\0b".into())) }, "string contains null byte");
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe { rust_free_string(ptr::null_mut()) };
    }

    // ---- generate_bls12_381_keypair_c ----

    #[test]
    fn a_generated_keypair_is_a_json_pair_of_matching_hex_keys() {
        let (out, err) = with_error(|e| unsafe { generate_bls12_381_keypair_c(e) });
        assert!(err.is_none());
        let json: Value = serde_json::from_str(&unsafe { take(out) }).expect("json");
        let pair = json.as_array().expect("a [private, public] pair");
        assert_eq!(pair.len(), 2);
        let sk = hex::decode(pair[0].as_str().unwrap()).unwrap();
        let pk = hex::decode(pair[1].as_str().unwrap()).unwrap();
        assert_eq!(sk.len(), 32);
        assert_eq!(pk.len(), 48);
        let derived = blst::min_pk::SecretKey::from_bytes(&sk).unwrap().sk_to_pk();
        assert_eq!(derived.to_bytes().to_vec(), pk);
    }

    #[test]
    fn two_generated_keypairs_differ() {
        let a = unsafe { take(generate_bls12_381_keypair_c(ptr::null_mut())) };
        let b = unsafe { take(generate_bls12_381_keypair_c(ptr::null_mut())) };
        assert_ne!(a, b);
    }

    // ---- create_get_exit_fee_unsigned_tx_c ----

    #[test]
    fn the_exit_fee_query_targets_the_eip7002_contract_with_empty_calldata() {
        let (out, err) = with_error(|e| unsafe { create_get_exit_fee_unsigned_tx_c(e) });
        assert!(err.is_none());
        let tx: Value = serde_json::from_str(&unsafe { take(out) }).unwrap();
        assert_eq!(
            tx["to"].as_str().unwrap().to_lowercase(),
            crate::deposit_exit::EIP7002_CONTRACT_ADDRESS.to_lowercase()
        );
        assert_eq!(tx["data"], "0x");
        // A null error slot is accepted.
        unsafe { rust_free_string(create_get_exit_fee_unsigned_tx_c(ptr::null_mut())) };
    }

    // ---- create_exit_unsigned_tx_c ----

    fn exit(pubkey: *const c_char, fee: *const c_char) -> (*mut c_char, Option<String>) {
        with_error(|e| unsafe { create_exit_unsigned_tx_c(pubkey, fee, e) })
    }

    #[test]
    fn an_exit_carries_the_pubkey_and_a_zero_amount_and_defaults_the_fee_to_one_wei() {
        let pk = c(PUBKEY);
        let empty = c("");
        for fee in [ptr::null(), empty.as_ptr()] {
            let (out, err) = exit(pk.as_ptr(), fee);
            assert!(err.is_none());
            let tx: Value = serde_json::from_str(&unsafe { take(out) }).unwrap();
            assert_eq!(tx["value"], "0x1");
            assert_eq!(tx["data"], format!("0x{PUBKEY}0000000000000000"));
        }
    }

    #[test]
    fn an_exit_fee_is_parsed_as_hex() {
        let pk = c(PUBKEY);
        let fee = c("0x10");
        let (out, err) = exit(pk.as_ptr(), fee.as_ptr());
        assert!(err.is_none());
        let tx: Value = serde_json::from_str(&unsafe { take(out) }).unwrap();
        assert_eq!(tx["value"], "0x10");
    }

    #[test]
    fn an_exit_fee_without_a_prefix_is_decimal() {
        let pk = c(PUBKEY);
        for (fee, expected) in [("100", "0x64"), ("0X10", "0x10"), ("16", "0x10")] {
            let fee = c(fee);
            let (out, err) = exit(pk.as_ptr(), fee.as_ptr());
            assert!(err.is_none(), "{err:?}");
            let tx: Value = serde_json::from_str(&unsafe { take(out) }).unwrap();
            assert_eq!(tx["value"], expected);
        }
    }

    #[test]
    fn wei_amounts_are_hex_with_a_prefix_and_decimal_without() {
        assert_eq!(parse_wei("100"), Ok(U256::from(100u64)));
        assert_eq!(parse_wei("0x100"), Ok(U256::from(256u64)));
        assert_eq!(parse_wei("0X0"), Ok(U256::zero()));
        assert_eq!(parse_wei("0"), Ok(U256::zero()));
        assert_eq!(parse_wei(&format!("0x{}", "f".repeat(64))), Ok(U256::MAX));
        assert_eq!(parse_wei(&format!("0x{}1", "0".repeat(70))), Ok(U256::one()));
        assert_eq!(parse_wei(&U256::MAX.to_string()), Ok(U256::MAX));
        // Bare hex letters, an empty string, a bare prefix, signs and spaces are errors.
        for bad in ["ff", "1bc16d674ec800000", "", "0x", "-1", "+1", " 1", "1.0", "0xg"] {
            assert_eq!(parse_wei(bad), Err(()), "{bad:?}");
        }
        // Overflow is an error in either base.
        assert_eq!(parse_wei(&format!("0x1{}", "0".repeat(64))), Err(()));
        assert_eq!(
            parse_wei("115792089237316195423570985008687907853269984665640564039457584007913129639936"),
            Err(())
        );
    }

    #[test]
    fn exit_errors_come_back_as_null_plus_a_message() {
        let pk = c(PUBKEY);
        let (out, err) = exit(ptr::null(), ptr::null());
        assert!(out.is_null());
        assert_eq!(err.as_deref(), Some("null pointer"));

        for bad in ["not a number", "10abc", "0x", &format!("0x1{}", "0".repeat(64))] {
            let fee = c(bad);
            let (out, err) = exit(pk.as_ptr(), fee.as_ptr());
            assert!(out.is_null(), "{bad:?}");
            assert_eq!(err.as_deref(), Some("invalid fee"), "{bad:?}");
        }

        let short = c("0xabcd");
        let (out, err) = exit(short.as_ptr(), ptr::null());
        assert!(out.is_null());
        assert!(err.unwrap().contains("48 bytes"));

        let bad_utf8 = c"\xff";
        let (out, err) = exit(pk.as_ptr(), bad_utf8.as_ptr());
        assert!(out.is_null());
        assert!(err.unwrap().starts_with("utf8 error"));

        // And with no error slot at all, nothing is written and nothing crashes.
        assert!(unsafe { create_exit_unsigned_tx_c(ptr::null(), ptr::null(), ptr::null_mut()) }.is_null());
    }

    // ---- create_deposit_unsigned_tx_c ----

    fn deposit(
        contract: *const c_char,
        sk: *const c_char,
        withdrawal: *const c_char,
        value: *const c_char,
    ) -> (*mut c_char, Option<String>) {
        with_error(|e| unsafe { create_deposit_unsigned_tx_c(contract, sk, withdrawal, value, e) })
    }

    #[test]
    fn a_deposit_matches_the_rust_api_and_targets_the_contract_with_the_value_and_gas() {
        let (contract, sk, wd, value) = (c(CONTRACT), c(SK), c(WITHDRAWAL), c("0x1bc16d674ec800000"));
        let (out, err) = deposit(contract.as_ptr(), sk.as_ptr(), wd.as_ptr(), value.as_ptr());
        assert!(err.is_none());
        let tx: Value = serde_json::from_str(&unsafe { take(out) }).unwrap();

        let expected = crate::deposit_exit::create_deposit_unsigned_tx(
            CONTRACT,
            SK,
            WITHDRAWAL,
            &"0x1bc16d674ec800000".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(tx, serde_json::to_value(&expected).unwrap(), "BLS signing is deterministic");
        assert_eq!(tx["to"].as_str().unwrap().to_lowercase(), CONTRACT.to_lowercase());
        assert_eq!(tx["value"], "0x1bc16d674ec800000");
        assert_eq!(tx["gas"], "0x493e0", "300,000 gas");
    }

    #[test]
    fn a_null_in_any_deposit_argument_is_reported() {
        let (contract, sk, wd, value) = (c(CONTRACT), c(SK), c(WITHDRAWAL), c("0x1"));
        for which in 0..4 {
            let mut args = [contract.as_ptr(), sk.as_ptr(), wd.as_ptr(), value.as_ptr()];
            args[which] = ptr::null();
            let (out, err) = deposit(args[0], args[1], args[2], args[3]);
            assert!(out.is_null(), "argument {which}");
            assert_eq!(err.as_deref(), Some("null pointer"), "argument {which}");
        }
    }

    #[test]
    fn a_bad_deposit_value_withdrawal_address_and_key_are_reported() {
        let (contract, sk, wd) = (c(CONTRACT), c(SK), c(WITHDRAWAL));
        for bad in ["xyz", "ff", "", "0x", &format!("0x1{}", "0".repeat(64))] {
            let bad_value = c(bad);
            let (out, err) =
                deposit(contract.as_ptr(), sk.as_ptr(), wd.as_ptr(), bad_value.as_ptr());
            assert!(out.is_null(), "{bad:?}");
            assert_eq!(err.as_deref(), Some("invalid deposit value"), "{bad:?}");
        }

        // A decimal value is read as decimal: "100" is 100 wei, not 0x100.
        let decimal = c("100");
        let (out, err) = deposit(contract.as_ptr(), sk.as_ptr(), wd.as_ptr(), decimal.as_ptr());
        assert!(err.is_none(), "{err:?}");
        let tx: Value = serde_json::from_str(&unsafe { take(out) }).unwrap();
        assert_eq!(tx["value"], "0x64");

        let value = c("0x1");
        let short = c("0x1234");
        let (out, err) = deposit(contract.as_ptr(), sk.as_ptr(), short.as_ptr(), value.as_ptr());
        assert!(out.is_null());
        assert!(err.unwrap().contains("20 bytes"));

        let bad_key = c("0x1234");
        let (out, err) = deposit(contract.as_ptr(), bad_key.as_ptr(), wd.as_ptr(), value.as_ptr());
        assert!(out.is_null());
        assert!(err.unwrap().contains("SecretKey"));
    }

    // ---- run_client_c ----

    #[test]
    fn run_client_reports_null_arguments_and_bad_keys_without_connecting() {
        let ws = c("ws://127.0.0.1:1");
        let (code, err) = with_error(|e| unsafe { run_client_c(ptr::null(), ws.as_ptr(), e) });
        assert_eq!((code, err.as_deref()), (-1, Some("null pointer")));
        let (code, err) = with_error(|e| unsafe { run_client_c(ws.as_ptr(), ptr::null(), e) });
        assert_eq!((code, err.as_deref()), (-1, Some("null pointer")));
        let not_hex = c("zz");
        let (code, err) = with_error(|e| unsafe { run_client_c(ws.as_ptr(), not_hex.as_ptr(), e) });
        assert_eq!(code, -1);
        assert!(err.is_some());
        assert_eq!(unsafe { run_client_c(ptr::null(), ptr::null(), ptr::null_mut()) }, -1);
    }

    #[test]
    fn run_client_fails_when_nothing_listens_at_the_url() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let ws = c(&format!("ws://127.0.0.1:{port}"));
        let sk = c(SK);
        let (code, err) = with_error(|e| unsafe { run_client_c(ws.as_ptr(), sk.as_ptr(), e) });
        assert_eq!(code, -1);
        assert!(!err.expect("a message").is_empty());
    }
}
