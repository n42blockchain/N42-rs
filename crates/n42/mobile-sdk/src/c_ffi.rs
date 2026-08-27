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
    let value = match val_str.parse::<U256>() {
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
            Ok(s) => match s.parse::<U256>() {
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
