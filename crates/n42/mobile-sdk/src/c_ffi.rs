use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use ethers::types::{TransactionRequest, U256};
use eyre::Result;
use serde_json;

use crate::{deposit_exit::{create_deposit_unsigned_tx, create_get_exit_fee_unsigned_tx, create_exit_unsigned_tx}, run_client};

// ---------------- Helpers ----------------
fn cstr_to_string(c: *const c_char) -> Result<String, String> {
    if c.is_null() {
        return Err("null pointer".into());
    }
    unsafe { CStr::from_ptr(c).to_str().map(|s| s.to_owned()).map_err(|e|
format!("utf8 error: {}", e)) }
}

fn make_c_string(s: String) -> *mut c_char {
    CString::new(s).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rust_free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { drop(CString::from_raw(s)); }
}

// ---------------- run_client ----------------
#[no_mangle]
pub extern "C" fn run_client_c(
    ws_url: *const c_char,
    validator_private_key: *const c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe { *out_error = make_c_string(msg); }
        }
    };

    let ws = match cstr_to_string(ws_url) { Ok(s) => s, Err(e) => {
set_error(e); return -1; } };
    let pk = match cstr_to_string(validator_private_key) { Ok(s) => s, Err(e)
=> { set_error(e); return -1; } };

    // run the async function blocking
    let res = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_client(&ws, &pk));

    match res {
        Ok(()) => 0, // success
        Err(e) => { set_error(format!("{}", e)); -1 }
    }
}

// ---------------- create_deposit_unsigned_tx ----------------
#[no_mangle]
pub extern "C" fn create_deposit_unsigned_tx_c(
    deposit_contract_address: *const c_char,
    validator_private_key: *const c_char,
    withdrawal_address: *const c_char,
    deposit_value_in_wei: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe { *out_error = make_c_string(msg); }
        }
    };

    let addr = match cstr_to_string(deposit_contract_address) { Ok(s) => s,
Err(e) => { set_error(e); return ptr::null_mut(); } };
    let pk = match cstr_to_string(validator_private_key) { Ok(s) => s, Err(e)
=> { set_error(e); return ptr::null_mut(); } };
    let wd = match cstr_to_string(withdrawal_address) { Ok(s) => s, Err(e) =>
{ set_error(e); return ptr::null_mut(); } };
    let val_str = match cstr_to_string(deposit_value_in_wei) { Ok(s) => s,
Err(e) => { set_error(e); return ptr::null_mut(); } };
    let value = match val_str.parse::<U256>() { Ok(v) => v, Err(_) => {
set_error("invalid deposit value".into()); return ptr::null_mut(); } };

    match create_deposit_unsigned_tx(addr, pk, wd, value) {
        Ok(tx) => make_c_string(serde_json::to_string(&tx).unwrap()),
        Err(e) => { set_error(format!("{}", e)); ptr::null_mut() }
    }
}

// ---------------- create_get_exit_fee_unsigned_tx ----------------
#[no_mangle]
pub extern "C" fn create_get_exit_fee_unsigned_tx_c(
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe { *out_error = make_c_string(msg); }
        }
    };

    match create_get_exit_fee_unsigned_tx() {
        Ok(tx) => make_c_string(serde_json::to_string(&tx).unwrap()),
        Err(e) => { set_error(format!("{}", e)); ptr::null_mut() }
    }
}

// ---------------- create_exit_unsigned_tx ----------------
#[no_mangle]
pub extern "C" fn create_exit_unsigned_tx_c(
    validator_public_key: *const c_char,
    fee_in_wei_or_empty: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let mut set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe { *out_error = make_c_string(msg); }
        }
    };

    let pubkey = match cstr_to_string(validator_public_key) { Ok(s) => s,
Err(e) => { set_error(e); return ptr::null_mut(); } };

    let fee_opt = if fee_in_wei_or_empty.is_null() {
        None
    } else {
        match cstr_to_string(fee_in_wei_or_empty) {
            Ok(s) if s.is_empty() => None,
            Ok(s) => Some(s.parse::<U256>().unwrap_or_else(|_| {
set_error("invalid fee".into()); U256::zero() })),
            Err(e) => { set_error(e); return ptr::null_mut(); }
        }
    };

    match create_exit_unsigned_tx(pubkey, fee_opt) {
        Ok(tx) => make_c_string(serde_json::to_string(&tx).unwrap()),
        Err(e) => { set_error(format!("{}", e)); ptr::null_mut() }
    }
}
