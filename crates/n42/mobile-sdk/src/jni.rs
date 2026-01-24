// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use ethers::types::U256;
use jni::objects::{GlobalRef, JObject, JString};
use jni::sys::{jobject, jstring};
use jni::JNIEnv;
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

use crate::blst_utils::generate_bls12_381_keypair;

/// Helper to safely extract a Java string, throwing exception if null or invalid.
fn get_required_string(
    env: &mut JNIEnv<'_>,
    s: &JString<'_>,
    field_name: &str,
) -> Result<String, ()> {
    if s.is_null() {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            format!("{} cannot be null", field_name),
        );
        return Err(());
    }
    match env.get_string(s) {
        Ok(js) => Ok(js.into()),
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("Failed to read {}", field_name),
            );
            Err(())
        }
    }
}
use crate::deposit_exit::{
    create_deposit_unsigned_tx, create_exit_unsigned_tx, create_get_exit_fee_unsigned_tx,
};
use crate::run_client;

static RUNTIME: Lazy<Runtime> =
    Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));

#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createDepositUnsignedTx(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    deposit_contract_address: JString<'_>,
    validator_private_key: JString<'_>,
    withdrawal_address: JString<'_>,
    deposit_value_wei_in_hex: JString<'_>,
) -> jstring {
    let deposit_contract_address = match get_required_string(
        &mut env,
        &deposit_contract_address,
        "deposit_contract_address",
    ) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let validator_private_key =
        match get_required_string(&mut env, &validator_private_key, "validator_private_key") {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
    let withdrawal_address =
        match get_required_string(&mut env, &withdrawal_address, "withdrawal_address") {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
    let deposit_value_wei_in_hex = match get_required_string(
        &mut env,
        &deposit_value_wei_in_hex,
        "deposit_value_wei_in_hex",
    ) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let deposit_value_wei = match deposit_value_wei_in_hex.parse::<U256>() {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    let transaction_request = match create_deposit_unsigned_tx(
        &deposit_contract_address,
        &validator_private_key,
        &withdrawal_address,
        &deposit_value_wei,
    ) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&transaction_request) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    env.new_string(&json_string)
        .expect("Couldn't create Java string!")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_generateBls12381Keypair(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jstring {
    let key_pair = match generate_bls12_381_keypair() {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&key_pair) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    env.new_string(&json_string)
        .expect("Couldn't create Java string!")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createGetExitFeeUnsignedTx(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jstring {
    let transaction_request = match create_get_exit_fee_unsigned_tx() {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&transaction_request) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    env.new_string(&json_string)
        .expect("Couldn't create Java string!")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createExitUnsignedTx(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    validator_public_key: JString<'_>,
    exit_fee_in_wei_in_hex: JString<'_>,
) -> jstring {
    let validator_public_key =
        match get_required_string(&mut env, &validator_public_key, "validator_public_key") {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
    let fee = if !exit_fee_in_wei_in_hex.is_null() {
        let exit_fee_in_wei_in_hex = match env.get_string(&exit_fee_in_wei_in_hex) {
            Ok(s) => String::from(s),
            Err(_) => {
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    "Failed to read exit_fee_in_wei_in_hex",
                );
                return std::ptr::null_mut();
            }
        };

        let exit_fee_in_wei = match exit_fee_in_wei_in_hex.parse::<U256>() {
            Ok(v) => v,
            Err(e) => {
                env.throw_new("java/lang/Exception", e.to_string())
                    .expect("Failed to throw exception");
                return std::ptr::null_mut();
            }
        };

        Some(exit_fee_in_wei)
    } else {
        None
    };

    let transaction_request = match create_exit_unsigned_tx(&validator_public_key, &fee) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&transaction_request) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };

    env.new_string(&json_string)
        .expect("Couldn't create Java string!")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_runClient(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ws_url: JString<'_>,
    validator_private_key: JString<'_>,
) -> jobject {
    let ws_url = match get_required_string(&mut env, &ws_url, "ws_url") {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let validator_private_key =
        match get_required_string(&mut env, &validator_private_key, "validator_private_key") {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

    // Create a new CompletableFuture object in Java
    let cf_class = match env.find_class("java/util/concurrent/CompletableFuture") {
        Ok(c) => c,
        Err(_) => {
            let _ = env.throw_new("java/lang/RuntimeException", "Failed to find CompletableFuture class");
            return std::ptr::null_mut();
        }
    };
    let cf_obj = match env.new_object(cf_class, "()V", &[]) {
        Ok(o) => o,
        Err(_) => {
            let _ = env.throw_new("java/lang/RuntimeException", "Failed to create CompletableFuture");
            return std::ptr::null_mut();
        }
    };

    // Promote CompletableFuture to a global ref so it outlives this JNI call
    let global_cf: GlobalRef = match env.new_global_ref(&cf_obj) {
        Ok(g) => g,
        Err(_) => {
            let _ = env.throw_new("java/lang/RuntimeException", "Failed to create global ref");
            return std::ptr::null_mut();
        }
    };

    let jvm = match env.get_java_vm() {
        Ok(j) => j,
        Err(_) => {
            let _ = env.throw_new("java/lang/RuntimeException", "Failed to get JVM");
            return std::ptr::null_mut();
        }
    };

    // Spawn async task
    RUNTIME.spawn(async move {
        let result = run_client(&ws_url, &validator_private_key).await;

        // Attach thread to JVM to call back into Java
        let mut env = match jvm.attach_current_thread() {
            Ok(env) => env,
            Err(e) => {
                eprintln!("Failed to attach thread to JVM: {}", e);
                return;
            }
        };

        match result {
            Ok(()) => {
                // Call CompletableFuture.complete(null)
                let _ = env.call_method(
                    &global_cf,
                    "complete",
                    "(Ljava/lang/Object;)Z",
                    &[(&JObject::null()).into()],
                );
            }

            Err(e) => {
                // Try to create and throw a Java exception
                let error_msg = e.to_string();
                let jmsg = match env.new_string(&error_msg) {
                    Ok(s) => s,
                    Err(je) => {
                        eprintln!("Failed to create Java string for error '{}': {}", error_msg, je);
                        return;
                    }
                };
                let ex_class = match env.find_class("java/lang/RuntimeException") {
                    Ok(c) => c,
                    Err(je) => {
                        eprintln!("Failed to find RuntimeException class: {}", je);
                        return;
                    }
                };
                let ex_obj = match env.new_object(ex_class, "(Ljava/lang/String;)V", &[(&jmsg).into()]) {
                    Ok(o) => o,
                    Err(je) => {
                        eprintln!("Failed to create RuntimeException: {}", je);
                        return;
                    }
                };

                let _ = env.call_method(
                    &global_cf,
                    "completeExceptionally",
                    "(Ljava/lang/Throwable;)Z",
                    &[(&JObject::from(ex_obj)).into()],
                );
            }
        }
    });

    cf_obj.into_raw() // return CompletableFuture immediately
}
