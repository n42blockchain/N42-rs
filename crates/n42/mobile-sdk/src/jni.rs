use ethers::types::U256;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::jstring;
use jni::sys::jobject;
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

use crate::deposit_exit::{create_deposit_unsigned_tx, create_exit_unsigned_tx};
use crate::run_client;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create Tokio runtime")
});

#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createDepositUnsignedTx(
    mut env: jni::JNIEnv<'_>,
    class: jni::objects::JClass<'_>,
    deposit_contract_address: JString<'_>,
    validator_private_key: JString<'_>,
    withdrawal_address: JString<'_>,
    deposit_value_wei_in_hex: JString<'_>,
) -> jstring {
    let deposit_contract_address: String = env.get_string(&deposit_contract_address)
            .expect("Couldn't get Java string from deposit_contract_address!")
            .into();
    let validator_private_key: String = env.get_string(&validator_private_key)
            .expect("Couldn't get Java string from validator_private_key!")
            .into();
    let withdrawal_address: String = env.get_string(&withdrawal_address)
            .expect("Couldn't get Java string from withdrawal_address!")
            .into();
    let deposit_value_wei_in_hex: String = env.get_string(&deposit_value_wei_in_hex)
            .expect("Couldn't get Java string from deposit_value_wei_in_hex!")
            .into();
    let deposit_value_wei = U256::from_str_radix(&deposit_value_wei_in_hex, 16)
                .expect("Failed to parse deposit_value_wei_in_hex as U256");

    let transaction_request = match create_deposit_unsigned_tx(
        deposit_contract_address,
        validator_private_key,
        withdrawal_address,
        deposit_value_wei,
    ) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                                .expect("Failed to throw exception");
            Default::default()
        }
    };

    let json_string = serde_json::to_string(&transaction_request).expect("Failed to serialize transaction_request struct to JSON");

    env.new_string(&json_string)
        .expect("Couldn't create Java string!")
        .into_raw()
}


#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createExitUnsignedTx(
    mut env: jni::JNIEnv<'_>,
    class: jni::objects::JClass<'_>,
    validator_public_key: JString<'_>,
    fee_wei_in_hex: JString<'_>,
) -> jstring {
    let validator_public_key: String = env.get_string(&validator_public_key)
            .expect("Couldn't get Java string from validator_public_key!")
            .into();
    let fee = if !fee_wei_in_hex.is_null() {
        let fee_wei_in_hex: String = env.get_string(&fee_wei_in_hex)
            .expect("Couldn't get Java string from fee_wei_in_hex!")
            .into();
        Some(U256::from_str_radix(&fee_wei_in_hex, 16)
            .expect("Failed to parse fee_wei_in_hex as U256"))
    } else {
        None
    };

    let transaction_request = match create_exit_unsigned_tx(
        validator_public_key,
        fee
    ) {
        Ok(v) => v,
        Err(e) => {
            env.throw_new("java/lang/Exception", e.to_string())
                                .expect("Failed to throw exception");
            Default::default()
        }
    };

    let json_string = serde_json::to_string(&transaction_request).expect("Failed to serialize transaction_request struct to JSON");

    env.new_string(&json_string)
        .expect("Couldn't create Java string!")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_runClient(
    mut env: jni::JNIEnv<'_>,
    class: jni::objects::JClass<'_>,
    ws_url: JString<'_>,
    validator_private_key: JString<'_>,
) -> jobject {
    let ws_url: String = env.get_string(&ws_url)
            .expect("Couldn't get Java string from ws_url!")
            .into();
    let validator_private_key: String = env.get_string(&validator_private_key)
            .expect("Couldn't get Java string from validator_private_key!")
            .into();

    // Create a new CompletableFuture object in Java
    let cf_class = env.find_class("java/util/concurrent/CompletableFuture")
.unwrap();
    let cf_obj = env.new_object(cf_class, "()V", &[]).unwrap();

    // Promote CompletableFuture to a global ref so it outlives this JNI call
    let global_cf: GlobalRef = env.new_global_ref(&cf_obj).unwrap();

    let jvm = env.get_java_vm().unwrap();

    // Spawn async task
    RUNTIME.spawn(async move {
        let result = run_client(&ws_url, &validator_private_key).await;

        // Attach thread to JVM to call back into Java
        let mut env = jvm.attach_current_thread().unwrap();

        match result {
            Ok(()) => {
                // Call CompletableFuture.complete(null)
                env.call_method(
                    &global_cf,
                    "complete",
                    "(Ljava/lang/Object;)Z",
                    &[(&JObject::null()).into()],
                )
                .unwrap();
            }

            Err(e) => {
                let jmsg = env.new_string(e.to_string()).unwrap();
                let ex_class = env.find_class("java/lang/RuntimeException")
.unwrap();
                let ex_obj = env
                    .new_object(ex_class, "(Ljava/lang/String;)V",
&[(&jmsg).into()])
                    .unwrap();

                env.call_method(
                    &global_cf,
                    "completeExceptionally",
                    "(Ljava/lang/Throwable;)Z",
                    &[(&JObject::from(ex_obj)).into()],
                )
                .unwrap();
            }
        };

        // Call CompletableFuture.complete(null)
        env.call_method(
            &global_cf,
            "complete",
            "(Ljava/lang/Object;)Z",
            &[(&JObject::null()).into()],
        )
        .unwrap();
    });

    cf_obj.into_raw() // return CompletableFuture immediately
}

