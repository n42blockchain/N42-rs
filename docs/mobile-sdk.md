# build
## prerequisites
1. gradle
2. jdk17, set JAVA_HOME and PATH
example:
```shell
brew install gradle
brew install openjdk@17

export JAVA_HOME="/usr//local/opt/openjdk@17"
export PATH="$JAVA_HOME/bin:$PATH"
```

```shell
cd crates/n42/mobile-sdk
./build-aar.sh
```

output:
mobile-sdk-release.aar

# for android apps that use mobile-sdk aar

Add the following to your app’s app/src/main/AndroidManifest.xml
```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
```

sdk api example:
```java
package com.example.test_mobile_sdk_aar;

import android.util.Log;

import com.mobileSdk.Api;

public class MobileSdkTest {
    public static void test() {
        //String wsUrl = "ws://127.0.0.1:8546";
        String wsUrl = "ws://10.0.2.2:8546";

        String validatorPrivateKey = "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
        String validatorPublicKey = "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";

        String withdrawalAddress = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";
        String depositContractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
        String depositValueWeiInHex = "0x1bc16d674ec800000";
        String tx = Api.createDepositUnsignedTx(
                depositContractAddress,
                validatorPrivateKey,
                withdrawalAddress,
                depositValueWeiInHex
        );
        Log.i("RustLib", "tx: " + tx);

        String exitTx = Api.createExitUnsignedTx(
                validatorPublicKey,
                withdrawalAddress
        );
        Log.i("RustLib", "exitTx: " + exitTx);

        Api.runClient(wsUrl, validatorPrivateKey).thenRun(() -> Log.d("APP", "Rust async done")).exceptionally(ex -> {
            System.err.println("Rust error: " + ex.getMessage());
            return null;
        });;
    }
}
```
