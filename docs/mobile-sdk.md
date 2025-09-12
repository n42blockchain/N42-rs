# build
## android
### prerequisites
1. gradle
2. jdk17, set JAVA_HOME and PATH
3. cargo-ndk
example:
```shell
brew install gradle
brew install openjdk@17

export JAVA_HOME="/usr//local/opt/openjdk@17"
export PATH="$JAVA_HOME/bin:$PATH"

cargo install cargo-ndk
```

### build commands
```shell
cd crates/n42/mobile-sdk
./build-aar.sh
```

output:
mobile-sdk-release.aar

## ios
### prerequisites
1. Xcode + iOS SDK
2. cbindgen
```shell
cargo install cbindgen
```
### build commands
```shell
cd crates/n42/mobile-sdk/ios/
./build_xcframework.sh
```

Run build_xcframework.sh → produces mobile_sdk.xcframework and headers.

# integration into an app
## for android apps that use mobile-sdk aar

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

        String fee_wei_in_hex = "0x1"; // should query the value from the exit
contract

        String exitTx = Api.createExitUnsignedTx(
                validatorPublicKey,
                fee_wei_in_hex
        );
        Log.i("RustLib", "exitTx: " + exitTx);

        Api.runClient(wsUrl, validatorPrivateKey).thenRun(() -> Log.d("APP", "Rust async done")).exceptionally(ex -> {
            System.err.println("Rust error: " + ex.getMessage());
            return null;
        });;
    }
}
```

## for ios apps developed in swift

1. Drag mobile_sdk.xcframework into your Xcode project.

2. Add mobile_sdk.h, MobileSdk.swift to your project.

3. Configure the bridging header for FFI.

### the Bridging Header
1. Create the Bridging Header

In Xcode, go to File → New → File → Header File.

Name it e.g., YourApp-Bridging-Header.h.

Add your Rust header:

// YourApp-Bridging-Header.h
#include "mobile_sdk.h"

2. Tell Xcode to use it

Select your project in the navigator → Build Settings.

Search for Objective-C Bridging Header (type it in the search bar).

If it’s not visible, make sure you select All instead of Basic settings.

Set the path relative to your project, for example:

ios/include/YourApp-Bridging-Header.h

This tells Swift to include the C header when compiling Swift files.

sdk api example:
```swift
import SwiftUI

struct ContentView: View {
    @State private var message = "Waiting..."
    @State private var resultText: String = "result"

    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text(resultText)
        }
        .padding()

        Button("Run Rust Client") {
            let depositContractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
            let validatorPrivateKey = "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec"
            let withdrawalAddress = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"
            let depositValueInWei = "0x1bc16d674ec800000"

            var result = MobileSdk.createDepositUnsignedTx(
                depositContractAddress: depositContractAddress,
                validatorPrivateKey: validatorPrivateKey,
                withdrawalAddress: withdrawalAddress,
                depositValueInWei: depositValueInWei
            )
            switch result {
            case .success(let txJson):
                self.resultText = "TX JSON: \(txJson)"
            case .failure(let error):
                self.resultText = "Error: \(error)"
            }
            print("createDepositUnsignedTx result", result)

            let validatorPublicKey =   "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a"
            result = MobileSdk.createExitUnsignedTx(
                validatorPublicKey: validatorPublicKey,
                feeInWeiOrEmpty: "0x1"  // should query the value from the exit
            )
            switch result {
            case .success(let txJson):
                self.resultText = "TX JSON: \(txJson)"
            case .failure(let error):
                self.resultText = "Error: \(error)"
            }
            print("createExitUnsignedTx result", result)

            let wsUrl = "ws://127.0.0.1:8546"
            MobileSdk.runClient(
                wsUrl: wsUrl,
                validatorPrivateKey: validatorPrivateKey,
                completion: { result in
                    switch result {
                    case .success:
                        self.resultText = "Client started successfully"
                    case .failure(let err):
                        self.resultText = "Error: \(err)"
                    }
                }
            )


        }
    }
}

#Preview {
    ContentView()
}
```
