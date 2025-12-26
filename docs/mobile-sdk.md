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
3. cargo-lipo
```shell
cargo install cbindgen
cargo install cargo-lipo
```
### build commands
```shell
cd crates/n42/mobile-sdk/ios/
./build_xcframework.sh
```

Run build_xcframework.sh → produces mobile_sdk.xcframework and headers.

## linux, mac
### build commands
```shell
cargo build -p mobile-sdk --example mobile-sdk-test
```

output:
target/debug/examples/mobile-sdk-test

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
import org.json.JSONArray;
import org.json.JSONException;

public class MobileSdkTest {
    public static void test() {
        //String wsUrl = "ws://127.0.0.1:8546";
        String wsUrl = "ws://10.0.2.2:8546";

        String validatorKeyPair = Api.generateBls12381Keypair();
        Log.i("RustLib", "validatorKeyPair: " + validatorKeyPair);
        String validatorPrivateKey = "";
        String validatorPublicKey = "";

        try {
            // Parse the JSON array string
            JSONArray jsonArray = new JSONArray(validatorKeyPair);

            // Access elements by index
            validatorPrivateKey = jsonArray.getString(0);
            validatorPublicKey = jsonArray.getString(1);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        Log.i("RustLib", "validatorPrivateKey: " + validatorPrivateKey);
        Log.i("RustLib", "validatorPublicKey: " + validatorPublicKey);
        //String validatorPrivateKey = "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
        //String validatorPublicKey = "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";

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

        String getExitFeeTx = Api.createGetExitFeeUnsignedTx();
        Log.i("RustLib", "getExitFeeTx: " + getExitFeeTx);

        String fee_wei_in_hex = "0x1"; // should query the value by sending getExitFee Tx(as it is, no signing needed) to the exit contract

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

sdk code example for genBlockVerifyResult
```java
package com.example.test_mobile_sdk_aar;

import android.util.Log;

import com.mobileSdk.Api;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;

public class MyWebSocketListener extends WebSocketListener {
    @Override
    public void onOpen(WebSocket webSocket, Response response) {
        // "Subscribe" by sending a JSON message once the connection is open
        // subscribe with validator bls_pubkey_hex_str
        String subscribeJson = "{\"jsonrpc\":\"2.0\",\"method\":\"consensusBeaconExt_subscribeToVerificationRequest\",\"params\":[\"9536b707bfa6a05a193bf6fe3b0951a9f16a5a42b0834d19fe3a8c60bb1d50d70d96f101833cd698c5a6d5e92dd96bbb\"],\"id\":1}";
        webSocket.send(subscribeJson);
        Log.i("RustLib","onOpen");
    }

    @Override
    public void onMessage(WebSocket webSocket, String text) {
        // Handle incoming text messages
        Log.i("RustLib","Received: " + text);
        try {
            JSONObject json = new JSONObject(text);

            // Notifications usually have a 'method' or 'params' field
            if (json.has("method")) {
                String method = json.getString("method");

                switch (method) {
                    case "subscribeToVerificationRequest":
                        JSONObject params = json.getJSONObject("params");
                        JSONObject result = params.getJSONObject("result");
                        Log.i("RustLib","result: " + result);

                        String validatorPrivateKeyForTest = "3fa701e2b5966ea4e5ad49a65bd59997b1e25f6d83dd5f075d0e01d1e92dfd81";
                        String blockVerifyResultStr = Api.genBlockVerifyResult(result.toString(), validatorPrivateKeyForTest).join();
                        Log.i("RustLib","blockVerifyResultStr: " + blockVerifyResultStr);

                        JSONObject blockVerifyResult = new JSONObject(blockVerifyResultStr);
                        JSONObject request = new JSONObject();
                        request.put("id", 1);
                        request.put("jsonrpc", "2.0");
                        request.put("method", "consensusBeaconExt_submitVerification");

                        // Put all arguments into a JSONArray in order
                        JSONArray paramsSubmit = new JSONArray();
                        paramsSubmit.put(blockVerifyResult.getString("pubkey"));
                        paramsSubmit.put(blockVerifyResult.getString("signature"));
                        paramsSubmit.put(blockVerifyResult.getJSONObject("attestation_data"));
                        paramsSubmit.put(blockVerifyResult.getString("block_hash"));

                        request.put("params", paramsSubmit);
                        Log.i("RustLib","blockVerifyResult: " + blockVerifyResult);
                        boolean sendOk = webSocket.send(request.toString());
                        Log.i("RustLib","sent consensusBeaconExt_submitVerification, return value: " + sendOk);
                        break;

                    default:
                        Log.i("RustLib","Unknown method: " + method);
                }
            }
        } catch (JSONException e) { Log.i("RustLib","error" + e.toString()); }


    }

    @Override
    public void onFailure(WebSocket webSocket, Throwable t, Response response) {
        // Handle errors here
        Log.i("RustLib","onFailure" + t.toString());
        t.printStackTrace();
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
import Foundation

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
            //let validatorPrivateKey = "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec"
            var validatorPublicKey = ""
            var validatorPrivateKey = ""
            let withdrawalAddress = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"
            let depositValueInWei = "0x1bc16d674ec800000"

            var result = MobileSdk.generateBls12381Keypair()
            switch result {
            case .success(let txJson):
                self.resultText = "TX JSON: \(txJson)"
                let jsonData = Data(txJson.utf8)
                do {
                    let keys = try JSONDecoder().decode([String].self, from: jsonData)
                    validatorPrivateKey = keys[0]
                    validatorPublicKey = keys[1]

                    print("validatorPrivateKey:", validatorPrivateKey)
                    print("validatorPublicKey:", validatorPublicKey)
                } catch {
                    print("Failed to decode:", error)
                }

            case .failure(let error):
                self.resultText = "Error: \(error)"
            }
            print("generateBls12381Keypair result", result)

            result = MobileSdk.createDepositUnsignedTx(
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

            result = MobileSdk.createGetExitFeeUnsignedTx()
            switch result {
            case .success(let txJson):
                self.resultText = "TX JSON: \(txJson)"
            case .failure(let error):
                self.resultText = "Error: \(error)"
            }
            print("createGetExitFeeUnsignedTx result", result)

            //let validatorPublicKey =   "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a"
            result = MobileSdk.createExitUnsignedTx(
                validatorPublicKey: validatorPublicKey,
                feeInWeiOrEmpty: "0x1"  // should query the value by sending getExitFee Tx(as it is, no signing needed) to the exit contract
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

         Button("Connect, Subscribe, Verify & Submit") {
            // 1. Connect to your server
            WebSocketManager.shared.connect(urlStr: wsUrl)

            let validatorPubkey = "9536b707bfa6a05a193bf6fe3b0951a9f16a5a42b0834d19fe3a8c60bb1d50d70d96f101833cd698c5a6d5e92dd96bbb"
            // 2. Subscribe after a tiny delay to ensure socket is open
            // In a real app, you'd do this inside the 'onOpen' equivalent
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                WebSocketManager.shared.subscribe(pubkey: validatorPubkey)
                self.resultText = "Started Connect, Subscribe, Verify & Submit"
            }
        }
        .buttonStyle(.borderedProminent) // Solid colored background
        .controlSize(.large)             // Makes it bigger and easier to hit
        .tint(.blue)
    }
}

#Preview {
    ContentView()
}
```

sdk code example for genBlockVerifyResult
```swift
import Foundation

class WebSocketManager: NSObject {
    static let shared = WebSocketManager()

    private var webSocket: URLSessionWebSocketTask?
    private var isConnected = false

    // Constant key for the hardcoded validator
    private let validatorKey = "3fa701e2b5966ea4e5ad49a65bd59997b1e25f6d83dd5f075d0e01d1e92dfd81"

    // MARK: - Connection Management

    func connect(urlStr: String) {
        guard let url = URL(string: urlStr) else { return }

        let session = URLSession(configuration: .default)
        webSocket = session.webSocketTask(with: url)
        webSocket?.resume()
        isConnected = true

        print("WebSocket: Connecting to \(urlStr)...")

        Task { await listen() }
    }

    func disconnect() {
        webSocket?.cancel(with: .normalClosure, reason: nil)
        isConnected = false
        print("WebSocket: Disconnected")
    }

    // MARK: - Outbound Communication

    /// Generic helper to send JSON-RPC requests
    private func sendJsonRpc(method: String, params: [Any], id: Int? = nil) {
        var request: [String: Any] = [
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        ]
        if let id = id { request["id"] = id }

        guard let data = try? JSONSerialization.data(withJSONObject: request),
              let jsonString = String(data: data, encoding: .utf8) else {
            print("WebSocket: Failed to serialize \(method)")
            return
        }

        webSocket?.send(.string(jsonString)) { error in
            if let error = error {
                print("WebSocket: Send Error for \(method): \(error)")
            } else {
                print("WebSocket: Successfully sent \(method)")
            }
        }
    }

    func subscribe(pubkey: String) {
        sendJsonRpc(method: "consensusBeaconExt_subscribeToVerificationRequest", params: [pubkey], id: 1)
    }

    // MARK: - Inbound Message Handling

    private func listen() async {
        guard let webSocket = webSocket else { return }

        do {
            let message = try await webSocket.receive()
            if case .string(let text) = message {
                handleIncomingText(text)
            }
            // Recursively listen
            await listen()
        } catch {
            print("WebSocket: Connection error: \(error)")
            isConnected = false
        }
    }

    private func handleIncomingText(_ text: String) {
        print("WebSocket Received: \(text)")
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let method = json["method"] as? String ?? ""

        switch method {
        case "subscribeToVerificationRequest":
            processVerificationRequest(json)
        default:
            print("WebSocket: Unhandled method: \(method)")
        }
    }

    // MARK: - SDK Logic

    private func processVerificationRequest(_ json: [String: Any]) {
        // Nested Extraction
        guard let params = json["params"] as? [String: Any],
              let resultObj = params["result"] as? [String: Any],
              let resultData = try? JSONSerialization.data(withJSONObject: resultObj),
              let blockJsonString = String(data: resultData, encoding: .utf8) else {
            print("WebSocket: Malformed Verification Request")
            return
        }

        MobileSdk.generateBlockVerifyResult(block: blockJsonString, validatorPrivateKey: validatorKey) { [weak self] result in
            switch result {
            case .success(let verifyResultJson):
                print("verifyResultJson: \(verifyResultJson)")
                self?.handleSubmitVerification(verifyResultJson)
            case .failure(let error):
                print("SDK: Verification Failed: \(error)")
            }
        }
    }

    private func handleSubmitVerification(_ rawResultJson: String) {
        guard let data = rawResultJson.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pubkey = json["pubkey"] as? String,
              let signature = json["signature"] as? String,
              let attestationData = json["attestation_data"] as? [String: Any],
              let blockHash = json["block_hash"] as? String else {
            print("SDK: Could not parse result for submission")
            return
        }

        // Send back to server
        sendJsonRpc(
            method: "consensusBeaconExt_submitVerification",
            params: [pubkey, signature, attestationData, blockHash],
            id: 1
        )
    }
}
```

## linux, mac
```shell
./target/debug/examples/mobile-sdk-test help
deposit, exit, validate

Usage: mobile-sdk-test <COMMAND>

Commands:
  deposit
  exit
  validate
  generate-bls12381-keypair
  help                       Print this message or the help of the given
subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### prerequisites
We have an ethereum EOA private key for paying for the
deposit(--deposit-private-key), example:
0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

We have an ethereum EOA private key and its public address to be used as withdrawal private key and withadrawal public address, example:

0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6,
0xa0Ee7A142d267C1f36714E4a8F75612F20a79720

1. generate bls12381 keypair (privkey, pubkey)
```shell
./target/debug/examples/mobile-sdk-test generate-bls12381-keypair
keypair: ("3c86f39ef84ea79bb632e56d6c2e6d9fb410ae681deaf4a1a87688a901852d54",
"af4a49ca1cc5ad0348bde8222a00bbab5d71c538abb23f91e1807932d02a3258cae1d718f16d9e0cf8be555fdd4800cd")
```

2. deposit
```shell
./target/debug/examples/mobile-sdk-test deposit -v
3c86f39ef84ea79bb632e56d6c2e6d9fb410ae681deaf4a1a87688a901852d54 -w
0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 -d
0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

3. validate
```shell
RUST_LOG=debug ./target/debug/examples/mobile-sdk-test validate -v
3c86f39ef84ea79bb632e56d6c2e6d9fb410ae681deaf4a1a87688a901852d54
```

4. exit
```shell
./target/debug/examples/mobile-sdk-test exit -w
0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 -v
af4a49ca1cc5ad0348bde8222a00bbab5d71c538abb23f91e1807932d02a3258cae1d718f16d9e0cf8be555fdd4800cd
```
