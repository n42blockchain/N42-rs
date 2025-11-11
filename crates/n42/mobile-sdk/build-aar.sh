#!/usr/bin/env bash
set -euo pipefail

if [[ "$OSTYPE" == "darwin"* ]]; then
  SED_INPLACE="sed -i ''"
else
  SED_INPLACE="sed -i"
fi

# -------------------------
# Configuration
# -------------------------
CRATE_NAME="mobile-sdk"
LIB_NAME="${CRATE_NAME//-/_}"
JAVA_PKG="com/mobileSdk"      # folder path
JAVA_CLASS="Api"               # public wrapper class
AAR_NAME="mobile-sdk-release.aar"

WORKDIR="$(pwd)/aar-build"
JNILIBS_DIR="$WORKDIR/src/main/jniLibs"
JAVA_DIR="$WORKDIR/src/main/java/$JAVA_PKG"
JNI_SRC="src/jni.rs"           # Rust file with all JNI functions

# -------------------------
# Prepare directories
# -------------------------
rm -rf "$WORKDIR"
mkdir -p "$JNILIBS_DIR" "$JAVA_DIR"

# Backup Cargo.toml
cp Cargo.toml Cargo.toml.bak

# Modify Cargo.toml for Android
$SED_INPLACE 's/^crate-type = \[\(.*\)\]/crate-type = [\1, "cdylib"]/' Cargo.toml

# -------------------------
# Build Rust crate for Android ABIs
# -------------------------
echo "Building Rust crate for Android..."
#cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 \
cargo ndk -t arm64-v8a -t x86_64 \
    -o "$JNILIBS_DIR" build --release -p "$CRATE_NAME"

mv Cargo.toml.bak Cargo.toml

# -------------------------
# Create Android library skeleton
# -------------------------
mkdir -p "$WORKDIR/src/main"

# AndroidManifest.xml
cat > "$WORKDIR/src/main/AndroidManifest.xml" <<EOF
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.mobileSdk">
    <application/>
</manifest>
EOF

# Create settings.gradle
cat > "$WORKDIR/settings.gradle" <<EOF
pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = 'aar-build'
EOF

# Update build.gradle with pluginManagement
cat > "$WORKDIR/build.gradle" <<EOF
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:8.3.0'
    }
}

apply plugin: 'com.android.library'

android {
    namespace "com.mobileSdk"
    compileSdk 34

    defaultConfig {
        minSdk 23
    }

    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }
}
EOF

# -------------------------
# Create NativeBindings.java manually
# -------------------------
echo "Creating JNI bridge..."
cat > "$JAVA_DIR/NativeBindings.java" <<EOF
package com.mobileSdk;

import java.util.concurrent.CompletableFuture;

class NativeBindings {
    static {
        System.loadLibrary("${LIB_NAME}");
    }

    // Declare your JNI functions here
    // Example: matches your Rust function:
    // #[no_mangle]
    // pub extern "system" fn
    // Java_com_mobileSdk_NativeBindings_callAsyncResult(...)
    //public static native CompletableFuture<Void> callAsyncResult();

    public static native String generateBls12381Keypair();

    public static native String createDepositUnsignedTx(
            String deposit_contract_address,
            String validator_private_key,
            String withdrawal_address,
            String deposit_value_wei_in_hex
    );

    public static native String createGetExitFeeUnsignedTx();

    public static native String createExitUnsignedTx(
            String validator_public_key,
            String fee_wei_in_hex
    );

    public static native CompletableFuture<Void> runClient(
            String ws_url,
            String validator_private_key
    );
}
EOF

# -------------------------
# Create public wrapper class Api.java
# -------------------------
cat > "$JAVA_DIR/$JAVA_CLASS.java" <<EOF
package com.mobileSdk;

import java.util.concurrent.CompletableFuture;

public class $JAVA_CLASS {
    private $JAVA_CLASS() {}

    // Wrap the native JNI function
    //public static CompletableFuture<Void> runAsyncTask() {
    //    return NativeBindings.callAsyncResult();
    //}

    public static String generateBls12381Keypair() {
	return NativeBindings.generateBls12381Keypair();
    }

    public static String createDepositUnsignedTx(
            String deposit_contract_address,
            String validator_private_key,
            String withdrawal_address,
            String deposit_value_wei_in_hex
	) {
		return NativeBindings.createDepositUnsignedTx(
		    deposit_contract_address,
		    validator_private_key,
		    withdrawal_address,
		    deposit_value_wei_in_hex
		);
    }

    public static String createGetExitFeeUnsignedTx() {
	return NativeBindings.createGetExitFeeUnsignedTx();
    }

    public static String createExitUnsignedTx(
            String validator_public_key,
            String fee_wei_in_hex
	) {
		return NativeBindings.createExitUnsignedTx(
		    validator_public_key,
		    fee_wei_in_hex
		);
    }

    public static CompletableFuture<Void> runClient(
            String ws_url,
            String validator_private_key
	) {
		return NativeBindings.runClient(
            ws_url,
            validator_private_key
	);
    }
}
EOF

# -------------------------
# Build AAR using Gradle
# -------------------------
pushd "$WORKDIR" > /dev/null
gradle wrapper --gradle-version 8.6
./gradlew assembleRelease
popd > /dev/null

# Copy final AAR to root folder
cp "$WORKDIR/build/outputs/aar/"*.aar "./$AAR_NAME"

echo "✅ Built AAR: $AAR_NAME"
