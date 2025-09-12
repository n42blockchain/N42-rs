#!/usr/bin/env bash
set -euo pipefail

# ---------------- CONFIG ----------------
CRATE_NAME="mobile-sdk"
LIB_NAME="${CRATE_NAME//-/_}"
IOS_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$IOS_DIR/build"
INCLUDE_DIR="$IOS_DIR/include"
XCFRAMEWORK="$OUT_DIR/MobileSdk.xcframework"

IOS_MIN_VERSION=11.0

# ---------------- ENSURE TARGETS ----------------
rustup target add aarch64-apple-ios x86_64-apple-ios

# ---------------- CLEAN ----------------
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

mkdir -p "$INCLUDE_DIR"

# ---------------- GENERATE HEADER ----------------
echo "Generating C header with cbindgen..."
(cd "$IOS_DIR/../" && cbindgen --config ios/cbindgen.toml --crate "$CRATE_NAME" --output "$INCLUDE_DIR/mobile_sdk.h")

# ---------------- BUILD RUST STATIC LIBRARIES ----------------
export RUSTFLAGS="-C link-arg=-miphoneos-version-min=$IOS_MIN_VERSION"

echo "Building Rust library for device (arm64)..."
cargo build --release --target aarch64-apple-ios

echo "Building Rust library for simulator (x86_64)..."
cargo build --release --target x86_64-apple-ios

LIB_DEVICE="$IOS_DIR/../../../../target/aarch64-apple-ios/release/lib${LIB_NAME}.a"
LIB_SIM="$IOS_DIR/../../../../target/x86_64-apple-ios/release/lib${LIB_NAME}.a"

# ---------------- CREATE XCFRAMEWORK ----------------
echo "Creating XCFramework..."
xcodebuild -create-xcframework \
  -library "$LIB_DEVICE" \
  -headers "$INCLUDE_DIR" \
  -library "$LIB_SIM" \
  -headers "$INCLUDE_DIR" \
  -output "$XCFRAMEWORK"

echo "✅ XCFramework built at: $XCFRAMEWORK"
echo "Swift wrapper files remain in ios/Swift/ for reference."
