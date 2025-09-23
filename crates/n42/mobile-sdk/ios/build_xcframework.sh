#!/usr/bin/env bash
set -euo pipefail

# ---------------- CONFIG ----------------
CRATE_NAME="mobile-sdk"
LIB_NAME="${CRATE_NAME//-/_}"
IOS_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$IOS_DIR/build"
INCLUDE_DIR="$IOS_DIR/include"
SWIFT_DIR="$IOS_DIR/Swift"
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

(cd "$IOS_DIR/../" && cp Cargo.toml Cargo.toml.bak.ios &&
sed -i '' 's/^crate-type = \[\(.*\)\]/crate-type = ["staticlib"]/' Cargo.toml
)
cargo lipo --release --targets aarch64-apple-ios,x86_64-apple-ios
(cd "$IOS_DIR/../" && mv Cargo.toml.bak.ios Cargo.toml)

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

tarname=mobile-sdk-ios
tarworkdir=$(mktemp -d /tmp/tardir.$tarname.XXXXX)
tardir="$tarworkdir/$tarname"
mkdir $tardir
cp -r $XCFRAMEWORK $tardir/
cp -r $SWIFT_DIR $tardir/
cp -r $INCLUDE_DIR $tardir/
(cd $tarworkdir && tar -cvzf $tarname.tar.gz $tarname)
cp "$tarworkdir/$tarname.tar.gz" .
rm -rf $tarworkdir
echo "✅ $tarname tarball at: $tarname.tar.gz"
