# SSZ golden vectors

Copied unchanged from alloy-rpc-types-engine 2.5.0's exact published source revision:

- Repository: https://github.com/alloy-rs/alloy
- Commit: `59174912873b337ea5868c295cefa70997596f29`
- Path: `crates/rpc-types-engine/src/ssz_engine_types/testdata/geth-golden.json`
- SHA256: `2263f5265956f6c9a102eabef4819847b22ef8cbf5501daf32337d16079fcb20`
- Upstream test identifies Geth commit `4797f85ef1add42799b09aa0cef9f715ac48f8d4` as the vector source.

The crates.io package omits this directory, while its SSZ tests use include_str!
for the JSON file. Keep all 11 upstream vectors to compile and run the vendored
crate's full test target without network access. License follows the upstream
MIT / Apache-2.0 crate.
