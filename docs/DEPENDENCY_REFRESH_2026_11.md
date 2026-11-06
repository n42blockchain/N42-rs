# Dependency refresh, 2026-11

Dated 2026-11-03, branch `upgrade/reth-v2.9.0` (from `main` at `ef45057a5`), stage 1 of the
reth v2.9.0 work: every dependency refreshed on the current reth **v2.8.1** pin. The reth step
itself (v2.9.0 replaces revm with evm2) is separate; see `docs/RETH_2_9_0_UPGRADE.md`.

## Rules applied

- `cargo update`: the semver-compatible latest of every crate. reth's own pins (alloy 2.5.0,
  revm 43.0.3, alloy-evm 0.39.0, reth-primitives-traits / reth-codecs 0.8.2, jsonrpsee 0.26)
  stay where reth v2.8.1 has them; the upstream tag did not move, and none of them moved.
- A major bump only for an N42-only direct dependency of `crates/n42/*` or `bin/n42` (one
  reth v2.8.1's `Cargo.toml` does not pin), and only when it compiles and the crate's tests
  pass. Everything else behind its latest major is listed under "Held".
- libp2p: already on the latest major (0.57.1; `libp2p-identity` 0.3.1 taken).
  The `secp256k1` feature and the gossipsub parameters are untouched.

## Versions moved

`Cargo.lock` before and after (a "(removed)" version is one no crate needs any more; another
version of the same crate may remain in the graph).

| Crate | Before | After |
|---|---|---|
| addr2line | 0.25.1 | 0.27.1 |
| alloy-primitives | 0.8.26 | (removed) |
| alloy-rlp | 0.3.16 | 0.3.17 |
| alloy-rlp-derive | 0.3.16 | 0.3.17 |
| arrayvec | 0.4.12 | (removed) |
| async-compression | 0.4.51 | 0.4.52 |
| aws-lc-rs | 1.18.2 | 1.19.0 |
| aws-lc-sys | 0.46.0 | 0.47.0 |
| backtrace | 0.3.76 | 0.3.77 |
| brotli | 9.1.0 | 9.1.1 |
| cc | 1.10.0 | 1.11.0 |
| cloudabi | 0.0.3 | (removed) |
| compression-codecs | 0.4.46 | 0.4.47 |
| crc32fast | 1.5.3 | 1.5.4 |
| crypto-bigint | 0.7.9 | 0.7.10 |
| ctutils | 0.4.6 | 0.4.8 |
| ethereum_hashing | 0.7.0 | (removed) |
| ethereum_serde_utils | 0.7.0 | (removed) |
| fixed-hash | 0.3.2 | (removed) |
| fuchsia-cprng | 0.1.1 | (removed) |
| futures-bounded | 0.3.0 | 0.3.1 |
| gimli | 0.32.3 | 0.34.0 |
| hashbrown | 0.15.5 | (removed) |
| hex-literal | 0.3.4 | 1.1.0 |
| impl-codec | 0.2.0 | (removed) |
| jiff | 0.2.38 | 0.2.39 |
| jiff-core | 0.1.1 | 0.1.2 |
| jiff-static | 0.2.38 | 0.2.39 |
| keccak-hash | 0.10.0 | (removed) |
| libp2p-identity | 0.3.0 | 0.3.1 |
| libz-sys | 1.1.30 | 1.1.31 |
| llvm-sys | 221.1.1 | 221.1.2 |
| log | 0.4.34 | 0.4.35 |
| lru | (new) | 0.19.0 |
| miniz_oxide | 0.8.9 | (removed) |
| nodrop | 0.1.14 | (removed) |
| notify-types | 2.1.0 | 2.2.0 |
| nybbles | 0.4.8 | 0.4.9 |
| object | 0.37.3, 0.39.1 | 0.39.1, 0.40.0 |
| openssl-probe | 0.2.1 | 0.2.2 |
| parity-codec | 3.5.4 | (removed) |
| pest | 2.9.4 | 2.9.5 |
| pest_stack_guard | (new) | 1.0.0 |
| primitive-types | 0.3.0 | (removed) |
| prometheus-client | 0.25.1 | 0.25.2 |
| rand | 0.5.6 | (removed) |
| rand_core | 0.3.2, 0.4.3 | (removed) |
| rlp | 0.4.6 | (removed) |
| rustix | 1.1.5 | 1.1.6 |
| static_assertions | 0.2.5 | (removed) |
| tonic | 0.14.6 | 0.14.9 |
| tonic-prost | 0.14.6 | 0.14.9 |
| tonic-types | 0.14.6 | 0.14.9 |
| uint | 0.7.1 | (removed) |
| unicode-width | 0.2.2 | 0.2.3 |
| utf16_iter | 1.0.5 | 1.1.0 |
| utf8_iter | 1.0.4 | 1.1.0 |
| utf_types | (new) | 1.0.0 |
| xattr | 1.6.1 | 1.7.0 |
| zerocopy | 0.7.35 | (removed) |
| zerocopy-derive | 0.7.35 | (removed) |
| zstd | 0.13.3 | 0.13.4 |
| zstd-safe | 7.3.0 | 7.4.0 |

## Majors taken

| Crate | Dependency | From | To | Change needed |
|---|---|---|---|---|
| `n42-primitives` | `ethereum_hashing` (workspace) | 0.7 | 0.8 | none |
| `n42-primitives` | `ethereum_serde_utils` | 0.7 | 0.8 | none (0.8 is on alloy-primitives 1.x) |
| `n42-primitives` | `hex-literal` | 0.3 | 1 | none |
| `n42-consensus-traits`, `n42-ef-tests` | `hashbrown` | 0.15 | 0.17 | none |
| `n42-mobile-verify` | `lru` | 0.18 | 0.19 | none |
| `n42-testing` | `zerocopy` | 0.7 | 0.8 | `AsBytes` is now `IntoBytes` |

`n42-clique` declared `keccak-hash` 0.10, `primitive-types` 0.3, `hex-literal` 0.3,
`num-bigint` 0.4, `uint` 0.9, `rlp` 0.4 and `sha3` 0.10 but used none of them (its `hex!` is
alloy's); they are removed instead of bumped, and with them `parity-codec`, `fixed-hash`,
`rand` 0.5 and the rest of their 2019-era tree. Its unused `tiny-keccak`, `hash-db`,
`lazy_static` and `unexpected` went too: `keccak-hash` had been the only thing switching on
tiny-keccak's `keccak` feature, so without it a crate building tiny-keccak alone failed its build
script. `n42-testing`, which does hash with `tiny_keccak::Keccak`, now asks for the feature
itself (`cargo check --workspace` did not show this; per-crate `cargo test` did).

## Majors held

| Dependency | Used by | Available | Why held |
|---|---|---|---|
| `jni` 0.21 | `mobile-sdk` | 0.22 | 0.22 replaces `JNIEnv` with `EnvUnowned` and `with_env` closures: every JNI entry point is rewritten, and the Android path cannot be exercised on this host |
| `rand_core` 0.6 | `n42-tx-types` | 0.10 | must match `merlin` 3, whose transcript RNG builder takes a rand_core 0.6 RNG (the 0x50 batch verification's coefficients) |
| `k256` 0.13, `sha2` 0.10, `secp256k1` 0.30 | several | 0.14 / 0.11 / 0.33 | on alloy's and reth's RustCrypto / secp generation; a bump splits the graph and the key types stop matching |
| `jsonwebtoken` 10, `base64` 0.22 | the `alloy-rpc-types-engine` fork, `reth-rpc` | 11 / 0.23 | the fork tracks upstream alloy 2.5.0, which pins them |
| `itertools`, `strum`, `rand` 0.9, `parking_lot`, `sysinfo`, `tikv-jemallocator`, `criterion` (codspeed), `similar-asserts` | several | newer majors | pinned by reth v2.8.1's workspace; they move with reth |
| `alloy-trie` 0.9.8 (lock pin) | reth-trie-common | 0.9.9 | 0.9.9 adds a public field (`all_branch_nodes`) to `HashBuilder`; reth's `From<HashBuilderState> for HashBuilder` (v2.8.1 and v2.9.0 alike) builds the struct literally and stops compiling. Pinned with `cargo update -p alloy-trie --precise 0.9.8`, the version reth v2.9.0's own lock has; a plain `cargo update` brings 0.9.9 back |
| `zstd` 0.13 | vendored reth crates | 0.14 | reth v2.8.1 pins 0.13 (v2.9.0 moves to 0.14.3) |

## Dependency repairs

- `alloy-primitives-0.8.26` removed: its only consumer was `ethereum_serde_utils` 0.7. Patch
  entry, `PROVENANCE.json` record and `PATCHES.diff` hunk removed with it.
- No other repaired crate moved: `cargo update` left every patched version in place and cargo
  reports no unused patch. `reth-{nippy-jar,transaction-pool}-2.8.1` stay on v2.8.1 with reth.

## Verification

Gate run through `quiet-run.sh` (logs `f-gate1*.log` in `/data/n42-build/audit-notes/ci/`).

| Command | Result |
|---|---|
| `cargo check --workspace` | clean |
| `cargo check -p n42-ef-tests -p mobile-sdk -p n42-testing --tests` | clean |
| `cargo test -p n42-testing` | 28 passed, 1 ignored |
| ported crates (`n42-bmt-core` ... `n42-h2-execution`) | 759 passed, 3 ignored |
| `cargo test -p n42-engine-types -p reth-chainspec --lib` | 375 passed, 11 ignored |
| `cargo test -p n42-clique -p n42-primitives -p n42-consensus-traits --lib` | 302 passed |
| `scripts/clippy-n42.sh` (`-D warnings`) | clean |
| `testdata/` fixtures (54 files, SHA-256 of raw bytes) | unchanged |

Not run here: a release build, the devnet or fleet. Nothing on the execution path moved (revm,
alloy, alloy-evm, reth unchanged); the moves are build tooling, compression, TLS and RLP patch
releases.
