# reth v2.10.0 → v2.11.0

Dated 2026-11-14/15, branch `upgrade/reth-v2.11.0`, made from main at 30007d39e. Upstream
v2.11.0 (`b9abbcc1`, 2026-11-11) is 94 commits after v2.10.0 (v2.10.1 lies in between and is
covered by the same diff). Like 2.9.0 → 2.10.0 this is a re-sync, but a larger one: evm2 moved
about 165 commits, reth's Ethereum block executor now runs on `evm2::block` (#28238), and the
discovery stack moved to secp256k1 0.33 / enr 0.14 / discv5 0.12 (#28289). No fleet or devnet
round was run for this record; the coordinator runs `roll --kill` and the throughput pair.

## Versions moved

| Crate | v2.10.0 | v2.11.0 |
|---|---|---|
| reth (git tag, 103 entries) | v2.10.0 (`f5192ac7`) | v2.11.0 (`b9abbcc1`); rust-version stays 1.96 upstream |
| evm2, evm2-inspectors, evm2-jit (git rev, and the `DaniPopes/evm2` patch) | `592bf18c` | `66687c18` |
| reth-core crates (`[patch.crates-io]`) | rev `275ce4cf` | unchanged |
| alloy 2.5.0, alloy-primitives | - | unchanged (the alloy forks need no re-merge) |
| alloy-trie | 0.9.8 (held back) | 0.9.9 (upstream bumped it with the `HashBuilder` field fix, #28367) |
| secp256k1 / enr / discv5 (workspace) | 0.30 / 0.13 / git `7663c00` | 0.33 / 0.14 / 0.12 from crates.io |
| new upstream crate | - | `reth-lru` (replaces `schnellru` in reth; N42 crates keep `schnellru`) |
| dropped | `rand_08`, the `inkwell` patch | evm2 no longer uses inkwell (#886) |

## Sync (`scripts/reth-sync.py v2.10.0 v2.11.0`)

49 files merged (most fast-forward), one added (`ethereum/node/tests/e2e/executor_replay.rs`),
none deleted, five conflicted (`ci/r211-sync.log`):

| File | Resolution |
|---|---|
| `chainspec/src/spec.rs` | ours: the dev fork-id test keeps `0x45b83612`. Upstream's dev genesis gained the Prague system contracts, so upstream's id moved, but this fork's `DEV` seals with the fixed `DEV_GENESIS_HASH` (upstream hashes `dev.json`, #18300), so ours did not. The merge first took theirs; `cargo test -p reth-chainspec` caught it (cb4ac42f1) |
| `node/core/src/args/engine.rs` (3 hunks) | upstream removed the no-op parallel-sparse-trie flags (#28369); the N42 `--engine.state-trie-overlay` field and its defaults stay |
| `provider/.../blockchain_provider.rs` | import list: upstream's `MetadataProvider` plus our `MemoryOverlayStateProvider` |
| `provider/.../static_file/writer.rs` | upstream's deferred truncation (`apply_pending_truncation`, #28370) runs first, then the N42 `N42_SF_DROP_CACHE` page release on the cut files (`drop_range` already handles a shrunk file) |
| `storage-overlay/src/manager.rs` (3 hunks) | upstream moved the manager's state behind one `Arc<OverlayManagerInner>` (#28333); the N42 `layered` flag stays on the outer struct, so a clone is still one reference count |

Dependency repairs, merged by hand (`ci/r211-repair-merge.py`):

- `reth-nippy-jar`, `reth-transaction-pool`: renamed `-2.11.0`, every upstream-changed file
  three-way merged (nippy-jar: deferred truncation; transaction pool: seven files of txpool
  fixes, `schnellru` → `reth-lru`; one manifest conflict). `PROVENANCE.json` / `PATCHES.diff`
  regenerated; nippy-jar's `modified_files` now also lists the N42 `src/lib.rs` / `src/writer.rs`.
  The nippy-jar unit tests read new `tests/fixtures/zstd-0.13` at compile time; those are vendored.
- **Found in the merge:** the N42 `NippyJarWriter::append_encoded_rows` (the static-file bulk
  append behind `n42_append_encoded_tx_rows`) did not apply a truncation deferred by v2.11.0's
  `prune_rows_deferred`. Upstream's `append_column` does. Without it, a bulk append after an
  unwind writes behind the pruned bytes and its offsets point past them. Fixed, with the test
  `append_encoded_rows_after_a_deferred_prune_matches_per_row_append`.
- `evm2-inspectors-0.1.0` (traceCall beneficiary prestate): rebased onto `66687c18`. The import
  hunk was re-made by hand, and the body applied. Upstream's `geth_prestate_pre_traces` still lists only changed
  accounts, so the repair is still needed.

## Code changes the bump required

- **secp256k1 0.33** (6688b6414): the context argument is gone. Recovery is now
  `RecoverableSignature::recover_ecdsa`, signing `RecoverableSignature::sign_ecdsa_recoverable`,
  and keys use `SecretKey::from_secret_bytes` / `to_secret_bytes`. The APoS header recovery in
  `n42-clique-utils` changes only its call shape, and the rest are test helpers. Transaction sender
  recovery is unaffected: alloy-consensus and reth-primitives-traits still use 0.30.
  `tx_flood` keeps signing with **0.30** through a dev-dependency, because 0.33 rerandomises its
  global context on every signature, and that would move the flood's supply ceiling between A/B legs.
- `payload.rs` (bf6b8a65f): `EthBlockExecutor` no longer has a public `receipts` field. The
  late-receipts check reads `BlockExecutor::receipts`, which returns the same list.
- `--rpc-cache.max-headers` (ed2d8483a): upstream removed this no-op flag. `scripts/fleet7-env.sh`
  passes it, so the node keeps it as a hidden no-op (`n42_legacy_max_headers`). Otherwise the
  v2.11.0 binary would refuse the fleet7 launch line.

`N42BlockExecutor`, the fast handler, the direct transfer path, `parallel_build`, `graft_fold`,
`batch_state` and the follower import needed no source change against evm2 `66687c18`. Their
equivalence tests pass (`ci/r211-t-main.log`).

## Dependency refresh

`cargo update` after the bump (`ci/r211-update.log`, on top of 9fd947a07) moved only
alloy-eip7928 to 0.4.13, bumpalo to 3.20.4, cc to 1.11.2 and mio to 1.2.5. `cargo update --verbose` lists 36
crates behind their latest version (`ci/r211-behind.log`). None was bumped. The reasons:

| Dependency | Reason it stays |
|---|---|
| `itertools`, `strum`, `rand` 0.9, `parking_lot`, `sysinfo`, `tikv-jemallocator`, `codspeed-criterion-compat`, `similar-asserts`, `toml`, `roaring`, `rocksdb`, `lz4_flex`, `proptest`, `generic-array` | pinned at reth v2.11.0's `[workspace.dependencies]` versions; they move with reth |
| `jsonwebtoken`, `base64` | the alloy-rpc-types-engine fork tracks alloy 2.5.0 |
| `k256` 0.14, `sha2` 0.11 | alloy's RustCrypto generation, and a bump would split the key types |
| `rand_core` 0.10 | it must match merlin 3's transcript RNG (0x50 batch verification) |
| `jni` 0.22 | every JNI entry point would be rewritten, and the Android path cannot be exercised here |
| `zstd` 0.13 (lock) | the nippy-jar repair's own pin (its zstd-0.13 fixtures) |
| wasm-bindgen / js-sys / web-sys, icu_*, futures-timer | compatible releases held by their dependants' exact pins; not built natively or not worth a manual override |

## Engine defaults (the reth-bump rule)

| File (upstream) | v2.10.0 → v2.11.0 |
|---|---|
| `engine/primitives/src/config.rs` (`TreeConfig`) | `always_compare_trie_updates` removed (a debug comparison, off by default); no other field or default moved |
| `node/core/src/args/engine.rs` (`EngineArgs`) | removed flags: `--engine.legacy-state-root`, `--engine.caching-and-prewarming`, `--engine.parallel-sparse-trie`, `--engine.disable-parallel-sparse-trie`, `--engine.state-root-task-compare-updates`, `--engine.precompile-cache` (all no-ops or debug-only; no N42 script passes them). No default moved |
| `engine/tree/src/persistence.rs` | unchanged |
| `engine/tree/src/tree/**` | trie-updates comparison removed, invalid-block hook output capped and offloaded, BAL execution moved onto `evm2::block`; no threshold or buffer moved |
| `node/core/src/args/{rpc_server,rpc_state_cache,network}.rs` | `--auth-ipc.path` is an `Option` (suffixed per instance), unset `--http.api` / `--ws.api` count as the standard set when a namespace is checked, `--rpc-cache.max-headers` removed (kept by N42, above) |

The persistence and masking defaults stand as recorded for v2.10.0: `persistence_threshold` 50,
`memory_block_buffer_target` 5, `num_state_masking_blocks` 30, plus the node's QMDB overrides
(`qmdb_tree_config`: masking 0, threshold 8, buffer 6). Nothing needed pinning.

Behaviour changes near persistence that are not defaults, for the `roll --kill` check:

- static files now truncate on reorg only at commit (#28370), which is the merge note above;
- an interrupted genesis initialisation resumes (#28376);
- MDBX's read monitor stops on environment drop, and its read-tx timeout monitor no longer has a lock inversion (#28404, #28254);
- snap trie reverts are no longer cached (#28401).

Other RPC-visible changes: the default `eth_call` gas is capped at the fork's transaction gas
cap (#28315); the builder validation window defaults to 3 blocks (#28424); `eth_callMany` and the
`*_callMany` tracers are bounded to 1024 calls and 5 s; `eth_getProof` is bounded to 1024 slots;
`eth_sendTransaction` nonces are serialised.

## Code gate

All through `audit-notes/scripts/quiet-run.sh`, target dir `/data/n42-build/wt-reth211/target`,
logs under `audit-notes/ci/`. check, clippy and the n42 / ported / main suites ran at bf6b8a65f; cb4ac42f1 after it changes one test constant:

| Step | Log | rc | Result |
|---|---|---|---|
| `cargo check --workspace --tests` | `r211-check.log` | 0 | clean |
| `cargo clippy --workspace --lib --bins --examples` | `r211-clippy.log` | 0 | clean |
| `scripts/clippy-n42.sh` (`-D warnings`) | `r211-clippy-n42.log` | 0 | clean |
| `cargo test -p n42-testing` | `r211-t-testing.log` | 0 | 28 passed, 1 ignored |
| ported crates (bmt-core, twig-core, h2-primitives, h2-wire, h2-consensus, mobile-verify, h2-net, h2-execution) | `r211-t-ported.log` | 0 | 780 passed, 4 ignored (byte-exact fixtures included) |
| `cargo test -p n42-engine-types -p n42-h2-node -p n42-qmdb-state -p n42-env -p n42` | `r211-t-main.log` | 0 | 749 passed, 19 ignored |
| `cargo test -p reth-nippy-jar -p reth-node-core -p reth-provider -p reth-chainspec --lib --tests` | `r211-t-vendored3.log` | 0 | 522 passed, 4 ignored (incl. the new nippy-jar test and the restored dev fork id; `r211-t-vendored2.log` was the fork-id failure) |
| `cargo test -p n42-clique-utils -p n42-tx-ingest -p n42-tx-types -p n42-clique` (the secp256k1 port) | `r211-t-touched.log` | 0 | 211 passed, 6 ignored |

## Dependency advisories (2026-11-15)

`cargo-audit` is not installed here. The check matched every lockfile in the repository
(`Cargo.lock`, `ddn/Cargo.lock`, `docs/sigbench/Cargo.lock`) two ways:

- against a fresh clone of `rustsec/advisory-db` (`02e2517`, at `/data/n42-build/rustsec`);
- against OSV.dev, which also carries the GHSA ids GitHub reports.

Only crates.io packages were checked; the git-sourced reth and evm2 crates are not. GitHub's
count on main ("4 advisories, 1 moderate, 3 low") is consistent with the four rustls advisories in
`ddn/Cargo.lock`. The root lock has no rustls hit.

| Advisory | Crate (lock) | Kind | Status |
|---|---|---|---|
| RUSTSEC-2026-0346 / 0347 / 0348 / 0349 (GHSA-c8m5…, -h2v8…, -vp88…, -w44r…) | rustls 0.23.45 (ddn) | TLS secrets in `Debug`, ECH data leak, Brotli 1 GiB allocation, ServerHello downgrade | **fixed**: 0.23.46 (d7bba8f47) |
| RUSTSEC-2026-0382 | rustls-webpki 0.103.15 (ddn) | distrusted intermediates accepted | **fixed**: 0.103.17 |
| RUSTSEC-2026-0383 | webpki-root-certs 1.0.9 (ddn) | distrusted emSign roots | **fixed**: 1.0.12 |
| RUSTSEC-2026-0386 | tokio 1.53.2 (ddn) | unsound `AsyncFd::new` | **fixed**: 1.54.1 |
| RUSTSEC-2026-0486 | rustix 1.1.5 (ddn) | unsound xattr zero-length buffer | **fixed**: 1.1.6 |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 (all three) | timing variability in constant-time ops | **left**: fixed only in 0.7.6, a major bump. 0.5 comes from `elliptic-curve` 0.13 / `k256` 0.13, alloy's RustCrypto generation. The node recovers senders with libsecp256k1, and k256 signs only in tooling (`TX_FLOOD_K256_SIGN`, mobile-sdk) |
| RUSTSEC-2024-0436 | paste 1.0.15 (root, ddn) | unmaintained | **left**: pulled in by evm2 / evm2-jit-builtins (upstream); the N42 repairs already use `pastey` |
| RUSTSEC-2024-0388 | derivative 2.2.0 (ddn) | unmaintained | **left**: transitive, ddn only |
| RUSTSEC-2026-0162 / 0163 / 0165 | pqcrypto-traits / -internals / -falcon (sigbench) | unmaintained | **left**: the signature benchmark only, not built with the node |

The v2.11.0 upgrade itself clears none of these: the root lock carries the same two hits as main.
The ddn bumps are lock-only. `cargo test --locked` in ddn passes (`ci/r211-ddn-test.log`, four
test binaries).

## SIGKILL recovery (`roll --kill`, 2026-11-17)

The recovery rounds ran on the upgrade natives (`target/native/release`, built from 6df0139bc
by the coordinator's chain). The runner was `audit-notes/scripts/rollkill-check.sh`: seven-node
`fleet7.sh up --fresh`, 200 tx/s offered, then `roll 1/2/3 --kill` 45 s apart and a 360 s watch.
It held the box through box-gate and ran under `flock devnet/.round.lock`, after `CEIL-CHAIN DONE`.
There were four shapes; the driver is `ci/r211-rollkill.out` and each shape's outputs are
`ci/r211<shape>-rollkill-{up,roll,watch,status}.out` and `ci/r211<shape>-node<i>-el-recovery.txt`:

| Shape | First kill | QMDB | Kills (height → restored from) | After 360 s | Fault lines |
|---|---|---|---|---|---|
| k20 | 20 s, before the first MDBX persistence | heap | node1 at 7 → genesis checkpoint (block 0); node2 at 24, node3 at 41 → their persisted forests | 117 blocks (0.325/s); all 7 at 118, one head `0x266ff56d…` | 0 |
| k90 | 90 s, after several persistence rounds | heap | node1 at 31 → block 21; node2 at 48, node3 at 65 | 118 blocks (0.328/s); all 7 at 119, one head `0x8aaad771…` | 0 |
| k20f | 20 s | entry file (`N42_QMDB_ENTRY_FILE=1`) | node1 at 7 → entry file at block 0; node2 at 24, node3 at 41 | 117 blocks; all 7 at 118, one head `0x233e23d9…` | 0 |
| k90f | 90 s | entry file | node1 at 31 → entry file at block 21; node2 at 48, node3 at 65 | 118 blocks; all 7 at 119, one head `0xe13c49bf…` | 0 |

In every round, each killed member did four things:

- logged `restored the QMDB forest`;
- ran reth's `check_consistency: Healing static file inconsistencies` on start-up, the
  static-file unwind that now goes through `prune_rows_deferred`;
- appended to the cut files again, covering the nippy-jar bulk-append fix;
- committed again within a minute ("commits since restart" 1-2).

No el.log carried a fault line (`SnapshotMismatch`, `PersistUnsettled`, `cannot follow the
canonical chain`, `not settled through`, an exit), an ERROR or an invalid block. No `n42` or
`h2_validator` process was left after `down`. The same fleet shape on v2.10.0 (gk90 / gk20)
read 118 / 117 blocks in the watch; this round matches it.

## Left for the coordinator

- The X22 throughput pair against main. Two things there could show: `evm2::block` under the
  builder and follower, and evm2's interpreter changes (64-byte aligned dispatch, tco stack
  length in bytes).
- A gov5 mixed devnet round. The hashes should be unchanged, because no consensus or encoding
  code moved.
