# reth v1.11.0 → 2.4.1: measured assessment

Dated 2026-08-24. Supersedes the stale "current version: reth v1.4.3" section of
`docs/RETH_UPGRADE_GUIDE.md`. This is a *measurement*, not a completed upgrade —
the attempt was run in a scratch copy and the working tree was not modified.

## The headline

The upgrade is not a version bump. Between v1.11.0 (2026-02-12) and 2.4.1 there
are **1,484 upstream commits**, and reth **deleted or relocated 22 of the 121
reth crates this repo depends on** — including two that this repo maintains
vendored forks of.

| Layer | v1.11.0 (here) | 2.4.1 |
|---|---|---|
| edition / rustc | 2021 / 1.86 | 2024 / 1.97 |
| revm | 34.0.0 | 42.0.1 |
| alloy-consensus, -eips, -genesis | 1.6.3 | 2.3.0 |
| alloy-primitives | 1.5.6 | 1.6.1 |

## What happened to the 22 crates

**16 are unused here** — declared in `[workspace.dependencies]` but referenced by
no member crate, so dropping them costs nothing: all eleven `reth-optimism-*`
(split into the op-reth repo), `reth-bench`, `reth-blockchain-tree`,
`reth-blockchain-tree-api`, `reth-auto-seal-consensus`,
`reth-rpc-api-testing-util`.

**6 are real**, with the migration for each already identifiable upstream:

| Crate | Used by | Upstream change | Migration |
|---|---|---|---|
| `reth-primitives-traits` | **25 manifests, 103 source files** | moved out of reth into the separate `reth-core` repo, consumed from crates.io ([#23210](https://github.com/paradigmxyz/reth/pull/23210), 2026-03-25) | re-home the vendored fork; patch via `[patch.crates-io]`, not the reth git URL |
| `reth-primitives` | 9 manifests, 9 source files | deleted ([#23220](https://github.com/paradigmxyz/reth/pull/23220), 2026-03-25) | `reth-ethereum-primitives` + `reth-primitives-traits` |
| `reth-codecs`, `reth-codecs-derive` | 4 manifests, 12 source files | moved to `reth-core`, crates.io v0.6.0 | repoint; note the `op` feature no longer exists |
| `reth-rpc-types-compat` | 4 manifests, 3 source files | renamed `reth-rpc-convert` ([#17013](https://github.com/paradigmxyz/reth/pull/17013), 2025-06-23) | rename + re-sync the vendored fork |
| `reth-engine-service` | 2 manifests, 1 source file | removed | folded into the engine tree |
| `reth-ress-provider` | 0 manifests, 2 source files | removed | already commented out in `bin/n42` |

## Why this is worse than it looks: the fork boundary moved

Two of this repo's vendored forks target crates that **no longer live in reth**:

- `crates/primitives-traits` — holds `clique_utils` (`recover_address`,
  `seal_hash`), the signature-recovery core of APoS. Upstream's copy is now in
  `reth-core` on crates.io.
- `crates/rpc/rpc-types-compat` — upstream renamed it.

`[patch.'https://github.com/paradigmxyz/reth.git']` cannot patch a crate that
URL no longer publishes. Both forks must be re-homed against a different
upstream and patched through `[patch.crates-io]`. This is the single most
consequential structural change in the upgrade, and it lands squarely on the
APoS consensus path.

## How far the mechanical attempt got

Run in a scratch copy (`cargo generate-lockfile`, iterating on each error):

1. ✅ 122 `tag = "v1.11.0"` → `tag = "v2.4.1"`
2. ✅ edition 2024, rust-version 1.97, revm/alloy pins aligned to 2.4.1's
3. ✅ 16 unused deleted crates commented out
4. ✅ `reth-primitives-traits` / `reth-codecs` / `reth-codecs-derive` repointed to crates.io 0.6.0
5. ✅ `reth-rpc-types-compat` → `reth-rpc-convert`
6. ✅ `reth-primitives` → `reth-ethereum-primitives` across 11 member manifests
7. ✅ five feature references dropped that 2.4.1 no longer offers
   (`reth-ethereum-primitives/asm-keccak`, `/serde-bincode-compat`,
   `reth-cli-commands/rocksdb`, `reth-evm/op`)
8. ❌ **blocked**: the vendored `crates/primitives-traits` fork itself requires
   `reth-codecs` with feature `op`, which reth-core 0.6.0 does not have.

That last one is the boundary: further progress is no longer manifest editing,
it is re-syncing the vendored forks against a different upstream. **The source
layer was never reached** — the ~103 files using `reth-primitives-traits`, the
revm 34→42 API drift, and edition-2024 migration are all still ahead.

## Recommended sequence

1. **Re-home the two orphaned forks first**, before touching anything else.
   Diff `crates/primitives-traits` against `reth-core` v0.6.0, re-apply
   `clique_utils` and the N42 header constants, and move its patch entry to
   `[patch.crates-io]`. Same for `rpc-types-compat` → `reth-rpc-convert`. Until
   this is done nothing else resolves.
2. **Drop the 16 unused crates** on `main` now — it is a safe, independent
   cleanup that shrinks the upgrade surface and is worth doing regardless.
3. **`reth-primitives` → `reth-ethereum-primitives`** across the 9 source files.
4. **Then** the 1,484-commit API drift, crate by vendored crate, in the tier
   order the existing `patches/` and prior upgrade commits established.
5. Edition 2024 last — it is mechanical (let-chains and friends) and touching it
   earlier just adds noise to every other diff.

## The alternative worth weighing

`../N42-26` already **is** the reth-2.4.1 Rust client, with HotStuff-2 and QMDB,
and it consumes reth by local path rather than fighting a fork. If the goal is a
Rust node on the gov5 fleet, converging on N42-26 is cheaper than carrying a
reth-1.11 fork across this boundary. What this repo owns that N42-26 does not is
APoS/Clique and the beacon storage layer — so the question is whether those need
to move onto reth 2.4.1 at all, or whether they stay on a maintained 1.11 branch
while new work happens in N42-26.
