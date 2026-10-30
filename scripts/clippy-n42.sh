#!/usr/bin/env bash
# Clippy with `-D warnings` over the N42-owned crates (crates/n42/* and bin/n42).
#
# Out of scope on purpose: the vendored reth forks (crates/{storage,consensus,node,ethereum,
# chainspec,chain-state,net,rpc,revm}, bin/reth), vendor/dependency-repairs and the two alloy
# forks crates/n42/alloy-rpc-types-{engine,beacon}; they track upstream and keep their warnings.
# `--no-deps` keeps the denied lints on the listed packages only; their path dependencies are
# built as before.
set -euo pipefail
cd "$(dirname "$0")/.."
PACKAGES=(
  n42 consensus-client mobile-sdk merkle_db_rs pubsub-mem reth-rpc
  n42-bmt-core n42-clique n42-clique-utils n42-consensus-core n42-consensus-traits
  n42-core-layout n42-deferred-reverts n42-dependency-compat-tests n42-ef-tests
  n42-engine-primitives n42-engine-types n42-env n42-fusaka n42-h2-consensus
  n42-h2-el-rpc n42-h2-execution n42-h2-net n42-h2-node n42-h2-primitives n42-h2-wire
  n42-legacy-codec n42-mobile-service n42-mobile-verify n42-primitives n42-qmdb-reth
  n42-qmdb-state n42-sharded-output n42-storage n42-testing n42-twig-core n42-tx-ingest
  n42-tx-queue n42-tx-types
)
args=()
for p in "${PACKAGES[@]}"; do args+=(-p "$p"); done
exec cargo clippy --no-deps "${args[@]}" --lib --bins --examples -- -D warnings "$@"
