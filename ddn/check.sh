#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--local" ) ]]; then
    echo 'Usage: ddn/check.sh [--local]' >&2
    exit 2
fi
export CARGO_BUILD_JOBS=1
export PYTHONDONTWRITEBYTECODE=1
cargo fmt --check
nice -n 19 cargo test --locked --offline -j 1
nice -n 19 cargo clippy --locked --offline --all-targets -j 1 -- -D warnings
nice -n 19 python3 -m unittest discover -s scripts -p 'test_*decision*.py'
nice -n 19 npm test --prefix sdk/decision-ts
if [[ "${1:-}" == "--local" ]]; then
    echo 'Local checks passed. Solidity and live testnet acceptance remain required.'
else
    command -v forge >/dev/null || { echo 'Acceptance incomplete: Foundry forge is required.' >&2; exit 1; }
    nice -n 19 forge build
    nice -n 19 forge test --match-path 'contracts/decision/test/*'
fi
