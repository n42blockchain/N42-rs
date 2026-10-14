# Narrow compatibility repair

Upstream: crates.io `proptest-arbitrary-interop` 0.1.0. Source and tests are retained.

Change: import `proptest::prelude::Rng` alongside `RngCore`, so `TestRng::fill_bytes`
resolves with proptest 1.11's newer rand API. The adapter previously imported
only the older trait. This changes trait visibility, not generated-byte semantics.

Keep this patch local and do not edit the shared Cargo registry source. The
upstream crate is licensed under MIT OR Apache-2.0; see its manifest and README.
