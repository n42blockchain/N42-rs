# Maintained dependency replacements

These are narrow source patches to the exact upstream releases in
`PROVENANCE.json`. They retain the upstream data formats, optional features and license files.
The codec error payload changes to the maintained encoder/decoder error types. They are not forks of the abandoned dependencies under new names.

- Consumers of `paste` use the maintained `pastey` implementation via a dependency
  alias. This includes Linux/profiling/compiler paths retained in Cargo.lock.
- Aquamarine uses `proc-macro-error3` (3.0.1 is the compatible version required by
  Alloy's macro dependency). The source import also changes because the attribute
  macro expands paths using the actual crate name.
- ark-ff 0.3/0.4 uses Educe for its existing field derives, with the original empty
  generic bounds preserved. A stale Debug field attribute on the manually
  implemented Debug type is removed. The local N42 primitives use Educe directly.
- sled 0.34.7 uses rustc-hash 1.1's FxHasher on the supported 64-bit host. The hash
  maps are in memory; this patch does not rewrite sled's serialization. Its old
  parking_lot dependencies use web-time for Instant. Current compiler style
  diagnostics in sled are warnings, matching the original registry dependency's
  capped lint behaviour; memory-safety lints remain unchanged.
- test-fuzz-internal uses postcard's `use-std` feature without its default
  `heapless-cas` feature. The standard allocator remains enabled and no fuzz API
  is removed. This removes heapless 0.7 and atomic-polyfill from the dependency tree.
- NippyJar uses `n42-legacy-codec`: a small Serde adapter backed by maintained
  `bincode_reloaded`, configured with the bincode 1 free-function wire format.
  It preserves fixed-width little-endian encoding and trailing-byte acceptance.
  The error type now wraps the maintained encoder/decoder errors. Old checkpoint
  and delta fixtures are checked independently. No persisted data migration is
  performed.

`PATCHES.diff` records changes against the pinned upstream source, excluding
copied upstream license files and packaging metadata. The vendored code is kept
for reproducible builds because these upstream releases still depend on abandoned
crates. Recheck these patches when upgrading a parent package and remove a patch
when a maintained upstream release supplies the same replacement. Updating only
Cargo.lock is not sufficient to keep these local patches current.
