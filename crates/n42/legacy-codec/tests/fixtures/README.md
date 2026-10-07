# Legacy fixtures

Generated using the original crates.io bincode 1.3.3 free `serialize` function,
with the unchanged `n42_qmdb_state::forest` types. The generator ran outside this
workspace so the original dependency is not retained in the project's lockfile.

- Checkpoint: version 1, head 42, hash [0xab; 32], next slot 65,
  active words [u64::MAX, 1].
- Delta: version 2, head 43, hash [0xcd; 32], base slot 65, next slot 67,
  no appended entries, changed [(0, false), (65, false), (66, true)].

The integration tests require byte-for-byte re-encoding of these files, retain
consecutive record boundaries, and reject every truncated checkpoint prefix.
- Validator changes: Add [0x11; 20], the BLS public key from `key_gen([7; 32])`,
  peer ID "peer-1"; Remove [0x22; 20]. Uses the real consensus Serde types and the
  original bincode 1.3.3 encoder. The encoded list is input to consensus hashes.
