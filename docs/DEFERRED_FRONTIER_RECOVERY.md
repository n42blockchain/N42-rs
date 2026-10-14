# Deferred depth-two execution frontier recovery

A child at depth two carries the execution result of its grandparent. Restoring only the execution fields of the database head leaves the first proposal after restart waiting forever for result(head-1). A deferred header cannot supply that block's own root: its fields describe an older ancestor.

Startup now resolves the canonical parent header and reconstructs its exact QMDB root before initialisation resumes compaction. When the checkpoint is older than that parent, the sealed log and current delta log are replayed to the parent's exact hash and number. Receipts are read from the database and combined with this root, then parent and head execution fields are seeded before serving proposals. Missing receipts of a non-empty block fail startup.

File-backed historical reconstruction uses a read-only entry-file opener. The normal recovery opener intentionally truncates records past its cursor; using it for head-1 would destroy entries needed by the real head. The historical path preserves all file bytes and rejects an incomplete entry prefix.

Before a depth-two checkpoint replaces its replay history, `forest.frontiers` durably records its immediate parent's hash and computed root. This bounded sidecar holds four checkpoint frontiers, including the old one while replacement is in progress. It carries a format version, chain ID, genesis hash and checksum. The sidecar is fsynced, atomically renamed and its directory synced before checkpoint replacement or log removal. Checkpoint formats remain unchanged, and no per-transaction operation is added.

Legacy data with the requisite delta history can migrate at startup without resetting chain data or consensus vote logs. If a legacy checkpoint has already compacted away its parent's state without a frontier, startup fails explicitly; the head root is never substituted. Corrupt, wrong-chain or mismatched frontier data is likewise rejected. The frontier is local recovery metadata under the same storage integrity assumptions as the QMDB checkpoint, not a remote state proof.

Regression coverage includes heap and entry-file recovery, sealed-log replay, synchronous and background compaction, interrupted checkpoint/segment cleanup, read-only entry preservation, checksum and chain-identity failures, and a frontier I/O failure before history deletion. Runtime validation must also restart the retained V=7/E=1 chain, verify that height advances beyond 258, preserve old transaction block hashes, and admit new strictly verified Ed25519 transactions.
