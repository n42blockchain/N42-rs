# QMDB history: verifiable state proofs at past heights

Status: implemented behind `--qmdb.history` / `N42_QMDB_HISTORY` (off by default), 2026-11-16.

## Release notes

- **`eth_getProof` on a QMDB chain is refused** with `-32004`, naming `n42_getProof`, on every
  transport (http, ws, ipc and the auth port). The Merkle-Patricia trie is not maintained on a
  QMDB chain, so the proofs it used to return never verified against a QMDB header. Use
  `n42_getProof`.
- **`n42_getProof(address, storageKeys[], block)`** and **`n42_proofWindow()`** are new, served
  on every transport that serves `eth_*`. They prove past blocks when history is on (below); with
  history off `n42_getProof` answers `-32004` (history off).
- **`mobile_getProof`** proves only at the head. A third parameter other than `"latest"` is now
  refused with `-32005` (it used to be ignored, so a head proof was returned for any block asked).
  A head proof that does not verify against the root read with it (the head moved while it was
  cut) is now `-32006` (retry), where it used to be `null` (which reads as "no such account").
- **History is opt-in**: `--qmdb.history <N|all|off>` or `N42_QMDB_HISTORY`. Without either,
  nothing is written or read, and roots, on-disk format and the persistence path are unchanged.

## What it serves

`n42_getProof(address, storageKeys[], block)` returns QMDB membership proofs for an
account and its storage slots as they stood **after** `block` (a number, a hash, or
`latest`/`finalized`/`safe`/`earliest`), together with:

| field | meaning |
|---|---|
| `blockNumber`, `blockHash` | the block whose post-state is proved |
| `stateRoot` | the QMDB root after it, rebuilt from history |
| `anchorNumber`, `anchorHash` | the persisted header that carries `stateRoot` (the block itself; under deferred execution the descendant at the chain's depth) |
| `account`, `storageProof[]` | per key: `key` (gov5 key hash), `found`, `value`, `proof` |
| `proofFormat` | `gov5-qmdb-v2` |

A client checks each `proof` with `QmdbProof::decode` + `verify_for_key(anchor.stateRoot, key)`
(Rust, `n42_twig_core::qmdb_compat`) or gov5's `qmdb.UnmarshalProof` + `VerifyProof`
(`lib/qmdb/proof.go`). `found: false` is the node's statement, not a proof: QMDB proofs prove
membership only (non-existence proofs need a format change, out of scope). The node says
`found: false` only when its recorded data shows the key had no live entry; when that depends on
blocks not recorded yet, or on a live tree on another branch, it answers `-32001` (retry).

`n42_proofWindow()` reports `{history, mode, earliest, latest, broken}`.

### Error codes

| code | when |
|---|---|
| `4444` | the block is below the earliest provable one (pruned, never kept), or a later rewind of persisted state re-appended slots its state used (see "Branch switches") |
| `-32001` | not persisted yet / root not yet carried by a persisted header / the key's answer depends on blocks after the history head or on a live tree on another branch / the leaf-root cache is still being built: retry |
| `-32004` | history off; block not recorded (inside a multi-block persistence span, or not the block history holds at that height); a key's lookup exceeds its read budget |
| `-32005` | the request would read more history than `N42_QMDB_HISTORY_BUDGET_MB` allows (EIP-1474 "limit exceeded") |
| `-32603` | the rebuilt root disagrees with the header (never a proof), or a history file is unreadable |

## The proof

The same proof the head serves (`QmdbCompatTree::prove`), cut from the tree as it stood after N:

```
leaf = hash_leaf(key, value)                         -- frozen at append
twig leaf tree: 11 siblings (twig_path)              -- twig_leaf_tree over the twig's 2048 leaves
twig root = hash_node(leaf_root, blake3(0x03 || active_bits))   -- active_bits at N (256 bytes)
upper binary tree: siblings up to the root at N's capacity (upper_path)
```

Layout (`QmdbProof::encode`, gov5 `Proof.Marshal`): `0x02 | key 32 | slot u64 LE | 11 | 11x32 |
bits 256 | upper_len u8 | upper_len x 32 | value_len u32 LE | value`. The history tests compare
every historical proof byte-for-byte with the head proof cut at that height.
`crates/n42/bmt-core` (the mobile SBMT) is not involved: QMDB roots are twig/upper trees.

## How N is rebuilt (`crates/n42/qmdb-reth/src/history.rs`)

A QMDB root is a function of the entry log (append-only, leaves frozen), the append cursor and
the active bits. History keeps, under `<datadir>/qmdb/history/`, segments each headed by a
snapshot:

| file | content |
|---|---|
| `seg-<S>.ckpt` | `ForestCheckpoint` (cursor + active bits) after block `S`; the oldest is the base, the others are written by a background thread |
| `seg-<S>.log` | the file-mode `ForestDelta` of each block after `S` (cursor, retired slots), framed like `forest.log` |
| `seg-<S>.idx` | 72 bytes a record (block, hash, cursors, offset); rebuilt from the log when torn |
| `seg-<S>.sum` | a sealed segment's summary |
| `twigs.idx` | leaf root of every full twig (32 B a twig): a cache of the entry log, cut on every unwind/rewind |

A segment is sealed (and the next one begun) after `N42_QMDB_HISTORY_SNAPSHOT_BLOCKS` blocks or
once its deltas outweigh a snapshot (at least 32 MiB, at most a quarter of the request budget).
Nothing about the records is held in memory: one small entry per segment, and the (rare)
rewinds.

For block N the prover loads the snapshot at or before N (twig roots from the cached leaf roots
and the snapshot's bits, then the upper tree), replays the deltas up to N onto copies of the twigs
they touch, recomputes those twigs' roots (the youngest, partial twig re-folded from
`entries.log`) and rehashes the upper tree along their paths. The work is bounded by the deltas
since the snapshot before N, never by the distance to the head. The root is compared with the
anchor header's `stateRoot` before any proof is cut; each proof is verified against it. Two loaded
snapshots and sixteen proof-ready heights are cached; at most two requests compute at once.

A key's slot at N: the live index's slot when it is below N's cursor and live at N; else its
latest append at or before N (a block's appended run is in key order: binary search); else from
genesis (the alloc, in key order) or, from a later base, the first retirement after N, recorded
or on the live tree past the history head. Every candidate is checked (the record holds the key,
the bit at N is set). One request takes the forest's lock once, for all its keys (an index probe
and the slots the live tree retired past the history head; it never moves the tree). Entry
records are read with positional reads at the offsets the tree publishes lock-free; nothing is
mapped.

## Operating it

`--qmdb.history <N|all|off>` on `n42 node`, or `N42_QMDB_HISTORY=<N>|all|off` (see
`docs/KNOBS.md`); the flag overrides the variable. An invalid value of either refuses to start,
as does the flag on a chain whose genesis does not declare QMDB. Requirements, refused at
start-up otherwise: `N42_QMDB_ENTRY_FILE=1`; `N42_QMDB_COMPACT` off, on a database it never
compacted (compaction moves the dead records past heights read).

Tuning: `N42_QMDB_HISTORY_SNAPSHOT_BLOCKS` (default 16384; with `<N>`, `max(N/4, 16)` at most)
and `N42_QMDB_HISTORY_BUDGET_MB` (default 512: delta bytes one request may replay or scan).

- **Where history starts.** A node that turns history on serves from its head at that start;
  lower heights answer `4444` with the earliest provable block. History from genesis means
  starting a fresh datadir with the flag set (or syncing one from genesis with it).
- **Crashes.** A stop between the `forest.log` append and history's is caught up at the next
  start from `forest.log` (it holds the same deltas). History that still does not reach the
  database head (it was off for a while, or `forest.log` was folded past the gap) restarts at the
  head, logged at ERROR with the new earliest block.
- **Branch switches.** A re-persisted height cuts the records from it and appends the new
  branch: heights below the fork stay provable, the replaced blocks answer `-32004` (not the
  block history holds). Only a persisted delta that itself rewinds the cursor (a multi-block
  delta across a branch switch, rare) makes the earlier heights whose state used the re-appended
  slots unprovable (`4444`, "rewound"); heights whose cursor lies at or below the rewind stay
  provable. A multi-block persistence (the delta fallback) makes the heights inside it
  unprovable.
- **Unwind / restart.** Records above the database head are cut at start and on `on_unwound`,
  and so are the cached leaf roots of the twigs re-appended from there. An offline
  `n42 stage unwind` does not work on a QMDB chain independently of history (the stock
  `MerkleUnwind` stage checks an MPT root; docs/BFT_RECOVERY_AUDIT.md) and leaves the database
  refusing to start; an EL that loses unpersisted blocks to a crash resumes from its database head.
- **Pruning.** `<N>` drops whole segments in the background once a newer snapshot lies at or
  below `head - N` (so between N and N plus two segments are kept); `all` never prunes.
- **Disk.** Per block: its delta (12 B frame + 41 B header + 9 B per retired slot), i.e. what
  `forest.log` writes, plus a 72 B index entry; per segment a snapshot of one bit per slot;
  `twigs.idx` 32 B per 2048 slots; `entries.log` is unchanged (history needs its dead records,
  which it keeps anyway with compaction off).
- **Memory.** Per segment one small entry; per cached snapshot one bit per slot plus 32 B per
  twig and the upper tree (at most two, plus the heights cached on them); per request the twigs
  its deltas touch.
- **Background work.** Snapshots, pruning and the leaf-root cache are written by one thread
  (`n42-qmdb-history`), never on the persistence path. The cache is built once after history is
  first turned on (O(state) hashing); until it covers a request's twigs, a request that would
  hash more than 1024 uncached twigs itself answers `-32001` (warming).
- **Flag absent.** Nothing is written or read; roots, on-disk format and the persistence path
  are unchanged (one `Option` check per persisted block).
