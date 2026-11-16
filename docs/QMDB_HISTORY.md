# QMDB history: verifiable state proofs at past heights

Status: implemented behind `N42_QMDB_HISTORY` (off by default), 2026-11-16.

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
membership only (non-existence proofs need a format change, out of scope).

`n42_proofWindow()` reports `{history, mode, earliest, latest, broken}`.

On a QMDB chain `eth_getProof` (http/ws/ipc and the auth port) is refused with code `-32004`
naming `n42_getProof`: the Merkle-Patricia trie is not maintained there, so its proofs never
verified against a QMDB header. `mobile_getProof` proves only at the head; a third param other
than `"latest"` is refused with `-32005`.

Errors: `4444` the block is below the earliest provable one (pruned, never kept, or below a
rewind); `-32001` not persisted yet / root not yet carried by a persisted header / key changed
after the history head (retry); `-32004` history off, block not recorded (inside a multi-block
persistence span), lookup budget; `-32603` the rebuilt root disagrees with the header (never a
proof) or a history file is unreadable.

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
the active bits. History keeps, under `<datadir>/qmdb/history/`:

| file | content |
|---|---|
| `base.ckpt` | `ForestCheckpoint` (cursor + active bits) of the earliest kept block |
| `spans.log` | each persisted block's file-mode `ForestDelta` (cursor, retired slots), framed like `forest.log` |
| `twigs.idx` | leaf root of every full twig (32 B a twig): a cache, rebuilt from `entries.log` when a root disagrees |

The prover keeps the history head in memory (active bits, twig roots, upper tree). For block N:
twigs no later block touched keep the head's roots; a touched twig gets its bits at N (later
retirements undone, slots at or past N's cursor cleared) and its frozen leaf root (the youngest,
partial twig re-folded from `entries.log`); the upper tree is the head's with those leaves
replaced and their ancestors rehashed, read at N's power-of-two capacity. The root is compared
with the anchor header's `stateRoot` before any proof is cut; each proof is verified against it.

A key's slot at N: the live index's slot when it is below N's cursor and live at N; else its
latest append at or before N (a block's appended run is in key order: binary search); else from
genesis (the alloc, in key order) or the first retirement after N. Every candidate is checked
(the record holds the key, the bit at N is set). The live index probe is the one forest-lock
access (a hash-table lookup; it never moves the tree). Entry records are read with positional
reads at the offsets the tree publishes lock-free; nothing is mapped.

## Operating it

`N42_QMDB_HISTORY=<blocks>|all|off` (see `docs/KNOBS.md`). Requirements, refused at start-up
otherwise: `N42_QMDB_ENTRY_FILE=1`; `N42_QMDB_COMPACT` off (compaction punches the dead records
past heights read).

- **Where history starts.** A node that turns history on serves from its head at that start;
  lower heights answer `4444` with the earliest provable block. History from genesis means
  starting a fresh datadir with the flag set (or syncing one from genesis with it).
- **Gaps.** History that does not reach the database head at start (it was off for a while, or a
  record was lost) is discarded and restarts at the head, logged at ERROR with the new earliest
  block. A multi-block persistence (rare: a branch switch or the delta fallback) makes the heights
  inside it unprovable; a rewind of persisted state makes the heights below it unprovable.
- **Unwind / restart.** Records above the database head are cut at start, and on `on_unwound`.
  An offline `n42 stage unwind` does not work on a QMDB chain independently of history (the stock
  `MerkleUnwind` stage checks an MPT root; docs/BFT_RECOVERY_AUDIT.md) and leaves the database
  refusing to start; an EL that loses unpersisted blocks to a crash resumes from its database head.
- **Pruning.** `<blocks>` folds the oldest records into `base.ckpt` once a quarter more (at least
  16) has accumulated; `all` never prunes.
- **Disk.** Per block: its delta (12 B frame + 41 B header + 9 B per retired slot), i.e. what
  `forest.log` writes; `base.ckpt` is one bit per slot; `twigs.idx` 32 B per 2048 slots;
  `entries.log` is unchanged (history needs its dead records, which it keeps anyway with
  compaction off).
- **Memory.** The prover's head cache: one bit per slot plus 32 B per twig and the upper tree,
  built on the first request (O(state) hashing once when `twigs.idx` is cold).
- **Flag absent.** Nothing is written or read; roots, on-disk format and the persistence path
  are unchanged (one `Option` check per persisted block).
