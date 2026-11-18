# Mobile proof budget (measured)

Status: 2026-11-18, branch `docs/proof-budget-and-trust` (n42-rs `main` 2a512ef7a + this work).
Question: where does a phone's budget go when it follows the chain and reads state: bytes on the
wire, verification CPU, and memory, each measured on its own. **Every CPU number below is a server
number. The phone factor is unknown: nothing here ran on a phone.** Byte counts and allocation
counts do not depend on the CPU and carry over as they are.

## How it was measured

`crates/n42/mobile-verify/examples/proof_budget.rs`:

```text
cargo build --release -p n42-mobile-verify --example proof_budget
taskset -c 2 target/release/examples/proof_budget <accounts> 20000
```

- Host: AMD EPYC 9B45 (server, 128 cores, up to 4.1 GHz), one thread pinned to CPU 2, release
  profile, box quiet (run through `quiet-run.sh`). Logs:
  `/data/n42-build/audit-notes/ci/proofs-budget-1m.log`, `.../proofs-budget-10m.log`.
- State: an in-memory `QmdbCompatTree` (the node's QMDB tree) in gov5's leaf encoding. Two shapes:
  - **1M**: 1,000,000 accounts (10,000 contracts with a code hash), 500,000 storage slots over the
    contracts, then 250,000 account rewrites: 1.5M live keys, 1.75M slots below the cursor (854
    twigs).
  - **10M**: 10M accounts, 5M slots, 2.5M rewrites: 15M live keys, 17.5M slots (8,545 twigs).
- Proofs: `QmdbCompatTree::prove` (what `n42_getProof` / `mobile_getProof` serve) encoded in
  gov5's v2 layout; the phone side is `QmdbProof::decode` + `verify_for_key`, timed per proof over
  20,000 random keys per series. "Past height": proofs cut after the load and before the rewrites,
  verified against the root of that moment. `history.rs` rebuilds exactly that tree for a past
  block and serves the same layout; the run does not go through `history.rs` (it needs a node).
- Allocation: a counting global allocator; "peak" = most bytes live during one decode + verify,
  maximum over the series.
- Finality: an H2-v4 `Decide` (what `mobile_finality` serves) over a seven-key validator set (the
  fleet7 genesis `hotstuff.validators`), f = 2, quorum 5; `decode_envelope` +
  `verify_h2_v4_decide`, 300 runs. Header: the gov5 header RLP fixture
  `crates/n42/h2-consensus/testdata/header_field_parity/gov5_header_bal22_slot23_root24.rlp`
  (the other two fixtures are 851 and 852 B).

## Results

### State proofs (QMDB v2 membership)

| series | shape | bytes (min / median / max) | upper path | verify median / p99 (us, server) | peak alloc |
|---|---|---|---|---|---|
| account, head | 1M | 984 / 988 / 1,023 | 10 | 2.72 / 2.84 | 368 B |
| storage slot, head | 1M | 1,007 | 10 | 2.80 / 2.91 | 352 B |
| account, past height | 1M | 984 / 988 / 1,023 | 10 | 2.72 / 2.84 | 368 B |
| storage slot, past height | 1M | 1,007 | 10 | 2.80 / 2.90 | 352 B |
| account, head | 10M | 1,112 / 1,116 / 1,151 | 14 | 3.12 / 3.25 | 496 B |
| storage slot, head | 10M | 1,135 | 14 | 3.20 / 3.32 | 480 B |
| account, past height | 10M | 1,080 / 1,084 / 1,119 | 13 | 3.02 / 3.15 | 464 B |
| storage slot, past height | 10M | 1,103 | 13 | 3.10 / 3.20 | 448 B |

Exclusion: **not measurable, the format has none.** QMDB v2 proves membership only; for an absent
key `prove` returns nothing and the RPCs answer `found: false` on the node's word
(`docs/PROOF_TRUST_INVENTORY.md`, gap 2).

A proof is `655 + 32 x upper + value` bytes: version 1, key 32, slot 8, twig height 1, twig path
11 x 32 = 352, active bits 256, upper length 1, value length 4. `upper` = ceil(log2(twigs)), one
level per doubling of the slots ever appended (live or dead); a past height is at most one level
shorter. Values: an account 9-48 B in gov5's encoding, a slot 32 B.

### Finality (what a phone checks before it trusts a root)

| item | bytes | verify median / p99 (us, server) | peak alloc |
|---|---|---|---|
| `Decide` envelope, 7 validators, 5 signers (quorum) | 287 (snappy gossip 162) | 847 / 852 | 8,633 B |
| `Decide` envelope, 7 validators, 7 signers | 287 (snappy 162) | 848 / 857 | 4,363 B |
| gov5 header RLP (binds the decided hash to `stateRoot`) | 851-884 | keccak 1.86 / 1.88 | n/a |
| for scale: one BLS aggregate over 512 keys (fleet7 `committeeSize`) | 96 sig (+ 24,576 if the keys were shipped) | 1,010 / 1,014 | n/a |

The 512-key row is not part of a phone's step: the committee evidence is derived from a public
seed and is not a root of trust (inventory row 10). It shows that verify cost is dominated by the
pairing, not by the key count (512 keys cost ~1.2x the whole 5-signer `Decide` check).

## What one phone step downloads

Raw bytes, before transport framing; JSON-RPC hex roughly doubles them (`mobile_finality`'s
`decideEnvelope` and the proof fields are hex strings).

- **Per block followed:** one `Decide` (287 B, 162 snappy) + one header (851-884 B) = **~1.15 KB**,
  ~0.85 ms server CPU (one aggregate BLS verify; the header hash is noise). Under deferred
  execution the root of block N sits in a later anchor header, which the phone follows anyway.
- **Per account read:** one proof, **~1.0 KB at 1M accounts, ~1.1 KB at 10M**, ~3 us server CPU,
  under 0.5 KB allocated. An account plus one storage slot: ~2.0-2.25 KB.
- **Per read on a block the phone does not yet trust:** add the block step above: ~2.2 KB and the
  BLS verify.

## Largest contributors

1. **BLS aggregate verification of the `Decide`**: ~0.85 ms server time, about 300 times one state
   proof's verify. It is paid once per followed block, not per read.
2. **The twig path** (352 B fixed, 11 levels) plus **the active-bits bitmap** (256 B fixed): 608 B
   of every state proof, 54-62 % of it, independent of state size.
3. **The upper path**: 32 B per doubling of the slot count, 320 B at 1.75M slots and 448 B at 17.5M
   (32-40 % of a proof); it grows with every slot ever appended, dead or live.

Not measured: anything on a phone (CPU factor, radio cost), the StreamPacket re-execution path
(its read log carries no proofs, inventory row 5), and transport overhead beyond the hex note.
