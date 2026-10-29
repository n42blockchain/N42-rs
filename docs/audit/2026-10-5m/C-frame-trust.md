# Area C -- frame attestation trust model and supply path (raw review, at c4064f700)

Scope: `crates/n42/tx-types`, `tx-ingest`, `tx-queue` (admission), the frame/description paths of
`engine-types` and `bin/n42`, and their changes since 91a360b57. Plan: `docs/PLAN_5M_AUDIT.md`.

## Trust model as implemented (reviewer)

**Default** (`N42_INGEST_VERIFY` unset = `all`; no gateways; with or without `N42_FRAME_BLOCKS`):
every node checks every signature itself -- at ingest (ecrecover, or Ed25519 in batches with a
per-signature fallback) and on the fill, whole-body, conversion and import paths on any cache miss.
The 0x50 sender cache is keyed by the hash of the full encoded transaction, signature included, and in
this mode is written only after a successful verification. The leader is trusted for nothing about
transactions: a frame id is the follower's own ingest-computed root; frames it lacks come in the fill,
which it decodes and verifies; the frame tree (or MPT root) is recomputed over its own copies and
compared with the header; repeated frames or transactions are refused; an includability check (chain
id, fee, intrinsic gas, nonce chaining, balance) runs before the vote, execution after. The ingest binds
loopback unless `*_ALLOW_REMOTE=1`; `leader` and `shard` need `N42_BENCH_UNSAFE=1`.

**X22 bench** (`N42_FRAME_GATEWAYS=<key from seed:n42-bench-gateway>`, `N42_FRAME_ATTEST_MIN=1`):
every node trusts any process that can sign with that key, which anyone can derive from the public seed
and which reaches the node over loopback. For a frame with a valid attestation, 0x50 transactions are
admitted under the sender derived from their public key with no signature check, and that sender goes
into the global cache; from then on the vote road, payload conversion, fill and import read the cache
as the answer, so nothing in the cluster verifies those Ed25519 signatures. secp256k1 transactions in
attested frames are still recovered and verified. The leader's power is unchanged. The attestation
binds `keccak("n42-frame-attest" || chain_id || frame_root)`, is counted per distinct configured key, and
is checked with `verify_strict`.

## Findings

| id | sev | file:line | title | trigger | impact | suggested fix (hot path?) | conf. |
|---|---|---|---|---|---|---|---|
| C-1 | P1 | `engine-types/src/frame_blocks.rs:679-684` -> `630-639`; `engine_validator/by_description.rs:446`; `bin/n42/src/payload_serve.rs:1709-1712, 1756-1763`; `frame_blocks.rs:1050` | A peer's unchecked frame layout poisons the table the node describes its own blocks from | `describe_frames` calls `remember_claimed` before any check, filing the claimed layout under the header's root in `LAYOUTS`; the first filing wins (test `frame_blocks.rs:1466-1471`). A Byzantine leader proposes body B (root R) and sends every follower a description with a wrong layout L' (held frames, counts summing to \|B\|); B fails. When an honest leader later seals the same B (same frames queued, same order and gas cut), `seal_root_timed`'s `remember_layout(R, correct)` is a no-op, and `payload_serve` describes B with L' unverified; under `N42_ANSWER_LAYOUT_ONLY` (adopted) the hash list is omitted. Followers compute the frame tree over L', mismatch, return `CompactBodyError::Invalid`. | Liveness only: honest leaders' views keep failing while B is rebuilt and R is among the last 64 roots. Safety holds (the root binding refuses). | Keep claimed layouts in a separate table only `root_for_body` reads, or let the own-seal filing overwrite; optionally check `layout.sum == tx_count` and ids against the build plan in `payload_serve`. Cold: one mutex op per block. | Mechanism high; exploitability medium; driver handling of `Invalid` not read |
| C-2 | P2 | `bin/n42/src/main.rs:76-87`; `tx-types/src/frame.rs:266-276`; `tx-ingest/src/lib.rs:2163-2179` | Attested frames trust more than `leader` mode but are not behind `N42_BENCH_UNSAFE` | `N42_FRAME_GATEWAYS` alone (min defaults to 1) turns it on with only a start-up warning. With the X22 key (secret derivable from the public seed) any local process can admit 0x50 transactions from any account whose public key is known, with garbage signatures; every node caches and votes on them. Attested 0x50s also skip the shape checks (`ed25519_key`: algorithm, key length, weak key) before the cache insert. | Bench-only by design and the production default is safe, but copying the X22 line to production silently allows sender forgery; same shape the previous audit gated for `shard`; nothing enforces f+1. | Refuse gateways without `N42_BENCH_UNSAFE=1` at start-up (at least while min < 2, or until a product trust root exists): zero cost. Optionally `ed25519_key()` in the attested branch (one key-cache lookup per attested 0x50: attested hot path). | High |
| C-3 | P2 | `tx-ingest/src/lib.rs:1859-1874`; `main.rs:83-87` | `N42_TX_INGEST_DIRECT` (`unsafe-bench`) is not gated | It sets the queue's frame admission (`push_frame`) apart from pool validation: chain id, fee, balance, size. Signatures still verified. | No consensus break (builder execution and the followers' includability check catch invalid ones); the queue can be filled with junk from loopback. | Add it to the `N42_BENCH_UNSAFE` gate; start-up only. | High |
| C-4 | P2 | `scripts/fleet7-env.sh:160-161` | The launcher exports `N42_BENCH_UNSAFE=1` automatically for `leader`/`shard` | Any fleet launch in a trusting mode. | The acknowledgement becomes implicit in bench runs. | Require it explicitly on the leg line. | High |

## Checked and sound (reviewer)

- Attestation: message = domain + chain id + frame root (`frame.rs:163-169`); keys de-duplicated (`frame.rs:228-238`); distinct gateways counted with `verify_strict`, stopping at the minimum (`frame.rs:291-317`); at most 16 read and kept only if gateways are trusted (`tx-ingest/src/lib.rs:1454-1469`); root computed locally from decoded hashes, whole frames only, duplicates refused before the attestation is considered (`lib.rs:1983-1998, 2012-2038`); replay on another frame fails, on another chain is harmless.
- 0x50 sender always derived from the key; a disagreeing wire claim drops the transaction (`lib.rs:2202-2215`).
- Ed25519 batch: a failed batch is re-verified per signature (`alt_sig.rs:374-408`); the merged equation is stricter than dalek's and a strict failure falls back to cofactored singles; transcript binds R, A, M, s (`alt_sig.rs:432-494`); non-canonical scalars and weak keys rejected (`alt_sig.rs:350-364, 177-193`).
- Sender cache key = keccak of the full encoding (`alt_sig.rs:225-228, 306-325`); `fixed_cache` compares the full key; default-mode inserts all follow a verification (`engine_validator.rs:262-272`, `n42_evm.rs:322-326`, `follower_import.rs:2390-2395`, `lib.rs:2306-2311`); `new_unchecked` only for local storage (`compact.rs:85`).
- Mode gates: `leader`/`shard` need the acknowledgement, parsed the same everywhere (`main.rs:67-82`, `sender_cache.rs:103-108, 157-214`); trusting modes never bind off loopback (`lib.rs:172-181, 1240-1253`); in `leader` mode queue senders become re-verified claims and the by-reference road is off (`follower_import.rs:2196-2202, 2284-2287, 2331-2337`).
- Byzantine leader on the description road: assembled from the follower's own frames, frame tree compared with the header, repeats refused (`by_description.rs:451-656`); missing positions come from the verified fill (`engine_validator.rs:634-685`); decode sizes bounded (`compact_body.rs:229-250`); cross-frame repeats caught by the nonce fold and `check_senders` (`follower_import.rs:1273-1310, 1369`); ingest summaries stand in only when positions were taken whole and lengths/senders match (`follower_import.rs:1121-1127`).
- Duplicate rejection on every path: ingest `lib.rs:1988`, description `by_description.rs:649`, whole body / range import / conversion via `root_for_body` (`frame_blocks.rs:1103-1131`); the hash road uses the MPT root.
- Frame index fed only from the ingest's `NewFrame`; `take_frames` checks each hash (`tx-queue lib.rs:2873-2880`). Fast transfer path checks chain id and nonce (`fast_transfer.rs:485, 532`).
- Changes since 91a360b57 weaken no check.

## Not covered (reviewer)

The h2-execution driver's reaction to `CompactBodyError::Invalid` vs `Missing` (C-1's impact);
`claimed_build`, `parallel_transfer` graft internals; road admission in depth; the pool validation DIRECT
skips; whether `N42_INGEST_VERIFY` is set on X22 legs. Nothing built or run.

## Verification

| id | verdict | note |
|---|---|---|
| C-1 | confirmed (mechanism) | `remember_claimed` (679-684) calls `remember_verified` -> `remember_layout`, which keeps the first filing for a root (630-639); `layout_by_root` serves the node's own descriptions from the same table. Exploitability (an honest leader rebuilding the same root) not shown. |
| C-2 | confirmed; P2 | The only gate, `trusting_mode_refusal` (`main.rs:76-82`, `sender_cache.rs:200-214`), covers `leader`/`shard`; `N42_FRAME_GATEWAYS` only produces a warning (`main.rs:83-87, 136-138`). The attested branch caches `alt_tx.sender()` without `ed25519_key()` (`tx-ingest/src/lib.rs:2163-2179`, `alt_sig.rs:169-193`). A gate needs `fleet7-env.sh` to acknowledge gateway legs too. |
| C-3 | confirmed; P2 | `setup.direct` sends the frame through `push_frame` and returns before `pool.add_transactions` (`lib.rs:1859-1874`); only a warning (`main.rs:85`); the hard gate is the off-loopback bind refusal (`lib.rs:1240-1253`). `KNOBS.md:233` says "presence only (`=0` still counts)", but the code reads it with `n42_env::flag` (`lib.rs:456`): the doc is stale. |
| C-4 | confirmed; P2 | `fleet7-env.sh:160-162` exports `N42_BENCH_UNSAFE=1` whenever `N42_INGEST_VERIFY` is leader or shard. |
