# Reducing the n42blockchain/reth fork

Dated 2026-08-25. Answers: of the N42 changes carried in the reth fork, which
*must* live inside reth, and which can move outside it as an independent crate
over reth's public API — the approach that removed this repo's
`crates/primitives-traits` fork by extracting `clique_utils`.

## First correction: the fork is smaller than its history suggests

The three N42 commits total ~880 lines, but **the largest is no longer in the
tree**. `d23dcc7dfc "proto: add n42 blake3 block root flag"` (398 lines, 18
files) was dropped in a later upstream merge — `n42_blake3_roots.rs` is gone and
no `n42_blake3` reference remains. Its own doc comment described it as
"Benchmark-only … exists only to quantify the serial root bottleneck", and the
commit was prefixed `proto:`. It was an experiment, and it has already lapsed.

What actually survives is **~440 lines across 7 files**, and it is one coherent
feature plus some instrumentation:

| File | markers |
|---|---|
| `crates/engine/tree/src/tree/payload_validator.rs` | 19 |
| `crates/evm/evm/src/lib.rs` | 7 |
| `crates/evm/evm/src/execute.rs` | 7 |
| `crates/ethereum/payload/src/lib.rs` | 4 |
| `crates/rpc/rpc-eth-types/src/utils.rs` | 2 |
| `crates/engine/tree/src/tree/state_root_strategy/mod.rs` | 2 |
| `crates/ethereum/payload/src/validator.rs` | 1 |

## Classification

### 1. Skip/defer the state root — **can leave the fork today**

The bulk of what remains: `N42_SKIP_STATE_ROOT` / `N42_DEFER_STATE_ROOT`, the
`prepare_n42_state_root_job` helper, and the branches that consult them in
`payload_validator.rs`.

This looks like it must be in-tree, because it changes what reth *does* rather
than what it offers. It does not, because **reth already ships the exact
extension point**:

```rust
// crates/engine/tree/src/tree/state_root_strategy/mod.rs
pub trait StateRootStrategy<N, P, Evm>: Send + Sync { … }
pub struct DefaultStateRootStrategy { … }

// crates/engine/tree/src/tree/payload_validator.rs
state_root_strategy: Arc<dyn StateRootStrategy<Evm::Primitives, P, Evm>>,

pub fn with_state_root_strategy(
    mut self,
    state_root_strategy: Arc<dyn StateRootStrategy<N, P, Evm>>,
) -> Self
```

The strategy is a trait object with a **public builder method to replace it**.
N42's skip/defer behaviour is a `StateRootStrategy` implementation in all but
name. The reason it is a fork is an accident of how it was written:
`prepare_n42_state_root_job` is `pub(crate)` and the call site branches on the
env vars *before* consulting the strategy, so it bypasses the very abstraction
it should be using.

**Action:** implement `StateRootStrategy` in an N42-side crate and install it
with `with_state_root_strategy(...)` at node construction. This is the same move
as `clique_utils`: the code is additive, so it belongs outside. Expect the fork
to lose its single largest remaining piece.

### 2. jit-off-by-default — **upstream it**

`449ecfdcef` drops `jit` from `reth-evm-ethereum`'s default features and adds
`#[cfg(not(feature = "jit"))]` stubs, because revmc needs an LLVM 22 toolchain
that Windows lacks.

Nothing about this is N42-specific: it is "make an optional backend actually
optional so platforms without LLVM 22 can build". It cannot be an external crate
(it changes reth's own feature defaults and adds cfg-gated stubs inside reth's
modules) but it is a clean upstream PR that benefits every Windows user.

**Action:** send it upstream. Carry it in the fork only until it merges.

### 3. Payload execution cache — **needs a hook that does not exist yet**

`crates/evm/evm/src/payload_cache.rs` (74 lines) plus its take/insert calls lets
`new_payload` reuse the leader's own execution output instead of re-executing.
The cache itself is a self-contained global and could live anywhere; the calls
that populate and consume it sit inside reth's build and validation paths, and
reth has no extension point there.

**Action:** this is the one piece that genuinely justifies a fork today. It is
also the one worth proposing upstream as a trait — something like an execution
-output cache the node can install — since "don't re-execute a block you just
built" is not an N42-specific desire.

### 4. `N42_*` tracing lines — **delete or fold into normal tracing**

`N42_PAYLOAD_CACHE_HIT`, `N42_NEW_PAYLOAD_EVM`, `N42_NEW_PAYLOAD_TOTAL`,
`N42_STATE_ROOT_SKIPPED`, `N42_FINISH_BREAKDOWN` and friends are `tracing` calls
with N42-prefixed messages. They carry no behaviour, and they collide on every
merge for nothing.

**Action:** drop them, or restate them through reth's existing metrics so they
stop being fork surface.

## Why this matters more than the line count

The expensive part of a fork is not its size, it is how often its lines sit next
to lines upstream is actively editing. Rebasing this repo's 16 vendored reth
crates onto 2.4.1 produced 23 conflicts — and **only two were real N42
behaviour**. The rest were edition-2021 let-chain de-sugaring, rustfmt
re-wrapping, copyright headers, and deleted upstream tests: noise that conflicts
every single merge and buys nothing.

The same discipline applies to the reth fork:

1. **Carry no formatting drift.** Match upstream's rustfmt exactly; never
   re-wrap a line you did not change.
2. **Do not add copyright headers to upstream files.** They guarantee a conflict
   on the first line of every file that ever moves.
3. **Never delete upstream tests.** A deleted test conflicts with every future
   edit to it, forever.
4. **Prefer additive files over inline edits.** A new module conflicts with
   nothing; a branch inside an upstream function conflicts with every refactor
   of that function.
5. **Use the extension point when one exists** — and when one does not, propose
   it upstream instead of branching inline.

Applying 1–4 alone would likely have made most of this repo's 23 conflicts
disappear. Applying 5 removes the fork's largest surviving piece outright.
