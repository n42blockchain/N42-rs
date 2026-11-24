# N42 native chain: mixed block production standard (DRAFT)

Status: draft for the owner, 2026-11-23. Read-only research; nothing in any repository was changed.
Scope is wider than the sync standard (`/data/blockchain/wr-logs/qs-scratch/sync/N42-SYNC-SPEC.md`,
"SYNC" below, owner-approved 2026-11-22): this document covers everything three clients must share to
**produce, vote on, import and finalise each other's blocks on one chain**. Where SYNC already rules,
this document cites its section and does not restate it.

## Revisions read

| Client | Tree read | Notes |
| --- | --- | --- |
| gov5 (reference) | `main` = `47e219a1` (2026-11-23), spot-checked by `git grep`/`git show`; the bulk inventory was read in the checkout at `641d5153` (`qs/block-time-budget`, 2026-11-02) | Line numbers marked `~` come from `641d5153` and may have drifted on main. Branches **not** in main: `fix/native-conformance-2026-11` (D3/D4), `feat/hotstuff-rotate-on-timeout` (52f31056), `integ/mvdev-slot`, `integ/mvdev-native-no-8282`. `qs/5m-int` (577b8dc1) is the bench line, with env-driven rules main does not have. |
| n42-rs | `main` = `3c25a2381` at `/data/n42-build/wt-docs` | `fix/conformance-decisions` is merged. |
| n42-26 | `main` = `5847275` (2026-11-03); tenure checked on `feat/native-port` 1b51564 and `upgrade/reth-v2.11.0` 22eb8bb | Read less deeply (one pass by a subagent, key claims spot-checked). |

Path abbreviations: gov5 `HS/` = `internal/consensus/hotstuff/`, `cfg` = `params/config.go`;
n42-rs paths are under `crates/n42/` unless they start with `crates/` or `bin/`;
n42-26 `C/` = `crates/`, `main.rs` = `bin/n42-node/src/main.rs`.

Verdict codes, one per inventory item:
**[AP]** agreed + proven (fixture with SHA, test vector, or a mixed round with equal hashes);
**[AU]** agreed + unproven (all implement the same rule, no cross-client evidence);
**[DIFF]** differs (described);
**[UNDEF]** nobody specified it, or only one client has a rule.

---

## 0. Scope, terms, conformance, change process

### 0.1 Scope

- Applies to an N42-native chain: genesis `config.consensus = "hotstuff"`, `config.stateScheme = "qmdb"`,
  with a `config.hotstuff` object. APoS/Clique chains and gov5's `eth-el` mode are out of scope.
- A **mixed network** is one whose validator set has members running more than one client. Every rule
  marked MUST below applies to every member of a mixed network. Rules marked "single-client only" MAY be
  used only when every validator runs the same client (and are then outside this standard).
- Out of scope: throughput, local scheduling, storage layout, anything that never crosses the wire or the
  header.

### 0.2 Terms

- **Chainspec**: the genesis JSON (`config` + `alloc` + header fields). The only permitted source of a
  consensus-visible value (rule 0.4.1).
- **Consensus-visible**: changes a block hash, a state/receipts root, a signature message, a QC/TC, the
  view sequence, the leader of a view, or the validity of any of these.
- **Leader / tenure T / view v / epoch length E**: as in SYNC §10 (`leader(v) = (v / max(T,1)) % n`).
- **Deferred execution depth k**: header N carries the execution result of block N-k.
- **H2-v4 profile**: chain-bound BLS signing (`"N42H2V4" ‖ phase ‖ chainId ‖ genesisHash ‖ view ‖ …`, POP DST).
  **Legacy profile**: gov5's pre-v4 messages (`view ‖ hash`, `"commit" ‖ …`), what chain 94 runs.

### 0.3 How conformance is shown

A client conforms to an item when it has at least one of:

1. **Fixture**: a byte-exact file produced by gov5's code, checked in each client's `testdata/` and pinned by
   SHA-256 of the raw bytes (never text-mode comparison).
2. **Vector**: a table of inputs/outputs in this document or SYNC (e.g. SYNC §10.4), run as a unit test in
   every client.
3. **Mixed round**: a recorded run on a shared genesis with at least one member of each client involved,
   where every client reports the same head hash and the same hash at every height, zero import errors, and
   each client both led and followed. A round counts for the items its traffic exercised, nothing else.

### 0.4 Change process (normative)

1. A consensus-visible value MUST come from the chainspec. An environment variable or CLI flag MAY override it
   only as a declared bench override (single-client only) and MUST NOT be the only source.
2. A consensus-visible change MUST activate at one point on all clients: a genesis `config` field holding a
   **timestamp** (`<name>Time`, compared with the header's timestamp) or, for pacemaker/view rules only, a
   **view** (`<name>View`, as `rotateOnTimeoutView`, SYNC §10.3). Block-number activations SHOULD NOT be
   introduced (reth's chainspec cannot express a block-number fork after Paris; see A4).
3. Absent = disabled = exact pre-change behaviour. A client that does not implement a rule MUST refuse to
   start on a chainspec that activates it (fail closed), rather than ignore the field.
4. Activation on a running chain: choose a point safely ahead, roll every member's chainspec and binary
   before it, verify with a mixed round on a copy of the chainspec with the point at 0.
5. Every change ships with (a) a fixture or vector, (b) a row in this document, (c) a mixed round.

Today rule 0.4.3 is broken everywhere: n42-rs ignores unknown `hotstuff` fields on purpose
(`qmdb-reth/src/hotstuff.rs:33-37`), and n42-26 reads almost nothing from the chainspec (A2). This is the
single most important structural fix (see section 2, R1).

---

## 1. Inventory

Format of each item: **Rule** (as it should read) / status per client (implementation, value source,
evidence) / verdict.

### (a) Chain configuration and genesis

**A1. Chain id, genesis hash, fork digest.**
Rule: `chainId` and the genesis hash MUST come from the chainspec; fork digest = `genesisHash[0:4]`
(SYNC §3.1).
- gov5: chainspec; genesis hash recorded in `cfg`. 
- n42-rs: chainspec; genesis header built by `crates/chainspec/src/qmdb.rs:307` `genesis_header` with the
  QMDB root (`:293`). Chain 94/95 hashes reproduced (`crates/chainspec/res/genesis/gov5/README.md`:
  `0xa2d2ff5d…be99`, `0xb0ff0c04…5271`).
- n42-26: `chainId` overridden by env `N42_CHAIN_ID` (default constant 4242, `C/n42-chainspec/src/lib.rs:288,300`);
  `N42_INTEROP_GENESIS_HASH` env (`main.rs:1404`) supplies the hash used in signing.
- Evidence: every `devnet-fleet.sh --gov5` round (equal hashes from block 0); chain 94 three-client soak
  (n42-26 `docs/chain94-three-client-soak-20261012.md` "2026-10-14 独占窗口最终结果", runs 114/115).
Verdict: **[DIFF]** (n42-26 takes both from env; agreed in value when the operator sets them, proven on chain 94).

**A2. Where HotStuff parameters come from.**
Rule: every value in `config.hotstuff` (A13-A22) MUST be read from the chainspec by every client.
- gov5: `cfg:~529-591` `HotStuffConfig`, wired in `HS/adapter.go:~150-321`.
- n42-rs: `qmdb-reth/src/hotstuff.rs:41-94` `HotStuffGenesisConfig` (chainspec).
- n42-26: a separate consensus-config file named by env `N42_CONSENSUS_CONFIG` (`main.rs:1277-1285`;
  struct `C/n42-chainspec/src/lib.rs:14-39`), else dev mode from `N42_VALIDATOR_COUNT`; reads only
  `hotstuff.committeePool`, `devBlockReward`, `devFaucetAddress` from genesis.
Verdict: **[DIFF]**.

**A3. Validator set and its order.**
Rule: `hotstuff.validators[] = {address, blsKey}`; list order is the QC bitmap order and the leader index;
`f = ⌊(n-1)/3⌋`, quorum `2f+1`.
- gov5: `HS/adapter.go:~261-306` (n<4 warns).
- n42-rs: `qmdb-reth/src/hotstuff.rs:24-31,68-70`.
- n42-26: `initial_validators` in the consensus-config file (env A2); genesis `validators` only written by
  `bin/n42-node/src/native_fleet_main.rs:213-217`, never read.
- Evidence: devnet `--gov5` rounds (4 validators); chain 94 soak (7, quorum 5).
Verdict: **[DIFF]** in source (n42-26), value agreed and proven.

**A4. Fork schedule.**
Rule: every Ethereum fork a native chain activates MUST be a timestamp field in `config`. gov5-only forks
(`eofTime`, `ltHashTime`, `beijingBlock`, `balTime`, `mobileAnchorTime`, `glamsterdamTime`,
`deferredExecutionTime`, `unchangedAccountNoOpTime`) MUST each be either implemented by every client or
refused at start-up by a client that lacks it.
- gov5: `cfg` (Glamsterdam `:245`, BAL `:305`, MobileAnchor `:312`, deferred `:340`, unchanged-account `:363`).
  Chains 94/95 carry `shanghaiBlock`/`cancunBlock` and `eofTime` 1765238400 (EOF active, `internal/vm/eof.go`).
- n42-rs: reth hardforks by timestamp; block-number forks need `n42-gov5-genesis --fork-time`
  (`res/genesis/gov5/README.md`); `eofTime`, `ltHashTime` carried inert (`docs/N42_26_PORT.md:1176-1182`);
  no EOF.
- n42-26: forces `cancun_activated()` (`C/n42-chainspec/src/lib.rs:435-447`); Prague from env
  `N42_GOV5_PRAGUE_TIME` (`main.rs:215-228`); Glamsterdam/MobileAnchor not read.
- Evidence: devnet genesis (all forks at 0, no EOF) proven by every `--gov5` round; chain 94 soak.
Verdict: **[DIFF]**: EOF on chain 94 has no Rust implementation (a chain-94 block with EOF code would fork
the Rust clients — not observed); n42-26 env-sourced Prague.

**A5. State scheme.**
Rule: `stateScheme = "qmdb"`; every client MUST compute the QMDB root (D8).
- gov5: `cfg:346`. n42-rs: `crates/chainspec/src/qmdb.rs:22-40`. n42-26: QMDB execution by env
  `N42_GOV5_QMDB_EXECUTION` (`main.rs:1471`); a native producer refuses trusted-root mode (`main.rs:3253-3255`).
Verdict: **[DIFF]** (n42-26 env), value proven (devnet rounds, chain 94 soak).

**A6. Genesis state root and header.**
Rule: genesis header = gov5's genesis block fields with `stateRoot` = QMDB root of the alloc
(`twig_core::qmdb_compat` key derivation and account encoding).
- gov5: reference. n42-rs: `qmdb.rs:293-307`; chain 94/95 hashes reproduced (README). n42-26: unverified.
Verdict: **[AP]** gov5/n42-rs; n42-26 unverified (it ran chain 94 from gov5 data, not from a genesis it built).

**A7. Alloc validity (Q-S1).**
Rule: an alloc entry with nonce 0, balance 0, empty code and non-empty storage is a config error (owner
decision 2026-11-22).
- gov5: done in main (`8eaae4f9`, handoff 2026-11-22). n42-rs: **not found** (`grep` for the rule finds
  nothing). n42-26: not found (unverified).
Verdict: **[DIFF]** (latent: no shipped genesis has such an entry).

**A8. Dev block reward and faucet.**
Rule: `hotstuff.devBlockReward` (wei) credited to the coinbase and, if `devFaucetAddress` is set, to it as
well, every block; state-root relevant.
- gov5: `cfg:565-572`, `Finalize`. n42-rs: `hotstuff.rs:78-82`. n42-26: genesis, `C/n42-node/src/sinks/mod.rs:26-57`.
- Evidence: every devnet `--gov5` round runs with 1 ETH reward; chain 94 soak.
Verdict: **[AP]**.

**A9. Unchanged-account rule (R3-E2).**
Rule: a touched account re-written with an unchanged value MUST NOT be written to QMDB (QMDB is
positional: a rewrite moves the root). Activated by `config.unchangedAccountNoOpTime`.
- gov5 main: implemented, gated by `unchangedAccountNoOpTime` (`cfg:363`, `internal/blockchain.go:2282`,
  `internal/miner/worker.go:1761`); absent = old rule (write it).
- n42-rs: always the new rule; the field is ignored (`docs/audit/2026-10-5m/R3_E2.md`). **None of the n42-rs
  genesis files sets the field** (`n42_devnet*.json`, `n42_fleet7*.json`).
- n42-26: unverified.
- Evidence of the divergence: R3_E2.md zero-fee legs (mixed devnet). Latent on today's devnet because the
  reward always changes the coinbase; a zero-value transfer to an untouched existing account still triggers it.
Verdict: **[DIFF] — consensus fork today** on any chain whose genesis lacks the field.

**A10. Deferred execution and depth.**
Rule: `deferredExecutionTime` (timestamp) turns it on; `deferredExecutionDepth` k in genesis (absent = 1);
header N carries `stateRoot`, `receiptsRoot`, `logsBloom`, `gasUsed` of block N-k.
- gov5 main: k = 1 only, `cfg:340`, `internal/deferred_execution.go:~26-65`. gov5 `qs/5m-int`: k from env
  `N42_DEFERRED_DEPTH` / `_FROM` / `_PREV` (`common/block/deferred_lag.go:25-75`, max 8, per-height boundary rule).
- n42-rs: genesis `deferredExecutionDepth` 1..2, depth > 1 only from genesis (`crates/chainspec/src/qmdb.rs:179-290`);
  check `engine-types/src/hotstuff_consensus.rs:381-407`.
- n42-26: not implemented (devlog-146/147; import-gated votes instead).
- Evidence: n42-rs `docs/DEFERRED_DEPTH_2_DESIGN.md:538-539` says a mixed fleet at depth 1 was measured in PD;
  record not re-read here.
Verdict: **[DIFF]** (gov5 bench line env vs n42-rs genesis; different transition semantics; n42-26 absent).

**A11. 0x50 AltSig transactions.**
Rule (proposed): `config.altSigTx = true` admits type 0x50 (`docs/spec/N42_TX_0x50.md`); a client without it
MUST refuse to start on such a chain.
- gov5: not implemented (no `altSigTx`, no 0x50 decoder at main). n42-rs: `crates/chainspec/src/qmdb.rs:54-66`,
  `crates/n42/tx-types`. n42-26: type implemented (`C/n42-tx-types/src/lib.rs:84,212-217`), genesis flag not read.
- Evidence: shared vectors `tx-types/testdata/altsig_vectors.json` exist in n42-rs and n42-26 (SHA not compared here).
Verdict: **[DIFF]**: a mixed network with gov5 MUST NOT set `altSigTx` (spec `N42_TX_0x50.md:111`).

**A12. Frame blocks.**
Rule (proposed): single-client only until one design is agreed.
- gov5 `qs/5m-int`: env `N42_FRAME_BLOCKS` (`internal/frame_blocks.go:48-49`): body carries frame hashes, resolved by
  FRQ1 pulls; also `N42_VOTE_ON_AVAILABILITY`.
- n42-rs: genesis `frameBlocks` (`qmdb.rs:72-85`): transactions root = frame-tree root.
- n42-26: env `N42_FRAME_BLOCKS` (`C/n42-tx-types/src/frame.rs:91,246`).
Verdict: **[DIFF]** (three incompatible designs; two env-sourced).

**A13. `twoPhaseVoteGate`.**
Rule: from genesis; when true Round-1 votes fire on static validation and the CommitVote waits for the import.
A client MAY stay import-gated on Round 1 (stricter, compatible).
- gov5: `cfg:585`, `HS/adapter.go:246`, `HS/proposal.go:~295-395`. n42-rs: `hotstuff.rs:88-93` (commit vote held,
  Round 1 still import-gated). n42-26: not read (gov5 profiles import-gated, `C/n42-consensus/src/protocol/proposal.rs:420-441`).
- Chain 94 runs it **true**. Evidence: gov5-only devnet shapes incl. the gate (memory, audit 10-30); no mixed
  round with the gate on found.
Verdict: **[DIFF]** in source (n42-26), behaviour compatible; unproven mixed.

**A14. Signing profile (`interopV4`).**
Rule: per SYNC §3.1, a mixed network MUST run H2-v4. (Open decision O2: chain 94 runs the legacy profile.)
- gov5: `cfg:590`, `HS/adapter.go:321` `EnableH2V4`; domains `HS/interop_v4.go:13-56`, legacy `HS/types.go:224-256`.
- n42-rs: genesis `interopV4`; profiles Native / H2V4 / Gov5Legacy (`h2-consensus/src/protocol/quorum.rs:62-95`).
- n42-26: env `N42_GOV5_LEGACY_SIGNING=1` (`main.rs:3293-3298`), default H2-v4; same three profiles
  (`C/n42-consensus/src/protocol/quorum.rs:20-32,165-178`).
- Evidence: fixtures `h2_v4_domains_v1.json` SHA `f3f20d46…9510`, `h2_v4_envelope_v1.json` `09a98f54…ff83`,
  `cross_client_h2_v1.json` `0c587743…2aee` (n42-26 `C/n42-network/src/h2_v4.rs:227-262`; n42-rs same files under
  `h2-wire`/`h2-net` per `docs/N42_26_PORT.md` "Interop contract"); devnet `--gov5` rounds (v4); chain 94 soak (legacy).
Verdict: **[DIFF]** in source (n42-26 env); both profiles proven.

**A15. Leader tenure.**
Rule: `hotstuff.leaderTenure` (absent/0 = 1) is THE tenure (SYNC §10.3).
- gov5 main: genesis, `HS/adapter.go:238`; env `N42_HOTSTUFF_LEADER_TENURE` (`HS/validator.go:160`) reaches no
  engine path. n42-rs: genesis, `hotstuff.rs:56-57`, selection `h2-consensus/src/validator/selection.rs:30-39`.
  n42-26 main: **no tenure** (`view % n`, `C/n42-consensus/src/validator/selection.rs:6,19-26`); `feat/native-port`
  and `upgrade/reth-v2.11.0`: env `N42_LEADER_TENURE` only (`selection.rs:16`).
- Evidence: T = 1 in every mixed round. No mixed round with T > 1.
Verdict: **[DIFF]** for T > 1; T = 1 proven.

**A16. View timeout parameters.**
Rule: `baseTimeout`, `maxTimeout` (ms) MUST be present in a mixed chainspec (defaults differ).
- gov5: `cfg:535-536`; default 60000/120000 when the config is nil (`HS/adapter.go:158-159`).
- n42-rs: serde defaults 6000/30000 (`hotstuff.rs:168-173`).
- n42-26: config file or env `N42_BASE_TIMEOUT_MS`/`N42_MAX_TIMEOUT_MS` (`main.rs:1300-1317`); dev 4000/8000
  (`C/n42-chainspec/src/lib.rs:98-108`).
- Shipped chainspecs all set 6000/30000.
Verdict: **[DIFF]** (defaults and n42-26 source); explicit values proven.

**A17. Block period.**
Rule: `hotstuff.period` (seconds, default 3) is the minimum timestamp step a leader MAY use (see F1).
- gov5: `cfg:534`, default 3 at `HS/adapter.go:~640`. n42-rs: `hotstuff.rs:44-45,162-164`. n42-26: env
  `N42_BLOCK_INTERVAL_MS` (default 0, `C/n42-consensus-service/src/orchestrator/mod.rs:2836`); `slot_time_ms` in the config file.
Verdict: **[DIFF]** (n42-26 source and unit).

**A18. Epoch length.**
Rule: `hotstuff.epochLength` in views; epoch(v) = (v-1)/E; boundary b: b > 1 and (b-1) % E == 0.
- gov5: `cfg:537`, `HS/validator.go:~355,398-402`. n42-rs: `hotstuff.rs:64-67`, `h2-consensus/src/validator/epoch.rs`.
  n42-26: config file `epoch_length` (default 0, dev 30).
- Evidence: MATURITY_HARDENING_2026_10.md:376-390, three mixed rounds (epochLength 20) crossing boundaries.
Verdict: **[DIFF]** source (n42-26); gov5/n42-rs proven.

**A19. Committee pool.**
Rule: `hotstuff.committeePool {enabled, seedHex, poolSize, committeeSize, rampBlocks}`.
- gov5: `cfg:556,~594` (also `allowHandover` at 641d5153; not checked on main). n42-rs: `hotstuff.rs:97-115`
  (no `allowHandover`). n42-26: genesis, `C/n42-consensus/src/committee_pool.rs:65-110`.
- Evidence: `gov5_committee_evidence.txt` fixture (n42-26); devnet rounds (4096/64); chain 94 soak (200000/512).
Verdict: **[AP]** (allowHandover unverified).

**A20. Glamsterdam and MobileAnchor activation.**
Rule: `glamsterdamTime`, `mobileAnchorTime` from genesis; root in header only when both are active.
- gov5: `cfg:245,312`, `params/config_rules.go:~391,438,446-456`. n42-rs: `qmdb.rs:109-176`.
  n42-26: not read.
- Evidence: `mv4h4b2` (MOBILEVERIFY_V3_PARITY.md:669-677), 160/160 hashes.
Verdict: **[DIFF]** (n42-26 cannot follow such a chain); gov5/n42-rs proven.

**A21. `fastPropose`, `minProposeDelayMs`, `ethELCompat`.**
Rule: leader-local pacing knobs; not consensus-visible; `ethELCompat` MUST be false on a mixed native chain.
- gov5: `cfg:~544-578`. n42-rs: ignored. n42-26: env `N42_FAST_PROPOSE`, `N42_MIN_PROPOSE_DELAY_MS`.
Verdict: **[UNDEF]** (no shared statement of meaning; harmless while local).

**A22. `rotateOnTimeoutView`.**
Rule: SYNC §10 (approved).
- gov5: branch `feat/hotstuff-rotate-on-timeout` only (`cfg:635` there). n42-rs: none. n42-26: none.
Verdict: **[UNDEF]** in practice (one unmerged implementation; mixed networks MUST leave it absent, SYNC §10.3).

**A23. Gas limit target.**
Rule (proposed): the target gas limit is a chainspec value (`hotstuff.gasLimitTarget`), and each header's limit
moves toward it by less than `parent/1024` (Ethereum's rule, already enforced by n42-rs, see B14).
- gov5: CLI `--miner.gasceil` (default 30M, `cmd/n42/config.go:146`), `internal/miner/gas_limit.go:~39-66`;
  env `N42_STRESS_GASLIMIT=1` jumps straight to the ceiling (`gas_limit.go:37`).
- n42-rs: reth `--builder.gaslimit` per node (`scripts/fleet7-env.sh:613`).
- n42-26: unverified.
Verdict: **[UNDEF]** (per-node CLI on both; `N42_STRESS_GASLIMIT` blocks are refused by n42-rs).

### (b) Header profile and block format

**B1. Extra layout.**
Rule: `"N42H"(4) ‖ view u64 LE ‖ QC ‖ seal(96)`; QC = the leader's last CommitQC (commit domain), absent before
its first; ≤ 4096 bytes (SYNC §3.2).
- gov5: `HS/header_extra.go:19-79`, build `:21`. n42-rs: `h2-consensus/src/header_profile.rs`; QC embedded
  (maturity 6.9). n42-26: `"N42H" ‖ view ‖ seal`, no QC (`C/n42-network/src/gov5_block.rs:177-181`) — SYNC B5.
- Evidence: header-profile fixture (`header_profile_fixture.rs`, bytes printed by gov5); devnet rounds.
Verdict: **[DIFF]** (n42-26 embeds no QC; owner already ruled every producer MUST).

**B2. Seal.** Rule: 96-byte BLS seal over the header hash minus the last 96 bytes; not verified by anyone
(SYNC §3.2). gov5 `HS/adapter.go:~1000-1013`; n42-rs signs (`header_profile.rs`); n42-26 zero seal from its
network constructor. Verdict: **[AU]** (n42-26 zero-seal unverified on its producer path).

**B3. Difficulty, coinbase, ommers, nonce.**
Rule: difficulty 0, coinbase = leader address, ommersHash = zero (Go zero value), nonce 0; a body with ommers
under a zero ommersHash is invalid.
- gov5: `HS/adapter.go:~586-593`. n42-rs: `hotstuff_consensus.rs:294-297,431-440`. n42-26: difficulty "0 or 1"
  accepted (`adapter.rs:74-85`).
Verdict: **[AP]** gov5/n42-rs (devnet); n42-26 acceptance broader (unverified producer value).

**B4. Timestamp.**
Rule (proposed): `parent.time < header.time ≤ local_now + 0` at import, and a leader MUST NOT stamp below
`parent.time + period`... **cannot be stated without a decision** (O4): today
- gov5: stamps `parent.time + period` with no now-floor (`HS/adapter.go:~655-667`); import requires only
  `time > parent.time` (`HS/adapter.go:443-445`); gossiped blocks ahead of the wall clock are ignored/queued
  (`docs/N42_26_PORT.md` "Timestamps: two clocks"; future-queue `internal/blockchain.go:127`; tolerance not
  re-verified on main).
- n42-rs: waits for the clock to pass the parent's stamp, stamps the wall clock (`ProposalContext::head_seen`);
  import enforces Ethereum's `time > parent.time`.
- n42-26: "deterministic time" following gov5 Prepare (soak doc §2026-10-14); unverified in code.
Verdict: **[UNDEF]** (no common rule; the two producers differ and only meet because each tolerates the other).

**B5. parentBeaconRoot = committee evidence.**
Rule: with `committeePool.enabled`, `parentBeaconRoot = Blake3(evidence(parent.number, parent.hash,
parent.receiptsRoot))`; zero for a genesis parent; zero on Cancun without a pool (gov5 `95d47b46`).
- gov5: `HS/adapter.go:1042` (compute), `~509-527` (verify). n42-rs: `hotstuff_consensus.rs:409-419`,
  `h2-consensus/src/committee_pool.rs`. n42-26: `adapter.rs:304-308,492`.
- Evidence: fixture `gov5_committee_evidence.txt` (n42-26); devnet rounds; chain 94 soak.
Verdict: **[AP]**.

**B6. Withdrawals = rewards.** Rule: `withdrawalsRoot = DeriveSha(rewards)` (keccak of concatenated
encodings; keccak("") when empty). gov5 `HS/adapter.go:~817`; n42-rs `header_profile.rs` (both spellings
accepted by `N42EngineValidator`); n42-26 `adapter.rs:148-175`, `gov5_rewards.rs`. Evidence: devnet rounds,
chain 94 soak. Verdict: **[AP]**.

**B7. Receipts root.** Rule: keccak of concatenated `rlp([status, cumulativeGas, logs])`; keccak("") when
empty. gov5 `internal/block_validator.go:161-165`; n42-rs `hotstuff_consensus.rs` (post-execution);
n42-26 `C/n42-consensus/src/receipt.rs:5-24`. Evidence: header-profile fixture; all mixed rounds.
Verdict: **[AP]**.

**B8. requestsHash.** Rule: empty-trie root (`keccak(rlp([]))`) when Prague is active, not EIP-7685's
`sha256("")`. gov5 `HS/adapter.go:845`; n42-rs accepts both spellings and writes gov5's
(`docs/N42_26_PORT.md` header profile); n42-26 unverified. Verdict: **[AP]** gov5/n42-rs (devnet).

**B9. Blob gas fields.** Rule: `blobGasUsed = 0`, `excessBlobGas = 0` on a native chain (follows from C2).
gov5 writes 0 whatever the body (`HS/adapter.go:~822-828`); n42-rs derives from the body (always 0 once type 3 is
refused); n42-26 strips them (`gov5_block.rs:132-133,158-159`). Verdict: **[AU]**.

**B10. Slot number (EIP-7843).** Rule: from `glamsterdamTime`, element 23 = block number. gov5
`HS/adapter.go:849,1138`; n42-rs `h2-el-rpc/src/engine.rs:1373-1380,2666-2675`; n42-26 none.
Evidence: `mv4h4`/`mv4h4b2`. Verdict: **[DIFF]** (n42-26); gov5/n42-rs proven.

**B11. mobileRegistryRoot.** Rule: element 24, present iff MobileAnchor ∧ Glamsterdam
(`docs/HEADER_FIELD_PARITY.md` §4). gov5 `common/block/header.go:94-119`, verify `HS/adapter.go:481-488`;
n42-rs `N42Header` (merged b87fa2884), `engine-types/src/assembler.rs`; n42-26 treats it as element 23,
zero on its producer (`C/n42-consensus/src/gov5_native_header.rs:5-9,47-50`; `main.rs:155-170`) — the
pre-`65f2c63f` layout. Evidence: `mv4h4b2` 160/160. Verdict: **[DIFF]** (n42-26 old layout).

**B12. Block access list hash (EIP-7928).** Rule: undecided (HEADER_FIELD_PARITY §10 Q1, "gap 2"): gov5 gates
it with `balTime`; nobody stamps it on a native chain. Verdict: **[UNDEF]**.

**B13. Deferred execution fields.** Rule: see A10; plus `header.gasUsed ≤ parent.gasLimit` at depth 1; the first
header after the gate repeats its parent's fields. gov5 `internal/deferred_execution.go:~26-65`,
`HS/adapter.go:446-462`; n42-rs `hotstuff_consensus.rs:381-407`. Verdict: **[DIFF]** at depth > 1 and for n42-26;
**[AU]** at depth 1 for gov5/n42-rs (mixed evidence claimed, not re-read). Counted as DIFF.

**B14. Gas limit and base fee validity.**
Rule (proposed): Ethereum's rules — `|gasLimit - parent.gasLimit| < parent.gasLimit/1024`, `gasLimit ≥ 5000`,
`gasUsed ≤ gasLimit`, EIP-1559 base fee derived from the parent — MUST be enforced on import by every client.
- gov5 main: only `gasUsed ≤ (parent's under deferral) gasLimit` (`HS/adapter.go:446-462`); base fee
  derivation "deliberately NOT enforced" (`HS/adapter.go:~463-470`, for replay-v2 history); no ramp check found.
- n42-rs: reth's `validate_header_against_parent` + `validate_header_base_fee` (`hotstuff_consensus.rs:330,376`),
  max `MAXIMUM_GAS_LIMIT_BLOCK` (`:324`).
- n42-26: unverified.
Verdict: **[DIFF]** (strictness: a gov5 block with a non-derived base fee or a stress gas limit is accepted by
gov5 and refused by n42-rs → liveness/fork).

**B15. Block byte size.** Rule: SYNC §3.1 `MAX_BLOCK_BYTES = 64 MiB` decoded; no EIP-7934 on native import
(`docs/PROTOCOL_CONFORMANCE_2026_11.md` item 1); gossip cap `N42_MAX_GOSSIP_MB` identical network-wide.
gov5 `internal/p2p/encoder/ssz.go:22-67`; n42-rs `h2-net/src/config.rs:57`, builder budget
`engine-types/src/byte_budget.rs`; n42-26 32 MiB on push/by-hash (`gov5_rpc.rs:23`, SYNC B1), gossip 1 MiB.
Verdict: **[DIFF]** (n42-26 32 MiB; gossip cap is env, not chainspec).

**B16. Transaction count.** Rule: no consensus bound on transaction count (gas and bytes bound a block).
n42-26 `N42_MAX_TXS_PER_BLOCK` is builder-only (`C/n42-node/src/pool.rs:19`). Verdict: **[AU]**.

### (c) Transaction types and validity

**C1. Types 0, 1, 2.** Rule: Ethereum rules at the active fork. All three. Evidence: every round with load
(mv4h4b2: 1,322 transfers). Verdict: **[AP]**.

**C2. Type 3 (blobs).** Rule (decided D4, 2026-11-19): invalid on a native chain — pool, builder, block
validation, execution, and deferred includability.
- gov5 main: **not merged** (`ErrBlobTxOnNativeChain` absent at `47e219a1`; branch
  `fix/native-conformance-2026-11` c553fef9 local/unmerged); pool admits, header writes 0 blob gas.
- n42-rs: done (`engine-types/src/consensus.rs:235`, `n42_tx_types::BLOB_TX_ON_NATIVE_CHAIN`).
- n42-26: pool built with EIP-4844 enabled (`C/n42-node/src/pool.rs:46,56,81`); no refusal found.
Verdict: **[DIFF] — consensus fork** if anyone submits a blob tx to a gov5-main or n42-26 leader.

**C3. Type 4 shape (D3).** Rule: native chains apply `checkSetCodeTxShape` (no create, non-empty list).
- gov5 main: native exemption still present (`internal/state_transition.go:560-581`; D3 commit 7826b798 unmerged).
- n42-rs: refuses (`docs/PROTOCOL_CONFORMANCE_2026_11.md` D3). n42-26: unverified.
Verdict: **[DIFF]** (latent: pool refuses such txs in gov5 since ecfcd65d; only a crafted block triggers it).

**C4. 0x50.** See A11. Verdict counted there.

**C5. EIP-7825 cap (2^24; 2^32-1 from Glamsterdam).** gov5 pool + state transition; n42-rs every path
(tests in PROTOCOL_CONFORMANCE item 2); n42-26 unverified. Verdict: **[AU]**.

**C6. Initcode cap before Glamsterdam (D5).** Rule: no EIP-3860 transaction-level cap on native chains
before `glamsterdamTime`; EIP-7954's 131,072 after. gov5 `internal/state_transition.go:577-581` exemption;
n42-rs `engine-types/src/native_tx_rules.rs`; n42-26 unverified. Verdict: **[AU]**.

**C7. Pool admission vs block validity.** Rule: pool policy is local and MUST be a subset of block validity;
only block validity is standardised. Verdict: **[AU]**.

**C8. Zero-tip / zero-value transactions.** Covered by A9: until the unchanged-account rule is active on every
client, a mixed network MUST NOT carry zero-tip transactions or zero-value transfers to untouched existing
accounts (R3_E2.md). Counted in A9.

### (d) Execution semantics

**D1. EVM fork set.** Rule: Ethereum through Osaka (and Amsterdam from `glamsterdamTime`), plus nothing else
unless activated by a shared field. gov5 adds EOF (`eofTime`) — see A4. Verdict counted in A4.

**D2. Amsterdam execution on native chains.** Rule: per `docs/GLAMSTERDAM_EXECUTION_PARITY.md` (G1-G7 closed;
EIP-8282 calls gated off on native chains: gov5 `UsesEIP8282BuilderRequests`, `internal/system_contract_registry.go:39`;
n42-rs not run on native). EIP-7997 absent in both; 8038/8246 in both from `glamsterdamTime`. n42-26: no
Amsterdam. Evidence: `mv4h4b2` (Glamsterdam at 0). Verdict: **[DIFF]** (n42-26), gov5/n42-rs proven.

**D3. Prague system calls and the caller leaf.** Rule: EIP-2935/4788 system calls; the caller
`0xfffffffffffffffffffffffffffffffffffffffe` is written as a live empty account leaf on Prague blocks.
gov5 (Erigon `SysCallContract`); n42-rs `changes_from_execution`; n42-26 unverified.
Evidence: devnet rounds (the original block-1 mismatch, `N42_26_PORT.md` "The system caller leaf").
Verdict: **[AP]** gov5/n42-rs.

**D4. Account deletion predicate.** Rule: an account is deleted iff EIP-161 empty (nonce 0, balance 0, no
code) after the block; accounts with code are never deleted by emptiness. gov5 `isAccountEmpty`
(`modules/state/commitment/jmt_commitment.go:~174-176`, unreachable for code accounts per handoff 2026-11-22);
n42-rs marks every bundle account initialised. Evidence: B10 verification + `mv4h4b2` 160/160.
Verdict: **[AP]** gov5/n42-rs; n42-26 unverified.

**D5. Storage writes.** Rule (proposed): a slot whose post-block value is zero is a QMDB delete; a slot
re-written with its pre-block value is no write (the storage analogue of A9). gov5: zero slot = delete
(`qmdb_root_computer.go:~846-856`); "net change" logic not found. n42-rs: unverified within budget.
Verdict: **[UNDEF]** (the account rule was fixed after a divergence; the storage analogue was never stated).

**D6. QMDB root.** Rule: gov5 `lib/qmdb` positional twig tree, keys/values per `twig_core::qmdb_compat`, ops
sorted by key hash. Fixtures: `twig-core/testdata/cross_client_v1.json` (n42-rs and n42-26), proof codec,
portable snapshot (SYNC §1.5). Verdict: **[AP]**.

**D7. Rewards in state.** See A8. **D8. Receipts root.** See B7.

### (e) Consensus

**E1. Quorum.** Rule: `f = ⌊(n-1)/3⌋`, QC needs `2f+1` signers of the view's set. All three. Evidence: fixtures,
all rounds. Verdict: **[AP]**.

**E2. Epochs and validator-set change.** Rule: a change is staged when committed (CommitQC) and activates at
the next boundary view; QCs verify against the set of their own view (SYNC §3.3, §3.6).
- gov5: `HS/reconfig.go:~88-315`, `HS/engine.go:~1015-1045`. n42-rs: exact-view sets (`115e1d486`, staged
  changes `98aef5e28`). n42-26: dynamic changes disabled in gov5 profiles (`quorum.rs:34-36`).
- Evidence: MATURITY_HARDENING rounds cross boundaries with a **static** set; no mixed round with an actual
  add/remove.
Verdict: **[DIFF]** (n42-26 cannot follow a set change; set change itself unproven mixed).

**E3. Leader schedule.** Rule: `leader(v) = (v / max(T,1)) % n` over the set of view v. gov5
`HS/validator.go:180`; n42-rs `selection.rs:30-39`; n42-26 `v % n`. Verdict: counted in A15.

**E4. Rotate on timeout.** SYNC §10 rule and vectors §10.4. Verdict counted in A22.

**E5. Pacemaker.** Rule (SHOULD, liveness): `timeout = min(eff_base · 2^k, max)`, k = consecutive local timeouts,
reset on QC/commit; `eff_base = max(base, 2·p95)` of the last 20 commit latencies once ≥ 5 samples.
gov5 `HS/pacemaker.go:~45-125`; n42-rs `h2-consensus/src/protocol/pacemaker.rs:8-95` (window 20, `:31`);
n42-26 `C/n42-consensus/src/protocol/pacemaker.rs:7-95`. Verdict: **[AU]** (same formula in all three; not
consensus-visible; the adaptive base is undocumented in any spec).

**E6. Proposal validity.** Rule: proposer = `leader(view)`; justify QC verified (view > 0) in either accepted
domain; block's parent = justify QC's block (`extendsJustify`, fail-open when justify is zero or parent unknown);
header valid (section b); `justify.view ≥ locked.view`.
- gov5: `HS/proposal.go:713-729`, `HS/round_state.go:~217`. n42-rs: extends rule added after the safety bug
  (`N42_26_PORT.md` "The safety bug", test `test_h2_vote_refuses_a_proposal_that_does_not_extend_its_justify`).
  n42-26: `proposal.rs:629-665`, gov5 profiles only.
Evidence: the safety bug was found by a mixed round; later rounds clean. Verdict: **[AP]**.

**E7. Vote rules.** Rule: one Round-1 vote and one CommitVote per view, journalled before sending; Round-1 vote
after import (or, with `twoPhaseVoteGate`, after static validation); CommitVote after the import (deferred: after
the check + the parent's import). gov5 `HS/proposal.go:~245-395`; n42-rs `h2-consensus/src/protocol/voting.rs`,
`vote_log.rs`; n42-26 `proposal.rs:420-441`. Verdict: **[AU]** (journal format is local; behaviour agreed).

**E8. Vote-before-slot / vote-before-import (n42-rs knobs).** Rule (proposed): a vote MUST NOT be sent before the
gate of E7 is met. n42-rs `N42_VOTE_BEFORE_SLOT` (experimental, off), `N42_VOTE_BEFORE_IMPORT` (`h2-node`).
Verdict: **[UNDEF]** (bench-only knobs that weaken the attestation; must be off on a mixed network).

**E9. Progress votes (n42-rs).** A follower that imports a block after its view passed sends a `Vote` whose
signature covers `vote_message ‖ "/n42/imported-late"` (`h2-consensus/src/protocol/quorum.rs:71-80`), on whenever
the straggler grace is on (`h2-node/src/service.rs:1911`). gov5 and n42-26 receive an invalid-signature vote;
whether they score/penalise the sender is unverified. Verdict: **[UNDEF]** (MUST be off in a mixed network
until specified).

**E10. Signing domains.** Rule: H2-v4: `"N42H2V4"(7) ‖ phase u8 (proposal 1, vote 2, commit 3, timeout 4,
newview 5) ‖ chainId u64 LE ‖ genesisHash ‖ view u64 LE ‖ payload`; proposal/commit payload `blockHash ‖
changesHash` (changesHash zero); POP DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. gov5 `HS/interop_v4.go:13-56`;
n42-rs `h2-primitives/src/bls/mod.rs:8-12`, `quorum.rs:62-95`; n42-26 `C/n42-primitives/src/consensus/h2_v4.rs:5-60`.
Fixture `h2_v4_domains_v1.json` (`f3f20d46…`). Verdict: **[AP]**.

**E11. QC / TC formats.** Rule: QC `{view, blockHash, aggSig, signers bitmap}`, TC `{view, aggSig, signers,
highQC}`; wire per SYNC §1.2. Fixtures `cross_client_h2_v1.json`, `h2_v4_envelope_v1.json`; n42-rs
`h2-wire`. Verdict: **[AP]**.

**E12. Commit rule.** Rule: two rounds on the same block: Round-1 votes → PrepareQC (lock); CommitVotes →
CommitQC commits the block and its ancestors; Decide broadcast. gov5 `HS/voting.go:~417-480`; n42-rs
`protocol/voting.rs`, `decision.rs:12`; n42-26 `voting.rs:150-172`. Evidence: all rounds (equal committed heads).
Verdict: **[AP]**.

**E13. Which QC verifies where.** Rule: SYNC §3.3 (commit-domain anchors, exact epoch set, no fallback). Today
gov5 verifies header QCs in any domain and skips when the set is unknown; n42-rs any domain, fails closed;
n42-26 none (SYNC B6). Verdict: **[DIFF]** (already scheduled in SYNC §7).

**E14. Finality tags exposed to the execution layer and RPC.** Rule (proposed): `latest` = committed head;
`safe` = execution-certified; `finalized` = committed and durable; documented per client.
gov5: `safe` and `finalized` alias `latest` (`internal/api/rpchelper/rpc_block.go:~45-55`); n42-rs: `split`
default (`h2-execution/src/settlement.rs`; `legacy` = all equal); n42-26: head = safe = finalized = committed
(`consensus_loop.rs:1066-1070`). Verdict: **[DIFF]** (operability only).

**E15. Equivocation.** Rule (proposed): a node MUST detect a second Round-1 vote or CommitVote by one validator
in one view, verify it, persist the pair as evidence, and expose it; slashing is out of scope until the owner
decides. gov5: trackers `HS/voting.go:~56-85,298-340`, evidence persisted (`HS/service.go:~855-868`), slashing
executor not wired; no double-proposal detector. n42-rs: tracker in `protocol/voting.rs:8-9`; persistence
unverified. n42-26: unverified. Verdict: **[UNDEF]**.

**E16. Vote transport.** Rule: votes MUST travel on the consensus gossip topic (or gov5's `hotstuff_direct/1`);
n42-rs `/n42/vote/1` (`N42_VOTE_TRANSPORT=direct`, set by the x22 profile) is single-client only; a mixed
network uses `gossip` or `both` (`docs/E1_MANY_KEYS.md:242`). n42-rs does not serve `hotstuff_direct/1`
(no match in `h2-net/src`); gov5 and n42-26 do. Verdict: **[DIFF]**.

**E17. Decide proofs on `/n42/h2/4/ssz_snappy`.** Rule: with H2-v4 a member publishes Decide proofs there for
observers; consensus stays on `/n42/<digest>/hotstuff_consensus/ssz_snappy`. gov5 `HS/service.go:~1019`;
n42-rs `h2-net/src/topic.rs:18-58`; n42-26 `topics.rs`. Verdict: **[AP]** (devnet rounds).

### (f) Block-production behaviour others depend on

**F1. Pacing.** Rule (proposed): a leader proposes no earlier than `period` after it saw the parent and stamps
per B4. n42-rs paces from `head_seen`; gov5 from its miner/`fastPropose`. Verdict: **[UNDEF]** (with B4).

**F2. Empty blocks.** Rule (proposed): a leader with an empty pool MUST still propose (an empty block) every
view, otherwise the view times out. gov5: `noempty` flag exists (`internal/miner/worker.go:~196,1375`), not
verified that an idle HotStuff leader proposes; n42-rs proposes empty blocks (devnet idle rounds); n42-26
`N42_MAX_EMPTY_SKIPS` env (`state_mgmt.rs:37`) suggests it may skip. Verdict: **[UNDEF]**.

**F3. Byte budget.** Rule: producers pack at most `cap/10·9 − 32 KiB − header` bytes of transactions, `cap` =
min(gossip, block chunk) caps (D1). gov5 `internal/miner/block_size.go:38-88`; n42-rs `byte_budget.rs`;
n42-26 unverified. Verdict: **[AU]** (builder policy; the validity rule is B15).

**F4. Leader must embed its last CommitQC.** See B1 (counted there).

**F5. Stale parent.** Rule: a leader MUST NOT propose a block whose parent is not the block of the justify QC it
attaches. gov5 drops (`HS/proposal.go:~21-105`, `hotstuff_proposal_stale_parent_total`); n42-rs rebuilds
(d5613db61, b759c48f3). Verdict: **[AP]** (wire-identical; mixed rounds clean).

**F6. Same-parent rebuilds / sibling proposals.** Rule (proposed): within one view a leader MUST propose at most
one block (equivocation otherwise); across views it MAY re-propose the block it sealed on the same parent.
gov5 re-proposes the first sealed on a parent and converges on the lowest-hash sibling
(`internal/miner/worker.go:~314-323,631-671`); n42-rs: unverified (memory: G8 "same-parent rebuild recurrence"
still instrumented, not explained). Verdict: **[UNDEF]**.

**F7. Deferred-execution seal ordering.** Rule: under deferred execution a leader MAY seal before it finishes
executing its own block (the header carries the parent's result); it MUST NOT propose block N+k before it has
executed N. n42-rs `N42_SEAL_FIRST` (default on, `engine-types/src/payload.rs:683`); gov5 `LagReady` gate
(qs). Verdict: **[AU]** at depth 1.

**F8. Straggler grace.** n42-rs leader waits for every validator's vote (`N42_STRAGGLER_GRACE_MS`, h2-node
`straggler.rs`); leader-local, but it enables E9. Verdict: **[AU]** (local).

### (g) Networking

SYNC §1.1-1.3, §4 and §6 already inventory the block-carrying protocols (status, block_by_hash, bodies_by_range,
block_push, hotstuff_direct), caps and quotas. Production adds:

**G1. Identity and transport.** Rule: libp2p with secp256k1 identities, Noise, yamux; `/ipfs/id/1.0.0`
identify MUST be spoken (go-libp2p-pubsub meshes only with identified peers). n42-rs `h2-net/src/transport.rs`
(identify `:446`); gov5 reference; n42-26 its own transport. Evidence: devnet rounds; chain 94 soak.
Verdict: **[AP]**.

**G2. Gossip topics.** Rule: `/n42/<digest>/hotstuff_consensus/ssz_snappy` (consensus),
`/n42/<digest>/block/ssz_snappy` (block bodies, RLP `[header, txs, verifiers, rewards]`),
`/n42/<digest>/transaction_v2/ssz_snappy` (txs), `/n42/h2/4/ssz_snappy` (Decide), `mobileverify_{packet,registration}`.
gov5 `internal/p2p/topics.go:5-55`; n42-rs `h2-net/src/{topic,block_gossip,tx_gossip}.rs`; n42-26
`C/n42-network/src/gossipsub/topics.rs`. Verdict: **[AP]** (rounds; mobileverify topics gov5/n42-rs only).

**G3. Message id.** Rule: `keccak(genesisHash ‖ topic ‖ data)[:20]`. gov5 `internal/p2p/message_id.go:30-45`;
n42-rs `h2-net/src/message_id.rs`; fixture `gov5_message_id_v1.json` (n42-26 testdata). Verdict: **[AP]**.

**G4. GossipSub parameters.** Rule: gov5's parameters are a wire contract (mesh degree, heartbeat, score
thresholds −4000/−8000/−16000, `internal/p2p/gossip_scoring_params.go:29-45`), asserted in n42-rs tests
(`docs/NATIVE_FLEET7.md`). n42-26 unverified. Verdict: **[AU]**.

**G5. Message caps.** Rule: consensus messages ≤ the consensus cap; blocks per B15. gov5 `MaxChunkSize` 1 MiB,
gossip 1 MiB by env; n42-26 16 KiB hotstuff direct, 4 MiB consensus; n42-rs `N42_H2_MAX_INBOUND` env.
Verdict: **[UNDEF]** (no common consensus-message cap; a QC with a large bitmap or an embedded TC must fit all).

**G6. Single-client protocols.** n42-rs `/n42/vote/1`, `/n42/block_txns/1/snappy` (`h2-net/src/rpc.rs:520,1182`),
n42-26 `/n42/consensus/1`, `/n42/sync/2`. Rule: a mixed network MUST NOT depend on them. Verdict: **[AU]**.

### (h) Sync

Normative in SYNC. Mixed-production dependencies on it: §3.2 (header Extra, = B1), §3.3 (anchors, = E13),
§3.4 (catch-up importer), §3.5 (legitimate behaviour not penalised), §3.6 (validator sets / checkpoint),
§4 (v1 frozen), §6 (limits), §10 (rotate on timeout). Breakages B1-B10 of SYNC §2 apply unchanged; not re-counted.

### (i) Mobile verification

**I1. `/mobileverify` surface and registry root.** Rule: `docs/MOBILEVERIFY_V3_PARITY.md` (registry epochs of
45 s, StreamPacket V2, cohort certificates, registry root into payload attributes under MobileAnchor).
gov5 reference + `mobileverify-packetd`; n42-rs `crates/n42/mobileverify`, `h2-node/src/mobile.rs`; n42-26 not
implemented (it has an older attestation threshold, `N42_MIN_ATTESTATION_THRESHOLD`, `consensus_state.rs:137`).
Evidence: `mv4h4b2` device 20/20, 159 packets. Verdict: **[DIFF]** (n42-26 absent); gov5/n42-rs proven.

**I2. Leader without a registry provider.** A validator without `--mobileverify.http` cannot build on a
MobileAnchor chain (n42-rs), gov5's leader lacks a registry-root provider per memory (open-items 10-30).
Rule (proposed): a member that cannot produce a MobileAnchor header MUST NOT be in the set of such a chain.
Verdict: **[UNDEF]**.

### (j) Operations

**J1. RPC semantics others rely on.** `eth_config` refused on native chains with gov5's message, code −32004
(n42-rs `bin/n42/src/native_rpc.rs`); witness methods refused on QMDB; finality tags per E14;
`n42Engine_persistedBlock` n42-rs only. Verdict: **[AU]** for eth_config/witness, rest single-client.

**J2. Metrics.** No cross-client metric contract exists (each client's names differ:
`hotstuff_proposal_stale_parent_total`, `sync_anchor_*` in gov5). Rule (proposed): a minimum common set
(head, committed view, timeouts, TCs, equivocations, refused blocks by reason). Verdict: **[UNDEF]**.

**J3. Upgrade / activation procedure.** Rule: 0.4. Today: gov5 uses timestamp fields; n42-rs timestamp fields
plus refusal of unsupported depths (`DeferredDepthError::NotImplemented`); n42-26 env. No client refuses to start
on an unknown activating field. Verdict: **[DIFF]**.

**J4. Environment knobs that are consensus-visible.** Rule: none permitted on a mixed network except declared
bench overrides. Found: gov5 `N42_STRESS_GASLIMIT`, `N42_MAX_GOSSIP_MB`, `qs` `N42_DEFERRED_DEPTH*`,
`N42_FRAME_BLOCKS`, `N42_VOTE_ON_AVAILABILITY`; n42-rs `N42_MAX_GOSSIP_MB`, `N42_VOTE_TRANSPORT`,
`N42_VOTE_BEFORE_SLOT`, `N42_VOTE_BEFORE_IMPORT`, `N42_STRAGGLER_*` (progress votes); n42-26 `N42_CHAIN_ID`,
`N42_CONSENSUS_CONFIG`, `N42_BASE/MAX_TIMEOUT_MS`, `N42_BLOCK_INTERVAL_MS`, `N42_GOV5_LEGACY_SIGNING`,
`N42_GOV5_PRAGUE_TIME`, `N42_GOV5_HEADER_PROFILE`, `N42_GOV5_QMDB_EXECUTION`, `N42_LEADER_TENURE` (branches),
`N42_FRAME_BLOCKS`, `N42_SKIP_STATE_ROOT`/`N42_DEFER_STATE_ROOT` (bench), `N42_REWARD_*` (main.rs:2855-2859).
Verdict: **[DIFF]**.

---

## 2. Differences and undefined items, ranked by risk

Risk classes: **C** consensus fork, **L** liveness, **I** interop failure, **O** operability.

| # | Item | Class | What happens | Proposed resolution | Who changes |
| --- | --- | --- | --- | --- | --- |
| R1 | A9 unchanged-account rule | C | gov5 main writes an unchanged touched account, n42-rs does not → different QMDB root on a zero-tip tx or zero-value transfer to an untouched account | Every mixed chainspec sets `unchangedAccountNoOpTime` (0 for new chains, a future time for running ones); n42-rs MUST read the field and apply the old rule before it (or refuse a chain where it is absent/non-zero) | chainspec owners; n42-rs; n42-26 (verify) |
| R2 | C2 type 3 on native chains | C | gov5 main / n42-26 leaders include a blob tx; n42-rs refuses the block | Merge gov5 `fix/native-conformance-2026-11` after the 94/95 history scan; n42-26 adds the refusal; activation: the rule is history-safe if the scan finds none (else gate by a `<name>Time`) | gov5, n42-26 |
| R3 | C3 type 4 shape | C | crafted malformed set-code tx: gov5 executes, n42-rs refuses | as R2 (D3 commit 7826b798) | gov5, n42-26 |
| R4 | B14 base fee / gas-limit ramp | C/L | a gov5 block with a non-derived base fee or `N42_STRESS_GASLIMIT` limit is refused by n42-rs; the Rust members stop voting → no quorum if they are > f | gov5 enforces the Ethereum rules on HotStuff import from an activation time (replay-v2 history stays below it); `N42_STRESS_GASLIMIT` declared single-client | gov5 |
| R5 | A4/D1 EOF on chain 94 | C | an EOF container deployed on chain 94 executes in gov5 only | decide (O3): gate EOF off on native chains from a time, or never admit Rust clients to chain 94 consensus | owner, gov5 |
| R6 | A10/B13 deferred depth | C | depth from env (gov5 qs) vs genesis (n42-rs); different transition rules; n42-26 none | `deferredExecutionDepth` + a `deferredExecutionDepthTime`-style activation in the chainspec, gov5 qs reads it; n42-26 refuses such chains | gov5 (qs), n42-26 |
| R7 | A12 frame blocks | C | three incompatible designs | declare single-client only; any merge needs one spec | owner |
| R8 | A11 0x50 | C | gov5 cannot decode a 0x50 block | mixed chainspecs MUST NOT set `altSigTx`; gov5 refuses to start on one | gov5 (start-up refusal) |
| R9 | A2/A3/A14-A18/A5 n42-26 env-sourced parameters | C | a misconfigured env (tenure, signing profile, chain id, validator list) silently forks or stalls one member | n42-26 reads `config.hotstuff` from the chainspec; env only as declared overrides | n42-26 |
| R10 | A15 tenure (n42-26) | C | T > 1 with an n42-26 member: it computes a different leader, refuses proposals | n42-26 reads `leaderTenure` (SYNC §10.5) | n42-26 |
| R11 | B11/B10/A20/D2/I1 Amsterdam + MobileAnchor (n42-26) | C | n42-26 decodes element 23 as the registry root and has no Amsterdam execution | n42-26 refuses to start when `glamsterdamTime`/`mobileAnchorTime` is set until it implements them | n42-26 |
| R12 | A7 Q-S1 alloc rule | C (genesis) | latent: different genesis root for a storage-only empty alloc entry | n42-rs and n42-26 reject such entries (owner-decided) | n42-rs, n42-26 |
| R13 | D5 storage net-change | C (unknown) | if one client writes an unchanged slot, the positional QMDB root differs (as A9) | write a vector set (slot set to same value, set then reset in one block, zero→zero) and run it on gov5 + n42-rs | gov5 + n42-rs (vectors) |
| R14 | E2 validator-set change | C/L | n42-26 disables dynamic changes; a reconfig on a mixed chain is untested | mixed round with an add/remove; n42-26 refuses reconfig chains or implements staging | all |
| R15 | A22/E4 rotate on timeout + A15 tenure > 1 | L | one dead leader stalls ~192 s per rotation (handoff run 97) | implement SYNC §10 in n42-rs and n42-26, merge gov5's branch, then set `rotateOnTimeoutView` | n42-rs, n42-26, gov5 |
| R16 | A16 timeout defaults | L | a chainspec without `baseTimeout`: gov5 60 s, n42-rs 6 s | make both fields mandatory on native chainspecs (refuse to start without them) | all |
| R17 | B4/F1 timestamp rule | L | gov5 stamps `parent+period` (may be ahead of other clocks), drops blocks ahead of its clock; n42-rs stamps wall clock | one rule (O4) with a stated clock tolerance | owner, then all |
| R18 | F2 empty blocks | L | a leader that skips empty views costs a timeout per view on an idle chain | MUST propose every view | n42-26 (`N42_MAX_EMPTY_SKIPS`), gov5 verify |
| R19 | E9 progress votes / E8 vote-before-slot | L/I | invalid-signature votes at gov5/n42-26; possible peer scoring | MUST be off in mixed networks; n42-rs refuses to enable them when the set is not all-Rust, or specify a message type | n42-rs |
| R20 | B1/E13 n42-26 no QC in Extra; QC rule divergence | I (sync) | ranges from n42-26-led stretches have no anchor | SYNC §3.2/§3.3 (scheduled) | n42-26, all |
| R21 | B15 block byte caps | I | n42-26 cannot receive a > 32 MiB block; `N42_MAX_GOSSIP_MB` differs per node | SYNC §3.1 64 MiB; move the gossip cap into the chainspec (`hotstuff.maxGossipBytes`) | n42-26; all |
| R22 | E16 vote transport | I | n42-rs `direct` votes never reach gov5/n42-26 | x22 profile MUST NOT set `N42_VOTE_TRANSPORT=direct` on a mixed chain | n42-rs |
| R23 | G5 consensus message cap | I | a large-set QC/TC may exceed one client's cap (n42-26 16 KiB direct) | define the cap from the set size (bitmap + 96 + header) and test with n = 512 | all |
| R24 | A23 gas-limit target | O/L | per-node CLI; members fight over the target | chainspec field | all |
| R25 | B12 BAL hash | O (future C) | undefined at Amsterdam | decide (HEADER_FIELD_PARITY §10 Q1) | owner |
| R26 | E15 equivocation | O | detection differs; nothing standard | evidence format + exposure; slashing later | all |
| R27 | E14 finality tags, J1, J2 metrics | O | RPC consumers see different `safe`/`finalized` | document per client; common metric set | all |
| R28 | A21, I2, F6 | O/L | single-client knobs; leader without registry provider; sibling proposals | specify or forbid | all |

---

## 3. Conformance test plan

### 3.1 Shared vector sets to create (owner of bytes: gov5)

| Set | Content | Exists? |
| --- | --- | --- |
| V1 header profile | extra layouts (no QC, QC, legacy), seal hash, header hash per fork (Cancun, Prague, Glamsterdam, Glamsterdam+MobileAnchor), requestsHash and withdrawalsRoot spellings | partly: n42-rs `header_profile_fixture.rs`; add the element-23/24 shapes and run in n42-26 |
| V2 roots | receipts DeriveSha, rewards root, committee evidence → parentBeaconRoot | partly (`gov5_committee_evidence.txt`) |
| V3 QMDB state transitions | per-block op lists → root, including: unchanged-account rewrite (A9) before/after `unchangedAccountNoOpTime`, zero-value transfer to an untouched account, storage set-to-same / set-then-reset / zero→zero (D5), system-caller leaf, code account with nonce 0 balance 0, storage-only alloc entry (Q-S1 refusal) | no — new |
| V4 transaction validity | type 3 refused, type 4 malformed refused, 2^24+1 gas, initcode 49,153 before/after Glamsterdam, 0x50 on a non-`altSigTx` chain, each as a whole block that MUST be refused at import | no — new (each client has unit tests only) |
| V5 header validity | base fee off by one, gas-limit step ≥ parent/1024, timestamp = parent, deferred fields at the gate and at depth 1/2 | no — new |
| V6 consensus messages | domains, envelope, QC/TC (exists: `h2_v4_domains_v1`, `h2_v4_envelope_v1`, `cross_client_h2_v1`, `gov5_message_id_v1`); add TC with highQC and a 512-member bitmap (G5) | partly |
| V7 schedule | `leader(v)` with T, `view_after_tc` (SYNC §10.4), epoch boundaries and the clamp | SYNC §10.4 table; not yet a fixture file |
| V8 chainspec | each shipped genesis → expected genesis hash; a set of chainspecs each client MUST refuse (unknown activating field, missing `baseTimeout`, `altSigTx` on gov5, depth 3) | partly (gov5 README hashes) |

### 3.2 Mixed-fleet round matrix

Pass criteria for every round: equal hash at every height on every client; every client led ≥ 1 block and
followed the others; 0 import/validation errors; no conflicting commit; TC count limited to the scripted faults;
round length ≥ 3 epochs where E > 0.

| ID | Shape | Leaders / followers | Load | Faults | Status |
| --- | --- | --- | --- | --- | --- |
| M1 | devnet `n42_devnet.json`, 3 n42-rs + 1 gov5 | all lead, T=1 | idle/light | none | **passed**: `devnet-fleet.sh mixed 90 --gov5` (37 blocks, `N42_26_PORT.md` "Joining a Go fleet"); `cd2a` 240 s h107 (PROTOCOL_CONFORMANCE_2026_11.md:72-75) |
| M2 | as M1, gov5 starts late | all | light | late join | **passed**: `gov5late` (MATURITY_HARDENING:384), `cd2b` |
| M3 | as M1, Rust member late / absent 1-3 h | all | light | rejoin | **passed**: `late`, `absent` (MATURITY_HARDENING:385-386); 1 h / 90 min / 3 h absences (`N42_26_PORT.md` "Coming back after hours away") |
| M4 | MobileAnchor + Glamsterdam devnet, 3 n42-rs + 1 gov5 | all | transfers + device | none | **passed**: `mv4h4b2` 160/160 (gov5 `integ/mvdev-slot` d4a00b01, not main); earlier `f4-mv`, `f6-mv`, `g-mv` (RETH_2_9_0/2_10_0 docs) |
| M5 | parallel follower in mixed | all | light | late member | **passed**: `f5d-gov5b` (RETH_2_9_0_UPGRADE.md:695) |
| M6 | chain 94, 5 gov5 + 1 n42-26 + 1 n42-rs, legacy profile | all 7 | 7,184 tx / 1 h | none | **passed**: n42-26 runs 114/115 (`chain94-three-client-soak-20261012.md`) |
| M7 | as M6, one Rust member restarted | all | light | crash + rejoin | **failed** (run 116), then **passed** after fixes (`chain94-recovery-repair-20261014.md`, n42-26 docs) |
| M8 | devnet, zero-tip / zero-value transfers, `devBlockReward` 0 | all | targeted | none | **failed as designed** (R3-E2 divergence, `docs/audit/2026-10-5m/R3_E2.md`); rerun after R1 with `unchangedAccountNoOpTime: 0` — **not run** |
| M9 | every client present (gov5 + n42-rs + n42-26) on a v4 native genesis | all | idle, then load | none | **not run** (blocked by R9-R11) |
| M10 | gov5 leads under bench load, Rust follows (and reverse) | gov5 / Rust | ≥ 1M tx/s class | none | **not run** (all mixed rounds were devnet-scale; the 5M runs are single-client) |
| M11 | tenure T > 1 (e.g. 8) mixed | all | light | kill the tenure leader | **not run** (needs R10, R15) |
| M12 | rotate on timeout active from view A | all | light | dead leader across A | **not run** (needs R15) |
| M13 | epoch boundary with an actual validator add/remove | all | light | none | **not run** (static sets only so far) |
| M14 | fork activation mid-round (e.g. `unchangedAccountNoOpTime`, `glamsterdamTime`, `mobileAnchorTime` at t0+120 s) | all | light | none | **not run** |
| M15 | deferred execution depth 1 mixed (`deferredExecutionTime` 0) | gov5 + n42-rs | load | crash + rejoin | claimed (`DEFERRED_DEPTH_2_DESIGN.md:539`, "PD"); record not re-read; depth 2 **not possible** (R6) |
| M16 | twoPhaseVoteGate true (chain 94 shape) mixed | all | load | slow member | **not run** |
| M17 | negative: V4/V5 invalid blocks injected by a test leader | each client leads once | — | Byzantine leader | **not run** |
| M18 | > f members of one client down (e.g. both Rust of 4) | — | light | partition | liveness expectation only; **not run** |

---

## 4. Open decisions for the owner

- **O1 Config source.** Adopt rule 0.4.1 (chainspec only; env as declared bench overrides) and 0.4.3 (refuse
  unknown activating fields) for all three clients? This is the precondition for n42-26 in a mixed set (R9).
- **O2 Signing profile.** SYNC §3.1 says a mixed network MUST run H2-v4, but the only three-client evidence
  (M6) is chain 94 on the legacy profile. Keep legacy as an allowed mixed profile, or schedule a v4 activation on
  chain 94 (needs a `interopV4Time`/view activation, which does not exist)?
- **O3 Chain 94 EOF.** Gate EOF off on native chains from a time, or keep Rust clients out of chain 94 consensus?
- **O4 Timestamp rule.** Deterministic `parent + period` (gov5) or wall clock ≥ `parent + 1` (n42-rs), and what
  future tolerance on import?
- **O5 Header validity strictness.** Make Ethereum's base-fee and gas-limit-ramp checks a native-chain rule
  for every client from an activation time (R4), and move the gas-limit target into the chainspec (A23)?
- **O6 Unchanged-account rule.** Make `unchangedAccountNoOpTime` mandatory in every native chainspec, and decide
  the activation time for chains 94/95.
- **O7 Deferred depth and frame blocks.** One chainspec-sourced depth with one transition rule (gov5's
  per-height `FROM/PREV` or n42-rs's "from genesis only")? Are frame blocks single-client forever, or is one
  design to be specified?
- **O8 0x50.** Is Ed25519 (0x50) meant for the shared native chain (then gov5 must implement it) or Rust-only chains?
- **O9 n42-26's role.** Full producer on native chains (needs R9-R11, deferred execution, QC embedding) or a
  follower/legacy-profile client only? This decides how much of section 1 n42-26 must meet.
- **O10 Equivocation and slashing.** Evidence format only, or slashing on chain (gov5's executor exists but is not wired)?
- **O11 Block access list hash** at Amsterdam (HEADER_FIELD_PARITY §10 Q1).
- **O12 Where this standard lives**: merge into SYNC as one "N42 native chain standard" (sections production +
  sync), or keep two documents with this one citing SYNC.
