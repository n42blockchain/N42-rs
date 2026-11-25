// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Starting a QMDB node at a chain's head instead of at its genesis.
//!
//! A member joining a long chain cannot afford to re-execute it: its
//! execution layer is fed over the Engine API and that path starts at
//! genesis. What it can take instead is the chain's state at the head —
//! gov5's `n42-reth-state-dump` writes it as reth's `init-state` JSONL plus
//! the head's header as RLP, and `n42-qmdb-export` writes the QMDB slot log
//! as the cross-client portable snapshot — and start from there. `init`
//! builds a datadir from those three files; `export` writes the same three
//! from a datadir, which is how a Rust node hands its state on.
//!
//! reth's own `init-state --without-evm` does the same for Ethereum, up to
//! one thing: it recomputes the Merkle root and compares it with the header,
//! and on a QMDB chain the header's root is the forest's, not the trie's. So
//! the header check here is against the forest rebuilt from the portable
//! snapshot, and the trie tables stay empty, as they are on any QMDB node.
//! That forest also authenticates the dump: every account and slot written
//! must be its leaf, and every live leaf must be written (gov5's exporter
//! makes the same two checks, `verifyExportValue` / `verifyExportCoverage`).

use alloy_consensus::Header;
use alloy_genesis::GenesisAccount;
use alloy_primitives::{Address, B256};
use clap::{Parser, Subcommand};
use eyre::{bail, Context as _};
use n42::snapshot_bundle as bundle;
use n42_engine_types::N42Node;
use n42_qmdb_reth::{state_scheme, N42ChainSpecParser, QmdbNodeState, StateScheme};
use n42_twig_core::qmdb_compat::{
    encode_gov5_account_value, gov5_account_key, gov5_storage_key, PortableFormat, QmdbCompatTree, QmdbPortableTree,
    verify_portable_stream,
};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::{
    common::{AccessRights, Environment, EnvironmentArgs},
    init_state::without_evm::setup_without_evm,
};
use alloy_primitives::{keccak256, map::B256Set, U256};
use reth_db_api::{
    cursor::DbCursorRW,
    models::{
        storage_sharded_key::StorageShardedKey, AccountBeforeTx, IntegerList, ShardedKey,
        StorageBeforeTx,
    },
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_primitives_traits::{Account, Bytecode, SealedHeader, StorageEntry};
use reth_provider::{
    providers::StaticFileWriter as _, BlockHashReader, BlockNumReader, DBProvider,
    DatabaseProviderFactory, HeaderProvider, RocksDBProviderFactory, StaticFileProviderFactory,
    StorageSettingsCache,
};
use reth_static_file_types::StaticFileSegment;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[command(name = "n42-init-snapshot", about = "Start a QMDB node from a chain's head")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Builds an empty datadir at the snapshot's block.
    Init(InitArgs),
    /// Writes a datadir's head state as a snapshot.
    Export(ExportArgs),
    /// Completes an exported bundle with its anchor: header P+1, the
    /// `CommitQC` on P+1 or later and the headers below it (`commit-qc.bin`),
    /// and the manifest.
    Anchor(AnchorArgs),
}

#[derive(Debug, Parser)]
struct AnchorArgs {
    /// The chain (a genesis path).
    #[arg(long, value_name = "CHAIN_OR_PATH")]
    chain: String,
    /// The bundle directory `export --bundle` wrote.
    #[arg(long, value_name = "DIR")]
    bundle: PathBuf,
    /// Headers max(P-255, 1)..P+k, k past the first one embedding a `CommitQC`
    /// on P+1 or later (hex lines, e.g. `debug_getRawHeader`, or raw RLP).
    #[arg(long, value_name = "HEADERS")]
    headers: PathBuf,
}

/// [`N42ChainSpecParser`] over the node's header: the node type opened here
/// stores `N42Header`, so its chain spec is [`n42_header::N42ChainSpec`].
#[derive(Debug, Clone, Copy, Default)]
struct SnapshotChainSpecParser;

impl reth_cli::chainspec::ChainSpecParser for SnapshotChainSpecParser {
    type ChainSpec = n42_header::N42ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] =
        <N42ChainSpecParser as reth_cli::chainspec::ChainSpecParser>::SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<std::sync::Arc<Self::ChainSpec>> {
        let spec = <N42ChainSpecParser as reth_cli::chainspec::ChainSpecParser>::parse(s)?;
        Ok(std::sync::Arc::new(n42_header::N42ChainSpec::from(spec)))
    }
}

#[derive(Debug, Parser)]
struct InitArgs {
    #[command(flatten)]
    env: EnvironmentArgs<SnapshotChainSpecParser>,
    /// reth `init-state` JSONL: `{"root": ...}` then one account per line.
    #[arg(long, value_name = "STATE_JSONL", required_unless_present = "bundle")]
    state: Option<PathBuf>,
    /// The head's header, RLP (raw or hex).
    #[arg(long, value_name = "HEADER_RLP", required_unless_present = "bundle")]
    header: Option<PathBuf>,
    /// The cross-client portable QMDB snapshot at the same head.
    #[arg(long, value_name = "SNAPSHOT", required_unless_present = "bundle")]
    qmdb: Option<PathBuf>,
    /// A profile-1 snapshot bundle directory (gov5's layout,
    /// `bin/n42/src/snapshot_bundle.rs`): stands for the four files and the
    /// `CommitQC`, and its manifest is checked.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["state", "header", "qmdb", "anchor", "commit_qc"])]
    bundle: Option<PathBuf>,
    /// Under deferred execution (depth 1): the head's child N+1 and the
    /// headers after it, RLP (raw, concatenated, or one hex string per line;
    /// e.g. `debug_getRawHeader` of N+1..N+4 from a member). Header N carries
    /// the state after N-1; the state after N, which the snapshot holds, is
    /// certified by N+1, and so are N's receipts root, bloom, gas used and
    /// requests hash. N+1 is trusted only once a `CommitQC` names it or a
    /// descendant: one embedded in a later header of this file, or `--commit-qc`.
    #[arg(long, value_name = "HEADERS_RLP")]
    anchor: Option<PathBuf>,
    /// Headers below the head, up to max(N-255, 1)..N-1 (hex lines or raw
    /// RLP): written as the real headers of those numbers, so BLOCKHASH reads
    /// the right hashes; a bundle supplies them from `commit-qc.bin`.
    #[arg(long, value_name = "HEADERS_RLP", conflicts_with = "bundle")]
    ancestors: Option<PathBuf>,
    /// A `CommitQC` (gov5's wire encoding, raw or hex) naming N+1 or a later
    /// header of `--anchor`, when no anchor header embeds one.
    #[arg(long, value_name = "QC")]
    commit_qc: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct ExportArgs {
    #[command(flatten)]
    env: EnvironmentArgs<SnapshotChainSpecParser>,
    /// Where the state JSONL (reth `init-state`, gov5's `n42-reth-state-dump`
    /// format) goes; the head's header goes to `<out>.header.rlp`.
    #[arg(long, value_name = "STATE_JSONL", required_unless_present = "bundle")]
    out: Option<PathBuf>,
    /// Where the portable QMDB snapshot goes.
    #[arg(long, value_name = "SNAPSHOT", required_unless_present = "bundle")]
    qmdb_out: Option<PathBuf>,
    /// Write gov5's bundle layout into this directory instead
    /// (`state.jsonl`, `state.jsonl.header.rlp`, `qmdb.bin`, `block.rlp`);
    /// `anchor` adds `next-header.rlp`, `commit-qc.bin` and `bundle.json`.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["out", "qmdb_out"])]
    bundle: Option<PathBuf>,
    /// The portable layout: `v1` (every slot's key and value; refused on a
    /// compacted tree) or `v2` (the tombstone layout,
    /// `docs/QMDB_COMPACTION_DESIGN.md` section 6). Unset: v1, or v2 when the
    /// tree has compacted twigs.
    #[arg(long, value_name = "v1|v2")]
    format: Option<PortableFormat>,
}

/// One account line of the JSONL, as reth's `init-state` reads it.
#[derive(Debug, serde::Deserialize)]
struct DumpLine {
    address: Address,
    #[serde(flatten)]
    account: GenesisAccount,
}

#[derive(Debug, serde::Deserialize)]
struct RootLine {
    root: B256,
}

/// Accounts plus storage slots written before a commit.
const COMMIT_UNITS: usize = 100_000;

/// A header from a file holding its RLP, raw or as hex. It is decoded as
/// [`n42_header::N42Header`], so a head that carries gov5's
/// `mobileRegistryRoot` (element 24, `MobileAnchor` + Glamsterdam) keeps it and
/// hashes to the chain's block hash; a header without one decodes as before.
fn read_header_from_file(path: &std::path::Path) -> eyre::Result<n42_header::N42Header> {
    let bytes = fs::read(path).wrap_err("header file")?;
    let text = std::str::from_utf8(&bytes).map(str::trim).unwrap_or("");
    let rlp = if text.starts_with("0x") || text.chars().all(|c| c.is_ascii_hexdigit()) && !text.is_empty() {
        alloy_primitives::hex::decode(text).wrap_err("header hex")?
    } else {
        bytes
    };
    let mut cursor = rlp.as_slice();
    let header = <n42_header::N42Header as alloy_rlp::Decodable>::decode(&mut cursor).wrap_err("header RLP")?;
    if !cursor.is_empty() {
        bail!("header file has {} trailing bytes", cursor.len());
    }
    Ok(header)
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let runner = reth_cli_runner::CliRunner::try_default_runtime()?;
    let runtime = runner.runtime();
    match cli.command {
        Command::Init(args) => init(args, runtime),
        Command::Export(args) => export(args, runtime),
        Command::Anchor(args) => anchor(args),
    }
}

fn require_qmdb(chain: &reth_chainspec::ChainSpec) -> eyre::Result<()> {
    if state_scheme(&chain.genesis) != StateScheme::Qmdb {
        bail!("the chain does not use the QMDB state scheme; reth's own `init-state` serves it");
    }
    Ok(())
}

fn init(args: InitArgs, runtime: reth_tasks::Runtime) -> eyre::Result<()> {
    let chain = args.env.chain.clone();
    require_qmdb(&chain)?;
    let Environment { provider_factory, data_dir, .. } =
        args.env.init::<N42Node>(AccessRights::RW, runtime)?;

    let (state_path, header_path, qmdb_path) = match &args.bundle {
        Some(dir) => (dir.join(bundle::STATE), dir.join(bundle::HEADER), dir.join(bundle::QMDB)),
        None => (
            args.state.clone().ok_or_else(|| eyre::eyre!("--state"))?,
            args.header.clone().ok_or_else(|| eyre::eyre!("--header"))?,
            args.qmdb.clone().ok_or_else(|| eyre::eyre!("--qmdb"))?,
        ),
    };
    let header = read_header_from_file(&header_path)?;
    let hash = header.hash_slow();
    let number = header.number;
    let (anchor, ancestors) = match &args.bundle {
        Some(dir) => {
            let (anchor, ancestors) = bundle_anchor(&chain, dir, &header)?;
            (Some(anchor), ancestors)
        }
        None => (
            anchor_for(&chain, &header, args.anchor.as_deref(), args.commit_qc.as_deref())?,
            match &args.ancestors {
                Some(path) => {
                    let mut headers = read_headers_from_file(path)?;
                    headers.sort_by_key(|h| h.number);
                    headers
                }
                None => Vec::new(),
            },
        ),
    };
    check_ancestors(&header, &ancestors, chain.genesis_hash())?;
    // The state after the head: its own header's root before deferred
    // execution, its child's past it (SYNC §5.3.1).
    let root = anchor.as_ref().map_or(header.state_root, |anchor| anchor.state_root);
    println!("head: block {number} {hash} state root {root}");

    // The chain up to the head: dummy headers below it, the head itself, and
    // every stage checkpointed there.
    {
        let provider_rw = provider_factory.database_provider_rw()?;
        let last = provider_rw.last_block_number()?;
        if last == 0 && number > 0 {
            // The head is stored as read, registry root included; the dummy
            // headers below it are Ethereum's and carry none.
            if ancestors.is_empty() {
                setup_without_evm(&provider_rw, SealedHeader::new(header, hash), |n| {
                    n42_header::N42Header::from(Header { number: n, ..Default::default() })
                })?;
            } else {
                setup_with_ancestors(&provider_rw, SealedHeader::new(header, hash), &ancestors)?;
            }
            provider_factory.static_file_provider().commit()?;
        } else if last != number {
            bail!("the datadir is at block {last}, the snapshot at {number}; init needs an empty datadir");
        }
        provider_rw.commit()?;
    }

    // The state. reth 2.5's storage keeps state hashed, with the changesets in
    // static files and the history indices in RocksDB; the plain tables are
    // not used. This is reth's own `init-state` path (`dump_state_v2`) with
    // the Merkle root check left out.
    {
        let settings = provider_factory.database_provider_rw()?.cached_storage_settings();
        if !settings.storage_v2 {
            bail!("the datadir uses reth's legacy storage layout; only the current layout is supported");
        }
    }
    let reader = BufReader::new(fs::File::open(&state_path).wrap_err("state file")?);
    let mut lines = reader.lines();
    let first = lines.next().ok_or_else(|| eyre::eyre!("state file is empty"))??;
    let dump_root: RootLine = serde_json::from_str(&first).wrap_err("first line must be {\"root\": ...}")?;
    if dump_root.root != root {
        bail!("state dump root {} is not the header's state root {root}", dump_root.root);
    }
    // The dump's first line is its own word; the portable snapshot, checked
    // against the header, is what authenticates each row (audit 2026-10
    // round 3, R3-P1).
    let portable = fs::read(&qmdb_path).wrap_err("portable snapshot")?;
    // Profile 1 refuses a 0x01 snapshot; any unknown layout fails verification below.
    profile1_format(&chain.genesis, PortableFormat::detect(&portable))?;
    let tree = authenticated_tree(&portable, &chain, (number, hash), root)?;
    let mut check = DumpCheck::new(&tree);
    let (accounts, slots) = write_state_v2(&provider_factory, number, lines, |address, account| {
        check.row(address, account)
    })?;
    check.finish()?;
    drop(tree);
    println!("state: {accounts} accounts, {slots} slots, every one a leaf of the snapshot");

    // The forest, from the portable snapshot, checked against the header.
    // A 0x03 snapshot carries dead slots as tombstones (leaf hash only),
    // which only the file mode holds; the node keeps that mode at start
    // (`QmdbNodeState::new` reads the checkpoint it leaves).
    // Profile 1 only: elsewhere the mode stays `N42_QMDB_ENTRY_FILE`'s, as before.
    let file_mode = if n42_qmdb_reth::profile1::is_profile1(&chain.genesis) {
        PortableFormat::detect(&portable) == Some(PortableFormat::V2)
    } else {
        n42_env::flag("N42_QMDB_ENTRY_FILE", false)
    };
    let qmdb = QmdbNodeState::new_with_entry_file(chain.inner().clone(), data_dir.data_dir().join("qmdb"), file_mode);
    qmdb.initialize_from_portable(&portable, chain.chain().id(), chain.genesis_hash(), (number, hash), root)?;
    if let Some(anchor) = anchor {
        let mut rlp = Vec::new();
        alloy_rlp::Encodable::encode(&anchor, &mut rlp);
        let path = n42::snapshot_anchor::anchor_path(&data_dir.data_dir().join("qmdb"));
        fs::write(&path, &rlp).wrap_err("anchor file")?;
        println!("anchor: block {} {} -> {}", anchor.number, anchor.hash_slow(), path.display());
    }
    println!("QMDB forest restored at block {number}; the node can start");
    Ok(())
}

/// The portable layout on this chain: on profile 1 only `0x03` (P5 removes
/// `0x01`, `MIXED_PRODUCTION_STANDARD_V1_RC` §3), so an unset format is V2 and
/// V1 is refused; elsewhere `format` as given.
fn profile1_format(genesis: &alloy_genesis::Genesis, format: Option<PortableFormat>) -> eyre::Result<Option<PortableFormat>> {
    let profile1 = n42_qmdb_reth::profile1::profile1(genesis).map_err(|e| eyre::eyre!("{e}"))?.is_some();
    match (profile1, format) {
        (true, Some(PortableFormat::V1)) => bail!("profile 1 has no portable 0x01 snapshot (P5); use the 0x03 layout (v2)"),
        (true, _) => Ok(Some(PortableFormat::V2)),
        (false, format) => Ok(format),
    }
}

/// Header RLPs from a file: one hex string per line, or raw RLP items back
/// to back.
fn read_headers_from_file(path: &std::path::Path) -> eyre::Result<Vec<n42_header::N42Header>> {
    let bytes = fs::read(path).wrap_err_with(|| format!("{}", path.display()))?;
    let text = std::str::from_utf8(&bytes).ok().filter(|text| {
        let t = text.trim();
        !t.is_empty() && t.split_whitespace().all(|w| w.trim_start_matches("0x").chars().all(|c| c.is_ascii_hexdigit()))
    });
    let blobs: Vec<Vec<u8>> = match text {
        Some(text) => text
            .split_whitespace()
            .map(|w| alloy_primitives::hex::decode(w).wrap_err("header hex"))
            .collect::<eyre::Result<_>>()?,
        None => vec![bytes],
    };
    let mut headers = Vec::new();
    for blob in blobs {
        let mut cursor = blob.as_slice();
        while !cursor.is_empty() {
            headers.push(<n42_header::N42Header as alloy_rlp::Decodable>::decode(&mut cursor).wrap_err("header RLP")?);
        }
    }
    Ok(headers)
}

/// A file holding bytes, raw or as hex.
fn read_bytes_or_hex(path: &std::path::Path) -> eyre::Result<Vec<u8>> {
    let bytes = fs::read(path).wrap_err_with(|| format!("{}", path.display()))?;
    match std::str::from_utf8(&bytes).map(str::trim) {
        Ok(text) if !text.is_empty() && text.trim_start_matches("0x").chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(alloy_primitives::hex::decode(text)?)
        }
        _ => Ok(bytes),
    }
}

/// The anchor of a bundle (`dir`) at `header`: the manifest (format, chain,
/// genesis, sha256 of every file, pivot), `commit-qc.bin`'s headers linking
/// from the QC's block down (to genesis when they reach block 1) and holding
/// header P and `next-header.rlp` as P+1, and [`check_anchor_chain`] on
/// P+1.. with the payload's QC. Returns header P+1.
fn bundle_anchor(
    chain: &n42_header::N42ChainSpec,
    dir: &std::path::Path,
    header: &n42_header::N42Header,
) -> eyre::Result<(n42_header::N42Header, Vec<n42_header::N42Header>)> {
    let genesis = chain.genesis();
    if !reth_chainspec::qmdb::deferred_execution_active_at(genesis, header.timestamp)
        || reth_chainspec::qmdb::deferred_execution_depth_at(genesis, header.timestamp) != 1
    {
        bail!("a snapshot bundle is for a chain under deferred execution at depth 1");
    }
    let manifest = bundle::check_manifest(dir, chain.chain().id(), chain.genesis_hash())?;
    let hash = header.hash_slow();
    if (manifest.pivot_number, manifest.pivot_hash) != (header.number, hash) {
        bail!("bundle manifest pivot {} {} is not header {} {hash}", manifest.pivot_number, manifest.pivot_hash, header.number);
    }
    let next = read_header_from_file(&dir.join(bundle::NEXT_HEADER))?;
    let (qc, descending) = bundle::decode_commit_qc_payload(&fs::read(dir.join(bundle::COMMIT_QC))?)?;
    bundle::check_descending_links(&descending, chain.genesis_hash())?;
    if descending.iter().find(|h| h.number == header.number + 1) != Some(&next) {
        bail!("commit-qc.bin does not hold next-header.rlp as block {}", header.number + 1);
    }
    if descending.iter().any(|h| h.number == header.number && h != header) {
        bail!("commit-qc.bin's block {} is not the bundle's header", header.number);
    }
    let mut ancestors: Vec<_> = descending.iter().filter(|h| h.number < header.number).cloned().collect();
    ancestors.reverse();
    let mut anchors: Vec<_> = descending.into_iter().filter(|h| h.number > header.number).collect();
    anchors.reverse();
    let rules = n42_engine_types::hotstuff_consensus::chain_header_rules(chain);
    let named = check_anchor_chain(&rules, (header.number, hash), &anchors, Some(&qc))?;
    if (named, manifest.post_state_root) != (manifest.anchor_block_number, next.state_root) {
        bail!(
            "bundle manifest: anchor block {} / root {}, the payload certifies block {named} / root {}",
            manifest.anchor_block_number,
            manifest.post_state_root,
            next.state_root
        );
    }
    println!("bundle: pivot {} certified by a CommitQC on block {named}", header.number);
    Ok((next, ancestors))
}

/// Checks that `ancestors` (ascending) are the headers right below `header`:
/// contiguous, ending at its parent, linked, and extending the genesis when
/// they reach block 1. Empty is allowed (dummy headers, zero hashes).
fn check_ancestors(header: &n42_header::N42Header, ancestors: &[n42_header::N42Header], genesis_hash: B256) -> eyre::Result<()> {
    let mut child = (header.number, header.parent_hash);
    for ancestor in ancestors.iter().rev() {
        if ancestor.number + 1 != child.0 || ancestor.hash_slow() != child.1 {
            bail!("ancestor header {} is not the parent of block {}", ancestor.number, child.0);
        }
        child = (ancestor.number, ancestor.parent_hash);
    }
    if !ancestors.is_empty() && child.0 == 1 && child.1 != genesis_hash {
        bail!("ancestor header 1 does not extend the genesis {genesis_hash}");
    }
    Ok(())
}

/// reth's `setup_without_evm` with real headers: blocks 1..P-1 empty in
/// every segment, but the headers `ancestors` (contiguous, ending at P-1)
/// stored with their own hashes, so `BLOCKHASH` over them reads what a full
/// node reads; dummy headers (zero hash) only below them. Then the head and
/// the stage checkpoints, as upstream does.
fn setup_with_ancestors<Provider>(
    provider_rw: &Provider,
    head: SealedHeader<n42_header::N42Header>,
    ancestors: &[n42_header::N42Header],
) -> eyre::Result<()>
where
    Provider: StaticFileProviderFactory<Primitives = n42_tx_types::N42Primitives>
        + DBProvider<Tx: DbTxMut>
        + reth_provider::StageCheckpointWriter
        + reth_provider::BlockWriter<Block = n42_tx_types::Block>,
{
    let sf = provider_rw.static_file_provider();
    let last = head.number - 1;
    for segment in [StaticFileSegment::Transactions, StaticFileSegment::Receipts, StaticFileSegment::TransactionSenders] {
        if sf.get_highest_static_file_block(segment).is_none() {
            continue;
        }
        let mut writer = sf.latest_writer(segment)?;
        for number in 1..=last {
            writer.increment_block(number)?;
        }
    }
    {
        let lowest = ancestors.first().map_or(head.number, |h| h.number);
        let mut writer = sf.latest_writer(StaticFileSegment::Headers)?;
        for number in 1..lowest {
            writer.append_header(&n42_header::N42Header::from(Header { number, ..Default::default() }), &B256::ZERO)?;
        }
        for ancestor in ancestors {
            writer.append_header(ancestor, &ancestor.hash_slow())?;
        }
    }
    // The hash -> number index, so the ancestors are found by hash too
    // (RPC, block_by_hash lookups); the dummies below stay unindexed.
    for ancestor in ancestors {
        provider_rw.tx_ref().put::<tables::HeaderNumbers>(ancestor.hash_slow(), ancestor.number)?;
    }
    let block = reth_primitives_traits::SealedBlock::<n42_tx_types::Block>::from_sealed_parts(head.clone(), Default::default())
        .try_recover()
        .map_err(|e| eyre::eyre!("{e}"))?;
    provider_rw.insert_block(&block)?;
    sf.latest_writer(StaticFileSegment::Receipts)?.increment_block(head.number)?;
    for stage in reth_stages_types::StageId::ALL {
        provider_rw.save_stage_checkpoint(stage, reth_stages_types::StageCheckpoint::new(head.number))?;
    }
    Ok(())
}

/// The anchor a snapshot at `header` needs: `None` before deferred execution
/// (the head's own header certifies its state), the head's child at depth 1,
/// once [`check_anchor_chain`] holds. A depth-2 chain is refused, as is a
/// missing anchor.
fn anchor_for(
    chain: &n42_header::N42ChainSpec,
    header: &n42_header::N42Header,
    anchor: Option<&std::path::Path>,
    commit_qc: Option<&std::path::Path>,
) -> eyre::Result<Option<n42_header::N42Header>> {
    let genesis = chain.genesis();
    if !reth_chainspec::qmdb::deferred_execution_active_at(genesis, header.timestamp) {
        if anchor.is_some() || commit_qc.is_some() {
            bail!("--anchor is for a chain under deferred execution; at block {} this one is not", header.number);
        }
        return Ok(None);
    }
    let depth = reth_chainspec::qmdb::deferred_execution_depth_at(genesis, header.timestamp);
    if depth != 1 {
        bail!("deferred execution depth {depth}: a snapshot join supports depth 1 only");
    }
    let Some(path) = anchor else {
        bail!(
            "the chain defers execution: the state after block {} is certified by block {}'s header; pass it as --anchor",
            header.number,
            header.number + 1
        );
    };
    let headers = read_headers_from_file(path)?;
    let qc = commit_qc.map(read_bytes_or_hex).transpose()?;
    let rules = n42_engine_types::hotstuff_consensus::chain_header_rules(chain);
    let named = check_anchor_chain(&rules, (header.number, header.hash_slow()), &headers, qc.as_deref())?;
    println!("anchor: block {} certified by a CommitQC on block {named}", header.number + 1);
    Ok(headers.into_iter().next())
}

/// Checks the anchor chain of a snapshot at `head`: `headers` start at the
/// head's child and link parent to child; each passes the chain's header
/// rules (on profile 1: the fields, the proposer's seal and any embedded QC,
/// a commit-domain QC of the genesis set, B1/B2/E13); and a `CommitQC` names
/// one of them -- `commit_qc` if given, else one embedded in a later header
/// (SYNC §5.3.1: a `CommitQC` on a block at or past P+k). Returns the number of
/// the block the QC names.
fn check_anchor_chain(
    rules: &n42_h2_consensus::HeaderRules,
    head: (u64, B256),
    headers: &[n42_header::N42Header],
    commit_qc: Option<&[u8]>,
) -> eyre::Result<u64> {
    let Some(first) = headers.first() else { bail!("--anchor holds no header") };
    n42::snapshot_anchor::check_child(first, head)?;
    let hashes: Vec<B256> = headers.iter().map(|h| h.hash_slow()).collect();
    for (i, h) in headers.iter().enumerate() {
        if i > 0 && (h.number != headers[i - 1].number + 1 || h.parent_hash != hashes[i - 1]) {
            bail!("--anchor: header {} does not follow header {}", h.number, headers[i - 1].number);
        }
        rules.check_header(h).map_err(|e| eyre::eyre!("--anchor: header {}: {e}", h.number))?;
    }
    let (Some(schedule), Some(identity)) = (&rules.proposers, rules.chain) else {
        bail!("the chain has no profile-1 validator set to check a CommitQC against");
    };
    let verify = |qc: &[u8]| -> eyre::Result<Option<u64>> {
        let extra = n42_h2_consensus::HeaderExtra { view: 0, qc: qc.to_vec(), seal: None };
        n42_h2_consensus::header_rules::verify_profile1_qc(&extra, schedule, identity).map_err(|e| eyre::eyre!("CommitQC: {e}"))?;
        let wire = n42_h2_wire::h2_wire::decode_h2_qc(qc).map_err(|e| eyre::eyre!("CommitQC: {e}"))?;
        Ok(hashes.iter().position(|hash| *hash == wire.block_hash).map(|i| headers[i].number))
    };
    if let Some(qc) = commit_qc {
        return verify(qc)?.ok_or_else(|| eyre::eyre!("--commit-qc names no header of --anchor"));
    }
    for h in &headers[1..] {
        let extra = n42_h2_consensus::decode_profile1_extra(&h.extra_data).map_err(|e| eyre::eyre!("{e}"))?;
        if extra.qc.is_empty() {
            continue;
        }
        if let Some(number) = verify(&extra.qc)? {
            return Ok(number);
        }
    }
    bail!(
        "no CommitQC names block {} or a later header of --anchor: pass more headers after it, or --commit-qc",
        first.number
    )
}

/// The portable snapshot's tree, once it is known to be at `head` on this
/// chain with the header's `root`.
fn authenticated_tree(
    portable: &[u8],
    chain: &reth_chainspec::ChainSpec,
    head: (u64, B256),
    root: B256,
) -> eyre::Result<QmdbCompatTree> {
    // Either layout: v1, or v2 whose tombstones rebuild as hash-only slots.
    // The stream is authenticated first with bounded memory (chain, genesis,
    // head and root), so a malformed snapshot is refused before `decode`
    // expands its dead twigs into placeholder slots.
    let verified = verify_portable_stream(portable, chain.chain().id(), &chain.genesis_hash().0)
        .map_err(|e| eyre::eyre!("portable snapshot: {e}"))?;
    let at = (verified.block_number, B256::from(verified.block_hash));
    if at != head {
        bail!("the portable snapshot is at block {} {}, the header at {} {}", at.0, at.1, head.0, head.1);
    }
    if B256::from(verified.root) != root {
        bail!("the portable snapshot's root {} is not the header's state root {root}", B256::from(verified.root));
    }
    let (_, snapshot) = QmdbPortableTree::decode(portable).map_err(|e| eyre::eyre!("portable snapshot: {e}"))?;
    let at = (snapshot.block_number, B256::from(snapshot.block_hash));
    if at != head {
        bail!("the portable snapshot is at block {} {}, the header at {} {}", at.0, at.1, head.0, head.1);
    }
    let tree = snapshot
        .verify_and_build(chain.chain().id(), &chain.genesis_hash().0)
        .map_err(|e| eyre::eyre!("portable snapshot: {e}"))?;
    if B256::from(tree.root()) != root {
        bail!("the portable snapshot's root {} is not the header's state root {root}", B256::from(tree.root()));
    }
    Ok(tree)
}

/// Checks a state dump row by row against the snapshot's tree: each account
/// and non-zero slot must be the tree's leaf, addresses strictly ascending
/// (so no row is counted twice), and at the end every live leaf must have
/// been a row but for the EIP-161 empty accounts QMDB keeps and the plain
/// state, which the dump is read from, drops.
struct DumpCheck<'a> {
    tree: &'a QmdbCompatTree,
    last: Option<Address>,
    /// Leaves the rows matched.
    matched: u64,
    /// Rows that were empty accounts (leaf value `[0]`).
    empty_rows: u64,
}

/// gov5's leaf for an account with no nonce, balance or code.
const EMPTY_ACCOUNT_LEAF: [u8; 1] = [0];

impl<'a> DumpCheck<'a> {
    const fn new(tree: &'a QmdbCompatTree) -> Self {
        Self { tree, last: None, matched: 0, empty_rows: 0 }
    }

    fn row(&mut self, address: &Address, account: &GenesisAccount) -> eyre::Result<()> {
        if self.last.is_some_and(|last| last >= *address) {
            bail!("state dump rows must be in strictly ascending address order: {address} after {:?}", self.last);
        }
        self.last = Some(*address);
        let code_hash = account.code.as_ref().map_or(alloy_primitives::KECCAK256_EMPTY, keccak256);
        let leaf = encode_gov5_account_value(
            account.nonce.unwrap_or_default(),
            &account.balance.to_be_bytes::<32>(),
            &code_hash.0,
        );
        if self.tree.get(&gov5_account_key(&address.0 .0)) != Some(leaf.as_slice()) {
            bail!("account {address} is not authenticated by the QMDB root");
        }
        self.matched += 1;
        if leaf == EMPTY_ACCOUNT_LEAF {
            self.empty_rows += 1;
        }
        for (slot, value) in account.storage.iter().flatten() {
            let committed = self.tree.get(&gov5_storage_key(&address.0 .0, &slot.0));
            let expected = (*value != B256::ZERO).then_some(value.as_slice());
            if committed != expected {
                bail!("storage {address} {slot} is not authenticated by the QMDB root");
            }
            self.matched += u64::from(expected.is_some());
        }
        Ok(())
    }

    fn finish(self) -> eyre::Result<()> {
        let retained_empty = (0..self.tree.next_slot())
            .filter(|slot| self.tree.slot_active(*slot) == Some(true))
            .filter(|slot| self.tree.entry_at(*slot).is_some_and(|entry| entry.value == EMPTY_ACCOUNT_LEAF))
            .count() as u64;
        let live = self.tree.len() as u64;
        if self.empty_rows > retained_empty || self.matched != live - retained_empty + self.empty_rows {
            bail!(
                "the state dump is incomplete: {} rows for {live} live QMDB keys ({retained_empty} retained empty accounts)",
                self.matched
            );
        }
        Ok(())
    }
}

/// Writes the accounts of a state dump at `block`, as reth 2.5 stores them:
/// hashed accounts and storage in MDBX, one changeset entry per account and
/// slot ("created at `block`") in the static files, the history indices in
/// `RocksDB`, bytecodes once. Chunked commits keep memory flat. `check` sees
/// each account before it is written.
fn write_state_v2<PF>(
    provider_factory: &PF,
    block: u64,
    lines: impl Iterator<Item = std::io::Result<String>>,
    mut check: impl FnMut(&Address, &GenesisAccount) -> eyre::Result<()>,
) -> eyre::Result<(u64, u64)>
where
    PF: DatabaseProviderFactory<
        ProviderRW: StaticFileProviderFactory
                        + DBProvider<Tx: DbTxMut>
                        + StorageSettingsCache
                        + RocksDBProviderFactory
                        + reth_provider::NodePrimitivesProvider,
    >,
{
    let history_list = IntegerList::new([block])?;
    let mut seen_bytecodes: B256Set = B256Set::default();
    let mut provider_rw = provider_factory.database_provider_rw()?;
    let static_file_provider = provider_rw.static_file_provider();
    let rocksdb_provider = provider_rw.rocksdb_provider();
    let mut history_batch = rocksdb_provider.batch_with_auto_commit();
    // A fresh datadir has no changesets; a segment file that starts below
    // the head would put the head's entries in the wrong file.
    for segment in [StaticFileSegment::AccountChangeSets, StaticFileSegment::StorageChangeSets] {
        if let Some(highest) = static_file_provider.get_highest_static_file_block(segment)
            && highest < block
        {
            static_file_provider.delete_segment(segment)?;
        }
    }
    let (mut accounts, mut slots, mut units) = (0u64, 0u64, 0usize);
    {
        let mut account_writer =
            static_file_provider.get_writer(block, StaticFileSegment::AccountChangeSets)?;
        let mut storage_writer =
            static_file_provider.get_writer(block, StaticFileSegment::StorageChangeSets)?;
        for empty in account_writer.next_block_number()..block {
            account_writer.append_account_changeset(Vec::new(), empty)?;
        }
        account_writer.begin_account_changeset(block)?;
        for empty in storage_writer.next_block_number()..block {
            storage_writer.append_storage_changeset(Vec::new(), empty)?;
        }
        storage_writer.begin_storage_changeset(block)?;

        for line in lines {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let parsed: DumpLine = serde_json::from_str(&line).wrap_err("account line")?;
            check(&parsed.address, &parsed.account)?;
            let account_slots = parsed.account.storage.as_ref().map_or(0, |s| s.len());
            if units > 0 && units + 1 + account_slots > COMMIT_UNITS {
                history_batch.commit()?;
                DbTx::commit(provider_rw.into_tx())?;
                provider_rw = provider_factory.database_provider_rw()?;
                history_batch = rocksdb_provider.batch_with_auto_commit();
                seen_bytecodes = B256Set::default();
                units = 0;
                println!("written: {accounts} accounts, {slots} slots");
            }
            let tx = provider_rw.tx_ref();
            let address = parsed.address;
            let genesis_account = &parsed.account;
            let bytecode_hash = match &genesis_account.code {
                Some(code) => {
                    let bytecode = Bytecode::new_raw_checked(code.clone())
                        .map_err(|e| eyre::eyre!("invalid bytecode for {address}: {e}"))?;
                    let hash = bytecode.hash_slow();
                    if seen_bytecodes.insert(hash) {
                        tx.put::<tables::Bytecodes>(hash, bytecode)?;
                    }
                    Some(hash)
                }
                None => None,
            };
            let account = Account {
                nonce: genesis_account.nonce.unwrap_or_default(),
                balance: genesis_account.balance,
                bytecode_hash,
            };
            let hashed_address = keccak256(address);
            tx.put::<tables::HashedAccounts>(hashed_address, account)?;
            account_writer.append_account_changeset_entry(AccountBeforeTx { address, info: None })?;
            history_batch.put::<tables::AccountsHistory>(ShardedKey::new(address, u64::MAX), &history_list)?;
            if let Some(storage) = &genesis_account.storage {
                let mut hashed_storage = tx.cursor_dup_write::<tables::HashedStorages>()?;
                for (&key, &value) in storage {
                    let value = U256::from_be_bytes(value.0);
                    hashed_storage.upsert(hashed_address, &StorageEntry { key: keccak256(key), value })?;
                    storage_writer.append_storage_changeset_entry(StorageBeforeTx {
                        address,
                        key,
                        value: U256::ZERO,
                    })?;
                    history_batch.put::<tables::StoragesHistory>(
                        StorageShardedKey::new(address, key, u64::MAX),
                        &history_list,
                    )?;
                }
            }
            accounts += 1;
            slots += account_slots as u64;
            units += 1 + account_slots;
        }
    }
    history_batch.commit()?;
    DbTx::commit(provider_rw.into_tx())?;
    static_file_provider.finalize()?;
    Ok((accounts, slots))
}

fn export(args: ExportArgs, runtime: reth_tasks::Runtime) -> eyre::Result<()> {
    let chain = args.env.chain.clone();
    require_qmdb(&chain)?;
    let Environment { provider_factory, data_dir, .. } =
        args.env.init::<N42Node>(AccessRights::RO, runtime)?;
    let provider = provider_factory.provider()?;
    let number = provider.last_block_number()?;
    let header = provider
        .header_by_number(number)?
        .ok_or_else(|| eyre::eyre!("no header for block {number}"))?;
    let hash = provider.block_hash(number)?.ok_or_else(|| eyre::eyre!("no hash for block {number}"))?;
    println!("head: block {number} {hash} state root {}", header.state_root);

    let mut header_rlp = Vec::new();
    alloy_rlp::Encodable::encode(&header, &mut header_rlp);
    let (out, qmdb_out, header_path) = match &args.bundle {
        Some(dir) => {
            fs::create_dir_all(dir)?;
            (dir.join(bundle::STATE), dir.join(bundle::QMDB), dir.join(bundle::HEADER))
        }
        None => {
            let out = args.out.clone().ok_or_else(|| eyre::eyre!("--out"))?;
            let header_path = out.with_extension("jsonl.header.rlp");
            (out, args.qmdb_out.clone().ok_or_else(|| eyre::eyre!("--qmdb-out"))?, header_path)
        }
    };
    fs::write(&header_path, &header_rlp)?;

    println!("header -> {}", header_path.display());

    let qmdb = QmdbNodeState::new(chain.inner().clone(), data_dir.data_dir().join("qmdb"));
    let format = profile1_format(&chain.genesis, args.format)?;
    let portable = qmdb.portable_export_as(chain.chain().id(), chain.genesis_hash(), format)?;
    // The forest's persisted head must be the database's: the snapshot and
    // the state rows describe one block. A running node's forest settles
    // ahead of its database; export from a stopped one.
    let verified = verify_portable_stream(portable.as_slice(), chain.chain().id(), &chain.genesis_hash().0)
        .map_err(|e| eyre::eyre!("portable snapshot: {e}"))?;
    if (verified.block_number, B256::from(verified.block_hash)) != (number, hash) {
        bail!(
            "the QMDB forest is at block {} {}, the database at {number} {hash}: export from a stopped node",
            verified.block_number,
            B256::from(verified.block_hash)
        );
    }
    let root = B256::from(verified.root);
    fs::write(&qmdb_out, &portable)?;
    let (accounts, slots) = write_state_dump(&provider, &provider_factory.latest()?, &chain.genesis, number, root, &out)?;
    println!("state: {accounts} accounts, {slots} slots at block {number} (root {root}) -> {}", out.display());
    if let Some(dir) = &args.bundle {
        // Block P in gov5's form, which gov5's importer stores as its head.
        let block = reth_provider::BlockReader::block_by_number(&provider, number)?
            .ok_or_else(|| eyre::eyre!("no block body for block {number}"))?;
        let transactions: Vec<alloy_primitives::Bytes> =
            block.body.transactions.iter().map(|tx| alloy_eips::eip2718::Encodable2718::encoded_2718(tx).into()).collect();
        let rewards = n42_h2_consensus::withdrawals_to_rewards(block.body.withdrawals.as_ref().map_or(&[][..], |w| w.as_slice()));
        let rlp = n42_h2_consensus::block_body::encode_block_rlp_raw(&block.header, &transactions, &rewards, None);
        fs::write(dir.join(bundle::BLOCK), rlp)?;
        println!("block {number} -> {}", dir.join(bundle::BLOCK).display());
    }
    let format = PortableFormat::detect(&portable).map_or_else(|| "?".to_owned(), |format| format.to_string());
    println!("QMDB snapshot ({format}): {} bytes -> {}", portable.len(), qmdb_out.display());
    Ok(())
}

fn anchor(args: AnchorArgs) -> eyre::Result<()> {
    let chain = <SnapshotChainSpecParser as reth_cli::chainspec::ChainSpecParser>::parse(&args.chain)?;
    let dir = &args.bundle;
    let header = read_header_from_file(&dir.join(bundle::HEADER))?;
    let head = (header.number, header.hash_slow());
    let mut headers = read_headers_from_file(&args.headers)?;
    headers.sort_by_key(|h| h.number);
    headers.dedup_by_key(|h| h.number);
    let above: Vec<_> = headers.iter().filter(|h| h.number > head.0).cloned().collect();
    let rules = n42_engine_types::hotstuff_consensus::chain_header_rules(&*chain);
    // The first header past P+1 whose embedded QC names P+1 or later.
    let mut found = None;
    for end in 2..=above.len() {
        let carrier = &above[end - 1];
        let extra = n42_h2_consensus::decode_profile1_extra(&carrier.extra_data).map_err(|e| eyre::eyre!("{e}"))?;
        if extra.qc.is_empty() {
            continue;
        }
        if let Ok(named) = check_anchor_chain(&rules, head, &above[..end - 1], Some(&extra.qc)) {
            found = Some((named, extra.qc));
            break;
        }
    }
    let Some((named, qc)) = found else {
        bail!("no header in --headers embeds a CommitQC on block {} or later; pass more headers", head.0 + 1)
    };
    let wire = n42_h2_wire::h2_wire::decode_h2_qc(&qc).map_err(|e| eyre::eyre!("{e}"))?;
    let lowest = head.0.saturating_sub(255).max(1);
    let mut descending: Vec<_> = headers.iter().filter(|h| h.number >= lowest && h.number <= named).cloned().collect();
    descending.reverse();
    if descending.len() as u64 != named - lowest + 1 {
        bail!("--headers must hold every header {lowest}..={named}");
    }
    bundle::check_descending_links(&descending, chain.genesis_hash())?;
    if descending.iter().find(|h| h.number == head.0).map(|h| h.hash_slow()) != Some(head.1) {
        bail!("--headers' block {} is not the bundle's header", head.0);
    }
    let next = above[0].clone();
    let mut rlp = Vec::new();
    alloy_rlp::Encodable::encode(&next, &mut rlp);
    fs::write(dir.join(bundle::NEXT_HEADER), rlp)?;
    fs::write(dir.join(bundle::COMMIT_QC), bundle::encode_commit_qc_payload(&qc, &descending)?)?;

    let portable = fs::read(dir.join(bundle::QMDB))?;
    let verified = verify_portable_stream(portable.as_slice(), chain.chain().id(), &chain.genesis_hash().0)
        .map_err(|e| eyre::eyre!("portable snapshot: {e}"))?;
    let (mut accounts, mut slots) = (0u64, 0u64);
    for line in BufReader::new(fs::File::open(dir.join(bundle::STATE))?).lines().skip(1) {
        let row: DumpLine = serde_json::from_str(&line?)?;
        accounts += 1;
        slots += row.account.storage.map_or(0, |s| s.len() as u64);
    }
    let mut files_sha256 = std::collections::BTreeMap::new();
    for name in [bundle::STATE, bundle::HEADER, bundle::QMDB, bundle::NEXT_HEADER, bundle::COMMIT_QC, bundle::BLOCK] {
        if dir.join(name).exists() {
            files_sha256.insert(name.to_owned(), bundle::sha256_file(&dir.join(name))?);
        }
    }
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("root_label".to_owned(), serde_json::json!("post_state_root is the state after executing pivot_number; it equals header(pivot_number+1).Root (deferred depth 1); header(pivot_number).Root is the state after pivot_number-1"));
    extra.insert("anchor_domain".to_owned(), serde_json::json!("H2-v4 commit (phase 3, changesHash 0), genesis validator set, >= n-f signers"));
    extra.insert("accounts".to_owned(), serde_json::json!(accounts));
    extra.insert("storage_slots".to_owned(), serde_json::json!(slots));
    extra.insert("qmdb_live_leaves".to_owned(), serde_json::json!(verified.live_count));
    extra.insert("qmdb_next_slot".to_owned(), serde_json::json!(verified.next_slot));
    let manifest = bundle::Manifest {
        format: bundle::FORMAT.to_owned(),
        chain_id: chain.chain().id(),
        genesis_hash: chain.genesis_hash(),
        pivot_number: head.0,
        pivot_hash: head.1,
        post_state_root: next.state_root,
        deferred_depth: 1,
        anchor_qc_view: wire.view,
        anchor_block_number: named,
        anchor_block_hash: wire.block_hash,
        anchor_lowest_header: lowest,
        files_sha256,
        extra,
    };
    fs::write(dir.join(bundle::MANIFEST), serde_json::to_vec_pretty(&manifest)?)?;
    println!(
        "anchor: pivot {} next {} QC view {} on block {named}, headers {named}..{lowest} -> {}",
        head.0,
        next.hash_slow(),
        wire.view,
        dir.display()
    );
    Ok(())
}

/// An account's dump row, or `None` for an EIP-161 empty account (no nonce,
/// balance, code or storage): the plain state gov5 dumps from drops those,
/// and QMDB holds none for a zero-balance genesis entry, which reth's hashed
/// state keeps (devnet-fleet LATE_SNAPSHOT on `n42_devnet.json`). `init`
/// accepts a dump without the empty leaves QMDB does retain.
fn dump_account(
    nonce: u64,
    balance: U256,
    code: Option<alloy_primitives::Bytes>,
    storage: std::collections::BTreeMap<B256, B256>,
) -> Option<GenesisAccount> {
    if nonce == 0 && balance.is_zero() && code.is_none() && storage.is_empty() {
        return None;
    }
    Some(GenesisAccount {
        nonce: Some(nonce),
        balance,
        code,
        storage: (!storage.is_empty()).then_some(storage),
        private_key: None,
    })
}

/// One account line of the JSONL this node writes (reth `init-state`'s, as
/// gov5's `n42-reth-state-dump` writes it).
#[derive(Debug, serde::Serialize)]
struct DumpRow<'a> {
    address: Address,
    #[serde(flatten)]
    account: &'a GenesisAccount,
}

/// Writes the state at `block` as reth `init-state` JSONL: `{"root": root}`
/// (the state root after `block`: under deferred execution header N+1's, not
/// header N's) then one line per account in ascending address order. The
/// database keeps the state hashed, so the preimages come from the genesis
/// allocation and the changesets of blocks 1..=block, which name every
/// address and plain slot key ever written (a snapshot-initialised node has
/// one changeset entry per account and slot at its snapshot block); the
/// values from the state at `block`. `init` proves each row against the
/// portable snapshot and refuses a dump that misses a live key.
fn write_state_dump<P>(
    provider: &P,
    state: &dyn reth_provider::StateProvider,
    genesis: &alloy_genesis::Genesis,
    block: u64,
    root: B256,
    out: &std::path::Path,
) -> eyre::Result<(u64, u64)>
where
    P: reth_provider::ChangeSetReader + reth_provider::StorageChangeSetReader,
{
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;
    let mut keys: BTreeMap<Address, BTreeSet<B256>> = BTreeMap::new();
    for (address, account) in &genesis.alloc {
        keys.entry(*address).or_default().extend(account.storage.iter().flatten().map(|(slot, _)| *slot));
    }
    for number in 1..=block {
        for change in provider.account_block_changeset(number)? {
            keys.entry(change.address).or_default();
        }
        for (key, entry) in provider.storage_changeset(number)? {
            keys.entry(key.address()).or_default().insert(entry.key);
        }
    }
    let mut file = std::io::BufWriter::new(fs::File::create(out).wrap_err("state file")?);
    writeln!(file, "{}", serde_json::json!({ "root": root }))?;
    let (mut accounts, mut slots) = (0u64, 0u64);
    for (address, slot_keys) in keys {
        let Some(account) = state.basic_account(&address)? else { continue };
        let code = match account.bytecode_hash {
            Some(hash) if hash != alloy_primitives::KECCAK256_EMPTY => Some(
                state
                    .bytecode_by_hash(&hash)?
                    .ok_or_else(|| eyre::eyre!("no bytecode {hash} for {address}"))?
                    .original_bytes(),
            ),
            _ => None,
        };
        let mut storage = std::collections::BTreeMap::new();
        for slot in slot_keys {
            if let Some(value) = state.storage(address, slot)?.filter(|value| !value.is_zero()) {
                storage.insert(slot, B256::from(value.to_be_bytes::<32>()));
            }
        }
        let Some(account) = dump_account(account.nonce, account.balance, code, storage) else { continue };
        slots += account.storage.as_ref().map_or(0, |s| s.len() as u64);
        serde_json::to_writer(&mut file, &DumpRow { address, account: &account })?;
        writeln!(file)?;
        accounts += 1;
    }
    file.flush()?;
    Ok((accounts, slots))
}

#[cfg(test)]
#[path = "init_snapshot_tests.rs"]
mod tests;
