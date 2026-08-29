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

use alloy_consensus::Header;
use alloy_genesis::GenesisAccount;
use alloy_primitives::{Address, B256};
use clap::{Parser, Subcommand};
use eyre::{bail, Context as _};
use n42_engine_types::N42Node;
use n42_qmdb_reth::{state_scheme, N42ChainSpecParser, QmdbNodeState, StateScheme};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::{
    common::{AccessRights, Environment, EnvironmentArgs},
    init_state::without_evm::setup_without_evm,
};
use alloy_primitives::{keccak256, map::B256Set, U256};
use reth_db_api::{
    cursor::{DbCursorRW, DbDupCursorRW},
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
}

#[derive(Debug, Parser)]
struct InitArgs {
    #[command(flatten)]
    env: EnvironmentArgs<N42ChainSpecParser>,
    /// reth `init-state` JSONL: `{"root": ...}` then one account per line.
    #[arg(long, value_name = "STATE_JSONL")]
    state: PathBuf,
    /// The head's header, RLP (raw or hex).
    #[arg(long, value_name = "HEADER_RLP")]
    header: PathBuf,
    /// The cross-client portable QMDB snapshot at the same head.
    #[arg(long, value_name = "SNAPSHOT")]
    qmdb: PathBuf,
}

#[derive(Debug, Parser)]
struct ExportArgs {
    #[command(flatten)]
    env: EnvironmentArgs<N42ChainSpecParser>,
    /// The state JSONL's path, for naming: the header goes to
    /// `<out>.header.rlp`. The JSONL itself comes from gov5's
    /// `n42-reth-state-dump` at the same block.
    #[arg(long, value_name = "STATE_JSONL")]
    out: PathBuf,
    /// Where the portable QMDB snapshot goes.
    #[arg(long, value_name = "SNAPSHOT")]
    qmdb_out: PathBuf,
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

/// A header from a file holding its RLP, raw or as hex.
fn read_header_from_file(path: &std::path::Path) -> eyre::Result<(Header, B256)> {
    let bytes = fs::read(path).wrap_err("header file")?;
    let text = std::str::from_utf8(&bytes).map(str::trim).unwrap_or("");
    let rlp = if text.starts_with("0x") || text.chars().all(|c| c.is_ascii_hexdigit()) && !text.is_empty() {
        alloy_primitives::hex::decode(text).wrap_err("header hex")?
    } else {
        bytes
    };
    // gov5's codec, which reads its own fields beyond Ethereum's and hashes
    // them; the hash is what the datadir is anchored at.
    let (header, extension) = n42_h2_consensus::decode_gov5_header(&rlp).wrap_err("header RLP")?;
    let hash = n42_h2_consensus::gov5_header_hash(&header, &extension);
    Ok((header, hash))
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let runner = reth_cli_runner::CliRunner::try_default_runtime()?;
    let runtime = runner.runtime();
    match cli.command {
        Command::Init(args) => init(args, runtime),
        Command::Export(args) => export(args, runtime),
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

    let (header, hash) = read_header_from_file(&args.header)?;
    let number = header.number;
    let root = header.state_root;
    println!("head: block {number} {hash} state root {root}");

    // The chain up to the head: dummy headers below it, the head itself, and
    // every stage checkpointed there.
    {
        let provider_rw = provider_factory.database_provider_rw()?;
        let last = provider_rw.last_block_number()?;
        if last == 0 && number > 0 {
            setup_without_evm(&provider_rw, SealedHeader::new(header.clone(), hash), |n| Header {
                number: n,
                ..Default::default()
            })?;
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
    let reader = BufReader::new(fs::File::open(&args.state).wrap_err("state file")?);
    let mut lines = reader.lines();
    let first = lines.next().ok_or_else(|| eyre::eyre!("state file is empty"))??;
    let dump_root: RootLine = serde_json::from_str(&first).wrap_err("first line must be {\"root\": ...}")?;
    if dump_root.root != root {
        bail!("state dump root {} is not the header's state root {root}", dump_root.root);
    }
    let (accounts, slots) = write_state_v2(&provider_factory, number, lines)?;
    println!("state: {accounts} accounts, {slots} slots");

    // The forest, from the portable snapshot, checked against the header.
    let qmdb = QmdbNodeState::new(chain.clone(), data_dir.data_dir().join("qmdb"));
    let portable = fs::read(&args.qmdb).wrap_err("portable snapshot")?;
    qmdb.initialize_from_portable(&portable, chain.chain().id(), chain.genesis_hash(), (number, hash), root)?;
    println!("QMDB forest restored at block {number}; the node can start");
    Ok(())
}

/// Writes the accounts of a state dump at `block`, as reth 2.5 stores them:
/// hashed accounts and storage in MDBX, one changeset entry per account and
/// slot ("created at `block`") in the static files, the history indices in
/// RocksDB, bytecodes once. Chunked commits keep memory flat.
fn write_state_v2<PF>(
    provider_factory: &PF,
    block: u64,
    lines: impl Iterator<Item = std::io::Result<String>>,
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
    let header_path = args.out.with_extension("jsonl.header.rlp");
    fs::write(&header_path, &header_rlp)?;

    // reth 2.5 keeps the state hashed — no addresses, no slot keys — so this
    // node cannot write the plain-state JSONL gov5's `n42-reth-state-dump`
    // does; the header goes out, the state comes from a gov5 node at the
    // same block.
    println!("header -> {}", header_path.display());

    let qmdb = QmdbNodeState::new(chain.clone(), data_dir.data_dir().join("qmdb"));
    let portable = qmdb.portable_export(chain.chain().id(), chain.genesis_hash())?;
    fs::write(&args.qmdb_out, &portable)?;
    println!("QMDB snapshot: {} bytes -> {}", portable.len(), args.qmdb_out.display());
    Ok(())
}
