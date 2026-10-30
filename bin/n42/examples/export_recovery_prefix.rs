//! Read-only canonical block export for validated recovery into a separate EL.
//! Usage: export_recovery_prefix DATADIR GENESIS LAST_BLOCK NEW_OUTPUT_DIRECTORY
//! Export is not execution validation and never changes QMDB or vote watermarks.

use alloy_consensus::proofs::calculate_transaction_root;
use alloy_eips::eip2718::Encodable2718;
use alloy_genesis::Genesis;
use eyre::{Result, ensure, eyre};
use n42_engine_types::N42Node;
use reth_db_api::{tables, transaction::DbTx};
use reth_provider::{BlockHashReader, BlockReader, DatabaseProviderFactory};
use serde_json::json;
use std::{fs, io::Write, path::PathBuf, sync::Arc};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 4,
        "usage: export_recovery_prefix DATADIR GENESIS LAST_BLOCK NEW_OUTPUT_DIRECTORY"
    );
    let datadir = fs::canonicalize(PathBuf::from(&args[0]))?;
    let genesis_path = fs::canonicalize(PathBuf::from(&args[1]))?;
    let last: u64 = args[2]
        .to_str()
        .ok_or_else(|| eyre!("invalid height"))?
        .parse()?;
    let output = PathBuf::from(&args[3]);
    ensure!(!output.exists(), "output must be a new directory");
    let output_parent = fs::canonicalize(
        output
            .parent()
            .ok_or_else(|| eyre!("output needs a parent directory"))?,
    )?;
    ensure!(
        !output_parent.starts_with(&datadir),
        "output must be outside the source datadir"
    );
    let genesis: Genesis = serde_json::from_slice(&fs::read(&genesis_path)?)?;
    let chain = Arc::new(n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from(genesis)));
    let factory = N42Node::provider_factory_builder().open_read_only(
        chain,
        datadir.clone(),
        reth_tasks::Runtime::test(),
    )?;
    let provider = factory.database_provider_ro()?;
    let durable = provider
        .tx_ref()
        .get::<tables::StageCheckpoints>("Finish".to_owned())?
        .ok_or_else(|| eyre!("missing durable Finish checkpoint"))?
        .block_number;
    ensure!(
        last > 0 && last <= durable,
        "export height must be within durable canonical history ({durable})"
    );
    fs::create_dir(&output)?;
    let mut rows = Vec::new();
    let mut parent = provider
        .block_hash(0)?
        .ok_or_else(|| eyre!("missing genesis hash"))?;
    for number in 1..=last {
        let block = provider
            .block_by_number(number)?
            .ok_or_else(|| eyre!("missing block {number}"))?;
        let hash = provider
            .block_hash(number)?
            .ok_or_else(|| eyre!("missing canonical hash {number}"))?;
        ensure!(
            block.header.number == number && block.header.hash_slow() == hash,
            "canonical header mismatch at {number}"
        );
        ensure!(
            block.header.parent_hash == parent,
            "canonical parent mismatch at {number}"
        );
        ensure!(
            calculate_transaction_root(&block.body.transactions) == block.header.transactions_root,
            "transaction root mismatch at {number}"
        );
        ensure!(
            block.body.ommers.is_empty(),
            "unsupported nonempty ommers at {number}"
        );
        let withdrawals = block
            .body
            .withdrawals
            .as_ref()
            .map(|w| w.as_slice())
            .unwrap_or_default();
        let rewards = n42_h2_consensus::withdrawals_to_rewards(withdrawals);
        ensure!(
            n42_h2_consensus::rewards_to_withdrawals(&rewards)? == withdrawals,
            "withdrawal metadata does not represent gov5 rewards at {number}"
        );
        ensure!(
            block.header.withdrawals_root
                == Some(n42_h2_consensus::gov5_rewards_root(rewards.iter().copied())),
            "reward commitment mismatch at {number}"
        );
        ensure!(
            block.header.block_access_list_hash.is_none(),
            "unsupported block access list at {number}"
        );
        let transactions: Vec<_> = block
            .body
            .transactions
            .iter()
            .map(|tx| tx.encoded_2718().into())
            .collect();
        let body =
            n42_h2_consensus::encode_block_rlp_raw(&block.header, &transactions, &rewards, None);
        let (decoded_hash, _) = n42_h2_consensus::decode_block_body_header(
            &body,
            n42_h2_consensus::N42HeaderProfile::Gov5H2,
        )?;
        ensure!(decoded_hash == hash, "exported header mismatch at {number}");
        let path = output.join(format!("{hash:x}.rlp"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&body)?;
        file.sync_all()?;
        rows.push(json!({"number":number,"hash":hash,"parent_hash":parent,"bytes":body.len()}));
        parent = hash;
    }
    let manifest = json!({"source_datadir":datadir,"genesis":genesis_path,"durable_finish":durable,
        "exported_through":last,"verification":"canonical header hashes, ancestry, transaction roots and reward commitments; execution replay pending","blocks":rows});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("manifest.json"))?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::File::open(&output)?.sync_all()?;
    fs::File::open(output_parent)?.sync_all()?;
    println!("exported {last} canonical blocks; execution replay remains required");
    Ok(())
}
