// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42: the `Transactions` static-file segment's write, off its single thread.
//!
//! Today's write (`write_transactions`) encodes every transaction into the
//! `Compact` row on the segment's task, one at a time, and appends it. Of the
//! 40 ms a 200k-transfer block costs in a five-block batch, 19 ms is the
//! encoding, 11 ms the per-row append and 10 ms the batch's `sync_all`
//! (`n42_sf_tests::bench_sf_transactions_{200k,batch}`). Two switches, both
//! default off, both leaving the files and their durability as they were:
//!
//! * `N42_SF_PARALLEL_ENCODE=1`: a block's rows are encoded in chunks on the
//!   pool the segment task runs on (the storage pool) and then appended in
//!   order. The bytes, offsets and header are those of the serial path.
//! * `N42_SF_EARLY_WRITEBACK=1`: after each block's rows are appended, the
//!   data file's dirty pages are handed to the device
//!   (`sync_file_range(SYNC_FILE_RANGE_WRITE)`, which does not wait), so the
//!   batch's `sync_all` waits only for the last block's tail instead of the
//!   whole batch. The `sync_all` itself is unchanged: what is durable when is
//!   what it was.

use super::StaticFileProviderRWRefMut;
use alloy_primitives::TxNumber;
use reth_codecs::Compact;
use reth_primitives_traits::NodePrimitives;
use reth_storage_errors::provider::ProviderResult;
use std::sync::OnceLock;

/// Rows encoded per parallel task: 4,096 transfer rows are ~760 KB.
pub(crate) const ENCODE_CHUNK: usize = 4096;

/// Below this many transactions a block is encoded on the segment's thread.
const PARALLEL_MIN: usize = 2 * ENCODE_CHUNK;

fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| matches!(v.trim(), "1" | "on" | "true"))
}

/// `N42_SF_PARALLEL_ENCODE=1`, read once.
pub(crate) fn parallel_encode() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| flag("N42_SF_PARALLEL_ENCODE"))
}

/// `N42_SF_EARLY_WRITEBACK=1`, read once.
pub(crate) fn early_writeback() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| flag("N42_SF_EARLY_WRITEBACK"))
}

/// One chunk of encoded rows: the `Compact` encodings back to back, and each length.
#[derive(Debug, Default)]
pub(crate) struct EncodedRows {
    pub(crate) rows: Vec<u8>,
    pub(crate) lens: Vec<u32>,
}

impl EncodedRows {
    fn encode<T: Compact>(txs: &[T]) -> Self {
        let mut out =
            Self { rows: Vec::with_capacity(txs.len() * 200), lens: Vec::with_capacity(txs.len()) };
        for tx in txs {
            let before = out.rows.len();
            tx.to_compact(&mut out.rows);
            out.lens.push((out.rows.len() - before) as u32);
        }
        out
    }
}

/// Encodes `txs` into chunks of rows, in order, on the current rayon pool.
pub(crate) fn encode_parallel<T: Compact + Sync>(txs: &[T]) -> Vec<EncodedRows> {
    use rayon::prelude::*;
    if txs.len() < PARALLEL_MIN {
        return vec![EncodedRows::encode(txs)];
    }
    txs.par_chunks(ENCODE_CHUNK).map(EncodedRows::encode).collect()
}

/// Appends one block's transactions, numbered from `first_tx`, to the segment
/// writer: one `append_transaction` each, or with `parallel` the rows encoded
/// by [`encode_parallel`] and appended in order. The caller has already called
/// `increment_block`.
pub(crate) fn append_block_transactions<N>(
    w: &mut StaticFileProviderRWRefMut<'_, N>,
    txs: &[N::SignedTx],
    first_tx: TxNumber,
    parallel: bool,
) -> ProviderResult<()>
where
    N: NodePrimitives<SignedTx: Compact>,
{
    if !parallel {
        for (i, tx) in txs.iter().enumerate() {
            w.append_transaction(first_tx + i as u64, tx)?;
        }
        return Ok(());
    }
    let mut next = first_tx;
    for chunk in encode_parallel(txs) {
        w.append_transactions_encoded(next, &chunk.rows, &chunk.lens)?;
        next += chunk.lens.len() as u64;
    }
    Ok(())
}
