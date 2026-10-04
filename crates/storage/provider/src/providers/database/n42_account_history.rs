//! N42: the account-history gap of `N42_ACCOUNT_HISTORY=off` (`docs/PERSISTENCE_COST_STUDY.md`).
//!
//! With the mode off a storage-v2 batch does not write `AccountsHistory`; its account changesets
//! are written as before. The first block whose index entries are missing is recorded in
//! `StageCheckpoints` under [`ACCOUNT_HISTORY_GAP_KEY`], in the batch's own MDBX transaction:
//!
//! * historical account reads trust the index only below the gap and answer from a changeset
//!   scan at and above it ([`DatabaseProvider::n42_account_history_info_in_gap`]);
//! * the restart healer leaves the gap alone (`heal_accounts_history`);
//! * an unwind below the gap closes it ([`DatabaseProvider::n42_close_account_history_gap`]).
//!
//! The `IndexAccountHistory` stage checkpoint advances as before, so neither the launch-time
//! pipeline consistency check nor the healer sees a lagging stage.

use super::DatabaseProvider;
use crate::{
    providers::n42_persist::{
        account_history_scan_max, account_history_scan_too_long, ACCOUNT_HISTORY_GAP_KEY,
    },
    ChangeSetReader, EitherReader,
};
use alloy_primitives::{Address, BlockNumber};
use reth_db_api::{
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_node_types::NodeTypes;
use reth_stages_types::StageCheckpoint;
use reth_storage_api::HistoryInfo;
use reth_storage_errors::provider::ProviderResult;

impl<TX: DbTx, N: NodeTypes> DatabaseProvider<TX, N> {
    /// The first block whose `AccountsHistory` entries are missing, if the mode was ever off since
    /// the index was last complete.
    pub(crate) fn n42_account_history_gap(&self) -> ProviderResult<Option<BlockNumber>> {
        Ok(self
            .tx
            .get::<tables::StageCheckpoints>(ACCOUNT_HISTORY_GAP_KEY.to_string())?
            .map(|checkpoint| checkpoint.block_number))
    }

    /// The first block in `from..=to` with an account changeset entry for `address`.
    fn n42_first_account_change(
        &self,
        address: Address,
        from: BlockNumber,
        to: BlockNumber,
        gap: BlockNumber,
    ) -> ProviderResult<Option<BlockNumber>> {
        if from > to {
            return Ok(None)
        }
        if to - from >= account_history_scan_max() {
            return Err(account_history_scan_too_long(gap, from, to))
        }
        for block in from..=to {
            if self.get_account_before_block(block, address)?.is_some() {
                return Ok(Some(block))
            }
        }
        Ok(None)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> DatabaseProvider<TX, N> {
    /// [`HistoryInfo`] for `address` at `block_number` when the index is missing from `gap`.
    ///
    /// The index is complete below `gap`, so it is consulted with its visible tip lowered to
    /// `gap - 1`; whatever it cannot settle there is settled by the changesets of
    /// `gap..=visible_tip` (or `block_number..=visible_tip` when the read is inside the gap). An
    /// `InChangeset(c)` result means the caller reads block `c`'s changeset, exactly as with a
    /// complete index; a scan that would be longer than `N42_ACCOUNT_HISTORY_SCAN_MAX` blocks is
    /// an error naming the mode, never a guess.
    pub(crate) fn n42_account_history_info_in_gap(
        &self,
        address: Address,
        block_number: BlockNumber,
        lowest_available_block_number: Option<BlockNumber>,
        visible_tip: BlockNumber,
        gap: BlockNumber,
    ) -> ProviderResult<HistoryInfo> {
        if block_number >= gap {
            // No index entry can be trusted here: the account at `block_number` is the value
            // before its first change at or after it, or the latest value if it never changed.
            return Ok(
                match self.n42_first_account_change(address, block_number, visible_tip, gap)? {
                    Some(block) => HistoryInfo::InChangeset(block),
                    None => HistoryInfo::InPlainState,
                },
            )
        }

        let index_tip = visible_tip.min(gap.saturating_sub(1));
        let mut reader = EitherReader::new_accounts_history(self, self.history_rocksdb_snapshot())?;
        let info: HistoryInfo = reader
            .account_history_info(address, block_number, lowest_available_block_number, index_tip)?
            .into();
        Ok(match info {
            // A change in `block_number..gap`: settled by the complete part of the index.
            HistoryInfo::InChangeset(block) => HistoryInfo::InChangeset(block),
            // No change at all before the gap and `block_number` before the first write: the
            // account did not exist yet, wherever in the gap it was first written.
            HistoryInfo::NotYetWritten => HistoryInfo::NotYetWritten,
            // No change in `block_number..gap`: the first change in the gap, if any, holds the
            // value.
            unsettled @ (HistoryInfo::InPlainState | HistoryInfo::MaybeInPlainState) => {
                match self.n42_first_account_change(address, gap, visible_tip, gap)? {
                    Some(block) => HistoryInfo::InChangeset(block),
                    None => unsettled,
                }
            }
        })
    }
}

impl<TX: DbTxMut + DbTx, N: NodeTypes> DatabaseProvider<TX, N> {
    /// Records that the batch starting at `first_block` did not write `AccountsHistory`, unless an
    /// earlier batch already opened the gap.
    pub(crate) fn n42_note_account_history_skipped(
        &self,
        first_block: BlockNumber,
    ) -> ProviderResult<()> {
        if self.n42_account_history_gap()?.is_none() {
            tracing::info!(
                target: "providers::db",
                first_block,
                "N42_ACCOUNT_HISTORY=off: AccountsHistory index missing from this block on"
            );
            self.tx.put::<tables::StageCheckpoints>(
                ACCOUNT_HISTORY_GAP_KEY.to_string(),
                StageCheckpoint::new(first_block),
            )?;
        }
        Ok(())
    }

    /// The database was unwound to `tip`: below the gap the index is complete again (the unwind
    /// removed every entry above `tip`), so the gap is closed.
    pub(crate) fn n42_close_account_history_gap(&self, tip: BlockNumber) -> ProviderResult<()> {
        if self.n42_account_history_gap()?.is_some_and(|gap| tip < gap) {
            self.tx.delete::<tables::StageCheckpoints>(ACCOUNT_HISTORY_GAP_KEY.to_string(), None)?;
        }
        Ok(())
    }
}
