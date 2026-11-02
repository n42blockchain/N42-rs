// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The follower's includability rule, kept by the builder (audit R3-E1).
//!
//! Under deferred execution a follower votes for a block before executing
//! it, so it checks that the block is *includable* instead
//! (`bin/n42/src/follower_import.rs`, `check_includable_laid_out`; gov5
//! applies the same rule, `docs/PHASE_D_DEFERRED_EXECUTION.md` 2.4):
//!
//! - the transactions' gas limits sum to at most the header's gas limit;
//! - per sender, in block order, the nonces run on from the account's nonce
//!   in the parent's post-state, and the sender's summed worst-case cost
//!   ([`crate::frame_scan::tx_cost`]: `gas_limit * max_fee_per_gas + value +
//!   blob_gas * max_fee_per_blob_gas`) is at most its balance there.
//!
//! An executing builder admits a transaction on its *actual* gas and its
//! cost at the *effective* price, which both rules can exceed: a block with
//! gas-limit headroom, or a sender whose balance covers what it spends but
//! not what it might, is built and then refused by every follower. The
//! builder therefore budgets by [`GasBudget`] and keeps a [`SenderLedger`]
//! when deferred execution is active, and does neither otherwise (reth's
//! semantics, unchanged).
//!
//! Both are O(1) per transaction: one addition and one comparison, and one
//! map entry per sender.

use alloy_primitives::{map::AddressHashMap, Address, U256};

/// The block's gas, budgeted by the transactions' gas limits (deferred
/// execution) or by the gas they used (reth).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasBudget {
    limit: u64,
    by_gas_limit: bool,
    /// The admitted transactions' gas limits, summed (kept in both modes,
    /// read only when budgeting by them).
    gas_limits: u64,
}

impl GasBudget {
    /// A budget of `limit`, by gas limits when `by_gas_limit`.
    pub const fn new(limit: u64, by_gas_limit: bool) -> Self {
        Self { limit, by_gas_limit, gas_limits: 0 }
    }

    /// Whether gas limits are what is budgeted.
    pub const fn by_gas_limit(&self) -> bool {
        self.by_gas_limit
    }

    /// The gas counted against the limit so far: the admitted gas limits,
    /// or `gas_used` (the block's executed gas) under reth's rule.
    pub const fn counted(&self, gas_used: u64) -> u64 {
        if self.by_gas_limit {
            self.gas_limits
        } else {
            gas_used
        }
    }

    /// Whether a transaction of `gas_limit` fits, `gas_used` the block's
    /// executed gas so far.
    pub const fn fits(&self, gas_limit: u64, gas_used: u64) -> bool {
        self.counted(gas_used).saturating_add(gas_limit) <= self.limit
    }

    /// The gas left for further transactions.
    pub const fn left(&self, gas_used: u64) -> u64 {
        self.limit.saturating_sub(self.counted(gas_used))
    }

    /// Notes an admitted (executed) transaction's gas limit.
    pub const fn admit(&mut self, gas_limit: u64) {
        self.gas_limits = self.gas_limits.saturating_add(gas_limit);
    }
}

/// A sender's entry: its balance in the parent's post-state and the
/// worst-case cost of its transactions admitted so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    balance: U256,
    cost: U256,
}

/// What a sender's first transaction in the ledger is opened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opening {
    /// The sender's balance in the parent's post-state.
    pub balance: U256,
    /// Whether the sender may already have transactions in the block that
    /// this ledger did not see (the parallel step's), whose worst-case cost
    /// it does not know: its transactions are then refused here.
    pub unseen_earlier: bool,
}

/// The ledger's verdict on one transaction.
#[derive(Debug)]
pub enum Admission<'a> {
    /// Within the sender's balance: commit it once the transaction is in.
    Admit(Admitted<'a>),
    /// The sender's worst-case cost would exceed its balance.
    OverBalance {
        /// The sender's balance in the parent's post-state.
        balance: U256,
        /// The worst-case cost with this transaction.
        cost: U256,
    },
    /// The sender has transactions in the block this ledger did not count.
    Unseen,
}

/// An admission to commit after the transaction executed.
#[derive(Debug)]
pub struct Admitted<'a> {
    cost: &'a mut U256,
    after: U256,
}

impl Admitted<'_> {
    /// Counts the transaction's worst-case cost against its sender.
    pub fn commit(self) {
        *self.cost = self.after;
    }
}

/// Per-sender worst-case cost against the parent's post-state balance.
#[derive(Debug, Default)]
pub struct SenderLedger {
    entries: AddressHashMap<Option<Entry>>,
}

impl SenderLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// The verdict on a transaction of `sender` with worst-case `cost`.
    /// `open` is called on the sender's first transaction only, before
    /// anything of it executed, and reads the parent's post-state.
    pub fn admit<E>(
        &mut self,
        sender: Address,
        cost: U256,
        open: impl FnOnce() -> Result<Opening, E>,
    ) -> Result<Admission<'_>, E> {
        let slot = match self.entries.entry(sender) {
            alloy_primitives::map::Entry::Occupied(slot) => slot.into_mut(),
            alloy_primitives::map::Entry::Vacant(slot) => {
                let opening = open()?;
                slot.insert((!opening.unseen_earlier).then_some(Entry { balance: opening.balance, cost: U256::ZERO }))
            }
        };
        let Some(entry) = slot.as_mut() else { return Ok(Admission::Unseen) };
        let after = entry.cost.saturating_add(cost);
        if after > entry.balance {
            return Ok(Admission::OverBalance { balance: entry.balance, cost: after });
        }
        Ok(Admission::Admit(Admitted { cost: &mut entry.cost, after }))
    }
}

/// One sender run's worst-case cost in the parallel executor, where every
/// sender's transactions are one run in a batch (`partition_by_sender`): the
/// run's opening balance is the sender's first transaction's pre-state,
/// which is the parent's post-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLedger {
    sender: Address,
    balance: U256,
    cost: U256,
}

impl RunLedger {
    /// A ledger before any run.
    pub const fn new() -> Self {
        Self { sender: Address::ZERO, balance: U256::ZERO, cost: U256::ZERO }
    }

    /// Whether a transaction of `sender` with worst-case `cost`, whose
    /// sender's balance before it is `balance_before`, fits; counted if so.
    /// `first` says it opens the sender's run.
    pub fn admit(&mut self, sender: Address, first: bool, balance_before: U256, cost: U256) -> bool {
        if first || sender != self.sender {
            *self = Self { sender, balance: balance_before, cost: U256::ZERO };
        }
        let after = self.cost.saturating_add(cost);
        if after > self.balance {
            return false;
        }
        self.cost = after;
        true
    }
}

impl Default for RunLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether the transaction at `index` of the parallel executor's run, with
/// `gas_limit`, fits the block's remaining gas (audit R3-E3): every earlier
/// transaction the path takes is a plain transfer that uses exactly
/// `transfer_gas`, so at most `index * transfer_gas` is used before it.
/// That bound is exact on a follower's block (every earlier transaction is
/// on the path, or the block goes to the serial executor) and conservative
/// on a build's candidates (a skipped one used nothing).
#[inline(always)]
pub const fn fits_block_gas(index: usize, gas_limit: u64, transfer_gas: u64, block_gas_limit: u64) -> bool {
    (index as u64).saturating_mul(transfer_gas).saturating_add(gas_limit) <= block_gas_limit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(i: u8) -> Address {
        Address::with_last_byte(i)
    }

    #[test]
    fn the_budget_counts_gas_limits_under_deferred_execution() {
        let mut budget = GasBudget::new(100_000, true);
        assert!(budget.fits(60_000, 0));
        budget.admit(60_000);
        // 21,000 used, 60,000 budgeted: a second 60,000 no longer fits.
        assert!(!budget.fits(60_000, 21_000));
        assert!(budget.fits(40_000, 21_000));
        assert_eq!(budget.left(21_000), 40_000);
    }

    #[test]
    fn the_reth_budget_counts_gas_used() {
        let mut budget = GasBudget::new(100_000, false);
        budget.admit(60_000);
        assert!(budget.fits(60_000, 21_000));
        assert_eq!(budget.left(21_000), 79_000);
    }

    #[test]
    fn the_ledger_sums_worst_case_costs_against_the_opening_balance() {
        let mut ledger = SenderLedger::new();
        let mut opened = 0;
        let mut open = |balance: u64| {
            opened += 1;
            Ok::<_, ()>(Opening { balance: U256::from(balance), unseen_earlier: false })
        };
        match ledger.admit(a(1), U256::from(60), || open(100)).unwrap() {
            Admission::Admit(admitted) => admitted.commit(),
            other => panic!("{other:?}"),
        }
        // 60 + 60 > 100.
        assert!(matches!(
            ledger.admit(a(1), U256::from(60), || open(1_000)).unwrap(),
            Admission::OverBalance { balance, cost } if balance == U256::from(100) && cost == U256::from(120)
        ));
        // An admission not committed (the execution failed) counts nothing.
        assert!(matches!(ledger.admit(a(1), U256::from(40), || open(0)).unwrap(), Admission::Admit(_)));
        assert!(matches!(ledger.admit(a(1), U256::from(40), || open(0)).unwrap(), Admission::Admit(_)));
        assert_eq!(opened, 1, "one read per sender");
    }

    #[test]
    fn a_sender_with_unseen_transactions_is_refused() {
        let mut ledger = SenderLedger::new();
        let open = || Ok::<_, ()>(Opening { balance: U256::MAX, unseen_earlier: true });
        assert!(matches!(ledger.admit(a(2), U256::from(1), open).unwrap(), Admission::Unseen));
        assert!(matches!(ledger.admit(a(2), U256::from(1), open).unwrap(), Admission::Unseen));
    }

    #[test]
    fn a_run_ledger_resets_per_sender() {
        let mut run = RunLedger::new();
        assert!(run.admit(a(1), true, U256::from(100), U256::from(60)));
        // The balance before the second is lower (the first's actual cost),
        // but the run keeps its opening balance.
        assert!(!run.admit(a(1), false, U256::from(70), U256::from(60)));
        assert!(run.admit(a(1), false, U256::from(70), U256::from(40)));
        assert!(run.admit(a(2), false, U256::from(10), U256::from(10)));
    }

    #[test]
    fn the_block_gas_check_bounds_by_index() {
        // Block of 63,000: three transfers fit, a fourth does not.
        assert!(fits_block_gas(2, 21_000, 21_000, 63_000));
        assert!(!fits_block_gas(3, 21_000, 21_000, 63_000));
        // A gas limit over what is left after two transfers.
        assert!(!fits_block_gas(2, 30_000, 21_000, 63_000));
        assert!(!fits_block_gas(usize::MAX, 1, 21_000, u64::MAX - 1));
    }
}
