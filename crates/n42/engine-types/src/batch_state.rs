// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A build batch's state: the part of revm's [`State`](revm::database::State)
//! the transfer path uses, one small map where `State` keeps two large ones.
//!
//! `State::commit` looks every touched account up in its cache, rebuilds the
//! cached plain account, turns the change into a [`TransitionAccount`], and
//! looks the account up again in its transition map to merge it there (plus
//! the block-access-list bookkeeping, a no-op here). For the leader's batch
//! loop that was 0.41 us a transfer of pool time for three accounts
//! (`N42_PHASE_TIMERS=1`, step 4b). Here each account is held as the bundle
//! account its merged transition becomes: a read returns its info, a commit
//! replaces the info and moves the status on with the same
//! [`AccountStatus::on_changed`] revm's `CacheAccount::change` uses, and the
//! close keeps the map, less the accounts only read, as the bundle's state,
//! each account's revert made by the same
//! [`BundleAccount::update_and_create_revert`]
//! [`BundleState::apply_transitions_and_create_reverts`] uses.

use crate::fast_transfer::PlainTransfer;
use alloy_primitives::{map::AddressMap, Address, B256};
use revm::{
    database::states::{AccountStatus, BundleAccount, BundleState, TransitionAccount},
    state::{AccountInfo, Bytecode, EvmState},
    Database,
};

/// A change [`BatchState::commit`] does not model: the transfer path never
/// makes one, and a batch that meets one sends the block to the serial
/// builder.
#[derive(Debug)]
pub struct Unsupported(pub Address);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "account {} changed in a way the batch state does not model", self.0)
    }
}

/// A build batch's accounts over `G`, the parent's state: reads are cached
/// as [`State`](revm::database::State) caches them, commits are merged as it
/// merges them, and [`BatchState::take_bundle`] is the bundle its
/// `merge_transitions(BundleRetention::Reverts)` and `take_bundle` return.
///
/// Each account is held as the bundle account the batch's transition becomes:
/// `original_info` as it was loaded (the transition's `previous_info`),
/// `info`/`status` as it stands; the loaded status is the one
/// [`loaded_status`] reads off `original_info`. A loaded status (`Loaded`,
/// `LoadedNotExisting`, `LoadedEmptyEIP161`) always moves on a change
/// ([`AccountStatus::on_changed`]), so an account whose status still equals
/// its loaded one was only read, and the close leaves it out. The close
/// keeps the map as the bundle's state: rebuilding every account into a
/// fresh map there (`apply_transitions_and_create_reverts`) was most of a
/// batch's close (490 ns a transfer on the fleet, loop283).
///
/// Only the transfer path's changes are modelled -- an account touched, not
/// destroyed, not created, not emptied, no storage written -- and any other
/// is refused ([`Unsupported`]). Storage and code are passed through to `G`
/// uncached: the transfer path reads neither.
#[derive(Debug)]
pub struct BatchState<G> {
    inner: G,
    accounts: AddressMap<BundleAccount>,
}

/// An account as `State` loads it into its cache (`load_cache_account`):
/// its info as `CacheAccount::account_info` then returns it, and its status;
/// the same info kept as the original.
fn loaded(info: Option<AccountInfo>) -> BundleAccount {
    let info = match info {
        // `CacheAccount::new_loaded_empty_eip161`: an empty plain account.
        Some(info) if info.is_empty() => Some(AccountInfo::default()),
        info => info,
    };
    let status = loaded_status(info.as_ref());
    BundleAccount { original_info: info.clone(), info, storage: Default::default(), status }
}

/// The status [`loaded`] gives an account whose loaded info is `original`:
/// an entry's status before its first change.
fn loaded_status(original: Option<&AccountInfo>) -> AccountStatus {
    match original {
        None => AccountStatus::LoadedNotExisting,
        Some(info) if info.is_empty() => AccountStatus::LoadedEmptyEIP161,
        Some(_) => AccountStatus::Loaded,
    }
}

/// `CacheAccount::change` merged into the batch's account: the status moved
/// on from the info as it stands, the info replaced (the loaded info stays
/// the original, the transition's `previous_info`).
#[inline]
fn change(entry: &mut BundleAccount, info: AccountInfo) {
    let had_no_nonce_and_code = entry.info.as_ref().is_some_and(AccountInfo::has_no_code_and_nonce);
    entry.status = entry.status.on_changed(had_no_nonce_and_code);
    entry.info = Some(info);
}

impl<G: Database> BatchState<G> {
    /// A batch over `inner` with room for `accounts` without regrowing.
    pub fn with_capacity(inner: G, accounts: usize) -> Self {
        Self { inner, accounts: AddressMap::with_capacity_and_hasher(accounts, Default::default()) }
    }

    /// Applies a transaction's changes as `State::commit` would
    /// (`CacheAccount::change`, then `TransitionAccount::update` onto the
    /// batch's transition): the account's info replaced, its status moved on.
    pub fn commit(&mut self, changes: EvmState) -> Result<(), Unsupported> {
        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            if account.is_selfdestructed()
                || account.is_created()
                || account.is_empty()
                || account.storage.values().any(|slot| slot.is_changed())
            {
                return Err(Unsupported(address));
            }
            let entry = self.accounts.entry(address).or_insert_with(|| {
                // Committed without having been read: loaded as it was
                // before the change, as `State` does for such an account.
                if account.is_loaded_as_not_existing() {
                    loaded(None)
                } else {
                    loaded(Some(account.original_info().clone()))
                }
            });
            change(entry, account.info);
        }
        Ok(())
    }

    /// [`Self::commit`] of a transfer's changes as the transfer path computed
    /// them, without the `EvmState` built from them: the same infos
    /// (`Account::from` keeps the read info; a missing recipient is
    /// `AccountInfo::default()`), the same status moves. The three accounts
    /// were read through this state, so each is here already.
    pub fn commit_transfer(&mut self, plain: PlainTransfer) -> Result<(), Unsupported> {
        let mut sender = plain.sender;
        sender.balance = plain.sender_balance;
        sender.nonce += 1;
        let mut recipient = plain.recipient.unwrap_or_default();
        recipient.balance = plain.recipient_balance;
        let mut coinbase = plain.coinbase;
        coinbase.balance = plain.coinbase_balance;
        for (address, info) in [(plain.caller, sender), (plain.to, recipient), (plain.beneficiary, coinbase)] {
            if info.is_empty() {
                return Err(Unsupported(address));
            }
            let Some(entry) = self.accounts.get_mut(&address) else { return Err(Unsupported(address)) };
            change(entry, info);
        }
        Ok(())
    }

    /// The batch's changes against `G`, with their reverts: the bundle
    /// `State` returns from `merge_transitions(BundleRetention::Reverts)`
    /// then `take_bundle`. The batch holds nothing afterwards.
    pub fn take_bundle(&mut self) -> BundleState {
        let mut accounts = std::mem::take(&mut self.accounts);
        let mut bundle = BundleState::default();
        let mut reverts = Vec::with_capacity(accounts.len());
        let (mut state_size, mut reverts_size, mut changed) = (0usize, 0usize, false);
        // One pass, in place and in the map's order (the order the
        // transitions map was walked in before): an account only read is
        // dropped; a changed one gets the revert
        // `apply_transitions_and_create_reverts` makes for an account new to
        // the bundle (`TransitionAccount::create_revert`), and stays as its
        // `present_bundle_account` only if that revert exists, as there.
        accounts.retain(|address, entry| {
            let previous_status = loaded_status(entry.original_info.as_ref());
            if entry.status == previous_status {
                return false;
            }
            changed = true;
            let (present_info, present_status) = (entry.info.clone(), entry.status);
            let transition = TransitionAccount {
                info: entry.info.take(),
                status: entry.status,
                previous_info: entry.original_info.clone(),
                previous_status,
                storage: std::mem::take(&mut entry.storage),
                storage_was_destroyed: false,
            };
            if let Some((hash, code)) = transition.has_new_contract() {
                bundle.contracts.insert(hash, code.clone());
            }
            // `original_bundle_account`, updated by the transition.
            entry.info = entry.original_info.clone();
            entry.status = previous_status;
            let Some(revert) = entry.update_and_create_revert(transition) else { return false };
            entry.info = present_info;
            entry.status = present_status;
            state_size += entry.size_hint();
            reverts_size += revert.size_hint();
            reverts.push((*address, revert));
            true
        });
        if changed {
            bundle.state = accounts;
            bundle.reverts.push(reverts);
            bundle.state_size = state_size;
            bundle.reverts_size = reverts_size;
        }
        bundle
    }
}

impl<G: Database> Database for BatchState<G> {
    type Error = G::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let entry = match self.accounts.entry(address) {
            alloy_primitives::map::Entry::Occupied(entry) => entry.into_mut(),
            alloy_primitives::map::Entry::Vacant(entry) => entry.insert(loaded(self.inner.basic(address)?)),
        };
        Ok(entry.info.clone())
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: revm::primitives::StorageKey,
    ) -> Result<revm::primitives::StorageValue, Self::Error> {
        self.inner.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use revm::{
        database::{states::bundle_state::BundleRetention, CacheDB, EmptyDB, State},
        state::{Account, TransactionId},
        DatabaseCommit as _,
    };

    fn addr(i: u8) -> Address {
        Address::with_last_byte(i)
    }

    /// A transfer's three accounts as `N42Evm::transfer` builds them.
    fn changes<D: Database>(db: &mut D, from: Address, to: Address, coinbase: Address, value: u64) -> EvmState
    where
        D::Error: std::fmt::Debug,
    {
        let mut state = EvmState::default();
        let mut touch = |address: Address, add: u64, sub: u64, bump: bool| {
            let info = db.basic(address).expect("read");
            let mut account = match info {
                Some(info) => Account::from(info),
                None => Account::new_not_existing(TransactionId::ZERO),
            };
            account.info.balance = account.info.balance + U256::from(add) - U256::from(sub);
            if bump {
                account.info.nonce += 1;
            }
            account.mark_touch();
            state.insert(address, account);
        };
        touch(from, 0, value + 7, true);
        touch(to, value, 0, false);
        touch(coinbase, 7, 0, false);
        state
    }

    /// The transfer's accounts as `N42Evm::transfer_plain` hands them over,
    /// read from a batch that has the transfer's reads already (so the reads
    /// here are cache hits and the balances are the ones before it).
    fn plain(db: &mut BatchState<CacheDB<EmptyDB>>, from: Address, to: Address, coinbase: Address, value: u64) -> PlainTransfer {
        let sender = db.basic(from).expect("read").expect("a sender");
        let recipient = db.basic(to).expect("read");
        let coinbase_info = db.basic(coinbase).expect("read").expect("a beneficiary");
        PlainTransfer {
            caller: from,
            sender_balance: sender.balance - U256::from(value + 7),
            sender,
            to,
            recipient_balance: recipient.as_ref().map_or(U256::ZERO, |r| r.balance) + U256::from(value),
            recipient,
            beneficiary: coinbase,
            coinbase_balance: coinbase_info.balance + U256::from(7u64),
            coinbase: coinbase_info,
        }
    }

    /// The same transfers through `State` and through `BatchState` give the
    /// same bundle: accounts, statuses, originals, contracts and reverts.
    #[test]
    fn the_batch_state_bundle_equals_the_states() {
        let mut db = CacheDB::new(EmptyDB::default());
        for i in 1..=4u8 {
            db.insert_account_info(addr(i), AccountInfo { balance: U256::from(1_000_000u64), ..Default::default() });
        }
        // An empty account (EIP-161) and a funded one with a nonce.
        db.insert_account_info(addr(20), AccountInfo::default());
        db.insert_account_info(addr(21), AccountInfo { balance: U256::from(5u64), nonce: 3, ..Default::default() });
        let coinbase = addr(1);
        // Senders 2..4 pay existing, empty, missing and repeated recipients,
        // and one sender is paid by another.
        let transfers = [(2u8, 20u8, 10u64), (2, 30, 11), (3, 21, 12), (3, 30, 13), (4, 2, 14), (2, 31, 15), (4, 21, 16)];

        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let mut direct = BatchState::with_capacity(db.clone(), 4);
        let mut batch = BatchState::with_capacity(db, 4);
        // An account only read stays out of the bundle.
        assert!(batch.basic(addr(40)).expect("read").is_none());
        assert!(state.basic(addr(40)).expect("read").is_none());
        for (from, to, value) in transfers {
            let a = changes(&mut state, addr(from), addr(to), coinbase, value);
            let b = changes(&mut batch, addr(from), addr(to), coinbase, value);
            assert_eq!(a, b, "the transfer reads the same accounts");
            let _ = changes(&mut direct, addr(from), addr(to), coinbase, value);
            state.commit(a);
            batch.commit(b).expect("a plain transfer");
            // The same transfer handed over as computed.
            let computed = plain(&mut direct, addr(from), addr(to), coinbase, value);
            direct.commit_transfer(computed).expect("a plain transfer");
        }
        state.merge_transitions(BundleRetention::Reverts);
        let mut theirs = state.take_bundle();
        let mut ours = batch.take_bundle();
        let mut direct = direct.take_bundle();
        for bundle in [&mut theirs, &mut ours, &mut direct] {
            for reverts in bundle.reverts.iter_mut() {
                reverts.sort_by_key(|(address, _)| *address);
            }
        }
        assert_eq!(ours.state, theirs.state);
        assert_eq!(ours.contracts, theirs.contracts);
        assert_eq!(ours.reverts, theirs.reverts);
        assert_eq!(ours.state_size, theirs.state_size);
        assert_eq!(ours.reverts_size, theirs.reverts_size);
        assert_eq!(direct.state, theirs.state);
        assert_eq!(direct.contracts, theirs.contracts);
        assert_eq!(direct.reverts, theirs.reverts);
        assert!(!ours.state.contains_key(&addr(40)));
        assert!(batch.accounts.is_empty());
    }
}
