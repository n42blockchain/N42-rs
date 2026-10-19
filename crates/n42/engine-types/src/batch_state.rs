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
    database::states::{
        reverts::{AccountInfoRevert, AccountRevert, RevertToSlot},
        AccountStatus, BundleAccount, BundleState, StorageWithOriginalValues, TransitionAccount,
    },
    primitives::StorageKeyMap,
    state::{AccountInfo, Bytecode, EvmState},
    Database,
};
use std::sync::LazyLock;

/// `N42_TAKE_BUNDLE_TRANSFER=1`, read once: [`BatchState::take_bundle`] builds each changed
/// account's present entry and revert directly ([`BatchState::take_bundle_transfer`]) instead of
/// through a [`TransitionAccount`] and [`BundleAccount::update_and_create_revert`], and the
/// empty storage maps of a loaded account and of a revert are cloned from one empty map
/// instead of each drawing a fresh hasher seed (`gen_per_hasher_seed`, 1.31% of the build
/// threads' cycles, `docs/BUILDER_FLOOR_PROFILE.md` 4). The bundle is equal either way.
pub fn take_bundle_transfer() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_TAKE_BUNDLE_TRANSFER").is_ok_and(|v| v == "1"))
}

/// An empty account storage map whose hasher was seeded once: a clone copies the seed and
/// allocates nothing, where `Default` draws a new seed per map. The maps stay the public types;
/// only their hashers share a seed (still random per process).
fn seedless_storage() -> StorageWithOriginalValues {
    static EMPTY: LazyLock<StorageWithOriginalValues> = LazyLock::new(Default::default);
    EMPTY.clone()
}

/// [`seedless_storage`] for a revert's storage map.
fn seedless_revert_storage() -> StorageKeyMap<RevertToSlot> {
    static EMPTY: LazyLock<StorageKeyMap<RevertToSlot>> = LazyLock::new(Default::default);
    EMPTY.clone()
}

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
    loaded_with(info, take_bundle_transfer())
}

/// [`loaded`], with the empty storage map from [`seedless_storage`] when `seedless`.
#[inline]
fn loaded_with(info: Option<AccountInfo>, seedless: bool) -> BundleAccount {
    let info = match info {
        // `CacheAccount::new_loaded_empty_eip161`: an empty plain account.
        Some(info) if info.is_empty() => Some(AccountInfo::default()),
        info => info,
    };
    let status = loaded_status(info.as_ref());
    let storage = if seedless { seedless_storage() } else { Default::default() };
    BundleAccount { original_info: info.clone(), info, storage, status }
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

    /// A hint, nothing else: probes the batch's map for `address` (the probe
    /// brings the map's control group and bucket into the cache) and, if the
    /// account is here, prefetches the lines of its entry. Issued for a
    /// transaction a few places ahead of the one running
    /// (`N42_BUILD_MLP`, [`crate::parallel_transfer::build_mlp`]) so its
    /// misses overlap the running one's instead of waiting their turn. Reads
    /// only: the map and every answer are as without it.
    #[inline]
    pub fn prefetch_account(&self, address: &Address) {
        if let Some(entry) = self.accounts.get(address) {
            let at = (entry as *const BundleAccount).cast::<u8>();
            let size = std::mem::size_of::<BundleAccount>();
            let mut offset = 0;
            while offset < size {
                crate::parallel_transfer::prefetch_hint(at.wrapping_add(offset));
                offset += 64;
            }
        }
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
    /// `N42_TAKE_BUNDLE_TRANSFER=1` takes [`Self::take_bundle_transfer`], the same bundle.
    pub fn take_bundle(&mut self) -> BundleState {
        if take_bundle_transfer() {
            self.take_bundle_transfer()
        } else {
            self.take_bundle_generic()
        }
    }

    /// [`Self::take_bundle`] through revm's own steps: a [`TransitionAccount`] per changed
    /// account and [`BundleAccount::update_and_create_revert`] onto its original.
    fn take_bundle_generic(&mut self) -> BundleState {
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

    /// [`Self::take_bundle_generic`]'s bundle built directly for the changes the batch
    /// models (no storage written, nothing created or destroyed): the present entry is the
    /// batch's entry as it stands, and the revert is the one
    /// [`BundleAccount::update_and_create_revert`] makes from the account's loaded original
    /// for a `Changed` or `InMemoryChange` transition with empty storage -- the info reverted
    /// to the original (or deleted, for an account loaded as not existing) when it differs,
    /// no storage reverts, the loaded status as the previous one. Any other status pair is
    /// handed to the generic step for that account.
    fn take_bundle_transfer(&mut self) -> BundleState {
        let mut accounts = std::mem::take(&mut self.accounts);
        let mut bundle = BundleState::default();
        let mut reverts = Vec::with_capacity(accounts.len());
        let (mut state_size, mut reverts_size, mut changed) = (0usize, 0usize, false);
        accounts.retain(|address, entry| {
            let previous_status = loaded_status(entry.original_info.as_ref());
            if entry.status == previous_status {
                return false;
            }
            changed = true;
            // `TransitionAccount::has_new_contract` on the transition the generic step builds.
            let present_code_hash = entry.info.as_ref().map(|info| &info.code_hash);
            let previous_code_hash = entry.original_info.as_ref().map(|info| &info.code_hash);
            if present_code_hash != previous_code_hash
                && let Some((hash, code)) =
                    entry.info.as_ref().and_then(|info| info.code.as_ref().map(|code| (info.code_hash, code)))
            {
                bundle.contracts.insert(hash, code.clone());
            }
            let info_revert = if entry.original_info != entry.info {
                AccountInfoRevert::RevertTo(entry.original_info.clone().unwrap_or_default())
            } else {
                AccountInfoRevert::DoNothing
            };
            let account = match (entry.status, previous_status) {
                (AccountStatus::Changed, AccountStatus::Loaded | AccountStatus::LoadedEmptyEIP161)
                | (AccountStatus::InMemoryChange, AccountStatus::Loaded | AccountStatus::LoadedEmptyEIP161) => {
                    info_revert
                }
                (AccountStatus::InMemoryChange, AccountStatus::LoadedNotExisting) => AccountInfoRevert::DeleteIt,
                _ => {
                    let Some(revert) = generic_revert(entry, previous_status) else { return false };
                    state_size += entry.size_hint();
                    reverts_size += revert.size_hint();
                    reverts.push((*address, revert));
                    return true;
                }
            };
            let revert =
                AccountRevert { account, storage: seedless_revert_storage(), previous_status, wipe_storage: false };
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

/// The generic step of [`BatchState::take_bundle_generic`] for one changed account whose
/// transition the transfer path does not build directly; the contract, if any, is recorded
/// by the caller already. `None` when revm makes no revert (the entry is then dropped).
#[cold]
fn generic_revert(
    entry: &mut BundleAccount,
    previous_status: AccountStatus,
) -> Option<AccountRevert> {
    let (present_info, present_status) = (entry.info.clone(), entry.status);
    let transition = TransitionAccount {
        info: entry.info.take(),
        status: entry.status,
        previous_info: entry.original_info.clone(),
        previous_status,
        storage: std::mem::take(&mut entry.storage),
        storage_was_destroyed: false,
    };
    entry.info = entry.original_info.clone();
    entry.status = previous_status;
    let revert = entry.update_and_create_revert(transition)?;
    entry.info = present_info;
    entry.status = present_status;
    Some(revert)
}

impl<G: Database + crate::parallel_transfer::AccountHint> BatchState<G> {
    /// The hint for an account a transaction a few places ahead will read
    /// (`N42_BUILD_MLP`): the batch's own entry prefetched when it holds the
    /// account ([`Self::prefetch_account`]); otherwise the hint goes down the
    /// parent's layers (`AccountHint`), each probing for it. Returns whether
    /// it went beneath this map.
    #[inline]
    pub fn hint_account(&self, address: &Address) -> bool {
        if self.accounts.contains_key(address) {
            self.prefetch_account(address);
            return false;
        }
        self.inner.hint_account(address);
        true
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

    /// `N42_TAKE_BUNDLE_TRANSFER`: the transfer-only close gives the generic close's bundle
    /// (and `State`'s) on a few hundred accounts -- existing with and without a nonce, empty
    /// (EIP-161) and missing recipients created by the transfer, a beneficiary, accounts only
    /// read -- through both `commit` and `commit_transfer`, with seedless storage maps.
    #[test]
    fn the_transfer_close_equals_the_generic_close() {
        let account = |i: u64| Address::from_word(B256::from(U256::from(i + 1)));
        let mut db = CacheDB::new(EmptyDB::default());
        // 0..100: funded, no nonce; 100..200: funded with a nonce; 200..300: empty.
        for i in 0..300u64 {
            let info = match i / 100 {
                0 => AccountInfo { balance: U256::from(1_000_000u64), ..Default::default() },
                1 => AccountInfo { balance: U256::from(2_000_000u64), nonce: i, ..Default::default() },
                _ => AccountInfo::default(),
            };
            db.insert_account_info(account(i), info);
        }
        let coinbase = account(0);
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let mut generic = BatchState::with_capacity(db.clone(), 600);
        let mut transfer = BatchState::with_capacity(db, 600);
        for k in 0..400u64 {
            let from = account(1 + k % 199);
            // Existing, empty, and missing (created by the transfer) recipients, some repeated.
            let to = match k % 4 {
                0 => account(k % 200),
                1 => account(200 + k % 100),
                2 => account(1_000 + k),
                _ => account(1_000 + k % 50),
            };
            // A transfer's three accounts are distinct.
            let to = if to == from || to == coinbase { account(1_000 + k) } else { to };
            let value = 10 + k;
            let made = changes(&mut state, from, to, coinbase, value);
            state.commit(made);
            for batch in [&mut generic, &mut transfer] {
                if k % 2 == 0 {
                    let made = changes(batch, from, to, coinbase, value);
                    batch.commit(made).expect("a plain transfer");
                } else {
                    let _ = changes(batch, from, to, coinbase, value);
                    let computed = plain(batch, from, to, coinbase, value);
                    batch.commit_transfer(computed).expect("a plain transfer");
                }
            }
        }
        // Accounts only read stay out of both.
        for i in 5_000..5_010u64 {
            assert!(generic.basic(account(i)).expect("read").is_none());
            assert!(transfer.basic(account(i)).expect("read").is_none());
        }
        // The knob's loaded accounts: seedless storage maps.
        for entry in transfer.accounts.values_mut() {
            entry.storage = seedless_storage();
        }
        state.merge_transitions(BundleRetention::Reverts);
        let mut theirs = state.take_bundle();
        let mut generic = generic.take_bundle_generic();
        let mut ours = transfer.take_bundle_transfer();
        for bundle in [&mut theirs, &mut generic, &mut ours] {
            for reverts in bundle.reverts.iter_mut() {
                reverts.sort_by_key(|(address, _)| *address);
            }
        }
        assert!(ours.state.len() > 300, "{} accounts changed", ours.state.len());
        assert_eq!(ours, generic);
        assert_eq!(ours.state, theirs.state);
        assert_eq!(ours.contracts, theirs.contracts);
        assert_eq!(ours.reverts, theirs.reverts);
        assert_eq!((ours.state_size, ours.reverts_size), (theirs.state_size, theirs.reverts_size));
        assert!(transfer.accounts.is_empty());
    }

    #[test]
    fn a_seedless_loaded_account_equals_the_default_one() {
        for info in [None, Some(AccountInfo::default()), Some(funded())] {
            assert_eq!(loaded_with(info.clone(), true), loaded_with(info, false));
        }
        assert!(seedless_storage().is_empty() && seedless_revert_storage().is_empty());
    }

    use revm::state::EvmStorageSlot;

    fn funded_db() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        for i in 1..=3u8 {
            db.insert_account_info(addr(i), AccountInfo { balance: U256::from(1_000u64), ..Default::default() });
        }
        db
    }

    fn touched(info: AccountInfo) -> Account {
        let mut account = Account::from(info);
        account.mark_touch();
        account
    }

    fn funded() -> AccountInfo {
        AccountInfo { balance: U256::from(10u64), ..Default::default() }
    }

    #[test]
    fn changes_the_transfer_path_never_makes_are_refused_by_account() {
        let refused = |account: Account| {
            let mut batch = BatchState::with_capacity(funded_db(), 1);
            let mut changes = EvmState::default();
            changes.insert(addr(1), account);
            batch.commit(changes).expect_err("not a transfer's change").0
        };
        let mut destroyed = touched(funded());
        destroyed.mark_selfdestruct();
        assert_eq!(refused(destroyed), addr(1));
        let mut created = touched(funded());
        created.mark_created();
        assert_eq!(refused(created), addr(1));
        // Emptied by the change.
        assert_eq!(refused(touched(AccountInfo::default())), addr(1));
        // A storage write.
        let mut written = touched(funded());
        written.storage.insert(U256::from(1), EvmStorageSlot::new_changed(U256::ZERO, U256::from(2), TransactionId::ZERO));
        assert_eq!(refused(written), addr(1));
    }

    #[test]
    fn an_untouched_account_in_the_changes_is_skipped() {
        let mut batch = BatchState::with_capacity(funded_db(), 1);
        let mut changes = EvmState::default();
        changes.insert(addr(1), Account::from(funded()));
        batch.commit(changes).expect("nothing to apply");
        assert!(batch.accounts.is_empty());
        let bundle = batch.take_bundle();
        assert!(bundle.state.is_empty() && bundle.reverts.is_empty());
    }

    #[test]
    fn a_batch_that_only_read_closes_with_the_empty_bundle() {
        let mut batch = BatchState::with_capacity(funded_db(), 2);
        assert_eq!(batch.basic(addr(1)).expect("read").map(|i| i.balance), Some(U256::from(1_000u64)));
        assert!(batch.basic(addr(9)).expect("read").is_none());
        let bundle = batch.take_bundle();
        assert!(bundle.state.is_empty());
        assert!(bundle.reverts.is_empty());
        assert_eq!((bundle.state_size, bundle.reverts_size), (0, 0));
        assert!(batch.accounts.is_empty(), "the batch holds nothing afterwards");
    }

    #[test]
    fn a_changed_account_is_in_the_bundle_with_its_original_and_a_revert() {
        let mut batch = BatchState::with_capacity(funded_db(), 1);
        let mut changes = EvmState::default();
        // Committed without a prior read: loaded as it was before the change.
        changes.insert(addr(2), {
            let mut account = Account::from(AccountInfo { balance: U256::from(1_000u64), ..Default::default() });
            account.info.balance = U256::from(900u64);
            account.mark_touch();
            account
        });
        batch.commit(changes).expect("a plain change");
        let bundle = batch.take_bundle();
        let account = bundle.state.get(&addr(2)).expect("changed");
        assert_eq!(account.info.as_ref().map(|i| i.balance), Some(U256::from(900u64)));
        assert_eq!(account.original_info.as_ref().map(|i| i.balance), Some(U256::from(1_000u64)));
        assert_eq!(bundle.reverts.len(), 1);
        assert_eq!(bundle.reverts[0].len(), 1);
        assert!(bundle.state_size > 0 && bundle.reverts_size > 0);
    }

    #[test]
    fn a_new_recipient_that_did_not_exist_is_created_by_the_change() {
        let mut batch = BatchState::with_capacity(funded_db(), 1);
        let mut changes = EvmState::default();
        let mut account = Account::new_not_existing(TransactionId::ZERO);
        account.info.balance = U256::from(3u64);
        account.mark_touch();
        changes.insert(addr(50), account);
        batch.commit(changes).expect("a plain change");
        let bundle = batch.take_bundle();
        let account = bundle.state.get(&addr(50)).expect("present");
        assert!(account.original_info.is_none(), "it did not exist before the batch");
        assert_eq!(account.info.as_ref().map(|i| i.balance), Some(U256::from(3u64)));
    }

    fn transfer_of(sender: AccountInfo, recipient: Option<AccountInfo>, recipient_balance: u64, coinbase_balance: u64) -> PlainTransfer {
        PlainTransfer {
            caller: addr(1),
            sender_balance: U256::from(500u64),
            sender,
            to: addr(2),
            recipient_balance: U256::from(recipient_balance),
            recipient,
            beneficiary: addr(3),
            coinbase_balance: U256::from(coinbase_balance),
            coinbase: AccountInfo { balance: U256::from(1_000u64), ..Default::default() },
        }
    }

    fn read_all(batch: &mut BatchState<CacheDB<EmptyDB>>) {
        for i in 1..=3u8 {
            batch.basic(addr(i)).expect("read");
        }
    }

    #[test]
    fn a_computed_transfer_needs_its_accounts_read_and_none_left_empty() {
        let sender = AccountInfo { balance: U256::from(1_000u64), ..Default::default() };
        let recipient = Some(AccountInfo { balance: U256::from(1_000u64), ..Default::default() });
        // Not read through the batch: refused, naming the first account.
        let mut batch = BatchState::with_capacity(funded_db(), 3);
        let err = batch.commit_transfer(transfer_of(sender.clone(), recipient.clone(), 1_500, 1_100)).expect_err("unread");
        assert_eq!(err.0, addr(1));
        // A recipient that ends empty (zero balance, no nonce) is refused.
        let mut batch = BatchState::with_capacity(funded_db(), 3);
        read_all(&mut batch);
        let err = batch.commit_transfer(transfer_of(sender.clone(), None, 0, 1_100)).expect_err("empty recipient");
        assert_eq!(err.0, addr(2));
        // A beneficiary that ends empty is refused.
        let mut batch = BatchState::with_capacity(funded_db(), 3);
        read_all(&mut batch);
        let err = batch.commit_transfer(transfer_of(sender.clone(), recipient.clone(), 1_500, 0)).expect_err("empty beneficiary");
        assert_eq!(err.0, addr(3));
        // The ordinary transfer commits: nonce bumped, balances replaced.
        let mut batch = BatchState::with_capacity(funded_db(), 3);
        read_all(&mut batch);
        batch.commit_transfer(transfer_of(sender, recipient, 1_500, 1_100)).expect("plain");
        let bundle = batch.take_bundle();
        let sender_after = bundle.state.get(&addr(1)).and_then(|a| a.info.clone()).expect("sender");
        assert_eq!((sender_after.nonce, sender_after.balance), (1, U256::from(500u64)));
        assert_eq!(bundle.state.get(&addr(2)).and_then(|a| a.info.as_ref().map(|i| i.balance)), Some(U256::from(1_500u64)));
        assert_eq!(bundle.state.get(&addr(3)).and_then(|a| a.info.as_ref().map(|i| i.balance)), Some(U256::from(1_100u64)));
    }

    #[test]
    fn storage_code_and_block_hashes_pass_through_to_the_parent_state() {
        let mut db = funded_db();
        let code = Bytecode::new_raw(vec![0x60, 0x00].into());
        let hash = code.hash_slow();
        db.insert_account_info(addr(7), AccountInfo { code_hash: hash, code: Some(code.clone()), ..Default::default() });
        db.insert_account_storage(addr(7), U256::from(4), U256::from(44)).expect("storage");
        let mut batch = BatchState::with_capacity(db, 1);
        assert_eq!(batch.storage(addr(7), U256::from(4)).expect("read"), U256::from(44));
        assert_eq!(batch.storage(addr(7), U256::from(5)).expect("read"), U256::ZERO);
        assert_eq!(batch.code_by_hash(hash).expect("read").original_bytes(), code.original_bytes());
        // EmptyDB hashes a block number as the keccak of its decimal text.
        assert_eq!(batch.block_hash(3).expect("read"), alloy_primitives::keccak256("3"));
        assert!(batch.accounts.is_empty(), "none of them is an account read");
    }

    #[test]
    fn the_refusal_names_the_account() {
        let text = Unsupported(addr(0x2a)).to_string();
        assert!(text.contains(&addr(0x2a).to_string()), "{text}");
    }
}
