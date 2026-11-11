// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A parallel batch's changes on evm2 (reth v2.9.0): the part of reth's
//! block accumulator ([`reth_execution_types::BlockState`]) the transfer path
//! needs, plus the refusals that keep a batch's bundle graftable.
//!
//! A batch runs its transactions on an evm2 `Evm` over the parent's state,
//! and after each one hands the finalised transaction's account changes
//! ([`evm2::evm::PendingState::account_changes`]) to [`BatchState::commit`].
//! An account change is folded into the batch's transition for that account
//! by exactly the rule `BlockState::commit_account_changes` applies (the
//! loaded status from the transaction's original, then
//! `AccountStatus::on_changed`), so [`BatchState::take_bundle`] is the bundle
//! `BlockState::into_bundle` would make of the same transactions
//! (`apply_transitions_and_create_reverts` with `BundleRetention::Reverts`).
//!
//! Only the transfer path's changes are modelled: an account whose info
//! changed, not created, not destroyed, not left empty, no storage written,
//! no code deployed. Anything else is refused ([`Unsupported`]) and the batch
//! sends the block to the serial path. The graft that folds batch bundles
//! into the block's bundle relies on exactly these refusals: a batch account
//! carries no storage, no code and no selfdestruct.
//!
//! Unlike the revm-era batch state (removed in F6a) this is not the batch's
//! database: an evm2 `Evm` owns
//! and caches its database, so the read side is the batch's read layers and
//! this is only the accumulator.

use alloy_primitives::{map::AddressMap, Address};
use evm2::evm::{AccountChanges, AccountInfo, Database, PendingState};
use reth_trie::bundle_state::{AccountStatus, BundleAccount, BundleState, TransitionAccount};

/// A change [`BatchState::commit`] does not model: the transfer path never
/// makes one, and a batch that meets one sends the block to the serial
/// builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported(pub Address);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "account {} changed in a way the batch state does not model", self.0)
    }
}

impl std::error::Error for Unsupported {}

/// A build or import batch's account transitions against the parent's state.
#[derive(Debug, Default)]
pub struct BatchState {
    /// Each changed account as the bundle will hold it: its info now, its
    /// info at the batch's start (`original_info`, the transition's
    /// `previous_info`) and its status. [`Self::take_bundle`] turns this map
    /// into the bundle's in place, without a second map to fill.
    accounts: AddressMap<BundleAccount>,
}

/// The status of an account as it was loaded, before its first change
/// (reth's `compat::loaded_status`).
fn loaded_status(info: Option<&AccountInfo>) -> AccountStatus {
    match info {
        None => AccountStatus::LoadedNotExisting,
        Some(info) if info.is_empty() => AccountStatus::LoadedEmptyEIP161,
        Some(_) => AccountStatus::Loaded,
    }
}

/// Whether the batch changed `entry` (an entry only read keeps the status
/// it was loaded with; a change never leaves an account at a loaded status,
/// `AccountStatus::on_changed`).
fn changed(entry: &BundleAccount) -> bool {
    entry.status != loaded_status(entry.original_info.as_ref())
}

/// An account info without its code, as reth's bundle keeps it (code lives
/// in the bundle's contracts by hash).
fn without_code(info: &AccountInfo) -> AccountInfo {
    let mut info = info.clone();
    info.code = None;
    info
}

impl BatchState {
    /// A batch with room for `accounts` transitions without regrowing.
    pub fn with_capacity(accounts: usize) -> Self {
        Self { accounts: AddressMap::with_capacity_and_hasher(accounts, Default::default()) }
    }

    /// Accounts the batch has changed so far.
    pub fn len(&self) -> usize {
        self.accounts.values().filter(|entry| changed(entry)).count()
    }

    /// Whether the batch has changed nothing.
    pub fn is_empty(&self) -> bool {
        !self.accounts.values().any(changed)
    }

    /// Whether the batch has changed `address`.
    pub fn holds(&self, address: &Address) -> bool {
        self.accounts.get(address).is_some_and(changed)
    }

    /// `address` as the batch sees it now: its info after the batch's
    /// changes, or as read when it has none; read from `inner` and kept here
    /// (as read, no change) when the batch has not met it. The direct
    /// transfer path's read layer (F5g10): one map for what the batch read
    /// and what it changed, one probe for each. An account only read stays
    /// out of the bundle ([`Self::take_bundle`]). The info is without its
    /// code, as the state provider gives it; nothing is kept on a read error.
    pub fn read<D: Database>(&mut self, address: &Address, inner: &mut D) -> Result<Option<AccountInfo>, D::Error> {
        match self.accounts.entry(*address) {
            alloy_primitives::map::Entry::Occupied(entry) => Ok(entry.get().info.clone()),
            alloy_primitives::map::Entry::Vacant(entry) => {
                let read = inner.get_account(address)?.map(|mut info| {
                    info.code = None;
                    info
                });
                entry.insert(BundleAccount {
                    info: read.clone(),
                    original_info: read.clone(),
                    storage: Default::default(),
                    status: loaded_status(read.as_ref()),
                });
                Ok(read)
            }
        }
    }

    /// [`Self::commit_info`] of `address`, which the batch holds (read
    /// through [`Self::read`] or changed), from `before` (its info now) to
    /// `current` (`before` is `None` for an account that does not exist):
    /// the entry's info replaced and its status moved on, by the same rule,
    /// without copying the infos again.
    pub fn change_held(&mut self, address: Address, before: Option<&AccountInfo>, mut current: AccountInfo) {
        let had_no_nonce_and_code = before.is_none_or(|i| i.nonce == 0 && i.is_empty_code_hash());
        current.code = None;
        match self.accounts.get_mut(&address) {
            Some(account) => {
                account.status = account.status.on_changed(had_no_nonce_and_code);
                account.info = Some(current);
            }
            None => self.commit_info(address, before, &current),
        }
    }

    /// The batch's changed accounts at their present infos: what a read layer
    /// over the parent's state must answer for them once the batch hands its
    /// transactions to an EVM (accounts only read are the parent's).
    pub fn changed_infos(&self) -> impl Iterator<Item = (Address, Option<AccountInfo>)> + '_ {
        self.accounts.iter().filter(|(_, entry)| changed(entry)).map(|(address, entry)| (*address, entry.info.clone()))
    }

    /// Folds one finalised transaction's changes into the batch.
    pub fn commit(&mut self, pending: &PendingState) -> Result<(), Unsupported> {
        for changes in pending.account_changes() {
            self.commit_account(changes)?;
        }
        Ok(())
    }

    /// Folds one account's transaction changes into the batch, as
    /// `BlockState::commit_account_changes` folds them into the block, or
    /// refuses a change the transfer path never makes.
    pub fn commit_account(&mut self, changes: AccountChanges<'_>) -> Result<(), Unsupported> {
        if !changes.is_changed() {
            return Ok(());
        }
        let address = changes.address;
        let Some(current) = changes.current else { return Err(Unsupported(address)) };
        if changes.created
            || changes.selfdestructed
            || changes.code.is_some()
            || changes.storage.wiped
            || changes.storage.is_changed()
            || current.is_empty()
        {
            return Err(Unsupported(address));
        }
        self.commit_info(address, changes.original, current);
        Ok(())
    }

    /// Folds one account's change from `original` (its info at the
    /// transaction's start, `None` for an account that did not exist) to
    /// `current` into the batch, by the rule [`Self::commit_account`]
    /// applies: the direct transfer path's commit (F5g10), which makes only
    /// changes that rule accepts.
    pub fn commit_info(&mut self, address: Address, original: Option<&AccountInfo>, current: &AccountInfo) {
        let original = original.map(without_code);
        let current = without_code(current);
        let had_no_nonce_and_code = original.as_ref().is_none_or(|i| i.nonce == 0 && i.is_empty_code_hash());
        match self.accounts.entry(address) {
            alloy_primitives::map::Entry::Vacant(entry) => {
                let previous_status = loaded_status(original.as_ref());
                entry.insert(BundleAccount {
                    info: Some(current),
                    status: previous_status.on_changed(had_no_nonce_and_code),
                    original_info: original,
                    storage: Default::default(),
                });
            }
            alloy_primitives::map::Entry::Occupied(mut entry) => {
                let account = entry.get_mut();
                account.status = account.status.on_changed(had_no_nonce_and_code);
                account.info = Some(current);
            }
        }
    }

    /// The batch's changes against the parent with their reverts: the bundle
    /// `BlockState::into_bundle` makes of the same transitions. The batch
    /// holds nothing afterwards.
    ///
    /// What `apply_transitions_and_create_reverts` does for a transition new
    /// to an empty bundle, done in this map: an entry is the transition's
    /// present bundle account already, so it stays where it is when the
    /// transition has a revert and is dropped otherwise -- no second map
    /// filled entry by entry (the revm-era batch state's one pass).
    pub fn take_bundle(&mut self) -> BundleState {
        let mut accounts = std::mem::take(&mut self.accounts);
        let mut bundle = BundleState::default();
        let mut reverts = Vec::with_capacity(accounts.len());
        let (mut state_size, mut reverts_size) = (0usize, 0usize);
        accounts.retain(|address, entry| {
            if !changed(entry) {
                return false;
            }
            let transition = TransitionAccount {
                info: entry.info.clone(),
                status: entry.status,
                previous_info: entry.original_info.clone(),
                previous_status: loaded_status(entry.original_info.as_ref()),
                storage: Default::default(),
                storage_was_destroyed: false,
            };
            if let Some((hash, code)) = transition.has_new_contract() {
                bundle.contracts.insert(hash, code.clone());
            }
            let Some(revert) = transition.create_revert() else { return false };
            state_size += entry.size_hint();
            reverts_size += revert.size_hint();
            reverts.push((*address, revert));
            true
        });
        bundle.state = accounts;
        bundle.reverts.push(reverts);
        bundle.state_size = state_size;
        bundle.reverts_size = reverts_size;
        bundle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n42_evm::N42EvmConfig;
    use alloy_consensus::{Signed, TxEip1559, TxLegacy};
    use alloy_primitives::{Bytes, Signature, TxKind, B256, U256};
    use evm2::{
        bytecode::Bytecode,
        evm::{CacheDB, EmptyDB},
    };
    use n42_tx_types::N42TxEnvelope;
    use reth_evm::ConfigureEvm as _;
    use reth_execution_types::BlockState;
    use reth_primitives_traits::Recovered;
    use std::sync::Arc;

    type Config = N42EvmConfig<n42_header::N42ChainSpec>;

    fn config() -> Config {
        let genesis: alloy_genesis::Genesis =
            serde_json::from_str(include_str!("../../../chainspec/res/genesis/n42_devnet.json")).expect("genesis");
        N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from_genesis(genesis))))
    }

    fn addr(i: u64) -> Address {
        Address::left_padding_from(&i.to_be_bytes())
    }

    const BENEFICIARY: u64 = 0xbe;
    /// A contract that stores its calldata's first word at slot 0.
    const STORE: u64 = 0x5701;
    const FUND: u64 = 1_000_000_000_000_000_000;

    fn parent() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        for i in 1..=40 {
            db.insert_account_info(&addr(i), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        }
        db.insert_account_info(&addr(BENEFICIARY), AccountInfo { balance: U256::from(1u64), ..Default::default() });
        // PUSH1 0 CALLDATALOAD PUSH1 0 SSTORE STOP
        let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00]));
        db.insert_account_info(&addr(STORE), AccountInfo::default().with_code(code));
        db
    }

    fn tx(from: u64, nonce: u64, to: Address, value: u64, input: Bytes) -> Recovered<N42TxEnvelope> {
        let tx = TxEip1559 {
            chain_id: 1143,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: TxKind::Call(to),
            value: U256::from(value),
            input,
            ..Default::default()
        };
        let signed = Signed::new_unchecked(tx, Signature::test_signature(), B256::with_last_byte(nonce as u8));
        Recovered::new_unchecked(N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::from(signed)), addr(from))
    }

    fn header() -> n42_header::N42Header {
        n42_header::N42Header::from(alloy_consensus::Header {
            number: 5,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            beneficiary: addr(BENEFICIARY),
            ..Default::default()
        })
    }

    /// Runs `txs` on one EVM over the parent, every transaction's changes
    /// folded into both reth's block accumulator and a batch state.
    fn run(txs: &[Recovered<N42TxEnvelope>]) -> (BundleState, Result<BundleState, Unsupported>) {
        let c = config();
        let env = c.evm_env(&header()).expect("env");
        let mut evm = c.evm_with_env(parent(), env);
        let (mut block, mut batch) = (BlockState::new(), BatchState::with_capacity(8));
        let mut refused = None;
        for t in txs {
            let t = t.clone().map(evm2::ethereum::TxEnvelope::from);
            let executed = evm.transact(&t).expect("the transaction executes").detach();
            for changes in executed.pending_state.account_changes() {
                block.commit_account_changes(changes, None);
            }
            if refused.is_none()
                && let Err(err) = batch.commit(&executed.pending_state)
            {
                refused = Some(err);
            }
            evm.state_mut().set_pending_state(executed.pending_state);
            evm.state_mut().commit_transaction();
        }
        let ours = match refused {
            Some(err) => Err(err),
            None => Ok(batch.take_bundle()),
        };
        (block.into_bundle(), ours)
    }

    fn sorted_reverts(bundle: &BundleState) -> Vec<Vec<(Address, String)>> {
        bundle
            .reverts
            .iter()
            .map(|block| {
                let mut v: Vec<_> = block.iter().map(|(a, r)| (*a, format!("{r:?}"))).collect();
                v.sort_by_key(|(a, _)| *a);
                v
            })
            .collect()
    }

    fn assert_same(ours: &BundleState, theirs: &BundleState) {
        assert_eq!(ours.state, theirs.state, "state");
        assert_eq!(ours.contracts, theirs.contracts, "contracts");
        assert_eq!(sorted_reverts(ours), sorted_reverts(theirs), "reverts");
        assert_eq!(ours.state_size, theirs.state_size, "state size");
        assert_eq!(ours.reverts_size, theirs.reverts_size, "reverts size");
    }

    /// Transfers with repeated senders, a recipient that sends later, a
    /// recipient that did not exist, and the beneficiary credited by every
    /// one: the batch's bundle is the block accumulator's, field for field.
    #[test]
    fn the_batch_bundle_equals_the_block_accumulators() {
        let fresh = addr(0xf00d);
        let txs = vec![
            tx(1, 0, addr(2), 10, Bytes::new()),
            tx(1, 1, addr(3), 11, Bytes::new()),
            tx(2, 0, addr(4), 12, Bytes::new()),
            tx(3, 0, fresh, 13, Bytes::new()),
            tx(5, 0, addr(1), 14, Bytes::new()),
            tx(6, 0, fresh, 15, Bytes::new()),
        ];
        let (theirs, ours) = run(&txs);
        let ours = ours.expect("plain transfers are modelled");
        assert_same(&ours, &theirs);
        assert!(ours.state.contains_key(&fresh) && ours.state.contains_key(&addr(BENEFICIARY)));
        assert_eq!(ours.state[&fresh].status, AccountStatus::InMemoryChange);
    }

    /// A legacy transfer and an EIP-1559 one in the same batch.
    #[test]
    fn a_legacy_transfer_folds_the_same() {
        let legacy = TxLegacy {
            chain_id: Some(1143),
            nonce: 0,
            gas_price: 100,
            gas_limit: 21_000,
            to: TxKind::Call(addr(9)),
            value: U256::from(5u64),
            input: Bytes::new(),
        };
        let signed = Signed::new_unchecked(legacy, Signature::test_signature(), B256::with_last_byte(0xaa));
        let txs = vec![Recovered::new_unchecked(N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::from(signed)), addr(8)), tx(9, 0, addr(8), 1, Bytes::new())];
        let (theirs, ours) = run(&txs);
        assert_same(&ours.expect("modelled"), &theirs);
    }

    /// Accounts only read through `read` (one there, one missing) stay out of
    /// the bundle, and an account read and then changed folds exactly as the
    /// same change committed without the read.
    #[test]
    fn a_read_account_folds_as_an_unread_one() {
        let mut db = parent();
        let (a, b, missing) = (addr(1), addr(2), addr(0xdead));
        let mut read_first = BatchState::with_capacity(4);
        let before = read_first.read(&a, &mut db).expect("read").expect("an account");
        assert!(read_first.read(&b, &mut db).expect("read").is_some());
        assert!(read_first.read(&missing, &mut db).expect("read").is_none());
        assert!(read_first.is_empty(), "nothing changed yet");
        let mut after = before.clone();
        after.balance -= U256::from(5u64);
        after.nonce += 1;
        read_first.change_held(a, Some(&before), after.clone());
        // A second change on top of the first.
        let mut again = after.clone();
        again.nonce += 1;
        read_first.change_held(a, Some(&after), again.clone());
        assert_eq!(read_first.read(&a, &mut db).expect("read"), Some(again.clone()), "the read answers the change");
        let mut plain = BatchState::with_capacity(4);
        plain.commit_info(a, Some(&before), &after);
        plain.commit_info(a, Some(&after), &again);
        assert_eq!(read_first.len(), 1);
        assert!(read_first.holds(&a) && !read_first.holds(&b) && !read_first.holds(&missing));
        assert_same(&read_first.take_bundle(), &plain.take_bundle());
    }

    /// A storage write is not the transfer path's: refused, naming the
    /// contract.
    #[test]
    fn a_storage_write_is_refused() {
        let word = Bytes::from(U256::from(7u64).to_be_bytes::<32>().to_vec());
        let txs = vec![tx(1, 0, addr(2), 1, Bytes::new()), tx(3, 0, addr(STORE), 0, word)];
        let (_, ours) = run(&txs);
        assert_eq!(ours.unwrap_err(), Unsupported(addr(STORE)));
    }

    /// A contract creation is refused.
    #[test]
    fn a_creation_is_refused() {
        let create = TxEip1559 {
            chain_id: 1143,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: TxKind::Create,
            // PUSH1 0 PUSH1 0 RETURN: deploys empty code, but creates the account.
            input: Bytes::from_static(&[0x60, 0x01, 0x60, 0x00, 0xf3]),
            ..Default::default()
        };
        let signed = Signed::new_unchecked(create, Signature::test_signature(), B256::with_last_byte(0xc0));
        let txs = vec![Recovered::new_unchecked(N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::from(signed)), addr(4))];
        let (_, ours) = run(&txs);
        assert!(ours.is_err(), "a creation must be refused");
    }
}
