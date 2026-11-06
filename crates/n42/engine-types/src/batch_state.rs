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
//! Unlike the revm-era batch state ([`crate::batch_state_legacy`] under
//! `legacy-revm-paths`) this is not the batch's database: an evm2 `Evm` owns
//! and caches its database, so the read side is the batch's read layers and
//! this is only the accumulator.

use alloy_primitives::{map::AddressMap, Address};
use evm2::evm::{AccountChanges, AccountInfo, PendingState};
use reth_trie::bundle_state::{AccountStatus, BundleRetention, BundleState, TransitionAccount, TransitionState};

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
    transitions: AddressMap<TransitionAccount>,
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
        Self { transitions: AddressMap::with_capacity_and_hasher(accounts, Default::default()) }
    }

    /// Accounts the batch has changed so far.
    pub fn len(&self) -> usize {
        self.transitions.len()
    }

    /// Whether the batch has changed nothing.
    pub fn is_empty(&self) -> bool {
        self.transitions.is_empty()
    }

    /// Whether the batch has changed `address`.
    pub fn holds(&self, address: &Address) -> bool {
        self.transitions.contains_key(address)
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
        match self.transitions.entry(address) {
            alloy_primitives::map::Entry::Vacant(entry) => {
                let previous_status = loaded_status(original.as_ref());
                entry.insert(TransitionAccount {
                    info: Some(current),
                    status: previous_status.on_changed(had_no_nonce_and_code),
                    previous_info: original,
                    previous_status,
                    storage: Default::default(),
                    storage_was_destroyed: false,
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
    pub fn take_bundle(&mut self) -> BundleState {
        let transitions = std::mem::take(&mut self.transitions);
        let mut bundle = BundleState::default();
        bundle.apply_transitions_and_create_reverts(TransitionState { transitions }, BundleRetention::Reverts);
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
