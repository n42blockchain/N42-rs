//! In-memory state shared by the state and blockchain test executors
//!
//! Both executors load the fixture's pre-state into an evm2 [`InMemoryDB`] (a cache over an
//! empty backing database), let the EVM or reth's block executor write into it, and compute the
//! state root from the cache with `alloy_trie`'s unhashed helpers.

use crate::models::Account;

use alloy_primitives::{Address, B256, U256};
use alloy_trie::{
    root::{state_root_unhashed, storage_root_unhashed},
    TrieAccount, EMPTY_ROOT_HASH,
};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB},
};
use hashbrown::HashMap;
use reth_primitives_traits::Account as RethAccount;

/// Builds an in-memory database holding the given pre-state.
pub(crate) fn build_pre_state_db(pre: &HashMap<Address, Account>) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    for (address, account) in pre {
        let mut info = AccountInfo::empty().with_balance(account.balance).with_nonce(account.nonce);
        if !account.code.is_empty() {
            // `insert_account_info` derives the code hash from the bytecode.
            info = info.with_code(Bytecode::new_raw(account.code.clone()));
        }
        db.insert_account_info(address, info);
        for (key, value) in &account.storage {
            db.insert_account_storage(address, key, value);
        }
    }
    db
}

/// Computes the state root of every account the database knows to exist.
///
/// Accounts cached as absent (never existed, or destroyed) are left out. Empty accounts are
/// left out unless `include_empty` is set (before EIP-161, Spurious Dragon, they stay in the
/// trie).
pub(crate) fn state_root_of_db(db: &InMemoryDB, include_empty: bool) -> B256 {
    let accounts = db.cache.accounts.iter().filter_map(|(address, info)| {
        let info = info.as_ref()?;
        let code_empty = info.is_empty_code_hash() || info.code_hash.is_zero();
        if !include_empty && info.balance.is_zero() && info.nonce == 0 && code_empty {
            return None;
        }
        let storage_root = db
            .cache
            .storage
            .get(address)
            .map_or(EMPTY_ROOT_HASH, |storage| storage_root_of(storage.slots.iter()));
        let account = RethAccount {
            nonce: info.nonce,
            balance: info.balance,
            bytecode_hash: (!code_empty).then_some(info.code_hash),
        };
        Some((*address, account.into_trie_account(storage_root)))
    });
    state_root_unhashed(accounts)
}

/// Computes the state root of a fixture's account map (`pre` or `postState`).
pub(crate) fn state_root_of_accounts(
    accounts: &HashMap<Address, Account>,
    include_empty: bool,
) -> B256 {
    let accounts = accounts.iter().filter_map(|(address, account)| {
        if !include_empty && account.is_empty() {
            return None;
        }
        Some((*address, trie_account(account)))
    });
    state_root_unhashed(accounts)
}

/// Converts a fixture account into its trie leaf.
fn trie_account(account: &Account) -> TrieAccount {
    let account_root = storage_root_of(account.storage.iter());
    let reth_account = RethAccount {
        nonce: account.nonce,
        balance: account.balance,
        bytecode_hash: (!account.code.is_empty()).then(|| account.code_hash()),
    };
    reth_account.into_trie_account(account_root)
}

/// Computes a storage root, skipping zero slots.
fn storage_root_of<'a>(slots: impl Iterator<Item = (&'a U256, &'a U256)>) -> B256 {
    let slots: Vec<(B256, U256)> =
        slots.filter(|(_, value)| !value.is_zero()).map(|(k, v)| (B256::from(*k), *v)).collect();
    if slots.is_empty() {
        EMPTY_ROOT_HASH
    } else {
        storage_root_unhashed(slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    fn sample_pre() -> HashMap<Address, Account> {
        let mut storage = HashMap::new();
        storage.insert(U256::from(1), U256::from(42));
        storage.insert(U256::from(2), U256::ZERO);
        let mut pre = HashMap::new();
        pre.insert(
            Address::with_last_byte(1),
            Account {
                nonce: 1,
                balance: U256::from(1000),
                code: Bytes::from_static(&[0x60, 0x00]),
                storage,
            },
        );
        pre.insert(Address::with_last_byte(2), Account::new());
        pre
    }

    #[test]
    fn db_root_matches_fixture_root() {
        let pre = sample_pre();
        let db = build_pre_state_db(&pre);
        for include_empty in [false, true] {
            assert_eq!(
                state_root_of_db(&db, include_empty),
                state_root_of_accounts(&pre, include_empty)
            );
        }
        assert_ne!(state_root_of_db(&db, false), state_root_of_db(&db, true));
    }

    #[test]
    fn pre_state_db_holds_accounts() {
        let pre = sample_pre();
        let db = build_pre_state_db(&pre);
        let info = db.account_info(&Address::with_last_byte(1)).unwrap();
        assert_eq!(info.nonce, 1);
        assert_eq!(info.balance, U256::from(1000));
        assert_eq!(info.code_hash, pre[&Address::with_last_byte(1)].code_hash());
    }
}
