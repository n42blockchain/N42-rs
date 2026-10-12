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
use alloy_primitives::{map::AddressMap, Address, B256, U256};
use revm::{
    database::states::{reverts::AccountRevert, AccountStatus, BundleAccount, BundleState, TransitionAccount},
    primitives::KECCAK_EMPTY,
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
    /// `N42_ONE_PROBE=2`: the batch's lane, holding every account the plan
    /// says its transactions touch; `accounts` then holds only the rest (the
    /// beneficiary, and any account the lane cannot hold).
    lane: Option<DenseLane>,
}

/// [`Work::flags`]: the account was read into the lane.
const LOADED: u8 = 1;
/// [`Work::flags`]: the account existed when read.
const ORIG_SOME: u8 = 2;
/// [`Work::flags`]: the read info carried `Some` empty code.
const ORIG_CODE: u8 = 4;
/// [`Work::flags`]: the account exists now.
const CUR_SOME: u8 = 8;
/// [`Work::flags`]: the info now carries `Some` empty code.
const CUR_CODE: u8 = 16;
/// [`Work::flags`]: not a plain account; held in the batch's map instead.
const SPILL: u8 = 32;

/// One account of a batch's lane (`N42_ONE_PROBE=2`): the bundle account
/// the batch's transition becomes, for a plain account (no code beyond
/// `Some` empty code, no account id), in 96 bytes: the balance and nonce as
/// read and as they stand, the status, and which of the read and the
/// current info exist and carry `Some` empty code. Reconstructed into the
/// same `AccountInfo` values the map would hold.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(32))]
struct Work {
    balance: U256,
    orig_balance: U256,
    nonce: u64,
    orig_nonce: u64,
    status: AccountStatus,
    flags: u8,
}

impl Work {
    const EMPTY: Self =
        Self { balance: U256::ZERO, orig_balance: U256::ZERO, nonce: 0, orig_nonce: 0, status: AccountStatus::LoadedNotExisting, flags: 0 };

    /// The entry for an account as [`loaded`] made it, if the lane can hold
    /// it.
    fn from_loaded(info: Option<&AccountInfo>) -> Option<Self> {
        let status = loaded_status(info);
        let Some(info) = info else { return Some(Self { status, flags: LOADED, ..Self::EMPTY }) };
        if info.code_hash != KECCAK_EMPTY || info.account_id.is_some() || info.code.as_ref().is_some_and(|code| *code != Bytecode::default()) {
            return None;
        }
        let code = if info.code.is_some() { ORIG_CODE | CUR_CODE } else { 0 };
        Some(Self {
            balance: info.balance,
            orig_balance: info.balance,
            nonce: info.nonce,
            orig_nonce: info.nonce,
            status,
            flags: LOADED | ORIG_SOME | CUR_SOME | code,
        })
    }

    /// A plain account's info; `code` the lane's own empty bytecode, cloned
    /// when the info carries `Some` empty code (a fresh `Bytecode::default()`
    /// a read was most of a lane read's cost).
    #[inline]
    fn make(balance: U256, nonce: u64, code: Option<&Bytecode>) -> AccountInfo {
        AccountInfo { balance, nonce, code_hash: KECCAK_EMPTY, account_id: None, code: code.cloned() }
    }

    /// The info as it stands.
    #[inline]
    fn info(&self, empty: &Bytecode) -> Option<AccountInfo> {
        (self.flags & CUR_SOME != 0).then(|| Self::make(self.balance, self.nonce, (self.flags & CUR_CODE != 0).then_some(empty)))
    }

    /// The info as read.
    fn original(&self, empty: &Bytecode) -> Option<AccountInfo> {
        (self.flags & ORIG_SOME != 0).then(|| Self::make(self.orig_balance, self.orig_nonce, (self.flags & ORIG_CODE != 0).then_some(empty)))
    }

    /// [`change`] on the lane's entry.
    #[inline]
    fn change(&mut self, info: &AccountInfo) {
        let had_no_nonce_and_code = self.flags & CUR_SOME != 0 && self.nonce == 0;
        self.status = self.status.on_changed(had_no_nonce_and_code);
        self.balance = info.balance;
        self.nonce = info.nonce;
        self.flags = (self.flags & !CUR_CODE) | CUR_SOME | if info.code.is_some() { CUR_CODE } else { 0 };
    }
}

/// A batch's lane (`N42_ONE_PROBE=2`): its entries by lane id, the plan
/// that names them, and the running transaction's two accounts and ids.
#[derive(Debug)]
struct DenseLane {
    plan: std::sync::Arc<crate::one_probe::Resolved>,
    batch: usize,
    work: Vec<Work>,
    cur: Option<(Address, Address, u32, u32)>,
    hits: u64,
    /// The lane's empty bytecode, cloned into the infos that carry one.
    empty: Bytecode,
    /// Entries read into the lane, counted when the bundle is taken.
    loaded: u64,
    /// `N42_ONE_PROBE=3`: the accounts several batches touch handed to the
    /// plan's lane fold when the bundle is taken.
    fold: bool,
}

impl DenseLane {
    /// The lane id of `address` when the running transaction names it.
    #[inline]
    fn lid(&self, address: &Address) -> Option<usize> {
        let (sender, recipient, s, r) = self.cur.as_ref()?;
        if address == sender {
            Some(*s as usize)
        } else if address == recipient {
            Some(*r as usize)
        } else {
            None
        }
    }
}

impl Drop for DenseLane {
    fn drop(&mut self) {
        if let Some(lanes) = self.plan.lanes.as_ref() {
            lanes.hits.fetch_add(self.hits, std::sync::atomic::Ordering::Relaxed);
            lanes.loaded.fetch_add(self.loaded, std::sync::atomic::Ordering::Relaxed);
        }
    }
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
        Self { inner, accounts: AddressMap::with_capacity_and_hasher(accounts, Default::default()), lane: None }
    }

    /// `N42_ONE_PROBE=2`: a batch over `inner` whose transactions are batch
    /// `batch` of `plan`'s lanes (checked by the caller): every account they
    /// touch is held in the lane, found by the running transaction's lane
    /// ids ([`Self::note_tx`]); the map keeps room for `accounts` others.
    /// A plan without lanes or batch makes the plain state.
    /// With `fold` (`N42_ONE_PROBE=3`) the accounts several batches touch
    /// are handed to the plan's lane fold ([`crate::one_probe::Lanes::fold_part`])
    /// when the bundle is taken.
    pub fn with_lane(inner: G, accounts: usize, plan: std::sync::Arc<crate::one_probe::Resolved>, batch: usize, fold: bool) -> Self {
        let mut state = Self::with_capacity(inner, accounts);
        if let Some(len) = plan.lanes.as_ref().and_then(|lanes| lanes.lane(batch)).map(<[Address]>::len) {
            state.lane = Some(DenseLane { plan, batch, work: vec![Work::EMPTY; len], cur: None, hits: 0, empty: Bytecode::default(), loaded: 0, fold });
        }
        state
    }

    /// Whether the batch runs on a lane.
    pub const fn on_lane(&self) -> bool {
        self.lane.is_some()
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
            if let Some(lane) = self.lane.as_mut()
                && let Some(lid) = lane.lid(&address)
                && let Some(work) = lane.work.get_mut(lid)
                && work.flags & SPILL == 0
            {
                if work.flags & LOADED == 0 || info.code_hash != KECCAK_EMPTY {
                    return Err(Unsupported(address));
                }
                work.change(&info);
                continue;
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
        // `N42_ONE_PROBE=2`: the lane's accounts put into the map here, at
        // the batch's end, in lane order: what the map path would hold.
        if let Some(lane) = self.lane.as_ref() {
            let lanes = lane.plan.lanes.as_ref();
            let addresses = lanes.and_then(|lanes| lanes.lane(lane.batch)).unwrap_or_default();
            // `N42_ONE_PROBE=3`: the lane fold's parts, in the same pass.
            let bids = lanes.filter(|_| lane.fold).and_then(|lanes| lanes.lane_bids(lane.batch)).unwrap_or_default();
            let mut parts = Vec::new();
            accounts.reserve(lane.work.len());
            for (lid, (work, address)) in lane.work.iter().zip(addresses).enumerate() {
                if work.flags & LOADED == 0 || work.flags & SPILL != 0 {
                    continue;
                }
                if let (Some(lanes), Some(&bid)) = (lanes, bids.get(lid))
                    && lanes.cross(bid)
                {
                    parts.push(crate::one_probe::FoldPart {
                        bid,
                        original: (work.flags & ORIG_SOME != 0).then_some((work.orig_balance, work.orig_nonce)),
                        current: (work.flags & CUR_SOME != 0).then_some((work.balance, work.nonce)),
                    });
                }
                accounts.insert(
                    *address,
                    BundleAccount {
                        original_info: work.original(&lane.empty),
                        info: work.info(&lane.empty),
                        storage: Default::default(),
                        status: work.status,
                    },
                );
            }
            if let Some(lanes) = lanes
                && !parts.is_empty()
            {
                lanes.fold_part(parts);
            }
        }
        if let Some(lane) = self.lane.as_mut() {
            for work in &mut lane.work {
                lane.loaded += u64::from(work.flags & LOADED != 0);
                *work = Work::EMPTY;
            }
        }
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
            if entry.status == loaded_status(entry.original_info.as_ref()) {
                return false;
            }
            changed = true;
            let Some(revert) = close(entry, |hash, code| {
                bundle.contracts.insert(hash, code.clone());
            }) else {
                return false;
            };
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

/// One changed account's close (`entry`'s status moved off its loaded one):
/// the revert `apply_transitions_and_create_reverts` makes for an account
/// new to the bundle (`TransitionAccount::create_revert`), `None` when it
/// makes none; `entry` is left as its `present_bundle_account`. A contract
/// the transition brings is handed to `contract`.
fn close(entry: &mut BundleAccount, mut contract: impl FnMut(B256, &Bytecode)) -> Option<AccountRevert> {
    let previous_status = loaded_status(entry.original_info.as_ref());
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
        contract(hash, code);
    }
    // `original_bundle_account`, updated by the transition.
    entry.info = entry.original_info.clone();
    entry.status = previous_status;
    let revert = entry.update_and_create_revert(transition)?;
    entry.info = present_info;
    entry.status = present_status;
    Some(revert)
}

/// A batch's lane handed over as the batch's output (`N42_ONE_PROBE=4`,
/// [`BatchState::take_output`]): the lane's entries as the batch left them
/// (96 bytes each), the lane ids of the changed ones, and their addresses
/// through the plan, with no `BundleAccount` made. [`Self::account`] and
/// [`Self::revert`] make the closed account and its revert exactly as
/// [`BatchState::take_bundle`] makes them; [`Self::get`] finds an address
/// through a table of positions (four bytes a slot) built at the hand-over.
#[derive(Clone)]
pub struct LaneOutput {
    plan: std::sync::Arc<crate::one_probe::Resolved>,
    batch: usize,
    work: Vec<Work>,
    /// Lane ids of the changed entries, in lane order: the output's
    /// positions.
    kept: Vec<u32>,
    /// Open addressing over the kept addresses: position + 1, 0 empty.
    slots: Vec<u32>,
    empty: Bytecode,
}

impl std::fmt::Debug for LaneOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneOutput").field("batch", &self.batch).field("accounts", &self.kept.len()).finish()
    }
}

/// [`LaneOutput`]'s table slot of `address` in a table of `mask + 1`.
#[inline]
fn lane_slot(address: &Address, mask: usize) -> usize {
    let bytes = &address.0 .0;
    let mut low = [0u8; 8];
    let mut high = [0u8; 8];
    low.copy_from_slice(&bytes[12..20]);
    high.copy_from_slice(&bytes[0..8]);
    let h = (u64::from_le_bytes(low) ^ u64::from_le_bytes(high).rotate_left(23)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (h >> 32) as usize & mask
}

impl LaneOutput {
    fn new(plan: std::sync::Arc<crate::one_probe::Resolved>, batch: usize, work: Vec<Work>, kept: Vec<u32>, empty: Bytecode) -> Self {
        let mut out = Self { plan, batch, work, kept, slots: Vec::new(), empty };
        let size = (out.kept.len() * 2).next_power_of_two().max(8);
        let mut slots = vec![0u32; size];
        let addresses = out.lane_addresses();
        for (pos, &lid) in out.kept.iter().enumerate() {
            let Some(address) = addresses.get(lid as usize) else { continue };
            let mut at = lane_slot(address, size - 1);
            while slots[at] != 0 {
                at = (at + 1) & (size - 1);
            }
            slots[at] = pos as u32 + 1;
        }
        out.slots = slots;
        out
    }

    fn lane_addresses(&self) -> &[Address] {
        self.plan.lanes.as_ref().and_then(|lanes| lanes.lane(self.batch)).unwrap_or_default()
    }

    /// The accounts held.
    pub fn len(&self) -> usize {
        self.kept.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.kept.is_empty()
    }

    /// The address at position `pos`.
    #[inline]
    pub fn address(&self, pos: usize) -> Option<&Address> {
        self.lane_addresses().get(*self.kept.get(pos)? as usize)
    }

    /// The position of `address`, if the batch changed it on its lane.
    #[inline]
    pub fn position(&self, address: &Address) -> Option<usize> {
        let mask = self.slots.len().checked_sub(1)?;
        let mut at = lane_slot(address, mask);
        loop {
            let pos = (*self.slots.get(at)?).checked_sub(1)? as usize;
            if self.address(pos) == Some(address) {
                return Some(pos);
            }
            at = (at + 1) & mask;
        }
    }

    /// The closed account at position `pos`, as the map's close leaves it.
    #[inline]
    pub fn account(&self, pos: usize) -> Option<BundleAccount> {
        let work = self.work.get(*self.kept.get(pos)? as usize)?;
        Some(BundleAccount {
            original_info: work.original(&self.empty),
            info: work.info(&self.empty),
            storage: Default::default(),
            status: work.status,
        })
    }

    /// The account at position `pos` with its revert, as the map's close
    /// makes them.
    pub fn closed(&self, pos: usize) -> Option<(BundleAccount, Option<AccountRevert>)> {
        let mut account = self.account(pos)?;
        let revert = close(&mut account, |_, _| {});
        Some((account, revert))
    }

    /// The account `address` as the batch left it, closed.
    pub fn get(&self, address: &Address) -> Option<BundleAccount> {
        self.account(self.position(address)?)
    }

    /// Every account with its address, in lane order, closed.
    pub fn iter(&self) -> impl Iterator<Item = (&Address, BundleAccount)> + '_ {
        (0..self.kept.len()).filter_map(|pos| Some((self.address(pos)?, self.account(pos)?)))
    }

    /// The accounts and their reverts as [`BatchState::take_bundle`] leaves
    /// them: the map form of this output.
    pub fn into_parts(self) -> (alloy_primitives::map::AddressHashMap<BundleAccount>, Vec<(Address, AccountRevert)>) {
        let mut map = alloy_primitives::map::AddressHashMap::with_capacity_and_hasher(self.kept.len(), Default::default());
        let mut reverts = Vec::with_capacity(self.kept.len());
        for pos in 0..self.kept.len() {
            let (Some(address), Some((account, revert))) = (self.address(pos), self.closed(pos)) else { continue };
            if let Some(revert) = revert {
                reverts.push((*address, revert));
                map.insert(*address, account);
            }
        }
        (map, reverts)
    }
}

impl<G: Database> BatchState<G> {
    /// `N42_ONE_PROBE=4`: [`Self::take_bundle`] with the lane handed over as
    /// it stands ([`LaneOutput`]) instead of put into the bundle's map: the
    /// bundle holds the map's accounts (the beneficiary, spilled ones), the
    /// lane's contracts (the empty code a created recipient carries), and the
    /// fold's parts are handed to the plan as there. `None` for the lane on
    /// a batch without one.
    pub fn take_output(&mut self) -> (BundleState, Option<LaneOutput>) {
        let Some(mut lane) = self.lane.take() else { return (self.take_bundle(), None) };
        let lanes = lane.plan.lanes.as_ref();
        let bids = lanes.filter(|_| lane.fold).and_then(|lanes| lanes.lane_bids(lane.batch)).unwrap_or_default();
        let mut parts = Vec::new();
        let mut kept = Vec::with_capacity(lane.work.len());
        let mut created = false;
        for (lid, work) in lane.work.iter().enumerate() {
            if work.flags & LOADED == 0 {
                continue;
            }
            lane.loaded += 1;
            if work.flags & SPILL != 0 {
                continue;
            }
            if let (Some(lanes), Some(&bid)) = (lanes, bids.get(lid))
                && lanes.cross(bid)
            {
                parts.push(crate::one_probe::FoldPart {
                    bid,
                    original: (work.flags & ORIG_SOME != 0).then_some((work.orig_balance, work.orig_nonce)),
                    current: (work.flags & CUR_SOME != 0).then_some((work.balance, work.nonce)),
                });
            }
            let original = (work.flags & ORIG_SOME != 0).then_some(work.orig_balance);
            if work.status == loaded_status_of(original.is_some(), work.orig_balance.is_zero() && work.orig_nonce == 0) {
                continue;
            }
            // `TransitionAccount::has_new_contract`: an account that did not
            // exist and now carries `Some` empty code.
            created |= work.flags & (ORIG_SOME | CUR_SOME | CUR_CODE) == CUR_SOME | CUR_CODE;
            kept.push(lid as u32);
        }
        if let Some(lanes) = lanes
            && !parts.is_empty()
        {
            lanes.fold_part(parts);
        }
        let mut bundle = self.take_bundle();
        if created {
            bundle.contracts.insert(KECCAK_EMPTY, lane.empty.clone());
        }
        let work = std::mem::take(&mut lane.work);
        let plan = std::sync::Arc::clone(&lane.plan);
        let out = LaneOutput::new(plan, lane.batch, work, kept, lane.empty.clone());
        (bundle, Some(out))
    }
}

/// [`loaded_status`] from whether the read info existed and was empty (a
/// lane's plain account: no code, so empty is a zero balance and nonce).
#[inline]
const fn loaded_status_of(existed: bool, empty: bool) -> AccountStatus {
    match (existed, empty) {
        (false, _) => AccountStatus::LoadedNotExisting,
        (true, true) => AccountStatus::LoadedEmptyEIP161,
        (true, false) => AccountStatus::Loaded,
    }
}

impl<G: Database + crate::parallel_transfer::AccountHint> BatchState<G> {
    /// `N42_ONE_PROBE`: the batch loop is about to run transaction `i`
    /// (`key` its sender and recipient); passed to the layers beneath.
    #[inline]
    pub fn note_tx(&mut self, i: usize, key: &(Address, Address)) {
        if let Some(lane) = self.lane.as_mut() {
            lane.cur = lane.plan.lanes.as_ref().and_then(|lanes| lanes.lid(i)).map(|(s, r)| (key.0, key.1, s, r));
        }
        self.inner.note_tx(i, key);
    }

    /// `N42_ONE_PROBE`: after a commit, the batch's value of each account the
    /// layers beneath keep ([`crate::parallel_transfer::AccountHint::written_accounts`])
    /// written through to them: one probe of this map each, on entries the
    /// commit just wrote. Nothing when no layer keeps any.
    #[inline]
    pub fn after_commit(&self) {
        if let Some(addresses) = self.inner.written_accounts() {
            for address in &addresses {
                if let Some(lane) = self.lane.as_ref()
                    && let Some(work) = lane.lid(address).and_then(|lid| lane.work.get(lid))
                    && work.flags & SPILL == 0
                {
                    // The balance, nonce and code hash are what is written.
                    let info = (work.flags & CUR_SOME != 0).then(|| Work::make(work.balance, work.nonce, None));
                    self.inner.write_through(address, info.as_ref());
                    continue;
                }
                self.inner.write_through(address, self.accounts.get(address).and_then(|entry| entry.info.as_ref()));
            }
        }
    }

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
        // `N42_ONE_PROBE=2`: the running transaction's accounts from the
        // lane, read beneath it once (as the map path reads a miss).
        if let Some(lane) = self.lane.as_mut()
            && let Some(lid) = lane.lid(&address)
            && let Some(work) = lane.work.get_mut(lid)
        {
            if work.flags & LOADED == 0 {
                let entry = loaded(self.inner.basic(address)?);
                match Work::from_loaded(entry.info.as_ref()) {
                    Some(fresh) => *work = fresh,
                    None => {
                        work.flags = LOADED | SPILL;
                        let info = entry.info.clone();
                        self.accounts.insert(address, entry);
                        return Ok(info);
                    }
                }
                return Ok(work.info(&lane.empty));
            }
            if work.flags & SPILL == 0 {
                lane.hits += 1;
                return Ok(work.info(&lane.empty));
            }
        }
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

    /// `N42_ONE_PROBE=4`: a lane batch's output handed over as the lane
    /// (`take_output`) closes into the bundle `take_bundle` leaves -- the
    /// map's accounts, the lane's accounts and reverts, the empty code a
    /// created recipient brings -- and finds every account by address.
    #[test]
    fn a_lane_output_closes_into_the_lane_bundle() {
        use crate::one_probe::{resolve_with, Rolling};
        let coinbase = addr(50);
        // Sender 1 pays 9 (absent: created) twice and 8; sender 2 pays 8
        // and the beneficiary's neighbour 7 (empty: EIP-161); sender 3 is
        // too poor for its transfer (read only).
        let keys = [(addr(1), addr(9)), (addr(1), addr(9)), (addr(1), addr(8)), (addr(2), addr(8)), (addr(2), addr(7)), (addr(3), addr(6))];
        let groups = vec![vec![0, 1, 2], vec![3, 4], vec![5]];
        let plan = std::sync::Arc::new(resolve_with(&mut Rolling::new(16), &keys).with_lanes(&groups, 1));
        let mut parent = CacheDB::new(EmptyDB::default());
        let plain = |balance: u64, nonce: u64| AccountInfo { balance: U256::from(balance), nonce, ..Default::default() };
        parent.insert_account_info(addr(1), plain(1_000, 0));
        parent.insert_account_info(addr(2), plain(1_000, 4));
        parent.insert_account_info(addr(3), plain(1, 0));
        parent.insert_account_info(addr(8), plain(5, 1));
        parent.insert_account_info(addr(7), plain(0, 0));
        parent.insert_account_info(addr(6), plain(5, 0));
        parent.insert_account_info(coinbase, plain(1, 0));
        let drive = |state: &mut BatchState<CacheDB<EmptyDB>>| {
            for (i, &(from, to)) in keys.iter().enumerate() {
                state.note_tx(i, &(from, to));
                let s = state.basic(from).unwrap().expect("sender");
                if s.balance < U256::from(10) {
                    let _ = state.basic(to).unwrap();
                    continue;
                }
                let r = state.basic(to).unwrap();
                let c = state.basic(coinbase).unwrap().expect("beneficiary");
                let plain = PlainTransfer {
                    caller: from,
                    sender_balance: s.balance - U256::from(10),
                    sender: s,
                    to,
                    recipient_balance: r.as_ref().map_or(U256::ZERO, |r| r.balance) + U256::from(9),
                    recipient: r,
                    beneficiary: coinbase,
                    coinbase_balance: c.balance + U256::from(1),
                    coinbase: c,
                };
                state.commit_transfer(plain).expect("commit");
            }
        };
        let mut by_map = BatchState::with_lane(parent.clone(), 4, std::sync::Arc::clone(&plan), 0, false);
        drive(&mut by_map);
        let theirs = by_map.take_bundle();
        let mut by_lane = BatchState::with_lane(parent, 4, plan, 0, false);
        drive(&mut by_lane);
        let (bundle, lane) = by_lane.take_output();
        let lane = lane.expect("a lane batch hands its lane over");
        assert!(bundle.state.contains_key(&coinbase) && bundle.state.len() == 1, "the map keeps the beneficiary");
        assert_eq!(bundle.contracts, theirs.contracts, "the created recipient's empty code");
        assert!(!lane.is_empty() && lane.position(&addr(3)).is_none() && lane.position(&addr(6)).is_none(), "read only: left out");
        for (address, account) in lane.iter() {
            assert_eq!(lane.get(address).as_ref(), Some(&account));
            assert_eq!(theirs.state.get(address), Some(&account), "{address}");
        }
        let (map, reverts) = lane.into_parts();
        let mut state = map;
        state.extend(bundle.state.clone());
        assert_eq!(state, theirs.state);
        let mut ours: std::collections::BTreeMap<_, _> = reverts.into_iter().collect();
        ours.extend(bundle.reverts.iter().flatten().cloned());
        let theirs: std::collections::BTreeMap<_, _> = theirs.reverts.iter().flatten().cloned().collect();
        assert_eq!(ours, theirs, "reverts");
    }
}
