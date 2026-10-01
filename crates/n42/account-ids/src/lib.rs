// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Node-local dense account ids (`docs/BREAKTHROUGH_DESIGN.md` section 4B).
//!
//! Every per-account structure on the block's chain -- a batch's state, the
//! output index, the parent's outputs -- is keyed by a 20-byte address through
//! a hash, and every one of those probes is a cache miss. This table gives an
//! account a `u32` once, the first time the node sees it (at admission, where
//! the ingest touches every transaction anyway), so the chain's structures can
//! be arrays indexed by id and the hashing happens off the chain.
//!
//! The ids are **node-local**: never on the wire, never in a block, never in
//! the state store (QMDB keys stay gov5's derivation). Two nodes give the same
//! account different ids and nothing may depend on them agreeing.
//!
//! Layout: [`SHARDS`] shards chosen by a fixed mix of the address (the same
//! in every process, so a saved table loads back to the same ids), each a
//! read-write lock over an address -> id map and its id -> address list. An
//! id is `(position in its shard << SHARD_BITS) | shard`, so the shards
//! assign ids without a shared counter and an id's address is one indexed
//! read; the ids are dense to within the shards' imbalance
//! ([`AccountIds::id_bound`]).
//!
//! Memory: ~20 bytes an account for the list plus ~32 for the map entry
//! (with the map's slack), ~110 MB at the flood's ~2M accounts.
//!
//! Persistence: [`AccountIds::save`] / [`AccountIds::load`] write and read
//! the shards' lists (20 bytes an account) and give back the same ids. The
//! node does not have to use them -- ids assigned lazily after a restart are
//! as good as the old ones, since nothing outside the process sees them.

use std::{
    io::{Read, Write},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
};

use alloy_primitives::{map::AddressMap, Address};
use parking_lot::RwLock;

/// A node-local account id.
pub type AccountId = u32;

/// The id a slot holds for "no account" (a contract creation's recipient).
pub const NO_ID: AccountId = u32::MAX;

/// log2 of [`SHARDS`].
pub const SHARD_BITS: u32 = 6;

/// How many shards the table holds.
pub const SHARDS: usize = 1 << SHARD_BITS;

/// The most accounts one shard can number (the id's upper bits, less
/// [`NO_ID`]).
const SHARD_CAPACITY: usize = (1 << (32 - SHARD_BITS)) - 1;

/// The file's magic and version.
const MAGIC: &[u8; 8] = b"N42AIDS1";

/// Why an id could not be given or a table not read.
#[derive(Debug)]
pub enum IdError {
    /// A shard holds every id it can (2^26 accounts, ~4.3B in the table).
    Full,
    /// The saved table could not be written or read.
    Io(std::io::Error),
    /// The saved table is not one this code wrote.
    Format(&'static str),
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "the account id table is full"),
            Self::Io(err) => write!(f, "account id table: {err}"),
            Self::Format(what) => write!(f, "account id table file: {what}"),
        }
    }
}

impl std::error::Error for IdError {}

impl From<std::io::Error> for IdError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug, Default)]
struct Shard {
    by_address: AddressMap<AccountId>,
    addresses: Vec<Address>,
}

/// What a batch of resolutions found ([`AccountIds::resolve_into`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Resolved {
    /// Addresses the table numbered for the first time.
    pub new: u64,
    /// Addresses it already held.
    pub hit: u64,
}

impl std::ops::AddAssign for Resolved {
    fn add_assign(&mut self, other: Self) {
        self.new += other.new;
        self.hit += other.hit;
    }
}

/// The table: address -> id, id -> address.
#[derive(Debug)]
pub struct AccountIds {
    shards: Box<[RwLock<Shard>]>,
    len: AtomicU64,
}

impl Default for AccountIds {
    fn default() -> Self {
        Self::new()
    }
}

/// The shard an address lives in: a fixed multiply-xor mix of its bytes, the
/// same in every process (a saved table must load back to the same ids), and
/// spread for the flood's recipients, whose addresses differ only in their
/// first four bytes.
#[inline]
pub fn shard_of(address: &Address) -> usize {
    let b = address.as_slice();
    let mut lo = [0u8; 8];
    let mut mid = [0u8; 8];
    let mut hi = [0u8; 4];
    lo.copy_from_slice(&b[0..8]);
    mid.copy_from_slice(&b[8..16]);
    hi.copy_from_slice(&b[16..20]);
    let x = u64::from_le_bytes(lo) ^ u64::from_le_bytes(mid).rotate_left(29) ^ u64::from(u32::from_le_bytes(hi)).rotate_left(47);
    let x = (x ^ (x >> 31)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (x >> (64 - SHARD_BITS)) as usize
}

/// The shard an id was given by.
#[inline]
pub const fn shard_of_id(id: AccountId) -> usize {
    (id as usize) & (SHARDS - 1)
}

#[inline]
const fn id_of(shard: usize, position: usize) -> AccountId {
    ((position << SHARD_BITS) | shard) as AccountId
}

impl AccountIds {
    /// An empty table.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// An empty table with room for about `accounts` without regrowing.
    pub fn with_capacity(accounts: usize) -> Self {
        let per = accounts.div_ceil(SHARDS) + accounts.div_ceil(SHARDS) / 8;
        let shards = (0..SHARDS)
            .map(|_| {
                RwLock::new(Shard {
                    by_address: AddressMap::with_capacity_and_hasher(per, Default::default()),
                    addresses: Vec::with_capacity(per),
                })
            })
            .collect();
        Self { shards, len: AtomicU64::new(0) }
    }

    /// How many accounts the table numbers.
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed) as usize
    }

    /// Whether it numbers none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One past the largest id given: a `Vec` indexed by id needs this many
    /// entries. Within the shards' imbalance of [`Self::len`].
    pub fn id_bound(&self) -> usize {
        let longest = self.shards.iter().map(|shard| shard.read().addresses.len()).max().unwrap_or(0);
        longest << SHARD_BITS
    }

    /// The id of `address`, if the table numbers it.
    #[inline]
    pub fn get(&self, address: &Address) -> Option<AccountId> {
        self.shards[shard_of(address)].read().by_address.get(address).copied()
    }

    /// The id of `address`, given now if it has none; `true` beside it when
    /// it is new.
    #[inline]
    pub fn resolve(&self, address: &Address) -> Result<(AccountId, bool), IdError> {
        let shard = shard_of(address);
        if let Some(id) = self.shards[shard].read().by_address.get(address) {
            return Ok((*id, false));
        }
        let mut held = self.shards[shard].write();
        // Another resolver may have numbered it between the two locks.
        if let Some(id) = held.by_address.get(address) {
            return Ok((*id, false));
        }
        let position = held.addresses.len();
        if position >= SHARD_CAPACITY {
            return Err(IdError::Full);
        }
        let id = id_of(shard, position);
        held.addresses.push(*address);
        held.by_address.insert(*address, id);
        drop(held);
        self.len.fetch_add(1, Ordering::Relaxed);
        Ok((id, true))
    }

    /// [`Self::resolve`] of each of `addresses`, appended to `out` in order;
    /// what was new and what was held.
    pub fn resolve_into(&self, addresses: &[Address], out: &mut Vec<AccountId>) -> Result<Resolved, IdError> {
        out.reserve(addresses.len());
        let mut counts = Resolved::default();
        for address in addresses {
            let (id, new) = self.resolve(address)?;
            if new {
                counts.new += 1;
            } else {
                counts.hit += 1;
            }
            out.push(id);
        }
        Ok(counts)
    }

    /// The address `id` was given to.
    #[inline]
    pub fn address(&self, id: AccountId) -> Option<Address> {
        if id == NO_ID {
            return None;
        }
        self.shards[shard_of_id(id)].read().addresses.get((id >> SHARD_BITS) as usize).copied()
    }

    /// The address of each of `ids`, in order; `None` for one the table did
    /// not give. One read lock a shard touched in a row, not one an id.
    pub fn addresses_of(&self, ids: &[AccountId]) -> Vec<Option<Address>> {
        ids.iter().map(|id| self.address(*id)).collect()
    }

    /// Writes the table to `path` (through a temporary file beside it and a
    /// rename): the magic, the shard count, then each shard's addresses in id
    /// order. 20 bytes an account.
    pub fn save(&self, path: &Path) -> Result<(), IdError> {
        let tmp = path.with_extension("tmp");
        {
            let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            out.write_all(MAGIC)?;
            out.write_all(&(SHARDS as u32).to_le_bytes())?;
            for shard in self.shards.iter() {
                let held = shard.read();
                let len = u32::try_from(held.addresses.len()).map_err(|_| IdError::Full)?;
                out.write_all(&len.to_le_bytes())?;
                for address in &held.addresses {
                    out.write_all(address.as_slice())?;
                }
            }
            out.flush()?;
            out.get_ref().sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// A table [`Self::save`] wrote: every account back at its id.
    pub fn load(path: &Path) -> Result<Self, IdError> {
        let mut input = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut magic = [0u8; 8];
        input.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(IdError::Format("bad magic"));
        }
        let mut word = [0u8; 4];
        input.read_exact(&mut word)?;
        if u32::from_le_bytes(word) as usize != SHARDS {
            return Err(IdError::Format("shard count differs"));
        }
        let table = Self::new();
        let mut total = 0u64;
        for (index, shard) in table.shards.iter().enumerate() {
            input.read_exact(&mut word)?;
            let len = u32::from_le_bytes(word) as usize;
            if len > SHARD_CAPACITY {
                return Err(IdError::Format("shard longer than its ids"));
            }
            let mut held = shard.write();
            held.addresses.reserve_exact(len);
            held.by_address.reserve(len);
            let mut bytes = [0u8; 20];
            for position in 0..len {
                input.read_exact(&mut bytes)?;
                let address = Address::from(bytes);
                if shard_of(&address) != index {
                    return Err(IdError::Format("an address in another shard's list"));
                }
                if held.by_address.insert(address, id_of(index, position)).is_some() {
                    return Err(IdError::Format("an address listed twice"));
                }
                held.addresses.push(address);
            }
            total += len as u64;
        }
        let mut rest = [0u8; 1];
        if input.read(&mut rest)? != 0 {
            return Err(IdError::Format("trailing bytes"));
        }
        table.len.store(total, Ordering::Relaxed);
        Ok(table)
    }
}

/// Whether the chain's structures key by dense id: `N42_DENSE_IDS=1` (off by
/// default). The ingest resolves ids at admission only when it is set.
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_DENSE_IDS").is_ok_and(|v| v == "1"))
}

/// The node's table, one per process.
pub fn global() -> &'static AccountIds {
    static TABLE: OnceLock<AccountIds> = OnceLock::new();
    TABLE.get_or_init(|| AccountIds::with_capacity(1 << 21))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(i: u32) -> Address {
        // The flood's recipient shape: four bytes of slot, then 0x42.
        let mut bytes = [0u8; 20];
        bytes[..4].copy_from_slice(&i.to_be_bytes());
        bytes[4] = 0x42;
        Address::from(bytes)
    }

    #[test]
    fn ids_are_unique_stable_and_map_back() {
        let table = AccountIds::new();
        let mut ids = Vec::new();
        for i in 0..10_000 {
            let (id, new) = table.resolve(&addr(i)).expect("room");
            assert!(new);
            ids.push(id);
        }
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(table.resolve(&addr(i as u32)).expect("room"), (*id, false));
            assert_eq!(table.get(&addr(i as u32)), Some(*id));
            assert_eq!(table.address(*id), Some(addr(i as u32)));
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "unique");
        assert_eq!(table.len(), 10_000);
        assert!(table.get(&addr(10_000)).is_none());
        assert_eq!(table.address(NO_ID), None);
        // Dense to within the shards' imbalance: under 1.5x of the count.
        assert!(table.id_bound() >= 10_000 && table.id_bound() < 15_000, "bound {}", table.id_bound());
    }

    #[test]
    fn the_shards_spread_the_floods_recipients() {
        let mut counts = [0usize; SHARDS];
        for i in 0..64_000 {
            counts[shard_of(&addr(i))] += 1;
        }
        let (min, max) = (counts.iter().min().copied().unwrap_or(0), counts.iter().max().copied().unwrap_or(0));
        assert!(min > 800 && max < 1_200, "min {min} max {max}");
    }

    #[test]
    fn concurrent_resolvers_agree() {
        let table = AccountIds::new();
        let results: Vec<Vec<AccountId>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let addresses: Vec<Address> = (0..5_000).map(addr).collect();
                        let mut out = Vec::new();
                        table.resolve_into(&addresses, &mut out).expect("room");
                        out
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("joined")).collect()
        });
        for other in &results[1..] {
            assert_eq!(other, &results[0]);
        }
        assert_eq!(table.len(), 5_000);
    }

    #[test]
    fn a_saved_table_loads_back_to_the_same_ids() {
        let dir = std::env::temp_dir().join(format!("n42-account-ids-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("ids.bin");
        let table = AccountIds::new();
        let addresses: Vec<Address> = (0..3_000).map(addr).chain((0..50).map(|i| Address::with_last_byte(i as u8))).collect();
        let mut ids = Vec::new();
        let counts = table.resolve_into(&addresses, &mut ids).expect("room");
        // The last 50 are 0..49 as last bytes: distinct from the first 3,000.
        assert_eq!(counts, Resolved { new: 3_050, hit: 0 });
        table.save(&path).expect("saved");
        let back = AccountIds::load(&path).expect("loaded");
        assert_eq!(back.len(), table.len());
        for (address, id) in addresses.iter().zip(&ids) {
            assert_eq!(back.get(address), Some(*id));
            assert_eq!(back.address(*id), Some(*address));
        }
        // New accounts after a reload continue past the loaded ones.
        let (fresh, new) = back.resolve(&addr(1_000_000)).expect("room");
        assert!(new && !ids.contains(&fresh));
        // A file that is not a table is refused.
        std::fs::write(&path, b"not a table").expect("written");
        assert!(AccountIds::load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
