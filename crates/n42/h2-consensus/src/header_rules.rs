// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The header validity rules of the mixed production standard, profile 1
//! (`docs/MIXED_PRODUCTION_STANDARD.md` section 2 items B1-B15, with the
//! amendments AM3, AM4, AM12 and AM22).
//!
//! Strict, and used only when a chain says so: [`HeaderRules::default`] is
//! today's behaviour (nothing here runs), and every caller asks
//! [`HeaderRules::is_profile1`] before it checks anything. The genesis layer
//! maps its profile-1 configuration onto [`HeaderRules`]; this module never
//! reads a genesis.
//!
//! What a profile-1 header is, item by item:
//!
//! - **B1** extra data `"N42H" ‖ view u64 LE ‖ QC ‖ seal(96)`, at most 4096
//!   bytes; the QC part empty or one gov5-encoded certificate whose view is
//!   not past the header's. The legacy layouts (no seal reserved, a QC
//!   alone) are refused. That the QC is in the commit domain and verifies
//!   against the set of its exact view needs the consensus engine and is the
//!   caller's (the validator's vote gate).
//! - **B2 / AM4** the seal: the proposer of the header's view signed
//!   [`crate::seal_hash`] under the H2-v4 proof-of-possession DST.
//! - **B3** difficulty 0, nonce 0, mix hash zero, ommers hash exactly zero
//!   (the empty-list hash is invalid), coinbase the proposer's address.
//! - **B4 / AM27** on the slot grid ([`SlotGrid`]): `(time - G) mod I = 0`
//!   and `time >= parent.time + I`; `time <= now + 2 s` only when voting
//!   ([`check_profile1_vote_time`]), never on import. Without a grid (rules
//!   built by a caller that does not know the genesis) the pre-AM27 lower
//!   bound `parent.time <= time` is what is checked.
//! - **B5 / B6** a parent beacon root and a withdrawals root are present
//!   (their values are the committee and rewards checks of the caller).
//! - **A23** the gas limit is the chain's constant.
//! - **B8 / AM24 / AM25** the requests hash is present; it is a deferred
//!   field (header N carries block N-1's EIP-7685 requests hash), so block 1
//!   carries the genesis's, exactly EIP-7685's hash of no requests,
//!   `sha256("")` = `0xe3b0c442…b855` (the empty trie root that AM3 named is
//!   refused there); later headers are checked against the parent's execution
//!   by the execution layer.
//! - **B9** blob gas used 0, excess blob gas 0, both present.
//! - **B10** the slot number (element 23) is the block number.
//! - **B11** `mobileRegistryRoot` (element 24) is present (its value is the
//!   proposer's statement, AM12).
//! - **B12** element 22, the access-list hash, is the `0x80` gap: absent.
//! - **B13** gas used is at most the parent's gas limit (deferred execution:
//!   it is an ancestor's).
//! - **B14** the base fee is EIP-1559's from the parent header (elasticity 2,
//!   denominator 8, the parent's `gasUsed` as written).
//! - **B15** a block's decoded RLP is at most `max_block_bytes`, on every
//!   carrier ([`HeaderRules::check_block_bytes`]).

use crate::header_profile::{
    seal_hash, HeaderExtra, N42Header, EXTRA_MIN_LEN, EXTRA_SEAL_LEN, MAX_HEADER_EXTRA_LEN,
};
use crate::ValidatorInfo;
use alloy_eips::eip1559::BaseFeeParams;
use alloy_primitives::{Address, B256, U256};
use n42_h2_primitives::bls::BlsSignature;

/// Profile 1's requests hash of no requests (B8 as amended by AM24 and AM25):
/// EIP-7685's `sha256("")`, the value Ethereum writes (the empty trie root of
/// AM3 was the requests root of an EIP draft that Ethereum did not ship).
/// Since AM25 `requestsHash` is a deferred field: header N carries the
/// requests hash of block N-1's execution, so this fixed value is what the
/// genesis and block 1 carry (and every header after a block that produced
/// no requests); past block 1 the header alone is checked for presence and
/// the carried value against this node's execution of the parent
/// (`HotStuffConsensus::validate_header_against_parent`).
pub const PROFILE1_REQUESTS_HASH: B256 = alloy_eips::eip7685::EMPTY_REQUESTS_HASH;

/// B4: how far past this node's clock a header's timestamp may be when it
/// votes, in seconds.
pub const PROFILE1_FUTURE_SLACK_SECS: u64 = 2;

/// Profile 1's block size (B15, the standard genesis' `maxBlockBytes`):
/// 64 MiB of decoded RLP.
pub const PROFILE1_MAX_BLOCK_BYTES: u64 = 64 << 20;

/// A17 / AM27: profile 1's slot grid. Slot `s` starts at
/// `genesis_time + s * interval_secs`, counted from the genesis timestamp
/// as on the Ethereum beacon chain, so there is no per-block drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotGrid {
    /// The genesis header's timestamp G, unix seconds.
    pub genesis_time: u64,
    /// The block interval I in whole seconds, at least 1.
    pub interval_secs: u64,
}

impl SlotGrid {
    /// The grid of a chain with genesis timestamp `genesis_time` and
    /// `blockIntervalMs` = `interval_ms`; `None` when the interval is not a
    /// positive whole number of seconds (no grid can carry it).
    pub const fn from_interval_ms(genesis_time: u64, interval_ms: u64) -> Option<Self> {
        if interval_ms == 0 || interval_ms % 1000 != 0 {
            return None;
        }
        Some(Self { genesis_time, interval_secs: interval_ms / 1000 })
    }

    /// The start of slot `slot`, unix seconds.
    pub const fn slot_start(&self, slot: u64) -> u64 {
        self.genesis_time.saturating_add(slot.saturating_mul(self.interval_secs))
    }

    /// The slot `time` starts, or `None` when it is off the grid (before
    /// genesis, or not on a boundary).
    pub const fn slot_of(&self, time: u64) -> Option<u64> {
        if time < self.genesis_time || self.interval_secs == 0 {
            return None;
        }
        let offset = time - self.genesis_time;
        if offset % self.interval_secs != 0 {
            return None;
        }
        Some(offset / self.interval_secs)
    }

    /// A17: the slot a leader holding a parent stamped `parent_time` proposes
    /// in at `now_ms` (unix milliseconds): `max(sP + 1, ceil((now - G) / I))`,
    /// the first boundary after the parent's slot that is not in the past.
    /// An off-grid parent (the genesis is slot 0 by definition) counts as the
    /// slot it falls in.
    pub const fn proposal_slot(&self, parent_time: u64, now_ms: u64) -> u64 {
        let interval_ms = self.interval_secs.saturating_mul(1000);
        if interval_ms == 0 {
            return 0;
        }
        let parent_slot = parent_time.saturating_sub(self.genesis_time) / self.interval_secs;
        let since_ms = now_ms.saturating_sub(self.genesis_time.saturating_mul(1000));
        let now_slot = since_ms.div_ceil(interval_ms);
        let next = parent_slot.saturating_add(1);
        if now_slot > next { now_slot } else { next }
    }

    /// A17 / B4, the producer's side: the timestamp a leader stamps, the
    /// start of [`Self::proposal_slot`]. Known before the wait for the
    /// boundary, so a build started ahead of it stamps the same value.
    pub const fn proposal_time(&self, parent_time: u64, now_ms: u64) -> u64 {
        self.slot_start(self.proposal_slot(parent_time, now_ms))
    }
}

/// Who proposes which view on a profile-1 chain: the genesis validator set
/// (AM5: the set never changes on profile 1) and the leader tenure.
/// `leader(v) = validators[(v / tenure) mod n]` (A15), the rule
/// [`crate::LeaderSelector::leader_for_view_with_tenure`] implements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerSchedule {
    /// The genesis validators, in genesis order.
    pub validators: Vec<ValidatorInfo>,
    /// Views per leader, at least 1.
    pub leader_tenure: u64,
}

impl ProposerSchedule {
    /// The proposer of `view`, or `None` for an empty set.
    pub fn proposer(&self, view: u64) -> Option<&ValidatorInfo> {
        if self.validators.is_empty() {
            return None;
        }
        let index = (view / self.leader_tenure.max(1)) % self.validators.len() as u64;
        self.validators.get(index as usize)
    }
}

/// The header rules a chain runs. The default is today's behaviour: not
/// profile 1, nothing in this module checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderRules {
    /// The chain is a profile-1 chain (`"n42Profile": 1`).
    pub profile1: bool,
    /// `config.hotstuff.gasLimit`: every header's gas limit (A23).
    pub gas_limit: u64,
    /// `config.hotstuff.maxBlockBytes`: the bound on a block's decoded RLP
    /// on every carrier (B15).
    pub max_block_bytes: u64,
    /// The proposer of every view, for the seal and the coinbase (B2, B3).
    /// `None` leaves both to a caller that knows the proposer itself.
    pub proposers: Option<ProposerSchedule>,
    /// The chain's H2-v4 signing identity: with it and the proposer
    /// schedule, the embedded QC is verified as a commit-domain QC of the
    /// genesis set (B1, E13). `None` leaves that to the caller.
    pub chain: Option<n42_h2_primitives::consensus::H2V4ChainIdentity>,
    /// The chain's slot grid (A17, B4 as amended by AM27). `None` keeps the
    /// pre-AM27 timestamp rule (`parent.time <= time`).
    pub slot_grid: Option<SlotGrid>,
}

impl HeaderRules {
    /// Profile 1 with these chain constants.
    pub const fn profile1(gas_limit: u64, max_block_bytes: u64, proposers: Option<ProposerSchedule>) -> Self {
        Self { profile1: true, gas_limit, max_block_bytes, proposers, chain: None, slot_grid: None }
    }

    /// The same rules on the slot grid `grid` (A17, AM27).
    pub const fn with_slot_grid(mut self, grid: Option<SlotGrid>) -> Self {
        self.slot_grid = grid;
        self
    }

    /// Whether the chain runs profile 1.
    pub const fn is_profile1(&self) -> bool {
        self.profile1
    }

    /// The block size bound a carrier applies: `max_block_bytes` on profile
    /// 1, `default` (the carrier's own constant) otherwise.
    pub const fn max_block_bytes_or(&self, default: u64) -> u64 {
        if self.profile1 {
            self.max_block_bytes
        } else {
            default
        }
    }

    /// B15: a block whose decoded RLP is `len` bytes. Nothing on a chain that
    /// is not profile 1.
    pub const fn check_block_bytes(&self, len: usize) -> Result<(), Profile1Error> {
        if self.profile1 && len as u64 > self.max_block_bytes {
            return Err(Profile1Error::BlockTooLarge { len: len as u64, max: self.max_block_bytes });
        }
        Ok(())
    }

    /// Every profile-1 rule a header can be checked against alone (B1, B3,
    /// B5, B6, B8-B12, A23), and the seal and coinbase (B2, B3) when the
    /// rules carry the proposer schedule. Nothing on a chain that is not
    /// profile 1. The genesis header is not a block and is not checked here
    /// ([`validate_profile1_genesis_header`]).
    pub fn check_header(&self, header: &N42Header) -> Result<(), Profile1Error> {
        if !self.profile1 || header.number == 0 {
            return Ok(());
        }
        let extra = validate_profile1_header(header, self)?;
        if let Some(schedule) = &self.proposers {
            if let Some(chain) = self.chain {
                verify_profile1_qc(&extra, schedule, chain)?;
            }
            let proposer = schedule.proposer(extra.view).ok_or(Profile1Error::NoProposer(extra.view))?;
            verify_profile1_seal(header, proposer)?;
        }
        Ok(())
    }

    /// B1's "the QC names an ancestor", gov5's reading: when the QC's block
    /// is known here (`lookup` gives a block's number and parent hash) it
    /// must be on the header's parent chain, walked at most
    /// [`PROFILE1_ANCESTOR_WALK`] blocks; an unknown block is checked by the
    /// QC's signature alone. Nothing off profile 1 or without a QC.
    pub fn check_qc_ancestry(
        &self,
        header: &N42Header,
        lookup: impl Fn(&B256) -> Option<(u64, B256)>,
    ) -> Result<(), Profile1Error> {
        if !self.profile1 || header.number == 0 {
            return Ok(());
        }
        let extra = decode_profile1_extra(&header.extra_data)?;
        if extra.qc.is_empty() {
            return Ok(());
        }
        let qc = n42_h2_wire::h2_wire::decode_h2_qc(&extra.qc)
            .map_err(|err| Profile1Error::Qc(format!("does not decode: {err}")))?;
        let Some((target_number, _)) = lookup(&qc.block_hash) else {
            return Ok(());
        };
        let mut cursor = header.parent_hash;
        for _ in 0..PROFILE1_ANCESTOR_WALK {
            if cursor == qc.block_hash {
                return Ok(());
            }
            match lookup(&cursor) {
                Some((number, parent)) if number > target_number => cursor = parent,
                _ => break,
            }
        }
        Err(Profile1Error::Qc(format!("QC block {} is not an ancestor", qc.block_hash)))
    }

    /// B8 under AM25: the header's requests hash against `carried`, the
    /// EIP-7685 requests hash of the parent's execution (`requestsHash` is a
    /// deferred field; block 1 carries the genesis's, the hash of no
    /// requests). Only the execution layer knows `carried`; this is the
    /// rule's spelling for a caller that does. Nothing on a chain that is
    /// not profile 1.
    pub fn check_carried_requests_hash(&self, header: &N42Header, carried: B256) -> Result<(), Profile1Error> {
        if !self.profile1 {
            return Ok(());
        }
        match header.requests_hash {
            None => Err(Profile1Error::Missing { item: "B8", field: "requestsHash" }),
            Some(hash) if hash != carried => Err(Profile1Error::CarriedRequestsHash { got: hash, carried }),
            Some(_) => Ok(()),
        }
    }

    /// The rules between a header and its parent (B4's lower bound, B13,
    /// B14, the parent link). Nothing on a chain that is not profile 1.
    pub fn check_against_parent(
        &self,
        header: &N42Header,
        parent: &N42Header,
        parent_hash: B256,
    ) -> Result<(), Profile1Error> {
        if !self.profile1 {
            return Ok(());
        }
        validate_profile1_against_parent(header, parent, parent_hash)?;
        if let Some(grid) = self.slot_grid {
            check_profile1_slot(&grid, header.timestamp, parent.timestamp)?;
        }
        Ok(())
    }
}

/// Why a header is not a profile-1 header. Every message names its item of
/// the standard.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Profile1Error {
    /// B1: the extra data is not `N42H ‖ view ‖ QC ‖ seal`.
    #[error("B1: {0}")]
    Extra(String),
    /// B1: the extra data reserves no seal (a legacy layout).
    #[error("B1: extra data of {0} bytes reserves no 96-byte seal (legacy layout)")]
    LegacyExtra(usize),
    /// B1: the embedded QC does not decode or is past the header's view.
    #[error("B1: embedded QC: {0}")]
    Qc(String),
    /// B2: the seal does not verify under the proposer's key.
    #[error("B2: seal: {0}")]
    Seal(String),
    /// B2: no proposer is known for the view.
    #[error("B2: no proposer for view {0}")]
    NoProposer(u64),
    /// B3: difficulty is not 0.
    #[error("B3: difficulty {0} is not 0")]
    Difficulty(U256),
    /// B3: nonce is not 0.
    #[error("B3: nonce is not 0")]
    Nonce,
    /// B3: mix hash is not zero.
    #[error("B3: mix hash {0} is not zero")]
    MixHash(B256),
    /// B3: ommers hash is not exactly zero.
    #[error("B3: ommers hash {0} is not zero (the empty-list hash is invalid)")]
    OmmersHash(B256),
    /// B3: the coinbase is not the proposer's address.
    #[error("B3: coinbase {got} is not the proposer's address {expected}")]
    Coinbase {
        /// The header's beneficiary.
        got: Address,
        /// The proposer's address.
        expected: Address,
    },
    /// B4: the timestamp is before the parent's.
    #[error("B4: timestamp {time} is before the parent's {parent}")]
    TimestampBeforeParent {
        /// The header's timestamp.
        time: u64,
        /// The parent's.
        parent: u64,
    },
    /// B4 (AM27): the timestamp is not on the slot grid.
    #[error("B4: timestamp {time} is off the slot grid (genesis {genesis}, interval {interval} s)")]
    TimestampOffGrid {
        /// The header's timestamp.
        time: u64,
        /// The genesis timestamp G.
        genesis: u64,
        /// The block interval I, seconds.
        interval: u64,
    },
    /// B4 (AM27): the timestamp is not in a later slot than the parent's.
    #[error("B4: timestamp {time} is not a later slot than the parent's {parent} (interval {interval} s)")]
    TimestampSameSlot {
        /// The header's timestamp.
        time: u64,
        /// The parent's.
        parent: u64,
        /// The block interval I, seconds.
        interval: u64,
    },
    /// B4: at vote time, the timestamp is past this node's clock plus 2 s.
    #[error("B4: timestamp {time} is past now {now} + 2 s")]
    TimestampInFuture {
        /// The header's timestamp.
        time: u64,
        /// This node's clock, whole seconds.
        now: u64,
    },
    /// B5 / B6 / B8 / B9 / B10 / B11: a field the profile requires is absent.
    #[error("{item}: {field} is missing")]
    Missing {
        /// The standard's item.
        item: &'static str,
        /// The header field.
        field: &'static str,
    },
    /// A23: the gas limit is not the chain's constant.
    #[error("A23: gas limit {got} is not the chain's {expected}")]
    GasLimit {
        /// The header's gas limit.
        got: u64,
        /// The chain's constant.
        expected: u64,
    },
    /// B8 / AM25: block 1's requests hash is not `sha256("")` (block 1
    /// carries the genesis's, which is the hash of no requests).
    #[error("B8: requests hash {0} of block 1 is not sha256(\"\") (EIP-7685's hash of no requests)")]
    RequestsHash(B256),
    /// B8 / AM25: the requests hash is not the parent's execution's.
    #[error("B8: requests hash {got} is not the parent's execution's {carried}")]
    CarriedRequestsHash {
        /// What the header carries.
        got: B256,
        /// The EIP-7685 requests hash of the parent's execution.
        carried: B256,
    },
    /// B9: blob gas used or excess blob gas is not 0.
    #[error("B9: blob gas used {used} / excess blob gas {excess} are not 0")]
    BlobGas {
        /// Blob gas used.
        used: u64,
        /// Excess blob gas.
        excess: u64,
    },
    /// B10: the slot number is not the block number.
    #[error("B10: slot number {slot} is not the block number {number}")]
    SlotNumber {
        /// The header's block number.
        number: u64,
        /// The slot number it carries.
        slot: u64,
    },
    /// B12: element 22 (the access-list hash) is not the `0x80` gap.
    #[error("B12: element 22 carries {0}, not the 0x80 gap")]
    AccessListHash(B256),
    /// B13: gas used is past the parent's gas limit.
    #[error("B13: gas used {used} is past the parent's gas limit {limit}")]
    GasUsed {
        /// The header's gas used.
        used: u64,
        /// The parent's gas limit.
        limit: u64,
    },
    /// B14: the base fee is not EIP-1559's from the parent.
    #[error("B14: base fee {got:?} is not {expected} (EIP-1559 from the parent)")]
    BaseFee {
        /// The header's base fee.
        got: Option<u64>,
        /// What the parent implies.
        expected: u64,
    },
    /// The header does not link to the parent it is checked against.
    #[error("parent link: header {number} / parent {parent_hash} is not the child of {parent_number} / {expected_hash}")]
    ParentLink {
        /// The header's number.
        number: u64,
        /// The header's parent hash.
        parent_hash: B256,
        /// The parent's number.
        parent_number: u64,
        /// The parent's hash.
        expected_hash: B256,
    },
    /// B15: the block's decoded RLP is past `maxBlockBytes`.
    #[error("B15: block of {len} bytes is past maxBlockBytes {max}")]
    BlockTooLarge {
        /// The block's decoded RLP length.
        len: u64,
        /// The chain's bound.
        max: u64,
    },
    /// A6 / B3 / B8: the genesis header is not profile 1's.
    #[error("A6: genesis header: {0}")]
    Genesis(String),
}

/// How far back [`HeaderRules::check_qc_ancestry`] walks (gov5's bound).
pub const PROFILE1_ANCESTOR_WALK: usize = 4096;

/// B1 / E13: the embedded QC is a commit-domain QC (changes hash zero) by a
/// quorum of the genesis set (AM5: the set of every view on profile 1).
pub fn verify_profile1_qc(
    extra: &HeaderExtra,
    schedule: &ProposerSchedule,
    chain: n42_h2_primitives::consensus::H2V4ChainIdentity,
) -> Result<(), Profile1Error> {
    if extra.qc.is_empty() {
        return Ok(());
    }
    let wire = n42_h2_wire::h2_wire::decode_h2_qc(&extra.qc)
        .map_err(|err| Profile1Error::Qc(format!("does not decode: {err}")))?;
    let n = schedule.validators.len();
    let qc = crate::wire_bridge::qc_to_engine(&wire, n, "profile-1 header QC")
        .map_err(|err| Profile1Error::Qc(err.to_string()))?;
    let set = crate::ValidatorSet::new(&schedule.validators, (n as u32).saturating_sub(1) / 3);
    crate::verify_commit_qc_with_profile(
        &qc,
        &set,
        &B256::ZERO,
        crate::protocol::quorum::ConsensusSigningProfile::H2V4(chain),
    )
    .map_err(|err| Profile1Error::Qc(err.to_string()))
}

/// B1: the extra data, strictly: magic, view, seal reserved, the QC part
/// empty or one certificate in gov5's encoding below the header's view (an
/// encoded empty QC is refused).
pub fn decode_profile1_extra(extra: &[u8]) -> Result<HeaderExtra, Profile1Error> {
    if extra.len() > MAX_HEADER_EXTRA_LEN {
        return Err(Profile1Error::Extra(format!("{} bytes, past the 4096-byte bound", extra.len())));
    }
    if extra.len() < EXTRA_MIN_LEN + EXTRA_SEAL_LEN {
        // `HeaderExtra::decode` reads a shorter payload as "no seal" or "a QC
        // alone", gov5's legacy layouts; profile 1 has neither.
        if extra.len() >= EXTRA_MIN_LEN && extra[..4] == crate::GOV5_HEADER_EXTRA_MAGIC {
            return Err(Profile1Error::LegacyExtra(extra.len()));
        }
    }
    let decoded = HeaderExtra::decode(extra).map_err(|err| Profile1Error::Extra(err.to_string()))?;
    if decoded.seal.is_none() {
        return Err(Profile1Error::LegacyExtra(extra.len()));
    }
    if !decoded.qc.is_empty() {
        let qc = n42_h2_wire::h2_wire::decode_h2_qc(&decoded.qc)
            .map_err(|err| Profile1Error::Qc(format!("does not decode: {err}")))?;
        // gov5: an absent QC is zero bytes, never an encoded empty one.
        if qc.view == 0 {
            return Err(Profile1Error::Extra("an absent QC is zero bytes, not an encoded empty QC".into()));
        }
        if qc.view >= decoded.view {
            return Err(Profile1Error::Qc(format!("QC view {} is not below the header's view {}", qc.view, decoded.view)));
        }
    }
    Ok(decoded)
}

/// Every profile-1 rule a non-genesis header can be checked against alone:
/// B1, B3 (all but the coinbase), B5/B6 presence, B8, B9, B10, B11, B12, A23.
/// Returns the decoded extra data. Unconditional: the caller asks
/// [`HeaderRules::is_profile1`] first, or uses [`HeaderRules::check_header`].
pub fn validate_profile1_header(header: &N42Header, rules: &HeaderRules) -> Result<HeaderExtra, Profile1Error> {
    let extra = decode_profile1_extra(&header.extra_data)?;
    validate_profile1_constant_fields(header)?;
    if header.gas_limit != rules.gas_limit {
        return Err(Profile1Error::GasLimit { got: header.gas_limit, expected: rules.gas_limit });
    }
    if header.withdrawals_root.is_none() {
        return Err(Profile1Error::Missing { item: "B6", field: "withdrawalsRoot" });
    }
    if header.parent_beacon_block_root.is_none() {
        return Err(Profile1Error::Missing { item: "B5", field: "parentBeaconRoot" });
    }
    // B8 / AM25: a deferred field. Block 1 carries the genesis's, the hash of
    // no requests; a later header carries its parent's, which only the
    // parent's execution tells (checked against it, not here).
    match header.requests_hash {
        None => return Err(Profile1Error::Missing { item: "B8", field: "requestsHash" }),
        Some(hash) if header.number <= 1 && hash != PROFILE1_REQUESTS_HASH => return Err(Profile1Error::RequestsHash(hash)),
        Some(_) => {}
    }
    match (header.blob_gas_used, header.excess_blob_gas) {
        (Some(0), Some(0)) => {}
        (None, _) => return Err(Profile1Error::Missing { item: "B9", field: "blobGasUsed" }),
        (_, None) => return Err(Profile1Error::Missing { item: "B9", field: "excessBlobGas" }),
        (Some(used), Some(excess)) => return Err(Profile1Error::BlobGas { used, excess }),
    }
    if let Some(hash) = header.block_access_list_hash {
        return Err(Profile1Error::AccessListHash(hash));
    }
    match header.slot_number {
        None => return Err(Profile1Error::Missing { item: "B10", field: "slotNumber" }),
        Some(slot) if slot != header.number => {
            return Err(Profile1Error::SlotNumber { number: header.number, slot })
        }
        Some(_) => {}
    }
    if header.mobile_registry_root.is_none() {
        return Err(Profile1Error::Missing { item: "B11", field: "mobileRegistryRoot" });
    }
    Ok(extra)
}

/// B3 without the coinbase: difficulty, nonce, mix hash, ommers hash.
fn validate_profile1_constant_fields(header: &N42Header) -> Result<(), Profile1Error> {
    if header.difficulty != U256::ZERO {
        return Err(Profile1Error::Difficulty(header.difficulty));
    }
    if !header.nonce.is_zero() {
        return Err(Profile1Error::Nonce);
    }
    if header.mix_hash != B256::ZERO {
        return Err(Profile1Error::MixHash(header.mix_hash));
    }
    if header.ommers_hash != B256::ZERO {
        return Err(Profile1Error::OmmersHash(header.ommers_hash));
    }
    Ok(())
}

/// B2 and B3's coinbase: the header names the proposer of its view as its
/// coinbase and carries that proposer's seal.
pub fn verify_profile1_seal(header: &N42Header, proposer: &ValidatorInfo) -> Result<(), Profile1Error> {
    if header.beneficiary != proposer.address {
        return Err(Profile1Error::Coinbase { got: header.beneficiary, expected: proposer.address });
    }
    let extra = decode_profile1_extra(&header.extra_data)?;
    let seal = extra.seal.ok_or(Profile1Error::LegacyExtra(header.extra_data.len()))?;
    let signature = BlsSignature::from_bytes(&seal).map_err(|err| Profile1Error::Seal(err.to_string()))?;
    proposer
        .bls_public_key
        .verify_h2_v4_prevalidated(seal_hash(header).as_slice(), &signature)
        .map_err(|err| Profile1Error::Seal(err.to_string()))
}

/// The rules between a header and its parent: the link, B4's lower bound
/// (equal timestamps allowed), B13 and B14.
pub fn validate_profile1_against_parent(
    header: &N42Header,
    parent: &N42Header,
    parent_hash: B256,
) -> Result<(), Profile1Error> {
    if header.number != parent.number + 1 || header.parent_hash != parent_hash {
        return Err(Profile1Error::ParentLink {
            number: header.number,
            parent_hash: header.parent_hash,
            parent_number: parent.number,
            expected_hash: parent_hash,
        });
    }
    if header.timestamp < parent.timestamp {
        return Err(Profile1Error::TimestampBeforeParent { time: header.timestamp, parent: parent.timestamp });
    }
    if header.gas_used > parent.gas_limit {
        return Err(Profile1Error::GasUsed { used: header.gas_used, limit: parent.gas_limit });
    }
    let expected = profile1_base_fee(parent);
    if header.base_fee_per_gas != Some(expected) {
        return Err(Profile1Error::BaseFee { got: header.base_fee_per_gas, expected });
    }
    Ok(())
}

/// B14: the base fee a child of `parent` carries, EIP-1559 with Ethereum's
/// parameters over the parent's fields as written.
pub fn profile1_base_fee(parent: &N42Header) -> u64 {
    alloy_eips::calc_next_block_base_fee(
        parent.gas_used,
        parent.gas_limit,
        parent.base_fee_per_gas.unwrap_or_default(),
        BaseFeeParams::ethereum(),
    )
}

/// B4's upper bound, checked only before a vote: `time <= now + 2 s`, with
/// `now` this node's clock in whole seconds.
pub const fn check_profile1_vote_time(header_time: u64, now_secs: u64) -> Result<(), Profile1Error> {
    if header_time > now_secs.saturating_add(PROFILE1_FUTURE_SLACK_SECS) {
        return Err(Profile1Error::TimestampInFuture { time: header_time, now: now_secs });
    }
    Ok(())
}

/// B4 as amended by AM27, checked on import: `(time - G) mod I = 0` and
/// `time >= parent.time + I`.
pub const fn check_profile1_slot(grid: &SlotGrid, time: u64, parent_time: u64) -> Result<(), Profile1Error> {
    if grid.slot_of(time).is_none() {
        return Err(Profile1Error::TimestampOffGrid {
            time,
            genesis: grid.genesis_time,
            interval: grid.interval_secs,
        });
    }
    if time < parent_time.saturating_add(grid.interval_secs) {
        return Err(Profile1Error::TimestampSameSlot { time, parent: parent_time, interval: grid.interval_secs });
    }
    Ok(())
}

/// B4 before AM27, the producer's side: `max(parent.time, floor(now))`.
/// Superseded on a chain with a slot grid by [`SlotGrid::proposal_time`].
pub fn profile1_timestamp(parent_time: u64, now_secs: u64) -> u64 {
    parent_time.max(now_secs)
}

/// The profile-1 genesis header (A6 with B3 and AM3): no consensus fields
/// (empty extra data), difficulty, nonce, mix hash and ommers hash zero, the
/// requests hash the empty trie root, the chain's gas limit, blob gas zero.
pub fn validate_profile1_genesis_header(header: &N42Header, rules: &HeaderRules) -> Result<(), Profile1Error> {
    let fail = |reason: String| Err(Profile1Error::Genesis(reason));
    if header.number != 0 {
        return fail(format!("number {} is not 0", header.number));
    }
    if !header.extra_data.is_empty() {
        return fail(format!("extra data of {} bytes is not empty", header.extra_data.len()));
    }
    validate_profile1_constant_fields(header).map_err(|err| Profile1Error::Genesis(err.to_string()))?;
    if header.gas_limit != rules.gas_limit {
        return fail(format!("gas limit {} is not the chain's {}", header.gas_limit, rules.gas_limit));
    }
    if header.requests_hash != Some(PROFILE1_REQUESTS_HASH) {
        return fail(format!("requests hash {:?} is not the EIP-7685 hash of no requests", header.requests_hash));
    }
    if header.blob_gas_used != Some(0) || header.excess_blob_gas != Some(0) {
        return fail("blob gas fields are not 0".into());
    }
    if header.parent_beacon_block_root != Some(B256::ZERO) {
        return fail("parent beacon root is not zero".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "header_rules_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "header_rules_v1_tests.rs"]
mod v1_tests;
