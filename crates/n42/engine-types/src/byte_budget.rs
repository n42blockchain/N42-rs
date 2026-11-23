// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The builder's block-size budget on an N42-native chain: gov5's
//! `internal/miner/block_size.go`, decision D1 of
//! `docs/PROTOCOL_CONFORMANCE_2026_11.md`.
//!
//! A sealed block has to reach every validator. Gossip refuses a block whose
//! uncompressed RLP is over `N42_MAX_GOSSIP_MB` (`h2-net`
//! `decompress_block_gossip`, gov5's `EncodeGossip`), and HotStuff votes only
//! for a block a replica imported, so a block over the cap makes no quorum
//! and the view times out; the leader would rebuild the same block from the
//! same pool. So the builder never packs one: it counts the bytes every
//! transaction it takes adds to the block's RLP and stops short of
//! 9/10 of the cap, less [`BLOCK_NON_TX_RESERVE`] and the header.
//!
//! Builder policy, not a validity rule: no node checks a block against it.
//! A transaction that does not fit is handed back to the pool for the next
//! block (the same refusal as a block's worth over the gas limit), never
//! dropped. The bytes counted are the pool's [`encoded_length`], already
//! known for every pooled transaction: nothing is encoded here.
//!
//! [`encoded_length`]: reth_transaction_pool::PoolTransaction::encoded_length

/// gov5's `blockSizeSafetyNum / blockSizeSafetyDen`: the share of the wire
/// cap a locally built block may fill.
pub const SAFETY_NUM: usize = 9;
/// See [`SAFETY_NUM`].
pub const SAFETY_DEN: usize = 10;

/// gov5's `blockNonTxReserve`: the allowance, beside the header, for what a
/// block carries besides its transactions (the seal, the verifiers and
/// rewards lists, the outer list framing).
pub const BLOCK_NON_TX_RESERVE: usize = 32 << 10;

/// gov5's `minPackableTxSize`: once less than this is left, nothing more
/// fits.
pub const MIN_PACKABLE_TX_SIZE: usize = 100;

/// gov5's `maxSizeSkipStreak`: consecutive candidates refused for size after
/// which the block counts as full.
pub const MAX_SIZE_SKIP_STREAK: usize = 8;

/// gov5's default `MaxGossipSize`, before `N42_MAX_GOSSIP_MB` (`h2-net`
/// `DEFAULT_MAX_GOSSIP_SIZE`).
pub const DEFAULT_WIRE_CAP: usize = 1 << 20;

/// The largest block payload the network carries: `N42_MAX_GOSSIP_MB`
/// mebibytes, read the way `h2-net`'s `max_gossip_size` and gov5's
/// `sizeFromEnvMB` read it (unset, unparseable or zero: 1 MiB). gov5's
/// `MaxWireMessageSize` is the smaller of this and the 64 MiB-or-more chunk
/// cap, which is this. Read once: the validator process reads the same
/// variable once.
pub fn wire_cap() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| wire_cap_from(std::env::var("N42_MAX_GOSSIP_MB").ok().as_deref()))
}

/// The cap `N42_MAX_GOSSIP_MB` names, in bytes.
pub fn wire_cap_from(megabytes: Option<&str>) -> usize {
    megabytes
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|mb| *mb > 0)
        .map_or(DEFAULT_WIRE_CAP, |mb| mb << 20)
}

/// The bytes a transaction of `encoded` EIP-2718 bytes adds to the block's
/// RLP: the encoding and, at most, the string header that wraps a typed one
/// in the transaction list (gov5's `txPayloadSize`; a legacy transaction is
/// embedded without one, so this over-counts it by a byte or three).
pub const fn payload_size(encoded: usize) -> usize {
    encoded + rlp_string_overhead(encoded)
}

/// gov5's `rlpStringOverhead`: an upper bound on the RLP prefix of a string
/// of `n` bytes.
pub const fn rlp_string_overhead(n: usize) -> usize {
    if n < 56 {
        1
    } else if n < 1 << 8 {
        2
    } else if n < 1 << 16 {
        3
    } else if n < 1 << 24 {
        4
    } else {
        5
    }
}

/// What the transaction-packing loop does with a candidate (gov5's
/// `packDecision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pack {
    /// It fits: execute it, and [`ByteBudget::add`] its size if it is kept.
    Accept,
    /// It does not fit this block: hand it (and its sender's later ones) back
    /// for the next, and go on with other senders.
    SkipSender,
    /// Too little is left for any transaction: stop packing.
    Stop,
}

/// The transaction bytes a block under construction has left (gov5's
/// `blockSizeLimiter`). Every size it counts is an upper bound, so a budget
/// that says "fits" never yields a block over the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudget {
    budget: usize,
    used: usize,
    skip_streak: usize,
}

impl ByteBudget {
    /// The budget under a wire cap of `wire_cap` bytes for a block whose
    /// header encodes to `header_len` bytes (gov5's `newBlockSizeLimiter`).
    pub const fn new(wire_cap: usize, header_len: usize) -> Self {
        let safe = wire_cap / SAFETY_DEN * SAFETY_NUM;
        let budget = safe.saturating_sub(BLOCK_NON_TX_RESERVE + header_len);
        Self { budget, used: 0, skip_streak: 0 }
    }

    /// No budget at all: a chain that is not N42-native has none.
    pub const fn unlimited() -> Self {
        Self { budget: usize::MAX, used: 0, skip_streak: 0 }
    }

    /// The transaction bytes a block may carry.
    pub const fn budget(&self) -> usize {
        self.budget
    }

    /// The bytes counted so far.
    pub const fn used(&self) -> usize {
        self.used
    }

    /// The bytes left.
    pub const fn remaining(&self) -> usize {
        self.budget.saturating_sub(self.used)
    }

    /// Whether `size` more bytes fit.
    pub const fn fits(&self, size: usize) -> bool {
        size <= self.remaining()
    }

    /// Counts `size` bytes as taken.
    pub const fn add(&mut self, size: usize) {
        self.used = self.used.saturating_add(size);
        self.skip_streak = 0;
    }

    /// Whether so little is left that no transaction can fit, or enough
    /// candidates in a row did not (gov5's `exhausted` and skip streak).
    pub const fn full(&self) -> bool {
        self.remaining() < MIN_PACKABLE_TX_SIZE || self.skip_streak >= MAX_SIZE_SKIP_STREAK
    }

    /// gov5's `admit`: what to do with a candidate of `size` bytes.
    pub const fn admit(&mut self, size: usize) -> Pack {
        if self.full() {
            return Pack::Stop;
        }
        if !self.fits(size) {
            self.skip_streak += 1;
            return Pack::SkipSender;
        }
        Pack::Accept
    }

    /// How many of `sizes`, taken in order, fit (all of them when the total
    /// does): the parallel step's cut. Counts them as taken.
    pub fn take_prefix(&mut self, sizes: impl IntoIterator<Item = usize>) -> usize {
        let mut taken = 0;
        for size in sizes {
            if !self.fits(size) {
                break;
            }
            self.used += size;
            taken += 1;
        }
        taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_is_gov5s() {
        // gov5: limit/10*9 - (32 KiB + header).
        let budget = ByteBudget::new(1 << 20, 600);
        assert_eq!(budget.budget(), (1_048_576 / 10) * 9 - 32_768 - 600);
        assert_eq!(ByteBudget::new(1_000, 600).budget(), 0, "a cap below the reserve leaves nothing");
    }

    #[test]
    fn the_wire_cap_reads_as_h2_net_reads_it() {
        assert_eq!(wire_cap_from(None), 1 << 20);
        assert_eq!(wire_cap_from(Some("57")), 57 << 20);
        assert_eq!(wire_cap_from(Some(" 8 ")), 8 << 20);
        for bad in ["0", "", "x", "-3"] {
            assert_eq!(wire_cap_from(Some(bad)), 1 << 20, "{bad:?}");
        }
    }

    #[test]
    fn sizes_carry_the_rlp_string_header() {
        assert_eq!(payload_size(55), 56);
        assert_eq!(payload_size(110), 112);
        assert_eq!(payload_size(300), 303);
        assert_eq!(payload_size(70_000), 70_004);
    }

    #[test]
    fn a_candidate_that_does_not_fit_is_skipped_and_the_streak_stops_the_block() {
        let mut budget = ByteBudget::new(1 << 20, 600);
        let total = budget.budget();
        assert_eq!(budget.admit(total - 150), Pack::Accept);
        budget.add(total - 150);
        // 150 left: a 200-byte candidate is skipped, a 120-byte one fits.
        assert_eq!(budget.admit(200), Pack::SkipSender);
        assert_eq!(budget.admit(120), Pack::Accept);
        budget.add(120);
        // 30 left: under the smallest transaction, the block is full.
        assert!(budget.full());
        assert_eq!(budget.admit(10), Pack::Stop);
        let mut streak = ByteBudget::new(1 << 20, 600);
        streak.add(streak.budget() - 1_000);
        for _ in 0..MAX_SIZE_SKIP_STREAK {
            assert_eq!(streak.admit(2_000), Pack::SkipSender);
        }
        assert_eq!(streak.admit(50), Pack::Stop, "eight skips in a row end the block");
    }

    /// The bench tier never meets the budget: `fleet7-bench.sh` sets the
    /// gossip cap to the gas ceiling over 60M (57 MiB at 3,423,000,000), and
    /// a block full of 21,000-gas transfers at that ceiling, each at its
    /// largest encoding (139 bytes), is under half the budget. The budget binds only on bytes cheaper than ~330 per
    /// 21,000 gas, i.e. calldata.
    #[test]
    fn the_bench_tier_has_headroom() {
        use alloy_consensus::{Signed, TxEip1559};
        use alloy_eips::eip2718::Encodable2718;
        use alloy_primitives::{Address, Signature, TxKind, B256, U256};
        let transfer = TxEip1559 {
            chain_id: 94,
            nonce: u64::from(u32::MAX),
            gas_limit: 21_000,
            max_fee_per_gas: u128::from(u64::MAX),
            max_priority_fee_per_gas: u128::from(u64::MAX),
            to: TxKind::Call(Address::repeat_byte(0xff)),
            value: U256::from(u128::MAX),
            ..Default::default()
        };
        let encoded = Signed::new_unchecked(transfer, Signature::test_signature(), B256::ZERO).encode_2718_len();
        let gas_ceiling: usize = 3_423_000_000;
        let cap = wire_cap_from(Some(&(gas_ceiling / 60_000_000).to_string()));
        assert_eq!(cap, 57 << 20);
        let budget = ByteBudget::new(cap, 1_024).budget();
        let full_block = gas_ceiling / 21_000 * payload_size(encoded);
        assert!(full_block * 2 < budget, "{full_block} bytes of transfers against a budget of {budget}");
    }

    #[test]
    fn the_prefix_cut_takes_what_fits_in_order() {
        let mut budget = ByteBudget::new(1 << 20, 600);
        let total = budget.budget();
        let sizes = [total / 2, total / 4, total / 2, 10];
        assert_eq!(budget.take_prefix(sizes), 2, "the third does not fit; nothing after it is taken");
        assert_eq!(budget.used(), total / 2 + total / 4);
        let mut unlimited = ByteBudget::unlimited();
        assert_eq!(unlimited.take_prefix([usize::MAX / 4; 3]), 3);
    }
}
