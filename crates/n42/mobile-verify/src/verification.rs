use alloy_primitives::B256;
use std::collections::{HashMap, HashSet};
use tracing::warn;

use crate::receipt::VerificationReceipt;

/// Aggregated verification status for a single block.
///
/// Tracks receipt counts and determines when the attestation threshold is met.
/// When `expected_receipts_root` is `Some`, receipts are validated against it.
/// When `None`, all receipts are counted as valid (backward-compatible mode).
#[derive(Debug)]
pub struct BlockVerificationStatus {
    pub block_hash: B256,
    pub block_number: u64,
    /// The expected receipts root for this block (from the original block header).
    /// When `Some`, incoming receipts are checked against it.
    /// When `None`, all receipts are counted as valid.
    pub expected_receipts_root: Option<B256>,
    pub valid_count: u32,
    pub invalid_count: u32,
    /// Number of valid receipts required for attestation (typically 2/3 of phones).
    pub threshold: u32,
    seen_verifiers: HashSet<[u8; 48]>,
}

impl BlockVerificationStatus {
    /// Creates a new verification status for a block.
    pub fn new(
        block_hash: B256,
        block_number: u64,
        expected_receipts_root: Option<B256>,
        threshold: u32,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            expected_receipts_root,
            valid_count: 0,
            invalid_count: 0,
            threshold,
            seen_verifiers: HashSet::new(),
        }
    }

    /// Adds a receipt. Returns `true` if the receipt was new (not a duplicate).
    ///
    /// Validity is determined by comparing the receipt's `computed_receipts_root`
    /// against the expected value. If no expected root is set, all receipts are
    /// considered valid.
    pub fn add_receipt(&mut self, receipt: &VerificationReceipt) -> bool {
        if !self.seen_verifiers.insert(receipt.verifier_pubkey) {
            return false;
        }
        let is_valid = match self.expected_receipts_root {
            Some(ref expected) => receipt.matches_expected(expected),
            None => true,
        };
        if is_valid {
            self.valid_count = self.valid_count.saturating_add(1);
        } else {
            self.invalid_count = self.invalid_count.saturating_add(1);
        }
        true
    }

    /// Returns true if the attestation threshold has been reached.
    pub fn is_attested(&self) -> bool {
        self.valid_count >= self.threshold
    }

    /// Returns the total number of receipts received.
    pub fn total_receipts(&self) -> u32 {
        self.valid_count + self.invalid_count
    }

    /// Returns the fraction of valid receipts (0.0–1.0).
    pub fn validity_ratio(&self) -> f64 {
        let total = self.total_receipts();
        if total == 0 {
            0.0
        } else {
            self.valid_count as f64 / total as f64
        }
    }
}

/// Aggregates verification receipts across multiple blocks.
///
/// Maintains per-block status for recent blocks and evicts old ones when at capacity.
pub struct ReceiptAggregator {
    blocks: HashMap<B256, BlockVerificationStatus>,
    default_threshold: u32,
    max_tracked_blocks: usize,
}

fn clamp_threshold(threshold: u32) -> u32 {
    if threshold == 0 {
        warn!("attestation threshold 0 is invalid, clamping to 1");
        1
    } else {
        threshold
    }
}

impl ReceiptAggregator {
    /// Creates a new receipt aggregator.
    ///
    /// `default_threshold` is clamped to 1 if 0, preventing attestation with zero receipts.
    pub fn new(default_threshold: u32, max_tracked_blocks: usize) -> Self {
        Self {
            blocks: HashMap::new(),
            default_threshold: clamp_threshold(default_threshold),
            max_tracked_blocks,
        }
    }

    /// Registers a new block for tracking. Idempotent — existing blocks are not reset.
    ///
    /// `expected_receipts_root`: when `Some`, receipts are validated against this value.
    /// When `None`, all receipts are counted as valid (backward-compatible mode).
    ///
    /// Evicts the oldest block (by block number) when at capacity.
    pub fn register_block(
        &mut self,
        block_hash: B256,
        block_number: u64,
        expected_receipts_root: Option<B256>,
    ) {
        if let Some(status) = self.blocks.get_mut(&block_hash) {
            if status.expected_receipts_root.is_none() && expected_receipts_root.is_some() {
                status.expected_receipts_root = expected_receipts_root;
            }
            return;
        }
        // NOTE: N42-26 writes this as an edition-2024 let-chain; this crate is
        // edition 2021, so the binding is nested instead. Same semantics.
        if self.blocks.len() >= self.max_tracked_blocks {
            if let Some(oldest) = self
                .blocks
                .iter()
                .min_by_key(|(_, s)| s.block_number)
                .map(|(h, _)| *h)
            {
                self.blocks.remove(&oldest);
            }
        }
        self.blocks.insert(
            block_hash,
            BlockVerificationStatus::new(
                block_hash,
                block_number,
                expected_receipts_root,
                self.default_threshold,
            ),
        );
        // TTL = 256 blocks ≈ 34 minutes at 8-second slots.
        self.prune_old_blocks(block_number, 256);
    }

    /// Processes a verification receipt.
    ///
    /// Returns `Some(true)` if this receipt caused the threshold to be reached,
    /// `Some(false)` if accepted but threshold not yet met,
    /// or `None` if the block is untracked or the receipt is a duplicate.
    pub fn process_receipt(&mut self, receipt: &VerificationReceipt) -> Option<bool> {
        let status = self.blocks.get_mut(&receipt.block_hash)?;
        let was_attested = status.is_attested();
        if !status.add_receipt(receipt) {
            return None;
        }
        if !was_attested && status.is_attested() {
            tracing::info!(
                block_hash = %receipt.block_hash,
                block_number = receipt.block_number,
                valid = status.valid_count,
                threshold = status.threshold,
                "block attestation threshold reached"
            );
            Some(true)
        } else {
            Some(false)
        }
    }

    /// Returns the verification status for a block, if tracked.
    pub fn get_status(&self, block_hash: &B256) -> Option<&BlockVerificationStatus> {
        self.blocks.get(block_hash)
    }

    /// Returns the number of blocks currently being tracked.
    pub fn tracked_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Updates the default threshold for newly registered blocks (clamped to 1 if 0).
    pub fn set_default_threshold(&mut self, threshold: u32) {
        self.default_threshold = clamp_threshold(threshold);
    }

    /// Removes blocks whose block number is older than `current_block - ttl_blocks`.
    ///
    /// Prevents unbounded memory growth when `max_tracked_blocks` is large and blocks
    /// accumulate over time without being explicitly evicted.
    ///
    /// `ttl_blocks = 256` ≈ 34 minutes at 8-second slots.
    pub fn prune_old_blocks(&mut self, current_block: u64, ttl_blocks: u64) {
        let cutoff = current_block.saturating_sub(ttl_blocks);
        self.blocks.retain(|_, s| s.block_number >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_h2_primitives::{BlsSecretKey, BlsSignature};
    use std::sync::LazyLock;

    /// Cached dummy BLS signature for mock receipts.
    /// Aggregator tests only check dedup/counting, not cryptographic validity.
    static DUMMY_SIG: LazyLock<BlsSignature> = LazyLock::new(|| {
        let sk = BlsSecretKey::key_gen(&[1u8; 32]).unwrap();
        sk.sign(b"dummy")
    });

    /// The expected receipts root used by most tests.
    const EXPECTED_RR: B256 = B256::new([0xAA; 32]);

    /// Helper: creates a mock VerificationReceipt with the given fields.
    /// Uses a cached dummy BLS signature (not matching the content, but sufficient
    /// for aggregator-level tests that don't verify signatures).
    fn mock_receipt(
        block_hash: B256,
        block_number: u64,
        computed_receipts_root: B256,
        verifier_pubkey: [u8; 48],
    ) -> VerificationReceipt {
        VerificationReceipt {
            block_hash,
            block_number,
            computed_receipts_root,
            verifier_pubkey,
            signature: DUMMY_SIG.clone(),
            timestamp_ms: 1_000_000,
        }
    }

    /// Helper: creates a B256 from a single byte.
    fn hash(b: u8) -> B256 {
        B256::from([b; 32])
    }

    /// Helper: creates a unique verifier pubkey from a single byte.
    fn pubkey(b: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = b;
        pk
    }

    #[test]
    fn test_block_verification_status() {
        let bh = hash(1);
        let mut status = BlockVerificationStatus::new(bh, 100, Some(EXPECTED_RR), 3);

        assert_eq!(status.valid_count, 0);
        assert_eq!(status.invalid_count, 0);
        assert!(!status.is_attested());
        assert_eq!(status.total_receipts(), 0);

        // Add two valid receipts (matching expected_receipts_root).
        let r1 = mock_receipt(bh, 100, EXPECTED_RR, pubkey(1));
        let r2 = mock_receipt(bh, 100, EXPECTED_RR, pubkey(2));
        assert!(status.add_receipt(&r1));
        assert!(status.add_receipt(&r2));

        assert_eq!(status.valid_count, 2);
        assert_eq!(status.invalid_count, 0);
        assert_eq!(status.total_receipts(), 2);
        assert!(!status.is_attested(), "threshold is 3, only 2 valid");

        // Add one invalid receipt (wrong computed_receipts_root).
        let r3 = mock_receipt(bh, 100, B256::from([0xBB; 32]), pubkey(3));
        assert!(status.add_receipt(&r3));
        assert_eq!(status.invalid_count, 1);
        assert!(!status.is_attested(), "only 2 valid, threshold 3");

        // Add a third valid receipt → threshold reached.
        let r4 = mock_receipt(bh, 100, EXPECTED_RR, pubkey(4));
        assert!(status.add_receipt(&r4));
        assert_eq!(status.valid_count, 3);
        assert!(status.is_attested());
    }

    #[test]
    fn test_block_verification_dedup() {
        let bh = hash(2);
        let mut status = BlockVerificationStatus::new(bh, 200, Some(EXPECTED_RR), 5);

        let pk = pubkey(10);
        let r1 = mock_receipt(bh, 200, EXPECTED_RR, pk);
        let r2 = mock_receipt(bh, 200, EXPECTED_RR, pk); // same verifier

        assert!(status.add_receipt(&r1), "first receipt should be accepted");
        assert!(
            !status.add_receipt(&r2),
            "duplicate verifier should be rejected"
        );

        assert_eq!(
            status.valid_count, 1,
            "dedup: only one receipt should be counted"
        );
        assert_eq!(status.total_receipts(), 1);
    }

    #[test]
    fn test_receipt_aggregator_register_and_process() {
        let mut agg = ReceiptAggregator::new(2, 100); // threshold = 2

        let bh = hash(10);
        agg.register_block(bh, 1000, Some(EXPECTED_RR));

        assert_eq!(agg.tracked_blocks(), 1);

        // Process first valid receipt — not yet attested.
        let r1 = mock_receipt(bh, 1000, EXPECTED_RR, pubkey(1));
        let result1 = agg.process_receipt(&r1);
        assert_eq!(
            result1,
            Some(false),
            "first receipt should not reach threshold"
        );

        // Process second valid receipt — threshold reached.
        let r2 = mock_receipt(bh, 1000, EXPECTED_RR, pubkey(2));
        let result2 = agg.process_receipt(&r2);
        assert_eq!(result2, Some(true), "second receipt should reach threshold");

        // Process a receipt for an untracked block.
        let untracked_bh = hash(99);
        let r3 = mock_receipt(untracked_bh, 999, EXPECTED_RR, pubkey(3));
        let result3 = agg.process_receipt(&r3);
        assert_eq!(result3, None, "untracked block should return None");

        // Process a duplicate receipt.
        let result4 = agg.process_receipt(&r1);
        assert_eq!(result4, None, "duplicate receipt should return None");

        // Verify status.
        let status = agg.get_status(&bh).expect("block should be tracked");
        assert_eq!(status.valid_count, 2);
        assert!(status.is_attested());
    }

    #[test]
    fn test_receipt_aggregator_eviction() {
        let max_tracked = 3;
        let mut agg = ReceiptAggregator::new(2, max_tracked);

        // Register exactly max_tracked blocks.
        for i in 0..max_tracked {
            agg.register_block(hash(i as u8), i as u64, None);
        }
        assert_eq!(agg.tracked_blocks(), max_tracked);

        // Register one more. The block with the lowest block_number (0) should be evicted.
        agg.register_block(hash(100), 100, None);
        assert_eq!(agg.tracked_blocks(), max_tracked);

        // hash(0) at block_number 0 should have been evicted.
        assert!(
            agg.get_status(&hash(0)).is_none(),
            "oldest block (block_number 0) should be evicted"
        );

        // The others should still be present.
        assert!(agg.get_status(&hash(1)).is_some());
        assert!(agg.get_status(&hash(2)).is_some());
        assert!(agg.get_status(&hash(100)).is_some());
    }

    #[test]
    fn test_register_block_no_overwrite() {
        let mut agg = ReceiptAggregator::new(3, 100);
        let bh = hash(20);
        agg.register_block(bh, 2000, Some(EXPECTED_RR));

        // Add two receipts to the block.
        let r1 = mock_receipt(bh, 2000, EXPECTED_RR, pubkey(1));
        let r2 = mock_receipt(bh, 2000, EXPECTED_RR, pubkey(2));
        agg.process_receipt(&r1);
        agg.process_receipt(&r2);

        let status = agg.get_status(&bh).unwrap();
        assert_eq!(status.valid_count, 2);

        // Re-register the same block — should NOT reset counts.
        agg.register_block(bh, 2000, Some(EXPECTED_RR));

        let status = agg.get_status(&bh).unwrap();
        assert_eq!(
            status.valid_count, 2,
            "register_block must not overwrite existing receipt counts"
        );
    }

    #[test]
    fn test_register_block_can_fill_missing_expected_root() {
        let mut agg = ReceiptAggregator::new(2, 100);
        let bh = hash(21);
        agg.register_block(bh, 2001, None);
        assert_eq!(
            agg.get_status(&bh).unwrap().expected_receipts_root,
            None,
            "initial consensus notification does not carry receipts_root"
        );

        agg.register_block(bh, 2001, Some(EXPECTED_RR));
        assert_eq!(
            agg.get_status(&bh).unwrap().expected_receipts_root,
            Some(EXPECTED_RR),
            "packet generator should be able to fill the imported-header root"
        );
    }

    #[test]
    fn test_threshold_one_immediate_attestation() {
        let mut agg = ReceiptAggregator::new(1, 100);
        let bh = hash(30);
        agg.register_block(bh, 3000, Some(EXPECTED_RR));

        // With threshold=1, the first valid receipt should trigger attestation.
        let r = mock_receipt(bh, 3000, EXPECTED_RR, pubkey(1));
        let result = agg.process_receipt(&r);
        assert_eq!(
            result,
            Some(true),
            "threshold=1 should attest on first valid receipt"
        );
        assert!(agg.get_status(&bh).unwrap().is_attested());
    }

    #[test]
    fn test_validity_ratio() {
        let bh = hash(50);
        let mut status = BlockVerificationStatus::new(bh, 500, Some(EXPECTED_RR), 10);

        // No receipts → ratio 0.0.
        assert_eq!(status.validity_ratio(), 0.0);

        // 3 valid, 1 invalid → 3/4 = 0.75.
        status.add_receipt(&mock_receipt(bh, 500, EXPECTED_RR, pubkey(1)));
        status.add_receipt(&mock_receipt(bh, 500, EXPECTED_RR, pubkey(2)));
        status.add_receipt(&mock_receipt(bh, 500, EXPECTED_RR, pubkey(3)));
        status.add_receipt(&mock_receipt(bh, 500, B256::from([0xBB; 32]), pubkey(4)));

        let ratio = status.validity_ratio();
        assert!(
            (ratio - 0.75).abs() < f64::EPSILON,
            "expected 0.75, got {ratio}"
        );
    }

    #[test]
    fn test_aggregator_threshold_zero_clamp() {
        // threshold=0 should be clamped to 1 in production builds.
        let mut agg = ReceiptAggregator::new(0, 100);
        let bh = hash(40);
        agg.register_block(bh, 4000, None);

        // Before any receipt, the block should NOT be attested (threshold=1 after clamp).
        assert!(!agg.get_status(&bh).unwrap().is_attested());

        // One valid receipt should now trigger attestation (threshold=1).
        let r = mock_receipt(bh, 4000, EXPECTED_RR, pubkey(1));
        let result = agg.process_receipt(&r);
        assert_eq!(
            result,
            Some(true),
            "clamped threshold=1 should attest on first valid receipt"
        );
    }

    #[test]
    fn test_set_default_threshold() {
        let mut agg = ReceiptAggregator::new(5, 100);

        // Register block with old threshold.
        let bh1 = hash(60);
        agg.register_block(bh1, 6000, None);
        assert_eq!(agg.get_status(&bh1).unwrap().threshold, 5);

        // Update threshold; new blocks should use the new value.
        agg.set_default_threshold(3);
        let bh2 = hash(61);
        agg.register_block(bh2, 6001, None);
        assert_eq!(agg.get_status(&bh2).unwrap().threshold, 3);

        // set_default_threshold(0) should be clamped to 1.
        agg.set_default_threshold(0);
        let bh3 = hash(62);
        agg.register_block(bh3, 6002, None);
        assert_eq!(agg.get_status(&bh3).unwrap().threshold, 1);
    }

    #[test]
    fn test_none_expected_root_counts_all_valid() {
        let bh = hash(70);
        let mut status = BlockVerificationStatus::new(bh, 700, None, 2);

        // Any computed_receipts_root should be valid when expected is None.
        status.add_receipt(&mock_receipt(bh, 700, B256::from([0x11; 32]), pubkey(1)));
        status.add_receipt(&mock_receipt(bh, 700, B256::from([0x22; 32]), pubkey(2)));

        assert_eq!(status.valid_count, 2);
        assert_eq!(status.invalid_count, 0);
        assert!(status.is_attested());
    }
}
