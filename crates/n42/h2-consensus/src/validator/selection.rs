use super::set::ValidatorSet;
use n42_h2_primitives::consensus::ViewNumber;

/// Leader selection strategy based on round-robin rotation.
///
/// The leader for view `v` is `v % n` where `n` is the validator set size.
/// This is deterministic and requires no communication—every honest node
/// can independently compute who the leader is for any view.
#[derive(Debug, Clone)]
pub struct LeaderSelector;

impl LeaderSelector {
    /// Returns the leader's validator index for the given view.
    ///
    /// # Panics
    /// Panics if the validator set is empty. Returning a synthetic validator
    /// index would let a malformed release configuration appear to have a
    /// leader and fail open.
    pub fn leader_for_view(view: ViewNumber, validator_set: &ValidatorSet) -> u32 {
        Self::leader_for_view_with_tenure(view, 1, validator_set)
    }

    /// The leader for view `v` when every validator leads `tenure` consecutive
    /// views: `(v / tenure) % n`. A tenure of 1 is the round-robin above, and
    /// 0 is read as 1 rather than dividing by it.
    ///
    /// # Panics
    /// Panics if the validator set is empty, for the reason given on
    /// [`Self::leader_for_view`].
    pub fn leader_for_view_with_tenure(
        view: ViewNumber,
        tenure: u64,
        validator_set: &ValidatorSet,
    ) -> u32 {
        assert!(
            !validator_set.is_empty(),
            "leader_for_view called with empty validator set"
        );
        ((view / tenure.max(1)) % validator_set.len() as u64) as u32
    }

    /// The view a validator enters once it holds a timeout certificate for
    /// `tc_view` (the rotate-on-timeout rule, consensus-visible). Mirrors
    /// gov5's `ViewAfterTimeout` (`internal/consensus/hotstuff/validator.go`,
    /// branch `feat/hotstuff-rotate-on-timeout`) operation for operation.
    ///
    /// The leader schedule stays `(view / tenure) % n`; the rule moves the
    /// view instead. Without rotation, or with a tenure of one, the next view
    /// is `tc_view + 1`. With rotation it is the first view of the next
    /// tenure window, `(tc_view / tenure + 1) * tenure`, so a timed-out leader
    /// loses the rest of its tenure and the next validator leads a full,
    /// fresh one. With epochs enabled (`epoch_length > 0`) the target is
    /// clamped to the first epoch-boundary view above `tc_view` (a boundary
    /// `b` has `(b - 1) % epoch_length == 0`), so every client enters it. On
    /// overflow the result is the classic `tc_view + 1` (wrapping to 0 at
    /// `u64::MAX`, exactly as gov5's unsigned arithmetic does).
    pub const fn view_after_timeout(
        tc_view: ViewNumber,
        tenure: u64,
        epoch_length: u64,
        rotate: bool,
    ) -> ViewNumber {
        let next = tc_view.wrapping_add(1);
        if !rotate || tenure <= 1 || next == 0 {
            return next;
        }
        let window = tc_view / tenure + 1;
        let target = window.wrapping_mul(tenure);
        if target / tenure != window || target < next {
            // Overflow: stay classic.
            return next;
        }
        if epoch_length > 0 && tc_view >= 1 {
            let boundary = ((tc_view - 1) / epoch_length + 1)
                .wrapping_mul(epoch_length)
                .wrapping_add(1);
            if boundary > tc_view && boundary < target {
                return boundary;
            }
        }
        target
    }

    /// Checks if the given validator is the leader for the given view.
    pub fn is_leader(validator_index: u32, view: ViewNumber, validator_set: &ValidatorSet) -> bool {
        Self::leader_for_view(view, validator_set) == validator_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use crate::ValidatorInfo;
    use n42_h2_primitives::BlsSecretKey;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
    }

    /// Helper: create a ValidatorSet with `n` deterministic validators.
    fn make_validator_set(n: usize) -> ValidatorSet {
        let infos: Vec<_> = (0..n)
            .map(|i| {
                let sk = test_key(0x30 + i as u8);
                ValidatorInfo {
                    address: Address::with_last_byte(i as u8),
                    bls_public_key: sk.public_key(),
                    p2p_peer_id: None,
                }
            })
            .collect();
        let f = ((n as u32).saturating_sub(1)) / 3;
        ValidatorSet::new(&infos, f)
    }

    #[test]
    fn test_round_robin() {
        let vs = make_validator_set(4);

        let expected = [0u32, 1, 2, 3, 0, 1, 2, 3];
        for (view, &expected_leader) in expected.iter().enumerate() {
            let leader = LeaderSelector::leader_for_view(view as u64, &vs);
            assert_eq!(leader, expected_leader);
        }
    }

    #[test]
    fn a_tenure_holds_the_leader_for_consecutive_views() {
        let vs = make_validator_set(3);
        // Tenure 1 is the round-robin, view by view.
        for view in 0..9u64 {
            assert_eq!(
                LeaderSelector::leader_for_view_with_tenure(view, 1, &vs),
                LeaderSelector::leader_for_view(view, &vs)
            );
        }
        // Tenure 4: views 0-3 -> 0, 4-7 -> 1, 8-11 -> 2, 12-15 -> 0 again.
        let expected = [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 0, 0, 0, 0];
        for (view, leader) in expected.iter().enumerate() {
            assert_eq!(LeaderSelector::leader_for_view_with_tenure(view as u64, 4, &vs), *leader, "view {view}");
        }
        // Tenure 0 is read as 1 rather than dividing by it.
        assert_eq!(LeaderSelector::leader_for_view_with_tenure(5, 0, &vs), 2);
    }

    /// gov5 `TestViewAfterTimeoutVectors`: the spec's section 10.4 table,
    /// read from `testdata/rotate_on_timeout_vectors.json`.
    #[test]
    fn view_after_timeout_vectors() {
        let raw = include_str!("../../testdata/rotate_on_timeout_vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).expect("vector file parses");
        let vectors = doc["vectors"].as_array().expect("vectors array");
        assert_eq!(vectors.len(), 16);
        for row in vectors {
            let tc_view = row[0].as_u64().expect("tc_view");
            let tenure = row[1].as_u64().expect("tenure");
            let epoch = row[2].as_u64().expect("epoch_length");
            let active = row[3].as_bool().expect("active");
            let want = row[4].as_u64().expect("result");
            assert_eq!(
                LeaderSelector::view_after_timeout(tc_view, tenure, epoch, active),
                want,
                "view_after_timeout({tc_view}, {tenure}, {epoch}, {active})"
            );
        }
    }

    /// The spec's section 10.4 view sequences S1-S9 (n = 7, T = 8): the view
    /// a TC leads to and that view's grid leader.
    #[test]
    fn view_after_timeout_sequences() {
        let vs = make_validator_set(7);
        let next = |x: u64, e: u64, on: bool| LeaderSelector::view_after_timeout(x, 8, e, on);
        let leader = |v: u64| LeaderSelector::leader_for_view_with_tenure(v, 8, &vs);
        // S1: leader 1 dead, TC(8) -> 16 (L2).
        assert_eq!((next(8, 0, true), leader(16)), (16, 2));
        // S2: leaders 1 and 2 dead, TC(16) -> 24 (L3).
        assert_eq!((next(16, 0, true), leader(24)), (24, 3));
        // S3: dies mid-tenure, TC(11) -> 16 (L2).
        assert_eq!(next(11, 0, true), 16);
        // S4: last view of the window, same as classic.
        assert_eq!(next(15, 0, true), next(15, 0, false));
        // S5: wrap-around, TC(48) (L6) -> 56 (L0).
        assert_eq!((leader(48), next(48, 0, true), leader(56)), (6, 56, 0));
        // S6: switch off, one view at a time.
        for x in 8..16 {
            assert_eq!(next(x, 0, false), x + 1);
        }
        // S7: epoch clamp with E = 10.
        assert_eq!((next(8, 10, true), leader(11)), (11, 1));
        assert_eq!(next(11, 10, true), 16);
        // S9: tenure 1 is the classic change.
        for x in 0..50 {
            assert_eq!(LeaderSelector::view_after_timeout(x, 1, 0, true), x + 1);
        }
    }

    #[test]
    fn test_is_leader() {
        let vs = make_validator_set(4);

        // View 0: validator 0 is leader
        assert!(LeaderSelector::is_leader(0, 0, &vs));
        assert!(!LeaderSelector::is_leader(1, 0, &vs));
        assert!(!LeaderSelector::is_leader(2, 0, &vs));
        assert!(!LeaderSelector::is_leader(3, 0, &vs));

        // View 1: validator 1 is leader
        assert!(!LeaderSelector::is_leader(0, 1, &vs));
        assert!(LeaderSelector::is_leader(1, 1, &vs));

        // View 5: validator 1 is leader (5 % 4 = 1)
        assert!(LeaderSelector::is_leader(1, 5, &vs));
        assert!(!LeaderSelector::is_leader(0, 5, &vs));
    }

    #[test]
    #[should_panic(expected = "leader_for_view called with empty validator set")]
    fn test_leader_for_view_empty_set() {
        let vs = ValidatorSet::new(&[], 0);
        let _leader = LeaderSelector::leader_for_view(5, &vs);
    }

    #[test]
    fn test_leader_for_view_single_validator() {
        let vs = make_validator_set(1);
        for view in 0..10u64 {
            let leader = LeaderSelector::leader_for_view(view, &vs);
            assert_eq!(leader, 0);
        }
    }
}
