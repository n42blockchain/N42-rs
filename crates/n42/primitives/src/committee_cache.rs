// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::arithmetic_side_effects)]

use crate::attestation_duty::AttestationDuty;
use crate::beacon::SHUFFLE_CACHE;
use crate::beacon_committee::BeaconCommittee;
use crate::safe_arith::SafeArith;
use crate::shuffle_list::shuffle_list;
use crate::*;
use crate::{ChainSpec, SLOTS_PER_EPOCH};
use alloy_primitives::B256;
use core::num::NonZeroUsize;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{four_byte_option_impl, Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::ops::Range;
use std::sync::Arc;
use tracing::debug;

// Define "legacy" implementations of `Option<Epoch>`, `Option<NonZeroUsize>` which use four bytes
// for encoding the union selector.
four_byte_option_impl!(four_byte_option_epoch, Epoch);
four_byte_option_impl!(four_byte_option_non_zero_usize, NonZeroUsize);

/// Computes and stores the shuffling for an epoch. Provides various getters to allow callers to
/// read the committees for the given epoch.
#[derive(Derivative, Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
#[derivative(PartialEq)]
pub struct CommitteeCache {
    #[ssz(with = "four_byte_option_epoch")]
    initialized_epoch: Option<Epoch>,
    shuffling: Vec<usize>,
    #[derivative(PartialEq(compare_with = "compare_shuffling_positions"))]
    shuffling_positions: Vec<NonZeroUsizeOption>,
    committees_per_slot: u64,
    slots_per_epoch: u64,
}

/// Equivalence function for `shuffling_positions` that ignores trailing `None` entries.
///
/// It can happen that states from different epochs computing the same cache have different
/// numbers of validators in `state.validators()` due to recent deposits. These new validators
/// cannot be active however and will always be omitted from the shuffling. This function checks
/// that two lists of shuffling positions are equivalent by ensuring that they are identical on all
/// common entries, and that new entries at the end are all `None`.
///
/// In practice this is only used in tests.
#[allow(clippy::indexing_slicing)]
fn compare_shuffling_positions(xs: &Vec<NonZeroUsizeOption>, ys: &Vec<NonZeroUsizeOption>) -> bool {
    use std::cmp::Ordering;

    let (shorter, longer) = match xs.len().cmp(&ys.len()) {
        Ordering::Equal => {
            return xs == ys;
        }
        Ordering::Less => (xs, ys),
        Ordering::Greater => (ys, xs),
    };
    shorter == &longer[..shorter.len()]
        && longer[shorter.len()..]
            .iter()
            .all(|new| *new == NonZeroUsizeOption(None))
}

impl CommitteeCache {
    /// Return a new, fully initialized cache.
    ///
    /// Spec v0.12.1
    /// PERF: Uses cached shuffle results when available
    pub fn initialized(
        state: &BeaconState,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> eyre::Result<CommitteeCache> {
        // Check that the cache is being built for an in-range epoch.
        if epoch > state.current_epoch() + 1 {
            return Err(eyre::eyre!("Error::EpochOutOfBounds"));
        }

        // May cause divide-by-zero errors.
        if SLOTS_PER_EPOCH == 0 {
            return Err(eyre::eyre!("Error::ZeroSlotsPerEpoch"));
        }

        // The use of `NonZeroUsize` reduces the maximum number of possible validators by one.
        if state.validators_store.len() == usize::MAX {
            return Err(eyre::eyre!("Error::TooManyValidators"));
        }

        let active_validator_indices = state.get_active_validator_indices(epoch);

        if active_validator_indices.is_empty() {
            return Err(eyre::eyre!("Error::InsufficientValidators"));
        }

        let committees_per_slot =
            get_committee_count_per_slot(active_validator_indices.len(), spec)? as u64;

        let seed = state.get_seed(epoch, DOMAIN_CONSTANT_BEACON_ATTESTER)?;

        // PERF: Try to get cached shuffle result first
        let cache_key = (epoch, B256::from_slice(&seed[..]));
        let shuffling = {
            // Try cache read
            let mut cached_result = None;
            if let Ok(cache) = SHUFFLE_CACHE.read() {
                if let Some(shuffling) = cache.peek(&cache_key) {
                    debug!(target: "committee_cache", epoch, "Shuffle cache hit");
                    cached_result = Some(shuffling.clone());
                }
            }

            if let Some(result) = cached_result {
                result
            } else {
                // Compute shuffle
                debug!(target: "committee_cache", epoch, "Shuffle cache miss, computing...");
                let computed = shuffle_list(
                    active_validator_indices,
                    spec.shuffle_round_count,
                    &seed[..],
                    false,
                )
                .ok_or(eyre::eyre!("Error::UnableToShuffle"))?;

                // Cache the result
                if let Ok(mut cache) = SHUFFLE_CACHE.write() {
                    cache.insert(cache_key, computed.clone());
                }

                computed
            }
        };

        let mut shuffling_positions = vec![<_>::default(); state.validators_store.len()];
        for (i, &v) in shuffling.iter().enumerate() {
            *shuffling_positions
                .get_mut(v)
                .ok_or(eyre::eyre!("Error::ShuffleIndexOutOfBounds, v={v}"))? =
                NonZeroUsize::new(i + 1).into();
        }

        Ok(CommitteeCache {
            initialized_epoch: Some(epoch),
            shuffling,
            shuffling_positions,
            committees_per_slot,
            slots_per_epoch: SLOTS_PER_EPOCH,
        })
    }

    /// Returns `true` if the cache has been initialized at the supplied `epoch`.
    ///
    /// An non-initialized cache does not provide any useful information.
    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    /// Returns the **shuffled** list of active validator indices for the initialized epoch.
    ///
    /// These indices are not in ascending order.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn active_validator_indices(&self) -> &[usize] {
        &self.shuffling
    }

    /// Returns the shuffled list of active validator indices for the initialized epoch.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn shuffling(&self) -> &[usize] {
        &self.shuffling
    }

    /// Get the Beacon committee for the given `slot` and `index`.
    ///
    /// Return `None` if the cache is uninitialized, or the `slot` or `index` is out of range.
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Option<BeaconCommittee<'_>> {
        if self.initialized_epoch.is_none()
            //|| !self.is_initialized_at(slot.epoch(self.slots_per_epoch))
            || !self.is_initialized_at(slot/self.slots_per_epoch)
            || index >= self.committees_per_slot
        {
            return None;
        }

        let committee_index = compute_committee_index_in_epoch(
            slot,
            self.slots_per_epoch as usize,
            self.committees_per_slot as usize,
            index as usize,
        );
        let committee = self.compute_committee(committee_index)?;

        Some(BeaconCommittee {
            slot,
            index,
            committee,
        })
    }

    /// Get all the Beacon committees at a given `slot`.
    ///
    /// Committees are sorted by ascending index order 0..committees_per_slot
    pub fn get_beacon_committees_at_slot(
        &self,
        slot: Slot,
    ) -> eyre::Result<Vec<BeaconCommittee<'_>>> {
        if self.initialized_epoch.is_none() {
            return Err(eyre::eyre!("Error::CommitteeCacheUninitialized(None)"));
        }

        (0..self.committees_per_slot())
            .map(|index| {
                self.get_beacon_committee(slot, index).ok_or(eyre::eyre!(
                    "Error::NoCommittee, slot={slot}, index={index}"
                ))
            })
            .collect()
    }

    /// Returns all committees for `self.initialized_epoch`.
    pub fn get_all_beacon_committees(&self) -> eyre::Result<Vec<BeaconCommittee<'_>>> {
        let initialized_epoch = self
            .initialized_epoch
            .ok_or(eyre::eyre!("Error::CommitteeCacheUninitialized(None)"))?;

        ((initialized_epoch * self.slots_per_epoch)..)
            .take(self.slots_per_epoch as usize)
            .try_fold(
                //initialized_epoch.slot_iter(self.slots_per_epoch).try_fold(
                Vec::with_capacity(self.epoch_committee_count()),
                |mut vec, slot| {
                    vec.append(&mut self.get_beacon_committees_at_slot(slot)?);
                    Ok(vec)
                },
            )
    }

    /// Returns the `AttestationDuty` for the given `validator_index`.
    ///
    /// Returns `None` if the `validator_index` does not exist, does not have duties or `Self` is
    /// non-initialized.
    pub fn get_attestation_duties(&self, validator_index: usize) -> Option<AttestationDuty> {
        let i = self.shuffled_position(validator_index)?;

        (0..self.epoch_committee_count())
            .map(|nth_committee| (nth_committee, self.compute_committee_range(nth_committee)))
            .find(|(_, range)| {
                if let Some(range) = range {
                    range.start <= i && range.end > i
                } else {
                    false
                }
            })
            .and_then(|(nth_committee, range)| {
                let (slot, index) = self.convert_to_slot_and_index(nth_committee as u64)?;
                let range = range?;
                let committee_position = i - range.start;
                let committee_len = range.end - range.start;

                Some(AttestationDuty {
                    slot,
                    index,
                    committee_position,
                    committee_len,
                    committees_at_slot: self.committees_per_slot(),
                })
            })
    }

    /// Convert an index addressing the list of all epoch committees into a slot and per-slot index.
    fn convert_to_slot_and_index(
        &self,
        global_committee_index: u64,
    ) -> Option<(Slot, CommitteeIndex)> {
        //let epoch_start_slot = self.initialized_epoch?.start_slot(self.slots_per_epoch);
        let epoch_start_slot = self.initialized_epoch? * self.slots_per_epoch;
        let slot_offset = global_committee_index / self.committees_per_slot;
        let index = global_committee_index % self.committees_per_slot;
        Some((epoch_start_slot.safe_add(slot_offset).ok()?, index))
    }

    /// Returns the number of active validators in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }

    /// Returns the total number of committees in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn epoch_committee_count(&self) -> usize {
        epoch_committee_count(
            self.committees_per_slot as usize,
            self.slots_per_epoch as usize,
        )
    }

    /// Returns the number of committees per slot for this cache's epoch.
    pub fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// Returns a slice of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// Spec v0.12.1
    fn compute_committee(&self, index: usize) -> Option<&[usize]> {
        self.shuffling.get(self.compute_committee_range(index)?)
    }

    /// Returns a range of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// To avoid a divide-by-zero, returns `None` if `self.committee_count` is zero.
    ///
    /// Will also return `None` if the index is out of bounds.
    ///
    /// Spec v0.12.1
    fn compute_committee_range(&self, index: usize) -> Option<Range<usize>> {
        compute_committee_range_in_epoch(self.epoch_committee_count(), index, self.shuffling.len())
    }

    /// Returns the index of some validator in `self.shuffling`.
    ///
    /// Always returns `None` for a non-initialized epoch.
    pub fn shuffled_position(&self, validator_index: usize) -> Option<usize> {
        self.shuffling_positions
            .get(validator_index)?
            .0
            .map(|p| p.get() - 1)
    }
}

/// Computes the position of the given `committee_index` with respect to all committees in the
/// epoch.
///
/// The return result may be used to provide input to the `compute_committee_range_in_epoch`
/// function.
pub fn compute_committee_index_in_epoch(
    slot: Slot,
    slots_per_epoch: usize,
    committees_per_slot: usize,
    committee_index: usize,
) -> usize {
    ((slot as usize) % slots_per_epoch) * committees_per_slot + committee_index
}

/// Computes the range for slicing the shuffled indices to determine the members of a committee.
///
/// The `index_in_epoch` parameter can be computed computed using
/// `compute_committee_index_in_epoch`.
pub fn compute_committee_range_in_epoch(
    epoch_committee_count: usize,
    index_in_epoch: usize,
    shuffling_len: usize,
) -> Option<Range<usize>> {
    if epoch_committee_count == 0 || index_in_epoch >= epoch_committee_count {
        return None;
    }

    let start = (shuffling_len * index_in_epoch) / epoch_committee_count;
    let end = (shuffling_len * (index_in_epoch + 1)) / epoch_committee_count;

    Some(start..end)
}

/// Returns the total number of committees in an epoch.
pub fn epoch_committee_count(committees_per_slot: usize, slots_per_epoch: usize) -> usize {
    committees_per_slot * slots_per_epoch
}

/// Returns a list of all `validators` indices where the validator is active at the given
/// `epoch`.
///
/// Spec v0.12.1
pub fn get_active_validator_indices<'a, V, I>(validators: V, epoch: Epoch) -> Vec<usize>
where
    V: IntoIterator<Item = &'a Validator, IntoIter = I>,
    I: ExactSizeIterator + Iterator<Item = &'a Validator>,
{
    let iter = validators.into_iter();

    let mut active = Vec::with_capacity(iter.len());

    for (index, validator) in iter.enumerate() {
        if validator.is_active_at(epoch) {
            active.push(index)
        }
    }

    active
}

impl arbitrary::Arbitrary<'_> for CommitteeCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}

/// This is a shim struct to ensure that we can encode a `Vec<Option<NonZeroUsize>>` an SSZ union
/// with a four-byte selector. The SSZ specification changed from four bytes to one byte during 2021
/// and we use this shim to avoid breaking the Lighthouse database.
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct NonZeroUsizeOption(Option<NonZeroUsize>);

impl From<Option<NonZeroUsize>> for NonZeroUsizeOption {
    fn from(opt: Option<NonZeroUsize>) -> Self {
        Self(opt)
    }
}

impl Encode for NonZeroUsizeOption {
    fn is_ssz_fixed_len() -> bool {
        four_byte_option_non_zero_usize::encode::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        four_byte_option_non_zero_usize::encode::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        four_byte_option_non_zero_usize::encode::ssz_bytes_len(&self.0)
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        four_byte_option_non_zero_usize::encode::ssz_append(&self.0, buf)
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        four_byte_option_non_zero_usize::encode::as_ssz_bytes(&self.0)
    }
}

impl Decode for NonZeroUsizeOption {
    fn is_ssz_fixed_len() -> bool {
        four_byte_option_non_zero_usize::decode::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        four_byte_option_non_zero_usize::decode::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        four_byte_option_non_zero_usize::decode::from_ssz_bytes(bytes).map(Self)
    }
}

/// Return the number of committees per slot.
///
/// Note: the number of committees per slot is constant in each epoch, and depends only on
/// the `active_validator_count` during the slot's epoch.
///
/// Spec v0.12.1
fn get_committee_count_per_slot(
    active_validator_count: usize,
    spec: &ChainSpec,
) -> eyre::Result<usize> {
    get_committee_count_per_slot_with(
        active_validator_count,
        spec.max_committees_per_slot,
        spec.target_committee_size,
    )
}

fn get_committee_count_per_slot_with(
    active_validator_count: usize,
    max_committees_per_slot_var: usize,
    target_committee_size_var: usize,
) -> eyre::Result<usize> {
    Ok(std::cmp::max(
        1,
        std::cmp::min(
            max_committees_per_slot_var,
            active_validator_count
                .safe_div(SLOTS_PER_EPOCH as usize)?
                .safe_div(target_committee_size_var)?,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_chain_spec;
    use crate::test_util::{active_validator, state_with_validators};

    fn spec() -> ChainSpec {
        beacon_chain_spec()
    }

    fn cache_for(n: usize) -> (BeaconState, CommitteeCache) {
        let state = state_with_validators(n, 0);
        let cache = CommitteeCache::initialized(&state, 0, &spec()).unwrap();
        (state, cache)
    }

    #[test]
    fn committee_count_per_slot_is_clamped() {
        // Fewer than 32 * target validators still yields one committee.
        assert_eq!(get_committee_count_per_slot_with(0, 4, 4).unwrap(), 1);
        assert_eq!(get_committee_count_per_slot_with(127, 4, 4).unwrap(), 1);
        // 32 slots * target 4 = 128 validators per committee-per-slot.
        assert_eq!(get_committee_count_per_slot_with(128, 4, 4).unwrap(), 1);
        assert_eq!(get_committee_count_per_slot_with(256, 4, 4).unwrap(), 2);
        // Capped by the max.
        assert_eq!(get_committee_count_per_slot_with(100_000, 4, 4).unwrap(), 4);
        // A zero target committee size is a division by zero, not a panic.
        assert!(get_committee_count_per_slot_with(256, 4, 0).is_err());
    }

    #[test]
    fn committee_index_and_range_arithmetic() {
        // slot 33 is the second slot of its epoch; 2 committees per slot.
        assert_eq!(compute_committee_index_in_epoch(33, 32, 2, 1), 3);
        assert_eq!(compute_committee_index_in_epoch(0, 32, 2, 0), 0);
        assert_eq!(epoch_committee_count(2, 32), 64);

        assert_eq!(compute_committee_range_in_epoch(0, 0, 10), None);
        assert_eq!(compute_committee_range_in_epoch(4, 4, 10), None);
        assert_eq!(compute_committee_range_in_epoch(4, 9, 10), None);

        // The ranges tile the shuffling exactly, with no gaps and no overlap.
        let mut next = 0;
        for i in 0..7 {
            let r = compute_committee_range_in_epoch(7, i, 100).unwrap();
            assert_eq!(r.start, next);
            next = r.end;
        }
        assert_eq!(next, 100);
    }

    #[test]
    fn initialized_builds_the_expected_shuffling() {
        let (state, cache) = cache_for(256);
        assert!(cache.is_initialized_at(0));
        assert!(!cache.is_initialized_at(1));
        assert_eq!(cache.active_validator_count(), 256);
        assert_eq!(cache.committees_per_slot(), 2);
        assert_eq!(cache.epoch_committee_count(), 64);

        let seed = state.get_seed(0, DOMAIN_CONSTANT_BEACON_ATTESTER).unwrap();
        let expected = shuffle_list((0..256).collect(), spec().shuffle_round_count, &seed[..], false)
            .unwrap();
        assert_eq!(cache.shuffling(), expected.as_slice());
        assert_eq!(cache.active_validator_indices(), expected.as_slice());

        // Positions invert the shuffling.
        for (pos, &v) in cache.shuffling().iter().enumerate() {
            assert_eq!(cache.shuffled_position(v), Some(pos));
        }
    }

    #[test]
    fn initialized_is_deterministic_across_shuffle_cache_hits() {
        let state = state_with_validators(64, 0);
        let a = CommitteeCache::initialized(&state, 0, &spec()).unwrap();
        let b = CommitteeCache::initialized(&state, 0, &spec()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.shuffling(), b.shuffling());
    }

    #[test]
    #[ignore = "BUG: SHUFFLE_CACHE key (epoch, seed) ignores the active validator set, so a changed set with the same seed gets a stale shuffling (committee_cache.rs:105)"]
    fn shuffle_cache_must_not_return_a_shuffling_of_another_validator_set() {
        let spec = spec();
        let state_a = state_with_validators(64, 0);
        let mut state_b = state_with_validators(65, 0);
        state_b.randao_mix = state_a.randao_mix;

        let a = CommitteeCache::initialized(&state_a, 0, &spec).unwrap();
        assert_eq!(a.active_validator_count(), 64);
        let b = CommitteeCache::initialized(&state_b, 0, &spec).unwrap();
        assert_eq!(b.active_validator_count(), 65);
        assert!(b.shuffling().contains(&64));
    }

    #[test]
    fn initialized_rejects_out_of_range_epoch_and_empty_sets() {
        let state = state_with_validators(8, 0);
        // current epoch is 0, so epoch 1 is the furthest allowed.
        assert!(CommitteeCache::initialized(&state, 1, &spec()).is_ok());
        let err = CommitteeCache::initialized(&state, 2, &spec()).unwrap_err();
        assert!(err.to_string().contains("EpochOutOfBounds"));

        let empty = BeaconState::new();
        let err = CommitteeCache::initialized(&empty, 0, &spec()).unwrap_err();
        assert!(err.to_string().contains("InsufficientValidators"));
    }

    #[test]
    fn committees_partition_the_shuffling() {
        let (_, cache) = cache_for(256);
        let all = cache.get_all_beacon_committees().unwrap();
        assert_eq!(all.len(), 64);

        let flat: Vec<usize> = all.iter().flat_map(|c| c.committee.iter().copied()).collect();
        assert_eq!(flat, cache.shuffling());
        assert!(all.iter().all(|c| c.committee.len() == 4));

        // Committees are ordered by slot, then by index.
        for (n, c) in all.iter().enumerate() {
            assert_eq!(c.slot, (n / 2) as u64);
            assert_eq!(c.index, (n % 2) as u64);
        }

        let at_slot = cache.get_beacon_committees_at_slot(5).unwrap();
        assert_eq!(at_slot.len(), 2);
        assert_eq!(at_slot[0], all[10]);
        assert_eq!(at_slot[1], all[11]);
    }

    #[test]
    fn get_beacon_committee_rejects_bad_slot_and_index() {
        let (_, cache) = cache_for(256);
        assert!(cache.get_beacon_committee(0, 0).is_some());
        // Index at or beyond committees_per_slot.
        assert!(cache.get_beacon_committee(0, 2).is_none());
        // Slot 32 belongs to epoch 1, which this cache is not initialised for.
        assert!(cache.get_beacon_committee(32, 0).is_none());
    }

    #[test]
    fn uninitialized_cache_gives_no_committees_or_duties() {
        let cache = CommitteeCache::default();
        assert!(!cache.is_initialized_at(0));
        assert!(cache.get_beacon_committee(0, 0).is_none());
        assert!(cache.get_beacon_committees_at_slot(0).is_err());
        assert!(cache.get_all_beacon_committees().is_err());
        assert!(cache.get_attestation_duties(0).is_none());
        assert!(cache.shuffled_position(0).is_none());
        assert_eq!(cache.active_validator_count(), 0);
        assert_eq!(cache.committees_per_slot(), 0);
        assert!(cache.shuffling().is_empty());
        assert_eq!(cache.convert_to_slot_and_index(3), None);
    }

    #[test]
    fn attestation_duties_match_the_committee_layout() {
        let (_, cache) = cache_for(256);
        let all = cache.get_all_beacon_committees().unwrap();
        for validator in 0..256usize {
            let duty = cache.get_attestation_duties(validator).unwrap();
            let committee = cache.get_beacon_committee(duty.slot, duty.index).unwrap();
            assert_eq!(committee.committee[duty.committee_position], validator);
            assert_eq!(duty.committee_len, committee.committee.len());
            assert_eq!(duty.committees_at_slot, 2);
            assert!(all.contains(&committee));
        }
        assert!(cache.get_attestation_duties(256).is_none());
    }

    #[test]
    fn inactive_validators_have_no_position_or_duty() {
        let spec = spec();
        let mut state = state_with_validators(64, 0);
        let mut exited = active_validator(3, &spec);
        exited.exit_epoch = 0;
        state.validators_store.set(3, exited).unwrap();

        let cache = CommitteeCache::initialized(&state, 0, &spec).unwrap();
        assert_eq!(cache.active_validator_count(), 63);
        assert!(!cache.shuffling().contains(&3));
        assert_eq!(cache.shuffled_position(3), None);
        assert!(cache.get_attestation_duties(3).is_none());
        assert!(cache.get_attestation_duties(4).is_some());
    }

    #[test]
    fn equality_ignores_trailing_inactive_validators() {
        let spec = spec();
        let state_a = state_with_validators(64, 0);
        let mut state_b = state_with_validators(64, 0);
        state_b.randao_mix = state_a.randao_mix;
        // A trailing, never-activated validator only extends shuffling_positions with None.
        let mut pending = active_validator(64, &spec);
        pending.activation_epoch = spec.far_future_epoch;
        state_b.validators_store.push(pending).unwrap();
        state_b.balances_store.push(0).unwrap();
        state_b.inactivity_scores_store.push(0).unwrap();

        let a = CommitteeCache::initialized(&state_a, 0, &spec).unwrap();
        let b = CommitteeCache::initialized(&state_b, 0, &spec).unwrap();
        assert_eq!(a.shuffling_positions.len() + 1, b.shuffling_positions.len());
        assert_eq!(a, b);
        assert_eq!(b, a);

        // A different set of active validators is not equal.
        let mut state_c = state_with_validators(65, 0);
        state_c.randao_mix = state_a.randao_mix ^ B256::repeat_byte(1);
        let c = CommitteeCache::initialized(&state_c, 0, &spec).unwrap();
        assert_ne!(a, c);
        // Equal-length position vectors that differ are not equal either.
        let mut d = a.clone();
        d.shuffling_positions.swap(0, 1);
        assert_ne!(a, d);
    }

    #[test]
    fn ssz_and_json_roundtrip() {
        let (_, cache) = cache_for(100);
        let bytes = cache.as_ssz_bytes();
        let back = CommitteeCache::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(back, cache);
        assert_eq!(back.shuffling(), cache.shuffling());
        assert!(back.is_initialized_at(0));

        let json = serde_json::to_string(&cache).unwrap();
        let from_json: CommitteeCache = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, cache);

        // An uninitialised cache keeps its `None` epoch through SSZ.
        let default_back =
            CommitteeCache::from_ssz_bytes(&CommitteeCache::default().as_ssz_bytes()).unwrap();
        assert!(!default_back.is_initialized_at(0));
        assert!(CommitteeCache::from_ssz_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn non_zero_usize_option_ssz_uses_four_byte_selector() {
        let none = NonZeroUsizeOption(None);
        let some = NonZeroUsizeOption::from(NonZeroUsize::new(5));
        assert_eq!(none.ssz_bytes_len(), none.as_ssz_bytes().len());
        assert_eq!(some.ssz_bytes_len(), some.as_ssz_bytes().len());
        // Four-byte selector followed by the value, so Some is longer than None.
        assert!(some.as_ssz_bytes().len() > none.as_ssz_bytes().len());
        assert_eq!(
            NonZeroUsizeOption::from_ssz_bytes(&some.as_ssz_bytes()).unwrap(),
            some
        );
        assert_eq!(
            NonZeroUsizeOption::from_ssz_bytes(&none.as_ssz_bytes()).unwrap(),
            none
        );
        assert!(!<NonZeroUsizeOption as Encode>::is_ssz_fixed_len());
        assert!(!<NonZeroUsizeOption as Decode>::is_ssz_fixed_len());
        let mut buf = Vec::new();
        some.ssz_append(&mut buf);
        assert_eq!(buf, some.as_ssz_bytes());
    }

    #[test]
    fn free_function_active_indices_filters_by_epoch() {
        let spec = spec();
        let mut late = active_validator(1, &spec);
        late.activation_epoch = 5;
        let mut exited = active_validator(2, &spec);
        exited.exit_epoch = 3;
        let validators = vec![active_validator(0, &spec), late, exited];
        assert_eq!(get_active_validator_indices(&validators, 0), vec![0, 2]);
        assert_eq!(get_active_validator_indices(&validators, 4), vec![0]);
        assert_eq!(get_active_validator_indices(&validators, 5), vec![0, 1]);
    }

    #[test]
    fn arbitrary_cache_is_the_default_cache() {
        use arbitrary::Arbitrary;
        let mut u = arbitrary::Unstructured::new(&[1, 2, 3]);
        let c = CommitteeCache::arbitrary(&mut u).unwrap();
        assert!(!c.is_initialized_at(0));
        assert_eq!(c.active_validator_count(), 0);
    }
}
