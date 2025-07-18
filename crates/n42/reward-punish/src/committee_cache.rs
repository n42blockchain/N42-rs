use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::Arc;
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use crate::slot_epoch::Epoch;
use serde::{Deserialize, Serialize};
use ssz::{four_byte_option_impl, Decode, DecodeError, Encode};
use crate::slot_epoch::Slot;
use crate::beaconstate::CommitteeIndex;
use crate::beacon_committee::BeaconCommittee;
use crate::beaconstate::Error;
use crate::spec::EthSpec;
use crate::beaconstate::BeaconState;
use crate::spec::Spec;
use crate::beaconstate::Validator;
use crate::spec::Domain;
use crate::shuffle_list::shuffle_list;
use crate::arith::SafeArith;


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

    /// Returns the number of active validators in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }


    /// Return a new, fully initialized cache.
    ///
    /// Spec v0.12.1
    pub fn initialized<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
        spec: &Spec,
    ) -> Result<Arc<CommitteeCache>, Error> {
        // Check that the cache is being built for an in-range epoch.
        //
        // We allow caches to be constructed for historic epochs, per:
        //
        // https://github.com/sigp/lighthouse/issues/3270
        let reqd_randao_epoch = epoch
            .saturating_sub(spec.min_seed_lookahead)
            .saturating_sub(1u64);

        if reqd_randao_epoch < state.min_randao_epoch() || epoch > state.current_epoch().safe_add(1)?{
            return Err(Error::EpochOutOfBounds);
        }

        // May cause divide-by-zero errors.
        if E::slots_per_epoch() == 0 {
            return Err(Error::ZeroSlotsPerEpoch);
        }

        // The use of `NonZeroUsize` reduces the maximum number of possible validators by one.
        if state.validators().len() == usize::MAX {
            return Err(Error::TooManyValidators);
        }

        let active_validator_indices = get_active_validator_indices(state.validators(), epoch);

        if active_validator_indices.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let committees_per_slot =
            E::get_committee_count_per_slot(active_validator_indices.len(), spec)? as u64;

        let seed = state.get_seed(epoch, Domain::BeaconAttester, spec)?;

        let shuffling = shuffle_list(
            active_validator_indices,
            spec.shuffle_round_count,
            &seed[..],
            false,
        )
            .ok_or(Error::UnableToShuffle)?;

        let mut shuffling_positions = vec![<_>::default(); state.validators().len()];
        for (i, &v) in shuffling.iter().enumerate() {
            *shuffling_positions
                .get_mut(v)
                .ok_or(Error::ShuffleIndexOutOfBounds(v))? = NonZeroUsize::new(i + 1).into();
        }

        Ok(Arc::new(CommitteeCache {
            initialized_epoch: Some(epoch),
            shuffling,
            shuffling_positions,
            committees_per_slot,
            slots_per_epoch: E::slots_per_epoch(),
        }))
    }

    /// Returns `true` if the cache has been initialized at the supplied `epoch`.
    ///
    /// An non-initialized cache does not provide any useful information.
    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    /// Get all the Beacon committees at a given `slot`.
    ///
    /// Committees are sorted by ascending index order 0..committees_per_slot
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<BeaconCommittee<'_>>, Error> {
        if self.initialized_epoch.is_none() {
            return Err(Error::CommitteeCacheUninitialized(None));
        }

        (0..self.committees_per_slot())
            .map(|index| {
                self.get_beacon_committee(slot, index)
                    .ok_or(Error::NoCommittee { slot, index })
            })
            .collect()
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




    /// Get the Beacon committee for the given `slot` and `index`.
    ///
    /// Return `None` if the cache is uninitialized, or the `slot` or `index` is out of range.
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Option<BeaconCommittee<'_>> {
        if self.initialized_epoch.is_none()
            || !self.is_initialized_at(slot.epoch(self.slots_per_epoch))
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
    (slot.as_usize() % slots_per_epoch) * committees_per_slot + committee_index
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