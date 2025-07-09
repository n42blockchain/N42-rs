use std::num::NonZeroUsize;
use std::ops::Range;
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use crate::slot_epoch::Epoch;
use serde::{Deserialize, Serialize};
use ssz::{four_byte_option_impl, Decode, DecodeError, Encode};
use crate::slot_epoch::Slot;
use crate::beaconstate::CommitteeIndex;
use crate::beacon_committee::BeaconCommittee;



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

    /// Returns `true` if the cache has been initialized at the supplied `epoch`.
    ///
    /// An non-initialized cache does not provide any useful information.
    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
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


impl arbitrary::Arbitrary<'_> for CommitteeCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}