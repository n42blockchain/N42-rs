use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use derivative::Derivative;
use crate::slot_epoch::Epoch;
use crate::beacon_state::Error as BeaconStateError;
use crate::chain_spec::ChainSpec;
use crate::crypto::PublicKeyBytes;
use crate::safe_aitrh::SafeArith;
use crate::validators::Validator;
use crate::Hash256;
use rpds::HashTrieMapSync as HashTrieMap;
use ssz_derive::{Decode, Encode};
use crate::error::EpochCacheError;
use serde::{Deserialize, Serialize};
use ssz::{four_byte_option_impl, Decode, DecodeError, Encode};

/// Map from exit epoch to the number of validators with that exit epoch.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ExitCache {
    /// True if the cache has been initialized.
    initialized: bool,
    /// Maximum `exit_epoch` of any validator.
    max_exit_epoch: Epoch,
    /// Number of validators known to be exiting at `max_exit_epoch`.
    max_exit_epoch_churn: u64,
}

impl ExitCache {

    /// Initialize a new cache for the given list of validators.
    pub fn new<'a, V, I>(validators: V, spec: &ChainSpec) -> Result<Self, BeaconStateError>
    where
        V: IntoIterator<Item = &'a Validator, IntoIter = I>,
        I: ExactSizeIterator + Iterator<Item = &'a Validator>,
    {
        let mut exit_cache = ExitCache {
            initialized: true,
            max_exit_epoch: Epoch::new(0),
            max_exit_epoch_churn: 0,
        };
        // Add all validators with a non-default exit epoch to the cache.
        validators
            .into_iter()
            .filter(|validator| validator.exit_epoch != spec.far_future_epoch)
            .try_for_each(|validator| exit_cache.record_validator_exit(validator.exit_epoch))?;
        Ok(exit_cache)
    }

    /// Check that the cache is initialized and return an error if it is not.
    pub fn check_initialized(&self) -> Result<(), BeaconStateError> {
        if self.initialized {
            Ok(())
        } else {
            Err(BeaconStateError::ExitCacheUninitialized)
        }
    }

    /// Record the exit epoch of a validator. Must be called only once per exiting validator.
    pub fn record_validator_exit(&mut self, exit_epoch: Epoch) -> Result<(), BeaconStateError> {
        self.check_initialized()?;
        match exit_epoch.cmp(&self.max_exit_epoch) {
            // Update churn for the current maximum epoch.
            Ordering::Equal => {
                self.max_exit_epoch_churn.safe_add_assign(1)?;
            }
            // Increase the max exit epoch, reset the churn to 1.
            Ordering::Greater => {
                self.max_exit_epoch = exit_epoch;
                self.max_exit_epoch_churn = 1;
            }
            // Older exit epochs are not relevant.
            Ordering::Less => (),
        }
        Ok(())
    }
}

impl arbitrary::Arbitrary<'_> for ExitCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

type ValidatorIndex = usize;

#[allow(clippy::len_without_is_empty)]
#[derive(Debug, PartialEq, Clone, Default)]
pub struct PubkeyCache {
    /// Maintain the number of keys added to the map. It is not sufficient to just use the
    /// HashTrieMap len, as it does not increase when duplicate keys are added. Duplicate keys are
    /// used during testing.
    len: usize,
    map: HashTrieMap<PublicKeyBytes, ValidatorIndex>,
}

impl PubkeyCache {
    /// Inserts a validator index into the map.
    ///
    /// The added index must equal the number of validators already added to the map. This ensures
    /// that an index is never skipped.
    pub fn insert(&mut self, pubkey: PublicKeyBytes, index: ValidatorIndex) -> bool {
        if index == self.len {
            self.map.insert_mut(pubkey, index);
            self.len = self
                .len
                .checked_add(1)
                .expect("map length cannot exceed usize");
            true
        } else {
            false
        }
    }

    /// Looks up a validator index's by their public key.
    pub fn get(&self, pubkey: &PublicKeyBytes) -> Option<ValidatorIndex> {
        self.map.get(pubkey).copied()
    }

    /// Returns the number of validator indices added to the map so far.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> ValidatorIndex {
        self.len
    }
}

impl arbitrary::Arbitrary<'_> for PubkeyCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

/// Cache of values which are uniquely determined at the start of an epoch.
///
/// The values are fixed with respect to the last block of the _prior_ epoch, which we refer
/// to as the "decision block". This cache is very similar to the `BeaconProposerCache` in that
/// beacon proposers are determined at exactly the same time as the values in this cache, so
/// the keys for the two caches are identical.
#[derive(Debug, PartialEq, Eq, Clone, Default, arbitrary::Arbitrary)]
pub struct EpochCache {
    inner: Option<Arc<Inner>>,
}

impl EpochCache {
    pub fn activation_queue(&self) -> Result<&ActivationQueue, EpochCacheError> {
        let inner = self
            .inner
            .as_ref()
            .ok_or(EpochCacheError::CacheNotInitialized)?;
        Ok(&inner.activation_queue)
    }
}


#[derive(Debug, PartialEq, Eq, Clone, arbitrary::Arbitrary)]
struct Inner {
    /// Unique identifier for this cache, which can be used to check its validity before use
    /// with any `BeaconState`.
    key: EpochCacheKey,
    /// Effective balance for every validator in this epoch.
    effective_balances: Vec<u64>,
    /// Base rewards for every effective balance increment (currently 0..32 ETH).
    ///
    /// Keyed by `effective_balance / effective_balance_increment`.
    base_rewards: Vec<u64>,
    /// Validator activation queue.
    activation_queue: ActivationQueue,
    /// Effective balance increment.
    effective_balance_increment: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, arbitrary::Arbitrary)]
pub struct EpochCacheKey {
    pub epoch: Epoch,
    pub decision_block_root: Hash256,
}

/// Activation queue computed during epoch processing for use in the *next* epoch.
#[derive(Debug, PartialEq, Eq, Default, Clone, arbitrary::Arbitrary)]
pub struct ActivationQueue {
    /// Validators represented by `(activation_eligibility_epoch, index)` in sorted order.
    ///
    /// These validators are not *necessarily* going to be activated. Their activation depends
    /// on how finalization is updated, and the `churn_limit`.
    queue: BTreeSet<(Epoch, usize)>,
}

impl ActivationQueue {
    /// Determine the final activation queue after accounting for finalization & the churn limit.
    pub fn get_validators_eligible_for_activation(
        &self,
        finalized_epoch: Epoch,
        churn_limit: usize,
    ) -> BTreeSet<usize> {
        self.queue
            .iter()
            .filter_map(|&(eligibility_epoch, index)| {
                (eligibility_epoch <= finalized_epoch).then_some(index)
            })
            .take(churn_limit)
            .collect()
    }
}

/// Defines the epochs relative to some epoch. Most useful when referring to the committees prior
/// to and following some epoch.
///
/// Spec v0.12.1
#[derive(Debug, PartialEq, Clone, Copy, arbitrary::Arbitrary)]
pub enum RelativeEpoch {
    /// The prior epoch.
    Previous,
    /// The current epoch.
    Current,
    /// The next epoch.
    Next,
}

impl RelativeEpoch {
    /// Returns the `epoch` that `self` refers to, with respect to the `base` epoch.
    ///
    /// Spec v0.12.1
    pub fn into_epoch(self, base: Epoch) -> Epoch {
        match self {
            // Due to saturating nature of epoch, check for current first.
            RelativeEpoch::Current => base,
            RelativeEpoch::Previous => base.saturating_sub(1u64),
            RelativeEpoch::Next => base.saturating_add(1u64),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

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
    /// Returns `true` if the cache has been initialized at the supplied `epoch`.
    ///
    /// An non-initialized cache does not provide any useful information.
    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    /// Returns the number of active validators in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }
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