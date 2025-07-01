use std::cmp::Ordering;
use crate::slot_epoch::Epoch;
use crate::beacon_state::Error as BeaconStateError;
use crate::chain_spec::ChainSpec;
use crate::safe_aitrh::SafeArith;
use crate::validators::Validator;

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