// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//use crate::{ChainSpec, Epoch, Validator};
use crate::{ChainSpec, Epoch, Validator};
use std::collections::BTreeSet;

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
    /// Check if `validator` could be eligible for activation in the next epoch and add them to
    /// the tentative activation queue if this is the case.
    pub fn add_if_could_be_eligible_for_activation(
        &mut self,
        index: usize,
        validator: &Validator,
        next_epoch: Epoch,
        spec: &ChainSpec,
    ) {
        if validator.could_be_eligible_for_activation_at(next_epoch, spec) {
            self.queue
                .insert((validator.activation_eligibility_epoch, index));
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_chain_spec;

    fn validator(eligibility: Epoch, activation: Epoch) -> Validator {
        Validator {
            activation_eligibility_epoch: eligibility,
            activation_epoch: activation,
            ..Validator::default()
        }
    }

    #[test]
    fn only_not_yet_activated_and_eligible_validators_are_queued() {
        let spec = beacon_chain_spec();
        let far = spec.far_future_epoch;
        let mut q = ActivationQueue::default();

        // Eligible: not activated, eligibility epoch strictly below next_epoch.
        q.add_if_could_be_eligible_for_activation(0, &validator(2, far), 5, &spec);
        // Already activated.
        q.add_if_could_be_eligible_for_activation(1, &validator(2, 3), 5, &spec);
        // Eligibility epoch equal to next_epoch is not enough (strictly less is required).
        q.add_if_could_be_eligible_for_activation(2, &validator(5, far), 5, &spec);
        // Never became eligible (far future eligibility).
        q.add_if_could_be_eligible_for_activation(3, &validator(far, far), 5, &spec);

        let all = q.get_validators_eligible_for_activation(u64::MAX, usize::MAX);
        assert_eq!(all.into_iter().collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn dequeue_respects_finalized_epoch_and_churn_limit() {
        let spec = beacon_chain_spec();
        let far = spec.far_future_epoch;
        let mut q = ActivationQueue::default();
        // Queue ordering is by (eligibility epoch, index).
        q.add_if_could_be_eligible_for_activation(7, &validator(1, far), 10, &spec);
        q.add_if_could_be_eligible_for_activation(3, &validator(1, far), 10, &spec);
        q.add_if_could_be_eligible_for_activation(5, &validator(4, far), 10, &spec);
        q.add_if_could_be_eligible_for_activation(1, &validator(6, far), 10, &spec);

        // Finalized epoch 1 only admits the two epoch-1 entries.
        let got: Vec<_> = q.get_validators_eligible_for_activation(1, 10).into_iter().collect();
        assert_eq!(got, vec![3, 7]);

        // The churn limit truncates in (epoch, index) order, so index 3 wins over index 7.
        let got: Vec<_> = q.get_validators_eligible_for_activation(10, 1).into_iter().collect();
        assert_eq!(got, vec![3]);
        let got: Vec<_> = q.get_validators_eligible_for_activation(10, 3).into_iter().collect();
        assert_eq!(got, vec![3, 5, 7]);

        // Nothing finalized yet, or zero churn: nothing activates.
        assert!(q.get_validators_eligible_for_activation(0, 10).is_empty());
        assert!(q.get_validators_eligible_for_activation(10, 0).is_empty());
    }
}
