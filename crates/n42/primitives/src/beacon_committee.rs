// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::*;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct BeaconCommittee<'a> {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: &'a [usize],
}

impl BeaconCommittee<'_> {
    pub fn into_owned(self) -> OwnedBeaconCommittee {
        OwnedBeaconCommittee {
            slot: self.slot,
            index: self.index,
            committee: self.committee.to_vec(),
        }
    }
}

#[derive(arbitrary::Arbitrary, Default, Clone, Debug, PartialEq)]
pub struct OwnedBeaconCommittee {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: Vec<usize>,
}
