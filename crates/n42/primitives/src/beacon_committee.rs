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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_owned_copies_the_committee_slice() {
        let members = vec![4usize, 8, 15];
        let c = BeaconCommittee {
            slot: 12,
            index: 2,
            committee: &members,
        };
        let owned = c.into_owned();
        assert_eq!(owned.slot, 12);
        assert_eq!(owned.index, 2);
        assert_eq!(owned.committee, members);
        assert!(BeaconCommittee::default().into_owned().committee.is_empty());
    }
}
