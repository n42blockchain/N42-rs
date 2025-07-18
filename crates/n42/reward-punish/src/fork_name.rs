use std::fmt;
use std::fmt::{Display, Formatter};
use ssz_derive::{Decode, Encode};
use serde::{Deserialize, Serialize};
#[derive(
    Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash
)]
// #[serde(try_from = "String")]
// #[serde(into = "String")]
#[ssz(enum_behaviour = "tag")]
pub enum ForkName {
    Base,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
}

impl Display for ForkName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ForkName::Base => "phase0".fmt(f),
            ForkName::Altair => "altair".fmt(f),
            ForkName::Bellatrix => "bellatrix".fmt(f),
            ForkName::Capella => "capella".fmt(f),
            ForkName::Deneb => "deneb".fmt(f),
            ForkName::Electra => "electra".fmt(f),
            ForkName::Fulu => "fulu".fmt(f),
        }
    }
}

impl From<ForkName> for String {
    fn from(fork: ForkName) -> String {
        fork.to_string()
    }
}





#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InconsistentFork {
    pub fork_at_slot: ForkName,
    pub object_fork: ForkName,
}



