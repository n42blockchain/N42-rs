use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

#[derive(
    Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(try_from = "String")]
#[serde(into = "String")]
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

impl ForkName {
    pub fn capella_enabled(self) -> bool {
        self >= ForkName::Capella
    }

    pub fn electra_enabled(self) -> bool {
        self >= ForkName::Electra
    }
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

impl TryFrom<String> for ForkName {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl FromStr for ForkName {
    type Err = String;

    fn from_str(fork_name: &str) -> Result<Self, String> {
        Ok(match fork_name.to_lowercase().as_ref() {
            "phase0" | "base" => ForkName::Base,
            "altair" => ForkName::Altair,
            "bellatrix" | "merge" => ForkName::Bellatrix,
            "capella" => ForkName::Capella,
            "deneb" => ForkName::Deneb,
            "electra" => ForkName::Electra,
            "fulu" => ForkName::Fulu,
            _ => return Err(format!("unknown fork name: {}", fork_name)),
        })
    }
}