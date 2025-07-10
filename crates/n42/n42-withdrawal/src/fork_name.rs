use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use alloy_primitives::private::serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use crate::Hash256;

#[derive(
    Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(try_from = "String")]
#[serde(into = "String")]
#[ssz(enum_behaviour = "tag")]
pub enum ForkName {
    Electra,
    Fulu,
}

impl ForkName {
    pub fn capella_enabled(self) -> bool {
        self >= ForkName::Electra
    }

    pub fn electra_enabled(self) -> bool {
        self >= ForkName::Electra
    }
}

impl Display for ForkName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
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
            "electra" => ForkName::Electra,
            "fulu" => ForkName::Fulu,
            _ => return Err(format!("unknown fork name: {}", fork_name)),
        })
    }
}

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, Clone, PartialEq, Default,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct ForkData {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: [u8; 4],
    pub genesis_validators_root: Hash256,
}