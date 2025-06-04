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