use alloy_primitives::Bytes;
use alloy_rlp::{RlpEncodable,  RlpDecodable};
use serde::{Deserialize, Serialize};

pub type Epoch = u64;

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct VoluntaryExit {
    pub epoch: Epoch,
    pub validator_index: u64,
}

#[derive(Debug, Clone, Hash, Default, RlpEncodable, RlpDecodable,  Serialize, Deserialize)]
pub struct VoluntaryExitWithSig {
    pub voluntary_exit: VoluntaryExit,
    pub signature: Bytes,
}
