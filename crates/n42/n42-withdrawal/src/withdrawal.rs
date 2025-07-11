use alloy_primitives::{Address, private::arbitrary, };
use tree_hash_derive::TreeHash;
pub use milhouse::{interface::Interface, List, Vector};
use std::fmt::Debug;
use std::hash::Hash;
use serde::{Deserialize, Serialize};
use ssz_types::{FixedVector, VariableList};
use ssz_types::typenum::U33;
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use crate::beacon_state::{EthSpec};
use crate::crypto::{PublicKeyBytes, SignatureBytes, BlsSignature as Signature, };
use crate::slot_epoch::{Epoch, Slot};
use crate::Hash256;

pub type Withdrawals<E> = VariableList<Withdrawal, <E as EthSpec>::MaxWithdrawalsPerPayload>;

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Withdrawal {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::address_hex")]
    pub address: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

/// Casper FFG checkpoint, used in attestations.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, Clone, Copy, PartialEq, Eq, Default, Hash,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Hash256,
}

/// The strategy to be used when validating the block's signatures.
// #[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum VerifySignatures {
    /// Validate all signatures encountered.
    True,
    /// Do not validate any signature. Use with caution.
    False,
}
impl VerifySignatures {
    pub fn is_true(self) -> bool {
        self == VerifySignatures::True
    }
}

/// A deposit to potentially become a beacon chain validator.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Deposit {
    pub proof: FixedVector<Hash256, U33>,
    pub data: DepositData,
}

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: SignatureBytes,
}
impl DepositData {
    /// Create a `DepositMessage` corresponding to this `DepositData`, for signature verification.
    ///
    /// Spec v0.12.1
    pub fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }
}

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct DepositMessage {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}
impl SignedRoot for DepositMessage {}

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct SigningData {
    pub object_root: Hash256,
    pub domain: Hash256,
}
pub trait SignedRoot: TreeHash {
    fn signing_root(&self, domain: Hash256) -> Hash256 {
        SigningData {
            object_root: self.tree_hash_root(),
            domain,
        }
            .tree_hash_root()
    }
}

/// Contains data obtained from the Eth1 chain.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub block_hash: Hash256,
}

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: Signature,
}

/// An exit voluntarily submitted a validator who wishes to withdraw.
#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    pub epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}
impl SignedRoot for VoluntaryExit {}

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct PendingDeposit {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: SignatureBytes,
    pub slot: Slot,
}

/// The strategy to be used when validating the block's signatures.
// #[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum BlockSignatureStrategy {
    /// Do not validate any signature. Use with caution.
    NoVerification,
    /// Validate each signature individually, as its object is being processed.
    VerifyIndividual,
    /// Validate only the randao reveal signature.
    VerifyRandao,
    /// Verify all signatures in bulk at the beginning of block processing.
    VerifyBulk,
}

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.

#[derive(
    arbitrary::Arbitrary, Debug, Clone, Copy, PartialEq, Default,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Fork {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub previous_version: [u8; 4],
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: [u8; 4],
    pub epoch: Epoch,
}
impl Fork {
    /// Return the fork version of the given ``epoch``.
    pub fn get_fork_version(&self, epoch: Epoch) -> [u8; 4] {
        if epoch < self.epoch {
            return self.previous_version;
        }
        self.current_version
    }
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, arbitrary::Arbitrary,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
pub struct SyncCommittee<E: EthSpec> {
    pub pubkeys: FixedVector<PublicKeyBytes, E::SyncCommitteeSize>,
    pub aggregate_pubkey: PublicKeyBytes,
}

