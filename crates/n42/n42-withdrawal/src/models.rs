use alloy_primitives::{Address,
                       private::{
                           arbitrary,
                           serde::{Deserialize, Serialize}, }, };
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
pub use milhouse::{interface::Interface, List, Vector};
use std::fmt::Debug;
use ssz_types::typenum::Unsigned;
use ssz_types::VariableList;
use crate::Hash256;
use superstruct::superstruct;
use derivative::Derivative;


pub type ValidatorIndex = usize;
pub type Withdrawals<E> = VariableList<Withdrawal, <E as EthSpec>::MaxWithdrawalsPerPayload>;

#[superstruct(
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            Derivative,
            Debug,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            // CompareFields,
            arbitrary::Arbitrary,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
        derivative(Clone),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    map_ref_mut_into(BeaconStateRef)
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, arbitrary::Arbitrary)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconState<E>
where
    E: EthSpec,
{
    #[compare_fields(as_iter)]
    #[test_random(default)]
    pub validators: List<Validator, E::ValidatorRegistryLimit>,
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    #[compare_fields(as_iter)]
    #[test_random(default)]
    pub balances: List<u64, E::ValidatorRegistryLimit>,

    // Capella
    #[superstruct(only(Capella, Deneb, Electra, Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Capella, Deneb, Electra, Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_validator_index: u64,

    #[compare_fields(as_iter)]
    #[test_random(default)]
    #[superstruct(only(Electra, Fulu))]
    pub pending_partial_withdrawals: List<PendingPartialWithdrawal, E::PendingPartialWithdrawalsLimit>,

}

#[derive(
    arbitrary::Arbitrary, Debug, Clone, PartialEq, Eq,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Validator {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

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

#[derive(
    arbitrary::Arbitrary, Debug, PartialEq, Eq, Hash, Clone,
    Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct PendingPartialWithdrawal {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}


pub struct BeaconChain<T: BeaconChainTypes> {

}

#[derive(
    arbitrary::Arbitrary, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Epoch(#[serde(with = "serde_utils::quoted_u64")] u64);

#[derive(arbitrary::Arbitrary, PartialEq, Debug, Clone)]
pub struct ChainSpec {
    pub max_pending_partials_per_withdrawals_sweep: u64,
    pub min_activation_balance: u64,
    pub far_future_epoch: Epoch,
    pub max_validators_per_withdrawals_sweep: u64,

}


#[derive(
    arbitrary::Arbitrary, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Slot(#[serde(with = "serde_utils::quoted_u64")] u64);

pub trait BeaconChainTypes: Send + Sync + 'static {
    type EthSpec: EthSpec;
}


/// Error representing the failure of an arithmetic operation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ArithError {
    Overflow,
    DivisionByZero,
}

pub type Result<T> = std::result::Result<T, ArithError>;

macro_rules! assign_method {
    ($name:ident, $op:ident, $doc_op:expr) => {
        assign_method!($name, $op, Self, $doc_op);
    };
    ($name:ident, $op:ident, $rhs_ty:ty, $doc_op:expr) => {
        #[doc = "Safe variant of `"]
        #[doc = $doc_op]
        #[doc = "`."]
        #[inline]
        fn $name(&mut self, other: $rhs_ty) -> Result<()> {
            *self = self.$op(other)?;
            Ok(())
        }
    };
}

/// Trait providing safe arithmetic operations for built-in types.
pub trait SafeArith<Rhs = Self>: Sized + Copy {

    /// Safe variant of `+` that guards against overflow.
    fn safe_add(&self, other: Rhs) -> Result<Self>;

    assign_method!(safe_add_assign, safe_add, Rhs, "+=");

}

pub trait EthSpec:
'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq + for<'a> arbitrary::Arbitrary<'a>
{
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingPartialWithdrawalsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn max_withdrawals_per_payload() -> usize {
        Self::MaxWithdrawalsPerPayload::to_usize()
    }
}