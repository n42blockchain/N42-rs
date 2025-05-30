use alloy_primitives::{Address,
                       private::{
                           arbitrary,
                           serde::{Deserialize, Serialize}, }, };
use tree_hash_derive::TreeHash;
pub use milhouse::{interface::Interface, List, Vector};
use std::fmt::Debug;
use std::hash::Hash;
use ssz_types::typenum::Unsigned;
use ssz_types::VariableList;
use crate::Hash256;
use ssz_derive::{Decode, Encode};
use crate::error::Error;
use tree_hash::TreeHash;


pub type Withdrawals<E> = VariableList<Withdrawal, <E as EthSpec>::MaxWithdrawalsPerPayload>;

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
    const ZERO: Self;
    const ONE: Self;

    /// Safe variant of `+` that guards against overflow.
    fn safe_add(&self, other: Rhs) -> Result<Self>;
    fn safe_rem(&self, other: Rhs) -> Result<Self>;

    assign_method!(safe_add_assign, safe_add, Rhs, "+=");
    assign_method!(safe_rem_assign, safe_rem, Rhs, "%=");

}

macro_rules! impl_safe_arith {
    ($typ:ty) => {
        impl SafeArith for $typ {
            const ZERO: Self = 0;
            const ONE: Self = 1;

            #[inline]
            fn safe_add(&self, other: Self) -> Result<Self> {
                self.checked_add(other).ok_or(ArithError::Overflow)
            }

            #[inline]
            fn safe_rem(&self, other: Self) -> Result<Self> {
                self.checked_rem(other).ok_or(ArithError::DivisionByZero)
            }

        }
    };
}

impl_safe_arith!(u64);


/// Extension trait for iterators, providing a safe replacement for `sum`.
pub trait SafeArithIter<T> {
    fn safe_sum(self) -> Result<T>;
}

impl<I, T> SafeArithIter<T> for I
where
    I: Iterator<Item = T> + Sized,
    T: SafeArith,
{
    fn safe_sum(mut self) -> Result<T> {
        self.try_fold(T::ZERO, |acc, x| acc.safe_add(x))
    }
}

pub trait EthSpec:
'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq + for<'a> arbitrary::Arbitrary<'a>
{
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingPartialWithdrawalsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;


    fn max_withdrawals_per_payload() -> usize {
        Self::MaxWithdrawalsPerPayload::to_usize()
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_epoch() -> u64 {
        Self::SlotsPerEpoch::to_u64()
    }
}

// ---------------
pub trait AbstractExecPayload<E: EthSpec>:
ExecPayload<E>
+ Sized
+ From<ExecutionPayload<E>>
+ TryFrom<ExecutionPayloadHeader<E>>
{
    type Ref<'a>: ExecPayload<E>
    + Copy;
}

/// A trait representing behavior of an `ExecutionPayload` that either has a full list of transactions
/// or a transaction hash in it's place.
pub trait ExecPayload<E: EthSpec>: Debug + Clone + PartialEq + Hash + TreeHash + Send {
    fn withdrawals_root(&self) -> std::result::Result<Hash256, Error>;

}