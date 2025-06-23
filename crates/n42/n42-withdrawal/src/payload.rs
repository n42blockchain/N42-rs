use std::fmt::Debug;
use std::hash::Hash;
use tree_hash::TreeHash;
use crate::Hash256;
use crate::beacon_state::{Error, EthSpec};
use std::marker::PhantomData;
use derivative::Derivative;
use serde::{Deserialize, Serialize};

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
    fn withdrawals_root(&self) -> Result<Hash256, Error>;

}

#[derive(
    Debug, Clone, Serialize, Deserialize,  Derivative,
)]
pub struct ExecutionPayload<E: EthSpec> {
    _phantom: PhantomData<E>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize,  Derivative,
)]
pub struct ExecutionPayloadHeader<E: EthSpec> {
    _phantom: PhantomData<E>,
}