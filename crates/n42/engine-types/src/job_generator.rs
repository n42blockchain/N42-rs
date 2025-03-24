//! A basic payload generator for n42.

use alloy_consensus::constants::EMPTY_WITHDRAWALS;
use alloy_eips::{BlockNumberOrTag};
use alloy_primitives::{Bytes, B256, U256};
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_evm::state_change::post_block_withdrawals_balance_increments;
use reth_payload_builder::{PayloadId, PayloadJob, PayloadJobGenerator};
use reth_payload_primitives::{
    BuiltPayload, PayloadBuilderAttributes, PayloadBuilderError,
};
use reth_primitives::{ proofs, SealedHeader, Withdrawals};
use reth_provider::{
    BlockReaderIdExt, BlockSource, CanonStateNotification, ProviderError, StateProviderFactory,
};
use reth_revm::cached::CachedReads;
use reth_tasks::TaskSpawner;
use reth_transaction_pool::TransactionPool;
use revm::{Database, State};
use std::{
    fmt,
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{oneshot, Semaphore},
    time::Sleep,
};
use tracing::{debug, warn};
use crate::job::{Cancelled, N42PayloadJob, N42PayloadJobGeneratorConfig, PendingPayload};
use crate::{
    minedblock::{MinedblockExtApiServer,MinedblockExt},
    unverifiedblock::UnverifiedBlock,
};

/// The [`PayloadJobGenerator`] that creates [`BasicPayloadJob`]s.
#[derive(Debug)]
pub struct N42PayloadJobGenerator<Client, Pool, Consensus, Tasks, Builder> {
    /// The client that can interact with the chain.
    client: Client,
    /// The transaction pool to pull transactions from.
    pool: Pool,
    /// the Consensus that prepare header and seal header
    consensus: Consensus,
    /// The task executor to spawn payload building tasks on.
    executor: Tasks,
    /// The configuration for the job generator.
    config: N42PayloadJobGeneratorConfig,
    /// Restricts how many generator tasks can be executed at once.
    payload_task_guard: PayloadTaskGuard,
    /// The type responsible for building payloads.
    ///
    /// See [`PayloadBuilder`]
    builder: Builder,
    /// Stored `cached_reads` for new payload jobs.
    pre_cached: Option<PrecachedState>,
}

// === impl BasicPayloadJobGenerator ===

impl<Client, Pool, Consensus, Tasks, Builder> N42PayloadJobGenerator<Client, Pool, Consensus, Tasks, Builder> {
    /// Creates a new [`N42PayloadJobGenerator`] with the given config and custom
    /// [`PayloadBuilder`]
    pub fn with_builder(
        client: Client,
        pool: Pool,
        consensus: Consensus,
        executor: Tasks,
        config: N42PayloadJobGeneratorConfig,
        builder: Builder,
    ) -> Self {
        Self {
            client,
            pool,
            consensus,
            executor,
            payload_task_guard: PayloadTaskGuard::new(config.max_payload_tasks),
            config,
            builder,
            pre_cached: None,
        }
    }

    /// Returns the maximum duration a job should be allowed to run.
    ///
    /// This adheres to the following specification:
    /// > Client software SHOULD stop the updating process when either a call to engine_getPayload
    /// > with the build process's payloadId is made or SECONDS_PER_SLOT (12s in the Mainnet
    /// > configuration) have passed since the point in time identified by the timestamp parameter.
    ///
    /// See also <https://github.com/ethereum/execution-apis/blob/431cf72fd3403d946ca3e3afc36b973fc87e0e89/src/engine/paris.md?plain=1#L137>
    #[inline]
    fn max_job_duration(&self, unix_timestamp: u64) -> Duration {
        let duration_until_timestamp = duration_until(unix_timestamp);

        // safety in case clocks are bad
        let duration_until_timestamp = duration_until_timestamp.min(self.config.deadline * 3);

        self.config.deadline + duration_until_timestamp
    }

    /// Returns the [Instant](tokio::time::Instant) at which the job should be terminated because it
    /// is considered timed out.
    #[inline]
    fn job_deadline(&self, unix_timestamp: u64) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.max_job_duration(unix_timestamp)
    }

    /// Returns a reference to the tasks type
    pub const fn tasks(&self) -> &Tasks {
        &self.executor
    }

    /// Returns the pre-cached reads for the given parent header if it matches the cached state's
    /// block.
    fn maybe_pre_cached(&self, parent: B256) -> Option<CachedReads> {
        self.pre_cached.as_ref().filter(|pc| pc.block == parent).map(|pc| pc.cached.clone())
    }
}

// === impl BasicPayloadJobGenerator ===

impl<Client, Pool, Consensus, Tasks, Builder> PayloadJobGenerator
for N42PayloadJobGenerator<Client, Pool, Consensus, Tasks, Builder>
where
    Client: StateProviderFactory + BlockReaderIdExt + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Consensus: reth_consensus::Consensus + Unpin + Clone + 'static,
    Tasks: TaskSpawner + Clone + Unpin + 'static,
    Builder: PayloadBuilder<Pool, Client, Consensus> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client, Consensus>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client, Consensus>>::BuiltPayload: Unpin + Clone,
{
    type Job = N42PayloadJob<Client, Pool, Consensus, Tasks, Builder>;

    fn new_payload_job(
        &self,
        attributes: <Self::Job as PayloadJob>::PayloadAttributes,
    ) -> Result<Self::Job, PayloadBuilderError> {
        let parent_block = if attributes.parent().is_zero() {
            // use latest block if parent is zero: genesis block
            self.client
                .block_by_number_or_tag(BlockNumberOrTag::Latest)?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(attributes.parent()))?
                .seal_slow()
        } else {
            let block = self
                .client
                .find_block_by_hash(attributes.parent(), BlockSource::Any)?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(attributes.parent()))?;

            // we already know the hash, so we can seal it
            block.seal(attributes.parent())
        };

        let hash = parent_block.hash();
        let parent_header = parent_block.header();
        let header = SealedHeader::new(parent_header.clone(), hash);

        let config =
            PayloadConfig::new(Arc::new(header), self.config.extradata.clone(), attributes);

        let until = self.job_deadline(config.attributes.timestamp());
        let deadline = Box::pin(tokio::time::sleep_until(until));

        let cached_reads = self.maybe_pre_cached(hash);

        let mut job = N42PayloadJob {
            config,
            client: self.client.clone(),
            pool: self.pool.clone(),
            consensus: self.consensus.clone(),
            executor: self.executor.clone(),
            deadline,
            // ticks immediately
            interval: tokio::time::interval(self.config.interval),
            best_payload: PayloadState::Missing,
            pending_block: None,
            cached_reads,
            payload_task_guard: self.payload_task_guard.clone(),
            metrics: Default::default(),
            builder: self.builder.clone(),
        };

        // start the first job right away
        job.spawn_build_job();

        Ok(job)
    }

    fn on_new_state(&mut self, new_state: CanonStateNotification) {
        let mut cached = CachedReads::default();

        // extract the state from the notification and put it into the cache
        let committed = new_state.committed();
        let new_execution_outcome = committed.execution_outcome();
        for (addr, acc) in new_execution_outcome.bundle_accounts_iter() {
            if let Some(info) = acc.info.clone() {
                // we want pre cache existing accounts and their storage
                // this only includes changed accounts and storage but is better than nothing
                let storage =
                    acc.storage.iter().map(|(key, slot)| (*key, slot.present_value)).collect();
                cached.insert_account(addr, info, storage);
            }
        }
        let minedblock_ext = MinedblockExt::instance();
        if let Ok(mut minedblock) = minedblock_ext.try_lock() {
            minedblock.set_db(cached.clone());
            minedblock.send_block(minedblock.unverifiedblock.clone()).expect("fail to send block");
            minedblock.clear_unverifiedblock();
        } else {
            println!("linyangerror");
        } 
        self.pre_cached = Some(PrecachedState { block: committed.tip().hash(), cached });
    }
}

/// Pre-filled [`CachedReads`] for a specific block.
///
/// This is extracted from the [`CanonStateNotification`] for the tip block.
#[derive(Debug, Clone)]
pub struct PrecachedState {
    /// The block for which the state is pre-cached.
    pub block: B256,
    /// Cached state for the block.
    pub cached: CachedReads,
}

/// Restricts how many generator tasks can be executed at once.
#[derive(Debug, Clone)]
pub struct PayloadTaskGuard(Arc<Semaphore>);

impl Deref for PayloadTaskGuard {
    type Target = Semaphore;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// === impl PayloadTaskGuard ===

impl PayloadTaskGuard {
    /// Constructs `Self` with a maximum task count of `max_payload_tasks`.
    pub fn new(max_payload_tasks: usize) -> Self {
        Self(Arc::new(Semaphore::new(max_payload_tasks)))
    }
}

/// Represents the current state of a payload being built.
#[derive(Debug, Clone)]
pub enum PayloadState<P> {
    /// No payload has been built yet.
    Missing,
    /// The best payload built so far, which may still be improved upon.
    Best(P),
    /// The payload is frozen and no further building should occur.
    ///
    /// Contains the final payload `P` that should be used.
    Frozen(P),
}

impl<P> PayloadState<P> {
    /// Checks if the payload is frozen.
    pub const fn is_frozen(&self) -> bool {
        matches!(self, Self::Frozen(_))
    }

    /// Returns the payload if it exists (either Best or Frozen).
    pub const fn payload(&self) -> Option<&P> {
        match self {
            Self::Missing => None,
            Self::Best(p) | Self::Frozen(p) => Some(p),
        }
    }
}

/// The future that returns the best payload to be served to the consensus layer.
///
/// This returns the payload that's supposed to be sent to the CL.
///
/// If payload has been built so far, it will return that, but it will check if there's a better
/// payload available from an in progress build job. If so it will return that.
///
/// If no payload has been built so far, it will either return an empty payload or the result of the
/// in progress build job, whatever finishes first.
#[derive(Debug)]
pub struct ResolveBestPayload<Payload> {
    /// Best payload so far.
    pub best_payload: Option<Payload>,
    /// Regular payload job that's currently running that might produce a better payload.
    pub maybe_better: Option<PendingPayload<Payload>>,
    /// The empty payload building job in progress, if any.
    pub empty_payload: Option<oneshot::Receiver<Result<Payload, PayloadBuilderError>>>,
}

impl<Payload> ResolveBestPayload<Payload> {
    const fn is_empty(&self) -> bool {
        self.best_payload.is_none() && self.maybe_better.is_none() && self.empty_payload.is_none()
    }
}

impl<Payload> Future for ResolveBestPayload<Payload>
where
    Payload: Unpin,
{
    type Output = Result<Payload, PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // check if there is a better payload before returning the best payload
        if let Some(fut) = Pin::new(&mut this.maybe_better).as_pin_mut() {
            if let Poll::Ready(res) = fut.poll(cx) {
                this.maybe_better = None;
                if let Ok(Some(payload)) = res.map(|out| out.into_payload())
                    .inspect_err(|err| warn!(target: "payload_builder", %err, "failed to resolve pending payload"))
                {
                    debug!(target: "payload_builder", "resolving better payload");
                    return Poll::Ready(Ok(payload))
                }
            }
        }

        if let Some(best) = this.best_payload.take() {
            debug!(target: "payload_builder", "resolving best payload");
            return Poll::Ready(Ok(best))
        }

        if let Some(fut) = Pin::new(&mut this.empty_payload).as_pin_mut() {
            if let Poll::Ready(res) = fut.poll(cx) {
                this.empty_payload = None;
                return match res {
                    Ok(res) => {
                        if let Err(err) = &res {
                            warn!(target: "payload_builder", %err, "failed to resolve empty payload");
                        } else {
                            debug!(target: "payload_builder", "resolving empty payload");
                        }
                        Poll::Ready(res)
                    }
                    Err(err) => Poll::Ready(Err(err.into())),
                }
            }
        }

        if this.is_empty() {
            return Poll::Ready(Err(PayloadBuilderError::MissingPayload))
        }

        Poll::Pending
    }
}


/// Static config for how to build a payload.
#[derive(Clone, Debug)]
pub struct PayloadConfig<Attributes> {
    /// The parent header.
    pub parent_header: Arc<SealedHeader>,
    /// Block extra data.
    pub extra_data: Bytes,
    /// Requested attributes for the payload.
    pub attributes: Attributes,
}

impl<Attributes> PayloadConfig<Attributes> {
    /// Returns an owned instance of the [`PayloadConfig`]'s `extra_data` bytes.
    pub fn extra_data(&self) -> Bytes {
        self.extra_data.clone()
    }
}

impl<Attributes> PayloadConfig<Attributes>
where
    Attributes: PayloadBuilderAttributes,
{
    /// Create new payload config.
    pub const fn new(
        parent_header: Arc<SealedHeader>,
        extra_data: Bytes,
        attributes: Attributes,
    ) -> Self {
        Self { parent_header, extra_data, attributes }
    }

    /// Returns the payload id.
    pub fn payload_id(&self) -> PayloadId {
        self.attributes.payload_id()
    }
}

/// The possible outcomes of a payload building attempt.
#[derive(Debug)]
pub enum BuildOutcome<Payload> {
    /// Successfully built a better block.
    Better {
        /// The new payload that was built.
        payload: Payload,
        /// The cached reads that were used to build the payload.
        cached_reads: CachedReads,
    },
    /// Aborted payload building because resulted in worse block wrt. fees.
    Aborted {
        /// The total fees associated with the attempted payload.
        fees: U256,
        /// The cached reads that were used to build the payload.
        cached_reads: CachedReads,
    },
    /// Build job was cancelled
    Cancelled,

    /// The payload is final and no further building should occur
    Freeze(Payload),
}

impl<Payload> BuildOutcome<Payload> {
    /// Consumes the type and returns the payload if the outcome is `Better`.
    pub fn into_payload(self) -> Option<Payload> {
        match self {
            Self::Better { payload, .. } => Some(payload),
            _ => None,
        }
    }

    /// Returns true if the outcome is `Better`.
    pub const fn is_better(&self) -> bool {
        matches!(self, Self::Better { .. })
    }

    /// Returns true if the outcome is `Aborted`.
    pub const fn is_aborted(&self) -> bool {
        matches!(self, Self::Aborted { .. })
    }

    /// Returns true if the outcome is `Cancelled`.
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

/// A collection of arguments used for building payloads.
///
/// This struct encapsulates the essential components and configuration required for the payload
/// building process. It holds references to the Ethereum client, transaction pool, cached reads,
/// payload configuration, cancellation status, and the best payload achieved so far.
#[derive(Debug)]
pub struct N42BuildArguments<Pool, Client, Cons, Attributes, Payload> {
    /// How to interact with the chain.
    pub client: Client,
    /// The transaction pool.
    ///
    /// Or the type that provides the transactions to build the payload.
    pub pool: Pool,
    /// the Consensus that prepare header and seal header
    pub consensus: Cons,
    /// Previously cached disk reads
    pub cached_reads: CachedReads,
    /// How to configure the payload.
    pub config: PayloadConfig<Attributes>,
    /// A marker that can be used to cancel the job.
    pub cancel: Cancelled,
    /// The best payload achieved so far.
    pub best_payload: Option<Payload>,
}

impl<Pool, Client, Cons, Attributes, Payload> N42BuildArguments<Pool, Client, Cons, Attributes, Payload> {
    /// Create new build arguments.
    pub const fn new(
        client: Client,
        pool: Pool,
        consensus: Cons,
        cached_reads: CachedReads,
        config: PayloadConfig<Attributes>,
        cancel: Cancelled,
        best_payload: Option<Payload>,
    ) -> Self {
        Self { client, pool, consensus, cached_reads, config, cancel, best_payload }
    }

    /// Maps the transaction pool to a new type.
    pub fn with_pool<P>(self, pool: P) -> N42BuildArguments<P, Client, Cons, Attributes, Payload> {
        N42BuildArguments {
            client: self.client,
            pool,
            consensus: self.consensus,
            cached_reads: self.cached_reads,
            config: self.config,
            cancel: self.cancel,
            best_payload: self.best_payload,
        }
    }

    /// Maps the transaction pool to a new type using a closure with the current pool type as input.
    pub fn map_pool<F, P>(self, f: F) -> N42BuildArguments<P, Client, Cons, Attributes, Payload>
    where
        F: FnOnce(Pool) -> P,
    {
        N42BuildArguments {
            client: self.client,
            pool: f(self.pool),
            consensus: self.consensus,
            cached_reads: self.cached_reads,
            config: self.config,
            cancel: self.cancel,
            best_payload: self.best_payload,
        }
    }
}

/// A trait for building payloads that encapsulate Ethereum transactions.
///
/// This trait provides the `try_build` method to construct a transaction payload
/// using `BuildArguments`. It returns a `Result` indicating success or a
/// `PayloadBuilderError` if building fails.
///
/// Generic parameters `Pool` and `Client` represent the transaction pool and
/// Ethereum client types.
pub trait PayloadBuilder<Pool, Client, Cons>: Send + Sync + Clone {
    /// The payload attributes type to accept for building.
    type Attributes: PayloadBuilderAttributes;
    /// The type of the built payload.
    type BuiltPayload: BuiltPayload;

    /// Tries to build a transaction payload using provided arguments.
    ///
    /// Constructs a transaction payload based on the given arguments,
    /// returning a `Result` indicating success or an error if building fails.
    ///
    /// # Arguments
    ///
    /// - `args`: Build arguments containing necessary components.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the build outcome or an error.
    fn try_build(
        &self,
        args: N42BuildArguments<Pool, Client, Cons, Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError>;

    /// Invoked when the payload job is being resolved and there is no payload yet.
    ///
    /// This can happen if the CL requests a payload before the first payload has been built.
    fn on_missing_payload(
        &self,
        _args: N42BuildArguments<Pool, Client, Cons, Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        MissingPayloadBehaviour::RaceEmptyPayload
    }

    /// Builds an empty payload without any transaction.
    fn build_empty_payload(
        &self,
        args: N42BuildArguments<Pool, Client, Cons, Self::Attributes, Self::BuiltPayload>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError>;
}

/// Tells the payload builder how to react to payload request if there's no payload available yet.
///
/// This situation can occur if the CL requests a payload before the first payload has been built.
pub enum MissingPayloadBehaviour<Payload> {
    /// Await the regular scheduled payload process.
    AwaitInProgress,
    /// Race the in progress payload process with an empty payload.
    RaceEmptyPayload,
    /// Race the in progress payload process with this job.
    RacePayload(Box<dyn FnOnce() -> Result<Payload, PayloadBuilderError> + Send>),
}

impl<Payload> fmt::Debug for MissingPayloadBehaviour<Payload> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitInProgress => write!(f, "AwaitInProgress"),
            Self::RaceEmptyPayload => {
                write!(f, "RaceEmptyPayload")
            }
            Self::RacePayload(_) => write!(f, "RacePayload"),
        }
    }
}

impl<Payload> Default for MissingPayloadBehaviour<Payload> {
    fn default() -> Self {
        Self::RaceEmptyPayload
    }
}

/// Represents the outcome of committing withdrawals to the runtime database and post state.
/// Pre-shanghai these are `None` values.
#[derive(Default, Debug)]
pub struct WithdrawalsOutcome {
    /// committed withdrawals, if any.
    pub withdrawals: Option<Withdrawals>,
    /// withdrawals root if any.
    pub withdrawals_root: Option<B256>,
}

impl WithdrawalsOutcome {
    /// No withdrawals pre shanghai
    pub const fn pre_shanghai() -> Self {
        Self { withdrawals: None, withdrawals_root: None }
    }

    /// No withdrawals
    pub fn empty() -> Self {
        Self {
            withdrawals: Some(Withdrawals::default()),
            withdrawals_root: Some(EMPTY_WITHDRAWALS),
        }
    }
}

/// Executes the withdrawals and commits them to the _runtime_ Database and `BundleState`.
///
/// Returns the withdrawals root.
///
/// Returns `None` values pre shanghai
pub fn commit_withdrawals<DB: Database<Error = ProviderError>>(
    db: &mut State<DB>,
    chain_spec: &ChainSpec,
    timestamp: u64,
    withdrawals: Withdrawals,
) -> Result<WithdrawalsOutcome, DB::Error> {
    if !chain_spec.is_shanghai_active_at_timestamp(timestamp) {
        return Ok(WithdrawalsOutcome::pre_shanghai())
    }

    if withdrawals.is_empty() {
        return Ok(WithdrawalsOutcome::empty())
    }

    let balance_increments =
        post_block_withdrawals_balance_increments(chain_spec, timestamp, &withdrawals);

    db.increment_balances(balance_increments)?;

    let withdrawals_root = proofs::calculate_withdrawals_root(&withdrawals);

    // calculate withdrawals root
    Ok(WithdrawalsOutcome {
        withdrawals: Some(withdrawals),
        withdrawals_root: Some(withdrawals_root),
    })
}

/// Checks if the new payload is better than the current best.
///
/// This compares the total fees of the blocks, higher is better.
#[inline(always)]
pub fn is_better_payload(best_payload: Option<impl BuiltPayload>, new_fees: U256) -> bool {
    if let Some(best_payload) = best_payload {
        new_fees > best_payload.fees()
    } else {
        true
    }
}

/// Returns the duration until the given unix timestamp in seconds.
///
/// Returns `Duration::ZERO` if the given timestamp is in the past.
fn duration_until(unix_timestamp_secs: u64) -> Duration {
    let unix_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let timestamp = Duration::from_secs(unix_timestamp_secs);
    timestamp.saturating_sub(unix_now)
}
