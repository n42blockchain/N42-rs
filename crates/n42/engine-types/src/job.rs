use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};
use std::time::Duration;
use alloy_eips::merge::SLOT_DURATION;
use alloy_primitives::Bytes;
use futures_core::ready;
use futures_util::FutureExt;
use reth_provider::StateProviderFactory;
use reth_payload_builder::{KeepPayloadJobAlive, PayloadJob};
use tokio::sync::oneshot;
use tokio::time::{Interval, Sleep};
use tracing::{debug, trace};
use reth_primitives::constants::RETH_CLIENT_VERSION;

use reth_payload_primitives::{
    BuiltPayload, PayloadBuilderAttributes, PayloadBuilderError, PayloadKind,
};
use reth::revm::cached::CachedReads;
use reth::tasks::TaskSpawner;
use reth_transaction_pool::TransactionPool;
use crate::job_generator::{BuildArguments, BuildOutcome, MissingPayloadBehaviour, N42PayloadJobGenerator, PayloadBuilder, PayloadConfig, PayloadState, PayloadTaskGuard, PendingPayload, ResolveBestPayload};
use crate::metrics::PayloadBuilderMetrics;


/// A future that resolves to the result of the block building job.
#[derive(Debug)]
pub struct PendingPayload<P> {
    /// The marker to cancel the job on drop
    _cancel: Cancelled,
    /// The channel to send the result to.
    payload: oneshot::Receiver<Result<BuildOutcome<P>, PayloadBuilderError>>,
}

impl<P> PendingPayload<P> {
    /// Constructs a `PendingPayload` future.
    pub const fn new(
        cancel: Cancelled,
        payload: oneshot::Receiver<Result<BuildOutcome<P>, PayloadBuilderError>>,
    ) -> Self {
        Self { _cancel: cancel, payload }
    }
}

impl<P> Future for PendingPayload<P> {
    type Output = Result<BuildOutcome<P>, PayloadBuilderError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let res = ready!(self.payload.poll_unpin(cx));
        Poll::Ready(res.map_err(Into::into).and_then(|res| res))
    }
}

/// A marker that can be used to cancel a job.
///
/// If dropped, it will set the `cancelled` flag to true.
#[derive(Default, Clone, Debug)]
pub struct Cancelled(Arc<AtomicBool>);

// === impl Cancelled ===

impl Cancelled {
    /// Returns true if the job was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Settings for the [`N42PayloadJobGenerator`].
#[derive(Debug, Clone)]
pub struct N42PayloadJobGeneratorConfig {
    /// Data to include in the block's extra data field.
    extradata: Bytes,
    /// The interval at which the job should build a new payload after the last.
    pub(crate) interval: Duration,
    /// The deadline for when the payload builder job should resolve.
    ///
    /// By default this is [`SLOT_DURATION`]: 12s
    pub(crate) deadline: Duration,
    /// Maximum number of tasks to spawn for building a payload.
    pub(crate) max_payload_tasks: usize,
}

// === impl BasicPayloadJobGeneratorConfig ===

impl N42PayloadJobGeneratorConfig {
    /// Sets the interval at which the job should build a new payload after the last.
    pub const fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Sets the deadline when this job should resolve.
    pub const fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Sets the maximum number of tasks to spawn for building a payload(s).
    ///
    /// # Panics
    ///
    /// If `max_payload_tasks` is 0.
    pub fn max_payload_tasks(mut self, max_payload_tasks: usize) -> Self {
        assert!(max_payload_tasks > 0, "max_payload_tasks must be greater than 0");
        self.max_payload_tasks = max_payload_tasks;
        self
    }

    /// Sets the data to include in the block's extra data field.
    ///
    /// Defaults to the current client version: `rlp(RETH_CLIENT_VERSION)`.
    pub fn extradata(mut self, extradata: Bytes) -> Self {
        self.extradata = extradata;
        self
    }
}

impl Default for N42PayloadJobGeneratorConfig {
    fn default() -> Self {
        Self {
            extradata: alloy_rlp::encode(RETH_CLIENT_VERSION.as_bytes()).into(),
            interval: Duration::from_secs(1),
            // 12s slot time
            deadline: SLOT_DURATION,
            max_payload_tasks: 3,
        }
    }
}

/// A basic payload job that continuously builds a payload with the best transactions from the pool.
#[derive(Debug)]
pub struct N42PayloadJob<Client, Pool, Tasks, Builder>
where
    Builder: PayloadBuilder<Pool, Client>,
{
    /// The configuration for how the payload will be created.
    pub(crate) config: PayloadConfig<Builder::Attributes>,
    /// The client that can interact with the chain.
    pub(crate) client: Client,
    /// The transaction pool.
    pub(crate) pool: Pool,
    /// How to spawn building tasks
    pub(crate) executor: Tasks,
    /// The deadline when this job should resolve.
    pub(crate) deadline: Pin<Box<Sleep>>,
    /// The interval at which the job should build a new payload after the last.
    pub(crate) interval: Interval,
    /// The best payload so far and its state.
    pub(crate) best_payload: PayloadState<Builder::BuiltPayload>,
    /// Receiver for the block that is currently being built.
    pub(crate) pending_block: Option<PendingPayload<Builder::BuiltPayload>>,
    /// Restricts how many generator tasks can be executed at once.
    pub(crate) payload_task_guard: PayloadTaskGuard,
    /// Caches all disk reads for the state the new payloads builds on
    ///
    /// This is used to avoid reading the same state over and over again when new attempts are
    /// triggered, because during the building process we'll repeatedly execute the transactions.
    pub(crate) cached_reads: Option<CachedReads>,
    /// metrics for this type
    pub(crate) metrics: PayloadBuilderMetrics,
    /// The type responsible for building payloads.
    ///
    /// See [`PayloadBuilder`]
    pub(crate) builder: Builder,
}

impl<Client, Pool, Tasks, Builder> N42PayloadJob<Client, Pool, Tasks, Builder>
where
    Client: StateProviderFactory + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Tasks: TaskSpawner + Clone + 'static,
    Builder: PayloadBuilder<Pool, Client> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client>>::BuiltPayload: Unpin + Clone,
{
    /// Spawns a new payload build task.
    pub(crate) fn spawn_build_job(&mut self) {
        trace!(target: "payload_builder", id = %self.config.payload_id(), "spawn new payload build task");
        let (tx, rx) = oneshot::channel();
        let client = self.client.clone();
        let pool = self.pool.clone();
        let cancel = Cancelled::default();
        let _cancel = cancel.clone();
        let guard = self.payload_task_guard.clone();
        let payload_config = self.config.clone();
        let best_payload = self.best_payload.payload().cloned();
        self.metrics.inc_initiated_payload_builds();
        let cached_reads = self.cached_reads.take().unwrap_or_default();
        let builder = self.builder.clone();
        self.executor.spawn_blocking(Box::pin(async move {
            // acquire the permit for executing the task
            let _permit = guard.acquire().await;
            let args = BuildArguments {
                client,
                pool,
                cached_reads,
                config: payload_config,
                cancel,
                best_payload,
            };
            let result = builder.try_build(args);
            let _ = tx.send(result);
        }));

        self.pending_block = Some(PendingPayload { _cancel, payload: rx });
    }
}

impl<Client, Pool, Tasks, Builder> Future for N42PayloadJob<Client, Pool, Tasks, Builder>
where
    Client: StateProviderFactory + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Tasks: TaskSpawner + Clone + 'static,
    Builder: PayloadBuilder<Pool, Client> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client>>::BuiltPayload: Unpin + Clone,
{
    type Output = Result<(), PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // check if the deadline is reached
        if this.deadline.as_mut().poll(cx).is_ready() {
            trace!(target: "payload_builder", "payload building deadline reached");
            return Poll::Ready(Ok(()))
        }

        // check if the interval is reached
        while this.interval.poll_tick(cx).is_ready() {
            // start a new job if there is no pending block, we haven't reached the deadline,
            // and the payload isn't frozen
            if this.pending_block.is_none() && !this.best_payload.is_frozen() {
                this.spawn_build_job();
            }
        }

        // poll the pending block
        if let Some(mut fut) = this.pending_block.take() {
            match fut.poll_unpin(cx) {
                Poll::Ready(Ok(outcome)) => match outcome {
                    BuildOutcome::Better { payload, cached_reads } => {
                        this.cached_reads = Some(cached_reads);
                        debug!(target: "payload_builder", value = %payload.fees(), "built better payload");
                        this.best_payload = PayloadState::Best(payload);
                    }
                    BuildOutcome::Freeze(payload) => {
                        debug!(target: "payload_builder", "payload frozen, no further building will occur");
                        this.best_payload = PayloadState::Frozen(payload);
                    }
                    BuildOutcome::Aborted { fees, cached_reads } => {
                        this.cached_reads = Some(cached_reads);
                        trace!(target: "payload_builder", worse_fees = %fees, "skipped payload build of worse block");
                    }
                    BuildOutcome::Cancelled => {
                        unreachable!("the cancel signal never fired")
                    }
                },
                Poll::Ready(Err(error)) => {
                    // job failed, but we simply try again next interval
                    debug!(target: "payload_builder", %error, "payload build attempt failed");
                    this.metrics.inc_failed_payload_builds();
                }
                Poll::Pending => {
                    this.pending_block = Some(fut);
                }
            }
        }

        Poll::Pending
    }
}

impl<Client, Pool, Tasks, Builder> PayloadJob for N42PayloadJob<Client, Pool, Tasks, Builder>
where
    Client: StateProviderFactory + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Tasks: TaskSpawner + Clone + 'static,
    Builder: PayloadBuilder<Pool, Client> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client>>::BuiltPayload: Unpin + Clone,
{
    type PayloadAttributes = Builder::Attributes;
    type ResolvePayloadFuture = ResolveBestPayload<Self::BuiltPayload>;
    type BuiltPayload = Builder::BuiltPayload;

    fn best_payload(&self) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        if let Some(payload) = self.best_payload.payload() {
            Ok(payload.clone())
        } else {
            // No payload has been built yet, but we need to return something that the CL then
            // can deliver, so we need to return an empty payload.
            //
            // Note: it is assumed that this is unlikely to happen, as the payload job is
            // started right away and the first full block should have been
            // built by the time CL is requesting the payload.
            self.metrics.inc_requested_empty_payload();
            self.builder.build_empty_payload(&self.client, self.config.clone())
        }
    }

    fn payload_attributes(&self) -> Result<Self::PayloadAttributes, PayloadBuilderError> {
        Ok(self.config.attributes.clone())
    }

    fn resolve_kind(
        &mut self,
        kind: PayloadKind,
    ) -> (Self::ResolvePayloadFuture, KeepPayloadJobAlive) {
        let best_payload = self.best_payload.payload().cloned();
        if best_payload.is_none() && self.pending_block.is_none() {
            // ensure we have a job scheduled if we don't have a best payload yet and none is active
            self.spawn_build_job();
        }

        let maybe_better = self.pending_block.take();
        let mut empty_payload = None;

        if best_payload.is_none() {
            debug!(target: "payload_builder", id=%self.config.payload_id(), "no best payload yet to resolve, building empty payload");

            let args = BuildArguments {
                client: self.client.clone(),
                pool: self.pool.clone(),
                cached_reads: self.cached_reads.take().unwrap_or_default(),
                config: self.config.clone(),
                cancel: Cancelled::default(),
                best_payload: None,
            };

            match self.builder.on_missing_payload(args) {
                MissingPayloadBehaviour::AwaitInProgress => {
                    debug!(target: "payload_builder", id=%self.config.payload_id(), "awaiting in progress payload build job");
                }
                MissingPayloadBehaviour::RaceEmptyPayload => {
                    debug!(target: "payload_builder", id=%self.config.payload_id(), "racing empty payload");

                    // if no payload has been built yet
                    self.metrics.inc_requested_empty_payload();
                    // no payload built yet, so we need to return an empty payload
                    let (tx, rx) = oneshot::channel();
                    let client = self.client.clone();
                    let config = self.config.clone();
                    let builder = self.builder.clone();
                    self.executor.spawn_blocking(Box::pin(async move {
                        let res = builder.build_empty_payload(&client, config);
                        let _ = tx.send(res);
                    }));

                    empty_payload = Some(rx);
                }
                MissingPayloadBehaviour::RacePayload(job) => {
                    debug!(target: "payload_builder", id=%self.config.payload_id(), "racing fallback payload");
                    // race the in progress job with this job
                    let (tx, rx) = oneshot::channel();
                    self.executor.spawn_blocking(Box::pin(async move {
                        let _ = tx.send(job());
                    }));
                    empty_payload = Some(rx);
                }
            };
        }

        let fut = ResolveBestPayload {
            best_payload,
            maybe_better,
            empty_payload: empty_payload.filter(|_| kind != PayloadKind::WaitForPending),
        };

        (fut, KeepPayloadJobAlive::No)
    }
}
