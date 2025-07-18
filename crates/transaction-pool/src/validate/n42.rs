//! N42 transaction validator.

use super::constants::DEFAULT_MAX_TX_INPUT_BYTES;
use crate::{
    blobstore::BlobStore,
    error::{
        Eip4844PoolTransactionError, Eip7702PoolTransactionError, InvalidPoolTransactionError,
    },
    metrics::TxPoolValidationMetrics,
    traits::TransactionOrigin,
    validate::{ValidTransaction, ValidationTask, MAX_INIT_CODE_BYTE_SIZE},
    EthBlobTransactionSidecar, EthPoolTransaction, LocalTransactionConfig,
    TransactionValidationOutcome, TransactionValidationTaskExecutor, TransactionValidator,
};
use alloy_consensus::{
    constants::{
        EIP1559_TX_TYPE_ID, EIP2930_TX_TYPE_ID, EIP4844_TX_TYPE_ID, EIP7702_TX_TYPE_ID,
        LEGACY_TX_TYPE_ID,
    },
    BlockHeader,
};
use alloy_eips::{
    eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M, eip4844::env_settings::EnvKzgSettings,
    eip7840::BlobParams,
};
use alloy_primitives::{address, Address};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_primitives_traits::{
    transaction::error::InvalidTransactionError, Block, GotExpected, SealedBlock,
};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_tasks::TaskSpawner;
use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc,
    },
    time::Instant,
};
use tokio::sync::Mutex;

// Import the fork tracker from eth module
use super::eth::{ensure_intrinsic_gas, ForkTracker};

/// Whitelist check function
pub fn is_on_the_whitelist(addr: &Address) -> bool {
    true
}

/// Staking contract address
const STAKING_CONTRACT: Address = address!("1234567890abcdef1234567890abcdef12345678");

/// Validator for N42 transactions.
/// It is a [`TransactionValidator`] implementation that validates N42 transaction.
/// Similar to EthTransactionValidator but with special handling for whitelisted addresses
/// sending to staking contract.
#[derive(Debug, Clone)]
pub struct N42TransactionValidator<Client, T> {
    /// The type that performs the actual validation.
    inner: Arc<N42TransactionValidatorInner<Client, T>>,
}

impl<Client, Tx> N42TransactionValidator<Client, Tx> {
    /// Returns the configured chain spec
    pub fn chain_spec(&self) -> Arc<Client::ChainSpec>
    where
        Client: ChainSpecProvider,
    {
        self.client().chain_spec()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        &self.inner.client
    }
}

impl<Client, Tx> N42TransactionValidator<Client, Tx>
where
    Client: ChainSpecProvider<ChainSpec: EthereumHardforks> + StateProviderFactory,
    Tx: EthPoolTransaction,
{
    /// Validates a single transaction.
    ///
    /// See also [`TransactionValidator::validate_transaction`]
    pub fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
    ) -> TransactionValidationOutcome<Tx> {
        self.inner.validate_one(origin, transaction)
    }

    /// Validates a single transaction with the provided state provider.
    ///
    /// This allows reusing the same provider across multiple transaction validations,
    /// which can improve performance when validating many transactions.
    ///
    /// If `state` is `None`, a new state provider will be created.
    pub fn validate_one_with_state(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
        state: &mut Option<Box<dyn StateProvider>>,
    ) -> TransactionValidationOutcome<Tx> {
        self.inner.validate_one_with_provider(origin, transaction, state)
    }

    /// Validates all given transactions.
    ///
    /// Returns all outcomes for the given transactions in the same order.
    ///
    /// See also [`Self::validate_one`]
    pub fn validate_all(
        &self,
        transactions: Vec<(TransactionOrigin, Tx)>,
    ) -> Vec<TransactionValidationOutcome<Tx>> {
        self.inner.validate_batch(transactions)
    }

    /// Validates all given transactions with origin.
    ///
    /// Returns all outcomes for the given transactions in the same order.
    ///
    /// See also [`Self::validate_one`]
    pub fn validate_all_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: Vec<Tx>,
    ) -> Vec<TransactionValidationOutcome<Tx>> {
        self.inner.validate_batch_with_origin(origin, transactions)
    }
}

impl<Client, Tx> TransactionValidator for N42TransactionValidator<Client, Tx>
where
    Client: ChainSpecProvider<ChainSpec: EthereumHardforks> + StateProviderFactory,
    Tx: EthPoolTransaction,
{
    type Transaction = Tx;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        self.validate_one(origin, transaction)
    }

    async fn validate_transactions(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        self.validate_all(transactions)
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: Vec<Self::Transaction>,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        self.validate_all_with_origin(origin, transactions)
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block.header())
    }
}

/// A [`TransactionValidator`] implementation that validates N42 transaction.
///
/// It supports all known ethereum transaction types:
/// - Legacy
/// - EIP-2718
/// - EIP-1559
/// - EIP-4844
/// - EIP-7702
///
/// And enforces additional constraints such as:
/// - Maximum transaction size
/// - Maximum gas limit
/// - Special handling for whitelisted addresses sending to staking contract
///
/// And adheres to the configured [`LocalTransactionConfig`].
#[derive(Debug)]
pub(crate) struct N42TransactionValidatorInner<Client, T> {
    /// This type fetches account info from the db
    client: Client,
    /// Blobstore used for fetching re-injected blob transactions.
    blob_store: Box<dyn BlobStore>,
    /// tracks activated forks relevant for transaction validation
    fork_tracker: ForkTracker,
    /// Fork indicator whether we are using EIP-2718 type transactions.
    eip2718: bool,
    /// Fork indicator whether we are using EIP-1559 type transactions.
    eip1559: bool,
    /// Fork indicator whether we are using EIP-4844 blob transactions.
    eip4844: bool,
    /// Fork indicator whether we are using EIP-7702 type transactions.
    eip7702: bool,
    /// The current max gas limit
    block_gas_limit: AtomicU64,
    /// The current tx fee cap limit in wei locally submitted into the pool.
    tx_fee_cap: Option<u128>,
    /// Minimum priority fee to enforce for acceptance into the pool.
    minimum_priority_fee: Option<u128>,
    /// Stores the setup and parameters needed for validating KZG proofs.
    kzg_settings: EnvKzgSettings,
    /// How to handle [`TransactionOrigin::Local`](TransactionOrigin) transactions.
    local_transactions_config: LocalTransactionConfig,
    /// Maximum size in bytes a single transaction can have in order to be accepted into the pool.
    max_tx_input_bytes: usize,
    /// Marker for the transaction type
    _marker: PhantomData<T>,
    /// Metrics for tsx pool validation
    validation_metrics: TxPoolValidationMetrics,
}

// === impl N42TransactionValidatorInner ===

impl<Client: ChainSpecProvider, Tx> N42TransactionValidatorInner<Client, Tx> {
    /// Returns the configured chain id
    pub(crate) fn chain_id(&self) -> u64 {
        self.client.chain_spec().chain().id()
    }
}

impl<Client, Tx> N42TransactionValidatorInner<Client, Tx>
where
    Client: ChainSpecProvider<ChainSpec: EthereumHardforks> + StateProviderFactory,
    Tx: EthPoolTransaction,
{
    /// Returns the configured chain spec
    fn chain_spec(&self) -> Arc<Client::ChainSpec> {
        self.client.chain_spec()
    }

    /// Validates a single transaction using an optional cached state provider.
    /// If no provider is passed, a new one will be created. This allows reusing
    /// the same provider across multiple txs.
    fn validate_one_with_provider(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
        maybe_state: &mut Option<Box<dyn StateProvider>>,
    ) -> TransactionValidationOutcome<Tx> {
        match self.validate_one_no_state(origin, transaction) {
            Ok(transaction) => {
                // stateless checks passed, pass transaction down stateful validation pipeline
                // If we don't have a state provider yet, fetch the latest state
                if maybe_state.is_none() {
                    match self.client.latest() {
                        Ok(new_state) => {
                            *maybe_state = Some(new_state);
                        }
                        Err(err) => {
                            return TransactionValidationOutcome::Error(
                                *transaction.hash(),
                                Box::new(err),
                            )
                        }
                    }
                }

                let state = maybe_state.as_deref().expect("provider is set");

                self.validate_one_against_state(origin, transaction, state)
            }
            Err(invalid_outcome) => invalid_outcome,
        }
    }

    /// Performs stateless validation on single transaction. Returns unaltered input transaction
    /// if all checks pass, so transaction can continue through to stateful validation as argument
    /// to [`validate_one_against_state`](Self::validate_one_against_state).
    fn validate_one_no_state(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
    ) -> Result<Tx, TransactionValidationOutcome<Tx>> {
        // Checks for tx_type
        match transaction.ty() {
            LEGACY_TX_TYPE_ID => {
                // Accept legacy transactions
            }
            EIP2930_TX_TYPE_ID => {
                // Accept only legacy transactions until EIP-2718/2930 activates
                if !self.eip2718 {
                    return Err(TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::Eip2930Disabled.into(),
                    ))
                }
            }
            EIP1559_TX_TYPE_ID => {
                // Reject dynamic fee transactions until EIP-1559 activates.
                if !self.eip1559 {
                    return Err(TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::Eip1559Disabled.into(),
                    ))
                }
            }
            EIP4844_TX_TYPE_ID => {
                // Reject blob transactions.
                if !self.eip4844 {
                    return Err(TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::Eip4844Disabled.into(),
                    ))
                }
            }
            EIP7702_TX_TYPE_ID => {
                // Reject EIP-7702 transactions.
                if !self.eip7702 {
                    return Err(TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::Eip7702Disabled.into(),
                    ))
                }
            }

            _ => {
                return Err(TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                ))
            }
        };

        // Reject transactions over defined size to prevent DOS attacks
        let tx_input_len = transaction.input().len();
        if tx_input_len > self.max_tx_input_bytes {
            return Err(TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::OversizedData(tx_input_len, self.max_tx_input_bytes),
            ))
        }

        // Check whether the init code size has been exceeded.
        if self.fork_tracker.is_shanghai_activated() {
            if let Err(err) = transaction.ensure_max_init_code_size(MAX_INIT_CODE_BYTE_SIZE) {
                return Err(TransactionValidationOutcome::Invalid(transaction, err))
            }
        }

        // Checks for gas limit
        let transaction_gas_limit = transaction.gas_limit();
        let block_gas_limit = self.max_gas_limit();
        if transaction_gas_limit > block_gas_limit {
            return Err(TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::ExceedsGasLimit(
                    transaction_gas_limit,
                    block_gas_limit,
                ),
            ))
        }

        // Ensure max_priority_fee_per_gas (if EIP1559) is less than max_fee_per_gas if any.
        if transaction.max_priority_fee_per_gas() > Some(transaction.max_fee_per_gas()) {
            return Err(TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::TipAboveFeeCap.into(),
            ))
        }

        // determine whether the transaction should be treated as local
        let is_local = self.local_transactions_config.is_local(origin, transaction.sender_ref());

        // Ensure max possible transaction fee doesn't exceed configured transaction fee cap.
        // Only for transactions locally submitted for acceptance into the pool.
        if is_local {
            match self.tx_fee_cap {
                Some(0) | None => {} // Skip if cap is 0 or None
                Some(tx_fee_cap_wei) => {
                    // max possible tx fee is (gas_price * gas_limit)
                    // (if EIP1559) max possible tx fee is (max_fee_per_gas * gas_limit)
                    let gas_price = transaction.max_fee_per_gas();
                    let max_tx_fee_wei = gas_price.saturating_mul(transaction.gas_limit() as u128);
                    if max_tx_fee_wei > tx_fee_cap_wei {
                        return Err(TransactionValidationOutcome::Invalid(
                            transaction,
                            InvalidPoolTransactionError::ExceedsFeeCap {
                                max_tx_fee_wei,
                                tx_fee_cap_wei,
                            },
                        ))
                    }
                }
            }
        }

        // Drop non-local transactions with a fee lower than the configured fee for acceptance into
        // the pool.
        if !is_local &&
            transaction.is_dynamic_fee() &&
            transaction.max_priority_fee_per_gas() < self.minimum_priority_fee
        {
            return Err(TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::Underpriced,
            ))
        }

        // Checks for chainid
        if let Some(chain_id) = transaction.chain_id() {
            if chain_id != self.chain_id() {
                return Err(TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::ChainIdMismatch.into(),
                ))
            }
        }

        if transaction.is_eip7702() {
            // Prague fork is required for 7702 txs
            if !self.fork_tracker.is_prague_activated() {
                return Err(TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                ))
            }

            if transaction.authorization_list().is_none_or(|l| l.is_empty()) {
                return Err(TransactionValidationOutcome::Invalid(
                    transaction,
                    Eip7702PoolTransactionError::MissingEip7702AuthorizationList.into(),
                ))
            }
        }

        if let Err(err) = ensure_intrinsic_gas(&transaction, &self.fork_tracker) {
            return Err(TransactionValidationOutcome::Invalid(transaction, err))
        }

        // light blob tx pre-checks
        if transaction.is_eip4844() {
            // Cancun fork is required for blob txs
            if !self.fork_tracker.is_cancun_activated() {
                return Err(TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::TxTypeNotSupported.into(),
                ))
            }

            let blob_count =
                transaction.blob_versioned_hashes().map(|b| b.len() as u64).unwrap_or(0);
            if blob_count == 0 {
                // no blobs
                return Err(TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::Eip4844(
                        Eip4844PoolTransactionError::NoEip4844Blobs,
                    ),
                ))
            }

            let max_blob_count = self.fork_tracker.max_blob_count();
            if blob_count > max_blob_count {
                return Err(TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::Eip4844(
                        Eip4844PoolTransactionError::TooManyEip4844Blobs {
                            have: blob_count,
                            permitted: max_blob_count,
                        },
                    ),
                ))
            }
        }

        Ok(transaction)
    }

    /// Validates a single transaction using given state provider.
    /// This is the key difference from EthTransactionValidator:
    /// Skip balance check if sender is whitelisted and recipient is staking contract.
    fn validate_one_against_state<P>(
        &self,
        origin: TransactionOrigin,
        mut transaction: Tx,
        state: P,
    ) -> TransactionValidationOutcome<Tx>
    where
        P: StateProvider,
    {
        // Use provider to get account info
        let account = match state.basic_account(transaction.sender_ref()) {
            Ok(account) => account.unwrap_or_default(),
            Err(err) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(err))
            }
        };

        // Unless Prague is active, the signer account shouldn't have bytecode.
        //
        // If Prague is active, only EIP-7702 bytecode is allowed for the sender.
        //
        // Any other case means that the account is not an EOA, and should not be able to send
        // transactions.
        if let Some(code_hash) = &account.bytecode_hash {
            let is_eip7702 = if self.fork_tracker.is_prague_activated() {
                match state.bytecode_by_hash(code_hash) {
                    Ok(bytecode) => bytecode.unwrap_or_default().is_eip7702(),
                    Err(err) => {
                        return TransactionValidationOutcome::Error(
                            *transaction.hash(),
                            Box::new(err),
                        )
                    }
                }
            } else {
                false
            };

            if !is_eip7702 {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidTransactionError::SignerAccountHasBytecode.into(),
                )
            }
        }

        let tx_nonce = transaction.nonce();

        // Checks for nonce
        if tx_nonce < account.nonce {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::NonceNotConsistent { tx: tx_nonce, state: account.nonce }
                    .into(),
            )
        }

        let cost = transaction.cost();

        let sender = transaction.sender_ref();
        let recipient = transaction.to();
        let should_skip_balance_check = is_on_the_whitelist(sender) && 
            recipient.map_or(false, |addr| addr == STAKING_CONTRACT);

        // Checks for max cost - skip if whitelisted sender to staking contract
        if !should_skip_balance_check && cost > &account.balance {
            let expected = *cost;
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::InsufficientFunds(
                    GotExpected { got: account.balance, expected }.into(),
                )
                .into(),
            )
        }

        let mut maybe_blob_sidecar = None;

        // heavy blob tx validation
        if transaction.is_eip4844() {
            // extract the blob from the transaction
            match transaction.take_blob() {
                EthBlobTransactionSidecar::None => {
                    // this should not happen
                    return TransactionValidationOutcome::Invalid(
                        transaction,
                        InvalidTransactionError::TxTypeNotSupported.into(),
                    )
                }
                EthBlobTransactionSidecar::Missing => {
                    // This can happen for re-injected blob transactions (on re-org), since the blob
                    // is stripped from the transaction and not included in a block.
                    // check if the blob is in the store, if it's included we previously validated
                    // it and inserted it
                    if matches!(self.blob_store.contains(*transaction.hash()), Ok(true)) {
                        // validated transaction is already in the store
                    } else {
                        return TransactionValidationOutcome::Invalid(
                            transaction,
                            InvalidPoolTransactionError::Eip4844(
                                Eip4844PoolTransactionError::MissingEip4844BlobSidecar,
                            ),
                        )
                    }
                }
                EthBlobTransactionSidecar::Present(blob) => {
                    let now = Instant::now();
                    // validate the blob
                    if let Err(err) = transaction.validate_blob(&blob, self.kzg_settings.get()) {
                        return TransactionValidationOutcome::Invalid(
                            transaction,
                            InvalidPoolTransactionError::Eip4844(
                                Eip4844PoolTransactionError::InvalidEip4844Blob(err),
                            ),
                        )
                    }
                    // Record the duration of successful blob validation as histogram
                    self.validation_metrics.blob_validation_duration.record(now.elapsed());
                    // store the extracted blob
                    maybe_blob_sidecar = Some(blob);
                }
            }
        }

        let authorities = transaction.authorization_list().map(|auths| {
            auths.iter().flat_map(|auth| auth.recover_authority()).collect::<Vec<_>>()
        });
        // Return the valid transaction
        TransactionValidationOutcome::Valid {
            balance: account.balance,
            state_nonce: account.nonce,
            bytecode_hash: account.bytecode_hash,
            transaction: ValidTransaction::new(transaction, maybe_blob_sidecar),
            // by this point assume all external transactions should be propagated
            propagate: match origin {
                TransactionOrigin::External => true,
                TransactionOrigin::Local => {
                    self.local_transactions_config.propagate_local_transactions
                }
                TransactionOrigin::Private => false,
            },
            authorities,
        }
    }

    /// Validates a single transaction.
    fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
    ) -> TransactionValidationOutcome<Tx> {
        let mut provider = None;
        self.validate_one_with_provider(origin, transaction, &mut provider)
    }

    /// Validates all given transactions.
    fn validate_batch(
        &self,
        transactions: Vec<(TransactionOrigin, Tx)>,
    ) -> Vec<TransactionValidationOutcome<Tx>> {
        let mut provider = None;
        transactions
            .into_iter()
            .map(|(origin, tx)| self.validate_one_with_provider(origin, tx, &mut provider))
            .collect()
    }

    /// Validates all given transactions with origin.
    fn validate_batch_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: Vec<Tx>,
    ) -> Vec<TransactionValidationOutcome<Tx>> {
        let mut provider = None;
        transactions
            .into_iter()
            .map(|tx| self.validate_one_with_provider(origin, tx, &mut provider))
            .collect()
    }

    fn on_new_head_block<T: BlockHeader>(&self, new_tip_block: &T) {
        // update all forks
        if self.chain_spec().is_cancun_active_at_timestamp(new_tip_block.timestamp()) {
            self.fork_tracker.cancun.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        if self.chain_spec().is_shanghai_active_at_timestamp(new_tip_block.timestamp()) {
            self.fork_tracker.shanghai.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        if self.chain_spec().is_prague_active_at_timestamp(new_tip_block.timestamp()) {
            self.fork_tracker.prague.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        if let Some(blob_params) =
            self.chain_spec().blob_params_at_timestamp(new_tip_block.timestamp())
        {
            self.fork_tracker
                .max_blob_count
                .store(blob_params.max_blob_count, std::sync::atomic::Ordering::Relaxed);
        }

        self.block_gas_limit.store(new_tip_block.gas_limit(), std::sync::atomic::Ordering::Relaxed);
    }

    fn max_gas_limit(&self) -> u64 {
        self.block_gas_limit.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// A builder for [`N42TransactionValidator`] and [`TransactionValidationTaskExecutor`]
#[derive(Debug)]
pub struct N42TransactionValidatorBuilder<Client> {
    client: Client,
    /// Fork indicator whether we are in the Shanghai stage.
    shanghai: bool,
    /// Fork indicator whether we are in the Cancun hardfork.
    cancun: bool,
    /// Fork indicator whether we are in the Prague hardfork.
    prague: bool,
    /// Fork indicator whether we are in the Osaka hardfork.
    osaka: bool,
    /// Max blob count at the block's timestamp.
    max_blob_count: u64,
    /// Whether using EIP-2718 type transactions is allowed
    eip2718: bool,
    /// Whether using EIP-1559 type transactions is allowed
    eip1559: bool,
    /// Whether using EIP-4844 type transactions is allowed
    eip4844: bool,
    /// Whether using EIP-7702 type transactions is allowed
    eip7702: bool,
    /// The current max gas limit
    block_gas_limit: AtomicU64,
    /// The current tx fee cap limit in wei locally submitted into the pool.
    tx_fee_cap: Option<u128>,
    /// Minimum priority fee to enforce for acceptance into the pool.
    minimum_priority_fee: Option<u128>,
    /// Determines how many additional tasks to spawn
    ///
    /// Default is 1
    additional_tasks: usize,

    /// Stores the setup and parameters needed for validating KZG proofs.
    kzg_settings: EnvKzgSettings,
    /// How to handle [`TransactionOrigin::Local`](TransactionOrigin) transactions.
    local_transactions_config: LocalTransactionConfig,
    /// Max size in bytes of a single transaction allowed
    max_tx_input_bytes: usize,
}

impl<Client> N42TransactionValidatorBuilder<Client> {
    /// Creates a new builder for the given client
    ///
    /// By default this assumes the network is on the `Cancun` hardfork and the following
    /// transactions are allowed:
    ///  - Legacy
    ///  - EIP-2718
    ///  - EIP-1559
    ///  - EIP-4844
    pub fn new(client: Client) -> Self {
        Self {
            block_gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M.into(),
            client,
            minimum_priority_fee: None,
            additional_tasks: 1,
            kzg_settings: EnvKzgSettings::Default,
            local_transactions_config: Default::default(),
            max_tx_input_bytes: DEFAULT_MAX_TX_INPUT_BYTES,
            tx_fee_cap: Some(1e18 as u128),
            // by default all transaction types are allowed
            eip2718: true,
            eip1559: true,
            eip4844: true,
            eip7702: true,

            // shanghai is activated by default
            shanghai: true,

            // cancun is activated by default
            cancun: true,

            // prague is activated by default
            prague: true,

            // osaka not yet activated
            osaka: false,

            // max blob count is prague by default
            max_blob_count: BlobParams::prague().max_blob_count,
        }
    }

    /// Disables the Cancun fork.
    pub const fn no_cancun(self) -> Self {
        self.set_cancun(false)
    }

    /// Whether to allow exemptions for local transaction exemptions.
    pub fn with_local_transactions_config(
        mut self,
        local_transactions_config: LocalTransactionConfig,
    ) -> Self {
        self.local_transactions_config = local_transactions_config;
        self
    }

    /// Set the Cancun fork.
    pub const fn set_cancun(mut self, cancun: bool) -> Self {
        self.cancun = cancun;
        self
    }

    /// Disables the Shanghai fork.
    pub const fn no_shanghai(self) -> Self {
        self.set_shanghai(false)
    }

    /// Set the Shanghai fork.
    pub const fn set_shanghai(mut self, shanghai: bool) -> Self {
        self.shanghai = shanghai;
        self
    }

    /// Disables the Prague fork.
    pub const fn no_prague(self) -> Self {
        self.set_prague(false)
    }

    /// Set the Prague fork.
    pub const fn set_prague(mut self, prague: bool) -> Self {
        self.prague = prague;
        self
    }

    /// Disables the Osaka fork.
    pub const fn no_osaka(self) -> Self {
        self.set_osaka(false)
    }

    /// Set the Osaka fork.
    pub const fn set_osaka(mut self, osaka: bool) -> Self {
        self.osaka = osaka;
        self
    }

    /// Disables the support for EIP-2718 transactions.
    pub const fn no_eip2718(self) -> Self {
        self.set_eip2718(false)
    }

    /// Set the support for EIP-2718 transactions.
    pub const fn set_eip2718(mut self, eip2718: bool) -> Self {
        self.eip2718 = eip2718;
        self
    }

    /// Disables the support for EIP-1559 transactions.
    pub const fn no_eip1559(self) -> Self {
        self.set_eip1559(false)
    }

    /// Set the support for EIP-1559 transactions.
    pub const fn set_eip1559(mut self, eip1559: bool) -> Self {
        self.eip1559 = eip1559;
        self
    }

    /// Disables the support for EIP-4844 transactions.
    pub const fn no_eip4844(self) -> Self {
        self.set_eip4844(false)
    }

    /// Set the support for EIP-4844 transactions.
    pub const fn set_eip4844(mut self, eip4844: bool) -> Self {
        self.eip4844 = eip4844;
        self
    }

    /// Sets the [`EnvKzgSettings`] to use for validating KZG proofs.
    pub fn kzg_settings(mut self, kzg_settings: EnvKzgSettings) -> Self {
        self.kzg_settings = kzg_settings;
        self
    }

    /// Sets a minimum priority fee that's enforced for acceptance into the pool.
    pub const fn with_minimum_priority_fee(mut self, minimum_priority_fee: u128) -> Self {
        self.minimum_priority_fee = Some(minimum_priority_fee);
        self
    }

    /// Sets the number of additional tasks to spawn.
    pub const fn with_additional_tasks(mut self, additional_tasks: usize) -> Self {
        self.additional_tasks = additional_tasks;
        self
    }

    /// Configures validation rules based on the head block's timestamp.
    ///
    /// For example, whether the Shanghai and Cancun hardfork is activated at launch.
    pub fn with_head_timestamp(mut self, timestamp: u64) -> Self
    where
        Client: ChainSpecProvider<ChainSpec: EthereumHardforks>,
    {
        self.shanghai = self.client.chain_spec().is_shanghai_active_at_timestamp(timestamp);
        self.cancun = self.client.chain_spec().is_cancun_active_at_timestamp(timestamp);
        self.prague = self.client.chain_spec().is_prague_active_at_timestamp(timestamp);
        self.osaka = self.client.chain_spec().is_osaka_active_at_timestamp(timestamp);
        self.max_blob_count = self
            .client
            .chain_spec()
            .blob_params_at_timestamp(timestamp)
            .unwrap_or_else(BlobParams::cancun)
            .max_blob_count;
        self
    }

    /// Sets a max size in bytes of a single transaction allowed into the pool
    pub const fn with_max_tx_input_bytes(mut self, max_tx_input_bytes: usize) -> Self {
        self.max_tx_input_bytes = max_tx_input_bytes;
        self
    }

    /// Sets the block gas limit
    ///
    /// Transactions with a gas limit greater than this will be rejected.
    pub fn set_block_gas_limit(self, block_gas_limit: u64) -> Self {
        self.block_gas_limit.store(block_gas_limit, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Sets the block gas limit
    ///
    /// Transactions with a gas limit greater than this will be rejected.
    pub const fn set_tx_fee_cap(mut self, tx_fee_cap: u128) -> Self {
        self.tx_fee_cap = Some(tx_fee_cap);
        self
    }

    /// Builds a the [`N42TransactionValidator`] without spawning validator tasks.
    pub fn build<Tx, S>(self, blob_store: S) -> N42TransactionValidator<Client, Tx>
    where
        S: BlobStore,
    {
        let Self {
            client,
            shanghai,
            cancun,
            prague,
            osaka,
            eip2718,
            eip1559,
            eip4844,
            eip7702,
            block_gas_limit,
            tx_fee_cap,
            minimum_priority_fee,
            kzg_settings,
            local_transactions_config,
            max_tx_input_bytes,
            ..
        } = self;

        // TODO: use osaka max blob count once <https://github.com/alloy-rs/alloy/pull/2427> is released
        let max_blob_count = if prague {
            BlobParams::prague().max_blob_count
        } else {
            BlobParams::cancun().max_blob_count
        };

        let fork_tracker = ForkTracker {
            shanghai: AtomicBool::new(shanghai),
            cancun: AtomicBool::new(cancun),
            prague: AtomicBool::new(prague),
            osaka: AtomicBool::new(osaka),
            max_blob_count: AtomicU64::new(max_blob_count),
        };

        let inner = N42TransactionValidatorInner {
            client,
            eip2718,
            eip1559,
            fork_tracker,
            eip4844,
            eip7702,
            block_gas_limit,
            tx_fee_cap,
            minimum_priority_fee,
            blob_store: Box::new(blob_store),
            kzg_settings,
            local_transactions_config,
            max_tx_input_bytes,
            _marker: Default::default(),
            validation_metrics: TxPoolValidationMetrics::default(),
        };

        N42TransactionValidator { inner: Arc::new(inner) }
    }

    /// Builds a [`N42TransactionValidator`] and spawns validation tasks via the
    /// [`TransactionValidationTaskExecutor`]
    ///
    /// The validator will spawn `additional_tasks` additional tasks for validation.
    ///
    /// By default this will spawn 1 additional task.
    pub fn build_with_tasks<Tx, T, S>(
        self,
        tasks: T,
        blob_store: S,
    ) -> TransactionValidationTaskExecutor<N42TransactionValidator<Client, Tx>>
    where
        T: TaskSpawner,
        S: BlobStore,
    {
        let additional_tasks = self.additional_tasks;
        let validator = self.build(blob_store);

        let (tx, task) = ValidationTask::new();

        // Spawn validation tasks, they are blocking because they perform db lookups
        for _ in 0..additional_tasks {
            let task = task.clone();
            tasks.spawn_blocking(Box::pin(async move {
                task.run().await;
            }));
        }

        // we spawn them on critical tasks because validation, especially for EIP-4844 can be quite
        // heavy
        tasks.spawn_critical_blocking(
            "transaction-validation-service",
            Box::pin(async move {
                task.run().await;
            }),
        );

        let to_validation_task = Arc::new(Mutex::new(tx));

        TransactionValidationTaskExecutor { validator, to_validation_task }
    }
}