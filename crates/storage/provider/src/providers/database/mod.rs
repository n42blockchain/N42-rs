use crate::{
    providers::{state::latest::LatestStateProvider, StaticFileProvider},
    to_range,
    traits::{BlockSource, ReceiptProvider},
    BlockHashReader, BlockNumReader, BlockReader, ChainSpecProvider, DatabaseProviderFactory,
    HashedPostStateProvider, HeaderProvider, HeaderSyncGapProvider, ProviderError,
    PruneCheckpointReader, StageCheckpointReader, StateProviderBox, StaticFileProviderFactory,
    TransactionVariant, TransactionsProvider, WithdrawalsProvider,
};
use n42_primitives::{APosConfig, Snapshot};
use reth_storage_api::{SnapshotProvider, SnapshotProviderWriter};
use alloy_consensus::transaction::TransactionMeta;
use alloy_eips::{eip4895::Withdrawals, BlockHashOrNumber};
use alloy_primitives::{Address, BlockHash, BlockNumber, TxHash, TxNumber, B256, U256};
use core::fmt;
use reth_chainspec::ChainInfo;
use reth_db::{init_db, mdbx::DatabaseArguments, DatabaseEnv};
use reth_db_api::{database::Database, models::StoredBlockBodyIndices};
use reth_errors::{RethError, RethResult};
use reth_node_types::{
    BlockTy, HeaderTy, NodeTypes, NodeTypesWithDB, NodeTypesWithDBAdapter, ReceiptTy, TxTy,
};
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use reth_prune_types::{PruneCheckpoint, PruneModes, PruneSegment};
use reth_stages_types::{StageCheckpoint, StageId};
use reth_static_file_types::StaticFileSegment;
use reth_storage_api::{
    BlockBodyIndicesProvider, NodePrimitivesProvider, OmmersProvider, StateCommitmentProvider,
    TryIntoHistoricalStateProvider,
};
use reth_storage_errors::provider::ProviderResult;
use reth_trie::HashedPostState;
use reth_trie_db::StateCommitment;
use revm_database::BundleState;
use std::{
    ops::{RangeBounds, RangeInclusive},
    path::Path,
    sync::Arc,
};

use tracing::trace;

mod provider;
pub use provider::{DatabaseProvider, DatabaseProviderRO, DatabaseProviderRW};

use super::ProviderNodeTypes;

mod builder;
pub use builder::{ProviderFactoryBuilder, ReadOnlyConfig};

mod metrics;

mod chain;
pub use chain::*;

/// A common provider that fetches data from a database or static file.
///
/// This provider implements most provider or provider factory traits.
pub struct ProviderFactory<N: NodeTypesWithDB> {
    /// Database instance
    db: N::DB,
    /// Chain spec
    chain_spec: Arc<N::ChainSpec>,
    /// Static File Provider
    static_file_provider: StaticFileProvider<N::Primitives>,
    /// Optional pruning configuration
    prune_modes: PruneModes,
    /// The node storage handler.
    storage: Arc<N::Storage>,
}

impl<N: NodeTypes> ProviderFactory<NodeTypesWithDBAdapter<N, Arc<DatabaseEnv>>> {
    /// Instantiates the builder for this type
    pub fn builder() -> ProviderFactoryBuilder<N> {
        ProviderFactoryBuilder::default()
    }
}

impl<N: NodeTypesWithDB> ProviderFactory<N> {
    /// Create new database provider factory.
    pub fn new(
        db: N::DB,
        chain_spec: Arc<N::ChainSpec>,
        static_file_provider: StaticFileProvider<N::Primitives>,
    ) -> Self {
        Self {
            db,
            chain_spec,
            static_file_provider,
            prune_modes: PruneModes::none(),
            storage: Default::default(),
        }
    }

    /// Enables metrics on the static file provider.
    pub fn with_static_files_metrics(mut self) -> Self {
        self.static_file_provider = self.static_file_provider.with_metrics();
        self
    }

    /// Sets the pruning configuration for an existing [`ProviderFactory`].
    pub fn with_prune_modes(mut self, prune_modes: PruneModes) -> Self {
        self.prune_modes = prune_modes;
        self
    }

    /// Returns reference to the underlying database.
    pub const fn db_ref(&self) -> &N::DB {
        &self.db
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Consumes Self and returns DB
    pub fn into_db(self) -> N::DB {
        self.db
    }
}

impl<N: NodeTypesWithDB<DB = Arc<DatabaseEnv>>> ProviderFactory<N> {
    /// Create new database provider by passing a path. [`ProviderFactory`] will own the database
    /// instance.
    pub fn new_with_database_path<P: AsRef<Path>>(
        path: P,
        chain_spec: Arc<N::ChainSpec>,
        args: DatabaseArguments,
        static_file_provider: StaticFileProvider<N::Primitives>,
    ) -> RethResult<Self> {
        Ok(Self {
            db: Arc::new(init_db(path, args).map_err(RethError::msg)?),
            chain_spec,
            static_file_provider,
            prune_modes: PruneModes::none(),
            storage: Default::default(),
        })
    }
}

impl<N: ProviderNodeTypes> ProviderFactory<N> {
    /// Returns a provider with a created `DbTx` inside, which allows fetching data from the
    /// database using different types of providers. Example: [`HeaderProvider`]
    /// [`BlockHashReader`]. This may fail if the inner read database transaction fails to open.
    ///
    /// This sets the [`PruneModes`] to [`None`], because they should only be relevant for writing
    /// data.
    #[track_caller]
    pub fn provider(&self) -> ProviderResult<DatabaseProviderRO<N::DB, N>> {
        Ok(DatabaseProvider::new(
            self.db.tx()?,
            self.chain_spec.clone(),
            self.static_file_provider.clone(),
            self.prune_modes.clone(),
            self.storage.clone(),
        ))
    }

    /// Returns a provider with a created `DbTxMut` inside, which allows fetching and updating
    /// data from the database using different types of providers. Example: [`HeaderProvider`]
    /// [`BlockHashReader`].  This may fail if the inner read/write database transaction fails to
    /// open.
    #[track_caller]
    pub fn provider_rw(&self) -> ProviderResult<DatabaseProviderRW<N::DB, N>> {
        Ok(DatabaseProviderRW(DatabaseProvider::new_rw(
            self.db.tx_mut()?,
            self.chain_spec.clone(),
            self.static_file_provider.clone(),
            self.prune_modes.clone(),
            self.storage.clone(),
        )))
    }

    /// State provider for latest block
    #[track_caller]
    pub fn latest(&self) -> ProviderResult<StateProviderBox> {
        trace!(target: "providers::db", "Returning latest state provider");
        Ok(Box::new(LatestStateProvider::new(self.database_provider_ro()?)))
    }

    /// Storage provider for state at that given block
    pub fn history_by_block_number(
        &self,
        block_number: BlockNumber,
    ) -> ProviderResult<StateProviderBox> {
        let state_provider = self.provider()?.try_into_history_at_block(block_number)?;
        trace!(target: "providers::db", ?block_number, "Returning historical state provider for block number");
        Ok(state_provider)
    }

    /// Storage provider for state at that given block hash
    pub fn history_by_block_hash(&self, block_hash: BlockHash) -> ProviderResult<StateProviderBox> {
        let provider = self.provider()?;

        let block_number = provider
            .block_number(block_hash)?
            .ok_or(ProviderError::BlockHashNotFound(block_hash))?;

        let state_provider = provider.try_into_history_at_block(block_number)?;
        trace!(target: "providers::db", ?block_number, %block_hash, "Returning historical state provider for block hash");
        Ok(state_provider)
    }
}

impl<N: NodeTypesWithDB> NodePrimitivesProvider for ProviderFactory<N> {
    type Primitives = N::Primitives;
}

impl<N: ProviderNodeTypes> DatabaseProviderFactory for ProviderFactory<N> {
    type DB = N::DB;
    type Provider = DatabaseProvider<<N::DB as Database>::TX, N>;
    type ProviderRW = DatabaseProvider<<N::DB as Database>::TXMut, N>;

    fn database_provider_ro(&self) -> ProviderResult<Self::Provider> {
        self.provider()
    }

    fn database_provider_rw(&self) -> ProviderResult<Self::ProviderRW> {
        self.provider_rw().map(|provider| provider.0)
    }
}

impl<N: NodeTypesWithDB> StateCommitmentProvider for ProviderFactory<N> {
    type StateCommitment = N::StateCommitment;
}

impl<N: NodeTypesWithDB> StaticFileProviderFactory for ProviderFactory<N> {
    /// Returns static file provider
    fn static_file_provider(&self) -> StaticFileProvider<Self::Primitives> {
        self.static_file_provider.clone()
    }
}

impl<N: ProviderNodeTypes> HeaderSyncGapProvider for ProviderFactory<N> {
    type Header = HeaderTy<N>;
    fn local_tip_header(
        &self,
        highest_uninterrupted_block: BlockNumber,
    ) -> ProviderResult<SealedHeader<Self::Header>> {
        self.provider()?.local_tip_header(highest_uninterrupted_block)
    }
}

impl<N: ProviderNodeTypes> HeaderProvider for ProviderFactory<N> {
    type Header = HeaderTy<N>;

    fn header(&self, block_hash: &BlockHash) -> ProviderResult<Option<Self::Header>> {
        self.provider()?.header(block_hash)
    }

    fn header_by_number(&self, num: BlockNumber) -> ProviderResult<Option<Self::Header>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::Headers,
            num,
            |static_file| static_file.header_by_number(num),
            || self.provider()?.header_by_number(num),
        )
    }

    fn header_td(&self, hash: &BlockHash) -> ProviderResult<Option<U256>> {
        self.provider()?.header_td(hash)
    }

    fn header_td_by_number(&self, number: BlockNumber) -> ProviderResult<Option<U256>> {
        self.provider()?.header_td_by_number(number)
    }

    fn headers_range(
        &self,
        range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Self::Header>> {
        self.static_file_provider.get_range_with_static_file_or_database(
            StaticFileSegment::Headers,
            to_range(range),
            |static_file, range, _| static_file.headers_range(range),
            |range, _| self.provider()?.headers_range(range),
            |_| true,
        )
    }

    fn sealed_header(
        &self,
        number: BlockNumber,
    ) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::Headers,
            number,
            |static_file| static_file.sealed_header(number),
            || self.provider()?.sealed_header(number),
        )
    }

    fn sealed_headers_range(
        &self,
        range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<SealedHeader<Self::Header>>> {
        self.sealed_headers_while(range, |_| true)
    }

    fn sealed_headers_while(
        &self,
        range: impl RangeBounds<BlockNumber>,
        predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool,
    ) -> ProviderResult<Vec<SealedHeader<Self::Header>>> {
        self.static_file_provider.get_range_with_static_file_or_database(
            StaticFileSegment::Headers,
            to_range(range),
            |static_file, range, predicate| static_file.sealed_headers_while(range, predicate),
            |range, predicate| self.provider()?.sealed_headers_while(range, predicate),
            predicate,
        )
    }
}

impl<N: ProviderNodeTypes> BlockHashReader for ProviderFactory<N> {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::Headers,
            number,
            |static_file| static_file.block_hash(number),
            || self.provider()?.block_hash(number),
        )
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.static_file_provider.get_range_with_static_file_or_database(
            StaticFileSegment::Headers,
            start..end,
            |static_file, range, _| static_file.canonical_hashes_range(range.start, range.end),
            |range, _| self.provider()?.canonical_hashes_range(range.start, range.end),
            |_| true,
        )
    }
}

impl<N: ProviderNodeTypes> BlockNumReader for ProviderFactory<N> {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        self.provider()?.chain_info()
    }

    fn best_block_number(&self) -> ProviderResult<BlockNumber> {
        self.provider()?.best_block_number()
    }

    fn last_block_number(&self) -> ProviderResult<BlockNumber> {
        self.provider()?.last_block_number()
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<BlockNumber>> {
        self.provider()?.block_number(hash)
    }
}

impl<N: ProviderNodeTypes> BlockReader for ProviderFactory<N> {
    type Block = BlockTy<N>;

    fn find_block_by_hash(
        &self,
        hash: B256,
        source: BlockSource,
    ) -> ProviderResult<Option<Self::Block>> {
        self.provider()?.find_block_by_hash(hash, source)
    }

    fn block(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Self::Block>> {
        self.provider()?.block(id)
    }

    fn pending_block(&self) -> ProviderResult<Option<SealedBlock<Self::Block>>> {
        self.provider()?.pending_block()
    }

    fn pending_block_with_senders(&self) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        self.provider()?.pending_block_with_senders()
    }

    fn pending_block_and_receipts(
        &self,
    ) -> ProviderResult<Option<(SealedBlock<Self::Block>, Vec<Self::Receipt>)>> {
        self.provider()?.pending_block_and_receipts()
    }

    fn recovered_block(
        &self,
        id: BlockHashOrNumber,
        transaction_kind: TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        self.provider()?.recovered_block(id, transaction_kind)
    }

    fn sealed_block_with_senders(
        &self,
        id: BlockHashOrNumber,
        transaction_kind: TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        self.provider()?.sealed_block_with_senders(id, transaction_kind)
    }

    fn block_range(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<Vec<Self::Block>> {
        self.provider()?.block_range(range)
    }

    fn block_with_senders_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        self.provider()?.block_with_senders_range(range)
    }

    fn recovered_block_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        self.provider()?.recovered_block_range(range)
    }
}

impl<N: ProviderNodeTypes> TransactionsProvider for ProviderFactory<N> {
    type Transaction = TxTy<N>;

    fn transaction_id(&self, tx_hash: TxHash) -> ProviderResult<Option<TxNumber>> {
        self.provider()?.transaction_id(tx_hash)
    }

    fn transaction_by_id(&self, id: TxNumber) -> ProviderResult<Option<Self::Transaction>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::Transactions,
            id,
            |static_file| static_file.transaction_by_id(id),
            || self.provider()?.transaction_by_id(id),
        )
    }

    fn transaction_by_id_unhashed(
        &self,
        id: TxNumber,
    ) -> ProviderResult<Option<Self::Transaction>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::Transactions,
            id,
            |static_file| static_file.transaction_by_id_unhashed(id),
            || self.provider()?.transaction_by_id_unhashed(id),
        )
    }

    fn transaction_by_hash(&self, hash: TxHash) -> ProviderResult<Option<Self::Transaction>> {
        self.provider()?.transaction_by_hash(hash)
    }

    fn transaction_by_hash_with_meta(
        &self,
        tx_hash: TxHash,
    ) -> ProviderResult<Option<(Self::Transaction, TransactionMeta)>> {
        self.provider()?.transaction_by_hash_with_meta(tx_hash)
    }

    fn transaction_block(&self, id: TxNumber) -> ProviderResult<Option<BlockNumber>> {
        self.provider()?.transaction_block(id)
    }

    fn transactions_by_block(
        &self,
        id: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Transaction>>> {
        self.provider()?.transactions_by_block(id)
    }

    fn transactions_by_block_range(
        &self,
        range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Transaction>>> {
        self.provider()?.transactions_by_block_range(range)
    }

    fn transactions_by_tx_range(
        &self,
        range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Transaction>> {
        self.provider()?.transactions_by_tx_range(range)
    }

    fn senders_by_tx_range(
        &self,
        range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        self.provider()?.senders_by_tx_range(range)
    }

    fn transaction_sender(&self, id: TxNumber) -> ProviderResult<Option<Address>> {
        self.provider()?.transaction_sender(id)
    }
}

impl<N: ProviderNodeTypes> ReceiptProvider for ProviderFactory<N> {
    type Receipt = ReceiptTy<N>;
    fn receipt(&self, id: TxNumber) -> ProviderResult<Option<Self::Receipt>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::Receipts,
            id,
            |static_file| static_file.receipt(id),
            || self.provider()?.receipt(id),
        )
    }

    fn receipt_by_hash(&self, hash: TxHash) -> ProviderResult<Option<Self::Receipt>> {
        self.provider()?.receipt_by_hash(hash)
    }

    fn receipts_by_block(
        &self,
        block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Receipt>>> {
        self.provider()?.receipts_by_block(block)
    }

    fn receipts_by_tx_range(
        &self,
        range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Receipt>> {
        self.static_file_provider.get_range_with_static_file_or_database(
            StaticFileSegment::Receipts,
            to_range(range),
            |static_file, range, _| static_file.receipts_by_tx_range(range),
            |range, _| self.provider()?.receipts_by_tx_range(range),
            |_| true,
        )
    }
}

impl<N: ProviderNodeTypes> WithdrawalsProvider for ProviderFactory<N> {
    fn withdrawals_by_block(
        &self,
        id: BlockHashOrNumber,
        timestamp: u64,
    ) -> ProviderResult<Option<Withdrawals>> {
        self.provider()?.withdrawals_by_block(id, timestamp)
    }
}

impl<N: ProviderNodeTypes> OmmersProvider for ProviderFactory<N> {
    fn ommers(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Vec<Self::Header>>> {
        self.provider()?.ommers(id)
    }
}

impl<N: ProviderNodeTypes> BlockBodyIndicesProvider for ProviderFactory<N> {
    fn block_body_indices(
        &self,
        number: BlockNumber,
    ) -> ProviderResult<Option<StoredBlockBodyIndices>> {
        self.static_file_provider.get_with_static_file_or_database(
            StaticFileSegment::BlockMeta,
            number,
            |static_file| static_file.block_body_indices(number),
            || self.provider()?.block_body_indices(number),
        )
    }

    fn block_body_indices_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<StoredBlockBodyIndices>> {
        self.static_file_provider.get_range_with_static_file_or_database(
            StaticFileSegment::BlockMeta,
            *range.start()..*range.end() + 1,
            |static_file, range, _| {
                static_file.block_body_indices_range(range.start..=range.end.saturating_sub(1))
            },
            |range, _| {
                self.provider()?.block_body_indices_range(range.start..=range.end.saturating_sub(1))
            },
            |_| true,
        )
    }
}

impl<N: ProviderNodeTypes> StageCheckpointReader for ProviderFactory<N> {
    fn get_stage_checkpoint(&self, id: StageId) -> ProviderResult<Option<StageCheckpoint>> {
        self.provider()?.get_stage_checkpoint(id)
    }

    fn get_stage_checkpoint_progress(&self, id: StageId) -> ProviderResult<Option<Vec<u8>>> {
        self.provider()?.get_stage_checkpoint_progress(id)
    }
    fn get_all_checkpoints(&self) -> ProviderResult<Vec<(String, StageCheckpoint)>> {
        self.provider()?.get_all_checkpoints()
    }
}

impl<N: NodeTypesWithDB> ChainSpecProvider for ProviderFactory<N> {
    type ChainSpec = N::ChainSpec;

    fn chain_spec(&self) -> Arc<N::ChainSpec> {
        self.chain_spec.clone()
    }
}

impl<N: ProviderNodeTypes> PruneCheckpointReader for ProviderFactory<N> {
    fn get_prune_checkpoint(
        &self,
        segment: PruneSegment,
    ) -> ProviderResult<Option<PruneCheckpoint>> {
        self.provider()?.get_prune_checkpoint(segment)
    }

    fn get_prune_checkpoints(&self) -> ProviderResult<Vec<(PruneSegment, PruneCheckpoint)>> {
        self.provider()?.get_prune_checkpoints()
    }
}

impl<N: ProviderNodeTypes> HashedPostStateProvider for ProviderFactory<N> {
    fn hashed_post_state(&self, bundle_state: &BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<<N::StateCommitment as StateCommitment>::KeyHasher>(
            bundle_state.state(),
        )
    }
}

impl<N> fmt::Debug for ProviderFactory<N>
where
    N: NodeTypesWithDB<DB: fmt::Debug, ChainSpec: fmt::Debug, Storage: fmt::Debug>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { db, chain_spec, static_file_provider, prune_modes, storage } = self;
        f.debug_struct("ProviderFactory")
            .field("db", &db)
            .field("chain_spec", &chain_spec)
            .field("static_file_provider", &static_file_provider)
            .field("prune_modes", &prune_modes)
            .field("storage", &storage)
            .finish()
    }
}

impl<N: NodeTypesWithDB> Clone for ProviderFactory<N> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            chain_spec: self.chain_spec.clone(),
            static_file_provider: self.static_file_provider.clone(),
            prune_modes: self.prune_modes.clone(),
            storage: self.storage.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        providers::{StaticFileProvider, StaticFileWriter},
        test_utils::{blocks::TEST_BLOCK, create_test_provider_factory, MockNodeTypesWithDB},
        BlockHashReader, BlockNumReader, BlockWriter, DBProvider, HeaderSyncGapProvider,
        StorageLocation, TransactionsProvider,
    };
    use alloy_primitives::{TxNumber, B256, U256};
    use assert_matches::assert_matches;
    use rand::Rng;
    use reth_chainspec::ChainSpecBuilder;
    use reth_db::{
        mdbx::DatabaseArguments,
        test_utils::{create_test_static_files_dir, ERROR_TEMPDIR},
    };
    use reth_db_api::tables;
    use reth_primitives_traits::SignerRecoverable;
    use reth_prune_types::{PruneMode, PruneModes};
    use reth_storage_errors::provider::ProviderError;
    use reth_testing_utils::generators::{self, random_block, random_header, BlockParams};
    use std::{ops::RangeInclusive, sync::Arc};
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use n42_primitives::{BeaconState, BeaconBlock,BeaconStateChangeset,BeaconBlockChangeset,BeaconBlockBody,
        Attestation,Deposit,DepositData,Validator, ValidatorBeforeTx, ValidatorChangeset,ValidatorRevert,
        VoluntaryExit};
    use reth_storage_api::ValidatorChangeWriter;
    use reth_storage_api::ValidatorReader;
    use reth_db_api::transaction::DbTxMut;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use reth_storage_api::BeaconReader;
    use reth_storage_api::BeaconWriter;
    use std::collections::HashMap;
    use std::collections::BTreeMap;

    #[test]
    fn test_beacon_traits_comprehensive() -> ProviderResult<()> {
        let factory = create_test_provider_factory();
        
        // Prepare test data
        let mut rng = StdRng::seed_from_u64(42);
        
        // Generate test block hashes
        let mut test_hashes = Vec::new();
        for _ in 0..5 {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes);
            test_hashes.push(B256::from_slice(&bytes));
        }
        
        // Create test beacon states
        let beacon_state1 = BeaconState {
            slot: 100,
            eth1_deposit_index: 10,
            validators: BTreeMap::new(),
            balances: BTreeMap::new(),
        };
        
        let beacon_state2 = BeaconState {
            slot: 200,
            eth1_deposit_index: 20,
            validators: BTreeMap::new(),
            balances: BTreeMap::new(),
        };
        
        let beacon_state3 = BeaconState {
            slot: 300,
            eth1_deposit_index: 30,
            validators: BTreeMap::new(),
            balances: BTreeMap::new(),
        };
        
        // Create test beacon blocks
        let beacon_block1 = BeaconBlock {
            eth1_block_hash: test_hashes[0],
            state_root: test_hashes[1],
            body: BeaconBlockBody {
                attestations: vec![Attestation::default()],
                deposits: vec![Deposit {
                    proof: vec![test_hashes[2]],
                    data: DepositData {
                        pubkey: 12345,
                        withdrawal_credentials: test_hashes[3],
                        amount: 32000000000,
                        signature: 67890,
                    },
                }],
                voluntary_exits: vec![VoluntaryExit {
                    epoch: 10,
                    validator_index: 1,
                }],
            },
        };
        
        let beacon_block2 = BeaconBlock {
            eth1_block_hash: test_hashes[1],
            state_root: test_hashes[2],
            body: BeaconBlockBody::default(),
        };
        
        let beacon_block3 = BeaconBlock {
            eth1_block_hash: test_hashes[2],
            state_root: test_hashes[3],
            body: BeaconBlockBody::default(),
        };
        
        // Phase 1: Test write_beaconstate function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Add multiple beacon states
            let changeset = BeaconStateChangeset {
                beaconstates: vec![
                    (test_hashes[0], beacon_state1.clone()),
                    (test_hashes[1], beacon_state2.clone()),
                ],
            };
            
            provider_rw.write_beaconstate(changeset)?;
            provider_rw.commit()?;
        }
        
        // Phase 2: Test BeaconReader trait's get_beaconstate_by_blockhash function
        {
            let provider_ro = factory.provider()?;
            
            // Test existing beacon states
            let result1 = provider_ro.get_beaconstate_by_blockhash(test_hashes[0])?;
            assert!(result1.is_some(), "beacon state 1 should exist");
            let retrieved_state1 = result1.unwrap();
            assert_eq!(beacon_state1.slot, retrieved_state1.slot);
            assert_eq!(beacon_state1.eth1_deposit_index, retrieved_state1.eth1_deposit_index);
            
            let result2 = provider_ro.get_beaconstate_by_blockhash(test_hashes[1])?;
            assert!(result2.is_some(), "beacon state 2 should exist");
            let retrieved_state2 = result2.unwrap();
            assert_eq!(beacon_state2.slot, retrieved_state2.slot);
            assert_eq!(beacon_state2.eth1_deposit_index, retrieved_state2.eth1_deposit_index);
            
            // Test non-existing beacon state
            let result3 = provider_ro.get_beaconstate_by_blockhash(test_hashes[2])?;
            assert!(result3.is_none(), "beacon state 3 should not exist");
        }
        
        // Phase 3: Test write_beaconblock function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Add multiple beacon blocks
            let changeset = BeaconBlockChangeset {
                beaconblocks: vec![
                    (test_hashes[0], beacon_block1.clone()),
                    (test_hashes[1], beacon_block2.clone()),
                ],
            };
            
            provider_rw.write_beaconblock(changeset)?;
            provider_rw.commit()?;
        }
        
        // Phase 4: Test BeaconReader trait's get_beaconblock_by_blockhash function
        {
            let provider_ro = factory.provider()?;
            
            // Test existing beacon blocks
            let result1 = provider_ro.get_beaconblock_by_blockhash(test_hashes[0])?;
            assert!(result1.is_some(), "beacon block 1 should exist");
            let retrieved_block1 = result1.unwrap();
            assert_eq!(beacon_block1.eth1_block_hash, retrieved_block1.eth1_block_hash);
            assert_eq!(beacon_block1.state_root, retrieved_block1.state_root);
            assert_eq!(beacon_block1.body.deposits.len(), retrieved_block1.body.deposits.len());
            
            let result2 = provider_ro.get_beaconblock_by_blockhash(test_hashes[1])?;
            assert!(result2.is_some(), "beacon block 2 should exist");
            let retrieved_block2 = result2.unwrap();
            assert_eq!(beacon_block2.eth1_block_hash, retrieved_block2.eth1_block_hash);
            assert_eq!(beacon_block2.state_root, retrieved_block2.state_root);
            
            // Test non-existing beacon block
            let result3 = provider_ro.get_beaconblock_by_blockhash(test_hashes[2])?;
            assert!(result3.is_none(), "beacon block 3 should not exist");
        }
        
        // Phase 5: Add more data for removal and unwind testing
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Add third beacon state and block
            let state_changeset = BeaconStateChangeset {
                beaconstates: vec![(test_hashes[2], beacon_state3.clone())],
            };
            let block_changeset = BeaconBlockChangeset {
                beaconblocks: vec![(test_hashes[2], beacon_block3.clone())],
            };
            
            provider_rw.write_beaconstate(state_changeset)?;
            provider_rw.write_beaconblock(block_changeset)?;
            
            // Add beacon number to hash mappings for unwind testing
            provider_rw.tx_ref().put::<tables::BeaconNum2Hash>(1, test_hashes[0])?;
            provider_rw.tx_ref().put::<tables::BeaconNum2Hash>(2, test_hashes[1])?;
            provider_rw.tx_ref().put::<tables::BeaconNum2Hash>(3, test_hashes[2])?;
            
            provider_rw.commit()?;
        }
        
        // Phase 6: Test remove_beaconstate function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Remove specific beacon state
            provider_rw.remove_beaconstate(vec![test_hashes[1]])?;
            provider_rw.commit()?;
            
            // Verify removal
            let provider_ro = factory.provider()?;
            let result = provider_ro.get_beaconstate_by_blockhash(test_hashes[1])?;
            assert!(result.is_none(), "beacon state should be removed");
            
            // Verify other states still exist
            let result1 = provider_ro.get_beaconstate_by_blockhash(test_hashes[0])?;
            assert!(result1.is_some(), "beacon state 1 should still exist");
            let result3 = provider_ro.get_beaconstate_by_blockhash(test_hashes[2])?;
            assert!(result3.is_some(), "beacon state 3 should still exist");
        }
        
        // Phase 7: Test remove_beaconblock function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Remove specific beacon block
            provider_rw.remove_beaconblock(vec![test_hashes[1]])?;
            provider_rw.commit()?;
            
            // Verify removal
            let provider_ro = factory.provider()?;
            let result = provider_ro.get_beaconblock_by_blockhash(test_hashes[1])?;
            assert!(result.is_none(), "beacon block should be removed");
            
            // Verify other blocks still exist
            let result1 = provider_ro.get_beaconblock_by_blockhash(test_hashes[0])?;
            assert!(result1.is_some(), "beacon block 1 should still exist");
            let result3 = provider_ro.get_beaconblock_by_blockhash(test_hashes[2])?;
            assert!(result3.is_some(), "beacon block 3 should still exist");
        }
        
        // Phase 8: Test unwind_beacon function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Unwind blocks 2 and 3 (should remove corresponding beacon data)
            provider_rw.unwind_beacon(2..=3)?;
            provider_rw.commit()?;
            
            // Verify unwind results
            let provider_ro = factory.provider()?;
            
            // Block 1 data should still exist
            let state_result1 = provider_ro.get_beaconstate_by_blockhash(test_hashes[0])?;
            assert!(state_result1.is_some(), "beacon state 1 should still exist after unwind");
            let block_result1 = provider_ro.get_beaconblock_by_blockhash(test_hashes[0])?;
            assert!(block_result1.is_some(), "beacon block 1 should still exist after unwind");
            
            // Block 3 data should be removed (block 2 was already removed in previous tests)
            let state_result3 = provider_ro.get_beaconstate_by_blockhash(test_hashes[2])?;
            assert!(state_result3.is_none(), "beacon state 3 should be removed after unwind");
            let block_result3 = provider_ro.get_beaconblock_by_blockhash(test_hashes[2])?;
            assert!(block_result3.is_none(), "beacon block 3 should be removed after unwind");
        }
        
        // Phase 9: Test edge cases
        {
            let provider_ro = factory.provider()?;
            
            // Test with non-existent hash
            let mut non_existent_bytes = [0u8; 32];
            rng.fill(&mut non_existent_bytes);
            let non_existent_hash = B256::from_slice(&non_existent_bytes);
            
            let state_result = provider_ro.get_beaconstate_by_blockhash(non_existent_hash)?;
            assert!(state_result.is_none(), "non-existent beacon state should return None");
            
            let block_result = provider_ro.get_beaconblock_by_blockhash(non_existent_hash)?;
            assert!(block_result.is_none(), "non-existent beacon block should return None");
        }
        
        // Phase 10: Test batch operations
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Test removing multiple items at once
            let mut batch_hashes = Vec::new();
            let mut batch_states = Vec::new();
            let mut batch_blocks = Vec::new();
            
            for i in 0..3 {
                let mut bytes = [0u8; 32];
                rng.fill(&mut bytes);
                let hash = B256::from_slice(&bytes);
                batch_hashes.push(hash);
                
                let state = BeaconState {
                    slot: 400 + i as u64,
                    eth1_deposit_index: 40 + i as u64,
                    validators: BTreeMap::new(),
                    balances: BTreeMap::new(),
                };
                batch_states.push((hash, state));
                
                let block = BeaconBlock {
                    eth1_block_hash: hash,
                    state_root: hash,
                    body: BeaconBlockBody::default(),
                };
                batch_blocks.push((hash, block));
            }
            
            // Write batch data
            let state_changeset = BeaconStateChangeset {
                beaconstates: batch_states,
            };
            let block_changeset = BeaconBlockChangeset {
                beaconblocks: batch_blocks,
            };
            
            provider_rw.write_beaconstate(state_changeset)?;
            provider_rw.write_beaconblock(block_changeset)?;
            provider_rw.commit()?;
            
            // Verify batch write
            let provider_ro = factory.provider()?;
            for hash in &batch_hashes {
                let state_result = provider_ro.get_beaconstate_by_blockhash(*hash)?;
                assert!(state_result.is_some(), "batch beacon state should exist");
                
                let block_result = provider_ro.get_beaconblock_by_blockhash(*hash)?;
                assert!(block_result.is_some(), "batch beacon block should exist");
            }
            
            // Test batch removal
            let mut provider_rw = factory.provider_rw()?;
            provider_rw.remove_beaconstate(batch_hashes.clone())?;
            provider_rw.remove_beaconblock(batch_hashes.clone())?;
            provider_rw.commit()?;
            
            // Verify batch removal
            let provider_ro = factory.provider()?;
            for hash in &batch_hashes {
                let state_result = provider_ro.get_beaconstate_by_blockhash(*hash)?;
                assert!(state_result.is_none(), "batch beacon state should be removed");
                
                let block_result = provider_ro.get_beaconblock_by_blockhash(*hash)?;
                assert!(block_result.is_none(), "batch beacon block should be removed");
            }
        }
        
        println!("✅ All BeaconReader and BeaconWriter trait functions tested successfully!");
        Ok(())
    }

    #[test]
    fn test_validator_funcs() -> ProviderResult<()> {
        let factory = create_test_provider_factory();
        
        // Prepare test data
        let validator_address1 = Address::random();
        let validator_address2 = Address::random();
        let validator_address3 = Address::random();
        
        let validator1 = Validator {
            index: 1,
            balance: 32000000000,
            is_active: true,
            is_slashed: false,
            is_withdrawal_allowed: false,
        };
        
        let validator2 = Validator {
            index: 2,
            balance: 33000000000,
            is_active: true,
            is_slashed: false,
            is_withdrawal_allowed: true,
        };
        
        let validator3 = Validator {
            index: 3,
            balance: 31000000000,
            is_active: false,
            is_slashed: true,
            is_withdrawal_allowed: false,
        };
        
        // Phase 1: Test write_validator_changes function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Add multiple validators
            let mut validators = Vec::new();
            validators.push((validator_address1, Some(validator1.clone())));
            validators.push((validator_address2, Some(validator2.clone())));
            let changeset = ValidatorChangeset { validators };
            
            provider_rw.write_validator_changes(changeset)?;
            provider_rw.commit()?;
        }
        
        // Phase 2: Test basic_validator function of ValidatorReader trait
        {
            let provider_ro = factory.provider()?;
            
            // Test existing validators
            let result1 = provider_ro.basic_validator(validator_address1)?;
            assert!(result1.is_some(), "validator1 should exist");
            let retrieved_validator1 = result1.unwrap();
            assert_eq!(validator1.index, retrieved_validator1.index);
            assert_eq!(validator1.balance, retrieved_validator1.balance);
            assert_eq!(validator1.is_active, retrieved_validator1.is_active);
            
            let result2 = provider_ro.basic_validator(validator_address2)?;
            assert!(result2.is_some(), "validator2 should exist");
            let retrieved_validator2 = result2.unwrap();
            assert_eq!(validator2.index, retrieved_validator2.index);
            assert_eq!(validator2.balance, retrieved_validator2.balance);
            assert_eq!(validator2.is_withdrawal_allowed, retrieved_validator2.is_withdrawal_allowed);
            
            // Test non-existing validators
            let result3 = provider_ro.basic_validator(validator_address3)?;
            assert!(result3.is_none(), "validator3 should not exist");
        }
        
        // Phase 3: Add changeset data and test changed_validators_and_blocks_with_range
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Add change record in block 1
            provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
                1,
                ValidatorBeforeTx {
                    address: validator_address1,
                    info: None,
                }
            )?;
            
            // Add change record in block 2
            provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
                2,
                ValidatorBeforeTx {
                    address: validator_address1,
                    info: Some(validator1.clone()),
                }
            )?;
            
            provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
                2,
                ValidatorBeforeTx {
                    address: validator_address2,
                    info: None,
                }
            )?;
            
            // Add change record in block 3
            provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
                3,
                ValidatorBeforeTx {
                    address: validator_address2,
                    info: Some(validator2.clone()),
                }
            )?;
            
            provider_rw.commit()?;
        }
        
        // Test changed_validators_and_blocks_with_range function
        {
            let provider_ro = factory.provider()?;
            
            // Test block range 1..=2
            let changes_1_2 = provider_ro.changed_validators_and_blocks_with_range(1..=2)?;
            assert!(changes_1_2.contains_key(&validator_address1), "validator1 should have changes in range 1..=2");
            assert!(changes_1_2.contains_key(&validator_address2), "validator2 should have changes in range 1..=2");
            
            let validator1_blocks = &changes_1_2[&validator_address1];
            assert!(validator1_blocks.contains(&1), "validator1 should have change in block 1");
            assert!(validator1_blocks.contains(&2), "validator1 should have change in block 2");
            
            let validator2_blocks = &changes_1_2[&validator_address2];
            assert!(validator2_blocks.contains(&2), "validator2 should have change in block 2");
            
            // Test block range 3..=3
            let changes_3 = provider_ro.changed_validators_and_blocks_with_range(3..=3)?;
            assert!(changes_3.contains_key(&validator_address2), "validator2 should have changes in range 3..=3");
            assert!(!changes_3.contains_key(&validator_address1), "validator1 should not have changes in range 3..=3");
        }
        
        // Phase 4: Test insert_validator_history_index function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Prepare history index data
            let mut validator_transitions = BTreeMap::new();
            validator_transitions.insert(validator_address1, vec![1u64, 2u64]);
            validator_transitions.insert(validator_address2, vec![2u64, 3u64]);
            
            provider_rw.insert_validator_history_index(validator_transitions)?;
            provider_rw.commit()?;
        }
        
        // Phase 5: Test write_validator_reverts function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Prepare revert data
            let validator_reverts = ValidatorRevert {
                validators: vec![
                    vec![
                        (validator_address1, Some(validator1.clone())),
                        (validator_address2, None),
                    ],
                    vec![
                        (validator_address2, Some(validator2.clone())),
                    ],
                ],
            };
            
            provider_rw.write_validator_reverts(10, validator_reverts)?;
            provider_rw.commit()?;
        }
        
        // Phase 6: Test unwind_validator_history_indices function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Prepare changeset data for unwinding
            let changesets = vec![
                (1u64, ValidatorBeforeTx {
                    address: validator_address1,
                    info: None,
                }),
                (2u64, ValidatorBeforeTx {
                    address: validator_address2,
                    info: Some(validator2.clone()),
                }),
            ];
            
            let unwound_count = provider_rw.unwind_validator_history_indices(changesets.iter())?;
            assert!(unwound_count > 0, "should have unwound some indices");
            
            provider_rw.commit()?;
        }
        
        // Phase 7: Test unwind_validator function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Add third validator for unwind testing
            let mut validators = Vec::new();
            validators.push((validator_address3, Some(validator3.clone())));
            let changeset = ValidatorChangeset { validators };
            provider_rw.write_validator_changes(changeset)?;
            
            // Add changeset record
            provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
                5,
                ValidatorBeforeTx {
                    address: validator_address3,
                    info: None,
                }
            )?;
            
            provider_rw.commit()?;
            
            // Verify validator exists
            let provider_ro = factory.provider()?;
            let result = provider_ro.basic_validator(validator_address3)?;
            assert!(result.is_some(), "validator3 should exist before unwind");
            
            // Execute unwind
            let mut provider_rw = factory.provider_rw()?;
            provider_rw.unwind_validator(5..=5)?;
            provider_rw.commit()?;
            
            // Verify unwind result
            let provider_ro = factory.provider()?;
            let result = provider_ro.basic_validator(validator_address3)?;
            assert!(result.is_none(), "validator3 should not exist after unwind");
        }
        
        // Phase 8: Test remove_validator function
        {
            let mut provider_rw = factory.provider_rw()?;
            
            // Add a new validator for removal testing
            let test_validator = Validator {
                index: 99,
                balance: 1000000000,
                is_active: true,
                is_slashed: false,
                is_withdrawal_allowed: false,
            };
            
            let test_address = Address::random();
            let mut validators = Vec::new();
            validators.push((test_address, Some(test_validator.clone())));
            let changeset = ValidatorChangeset { validators };
            provider_rw.write_validator_changes(changeset)?;
            
            // 添加变更集记录
            provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
                6,
                ValidatorBeforeTx {
                    address: test_address,
                    info: None,
                }
            )?;
            
            provider_rw.commit()?;
            
            // Verify validator exists
            let provider_ro = factory.provider()?;
            let result = provider_ro.basic_validator(test_address)?;
            assert!(result.is_some(), "test validator should exist before removal");
            
            // Execute removal
            let mut provider_rw = factory.provider_rw()?;
            provider_rw.remove_validator(6..=6)?;
            provider_rw.commit()?;
            
            // Verify removal result
            let provider_ro = factory.provider()?;
            let result = provider_ro.basic_validator(test_address)?;
            assert!(result.is_none(), "test validator should not exist after removal");
        }
        
        println!("✅ All ValidatorReader and ValidatorChangeWriter trait functions tested successfully!");
        Ok(())
    }
    
    // #[test]
    // fn test_beaconstate_flow() -> ProviderResult<()> {
    //     let factory=create_test_provider_factory();
    //     let mut provider_rw=factory.provider_rw()?;
    //     let mut changes = BeaconStateChangeset { beaconstates: vec![] };
    //     let mut header_number_entries = vec![];
    //     let mut blockhash_to_number = HashMap::new();
    //     for i in 1..=5u64 {
    //         let mut bytes = [0u8; 32];
    //         bytes[24..].copy_from_slice(&i.to_be_bytes());
    //         let blockhash = B256::new(bytes);
    //         let beaconstate = BeaconState::default();
    //         changes.beaconstates.push((blockhash, beaconstate));
    //         header_number_entries.push((blockhash, i));
    //         blockhash_to_number.insert(i, blockhash);
    //     }
    //     provider_rw.write_beaconstate(changes)?;
    //     for (bh, num) in &header_number_entries {
    //         provider_rw.tx_ref().put::<tables::HeaderNumbers>(*bh, *num)?;
    //     }
    //     provider_rw.commit()?;
    //     for (_num, bh) in &blockhash_to_number {
    //         let mut provider_ro=factory.provider()?;
    //         assert!(provider_ro.get_beaconstate_by_blockhash(*bh)?.is_some());
    //     }
    //     let mut provider_rw=factory.provider_rw()?;
    //     provider_rw.unwind_beaconstate(3..=5)?;
    //     provider_rw.commit()?;
    //     let mut provider_ro=factory.provider()?;
    //     assert!(provider_ro.get_beaconstate_by_blockhash(blockhash_to_number[&3])?.is_none());
    //     assert!(provider_ro.get_beaconstate_by_blockhash(blockhash_to_number[&5])?.is_none());
    //     assert!(provider_ro.get_beaconstate_by_blockhash(blockhash_to_number[&1])?.is_some());
    //     assert!(provider_ro.get_beaconstate_by_blockhash(blockhash_to_number[&2])?.is_some());
    //     Ok(())
    // }

    #[test]
    fn test_beaconstaterecord()->ProviderResult<()>{
        let factory=create_test_provider_factory();
        let mut provider_rw=factory.provider_rw()?;
        let mut rng=StdRng::seed_from_u64(42);
        let mut blockhash=B256::ZERO;
        // let mut cursor=provider_rw.tx_mut().cursor_write::<tables::BeaconStateRecord>()?;
        for i in 0..5{
            let mut bytes=[0u8;32];
            rng.fill(&mut bytes);
            blockhash=B256::from_slice(&bytes);
            println!("{:?}",blockhash);
            let state=BeaconState::default();
            provider_rw.tx_ref().put::<tables::BeaconStateRecord>(blockhash, state)?;
        }
        provider_rw.commit()?;
        let provider_ro=factory.provider()?;
        let res=provider_ro.get_beaconstate_by_blockhash(blockhash)?;
        match res{
            Some(bs)=>println!("{:?}",bs),
            None=>println!("not found"),
        }
        Ok(())
    }

    // #[test]
    // fn test_basic_validator()->ProviderResult<()>{
    //     let factory=create_test_provider_factory();
    //     let mut provider_rw=factory.provider_rw()?;
    //     let validator_address=Address::random();
    //     let validator=Validator{
    //         index:1,
    //         balance:32000000000,
    //         is_active:true,
    //         is_slashed:false,
    //         is_withdrawal_allowed:false,
    //     };
    //     let mut validators=Vec::new();
    //     validators.push((validator_address,Some(validator.clone())));
    //     let changeset =ValidatorChangeset{validators};
    //     provider_rw.write_validator_changes(changeset)?;
    //     provider_rw.commit()?;
    //     let provider_ro=factory.provider()?;
    //     let result=provider_ro.basic_validator(validator_address)?;
    //     assert!(result.is_some(),"validator data");
    //     let retrieved_validator=result.unwrap();
    //     assert_eq!(validator.index, retrieved_validator.index);
    //     assert_eq!(validator.balance, retrieved_validator.balance);
    //     assert_eq!(validator.is_active, retrieved_validator.is_active);
    //     assert_eq!(validator.is_slashed, retrieved_validator.is_slashed);
    //     assert_eq!(validator.is_withdrawal_allowed, retrieved_validator.is_withdrawal_allowed);
    //     let non_existent_address=Address::random();
    //     let non_existent_result=provider_ro.basic_validator(non_existent_address)?;
    //     assert!(non_existent_result.is_none(),"non-existent validator data");
    //     Ok(())
    // }

    // #[test]
    // fn test_unwind_validator() -> ProviderResult<()> {
    //     let factory = create_test_provider_factory();
    //     let mut provider_rw = factory.provider_rw()?;
        
    //     let validator_address1 = Address::random();
    //     let validator_address2 = Address::random();
        
    //     let validator1 = Validator {
    //         index: 1,
    //         balance: 32000000000,
    //         is_active: true,
    //         is_slashed: false,
    //         is_withdrawal_allowed: false,
    //     };
        
    //     let validator2 = Validator {
    //         index: 2,
    //         balance: 32000000000,
    //         is_active: true,
    //         is_slashed: false,
    //         is_withdrawal_allowed: false,
    //     };
        
    //     let mut validators = Vec::new();
    //     validators.push((validator_address1, Some(validator1.clone())));
    //     let changeset = ValidatorChangeset { validators };
    //     provider_rw.write_validator_changes(changeset)?;
        
    //     provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
    //         1, 
    //         ValidatorBeforeTx {
    //             address: validator_address1,
    //             info: None, 
    //         }
    //     )?;
        
    //     provider_rw.commit()?;
        
    //     let mut provider_rw = factory.provider_rw()?;
    //     let mut modified_validator1 = validator1.clone();
    //     modified_validator1.balance = 33000000000; 
    //     modified_validator1.is_slashed = true; 
        
    //     let mut validators = Vec::new();
    //     validators.push((validator_address1, Some(modified_validator1.clone())));
    //     validators.push((validator_address2, Some(validator2.clone())));
    //     let changeset = ValidatorChangeset { validators };
    //     provider_rw.write_validator_changes(changeset)?;
        
    //     provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
    //         2, 
    //         ValidatorBeforeTx {
    //             address: validator_address1,
    //             info: Some(validator1.clone()), 
    //         }
    //     )?;
        
    //     provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
    //         2, 
    //         ValidatorBeforeTx {
    //             address: validator_address2,
    //             info: None, 
    //         }
    //     )?;
        
    //     provider_rw.commit()?;
        
    //     let mut provider_rw = factory.provider_rw()?;
    //     let mut modified_validator2 = validator2.clone();
    //     modified_validator2.is_active = false; 
        
    //     let mut validators = Vec::new();
    //     validators.push((validator_address2, Some(modified_validator2.clone())));
    //     let changeset = ValidatorChangeset { validators };
    //     provider_rw.write_validator_changes(changeset)?;
        
    //     provider_rw.tx_ref().put::<tables::ValidatorChangeSets>(
    //         3, 
    //         ValidatorBeforeTx {
    //             address: validator_address2,
    //             info: Some(validator2.clone()), 
    //         }
    //     )?;
        
    //     provider_rw.commit()?;
        
    //     let provider_ro = factory.provider()?;
        
    //     let result1 = provider_ro.basic_validator(validator_address1)?;
    //     assert!(result1.is_some(), "validator1 data should exist");
    //     let retrieved_validator1 = result1.unwrap();
    //     assert_eq!(modified_validator1.balance, retrieved_validator1.balance);
    //     assert_eq!(modified_validator1.is_slashed, retrieved_validator1.is_slashed);
        
    //     let result2 = provider_ro.basic_validator(validator_address2)?;
    //     assert!(result2.is_some(), "validator2 data should exist");
    //     let retrieved_validator2 = result2.unwrap();
    //     assert_eq!(modified_validator2.is_active, retrieved_validator2.is_active);
        
    //     let mut provider_rw = factory.provider_rw()?;
    //     provider_rw.unwind_validator(2..=3)?;
    //     provider_rw.commit()?;
        
    //     let provider_ro = factory.provider()?;
        
    //     let result1 = provider_ro.basic_validator(validator_address1)?;
    //     assert!(result1.is_some(), "validator1 data should exist after unwind");
    //     let retrieved_validator1 = result1.unwrap();
    //     assert_eq!(validator1.balance, retrieved_validator1.balance);
    //     assert_eq!(validator1.is_slashed, retrieved_validator1.is_slashed);
        
    //     let result2 = provider_ro.basic_validator(validator_address2)?;
    //     assert!(result2.is_none(), "validator2 data should not exist after unwind");
        
    //     Ok(())
    // }

    #[test]
    fn common_history_provider() {
        let factory = create_test_provider_factory();
        let _ = factory.latest();
    }

    #[test]
    fn default_chain_info() {
        let factory = create_test_provider_factory();
        let provider = factory.provider().unwrap();

        let chain_info = provider.chain_info().expect("should be ok");
        assert_eq!(chain_info.best_number, 0);
        assert_eq!(chain_info.best_hash, B256::ZERO);
    }

    #[test]
    fn provider_flow() {
        let factory = create_test_provider_factory();
        let provider = factory.provider().unwrap();
        provider.block_hash(0).unwrap();
        let provider_rw = factory.provider_rw().unwrap();
        provider_rw.block_hash(0).unwrap();
        provider.block_hash(0).unwrap();
    }

    #[test]
    fn provider_factory_with_database_path() {
        let chain_spec = ChainSpecBuilder::mainnet().build();
        let (_static_dir, static_dir_path) = create_test_static_files_dir();
        let factory = ProviderFactory::<MockNodeTypesWithDB<DatabaseEnv>>::new_with_database_path(
            tempfile::TempDir::new().expect(ERROR_TEMPDIR).keep(),
            Arc::new(chain_spec),
            DatabaseArguments::new(Default::default()),
            StaticFileProvider::read_write(static_dir_path).unwrap(),
        )
        .unwrap();

        let provider = factory.provider().unwrap();
        provider.block_hash(0).unwrap();
        let provider_rw = factory.provider_rw().unwrap();
        provider_rw.block_hash(0).unwrap();
        provider.block_hash(0).unwrap();
    }

    #[test]
    fn insert_block_with_prune_modes() {
        let factory = create_test_provider_factory();

        let block = TEST_BLOCK.clone();
        {
            let provider = factory.provider_rw().unwrap();
            assert_matches!(
                provider
                    .insert_block(block.clone().try_recover().unwrap(), StorageLocation::Database),
                Ok(_)
            );
            assert_matches!(
                provider.transaction_sender(0), Ok(Some(sender))
                if sender == block.body().transactions[0].recover_signer().unwrap()
            );
            assert_matches!(
                provider.transaction_id(*block.body().transactions[0].tx_hash()),
                Ok(Some(0))
            );
        }

        {
            let prune_modes = PruneModes {
                sender_recovery: Some(PruneMode::Full),
                transaction_lookup: Some(PruneMode::Full),
                ..PruneModes::none()
            };
            let provider = factory.with_prune_modes(prune_modes).provider_rw().unwrap();
            assert_matches!(
                provider
                    .insert_block(block.clone().try_recover().unwrap(), StorageLocation::Database),
                Ok(_)
            );
            assert_matches!(provider.transaction_sender(0), Ok(None));
            assert_matches!(
                provider.transaction_id(*block.body().transactions[0].tx_hash()),
                Ok(None)
            );
        }
    }

    #[test]
    fn take_block_transaction_range_recover_senders() {
        let factory = create_test_provider_factory();

        let mut rng = generators::rng();
        let block =
            random_block(&mut rng, 0, BlockParams { tx_count: Some(3), ..Default::default() });

        let tx_ranges: Vec<RangeInclusive<TxNumber>> = vec![0..=0, 1..=1, 2..=2, 0..=1, 1..=2];
        for range in tx_ranges {
            let provider = factory.provider_rw().unwrap();

            assert_matches!(
                provider
                    .insert_block(block.clone().try_recover().unwrap(), StorageLocation::Database),
                Ok(_)
            );

            let senders = provider.take::<tables::TransactionSenders>(range.clone());
            assert_eq!(
                senders,
                Ok(range
                    .clone()
                    .map(|tx_number| (
                        tx_number,
                        block.body().transactions[tx_number as usize].recover_signer().unwrap()
                    ))
                    .collect())
            );

            let db_senders = provider.senders_by_tx_range(range);
            assert!(matches!(db_senders, Ok(ref v) if v.is_empty()));
        }
    }

    #[test]
    fn header_sync_gap_lookup() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();

        let mut rng = generators::rng();

        // Genesis
        let checkpoint = 0;
        let head = random_header(&mut rng, 0, None);

        // Empty database
        assert_matches!(
            provider.local_tip_header(checkpoint),
            Err(ProviderError::HeaderNotFound(block_number))
                if block_number.as_number().unwrap() == checkpoint
        );

        // Checkpoint and no gap
        let static_file_provider = provider.static_file_provider();
        let mut static_file_writer =
            static_file_provider.latest_writer(StaticFileSegment::Headers).unwrap();
        static_file_writer.append_header(head.header(), U256::ZERO, &head.hash()).unwrap();
        static_file_writer.commit().unwrap();
        drop(static_file_writer);

        let local_head = provider.local_tip_header(checkpoint).unwrap();

        assert_eq!(local_head, head);
    }

    #[test]
    fn snapshot_test(){
        let factory=create_test_provider_factory();
        let provider=factory.provider_rw().unwrap();
        let config = APosConfig {
            period: 10, 
            epoch: 100, 
            reward_epoch: 1000, 
            reward_limit: U256::from(1000), 
            deposit_contract: "0x0000000000000000000000000000000000000000".parse::<Address>().unwrap(),
        };
        let number=1;
        let hash: B256 = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
        let signers: Vec<Address> = vec!["0x1111111111111111111111111111111111111111".parse().unwrap(),"0x2222222222222222222222222222222222222222".parse().unwrap(),];
        let mut snapshot=Snapshot::new_snapshot(config, number, hash, signers);
        let address1: Address = "0x3333333333333333333333333333333333333333".parse().unwrap();
        let address2: Address = "0x4444444444444444444444444444444444444444".parse().unwrap();
        snapshot.cast(address1, true); 
        snapshot.cast(address2, false); 
        snapshot.cast(address1, true);  
        snapshot.uncast(address2, false);
        let block_id=BlockHashOrNumber::Number(number);
        let timestamp=SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards").as_secs();
        provider.save_snapshot(number, snapshot.clone()).expect("fail to save snapshot");
        let loaded_snapshot=provider.load_snapshot(block_id).expect("fail to load snapshot").expect("cannot find snapshot");
        assert_eq!(snapshot.config,loaded_snapshot.config);
        assert_eq!(snapshot.number, loaded_snapshot.number);
        assert_eq!(snapshot.hash, loaded_snapshot.hash);
        assert_eq!(snapshot.signers, loaded_snapshot.signers);
        assert_eq!(snapshot.recents, loaded_snapshot.recents);
        assert_eq!(snapshot.votes, loaded_snapshot.votes);
        assert_eq!(snapshot.tally, loaded_snapshot.tally);

        println!("{:#?}", snapshot);
        println!("{:#?}", loaded_snapshot);
        
    }
}
