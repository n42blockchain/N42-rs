use alloy_primitives::{Address, B256, Bytes as AlloyBytes, B64, BlockNumber};
use alloy_genesis::{ChainConfig, Genesis,CliqueConfig};
use reth_primitives::{Header,Block};
use n42_clique::{NONCE_AUTH_VOTE, APos};

use reth_provider::{
    test_utils::create_test_provider_factory_with_chain_spec,
    providers::{BlockchainProvider, StaticFileProvider}, ProviderFactory
};
use reth_blockchain_tree::noop::NoopBlockchainTree;
use std::sync::Arc;
use reth_chainspec::ChainSpec;
use reth_transaction_pool::test_utils::testing_pool;
use reth_evm::test_utils::MockExecutorProvider;
use reth_consensus::test_utils::TestConsensus;
use reth_db::{test_utils::{create_test_rw_db, create_test_static_files_dir}};
use reth_db_common::init::init_genesis;
use reth_network::{config::SecretKey, NetworkConfigBuilder, NetworkManager};
use reth_node_ethereum::{EthEvmConfig};
use crate::snapshot_test_utils::{EXTRA_SEAL, DIFF_IN_TURN, EXTRA_VANITY, TesterAccountPool};

// Types representing tester votes and test structure
#[derive(Debug)]
pub struct TesterVote {
    pub signer: String,
    pub voted: String,
    pub auth: bool,
    pub checkpoint: Vec<String>,
    pub newbatch: bool,
}

#[derive(Debug)]
pub struct CliqueTest {
    pub epoch: u64,
    pub signers: Vec<String>,
    pub votes: Vec<TesterVote>,
    pub results: Vec<String>,
    pub failure: Option<String>,
}


impl CliqueTest {
    pub async fn run(&self, chain_spec: Arc<ChainSpec>) -> eyre::Result<()> {
        let transaction_pool = testing_pool();
        let evm_config = EthEvmConfig::new(chain_spec.clone());
        let executor = MockExecutorProvider::default();
        let consensus = Arc::new(TestConsensus::default());

        let (static_dir, _) = create_test_static_files_dir();
        let db = create_test_rw_db();
        let provider_factory = ProviderFactory::new(
            db,
            chain_spec.clone(),
            StaticFileProvider::read_write(static_dir.into_path()).expect("static file provider"),
        );

        let genesis_hash = init_genesis(&provider_factory)?;
        let provider =
            BlockchainProvider::new(provider_factory.clone(), Arc::new(NoopBlockchainTree::default()))?;

        let network_manager = NetworkManager::new(
            NetworkConfigBuilder::new(SecretKey::new(&mut rand::thread_rng()))
                .with_unused_discovery_port()
                .with_unused_listener_port()
                .build(provider_factory.clone()),
        ).await;
        let mut accounts = TesterAccountPool::new();

        // Generate the initial set of signers
        let mut signers: Vec<Address> = self.signers.iter().map(|s| accounts.address(s)).collect();
        signers.sort();

        // Create the genesis block with only the relevant fields for testing
        let mut genesis = Genesis {
            base_fee_per_gas: Some(1_000_000_000u128),
            extra_data: AlloyBytes::from(vec![0u8; 32]), // Initialize with extra data of sufficient size
            ..Default::default() // Use the Default trait to fill in other fields with defaults
        };

        for (j, signer) in signers.iter().enumerate() {
            let start = EXTRA_VANITY + j * Address::len_bytes();
            let end = start + Address::len_bytes();
            genesis.extra_data[start..end].copy_from_slice(signer.as_bytes());
        }

        let extra_data = genesis.extra_data.clone();

        let chainspce = ChainSpec {
            genesis,
            ..Default::default()
        };

        let config = ChainConfig {
            clique: Some(CliqueConfig {
                period: Some(1u64),
                epoch: Some(self.epoch),
            }),
            ..Default::default()
        };
        genesis.config = config;

        // let engine = APos::new(None,genesis.config.clique.unwrap());

        let mut blocks: Vec<Block> = Vec::new();

        for mut i in 1..self.votes.len(){
            if i == 1 {
                blocks.push(
                    Block {
                        header: Header {
                            parent_hash: B256::from_slice(&extra_data),
                            number: i as BlockNumber,
                            nonce: B64::from(NONCE_AUTH_VOTE),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                );
            } else {
                blocks.push(
                    Block{
                        header:Header{
                            parent_hash: blocks[i].header.ommers_hash.clone(),
                            number: i as BlockNumber,
                            nonce: B64::from(NONCE_AUTH_VOTE),

                            ..Default::default()
                        },
                        ..Default::default()

                    }

                )
            }
        }

        //
        // let blocks = Block{
        //     header:Header{
        //         parent_hash: genesis.extra_data.clone(),
        //         number: 1,
        //         nonce: NONCE_AUTH_VOTE,
        //
        //         ..Default::default()
        //     },
        //     ..Default::default()
        //
        // };

        // Placeholder for blockchain and engine setup
        // Example: let engine = Engine::new(config, ...);

        // Iterate through the votes and create blocks accordingly
        for (j, vote) in self.votes.iter().enumerate() {
            let mut header = blocks[j].header.clone();
            if j > 0 {
                // Set the parent hash to the hash of the previous block (placeholder logic)
                header.parent_hash = B256::from([0u8; 32]); // Replace with actual hash of previous block
            }

            header.extra_data = AlloyBytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL]);
            if !vote.checkpoint.is_empty() {
                header.extra_data = AlloyBytes::from(vec![
                    0u8;
                    EXTRA_VANITY + vote.checkpoint.len() * Address::len_bytes() + EXTRA_SEAL
                ]);
                accounts.checkpoint(&mut header, &vote.checkpoint);
            }

            header.difficulty = DIFF_IN_TURN.into();

            // Generate the signature and embed it into the header
            accounts.sign(&mut header, &vote.signer);
        }

        // Validate the results against expected signers
        let mut expected_signers: Vec<Address> = self.results.iter().map(|s| accounts.address(s)).collect();
        expected_signers.sort();

        // Placeholder logic to retrieve the actual snapshot
        // Example: let snapshot = engine.snapshot(...);

        let head = blocks[blocks.len()-1].clone();

        let provider_factory = create_test_provider_factory_with_chain_spec(Arc::from(chainspce));

        let provider =
            BlockchainProvider::new(provider_factory.clone(), Arc::new(NoopBlockchainTree::default()))?;

        let snap = APos::snapshot(provider,head.number, head.ommers_hash, None)?;

        let result_signers: Vec<Address> = snap.singers();

        if result_signers.len() != expected_signers.len() {
            panic!("signers mismatch: have {:?}, want {:?}", result_signers, expected_signers);
        }

        for (j, signer) in result_signers.iter().enumerate() {
            if signer != &expected_signers[j] {
                panic!("signer {} mismatch: have {:?}, want {:?}", j, signer, expected_signers[j]);
            }
        }
        Ok(())
    }
}