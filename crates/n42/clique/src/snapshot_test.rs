use secp256k1::{SecretKey, PublicKey, Message,Secp256k1};
use secp256k1::ecdsa;
use alloy_primitives::{Address,B256,Bytes};
use alloy_genesis::{ChainConfig, Genesis,CliqueConfig};

use crate::traits::Engine;
use secp256k1::{ecdsa::{Signature}};
use secp256k1::rand::rngs::OsRng;
use reth_primitives::{Header,Block};

use crate::apos::{NONCE_AUTH_VOTE,NONCE_DROP_VOTE};

use std::default;
use std::marker::Tuple;
use std::str::FromStr;
// use bytes::{Bytes, BytesMut};
use sha3::{Digest, Keccak256}; // Import the Keccak256 hasher and Digest trait
use crate::apos::APos;
use n42_primitives::Snapshot;
use reth_exex_test_utils::test_exex_context_with_chain_spec;
use reth_provider::providers::{BlockchainProvider};
use reth_provider::test_utils::create_test_provider_factory_with_chain_spec;
use reth_blockchain_tree::noop::NoopBlockchainTree;

// use web3::types::{Address, H256, U256};
// use web3::transports::Http;
// use web3::signing::SecretKeyRef;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use reth_provider::OriginalValuesKnown::No;
use tracing::dispatcher::set_default;
use reth_chainspec::ChainSpec;
use crate::error::Error::Block as BlockError;

pub const EXTRA_SEAL: usize = 65;


// TesterAccountPool is a pool to maintain currently active tester accounts
struct TesterAccountPool {
    accounts: HashMap<String, SecretKey>,
}

impl TesterAccountPool {
    fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    // Returns the Ethereum address for a given signer label
    fn address(&mut self, account: &str) -> Address {
        if account.is_empty() {
            return Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
        }
        if !self.accounts.contains_key(account) {
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            self.accounts.insert(account.to_string(), secret_key);
        }
        // let public_key = PublicKey::from_secret_key(&self.accounts[account]);
        // Initialize secp256k1 context
        let secp = Secp256k1::new();

        // Get the corresponding public key
        let secret_key = self.accounts.get(account).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);
        Address::from_slice(&public_key.serialize()[1..21])
    }

    // Calculate a Clique digital signature for the given block and embed it into the header
    fn sign(&mut self, header: &mut Header, signer: &str) {
        // Ensure we have a persistent key for the signer
        let secp = Secp256k1::new();
        let secret_key = self.accounts.entry(signer.to_string())
            .or_insert_with(|| SecretKey::new(&mut OsRng));

        // Compute the seal hash
        let seal_hash = seal_hash(header);
        let message = Message::from_slice(&seal_hash).expect("32 bytes");

        // Sign the header
        let sig = secp.sign_ecdsa(&message, secret_key);

        // Serialize the signature to bytes and embed it in extra_data
        let sig_bytes = sig.serialize_compact();
        let extra_len = header.extra_data.len();

        // Ensure there's enough space for the signature in extra_data
        if extra_len < sig_bytes.len() {
            header.extra_data.resize(extra_len + sig_bytes.len(), 0);
        }

        header.extra_data[extra_len - sig_bytes.len()..].copy_from_slice(&sig_bytes);
    }


    // Creates a checkpoint from the authorized signers and embeds it in the header
    fn checkpoint(&mut self, header: &mut Header, signers: &[String]) {
        let mut auth_addresses: Vec<Address> = signers.iter()
            .map(|signer| self.address(signer))
            .collect();

        auth_addresses.sort_by(|a, b| a.0.cmp(&b.0));
        for (i, address) in auth_addresses.iter().enumerate() {
            header.extra_data[i * Address.len()] = address.clone().into();
        }
    }

    // // Compute the hash for the header (equivalent of Go's SealHash function)
    // fn seal_hash(&self, header: &Header) -> U256 {
    //     // Normally, SealHash would compute a keccak256 hash of the RLP-encoded
    //     // block header with some fields excluded (like extra-data signatures).
    //     // Here, we'll just hash the header's fields for simplicity.
    //     let mut hash_data = vec![];
    //     hash_data.extend_from_slice(&header.parent_hash.as_bytes());
    //     hash_data.extend_from_slice(&header.ommers_hash.as_bytes());
    //     hash_data.extend_from_slice(&header.beneficiary.as_bytes());
    //     // You can add more fields as needed.
    //     U256::from(keccak256(&hash_data))
    // }
}

// Compute the hash for the header (equivalent of Go's SealHash function)
fn seal_hash(header: &Header) -> [u8; 32] {
    // Normally, SealHash would compute a keccak256 hash of the RLP-encoded
    // block header with some fields excluded (like extra-data signatures).
    // Here, we'll hash the header's fields for simplicity.

    let mut hasher = Keccak256::new();
    hasher.update(header.parent_hash.as_bytes());
    hasher.update(header.ommers_hash.as_bytes());
    hasher.update(header.beneficiary.as_bytes());
    // Add more fields as needed based on your header structure.

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}


// Types representing tester votes and test structure
#[derive(Debug)]
struct TesterVote {
    signer: String,
    voted: String,
    auth: bool,
    checkpoint: Vec<String>,
    newbatch: bool,
}

#[derive(Debug)]
struct CliqueTest {
    epoch: u64,
    signers: Vec<String>,
    votes: Vec<TesterVote>, 
    results: Vec<String>,
    failure: Option<String>,
}


impl CliqueTest {
    fn run(&self) {
        let mut accounts = TesterAccountPool::new();

        // Generate the initial set of signers
        let mut signers: Vec<Address> = self.signers.iter().map(|s| accounts.address(s)).collect();
        signers.sort();

        // Create the genesis block with only the relevant fields for testing
        let mut genesis = Genesis {
            base_fee_per_gas:Some(1_000_000_000u128),
            extra_data: Bytes::from(vec![0u8; 32]),// Initialize with extra data of sufficient size
            ..Default::default()          // Use the Default trait to fill in other fields with defaults
        };

        let mut chainspce = ChainSpec{
            genesis,
            ..Default::default()

        };

        for (j, signer) in signers.iter().enumerate() {
            let start = EXTRA_VANITY + j * Address::len_bytes();
            let end = start + Address::len_bytes();
            genesis.extra_data[start..end].copy_from_slice(signer.as_bytes());
        }

        let config = ChainConfig {
            clique: Some(CliqueConfig {
                period: 1,
                epoch: Some(self.epoch),
            }),
            ..Default::default()
        };
        genesis.config = Some(config);



        // let engine = APos::new(None,genesis.config.clique.unwrap());


        let mut blocks: Vec<Block> = Vec::new();

        for mut i in 1..self.votes.len(){

            if i == 1{
                blocks.push(
                    Block{
                        header:Header{
                            parent_hash: genesis.extra_data.clone(),
                            number: i,
                            nonce: NONCE_AUTH_VOTE,

                            ..Default::default()
                        },
                        ..Default::default()

                    }

                )

            }
            else {
                blocks.push(
                    Block{
                        header:Header{
                            parent_hash: blocks[i].header.ommers_hash.clone(),
                            number: i,
                            nonce: NONCE_AUTH_VOTE,

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

            header.extra_data = vec![0; EXTRA_VANITY + EXTRA_SEAL];
            if !vote.checkpoint.is_empty() {
                header.extra_data = vec![0; EXTRA_VANITY + vote.checkpoint.len() * Address::len_bytes() + EXTRA_SEAL];
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

        let provider_factory = create_test_provider_factory_with_chain_spec(chainspce);

        let provider =
            BlockchainProvider::new(provider_factory.clone(), Arc::new(NoopBlockchainTree::default()))?;

        let snap = APos::snapshot(provider,head.number, head.ommers_hash, head.parent_hash)?;

        let result_signers: Vec<Address> = snap.singer();

        if result_signers.len() != expected_signers.len() {
            panic!("signers mismatch: have {:?}, want {:?}", result_signers, expected_signers);
        }

        for (j, signer) in result_signers.iter().enumerate() {
            if signer != &expected_signers[j] {
                panic!("signer {} mismatch: have {:?}, want {:?}", j, signer, expected_signers[j]);
            }
        }
    }
}

// Constants and other placeholders
const EXTRA_VANITY: usize = 32; // Placeholder for extra vanity size
// const EXTRA_SEAL: usize = 65;   // Placeholder for extra seal size
const DIFF_IN_TURN: B256 = B256::from(1);    // Placeholder difficulty

#[cfg(test)]
mod tests {
    #[test]
fn main() {
    let tests = vec![
        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: B.to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            }],
            results: vec!["A".to_string()],
            failure: None,
        },
        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),“B”.to_string(),"C".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),“B”.to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "B".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "B".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            ],
            results: vec!["A".to_string()],
            failure: None,
        },


        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),“B”.to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },TesterVote{
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote{
                signer: "A".to_string(),
                voted: "D".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote{
                signer: "B".to_string(),
                voted: "D".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote{
                signer: "A".to_string(),
                voted: "E".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote{
                signer: "B".to_string(),
                voted: "E".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                ..default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                ..default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            }
            
            
            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
           
            TesterVote {
                signer: "A".to_string(),
                voted: "D".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
           
            TesterVote {
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "D".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            }
            
            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
           
            TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
           
            TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
          
            
            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: vec![],
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: vec![],
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "A".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: ture,
                checkpoint: vec![],
                newbatch: false,
            },
            
            
            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string()],
            failure: None,
        },
        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: vec![],
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: vec![],
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "A".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: "C".to_string(),
                auth: ture,
                checkpoint: vec![],
                newbatch: false,
            },
            
            
            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "A".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: "D".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },


            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string(),],
            failure: None,
        },



        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string(),"E".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "F".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "F".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: "F".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "D".to_string(),
                voted: "F".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "E".to_string(),
                voted: "F".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "F".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: "F".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "D".to_string(),
                voted: "F".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "E".to_string(),
                voted: "F".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "A".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "C".to_string(),
                voted: "A".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "D".to_string(),
                voted: "A".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "F".to_string(),
                auth: ture,
                checkpoint: vec![],
                newbatch: false,
            },
            


            ],
            results: vec!["B".to_string(),"C".to_string(),"D".to_string(),"E".to_string(),"F".to_string()],
            failure: None,
        },






        CliqueTest {
            epoch: 3,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                ..default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec!["A".to_string(),"B".to_string()],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            

            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },
        CliqueTest {
            epoch: 3,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
            TesterVote {
                signer: "A".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec!["A".to_string(),"B".to_string(),"C".to_string()],
                newbatch: false,
            },
            TesterVote {
                signer: "B".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec![],
                newbatch: ture,
            },
            

            ],
            results: vec![],
            failure: "recently signed",
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            }],
            results: vec![],
            failure: "unauthorized signer",
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec!["A".to_string(),"B".to_string(),"C".to_string()],
                newbatch: false,
            },
            TesterVote {
                signer: "A".to_string(),
                voted: vec![],
                auth: true,
                checkpoint: vec![],
                newbatch: true,
            }
            
            ],
            results: vec![],
            failure: "unauthorized signer",
        },




        // Add more test cases here...
    ];

    for (i, test) in tests.iter().enumerate() {
        if let Err(e) = test.run() {
            eprintln!("Test {} failed: {:?}", i, e);
        }
    }

    // // Run each test in the vector
    // for test in tests {
    //     test.run();
    // }

}
}
