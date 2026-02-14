use reth_primitives_traits::AlloyBlockHeader;
use blst::min_pk::{PublicKey, Signature};
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use reth_chainspec::EthereumHardforks;
use reth_provider::{BlockIdReader, BlockReader, ChainSpecProvider, BeaconProvider, BeaconProviderWriter};
use alloy_primitives::Sealable;
use reth_primitives::{Block, Header, SealedBlock};
use merkle_db_rs::tree::{Tree, VecTree};

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals}, eip7685::Requests,
};
use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use alloy_rlp::{Encodable, Decodable, RlpEncodable,  RlpDecodable};
use std::collections::{HashMap, BTreeMap};
use alloy_primitives::{keccak256, BlockHash, B256, Log};
use n42_primitives::{Attestation, BLSPubkey, BeaconBlock, BeaconBlockBody, BeaconState, BlockVerifyResultAggregate, CommitteeIndex, Deposit, DepositData, Epoch, ExecutionRequests, Gwei, Validator, ValidatorInfo, VoluntaryExitWithSig, SLOTS_PER_EPOCH};
use tracing::{trace, debug, error, info, warn};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub struct Beacon<Provider> {
    provider: Provider,
}

impl<Provider> Beacon<Provider>
where
    Provider:
        BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static + Clone,
{
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
        }
    }

    pub fn gen_beacon_block(&mut self, old_beacon_state: BeaconState, parent_hash: BlockHash, attestations: &Vec<Attestation>, execution_requests: &Option<Requests>, eth1_sealed_block: &SealedBlock) -> eyre::Result<(BeaconBlock, BeaconState)> {
        let mut execution_requests = parse_execution_requests(execution_requests)?;

        execution_requests.deposits.retain(|deposit|
            {
                let deposit_data = DepositData {
                    pubkey: deposit.pubkey,
                    withdrawal_credentials: deposit.withdrawal_credentials,
                    signature: deposit.signature,
                    amount: deposit.amount,
                };

                let deposit_data_verify_result = deposit_data.verify_signature();
                debug!(target: "consensus-client", pubkey=?deposit_data.pubkey, ?deposit_data_verify_result, "gen_beacon_block");
                deposit_data_verify_result
            }
        );

        let deposits: Vec<Deposit> = execution_requests.deposits.iter().map(|d| {
            Deposit {
                data: DepositData {
                    pubkey: d.pubkey,
                    withdrawal_credentials: d.withdrawal_credentials,
                    signature: d.signature,
                    amount: d.amount,
                },
                ..Default::default()
            }
        }).collect();

        let mut beacon_block = BeaconBlock {
            slot: old_beacon_state.slot + 1,
            parent_hash,
            eth1_block_hash: eth1_sealed_block.hash_slow(),
            body: BeaconBlockBody {
                deposits,
                attestations: attestations.clone(),
                voluntary_exits: Default::default(),
                execution_requests,
            },
            ..Default::default()
        };
        let beacon_state = BeaconState::state_transition(&old_beacon_state, &beacon_block)?;
        beacon_block.state_root = beacon_state.hash_slow();
        Ok((beacon_block, beacon_state))
    }
}

fn parse_execution_requests(requests: &Option<Requests>) -> eyre::Result<ExecutionRequestsV4> {
    Ok(requests.clone().unwrap_or_default().try_into()?)
}

// --- CORE TRAITS & TYPES ---

/// The contract: Any type implementing this defines its own response type.
pub trait Request: Send + 'static {
    type Response: Send + 'static;
}

/// The internal wrapper that carries the request and the return path.
#[derive(Debug)]
pub struct Envelope<R: Request> {
    pub request: R,
    pub response_tx: oneshot::Sender<R::Response>,
}

// 1. Define specific requests and their responses
#[derive(Debug)]
pub struct GetTotalActiveBalance;
impl Request for GetTotalActiveBalance { type Response = Gwei; }

#[derive(Debug)]
pub struct GetValidatorInfo { pub pubkey: BLSPubkey }
impl Request for GetValidatorInfo { type Response = Option<ValidatorInfo>; }

// 2. Since an MPSC channel needs one concrete type, use an Enum to wrap
// Envelopes
#[derive(Debug)]
pub enum RpcToBeaconCommand {
    GetTotalActiveBalance(Envelope<GetTotalActiveBalance>),
    GetValidatorInfo(Envelope<GetValidatorInfo>),
}
