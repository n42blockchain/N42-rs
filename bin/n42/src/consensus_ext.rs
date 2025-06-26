use std::collections::HashMap;
use reth_consensus::{ConsensusError, FullConsensus};
use reth_ethereum_primitives::{EthPrimitives};
use alloy_primitives::{Sealable, Bytes};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::{error::INVALID_PARAMS_CODE, ErrorObject}};
use alloy_primitives::Address;
use n42_primitives::{Snapshot, VoluntaryExit};
use reth_provider::HeaderProvider;

/// trait interface for a custom rpc namespace: `consensus`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "consensusExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "consensusExt"))]
pub trait ConsensusExtApi {
    /// Propose in the clique consensus.
    #[method(name = "propose")]
    fn propose(&self,
        address: Address,
        auth: bool,
        ) -> RpcResult<()>;

    /// Discard in the clique consensus.
    #[method(name = "discard")]
    fn discard(
        &self,
        address: Address,
        ) -> RpcResult<()>;

    /// GetSnapshot in the clique consensus.
    #[method(name = "get_snapshot")]
    fn get_snapshot(
        &self,
        number: u64,
        ) -> RpcResult<Snapshot>;

    /// Proposals in the clique consensus.
    #[method(name = "proposals")]
    fn proposals(
        &self,
        ) -> RpcResult<HashMap<Address, bool>>;
}

/// The type that implements the `consensus` rpc namespace trait
pub struct ConsensusExt<Cons, Provider> {
    pub consensus: Cons,
    pub provider: Provider,
}

impl<Cons, Provider> ConsensusExtApiServer for ConsensusExt<Cons, Provider>
where
    Cons:
        FullConsensus<EthPrimitives, Error = ConsensusError> + Clone + Unpin + 'static,
    Provider: HeaderProvider + Clone + 'static,
{
    fn propose(&self,
        address: Address,
        auth: bool,
        ) -> RpcResult<()> {
        Ok(self.consensus.propose(address, auth).unwrap_or_default())
    }

    fn discard(&self,
        address: Address,
        ) -> RpcResult<()> {
        Ok(self.consensus.discard(address).unwrap_or_default())
    }

    fn get_snapshot(&self,
        number: u64,
        ) -> RpcResult<Snapshot> {
        let hash = self.provider.header_by_number(number).unwrap_or_default().unwrap_or_default().hash_slow();
        self.consensus.snapshot(number, hash, None).map_err(|err| ErrorObject::owned(INVALID_PARAMS_CODE, err.to_string(), Option::<()>::None))
    }

    fn proposals(
        &self,
        ) -> RpcResult<HashMap<Address, bool>> {
        Ok(self.consensus.proposals().unwrap_or_default())
    }
}

/// trait interface for a custom rpc namespace: `consensusBeaconExt`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "consensusBeaconExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "consensusBeaconExt"))]
pub trait ConsensusBeaconExtApi {
    /// Voluntary exit in the clique consensus.
    #[method(name = "voluntary_exit")]
    fn voluntary_exit(&self,
        message: VoluntaryExit,
        signature: Bytes,
        ) -> RpcResult<()>;
}

/// The type that implements the `consensusBeaconRpc` rpc namespace trait
pub struct ConsensusBeaconExt<Cons, Provider> {
    pub consensus: Cons,
    pub provider: Provider,
}

impl<Cons, Provider> ConsensusBeaconExtApiServer for ConsensusBeaconExt<Cons, Provider>
where
    Cons:
        FullConsensus<EthPrimitives, Error = ConsensusError> + Clone + Unpin + 'static,
    Provider: HeaderProvider + Clone + 'static,
{
    fn voluntary_exit(&self,
        message: VoluntaryExit,
        signature: Bytes,
        ) -> RpcResult<()> {
        Ok(self.consensus.voluntary_exit(message, signature).unwrap_or_default())
    }
}

 mod tests {
     use super::*;
     use jsonrpsee::{http_client::HttpClientBuilder, server::ServerBuilder};
     use reth_consensus::noop::NoopConsensus;
     use reth_provider::test_utils::NoopProvider;

     #[tokio::test(flavor = "multi_thread")]
     async fn test_call_propose_http() {
         let server_addr = start_server().await;
         let uri = format!("http://{}", server_addr);
         let client = HttpClientBuilder::default().build(&uri).unwrap();
         let result = ConsensusExtApiClient::propose(&client, Address::random(), true).await.unwrap();
         assert_eq!(result, ());
     }

     #[tokio::test(flavor = "multi_thread")]
     async fn test_call_discard_http() {
         let server_addr = start_server().await;
         let uri = format!("http://{}", server_addr);
         let client = HttpClientBuilder::default().build(&uri).unwrap();
         let result = ConsensusExtApiClient::discard(&client, Address::random()).await.unwrap();
         assert_eq!(result, ());
     }

     #[tokio::test(flavor = "multi_thread")]
     async fn test_call_get_snapshot_http() {
         let server_addr = start_server().await;
         let uri = format!("http://{}", server_addr);
         let client = HttpClientBuilder::default().build(&uri).unwrap();
         let result = ConsensusExtApiClient::get_snapshot(&client, 0).await.unwrap();
         assert_eq!(result, Snapshot::default());
     }

     #[tokio::test(flavor = "multi_thread")]
     async fn test_call_proposals_http() {
         let server_addr = start_server().await;
         let uri = format!("http://{}", server_addr);
         let client = HttpClientBuilder::default().build(&uri).unwrap();
         let result = ConsensusExtApiClient::proposals(&client).await.unwrap();
         assert_eq!(result, HashMap::default());
     }

     async fn start_server() -> std::net::SocketAddr {
         let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
         let addr = server.local_addr().unwrap();
         let consensus = NoopConsensus::default();
         let provider = NoopProvider::default();
         let api = ConsensusExt { consensus, provider };
         let server_handle = server.start(api.into_rpc());

         tokio::spawn(server_handle.stopped());

         addr
     }
 }
