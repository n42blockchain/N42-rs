use crate::subprotocol::connection::CustomCommand;
use reth_provider::{BlockIdReader, BlockReader, ChainSpecProvider, BeaconProvider, BeaconProviderWriter};
use reth_chainspec::EthereumHardforks;
use super::event::ProtocolEvent;
use crate::subprotocol::connection::handler::CustomRlpxConnectionHandler;
//use reth_ethereum::network::{api::PeerId, protocol::ProtocolHandler};
use reth_network_api::{PeerId};
use reth_network::protocol::ProtocolHandler;
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Protocol state is an helper struct to store the protocol events.
#[derive(Clone, Debug)]
pub(crate) struct ProtocolState {
    pub(crate) events: mpsc::UnboundedSender<ProtocolEvent>,
}

/// The protocol handler takes care of incoming and outgoing connections.
#[derive(Debug)]
pub(crate) struct CustomRlpxProtoHandler<Provider> {
    pub state: ProtocolState,
    pub provider: Provider,
}

impl<Provider> ProtocolHandler for CustomRlpxProtoHandler<Provider>
where
    Provider:
        BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static + Clone,
{
    type ConnectionHandler = CustomRlpxConnectionHandler<Provider>;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(CustomRlpxConnectionHandler {
            state: self.state.clone(),
            provider: self.provider.clone(),
        })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(CustomRlpxConnectionHandler {
            state: self.state.clone(),
            provider: self.provider.clone(),
        })
    }
}
