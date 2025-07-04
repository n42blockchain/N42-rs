use reth_provider::{BlockIdReader, BlockReader, ChainSpecProvider, BeaconProvider, BeaconProviderWriter};
use reth_chainspec::EthereumHardforks;
use super::CustomRlpxConnection;
use crate::subprotocol::protocol::{
    event::ProtocolEvent, handler::ProtocolState, proto::CustomRlpxProtoMessage,
};
use reth_network_api::{Direction, PeerId};
use reth_eth_wire::{capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol};
use reth_network::protocol::{ConnectionHandler, OnNotSupported};
/*
use reth_ethereum::network::{
    api::{Direction, PeerId},
    eth_wire::{capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol},
    protocol::{ConnectionHandler, OnNotSupported},
};
*/
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{info, debug};

const INMEMORY_BEACON_BLOCK_RX: u32 = 128;

/// The connection handler for the custom RLPx protocol.
pub(crate) struct CustomRlpxConnectionHandler<Provider> {
    pub(crate) state: ProtocolState,
    pub(crate) provider: Provider,
}

impl<Provider> ConnectionHandler for CustomRlpxConnectionHandler<Provider>
where
    Provider:
        BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static + Clone,
{
    type Connection = CustomRlpxConnection<Provider>;

    fn protocol(&self) -> Protocol {
        CustomRlpxProtoMessage::protocol()
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        let (tx, rx) = mpsc::unbounded_channel();
        self.state
            .events
            .send(ProtocolEvent::Established { direction, peer_id, to_connection: tx })
            .ok();
        debug!(target: "reth::cli", ?direction, ?peer_id, "custom_rlpx into_connection");
        CustomRlpxConnection {
            conn,
//            initial_ping: direction.is_outgoing().then(CustomRlpxProtoMessage::ping),
            initial_ping: None,
            commands: UnboundedReceiverStream::new(rx),
            pending_pong: None,
            pending_beacon_blocks: schnellru::LruMap::new(schnellru::ByLength::new(INMEMORY_BEACON_BLOCK_RX)),
            provider: Box::pin(self.provider.clone()),
        }
    }
}
