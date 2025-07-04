use n42_primitives::{BeaconBlock};

use tracing::{trace, debug, error, info, warn};
use reth_provider::{BlockIdReader, BlockReader, ChainSpecProvider, BeaconProvider, BeaconProviderWriter};
use reth_chainspec::EthereumHardforks;
use super::protocol::proto::{CustomRlpxProtoMessage, CustomRlpxProtoMessageKind};
use alloy_consensus::Sealable;
use alloy_primitives::{bytes::BytesMut, BlockHash};
use futures::{Stream, StreamExt};
//use reth_ethereum::network::eth_wire::multiplex::ProtocolConnection;
use reth_eth_wire::multiplex::ProtocolConnection;
use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnboundedReceiverStream;

pub(crate) mod handler;

/// We define some custom commands that the subprotocol supports.
#[derive(Debug)]
pub(crate) enum CustomCommand {
    /// Sends a message to the peer
    Message {
        msg: String,
        /// The response will be sent to this channel.
        response: oneshot::Sender<String>,
    },
    FetchBeaconBlock {
        block_hash: BlockHash,
        /// The response will be sent to this channel.
        beacon_block: oneshot::Sender<BeaconBlock>,
    },
}

/// The connection handler for the custom RLPx protocol.
pub(crate) struct CustomRlpxConnection<Provider> {
    conn: ProtocolConnection,
    initial_ping: Option<CustomRlpxProtoMessage>,
    commands: UnboundedReceiverStream<CustomCommand>,
    pending_pong: Option<oneshot::Sender<String>>,
    pending_beacon_blocks: schnellru::LruMap<BlockHash, Option<oneshot::Sender<BeaconBlock>>>,
    provider: Pin<Box<Provider>>,
}

impl<Provider> Stream for CustomRlpxConnection<Provider>
where
    Provider:
        BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static + Clone,
{
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(initial_ping) = this.initial_ping.take() {
            return Poll::Ready(Some(initial_ping.encoded()))
        }

        loop {
            if let Poll::Ready(Some(cmd)) = this.commands.poll_next_unpin(cx) {
                return match cmd {
                    CustomCommand::Message { msg, response } => {
                        this.pending_pong = Some(response);
                        Poll::Ready(Some(CustomRlpxProtoMessage::ping_message(msg).encoded()))
                    }
                    CustomCommand::FetchBeaconBlock { block_hash, beacon_block } => {
                        this.pending_beacon_blocks.insert(block_hash, Some(beacon_block));
                        Poll::Ready(Some(CustomRlpxProtoMessage::beacon_block_request(block_hash).encoded()))
                    }
                }
            }

            let Some(msg) = ready!(this.conn.poll_next_unpin(cx)) else { return Poll::Ready(None) };

            let Some(msg) = CustomRlpxProtoMessage::decode_message(&mut &msg[..]) else {
                return Poll::Ready(None)
            };

            match msg.message {
                CustomRlpxProtoMessageKind::Ping => {
                    return Poll::Ready(Some(CustomRlpxProtoMessage::pong().encoded()))
                }
                CustomRlpxProtoMessageKind::Pong => {}
                CustomRlpxProtoMessageKind::PingMessage(msg) => {
                    return Poll::Ready(Some(CustomRlpxProtoMessage::pong_message(msg).encoded()))
                }
                CustomRlpxProtoMessageKind::PongMessage(msg) => {
                    if let Some(sender) = this.pending_pong.take() {
                        sender.send(msg).ok();
                    }
                    continue
                }
                CustomRlpxProtoMessageKind::BeaconBlockRequest(block_hash) => {
                    debug!(target: "consensus-client", ?block_hash, "Got BeaconBlockRequest");
                    match this.provider.get_beacon_block_by_hash(&block_hash) {
                        Ok(v) => {
                            match v {
                                Some(beacon_block) => {
                                    debug!(target: "consensus-client", ?beacon_block, "Got beacon_block from storage");
                                    return Poll::Ready(Some(CustomRlpxProtoMessage::beacon_block_response(beacon_block).encoded()))
                                }
                                None => {
                                    debug!(target: "consensus-client", "None in getting beacon_block from storage");
                                }
                            }
                        }
                        Err(err) => {
                            debug!(target: "consensus-client", ?err, "error in getting beacon_block from storage");
                        }
                    }
                }
                CustomRlpxProtoMessageKind::BeaconBlockResponse(beacon_block) => {
                    //let block_hash = beacon_block.hash_slow();
                    let eth1_block_hash = beacon_block.eth1_block_hash;
                    if let Some(sender) = this.pending_beacon_blocks.get(&eth1_block_hash) {
                        sender.take().unwrap().send(beacon_block).ok();
                    }
                    continue
                }
            }

            return Poll::Pending
        }
    }
}
