use alloy_primitives::{BlockHash};
use tokio::time;
use n42_primitives::{BeaconBlock};
use reth_network_api::{PeerId};
use tokio::sync::{mpsc, oneshot::error::RecvError};
use tokio::task::JoinSet;
use tokio::sync::oneshot;
use crate::subprotocol::{
    connection::CustomCommand,
    protocol::{
        event::ProtocolEvent,
    },
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{trace, debug, error, info, warn};

pub fn fetch_beacon_block(block_hash: BlockHash) -> eyre::Result<BeaconBlock> {
    todo!()
 }
 
pub fn broadcast_beacon_block(block_hash: BlockHash, beacon_block: &BeaconBlock) -> eyre::Result<()> {
    todo!()
}

/// The peer
#[derive(Debug, Clone)]
pub struct Peer {
    peer_id: PeerId,
    to_connection: mpsc::UnboundedSender<CustomCommand>,
}

#[derive(Debug)]
pub struct NetworkManager {
    events: UnboundedReceiver<ProtocolEvent>,
    commands: UnboundedReceiver<CustomCommand>,
    peers: Vec<Peer>,
}

impl NetworkManager {
    pub fn spawn_new(events: UnboundedReceiver<ProtocolEvent>, commands: UnboundedReceiver<CustomCommand>) {
        let network_manager = Self {
            events,
            commands,
            peers: Vec::new(),
        };
        tokio::spawn(network_manager.run());
    }

    pub async fn run(mut self) -> eyre::Result<()> {
        debug!(target: "consensus-client::network_manager", "Start running");
        let mut join_set = JoinSet::new();
        loop {
            tokio::select! {
                Some(event) = self.events.recv() => {
                    debug!(target: "consensus-client::network_manager", ?event, "Received event");
                    match event {
                        ProtocolEvent::Established { direction: _, peer_id, to_connection } => {
                            self.peers.retain(|peer| peer.peer_id != peer_id);
                            self.peers.push(
                                Peer {
                                    peer_id,
                                    to_connection,
                                }
                                );
                        }
                    }
                }
                Some(command) = self.commands.recv() => {
                    debug!(target: "consensus-client::network_manager", ?command, "Received command");
                    join_set.spawn(broadcast_command(self.peers.clone(), command));
                }
                Some(res) = join_set.join_next() => {
                    match res {
                        Ok(message) => {
                            debug!(target: "consensus-client::network_manager", ?message, "Received message");
                        }
                        Err(e) => {
                            error!("Task panicked or was cancelled: {:?}", e);
                        }
                    }
                }
            }
        }
    }

}

pub async fn broadcast_command(peers: Vec<Peer>, command: CustomCommand) -> eyre::Result<()> {
    match command {
        CustomCommand::Message { ref msg, response } => {
            let mut join_set = JoinSet::new();
            for peer in &peers {
                let (tx, rx) = oneshot::channel();
                let peer_id = peer.peer_id;
                        join_set.spawn(async move {
                            let response = rx.await;
                            debug!(target: "consensus-client::network_manager", ?response, ?peer_id, "Received response");
                            response.unwrap()
                        });
                        let peer_command = CustomCommand::Message {
                            msg: msg.clone(),
                            response: tx,
                        };
                debug!(target: "consensus-client::network_manager", ?peer_id, "Before sending");
                match peer.to_connection.send(peer_command) {
                    Ok(_) => {}
                    Err(err) => {
                        debug!(target: "consensus-client::network_manager", ?peer, ?err, "Send failed");
                    }
                }
                debug!(target: "consensus-client::network_manager", ?peer_id, "After sending");
            }
            let mut result = Default::default();
            while let Some(res) = join_set.join_next().await {
                match res {
                    Ok(success) => {
                        result = success;
                        break;
                    }
                    Err(e) => {
                        debug!(target: "consensus-client::network_manager", ?e, "join_next() error");
                        return Err(eyre::eyre!(format!("broadcast_command failed: {:?}", e)));
                    }
                }
            }

            let _ = response.send(result);
        }
        CustomCommand::FetchBeaconBlock { ref block_hash, beacon_block } => {
            debug!(target: "consensus-client::network_manager", ?peers, "FetchBeaconBlock");
            let mut join_set = JoinSet::new();
            for peer in &peers {
                let (tx, rx) = oneshot::channel();
                let peer_id = peer.peer_id;
                        join_set.spawn(async move {
                            let response = rx.await;
                            debug!(target: "consensus-client::network_manager", ?response, ?peer_id, "Received response");
                            response.map_err(|err| Err::<BeaconBlock, eyre::Error>(eyre::eyre!("recv error")))
                        });
                        let peer_command = CustomCommand::FetchBeaconBlock {
                            block_hash: block_hash.clone(),
                            beacon_block: tx,
                        };
                debug!(target: "consensus-client::network_manager", ?peer_id, "Before sending");
                match peer.to_connection.send(peer_command) {
                    Ok(_) => {}
                    Err(err) => {
                        debug!(target: "consensus-client::network_manager", ?peer, ?err, "Send failed");
                    }
                }
                debug!(target: "consensus-client::network_manager", ?peer_id, "After sending");
            }
            join_set.spawn(async move {
                time::sleep(time::Duration::from_secs(5)).await;
                debug!(target: "consensus-client::network_manager", "timeout");
                Err(Err(eyre::eyre!("timeout")))
            });
            let mut result = Default::default();
            let mut received_block = false;
            while let Some(res) = join_set.join_next().await {
                match res {
                    Ok(recv_result) => {
                        match recv_result {
                            Ok(beacon_block) => {
                                received_block = true;
                                result = beacon_block;
                                break;
                            }
                            Err(err) => {
                                debug!(target: "consensus-client::network_manager", ?err, "error");
                                if err.err().unwrap().to_string() == "timeout" {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!(target: "consensus-client::network_manager", ?e, "join_next() error");
                        return Err(eyre::eyre!(format!("broadcast_command failed: {:?}", e)));
                    }
                }
            }
            if received_block {
                let _ = beacon_block.send(result);
            } else {
                debug!(target: "consensus-client::network_manager", "return without getting a beacon block");
            }
        }
    };

    Ok(())
}
