use crate::unverifiedblock::UnverifiedBlock;
use jsonrpsee::{
    core::{RpcResult, SubscriptionResult},
    proc_macros::rpc,
    tokio,
    PendingSubscriptionSink, SubscriptionMessage, SubscriptionSink,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref MINEDBLOCK_INSTANCE: Arc<MinedblockExt> = Arc::new(MinedblockExt::new());
}

#[cfg_attr(not(test), rpc(server, client,namespace = "minedblockExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "minedblockExt"))]
pub trait MinedblockExtApi {
    #[subscription(name = "subscribeMinedblock", item = UnverifiedBlock)]
    fn subscribe_minedblock(&self) -> SubscriptionResult;

    /// send block data
    #[method(name = "sendBlock")]
    fn send_block(&self, block: UnverifiedBlock) -> RpcResult<()>;
}
#[derive(Clone)]
pub struct MinedblockExt {
    // add a channel to store subscribers
    subscribers: Arc<Mutex<Vec<SubscriptionSink>>>,
}

impl MinedblockExt {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    pub fn instance() -> Arc<MinedblockExt> {
        MINEDBLOCK_INSTANCE.clone()
    }
}

impl MinedblockExtApiServer for MinedblockExt {
    fn subscribe_minedblock(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let subscribers = self.subscribers.clone();

        // start an async task and immediately return
        tokio::spawn(async move {
            if let Ok(sink) = pending.accept().await {
                let mut subs = subscribers.lock().await;
                subs.push(sink);
            }
        });

        Ok(())  
    }

    fn send_block(&self, block: UnverifiedBlock) -> RpcResult<()> {
        let subscribers = self.subscribers.clone();

        tokio::spawn(async move {
            let mut subs = subscribers.lock().await;
            for sub in subs.iter_mut() {
                let message = SubscriptionMessage::from_json(&block.clone()).unwrap();
                if let Err(e) = sub.send(message).await {
                    println!("Error sending block to subscriber: {:?}", e);
                }
            }
        });

        Ok(())
    }
}

impl MinedblockExtApiServer for Arc<MinedblockExt> {
    fn subscribe_minedblock(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let subscribers = self.subscribers.clone();
        
        tokio::spawn(async move {
            if let Ok(sink) = pending.accept().await {
                let mut subs = subscribers.lock().await;
                subs.push(sink);
            }
        });

        Ok(())
    }

    fn send_block(&self, block: UnverifiedBlock) -> RpcResult<()> {
        let subscribers = self.subscribers.clone();

        tokio::spawn(async move {
            let mut subs = subscribers.lock().await;
            for sub in subs.iter_mut() {
                let message = SubscriptionMessage::from_json(&block.clone()).unwrap();
                if let Err(e) = sub.send(message).await {
                    println!("Error sending block to subscriber: {:?}", e);
                }
            }
        });

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::unverifiedblock::UnverifiedBlock;
    use jsonrpsee::{server::ServerBuilder, ws_client::WsClientBuilder};
    use tokio::{sync::oneshot, time::{sleep, Duration}};

    async fn start_server() -> (std::net::SocketAddr, MinedblockExt) {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        let api = MinedblockExt::new();
        let api_clone = api.clone();
        let server_handle = server.start(api.into_rpc());

        tokio::spawn(server_handle.stopped());

        (addr, api_clone)
    }

    async fn run_client(ws_url: String, client_id: u32, tx: oneshot::Sender<bool>) {
        let client = WsClientBuilder::default().build(&ws_url).await.unwrap();
        let mut subscription = MinedblockExtApiClient::subscribe_minedblock(&client)
            .await
            .unwrap();

        let mut received_blocks = 0;
        while let Some(block) = subscription.next().await {
            let block = block.unwrap();
            println!("Client {} received block: {:?}", client_id, block);
            received_blocks += 1;
            
            if received_blocks >= 10 {
                tx.send(true).unwrap();
                break;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multiple_clients_receive_blocks() {
        let (server_addr, api) = start_server().await;
        let ws_url = format!("ws://{}", server_addr);
        let (tx1, rx1) = oneshot::channel::<bool>();
        let (tx2, rx2) = oneshot::channel::<bool>();
        let client1 = tokio::spawn(run_client(ws_url.clone(), 1, tx1));
        let client2 = tokio::spawn(run_client(ws_url.clone(), 2, tx2));
        sleep(Duration::from_secs(1)).await;
        tokio::spawn(async move {
            for i in 0..10 {
                let block = UnverifiedBlock::default();
                api.send_block(block).unwrap();
                sleep(Duration::from_millis(100)).await; 
            }
        });

        let (result1, result2) = tokio::join!(rx1, rx2);
        assert!(result1.unwrap(), "Client 1 did not receive all blocks");
        assert!(result2.unwrap(), "Client 2 did not receive all blocks");

        let _ = tokio::join!(client1, client2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_subscription() {
        let ws_url = "ws://127.0.0.1:8546".to_string();
        println!("linking to server: {}", ws_url);
        
        let client = WsClientBuilder::default()
            .build(&ws_url)
            .await
            .expect("falied to connect to server");
        println!("successfully connected to server");

        let mut subscription = MinedblockExtApiClient::subscribe_minedblock(&client)
            .await
            .expect("fail to subscribe to minedblock");
        println!("successfully subscribed to minedblock");

        println!("listenning for new blocks...");
        loop {
            println!("waiting for new block...");
            match subscription.next().await {
                Some(Ok(block)) => {
                    println!("the new block: {:?}", block);
                }
                Some(Err(e)) => {
                    println!("fail to receive the new block: {:?}", e);
                }
                None => {
                    println!("link been cut");
                    break;
                }
            }
        }
    }

}
