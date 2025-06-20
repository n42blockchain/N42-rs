use crate::unverifiedblock::UnverifiedBlock;
use jsonrpsee::{
    core::{RpcResult, SubscriptionResult}, proc_macros::rpc, tokio, types::SubscriptionId, ws_client::WsClientBuilder, PendingSubscriptionSink, SubscriptionMessage, SubscriptionSink
};
use reth_network::message;
use std::sync::Arc;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use reth_primitives::BlockBody;
use reth_revm::cached::CachedReads;
use alloy_primitives::U256;
use std::error::Error;

lazy_static! {
    static ref MINEDBLOCK_INSTANCE: Arc<Mutex<MinedblockExt>> = Arc::new(Mutex::new(MinedblockExt::new()));
}

#[cfg_attr(not(test), rpc(server, client,namespace = "minedblockExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "minedblockExt"))]
pub trait MinedblockExtApi {
    #[subscription(name = "subscribeMinedblock", item = UnverifiedBlock)]
    fn subscribe_minedblock(&self) -> SubscriptionResult;

    /// Send block data
    #[method(name = "sendBlock")]
    fn send_block(&self, block: UnverifiedBlock) -> RpcResult<()>;
}
#[derive(Clone)]
pub struct MinedblockExt {
    // Add a channel to store subscribers
    subscribers: Arc<Mutex<Vec<SubscriptionSink>>>,
    pub unverifiedblock:UnverifiedBlock,
}

impl MinedblockExt {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
            unverifiedblock: UnverifiedBlock::default(),
        }
    }
    // pub fn instance() -> Arc<MinedblockExt> {
    //     MINEDBLOCK_INSTANCE.clone()
    // }
    pub fn instance() -> Arc<Mutex<MinedblockExt>> {
        MINEDBLOCK_INSTANCE.clone()
    }
    pub fn set_blockbody(&mut self, blockbody: BlockBody) {
        self.unverifiedblock.blockbody = blockbody;
    }
    pub fn set_db(&mut self, db: CachedReads) {
        self.unverifiedblock.db = db;
    }
    pub fn set_td(&mut self, td: U256) {
        self.unverifiedblock.td = td;
    }
    pub fn clear_unverifiedblock(&mut self) {
        self.unverifiedblock = UnverifiedBlock::default();
    }
}

impl MinedblockExtApiServer for MinedblockExt {
    fn subscribe_minedblock(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let subscribers = self.subscribers.clone();
        
        // Here we start an asynchronous task and return immediately.
        tokio::spawn(async move {
            if let Ok(sink) = pending.accept().await {
                let mut subs = subscribers.lock().await;
                subs.push(sink);
            }
        });

        Ok(())  // Return a `Result` that returns immediately.
    }

    // Make send_block a synchronous function instead of an async fn, and use tokio::spawn to execute the asynchronous task.
    fn send_block(&self, block: UnverifiedBlock) -> RpcResult<()> {
        let subscribers = self.subscribers.clone();

        // Asynchronously handle sending messages to subscribers.
        tokio::spawn(async move {
            let mut subs = subscribers.lock().await;
            for (i,sub) in subs.iter_mut().enumerate() {
                // Send block data to subscribers.
                // let message = SubscriptionMessage::from_json(&block.clone()).unwrap();
                let message=SubscriptionMessage::new("block", SubscriptionId::Num(i as u64), &block);
                match message{
                    Ok(message)=>{
                        if let Err(e) =  sub.send(message).await{
                            println!("Error sending block to subscriber: {:?}", e);
                        }
                    }
                    Err(e)=>{
                        println!("Error sending block to subscriber: {:?}", e);
                    }
                }
            }
        });


        Ok(()) // Return `RpcResult` synchronously.
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

        // tokio::spawn(async move {
        //     let mut subs = subscribers.lock().await;
        //     for mut sub in subs.iter_mut() {
        //         let message = SubscriptionMessage::from_json(&block.clone()).unwrap();
        //         if let Err(e) = sub.send(message).await {
        //             println!("Error sending block to subscriber: {:?}", e);
        //         }
        //     }
        // });

        // Asynchronously handle sending messages to subscribers.
        tokio::spawn(async move {
            let mut subs = subscribers.lock().await;
            for (i,sub) in subs.iter_mut().enumerate() {
                // Send block data to subscribers.
                // let message = SubscriptionMessage::from_json(&block.clone()).unwrap();
                let message=SubscriptionMessage::new("block", SubscriptionId::Num(i as u64), &block);
                match message{
                    Ok(message)=>{
                        if let Err(e) =  sub.send(message).await{
                            println!("Error sending block to subscriber: {:?}", e);
                        }
                    }
                    Err(e)=>{
                        println!("Error sending block to subscriber: {:?}", e);
                    }
                }
            }
        });

        Ok(())
    }
}