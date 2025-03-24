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
use reth_primitives::BlockBody;
use reth_revm::cached::CachedReads;
use alloy_primitives::U256;
lazy_static! {
    static ref MINEDBLOCK_INSTANCE: Arc<Mutex<MinedblockExt>> = Arc::new(Mutex::new(MinedblockExt::new()));
}
#[cfg_attr(not(test), rpc(server, client, namespace = "minedblockExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "minedblockExt"))]
pub trait MinedblockExtApi {
    #[subscription(name = "subscribeMinedblock", item = UnverifiedBlock)]
    fn subscribe_minedblock(&self) -> SubscriptionResult;
    #[method(name = "sendBlock")]
    fn send_block(&self, block: UnverifiedBlock) -> RpcResult<()>;
}
#[derive(Clone)]
pub struct MinedblockExt {
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