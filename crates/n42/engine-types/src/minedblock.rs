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
use alloy_primitives::B256;
use bls::AggregateSignature;

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
    /// 客户端提交签名数据
    #[method(name = "submitSignature")]
    fn submit_signature(&self, pubkey: Vec<u8>, signature: Vec<u8>) -> RpcResult<()>;
}

pub struct MinedblockExt {
    // Add a channel to store subscribers
    subscribers: Arc<Mutex<Vec<SubscriptionSink>>>,
    pub unverifiedblock:UnverifiedBlock,
    pub agg_signature: std::sync::RwLock<Option<AggregateSignature>>,
    pub signatures: std::sync::RwLock<Vec<(Vec<u8>, Vec<u8>)>>, // 新增字段存储(pubkey, signature)
}

impl Clone for MinedblockExt {
    fn clone(&self) -> Self {
        MinedblockExt {
            subscribers: self.subscribers.clone(),
            unverifiedblock: self.unverifiedblock.clone(),
            agg_signature: std::sync::RwLock::new(self.agg_signature.read().unwrap().clone()),
            signatures: std::sync::RwLock::new(self.signatures.read().unwrap().clone()),
        }
    }
}

impl MinedblockExt {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
            unverifiedblock: UnverifiedBlock::default(),
            agg_signature: std::sync::RwLock::new(None),
            signatures: std::sync::RwLock::new(Vec::new()),
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
    pub fn clear_signatures(&self) {
        let mut sigs = self.signatures.write().unwrap();
        sigs.clear();
        println!("signatures 已清空");
    }
    pub fn subscriber_count(&self) -> usize {
        // 由于subscribers是Arc<Mutex<>>，需要异步获取，但这里提供同步方法用于简单场景
        // 实际调用时建议在异步环境下使用lock().await
        match self.subscribers.try_lock() {
            Ok(subs) => subs.len(),
            Err(_) => 0 // 获取不到锁时返回0或可自定义处理
        }
    }
    pub fn print_signatures(&self) {
        let sigs = self.signatures.read().unwrap();
        println!("当前signatures内容: {:?}", *sigs);
    }
    pub fn get_signatures(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let sigs = self.signatures.read().unwrap();
        sigs.clone()
    }
}

impl MinedblockExtApiServer for MinedblockExt {
    fn subscribe_minedblock(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let subscribers = self.subscribers.clone();
        
        // Here we start an asynchronous task and return immediately.
        tokio::spawn(async move {
            if let Ok(sink) = pending.accept().await {
                println!("✅ Successfully subscribed to minedblockExt_subscribeMinedblock");
                println!("✅ Successfully subscribed to minedblockExt_subscribeMinedblock");
                println!("✅ Successfully subscribed to minedblockExt_subscribeMinedblock");
                println!("✅ Successfully subscribed to minedblockExt_subscribeMinedblock");
                println!("✅ Successfully subscribed to minedblockExt_subscribeMinedblock");
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
                let message=SubscriptionMessage::new("subscribeMinedblock", SubscriptionId::Num(i as u64), &block);
                match message{
                    Ok(message)=>{
                        println!("✅ Successfully sent minedblockExt_subscribeMinedblock");
                        println!("✅ Successfully sent minedblockExt_subscribeMinedblock");
                        println!("✅ Successfully sent minedblockExt_subscribeMinedblock");
                        println!("✅ Successfully sent minedblockExt_subscribeMinedblock");
                        println!("✅ Successfully sent minedblockExt_subscribeMinedblock");
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
    fn submit_signature(&self, pubkey: Vec<u8>, signature: Vec<u8>) -> RpcResult<()> {
        println!("MinedblockExt 结构体地址: {:p}", self as *const _);
        println!("收到客户端签名上报: pubkey={:?}, signature={:?}", pubkey, signature);
        {
            let mut sigs = self.signatures.write().unwrap();
            sigs.push((pubkey.clone(), signature.clone()));
            println!("已保存(pubkey, signature)对, 当前数量: {}", sigs.len());
        }
        // self.print_signatures();
        Ok(())
    }
}




