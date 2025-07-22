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
use alloy_primitives::hex::encode as hex_encode;

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
    /// Client submits signature data
    #[method(name = "submitSignature")]
    fn submit_signature(&self, pubkey: Vec<u8>, signature: Vec<u8>, receipt_root: Vec<u8>) -> RpcResult<()>;
}

pub struct MinedblockExt {
    // Add a channel to store subscribers
    subscribers: Arc<Mutex<Vec<SubscriptionSink>>>,
    pub unverifiedblock:UnverifiedBlock,
    pub agg_signature: std::sync::RwLock<Option<AggregateSignature>>,
    pub signatures: std::sync::RwLock<Vec<(Vec<u8>, Vec<u8>)>>, // New field to store (pubkey, signature)
    pub sig_receipts: std::sync::RwLock<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>, // New field to store (pubkey, signature, receipt_root)
}

impl Clone for MinedblockExt {
    fn clone(&self) -> Self {
        MinedblockExt {
            subscribers: self.subscribers.clone(),
            unverifiedblock: self.unverifiedblock.clone(),
            agg_signature: std::sync::RwLock::new(self.agg_signature.read().unwrap().clone()),
            signatures: std::sync::RwLock::new(self.signatures.read().unwrap().clone()),
            sig_receipts: std::sync::RwLock::new(self.sig_receipts.read().unwrap().clone()),
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
            sig_receipts: std::sync::RwLock::new(Vec::new()),
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
        println!("signatures cleared");
    }
    pub fn subscriber_count(&self) -> usize {
        // Since subscribers is Arc<Mutex<>>, asynchronous access is required, but here a synchronous method is provided for simple scenarios
        // It is recommended to use lock().await in asynchronous environments
        match self.subscribers.try_lock() {
            Ok(subs) => subs.len(),
            Err(_) => 0 // If the lock cannot be obtained, return 0 or customize the handling
        }
    }
    pub fn print_signatures(&self) {
        let sigs = self.signatures.read().unwrap();
        println!("Current signatures content: {:?}", *sigs);
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
    fn submit_signature(&self, pubkey: Vec<u8>, signature: Vec<u8>, receipt_root: Vec<u8>) -> RpcResult<()> {
        // 1. Print the received receipt_root (hex string)
        println!("Received client signature report: pubkey={:?}, signature={:?}", hex_encode(&pubkey), hex_encode(&signature));
        println!("Received receipt_root: 0x{}", hex_encode(&receipt_root));
        // Cache (pubkey, signature, receipt_root)
        {
            let mut sigs = self.sig_receipts.write().unwrap();
            sigs.push((pubkey.clone(), signature.clone(), receipt_root.clone()));
        }
        // Aggregate signatures
        use bls::{PublicKey, Signature, AggregateSignature, Hash256};
        let sigs = self.sig_receipts.read().unwrap();
        let mut agg_sig = AggregateSignature::infinity();
        let mut pubkeys = Vec::new();
        let mut msgs = Vec::new();
        for (pk_bytes, sig_bytes, root_bytes) in sigs.iter() {
            // Deserialize public key
            let pk = match PublicKey::deserialize(&pk_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("Public key deserialization failed: {:?}", e);
                    continue;
                }
            };
            // Deserialize signature
            let sig = match Signature::deserialize(&sig_bytes) {
                Ok(sig) => sig,
                Err(e) => {
                    println!("Signature deserialization failed: {:?}", e);
                    continue;
                }
            };
            // Organize message
            let msg = if root_bytes.len() == 32 {
                Hash256::from_slice(&root_bytes)
            } else {
                println!("receipt_root length error: {}", root_bytes.len());
                continue;
            };
            agg_sig.add_assign(&sig);
            pubkeys.push(pk);
            msgs.push(msg);
        }
        println!("Current aggregate signature (after serialization): 0x{}", hex_encode(&agg_sig.serialize()));
        // Verify aggregate signature
        let pubkey_refs: Vec<_> = pubkeys.iter().collect();
        let verify_result = agg_sig.aggregate_verify(&msgs, &pubkey_refs);
        println!("Aggregate signature verification result: {} (total signatures: {})", verify_result, sigs.len());
        Ok(())
    }
}




