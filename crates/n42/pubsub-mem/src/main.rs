// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use pubsub_mem::{Event, RouterMsg, publish, router_loop, subscribe};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber for logging
    fmt().with_max_level(tracing::Level::TRACE).init();

    // Create router control channel
    let (router_tx, router_rx) = mpsc::channel::<RouterMsg<String>>(128);

    // Spawn router loop task
    tokio::spawn(router_loop(router_rx));

    // --- Subscriber 1: listens to "blocks" ---
    let router_tx1 = router_tx.clone();
    tokio::spawn(async move {
        if let Ok((_id, mut rx)) = subscribe(router_tx1, "blocks".into()).await {
            while let Some(event) = rx.recv().await {
                println!("Subscriber 1 received: {:?}", event);
            }
        }
    });

    // --- Subscriber 2: listens to "txs" ---
    let router_tx2 = router_tx.clone();
    tokio::spawn(async move {
        if let Ok((_id, mut rx)) = subscribe(router_tx2, "txs".into()).await {
            while let Some(event) = rx.recv().await {
                println!("Subscriber 2 received: {:?}", event);
            }
        }
    });

    // --- Publisher task: alternates events ---
    let router_tx_pub = router_tx.clone();
    tokio::spawn(async move {
        for i in 0..10 {
            let topic = if i % 2 == 0 { "blocks" } else { "txs" };
            let event = Event {
                topic: topic.into(),
                payload: format!("event {}", i),
            };
            publish(&router_tx_pub, event).await;

            // Sleep a bit between events
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    // Let the program run long enough to see some events
    tokio::time::sleep(Duration::from_secs(3)).await;
}
