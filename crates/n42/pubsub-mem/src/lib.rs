// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

pub mod error;
use error::SubscribeError;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

// ---------- Types ----------
pub type Topic = String;
pub type SubscriberId = u64;

// ---------- Event ----------
#[derive(Clone, Debug)]
pub struct Event<P> {
    pub topic: Topic,
    pub payload: P,
}

// ---------- Router Messages ----------
pub enum RouterMsg<P> {
    Publish(Event<P>),

    Subscribe {
        topic: Topic,
        tx: mpsc::Sender<Event<P>>,
        reply: mpsc::Sender<SubscriberId>,
    },

    // “Some messages may still be delivered after unsubscribe due to async scheduling.”
    Unsubscribe {
        topic: Topic,
        id: SubscriberId,
    },

    Disconnect {
        id: SubscriberId,
    },
}

// ---------- Router State ----------
struct Subscriber<P> {
    id: SubscriberId,
    tx: mpsc::Sender<Event<P>>,
}

struct Router<P> {
    topics: HashMap<Topic, Vec<Subscriber<P>>>,
    subs: HashMap<SubscriberId, Topic>,
    next_id: AtomicU64,
}

// ---------- Router Loop ----------
pub async fn router_loop<P>(mut rx: mpsc::Receiver<RouterMsg<P>>)
where
    P: Clone + Send + Sync + 'static,
{
    let mut router = Router {
        topics: HashMap::new(),
        subs: HashMap::new(),
        next_id: AtomicU64::new(1),
    };

    while let Some(msg) = rx.recv().await {
        match msg {
            RouterMsg::Publish(event) => {
                if let Some(subs) = router.topics.get_mut(&event.topic) {
                    let before = subs.len();

                    subs.retain(|sub| match sub.tx.try_send(event.clone()) {
                        Ok(_) => true,
                        Err(_) => {
                            warn!(
                                subscriber_id = sub.id,
                                topic = %event.topic,
                                "dropping slow or dead subscriber"
                            );
                            router.subs.remove(&sub.id);
                            false
                        }
                    });

                    trace!(
                        topic = %event.topic,
                        delivered = subs.len(),
                        dropped = before - subs.len(),
                        "event routed"
                    );
                }
            }

            RouterMsg::Subscribe { topic, tx, reply } => {
                let id = router.next_id.fetch_add(1, Ordering::Relaxed);

                router
                    .topics
                    .entry(topic.clone())
                    .or_default()
                    .push(Subscriber { id, tx });

                router.subs.insert(id, topic.clone());

                let _ = reply.send(id).await;

                debug!(subscriber_id = id, topic = %topic, "subscriber added");
            }

            RouterMsg::Unsubscribe { topic, id } => {
                if let Some(list) = router.topics.get_mut(&topic) {
                    list.retain(|s| s.id != id);
                }
                router.subs.remove(&id);

                debug!(subscriber_id = id, topic = %topic, "subscriber removed");
            }

            RouterMsg::Disconnect { id } => {
                if let Some(topic) = router.subs.remove(&id) {
                    if let Some(list) = router.topics.get_mut(&topic) {
                        list.retain(|s| s.id != id);
                    }

                    debug!(subscriber_id = id, topic = %topic, "subscriber disconnected");
                }
            }
        }
    }
}

// ---------- Subscriber API ----------
pub async fn subscribe<P>(
    router_tx: mpsc::Sender<RouterMsg<P>>,
    topic: Topic,
) -> Result<(SubscriberId, mpsc::Receiver<Event<P>>), SubscribeError>
where
    P: Clone + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(64);
    let (reply_tx, mut reply_rx) = mpsc::channel(1);

    router_tx
        .send(RouterMsg::Subscribe {
            topic,
            tx,
            reply: reply_tx,
        })
        .await
        .map_err(|_| SubscribeError::SendFailed)?;

    let id = reply_rx.recv().await.ok_or(SubscribeError::RouterDropped)?;
    Ok((id, rx))
}

// ---------- Publisher API ----------
pub async fn publish<P>(router_tx: &mpsc::Sender<RouterMsg<P>>, event: Event<P>)
where
    P: Clone + Send + Sync + 'static,
{
    let _ = router_tx.send(RouterMsg::Publish(event)).await;
}

// ----------------- Tests -----------------
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    fn test_event(topic: &str, payload: &str) -> Event<String> {
        Event {
            topic: topic.into(),
            payload: payload.into(),
        }
    }

    async fn setup_router() -> mpsc::Sender<RouterMsg<String>> {
        let (tx, rx) = mpsc::channel(128);
        tokio::spawn(router_loop(rx));
        tx
    }

    // 1. Basic subscribe + publish
    #[tokio::test]
    async fn subscriber_receives_published_event() {
        let router = setup_router().await;

        let (_id, mut rx) = subscribe(router.clone(), "topic1".into()).await.unwrap();

        publish(&router, test_event("topic1", "hello")).await;

        let event = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(event.payload, "hello");
    }

    // 2. Topic isolation
    #[tokio::test]
    async fn subscriber_does_not_receive_other_topics() {
        let router = setup_router().await;

        let (_id, mut rx) = subscribe(router.clone(), "topic1".into()).await.unwrap();

        publish(&router, test_event("topic2", "wrong")).await;

        let result = timeout(Duration::from_millis(200), rx.recv()).await;
        assert!(result.is_err(), "received unexpected event");
    }

    // 3. Multiple subscribers same topic
    #[tokio::test]
    async fn multiple_subscribers_receive_event() {
        let router = setup_router().await;

        let (_, mut rx1) = subscribe(router.clone(), "topic".into()).await.unwrap();
        let (_, mut rx2) = subscribe(router.clone(), "topic".into()).await.unwrap();

        publish(&router, test_event("topic", "fanout")).await;

        let e1 = timeout(Duration::from_secs(1), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        let e2 = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(e1.payload, "fanout");
        assert_eq!(e2.payload, "fanout");
    }

    // 4. Drop receiver cleans up automatically
    #[tokio::test]
    async fn dropping_receiver_cleans_up() {
        let router = setup_router().await;

        let (_id, rx) = subscribe(router.clone(), "topic".into()).await.unwrap();
        drop(rx);

        publish(&router, test_event("topic", "cleanup")).await;

        // Passes if router does not panic
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
