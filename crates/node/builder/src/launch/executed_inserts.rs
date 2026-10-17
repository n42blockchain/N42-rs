//! N42: a way for the node to hand the engine a block it has already executed.
//!
//! reth inserts the payloads its own builder produced without re-executing
//! them (`InsertExecutedBlock`), but only through the payload builder's event
//! stream, and only for payload types that carry an execution result -- the
//! Ethereum ones do not. On a chain where consensus seals the header after
//! the build, the sealed block is a different hash from the built one, so
//! the node has to make the pairing itself and hand the engine the result.
//! This is the channel it does that on; the engine loop in `engine.rs`
//! forwards each message as an `InsertExecutedBlock`.
//!
//! The block travels as `Box<dyn Any>` because this module has no way to
//! name the node's primitives; the loop downcasts to the type it inserts and
//! answers `false` on a mismatch.

use std::{
    any::Any,
    sync::{Mutex, OnceLock},
};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

/// One already-executed block for the engine, and where to say it went in.
#[derive(Debug)]
pub struct ExecutedInsert {
    /// A `BuiltPayloadExecutedBlock<N>` for the node's `N`.
    pub block: Box<dyn Any + Send>,
    /// `true` once the engine has been handed the block; `false` if it was
    /// not of the type the engine inserts.
    pub done: oneshot::Sender<bool>,
}

struct Channel {
    sender: UnboundedSender<ExecutedInsert>,
    receiver: Mutex<Option<UnboundedReceiver<ExecutedInsert>>>,
}

fn channel() -> &'static Channel {
    static CHANNEL: OnceLock<Channel> = OnceLock::new();
    CHANNEL.get_or_init(|| {
        let (sender, receiver) = unbounded_channel();
        Channel { sender, receiver: Mutex::new(Some(receiver)) }
    })
}

/// A sender into the engine loop. Messages sent before the engine has been
/// launched wait in the channel.
pub fn sender() -> UnboundedSender<ExecutedInsert> {
    channel().sender.clone()
}

/// The receiving end, once: the engine loop takes it at launch.
pub(crate) fn take_receiver() -> Option<UnboundedReceiver<ExecutedInsert>> {
    channel().receiver.lock().unwrap_or_else(|p| p.into_inner()).take()
}

/// Own blocks answered before their executed insert was sent
/// (`N42_STATE_READY_WITHOUT_MERGE`, docs/DELTA_LOG_DESIGN.md stage 1): the
/// tree does not hold such a block until its merged map lands and the insert
/// goes in. Until then a forkchoice naming it, and a `newPayload` (or another
/// executed insert) on top of it, waits here ([`wait_for_insert`]). Empty
/// unless the switch is on, and then every check is one atomic load.
pub mod pending {
    use alloy_primitives::B256;
    use std::{
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
            Mutex, OnceLock,
        },
        time::{Duration, Instant},
    };
    use tokio::sync::Notify;

    /// How long a held message waits for an insert before it is let through
    /// (and counted): a stall guard, the hand-off's own bound.
    pub const WAIT: Duration = Duration::from_secs(2);

    static COUNT: AtomicUsize = AtomicUsize::new(0);
    static HELD: AtomicU64 = AtomicU64::new(0);
    static HELD_US: AtomicU64 = AtomicU64::new(0);
    static HELD_MAX_US: AtomicU64 = AtomicU64::new(0);
    static TIMEOUTS: AtomicU64 = AtomicU64::new(0);

    fn set() -> &'static (Mutex<Vec<B256>>, Notify) {
        static SET: OnceLock<(Mutex<Vec<B256>>, Notify)> = OnceLock::new();
        SET.get_or_init(|| (Mutex::new(Vec::new()), Notify::new()))
    }

    fn contains(hash: B256) -> bool {
        COUNT.load(Relaxed) != 0 && set().0.lock().unwrap_or_else(|p| p.into_inner()).contains(&hash)
    }

    /// `hash` was answered and its executed insert is still to come.
    pub fn expect(hash: B256) {
        let mut pending = set().0.lock().unwrap_or_else(|p| p.into_inner());
        if !pending.contains(&hash) {
            pending.push(hash);
            COUNT.store(pending.len(), Relaxed);
        }
    }

    /// `hash`'s insert was forwarded to the tree (or given up): whatever
    /// waits on it goes on.
    pub fn landed(hash: B256) {
        let (pending, notify) = set();
        {
            let mut pending = pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.retain(|h| *h != hash);
            COUNT.store(pending.len(), Relaxed);
        }
        notify.notify_waiters();
    }

    /// Whether `hash`'s insert is still to come.
    pub fn is_pending(hash: B256) -> bool {
        contains(hash)
    }

    /// Waits until `hash` is not pending, up to [`WAIT`]. Returns how long it
    /// waited when it had to (`None`: not pending, no wait).
    pub async fn wait_for_insert(hash: B256) -> Option<Duration> {
        if !contains(hash) {
            return None;
        }
        let started = Instant::now();
        let deadline = started + WAIT;
        loop {
            // Created before the check: `notify_waiters` reaches it either way.
            let notified = set().1.notified();
            if !contains(hash) {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                TIMEOUTS.fetch_add(1, Relaxed);
                break;
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
        let waited = started.elapsed();
        let us = waited.as_micros() as u64;
        HELD.fetch_add(1, Relaxed);
        HELD_US.fetch_add(us, Relaxed);
        HELD_MAX_US.fetch_max(us, Relaxed);
        Some(waited)
    }

    /// What [`wait_for_insert`] held since the last call: how many waits,
    /// their total and longest us, and how many ran out of time.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct HeldCounts {
        /// Waits that found their block pending.
        pub held: u64,
        /// Their total wait, us.
        pub held_us: u64,
        /// The longest, us.
        pub held_max_us: u64,
        /// Waits that gave up at [`WAIT`].
        pub timeouts: u64,
    }

    /// [`HeldCounts`] since the last call, reset.
    pub fn take_counts() -> HeldCounts {
        HeldCounts {
            held: HELD.swap(0, Relaxed),
            held_us: HELD_US.swap(0, Relaxed),
            held_max_us: HELD_MAX_US.swap(0, Relaxed),
            timeouts: TIMEOUTS.swap(0, Relaxed),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn a_wait_ends_when_the_insert_lands() {
            let hash = B256::repeat_byte(0x5A);
            assert!(wait_for_insert(hash).await.is_none(), "nothing pending: no wait");
            expect(hash);
            assert!(is_pending(hash));
            let waiter = tokio::spawn(wait_for_insert(hash));
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(!waiter.is_finished(), "held while the insert is to come");
            landed(hash);
            let waited = waiter.await.unwrap().expect("it waited");
            assert!(waited >= Duration::from_millis(25) && waited < WAIT);
            assert!(!is_pending(hash));
        }
    }
}
