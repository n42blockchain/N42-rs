// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's `/mobileverify` phone surface on a validator (`--mobileverify.http`),
//! wired the way gov5's `startMobileVerify` (`internal/node/node.go`) wires it:
//!
//! * the HTTP server of [`n42_mobileverify::http`] on its own listener;
//! * the head `/latest` reports and the block lookup receipts are pinned to:
//!   the committed chain as [`crate::ServiceEvent::Committed`] reports it
//!   ([`CommittedHead`]), with every commit also advancing the cohort
//!   coordinator's height clock;
//! * the epoch committer: every `collect_window` the pending registrations
//!   are folded into the committed set (gov5 `EpochCommitter`), and the
//!   committed set is written to `<datadir>/mobileverify/registry.bin`.
//!   gov5 appends each commit's root to an anchor log in its chain database
//!   and does not persist the members; this node keeps the member snapshot
//!   itself (the format of `GET /mobileverify/snapshot`), so device indices
//!   survive a restart, and the root is recomputed from it on start;
//! * the gossip relay: packets and registrations from gov5's two topics (see
//!   [`n42_h2_net::MobileTopic`]) are validated here, off the consensus loop,
//!   and registrations this node admits are published.
//!
//! The leader's registry root reaches the payload attributes through
//! [`MobileVerify::registry_root`].

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use bytes::Bytes;
use n42_h2_net::MobileTopic;
use n42_mobileverify::cohort::{AlarmBuffer, DEFAULT_ALARM_CAPACITY};
use n42_mobileverify::{CertStore, CohortConfig, CohortCoordinator, HeadSource, PacketCache, Registry};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Gossip messages queued between the consensus loop and the relay task.
pub const GOSSIP_QUEUE: usize = 1024;

/// The snapshot file under the datadir.
pub const REGISTRY_FILE: &str = "mobileverify/registry.bin";

/// What `--mobileverify.*` configures.
#[derive(Debug, Clone)]
pub struct MobileVerifyConfig {
    /// The phone-facing listener.
    pub http: SocketAddr,
    /// Registration proof-of-work bits (0 = off).
    pub pow_bits: u32,
    /// Blocks of packets served (gov5 `packet_window`, 256).
    pub packet_window: u64,
    /// The epoch-commit interval (gov5 `collect_window_sec`, 45 s).
    pub collect_window: Duration,
    /// Blocks of certificates kept (gov5 `cert_blocks`, 512).
    pub cert_blocks: usize,
    /// Where the registry snapshot lives; `None` keeps it in memory only.
    pub datadir: Option<PathBuf>,
    /// This node's reporter identity for the cohort (its validator address).
    pub self_reporter: [u8; 20],
}

/// The committed chain as the mobile surface sees it: the head and a bounded
/// hash → number map of recent commits.
#[derive(Debug)]
pub struct CommittedHead {
    inner: RwLock<HeadInner>,
}

#[derive(Debug)]
struct HeadInner {
    head: Option<(u64, B256)>,
    numbers: HashMap<B256, u64>,
    order: VecDeque<B256>,
    cap: usize,
}

impl CommittedHead {
    /// Remembers the last `cap` committed blocks.
    pub fn new(cap: usize) -> Self {
        Self {
            inner: RwLock::new(HeadInner { head: None, numbers: HashMap::new(), order: VecDeque::new(), cap: cap.max(1) }),
        }
    }

    /// Records a commit; the head moves only forward.
    pub fn record(&self, number: u64, hash: B256) {
        let mut inner = self.inner.write();
        if inner.head.is_none_or(|(n, _)| number >= n) {
            inner.head = Some((number, hash));
        }
        Self::remember_locked(&mut inner, number, hash);
    }

    /// Learns a block's number without moving the head: a header this node
    /// holds before its commit (a relayed packet carries one, hash-checked).
    /// gov5 pins receipts to any header it has (`ReadHeaderNumber`), so a
    /// receipt that races the commit is not refused as unknown.
    pub fn remember(&self, number: u64, hash: B256) {
        Self::remember_locked(&mut self.inner.write(), number, hash);
    }

    fn remember_locked(inner: &mut HeadInner, number: u64, hash: B256) {
        if inner.numbers.insert(hash, number).is_none() {
            inner.order.push_back(hash);
        }
        while inner.order.len() > inner.cap {
            if let Some(old) = inner.order.pop_front() {
                inner.numbers.remove(&old);
            }
        }
    }
}

impl HeadSource for CommittedHead {
    fn head(&self) -> Option<(u64, B256)> {
        self.inner.read().head
    }

    fn number_of(&self, hash: &B256) -> Option<u64> {
        self.inner.read().numbers.get(hash).copied()
    }
}

/// The running surface: what the validator's loop talks to.
#[derive(Debug)]
pub struct MobileVerify {
    registry: Arc<Registry>,
    coordinator: Arc<CohortCoordinator>,
    head: Arc<CommittedHead>,
}

/// The two channel ends the service needs: inbound gossip goes to the relay
/// task, outbound gossip (this node's registrations) comes from it.
#[derive(Debug)]
pub struct MobileGossipChannels {
    /// Where the service forwards messages from the two topics.
    pub inbound: mpsc::Sender<(MobileTopic, Vec<u8>)>,
    /// What the service publishes on them.
    pub outbound: mpsc::Receiver<(MobileTopic, Vec<u8>)>,
}

impl MobileVerify {
    /// Binds the listener and starts the server, the epoch committer and the
    /// relay task on the current runtime.
    pub async fn start(cfg: MobileVerifyConfig) -> std::io::Result<(Self, MobileGossipChannels)> {
        let registry = Arc::new(Registry::new());
        let snapshot = cfg.datadir.as_ref().map(|dir| dir.join(REGISTRY_FILE));
        if let Some(path) = &snapshot {
            match std::fs::read(path) {
                Ok(data) => match registry.import_committed(&data) {
                    Ok(root) => info!(
                        target: "mobileverify",
                        count = registry.index_bound(), %root, path = %path.display(),
                        "restored the committed registry"
                    ),
                    Err(err) => {
                        return Err(std::io::Error::other(format!("{}: {err}", path.display())));
                    }
                },
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        let packets = Arc::new(PacketCache::new(cfg.packet_window));
        let certs = Arc::new(CertStore::new(cfg.cert_blocks));
        let head = Arc::new(CommittedHead::new(
            usize::try_from(cfg.packet_window).unwrap_or(usize::MAX).saturating_add(cfg.cert_blocks),
        ));
        let alarms = Arc::new(AlarmBuffer::new(DEFAULT_ALARM_CAPACITY));
        let coordinator = Arc::new(
            CohortCoordinator::new(registry.clone(), head.clone(), certs.clone(), CohortConfig::default())
                .with_self_reporter(cfg.self_reporter),
        );
        coordinator.record_alarms_into(alarms.clone());

        // Registrations this node admits go to the fleet, as gov5's
        // registration service publishes them.
        let (out_tx, out_rx) = mpsc::channel(GOSSIP_QUEUE);
        {
            let out_tx = out_tx.clone();
            registry.set_on_register(Arc::new(move |pubkey, pop| {
                let payload = n42_mobileverify::topics::registration_payload(pubkey, pop).to_vec();
                if out_tx.try_send((MobileTopic::Registration, payload)).is_err() {
                    debug!(target: "mobileverify", "registration gossip queue full; not relayed");
                }
            }));
        }

        let listener = tokio::net::TcpListener::bind(cfg.http).await?;
        let service = Arc::new(n42_mobileverify::Service::new(
            registry.clone(),
            packets.clone(),
            coordinator.clone(),
            certs,
            alarms,
            head.clone(),
            n42_mobileverify::ServiceConfig { pow_bits: cfg.pow_bits, ..Default::default() },
        ));
        tokio::spawn(n42_mobileverify::serve(listener, service, std::future::pending()));

        tokio::spawn(commit_epochs(registry.clone(), cfg.collect_window, snapshot));

        let (in_tx, in_rx) = mpsc::channel(GOSSIP_QUEUE);
        tokio::spawn(relay(in_rx, registry.clone(), packets, head.clone()));

        info!(
            target: "mobileverify",
            http = %cfg.http, window = cfg.packet_window, pow_bits = cfg.pow_bits,
            epoch_s = cfg.collect_window.as_secs(), "mobile verification surface enabled"
        );
        Ok((Self { registry, coordinator, head }, MobileGossipChannels { inbound: in_tx, outbound: out_rx }))
    }

    /// A committed block: the head for `/latest`, the lookup for receipts,
    /// and the cohort's height clock.
    /// The cohort cascade (aggregation pairings) runs on the blocking pool,
    /// never on the consensus loop; must be called inside the runtime.
    pub fn on_commit(&self, number: u64, hash: B256) {
        self.head.record(number, hash);
        let coordinator = self.coordinator.clone();
        tokio::spawn(async move { coordinator.on_block_committed_async(number).await });
    }

    /// The committed accumulator root the leader names in its payload
    /// attributes (gov5's `SetMobileAnchorRoot` provider).
    pub fn registry_root(&self) -> B256 {
        self.registry.root()
    }

    /// The registry, for tests and status.
    pub const fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }
}

/// gov5's `EpochCommitter`: fold the pending set every `every`, persist and
/// log what changed.
async fn commit_epochs(registry: Arc<Registry>, every: Duration, snapshot: Option<PathBuf>) {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every.max(Duration::from_secs(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let (root, added) = registry.commit_epoch();
        if added == 0 {
            continue;
        }
        info!(target: "mobileverify", added, count = registry.index_bound(), %root, "registry epoch committed");
        if let Some(path) = &snapshot
            && let Err(err) = write_snapshot(path, &registry.export_committed())
        {
            warn!(target: "mobileverify", path = %path.display(), %err, "could not persist the registry snapshot");
        }
    }
}

/// Writes `data` to `path` through a temporary file and a rename, so a crash
/// leaves the previous snapshot or the new one, never half of one.
pub fn write_snapshot(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Validates what the two topics deliver: a packet against the window around
/// the committed head (gov5 `packetservice.go`), a registration by its proof
/// of possession (`replication.go`).
async fn relay(
    mut inbound: mpsc::Receiver<(MobileTopic, Vec<u8>)>,
    registry: Arc<Registry>,
    packets: Arc<PacketCache>,
    head: Arc<CommittedHead>,
) {
    while let Some((topic, data)) = inbound.recv().await {
        match topic {
            MobileTopic::Packet => {
                let at = head.head().map(|(n, _)| n);
                match packets.validate_incoming(Bytes::from(data), at) {
                    Ok((hash, number, new)) => {
                        head.remember(number, hash);
                        debug!(target: "mobileverify", %hash, number, new, "relayed packet cached");
                    }
                    Err(err) => debug!(target: "mobileverify", %err, "dropped a gossiped packet"),
                }
            }
            MobileTopic::Registration => {
                let Some((pubkey, pop)) = n42_mobileverify::topics::parse_registration_payload(&data) else {
                    debug!(target: "mobileverify", len = data.len(), "dropped a malformed registration");
                    continue;
                };
                // A proof of possession takes a pairing: off the runtime's
                // async workers.
                let registry = registry.clone();
                match tokio::task::spawn_blocking(move || registry.adopt_pending(&pubkey, &pop)).await {
                    Ok(Ok(new)) => debug!(target: "mobileverify", new, "gossiped registration admitted"),
                    Ok(Err(err)) => debug!(target: "mobileverify", %err, "dropped a gossiped registration"),
                    Err(err) => debug!(target: "mobileverify", %err, "registration check did not finish"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_head_moves_forward_and_forgets_old_blocks() {
        let head = CommittedHead::new(2);
        assert_eq!(head.head(), None);
        head.record(5, B256::repeat_byte(5));
        head.record(4, B256::repeat_byte(4));
        assert_eq!(head.head(), Some((5, B256::repeat_byte(5))), "the head never moves back");
        head.record(6, B256::repeat_byte(6));
        assert_eq!(head.number_of(&B256::repeat_byte(5)), None, "only the last two are kept");
        assert_eq!(head.number_of(&B256::repeat_byte(4)), Some(4));
        assert_eq!(head.number_of(&B256::repeat_byte(6)), Some(6));
        assert_eq!(head.head(), Some((6, B256::repeat_byte(6))));
        head.remember(9, B256::repeat_byte(9));
        assert_eq!(head.number_of(&B256::repeat_byte(9)), Some(9), "a known header is looked up");
        assert_eq!(head.head(), Some((6, B256::repeat_byte(6))), "but does not move the head");
    }

    #[test]
    fn the_snapshot_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("n42-mv-snap-{}", std::process::id()));
        let path = dir.join(REGISTRY_FILE);
        let reg = Registry::new();
        let key = n42_mobileverify::DeviceKey::from_ikm(&[7u8; 32]).expect("key");
        reg.register(&key.pubkey(), &key.proof_of_possession()).expect("registers");
        let (root, added) = reg.commit_epoch();
        assert_eq!(added, 1);
        write_snapshot(&path, &reg.export_committed()).expect("writes");
        let back = Registry::new();
        assert_eq!(back.import_committed(&std::fs::read(&path).expect("reads")).expect("imports"), root);
        assert_eq!(back.lookup(&key.pubkey()), Some(0));
        let _ = std::fs::remove_dir_all(dir);
    }
}
