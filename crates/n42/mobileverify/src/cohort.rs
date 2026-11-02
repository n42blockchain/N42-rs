// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The height-driven receipt intake (`internal/mobileverify/coordinator.go`,
//! `DefaultCohortConfig` 1/2/3/5 blocks).
//!
//! A window opens on a block's first receipt with `opened_height` = the
//! receipt's (looked-up) block number. As committed heights arrive through
//! [`CohortCoordinator::on_block_committed`]:
//!
//! - at `N+1` intake closes (the collector is frozen; later receipts get
//!   `collection window closed`), gov5 announces its index set here;
//! - at `N+2` gov5 reveals the raw signatures;
//! - at `N+3` it reconciles, excludes devices counted at more than one node,
//!   and aggregates locally (one certificate per receipts root);
//! - at `N+5` same-root certificates are merged, the largest bucket is kept
//!   (ties: the smaller root) and stored, and losing buckets raise a
//!   divergence alarm.
//!
//! Single node first: the announce/reveal/reconcile rounds have no peers
//! here, so they reduce to the freeze and the local close. Peer
//! certificates enter through [`CohortCoordinator::on_peer_cert`] and are
//! merged at `N+5`.
// TODO(stage 2): index-commitment / reveal gossip and `ReconcileWithReveals`
// (`cohort_relay.go`, `reconcile_reveal.go`) for multi-node fleets.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use alloy_primitives::B256;
use parking_lot::Mutex;
use tracing::{debug, warn};

use crate::cert::{CertStore, MobileAttestationCert, merge_certs_at, select_majority_bucket};
use crate::collector::Collector;
use crate::error::MobileVerifyError;
use crate::gojson::{self, Obj};
use crate::receipt::Receipt;
use crate::registry::{MobileIndex, Registry, now_ms};

/// The bound on concurrently collecting blocks (`maxOpenWindows`).
pub const MAX_OPEN_WINDOWS: usize = 128;
/// The bound on distinct reporters per window (`maxReportersPerWindow`).
pub const MAX_REPORTERS_PER_WINDOW: usize = 256;
/// Alarms the node retains (`NewAlarmBuffer(256)` in `node.go`).
pub const DEFAULT_ALARM_CAPACITY: usize = 256;
/// Alarms `GET /mobileverify/alarms` returns.
pub const ALARMS_SERVED: usize = 100;

/// The node's chain view the mobile surface needs.
pub trait HeadSource: Send + Sync {
    /// The canonical head `(number, hash)`, `None` before there is one.
    fn head(&self) -> Option<(u64, B256)>;
    /// The number of any header the node has for `hash` (not only
    /// canonical; gov5 reads `ReadHeaderNumber`).
    fn number_of(&self, hash: &B256) -> Option<u64>;
}

/// The height offsets of the cohort phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CohortConfig {
    /// Blocks after open before intake closes (index announce).
    pub index_announce_delay: u64,
    /// Blocks after open before the reveal.
    pub reveal_delay: u64,
    /// Blocks after open before the local close.
    pub reconcile_delay: u64,
    /// Blocks after open before the merge and store.
    pub merge_delay: u64,
}

impl Default for CohortConfig {
    fn default() -> Self {
        Self { index_announce_delay: 1, reveal_delay: 2, reconcile_delay: 3, merge_delay: 5 }
    }
}

impl CohortConfig {
    /// gov5's `sane()`: strictly increasing checkpoints.
    pub const fn sane(mut self) -> Self {
        if self.index_announce_delay == 0 {
            self.index_announce_delay = 1;
        }
        if self.reveal_delay <= self.index_announce_delay {
            self.reveal_delay = self.index_announce_delay + 1;
        }
        if self.reconcile_delay <= self.reveal_delay {
            self.reconcile_delay = self.reveal_delay + 1;
        }
        if self.merge_delay <= self.reconcile_delay {
            self.merge_delay = self.reconcile_delay + 2;
        }
        self
    }
}

/// A divergent window: devices re-executed a block to disagreeing roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceAlarm {
    /// The block.
    pub block_hash: B256,
    /// Its number.
    pub block_number: u64,
    /// Number of root buckets (winner included).
    pub cohorts: usize,
    /// Unix ms the alarm was raised.
    pub at_ms: u64,
}

impl DivergenceAlarm {
    /// gov5's JSON (struct order: `blockHash`, `blockNumber`, `cohorts`, `atMs`).
    pub fn to_json(&self) -> String {
        Obj::new()
            .str("blockHash", &gojson::hex0x(self.block_hash.as_slice()))
            .num("blockNumber", self.block_number)
            .num("cohorts", self.cohorts as u64)
            .num("atMs", self.at_ms)
            .finish()
    }
}

/// A bounded ring of divergence alarms.
#[derive(Debug)]
pub struct AlarmBuffer {
    max: usize,
    items: Mutex<Vec<DivergenceAlarm>>,
}

impl Default for AlarmBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_ALARM_CAPACITY)
    }
}

impl AlarmBuffer {
    /// A buffer keeping the latest `max` alarms (0 means 256).
    pub const fn new(max: usize) -> Self {
        Self { max: if max == 0 { DEFAULT_ALARM_CAPACITY } else { max }, items: Mutex::new(Vec::new()) }
    }

    /// Records one alarm, evicting the oldest past capacity.
    pub fn record(&self, alarm: DivergenceAlarm) {
        let mut items = self.items.lock();
        items.push(alarm);
        if items.len() > self.max {
            let excess = items.len() - self.max;
            items.drain(..excess);
        }
    }

    /// Up to `n` alarms, newest first (`n == 0`: all).
    pub fn recent(&self, n: usize) -> Vec<DivergenceAlarm> {
        let items = self.items.lock();
        let n = if n == 0 || n > items.len() { items.len() } else { n };
        items.iter().rev().take(n).cloned().collect()
    }

    /// Number retained.
    pub fn len(&self) -> usize {
        self.items.lock().len()
    }

    /// Whether none is retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Divergence callback.
pub type DivergenceSink = Arc<dyn Fn(DivergenceAlarm) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Collecting,
    IndexAnnounced,
    Revealed,
    Reconciled,
    Final,
}

struct Window {
    block_number: u64,
    opened_height: u64,
    col: Arc<Collector>,
    phase: Phase,
    /// root → reporter → certificate (own entries under [`SELF_REPORTER`]).
    peer_certs: BTreeMap<B256, HashMap<[u8; 20], MobileAttestationCert>>,
}

impl Window {
    fn peer_cert_count(&self) -> usize {
        self.peer_certs.values().map(HashMap::len).sum()
    }
}

/// The reporter key this node files its own certificates under.
pub const SELF_REPORTER: [u8; 20] = [0u8; 20];

struct State {
    current_height: u64,
    windows: HashMap<B256, Window>,
    stopped: bool,
}

/// A wall clock in Unix milliseconds (injectable for reproducible
/// `windowClosedAt` / alarm timestamps).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The per-block certificate lifecycle, driven by committed heights.
pub struct CohortCoordinator {
    clock: Clock,
    reg: Arc<Registry>,
    head: Arc<dyn HeadSource>,
    certs: Arc<CertStore>,
    cfg: CohortConfig,
    self_reporter: [u8; 20],
    state: Mutex<State>,
    /// Serialises phase cascades so two height notifications never run one
    /// window's handlers concurrently (gov5's `inFlight` claim).
    cascade: Mutex<()>,
    on_divergence: Mutex<Option<DivergenceSink>>,
}

impl std::fmt::Debug for CohortCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.state.lock();
        f.debug_struct("CohortCoordinator")
            .field("cfg", &self.cfg)
            .field("height", &st.current_height)
            .field("open_windows", &st.windows.len())
            .finish()
    }
}

impl CohortCoordinator {
    /// A coordinator storing finalised certificates into `certs`.
    pub fn new(reg: Arc<Registry>, head: Arc<dyn HeadSource>, certs: Arc<CertStore>, cfg: CohortConfig) -> Self {
        Self {
            clock: Arc::new(now_ms),
            reg,
            head,
            certs,
            cfg: cfg.sane(),
            self_reporter: SELF_REPORTER,
            state: Mutex::new(State { current_height: 0, windows: HashMap::new(), stopped: false }),
            cascade: Mutex::new(()),
            on_divergence: Mutex::new(None),
        }
    }

    /// Sets the identity this node's own certificates are filed under
    /// (gov5 uses the validator address).
    pub const fn with_self_reporter(mut self, reporter: [u8; 20]) -> Self {
        self.self_reporter = reporter;
        self
    }

    /// Replaces the wall clock used for `windowClosedAt` and alarm times.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Installs the alarm callback.
    pub fn set_divergence_sink(&self, sink: DivergenceSink) {
        *self.on_divergence.lock() = Some(sink);
    }

    /// Routes alarms into `alarms`.
    pub fn record_alarms_into(&self, alarms: Arc<AlarmBuffer>) {
        self.set_divergence_sink(Arc::new(move |a| alarms.record(a)));
    }

    /// The registry this coordinator verifies against.
    pub const fn registry(&self) -> &Arc<Registry> {
        &self.reg
    }

    /// Routes one receipt into its block's window, opening it on the first
    /// receipt (gov5 `Submit`). Order: unknown block, number mismatch, then
    /// (for a block without a window) the key and signature, the open window
    /// cap, intake closed, then the collector's checks.
    ///
    /// A window opens only for an authenticated receipt (a registered key
    /// and a valid signature), so junk receipts for known hashes cannot fill
    /// [`MAX_OPEN_WINDOWS`]; gov5 opens first and checks after. The chain
    /// lookup and the signature check run outside the coordinator's lock.
    ///
    /// CPU-bound (a BLS pairing) and the chain lookup may read the database:
    /// call it from a blocking context, not from an async task's poll.
    pub fn submit(&self, r: &Receipt) -> Result<MobileIndex, MobileVerifyError> {
        let mut verified = false;
        let col = loop {
            {
                let mut st = self.state.lock();
                if st.stopped {
                    return Err(MobileVerifyError::WindowClosed);
                }
                if let Some(w) = st.windows.get(&r.block_hash) {
                    if w.phase != Phase::Collecting {
                        return Err(MobileVerifyError::WindowClosed);
                    }
                    break w.col.clone();
                }
                if verified {
                    if st.windows.len() >= MAX_OPEN_WINDOWS {
                        return Err(MobileVerifyError::TooManyWindows);
                    }
                    let col = Arc::new(Collector::new(self.reg.clone(), r.block_hash, r.block_number));
                    st.windows.insert(
                        r.block_hash,
                        Window {
                            block_number: r.block_number,
                            opened_height: r.block_number,
                            col: col.clone(),
                            phase: Phase::Collecting,
                            peer_certs: BTreeMap::new(),
                        },
                    );
                    break col;
                }
            }
            // No window yet: check the block and authenticate the receipt
            // with the lock released, then take it again to open one.
            let number = self.head.number_of(&r.block_hash).ok_or(MobileVerifyError::UnknownBlock)?;
            if number != r.block_number {
                return Err(MobileVerifyError::WrongBlockNumber { receipt: r.block_number, block: number });
            }
            self.reg.lookup(&r.verifier_pubkey).ok_or(MobileVerifyError::NotRegistered)?;
            r.verify_signature()?;
            verified = true;
        };
        let idx = col.add_checked(r, verified)?;
        self.reg.mark_active(&r.verifier_pubkey);
        Ok(idx)
    }

    /// Admits a peer's local certificate after verifying it (gov5
    /// `OnPeerCert`); dropped for unknown blocks or past the reporter cap.
    pub fn on_peer_cert(&self, reporter: [u8; 20], cert: MobileAttestationCert) {
        if let Err(e) = cert.verify(&self.reg) {
            debug!(target: "mobileverify", err = %e, "rejected invalid peer certificate");
            return;
        }
        let mut st = self.state.lock();
        let Some(w) = st.windows.get_mut(&cert.block_hash) else { return };
        if cert.block_number != w.block_number {
            return;
        }
        let exists = w.peer_certs.get(&cert.receipts_root).is_some_and(|m| m.contains_key(&reporter));
        if !exists && w.peer_cert_count() >= MAX_REPORTERS_PER_WINDOW {
            return;
        }
        w.peer_certs.entry(cert.receipts_root).or_default().insert(reporter, cert);
    }

    /// Advances every window whose next checkpoint `number` reaches. Call on
    /// every committed block.
    ///
    /// CPU-bound when a window closes or merges (signature aggregation and
    /// a certificate pairing): from async code use
    /// [`Self::on_block_committed_async`].
    pub fn on_block_committed(&self, number: u64) {
        let alarms = {
            let _guard = self.cascade.lock();
            let hashes: Vec<B256> = {
                let mut st = self.state.lock();
                st.current_height = st.current_height.max(number);
                st.windows.keys().copied().collect()
            };
            hashes.into_iter().filter_map(|hash| self.cascade_window(hash, false)).collect::<Vec<_>>()
        };
        self.fire(alarms);
    }

    /// [`Self::on_block_committed`] on tokio's blocking pool.
    pub async fn on_block_committed_async(self: &Arc<Self>, number: u64) {
        let this = self.clone();
        join_blocking(tokio::task::spawn_blocking(move || this.on_block_committed(number))).await;
    }

    /// Finalises every open window now, merging what was collected, and
    /// refuses further receipts.
    pub fn stop(&self) {
        let alarms = {
            let _guard = self.cascade.lock();
            let hashes: Vec<B256> = {
                let mut st = self.state.lock();
                st.stopped = true;
                st.windows.keys().copied().collect()
            };
            hashes.into_iter().filter_map(|hash| self.cascade_window(hash, true)).collect::<Vec<_>>()
        };
        self.fire(alarms);
    }

    /// [`Self::stop`] on tokio's blocking pool.
    pub async fn stop_async(self: &Arc<Self>) {
        let this = self.clone();
        join_blocking(tokio::task::spawn_blocking(move || this.stop())).await;
    }

    /// Hands alarms to the sink with no coordinator lock held, so the sink
    /// may call back into the coordinator.
    fn fire(&self, alarms: Vec<DivergenceAlarm>) {
        if alarms.is_empty() {
            return;
        }
        let sink = self.on_divergence.lock().clone();
        if let Some(sink) = sink {
            for alarm in alarms {
                sink(alarm);
            }
        }
    }

    /// Number of windows not yet finalised.
    pub fn open_windows(&self) -> usize {
        self.state.lock().windows.len()
    }

    fn next_due(&self, st: &State, w: &Window, force: bool) -> Option<Phase> {
        let h = st.current_height;
        let o = w.opened_height;
        let c = &self.cfg;
        let (next, at) = match w.phase {
            Phase::Collecting => (Phase::IndexAnnounced, c.index_announce_delay),
            Phase::IndexAnnounced => (Phase::Revealed, c.reveal_delay),
            Phase::Revealed => (Phase::Reconciled, c.reconcile_delay),
            Phase::Reconciled => (Phase::Final, c.merge_delay),
            Phase::Final => return None,
        };
        (force || h >= o.saturating_add(at)).then_some(next)
    }

    /// Runs `hash`'s due phases; returns the divergence alarm its merge
    /// raised, for the caller to fire once the cascade lock is released.
    fn cascade_window(&self, hash: B256, force: bool) -> Option<DivergenceAlarm> {
        loop {
            let (phase, col) = {
                let mut st = self.state.lock();
                let st = &mut *st;
                let w = st.windows.get(&hash)?;
                let next = self.next_due(st, w, force)?;
                let w = st.windows.get_mut(&hash)?;
                w.phase = next;
                (next, w.col.clone())
            };
            match phase {
                Phase::IndexAnnounced => {
                    col.freeze();
                }
                Phase::Revealed | Phase::Collecting => {}
                Phase::Reconciled => self.close_locally(hash, &col),
                Phase::Final => return self.merge_and_finalize(hash),
            }
        }
    }

    fn close_locally(&self, hash: B256, col: &Collector) {
        let local = col.close((self.clock)()).unwrap_or_else(|e| {
            warn!(target: "mobileverify", err = %e, "local close failed");
            Vec::new()
        });
        let mut st = self.state.lock();
        let Some(w) = st.windows.get_mut(&hash) else { return };
        for cert in local {
            w.peer_certs.entry(cert.receipts_root).or_default().insert(self.self_reporter, cert);
        }
    }

    fn merge_and_finalize(&self, hash: B256) -> Option<DivergenceAlarm> {
        let (per_root, block_number) = {
            let mut st = self.state.lock();
            let w = st.windows.remove(&hash)?;
            let per_root: Vec<(B256, Vec<MobileAttestationCert>)> =
                w.peer_certs.into_iter().map(|(root, m)| (root, m.into_values().collect())).collect();
            (per_root, w.block_number)
        };
        if per_root.is_empty() {
            return None;
        }
        // BTreeMap order: ascending root, gov5's sort before selection.
        let mut merged = Vec::with_capacity(per_root.len());
        for (root, certs) in per_root {
            match merge_certs_at(&certs, &self.reg, (self.clock)()) {
                Ok(m) => {
                    if !m.dropped_for_overlap.is_empty() {
                        warn!(target: "mobileverify", block = block_number, %root, dropped = m.dropped_for_overlap.len(), "certs conflicted at merge time");
                    }
                    merged.push(m.cert);
                }
                Err(e) => warn!(target: "mobileverify", block = block_number, %root, err = %e, "merge failed for a receipts-root bucket"),
            }
        }
        if merged.is_empty() {
            return None;
        }
        let bound = self.reg.index_bound();
        let (winner, discarded) = match select_majority_bucket(&merged, bound) {
            Ok(x) => x,
            Err(e) => {
                warn!(target: "mobileverify", block = block_number, err = %e, "majority-bucket selection failed");
                return None;
            }
        };
        if let Err(e) = winner.verify(&self.reg) {
            warn!(target: "mobileverify", block = block_number, err = %e, "merged certificate failed self-verification");
            return None;
        }
        self.certs.put(vec![winner]);
        if discarded.is_empty() {
            return None;
        }
        warn!(target: "mobileverify", block = block_number, %hash, buckets = discarded.len() + 1, "divergent attestation cohorts");
        Some(DivergenceAlarm { block_hash: hash, block_number, cohorts: discarded.len() + 1, at_ms: (self.clock)() })
    }
}

/// Awaits a blocking task, re-raising its panic.
async fn join_blocking(task: tokio::task::JoinHandle<()>) {
    if let Err(e) = task.await
        && e.is_panic()
    {
        std::panic::resume_unwind(e.into_panic());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKey;
    use parking_lot::RwLock;

    #[derive(Default)]
    struct Chain {
        blocks: RwLock<HashMap<B256, u64>>,
    }
    impl HeadSource for Chain {
        fn head(&self) -> Option<(u64, B256)> {
            None
        }
        fn number_of(&self, hash: &B256) -> Option<u64> {
            self.blocks.read().get(hash).copied()
        }
    }

    fn receipt(k: &DeviceKey, hash: B256, n: u64, root: B256) -> Receipt {
        Receipt {
            block_hash: hash,
            block_number: n,
            computed_receipts_root: root,
            verifier_pubkey: k.pubkey(),
            signature: k.sign_receipt(hash, n, root),
            timestamp_ms: 0,
        }
    }

    fn setup() -> (Arc<Registry>, Arc<Chain>, Arc<CertStore>, Vec<DeviceKey>) {
        let reg = Arc::new(Registry::new());
        let keys: Vec<_> = (1..=5u8).map(|i| DeviceKey::from_ikm(&[i; 32]).unwrap()).collect();
        for k in &keys {
            reg.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
        }
        reg.commit_epoch_at(1);
        (reg, Arc::new(Chain::default()), Arc::new(CertStore::new(512)), keys)
    }

    #[test]
    fn schedule_majority_and_alarm() {
        let (reg, chain, certs, keys) = setup();
        let h = B256::repeat_byte(0x10);
        chain.blocks.write().insert(h, 100);
        let co = CohortCoordinator::new(reg.clone(), chain, certs.clone(), CohortConfig::default());
        let alarms = Arc::new(AlarmBuffer::default());
        co.record_alarms_into(alarms.clone());

        assert_eq!(co.submit(&receipt(&keys[0], B256::ZERO, 100, B256::ZERO)).unwrap_err(), MobileVerifyError::UnknownBlock);
        assert_eq!(
            co.submit(&receipt(&keys[0], h, 99, B256::ZERO)).unwrap_err().to_string(),
            "mobileverify: receipt is for a different block: receipt number 99, block is 100"
        );
        let good = B256::repeat_byte(0xAA);
        let bad = B256::repeat_byte(0xBB);
        for k in &keys[..3] {
            co.submit(&receipt(k, h, 100, good)).unwrap();
        }
        co.submit(&receipt(&keys[3], h, 100, bad)).unwrap();
        assert_eq!(co.open_windows(), 1);

        co.on_block_committed(100);
        co.submit(&receipt(&keys[4], h, 100, bad)).unwrap();
        co.on_block_committed(101); // intake closes
        assert_eq!(co.submit(&receipt(&keys[4], h, 100, good)).unwrap_err(), MobileVerifyError::WindowClosed);
        co.on_block_committed(103); // local close
        assert!(certs.get(&h).is_empty());
        co.on_block_committed(104);
        assert_eq!(co.open_windows(), 1);
        co.on_block_committed(105); // merge and store
        assert_eq!(co.open_windows(), 0);
        let stored = certs.get(&h);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].receipts_root, good);
        assert_eq!(stored[0].verify(&reg).unwrap().len(), 3);
        let a = alarms.recent(ALARMS_SERVED);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].cohorts, 2);
        assert_eq!(a[0].block_number, 100);
    }

    #[test]
    fn jump_cascades_and_stop_flushes() {
        let (reg, chain, certs, keys) = setup();
        let h1 = B256::repeat_byte(1);
        let h2 = B256::repeat_byte(2);
        chain.blocks.write().extend([(h1, 10), (h2, 20)]);
        let co = CohortCoordinator::new(reg, chain, certs.clone(), CohortConfig::default());
        let r = B256::repeat_byte(7);
        co.submit(&receipt(&keys[0], h1, 10, r)).unwrap();
        co.submit(&receipt(&keys[1], h2, 20, r)).unwrap();
        co.on_block_committed(15); // h1 runs every phase in one call
        assert_eq!(certs.get(&h1).len(), 1);
        assert_eq!(co.open_windows(), 1);
        co.stop();
        assert_eq!(certs.get(&h2).len(), 1);
        assert_eq!(co.submit(&receipt(&keys[2], h2, 20, r)).unwrap_err(), MobileVerifyError::WindowClosed);
    }

    /// Runs `f` on a thread; fails instead of hanging if it deadlocks.
    fn within(f: impl FnOnce() + Send + 'static) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("deadlocked");
    }

    #[test]
    fn unauthenticated_receipts_open_no_window() {
        let (reg, chain, certs, keys) = setup();
        let h = B256::repeat_byte(0x30);
        chain.blocks.write().insert(h, 7);
        let co = CohortCoordinator::new(reg, chain, certs, CohortConfig::default());
        let stranger = DeviceKey::from_ikm(&[99; 32]).unwrap();
        let root = B256::repeat_byte(1);
        assert_eq!(co.submit(&receipt(&stranger, h, 7, root)).unwrap_err(), MobileVerifyError::NotRegistered);
        let mut forged = receipt(&keys[0], h, 7, root);
        forged.computed_receipts_root = B256::repeat_byte(2);
        assert_eq!(co.submit(&forged).unwrap_err(), MobileVerifyError::BadReceiptSignature);
        assert_eq!(co.open_windows(), 0);
        co.submit(&receipt(&keys[0], h, 7, root)).unwrap();
        assert_eq!(co.open_windows(), 1);
        // Once open, the collector's own checks answer, with gov5's texts.
        assert_eq!(co.submit(&receipt(&stranger, h, 7, root)).unwrap_err(), MobileVerifyError::NotRegistered);
    }

    /// A chain whose lookup reads the coordinator back, as a provider that
    /// takes its own locks could.
    struct Reentrant {
        inner: Chain,
        co: std::sync::OnceLock<std::sync::Weak<CohortCoordinator>>,
    }
    impl HeadSource for Reentrant {
        fn head(&self) -> Option<(u64, B256)> {
            None
        }
        fn number_of(&self, hash: &B256) -> Option<u64> {
            if let Some(co) = self.co.get().and_then(std::sync::Weak::upgrade) {
                let _ = co.open_windows();
            }
            self.inner.number_of(hash)
        }
    }

    #[test]
    fn chain_lookup_runs_outside_the_lock() {
        let (reg, _, certs, keys) = setup();
        let h = B256::repeat_byte(0x31);
        let chain = Arc::new(Reentrant { inner: Chain::default(), co: std::sync::OnceLock::new() });
        chain.inner.blocks.write().insert(h, 3);
        let co = Arc::new(CohortCoordinator::new(reg, chain.clone(), certs, CohortConfig::default()));
        let _ = chain.co.set(Arc::downgrade(&co));
        let k = keys[0].clone();
        within(move || {
            co.submit(&receipt(&k, h, 3, B256::ZERO)).unwrap();
            assert_eq!(co.open_windows(), 1);
        });
    }

    #[test]
    fn divergence_sink_may_call_back() {
        let (reg, chain, certs, keys) = setup();
        let h = B256::repeat_byte(0x32);
        chain.blocks.write().insert(h, 40);
        let co = Arc::new(CohortCoordinator::new(reg, chain, certs, CohortConfig::default()));
        let fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let weak = Arc::downgrade(&co);
        let count = fired.clone();
        co.set_divergence_sink(Arc::new(move |_| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(co) = weak.upgrade() {
                co.stop();
            }
        }));
        co.submit(&receipt(&keys[0], h, 40, B256::repeat_byte(1))).unwrap();
        co.submit(&receipt(&keys[1], h, 40, B256::repeat_byte(2))).unwrap();
        let co2 = co.clone();
        within(move || co2.on_block_committed(45));
        assert_eq!(fired.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(co.submit(&receipt(&keys[2], h, 40, B256::ZERO)).unwrap_err(), MobileVerifyError::WindowClosed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_variants_run_the_cascade() {
        let (reg, chain, certs, keys) = setup();
        let h = B256::repeat_byte(0x33);
        chain.blocks.write().insert(h, 60);
        let co = Arc::new(CohortCoordinator::new(reg, chain, certs.clone(), CohortConfig::default()));
        co.submit(&receipt(&keys[0], h, 60, B256::ZERO)).unwrap();
        co.on_block_committed_async(65).await;
        assert_eq!(certs.get(&h).len(), 1);
        co.stop_async().await;
        assert_eq!(co.submit(&receipt(&keys[0], h, 60, B256::ZERO)).unwrap_err(), MobileVerifyError::WindowClosed);
    }

    #[test]
    fn alarm_buffer_and_json() {
        let b = AlarmBuffer::new(2);
        for i in 1..=3u64 {
            b.record(DivergenceAlarm { block_hash: B256::ZERO, block_number: i, cohorts: 2, at_ms: i });
        }
        let r = b.recent(100);
        assert_eq!(r.iter().map(|a| a.block_number).collect::<Vec<_>>(), vec![3, 2]);
        assert_eq!(
            r[0].to_json(),
            format!("{{\"blockHash\":\"0x{}\",\"blockNumber\":3,\"cohorts\":2,\"atMs\":3}}", "00".repeat(32))
        );
    }

    #[test]
    fn config_sane() {
        let c = CohortConfig { index_announce_delay: 0, reveal_delay: 0, reconcile_delay: 0, merge_delay: 0 }.sane();
        assert_eq!(c, CohortConfig { index_announce_delay: 1, reveal_delay: 2, reconcile_delay: 3, merge_delay: 5 });
    }
}
