// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A node-internal CPU layout (`N42_CORE_LAYOUT=isolate`, off by default).
//!
//! The fleet pins each node to a set of whole physical cores with `taskset`;
//! inside that set nothing was pinned, so the build pool's memory-bound
//! batches shared physical cores with the SMT siblings of tokio, the storage
//! pool, the merge, persistence and jemalloc's purging (`docs/BREAKTHROUGH_DESIGN.md`
//! 10.13, 10.21). This crate splits the node's own affinity mask, by its SMT
//! topology, into three sets computed once:
//!
//! - **build**: the first `N42_CORE_LAYOUT_BUILD_CORES` physical cores (16 by
//!   default), for the build pool. One logical CPU a core with the sibling
//!   left empty, or both siblings with `N42_CORE_LAYOUT_BUILD_SIBLINGS=1`
//!   (the build's own threads are then each other's only neighbours).
//! - **critical**: the next `N42_CORE_LAYOUT_CRITICAL_CORES` physical cores
//!   (4 by default), one logical CPU each with the sibling left empty, for the
//!   other threads on a block's chain: the follower's root and vote-check
//!   pools and the leader's QMDB root job. With 0 they share the build set.
//! - **background**: every logical CPU of the remaining cores, both siblings.
//!
//! [`init`] (called first thing in the node's `main`) moves every thread the
//! process has to the background set; threads created afterwards inherit their
//! creator's mask, so tokio, reth's rayon pools, persistence, the engine and
//! jemalloc's background threads all stay there without a hook. The critical
//! pools pin their own threads ([`pin_current_thread`] from a rayon
//! `start_handler`), and helpers that a critical thread may spawn call
//! [`background_thread`] to step back out.
//!
//! `N42_BACKGROUND_NICE=<1..19|idle>` lowers the priority of the background
//! work that has no deadline of its own (merges, persistence, prefault /
//! populate / release threads, the ingest's recovery), independent of the
//! layout: when the background set is oversubscribed, tokio and the engine
//! run first.

use std::{collections::BTreeMap, fmt, sync::OnceLock};

/// The physical cores the build pool gets by default.
pub const DEFAULT_BUILD_CORES: usize = 16;
/// The physical cores the other critical threads get by default.
pub const DEFAULT_CRITICAL_CORES: usize = 4;
/// The fewest logical CPUs the background set may be left with.
pub const DEFAULT_MIN_BACKGROUND_CPUS: usize = 4;

/// One of the layout's CPU sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Set {
    /// The build pool's threads.
    Build,
    /// The other critical threads: the follower's root and vote-check pools,
    /// the leader's QMDB root job.
    Critical,
    /// Everything else.
    Background,
}

/// How the mask is split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Physical cores for the build pool.
    pub build_cores: usize,
    /// Whether the build pool also takes its cores' SMT siblings.
    pub build_siblings: bool,
    /// Physical cores for the other critical threads (0: they share the build set).
    pub critical_cores: usize,
    /// The fewest logical CPUs the background set may be left with.
    pub min_background_cpus: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            build_cores: DEFAULT_BUILD_CORES,
            build_siblings: false,
            critical_cores: DEFAULT_CRITICAL_CORES,
            min_background_cpus: DEFAULT_MIN_BACKGROUND_CPUS,
        }
    }
}

impl Config {
    /// The split from `N42_CORE_LAYOUT_BUILD_CORES`,
    /// `N42_CORE_LAYOUT_BUILD_SIBLINGS` and `N42_CORE_LAYOUT_CRITICAL_CORES`.
    pub fn from_env() -> Self {
        let num = |var: &str| std::env::var(var).ok().and_then(|v| v.trim().parse::<usize>().ok());
        let defaults = Self::default();
        Self {
            build_cores: num("N42_CORE_LAYOUT_BUILD_CORES").filter(|n| *n > 0).unwrap_or(defaults.build_cores),
            build_siblings: std::env::var("N42_CORE_LAYOUT_BUILD_SIBLINGS").is_ok_and(|v| v == "1"),
            critical_cores: num("N42_CORE_LAYOUT_CRITICAL_CORES").unwrap_or(defaults.critical_cores),
            min_background_cpus: defaults.min_background_cpus,
        }
    }
}

/// The three sets, as logical CPU numbers in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The build pool's CPUs.
    pub build: Vec<usize>,
    /// The other critical threads' CPUs (empty: they share `build`).
    pub critical: Vec<usize>,
    /// Everything else's CPUs.
    pub background: Vec<usize>,
    /// The siblings left empty beside the build and critical CPUs.
    pub idle: Vec<usize>,
    /// Whether the build set holds its cores' siblings too.
    pub build_siblings: bool,
}

impl Layout {
    /// The CPUs of `set`.
    pub fn cpus(&self, set: Set) -> &[usize] {
        match set {
            Set::Build => &self.build,
            Set::Critical if self.critical.is_empty() => &self.build,
            Set::Critical => &self.critical,
            Set::Background => &self.background,
        }
    }

    /// A short tag for log lines: `b16/c4/bg34` (`b16x2` when the build set
    /// holds its siblings).
    pub fn tag(&self) -> String {
        let cores = if self.build_siblings { self.build.len() / 2 } else { self.build.len() };
        let siblings = if self.build_siblings { "x2" } else { "" };
        format!("b{cores}{siblings}/c{}/bg{}", self.critical.len(), self.background.len())
    }
}

/// Why a mask could not be laid out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// The affinity mask is empty or could not be read.
    EmptyMask,
    /// Fewer physical cores than the build and critical sets plus one.
    TooFewCores {
        /// Physical cores in the mask.
        have: usize,
        /// Physical cores the layout needs.
        need: usize,
    },
    /// The background set would be smaller than its floor.
    TooFewBackground {
        /// Logical CPUs left for the background.
        have: usize,
        /// The floor.
        need: usize,
    },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMask => write!(f, "the affinity mask is empty"),
            Self::TooFewCores { have, need } => {
                write!(f, "{have} physical cores in the affinity mask, the layout needs {need}")
            }
            Self::TooFewBackground { have, need } => {
                write!(f, "{have} logical CPUs left for the background, the layout needs {need}")
            }
        }
    }
}

impl std::error::Error for LayoutError {}

/// Parses a kernel CPU list (`0,128`, `3-4`, `0-7,64-71`).
pub fn parse_cpu_list(list: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in list.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (lo.trim().parse::<usize>().ok()?, hi.trim().parse::<usize>().ok()?);
                if hi < lo {
                    return None;
                }
                cpus.extend(lo..=hi);
            }
            None => cpus.push(part.trim().parse().ok()?),
        }
    }
    Some(cpus)
}

/// Formats CPUs as a kernel CPU list, ranges collapsed.
pub fn format_cpu_list(cpus: &[usize]) -> String {
    let mut sorted = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            i += 1;
            end = sorted[i];
        }
        out.push(if start == end { start.to_string() } else { format!("{start}-{end}") });
        i += 1;
    }
    if out.is_empty() {
        "-".to_string()
    } else {
        out.join(",")
    }
}

/// The mask's physical cores: its CPUs grouped by the lowest CPU of their
/// sibling list (`siblings` answers a CPU's full list, `None` if unknown: the
/// CPU is then a core of its own), cores in ascending order, each core's
/// CPUs in ascending order. Siblings outside the mask are not counted.
pub fn physical_cores(mask: &[usize], siblings: impl Fn(usize) -> Option<Vec<usize>>) -> Vec<Vec<usize>> {
    let mut cores: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &cpu in mask {
        let key = siblings(cpu).and_then(|list| list.into_iter().min()).unwrap_or(cpu).min(cpu);
        cores.entry(key).or_default().push(cpu);
    }
    cores
        .into_values()
        .map(|mut cpus| {
            cpus.sort_unstable();
            cpus.dedup();
            cpus
        })
        .collect()
}

/// Splits `mask` into the layout's sets (see the crate's docs).
pub fn compute(
    mask: &[usize],
    siblings: impl Fn(usize) -> Option<Vec<usize>>,
    config: &Config,
) -> Result<Layout, LayoutError> {
    if mask.is_empty() {
        return Err(LayoutError::EmptyMask);
    }
    let cores = physical_cores(mask, siblings);
    let need = config.build_cores + config.critical_cores + 1;
    if config.build_cores == 0 || cores.len() < need {
        return Err(LayoutError::TooFewCores { have: cores.len(), need });
    }
    let (build_cores, rest) = cores.split_at(config.build_cores);
    let (critical_cores, background_cores) = rest.split_at(config.critical_cores);
    let mut layout = Layout {
        build: Vec::new(),
        critical: Vec::new(),
        background: background_cores.iter().flatten().copied().collect(),
        idle: Vec::new(),
        build_siblings: config.build_siblings,
    };
    for core in build_cores {
        if config.build_siblings {
            layout.build.extend_from_slice(core);
        } else if let Some((first, others)) = core.split_first() {
            layout.build.push(*first);
            layout.idle.extend_from_slice(others);
        }
    }
    for core in critical_cores {
        if let Some((first, others)) = core.split_first() {
            layout.critical.push(*first);
            layout.idle.extend_from_slice(others);
        }
    }
    if layout.background.len() < config.min_background_cpus {
        return Err(LayoutError::TooFewBackground { have: layout.background.len(), need: config.min_background_cpus });
    }
    for set in [&mut layout.build, &mut layout.critical, &mut layout.background, &mut layout.idle] {
        set.sort_unstable();
    }
    Ok(layout)
}

/// A CPU's sibling list from sysfs, `None` if it cannot be read.
pub fn sysfs_siblings(cpu: usize) -> Option<Vec<usize>> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    std::fs::read_to_string(path).ok().and_then(|list| parse_cpu_list(&list))
}

#[cfg(target_os = "linux")]
fn cpu_set_of(cpus: &[usize]) -> std::io::Result<libc::cpu_set_t> {
    // SAFETY: cpu_set_t is a plain bit array; all-zero is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let bits = 8 * std::mem::size_of::<libc::cpu_set_t>();
    for &cpu in cpus {
        if cpu >= bits {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("cpu {cpu} beyond the set")));
        }
        // SAFETY: cpu is within the set's bit range, checked above.
        unsafe { libc::CPU_SET(cpu, &mut set) };
    }
    Ok(set)
}

/// The CPUs the calling thread may run on.
#[cfg(target_os = "linux")]
pub fn current_thread_cpus() -> std::io::Result<Vec<usize>> {
    // SAFETY: as in `cpu_set_of`.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: sched_getaffinity fills a cpu_set_t of the size given.
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw mut set) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bits = 8 * std::mem::size_of::<libc::cpu_set_t>();
    // SAFETY: every cpu tested is within the set's bit range.
    Ok((0..bits).filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) }).collect())
}

/// The CPUs the calling thread may run on (unsupported off Linux).
#[cfg(not(target_os = "linux"))]
pub fn current_thread_cpus() -> std::io::Result<Vec<usize>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "thread affinity"))
}

/// Restricts thread `tid` (0: the calling thread) to `cpus`.
#[cfg(target_os = "linux")]
pub fn pin_thread_to(tid: libc::pid_t, cpus: &[usize]) -> std::io::Result<()> {
    if cpus.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "an empty CPU set"));
    }
    let set = cpu_set_of(cpus)?;
    // SAFETY: sched_setaffinity reads a cpu_set_t of the size given.
    if unsafe { libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &raw const set) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Restricts the calling thread to `cpus`.
#[cfg(target_os = "linux")]
pub fn pin_current_thread_to(cpus: &[usize]) -> std::io::Result<()> {
    pin_thread_to(0, cpus)
}

/// Restricts the calling thread to `cpus` (unsupported off Linux).
#[cfg(not(target_os = "linux"))]
pub fn pin_current_thread_to(_cpus: &[usize]) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "thread affinity"))
}

/// What the process runs under.
#[derive(Debug)]
enum State {
    /// `N42_CORE_LAYOUT` is not `isolate`.
    Off,
    /// Asked for, but the mask could not be laid out: nothing is pinned.
    Fallback(String),
    /// The layout in force.
    On(Layout),
}

fn state() -> &'static State {
    static STATE: OnceLock<State> = OnceLock::new();
    STATE.get_or_init(|| {
        if !std::env::var("N42_CORE_LAYOUT").is_ok_and(|v| v == "isolate") {
            return State::Off;
        }
        let mask = match current_thread_cpus() {
            Ok(mask) => mask,
            Err(err) => return State::Fallback(format!("the affinity mask could not be read: {err}")),
        };
        match compute(&mask, sysfs_siblings, &Config::from_env()) {
            Ok(layout) => State::On(layout),
            Err(err) => State::Fallback(format!("{err} (mask {})", format_cpu_list(&mask))),
        }
    })
}

/// The layout in force, `None` when it is off or fell back.
pub fn layout() -> Option<&'static Layout> {
    match state() {
        State::On(layout) => Some(layout),
        _ => None,
    }
}

/// The tag log lines carry under `core_layout=`: `off`, `fallback`, or the
/// layout's [`Layout::tag`].
pub fn label() -> &'static str {
    static LABEL: OnceLock<String> = OnceLock::new();
    LABEL.get_or_init(|| match state() {
        State::Off => "off".to_string(),
        State::Fallback(_) => "fallback".to_string(),
        State::On(layout) => layout.tag(),
    })
}

/// Logs the layout once: INFO with the sets, or one WARN when it fell back.
pub fn log_once() {
    static LOGGED: std::sync::Once = std::sync::Once::new();
    LOGGED.call_once(|| match state() {
        State::Off => {}
        State::Fallback(why) => {
            tracing::warn!(target: "n42::core_layout", %why, "core layout: not enough CPUs, nothing pinned")
        }
        State::On(layout) => tracing::info!(
            target: "n42::core_layout",
            "core layout: build={} critical={} background={} idle={} nice={}",
            format_cpu_list(&layout.build),
            format_cpu_list(layout.cpus(Set::Critical)),
            format_cpu_list(&layout.background),
            format_cpu_list(&layout.idle),
            background_priority().map_or_else(|| "-".to_string(), |p| p.to_string()),
        ),
    });
}

/// Computes the layout from the calling thread's mask (call it first thing
/// in `main`, before any thread is spawned) and moves every thread the
/// process already has to the background set; later threads inherit it.
/// Returns the layout in force.
pub fn init() -> Option<&'static Layout> {
    let layout = layout()?;
    #[cfg(target_os = "linux")]
    {
        static SWEPT: std::sync::Once = std::sync::Once::new();
        SWEPT.call_once(|| {
            for tid in process_threads() {
                // A thread that ended meanwhile is no error.
                let _ = pin_thread_to(tid, &layout.background);
            }
        });
    }
    Some(layout)
}

/// Pins the calling thread to `set` when the layout is on. `Ok(false)` when
/// it is off (nothing changed).
pub fn pin_current_thread(set: Set) -> std::io::Result<bool> {
    let Some(layout) = layout() else { return Ok(false) };
    log_once();
    pin_current_thread_to(layout.cpus(set))?;
    Ok(true)
}

/// [`pin_current_thread`] for a thread start hook: a failure is logged, not
/// returned.
pub fn enter(set: Set) {
    if let Err(err) = pin_current_thread(set) {
        tracing::debug!(target: "n42::core_layout", %err, ?set, "could not pin a thread");
    }
}

/// For a helper thread with no deadline of its own (a merge, a release, a
/// prefault): back to the background set when the layout is on -- it may have
/// been spawned from a critical thread -- and at the background priority
/// when `N42_BACKGROUND_NICE` is set.
pub fn background_thread() {
    enter(Set::Background);
    lower_current_thread_priority();
}

/// A background priority (`N42_BACKGROUND_NICE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// `nice` 1-19.
    Nice(i32),
    /// `SCHED_IDLE`: runs only when nothing else on the CPU wants to.
    Idle,
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nice(n) => write!(f, "{n}"),
            Self::Idle => write!(f, "idle"),
        }
    }
}

/// Parses an `N42_BACKGROUND_NICE` value: `idle`, or 1-19 (clamped).
pub fn parse_priority(value: &str) -> Option<Priority> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("idle") {
        return Some(Priority::Idle);
    }
    value.parse::<i32>().ok().filter(|n| *n > 0).map(|n| Priority::Nice(n.min(19)))
}

/// `N42_BACKGROUND_NICE`, read once; `None` when unset (no change).
pub fn background_priority() -> Option<Priority> {
    static PRIORITY: OnceLock<Option<Priority>> = OnceLock::new();
    *PRIORITY.get_or_init(|| std::env::var("N42_BACKGROUND_NICE").ok().and_then(|v| parse_priority(&v)))
}

/// Sets thread `tid` (0: the calling thread) to `priority`.
#[cfg(target_os = "linux")]
pub fn set_thread_priority(tid: libc::pid_t, priority: Priority) -> std::io::Result<()> {
    let tid = if tid == 0 {
        // SAFETY: gettid takes no arguments and cannot fail.
        unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
    } else {
        tid
    };
    // SAFETY: setpriority / sched_setscheduler on one thread id are plain
    // syscalls; the param is a valid struct for the duration of the call.
    let rc = unsafe {
        match priority {
            Priority::Nice(n) => libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, n),
            Priority::Idle => {
                let param = libc::sched_param { sched_priority: 0 };
                libc::sched_setscheduler(tid, libc::SCHED_IDLE, &raw const param)
            }
        }
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Lowers the calling thread to [`background_priority`] when it is set.
pub fn lower_current_thread_priority() {
    #[cfg(target_os = "linux")]
    if let Some(priority) = background_priority()
        && let Err(err) = set_thread_priority(0, priority)
    {
        tracing::debug!(target: "n42::core_layout", %err, "could not lower a thread's priority");
    }
}

/// The process's thread ids.
#[cfg(target_os = "linux")]
fn process_threads() -> Vec<libc::pid_t> {
    std::fs::read_dir("/proc/self/task")
        .map(|dir| {
            dir.filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<libc::pid_t>().ok()).collect()
        })
        .unwrap_or_default()
}

/// Lowers every thread whose name starts with one of `prefixes` to
/// [`background_priority`] (for threads spawned by code we do not own, such
/// as reth's `persistence`). Returns how many were changed.
pub fn lower_threads_named(prefixes: &[&str]) -> usize {
    #[cfg(target_os = "linux")]
    if let Some(priority) = background_priority() {
        let mut changed = 0;
        for tid in process_threads() {
            let Ok(comm) = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")) else { continue };
            let comm = comm.trim_end();
            if prefixes.iter().any(|p| comm.starts_with(p)) && set_thread_priority(tid, priority).is_ok() {
                changed += 1;
            }
        }
        return changed;
    }
    let _ = prefixes;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This host's shape: SMT siblings at +`offset` (`f7_smt_offset`).
    fn smt(offset: usize) -> impl Fn(usize) -> Option<Vec<usize>> {
        move |cpu| {
            let core = cpu % offset;
            Some(vec![core, core + offset])
        }
    }

    /// A fleet node: 37 physical cores from `lo` plus their siblings.
    fn fleet_mask(lo: usize, offset: usize) -> Vec<usize> {
        (lo..lo + 37).chain(lo + offset..lo + offset + 37).collect()
    }

    #[test]
    fn cpu_lists_round_trip() {
        assert_eq!(parse_cpu_list("0,128\n"), Some(vec![0, 128]));
        assert_eq!(parse_cpu_list("3-5,64"), Some(vec![3, 4, 5, 64]));
        assert_eq!(parse_cpu_list("5-3"), None);
        assert_eq!(format_cpu_list(&[0, 1, 2, 3, 128, 130, 129]), "0-3,128-130");
        assert_eq!(format_cpu_list(&[]), "-");
    }

    #[test]
    fn fleet_node_sixteen_build_cores_siblings_idle() {
        let mask = fleet_mask(0, 128);
        assert_eq!(mask.len(), 74);
        let layout = compute(&mask, smt(128), &Config::default()).expect("a layout");
        assert_eq!(layout.build, (0..16).collect::<Vec<_>>());
        assert_eq!(layout.critical, (16..20).collect::<Vec<_>>());
        assert_eq!(layout.background, (20..37).chain(148..165).collect::<Vec<_>>());
        assert_eq!(layout.idle, (128..148).collect::<Vec<_>>());
        assert_eq!(layout.build.len() + layout.critical.len() + layout.background.len() + layout.idle.len(), 74);
        assert_eq!(layout.tag(), "b16/c4/bg34");
    }

    #[test]
    fn fleet_node_build_takes_its_siblings() {
        let mask = fleet_mask(37, 128);
        let config = Config { build_siblings: true, ..Config::default() };
        let layout = compute(&mask, smt(128), &config).expect("a layout");
        assert_eq!(layout.build, (37..53).chain(165..181).collect::<Vec<_>>());
        assert_eq!(layout.critical, (53..57).collect::<Vec<_>>());
        assert_eq!(layout.idle, (181..185).collect::<Vec<_>>());
        assert_eq!(layout.background, (57..74).chain(185..202).collect::<Vec<_>>());
        assert_eq!(layout.tag(), "b16x2/c4/bg34");
    }

    #[test]
    fn critical_zero_shares_the_build_set() {
        let config = Config { critical_cores: 0, ..Config::default() };
        let layout = compute(&fleet_mask(0, 128), smt(128), &config).expect("a layout");
        assert!(layout.critical.is_empty());
        assert_eq!(layout.cpus(Set::Critical), layout.cpus(Set::Build));
        assert_eq!(layout.background.len(), 42);
    }

    #[test]
    fn sixteen_cpu_box_falls_back_with_defaults() {
        let mask: Vec<usize> = (0..16).collect();
        assert_eq!(
            compute(&mask, smt(8), &Config::default()),
            Err(LayoutError::TooFewCores { have: 8, need: 21 })
        );
        let small = Config { build_cores: 4, critical_cores: 1, ..Config::default() };
        let layout = compute(&mask, smt(8), &small).expect("a layout");
        assert_eq!(layout.build, vec![0, 1, 2, 3]);
        assert_eq!(layout.critical, vec![4]);
        assert_eq!(layout.background, vec![5, 6, 7, 13, 14, 15]);
        assert_eq!(layout.idle, vec![8, 9, 10, 11, 12]);
        let tight = Config { build_cores: 5, critical_cores: 2, ..Config::default() };
        assert_eq!(compute(&mask, smt(8), &tight), Err(LayoutError::TooFewBackground { have: 2, need: 4 }));
    }

    #[test]
    fn mask_without_siblings() {
        let mask: Vec<usize> = (0..40).collect();
        let layout = compute(&mask, |_| None, &Config::default()).expect("a layout");
        assert_eq!(layout.build, (0..16).collect::<Vec<_>>());
        assert_eq!(layout.critical, (16..20).collect::<Vec<_>>());
        assert_eq!(layout.background, (20..40).collect::<Vec<_>>());
        assert!(layout.idle.is_empty());
        // The siblings exist but `taskset` left them out: one CPU a core.
        let primaries: Vec<usize> = (0..37).collect();
        let layout = compute(&primaries, smt(128), &Config::default()).expect("a layout");
        assert_eq!(layout.background, (20..37).collect::<Vec<_>>());
        assert!(layout.idle.is_empty());
    }

    #[test]
    fn empty_mask_is_an_error() {
        assert_eq!(compute(&[], |_| None, &Config::default()), Err(LayoutError::EmptyMask));
    }

    #[test]
    fn priorities_parse() {
        assert_eq!(parse_priority("idle"), Some(Priority::Idle));
        assert_eq!(parse_priority("10"), Some(Priority::Nice(10)));
        assert_eq!(parse_priority("40"), Some(Priority::Nice(19)));
        assert_eq!(parse_priority("0"), None);
        assert_eq!(parse_priority("x"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pin_round_trips_through_getaffinity() {
        let handle = std::thread::spawn(|| -> std::io::Result<(Vec<usize>, Vec<usize>)> {
            let before = current_thread_cpus()?;
            let target: Vec<usize> = before.iter().copied().take(2).collect();
            pin_current_thread_to(&target)?;
            let after = current_thread_cpus()?;
            Ok((target, after))
        });
        let (target, after) = handle.join().expect("the thread does not panic").expect("affinity calls succeed");
        assert!(!target.is_empty());
        assert_eq!(after, target);
        // The layout is off without `N42_CORE_LAYOUT=isolate`: no change.
        if std::env::var("N42_CORE_LAYOUT").is_err() {
            assert!(!pin_current_thread(Set::Build).expect("no error when off"));
            assert_eq!(label(), "off");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_host_lays_out_or_falls_back() {
        let Ok(mask) = current_thread_cpus() else { return };
        match compute(&mask, sysfs_siblings, &Config::default()) {
            Ok(layout) => {
                let total = layout.build.len() + layout.critical.len() + layout.background.len() + layout.idle.len();
                assert_eq!(total, mask.len());
            }
            Err(LayoutError::TooFewCores { .. } | LayoutError::TooFewBackground { .. }) => {}
            Err(err) => panic!("unexpected: {err}"),
        }
    }
}
