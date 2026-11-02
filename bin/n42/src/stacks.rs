// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Thread stacks on demand, for a node that has stopped making progress.
//!
//! [`install`] puts a `SIGUSR2` handler in place; [`dump_all`] signals every
//! thread of the process in turn, waits briefly for each, and prints what it
//! recorded. The handler runs on a thread stopped at an arbitrary point,
//! possibly inside the allocator or holding stderr's lock, on a node that may
//! only be slow: allocating, formatting or printing there can wedge that
//! thread for good, or abort the process on stderr's reentrancy check. So the
//! handler only copies the return addresses `backtrace(3)` finds into static
//! atomics, and the sender resolves and prints them on its own thread.
//!
//! `backtrace(3)` does not allocate once libgcc is loaded, which [`install`]
//! makes sure of; it reads `.eh_frame` and may briefly take the dynamic
//! loader's lock. A thread that cannot answer within the wait (round 43: a
//! leader's execution layer stopped inside a build, with no debugger on the
//! host) is reported as such and skipped. Frames resolve only with symbols:
//! build with `--profile profiling`.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Return addresses kept per thread.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const MAX_FRAMES: usize = 64;

/// [`TARGET`]'s value while a handler is copying its frames.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const CAPTURING: u64 = u64::MAX;

/// The handshake with the handler: the sender sets the thread id it signals;
/// that thread's handler claims it ([`CAPTURING`]) and clears it when its
/// frames are in place. A handler arriving for any other thread does nothing.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static TARGET: AtomicU64 = AtomicU64::new(0);

/// How many of [`FRAMES`] the last handler wrote.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static FRAME_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The last handler's return addresses.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static FRAMES: [AtomicUsize; MAX_FRAMES] = [const { AtomicUsize::new(0) }; MAX_FRAMES];

/// Async-signal-safe: raw syscalls, lock-free atomics and `backtrace(3)` into
/// a stack buffer, with `errno` put back for the interrupted code.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
extern "C" fn on_signal(_sig: libc::c_int) {
    // SAFETY: `__errno_location` returns this thread's errno slot.
    let errno = unsafe { *libc::__errno_location() };
    // SAFETY: gettid takes no arguments and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    if TARGET.compare_exchange(tid, CAPTURING, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        let mut frames = [std::ptr::null_mut(); MAX_FRAMES];
        // SAFETY: `frames` holds `MAX_FRAMES` pointers.
        let n = unsafe { libc::backtrace(frames.as_mut_ptr(), MAX_FRAMES as libc::c_int) };
        let n = usize::try_from(n).unwrap_or(0).min(MAX_FRAMES);
        for (slot, frame) in FRAMES.iter().zip(&frames[..n]) {
            slot.store(*frame as usize, Ordering::Relaxed);
        }
        FRAME_COUNT.store(n, Ordering::Relaxed);
        TARGET.store(0, Ordering::SeqCst);
    }
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = errno };
}

/// Installs the handler. Idempotent.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn install() {
    // libgcc is loaded on the first `backtrace(3)`, and loading allocates:
    // that first call must not be the handler's.
    let mut probe = [std::ptr::null_mut(); 2];
    // SAFETY: `probe` holds two pointers. The sigaction call gets a zeroed
    // struct with a valid handler and an initialised mask.
    unsafe {
        libc::backtrace(probe.as_mut_ptr(), 2);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(libc::SIGUSR2, &raw const action, std::ptr::null_mut());
    }
}

/// What came of signalling one thread.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[derive(Debug, PartialEq, Eq)]
enum Capture {
    /// Its return addresses, innermost first.
    Frames(Vec<usize>),
    /// The thread is gone.
    Gone,
    /// It did not run the handler in time, and will do nothing if it does later.
    NoAnswer,
    /// Its handler is still copying: [`FRAMES`] is not free to reuse.
    Stuck,
}

/// Signals `tid` and collects its frames, waiting up to `each`.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn capture(pid: libc::pid_t, tid: u64, each: std::time::Duration) -> Capture {
    TARGET.store(tid, Ordering::SeqCst);
    // SAFETY: tgkill takes plain integers.
    if unsafe { libc::syscall(libc::SYS_tgkill, pid, tid as libc::pid_t, libc::SIGUSR2) } != 0 {
        TARGET.store(0, Ordering::SeqCst);
        return Capture::Gone;
    }
    let deadline = std::time::Instant::now() + each;
    while TARGET.load(Ordering::SeqCst) != 0 {
        if std::time::Instant::now() >= deadline {
            // Withdraw the request; a claim that got in first still owns FRAMES.
            return match TARGET.compare_exchange(tid, 0, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => Capture::NoAnswer,
                Err(0) => break,
                Err(_) => Capture::Stuck,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let n = FRAME_COUNT.load(Ordering::Relaxed);
    Capture::Frames(FRAMES[..n].iter().map(|frame| frame.load(Ordering::Relaxed)).collect())
}

/// One thread's frames on stderr. Off the signal path: this allocates.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn print_frames(frames: &[usize]) {
    for (i, frame) in frames.iter().enumerate() {
        let mut named = false;
        // A return address: the call is the instruction before it.
        backtrace::resolve(frame.wrapping_sub(1) as *mut std::ffi::c_void, |symbol| {
            named = true;
            let name = symbol.name().map_or_else(|| "?".to_owned(), |name| name.to_string());
            match (symbol.filename(), symbol.lineno()) {
                (Some(file), Some(line)) => eprintln!("{i:3}: {frame:#x} {name} ({}:{line})", file.display()),
                _ => eprintln!("{i:3}: {frame:#x} {name}"),
            }
        });
        if !named {
            eprintln!("{i:3}: {frame:#x}");
        }
    }
}

/// Prints every thread's stack to stderr, one at a time, waiting up to
/// `each` for a thread to answer. Returns how many answered.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn dump_all(each: std::time::Duration) -> usize {
    if TARGET.load(Ordering::SeqCst) != 0 {
        eprintln!("=== stack dump skipped: a thread of the last dump is still unwinding");
        return 0;
    }
    // SAFETY: neither call has preconditions or can fail.
    let (me, pid) = unsafe { (libc::syscall(libc::SYS_gettid) as u64, libc::getpid()) };
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else { return 0 };
    let mut tids: Vec<u64> = tasks.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
    tids.sort_unstable();
    let mut answered = 0;
    eprintln!("=== stack dump: {} threads", tids.len());
    for tid in tids {
        if tid == me {
            continue;
        }
        let comm = || std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")).unwrap_or_default();
        match capture(pid, tid, each) {
            Capture::Frames(frames) => {
                answered += 1;
                eprintln!("=== thread {tid} {:?}", comm().trim());
                print_frames(&frames);
            }
            Capture::Gone => {}
            Capture::NoAnswer => {
                let wchan = std::fs::read_to_string(format!("/proc/self/task/{tid}/wchan")).unwrap_or_default();
                eprintln!("=== thread {tid} {:?} did not answer (wchan {})", comm().trim(), wchan.trim());
            }
            Capture::Stuck => {
                eprintln!("=== thread {tid} {:?} is still unwinding; ending the dump", comm().trim());
                break;
            }
        }
    }
    eprintln!("=== stack dump done: {answered} answered");
    answered
}

/// Stack signalling requires glibc's `backtrace`, Linux thread IDs and
/// `/proc`; no handler is installed elsewhere.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn install() {}

/// No threads are signalled on platforms without the Linux diagnostic backend.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn dump_all(_each: std::time::Duration) -> usize { 0 }

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    fn gettid() -> u64 {
        // SAFETY: gettid takes no arguments and cannot fail.
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }

    fn set_errno(value: i32) {
        // SAFETY: `__errno_location` returns this thread's errno slot.
        unsafe { *libc::__errno_location() = value };
    }

    fn errno() -> i32 {
        // SAFETY: as above.
        unsafe { *libc::__errno_location() }
    }

    /// One test, because [`TARGET`] and [`FRAMES`] serve one capture at a time.
    #[test]
    fn the_handler_records_frames_and_touches_nothing_else() {
        install();
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };

        // Answers with stderr's lock held elsewhere, and leaves errno alone.
        let stop = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = mpsc::channel();
        let (stopped, arm) = (stop.clone(), armed.clone());
        let worker = std::thread::spawn(move || {
            tid_tx.send(gettid()).unwrap();
            set_errno(77);
            arm.store(true, Ordering::SeqCst);
            while !stopped.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            errno()
        });
        let tid = tid_rx.recv().unwrap();
        while !armed.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        let held = std::io::stderr().lock();
        let got = capture(pid, tid, Duration::from_secs(10));
        drop(held);
        stop.store(true, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), 77, "errno survives the handler");
        let Capture::Frames(frames) = got else { panic!("no frames: {got:?}") };
        assert!(frames.len() >= 2, "{frames:?}");
        assert_eq!(TARGET.load(Ordering::SeqCst), 0);

        // A thread that cannot answer withdraws the request, and its late
        // handler then leaves the frames alone.
        let (tid_tx, tid_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let blocked = std::thread::spawn(move || {
            // SAFETY: the set is initialised before use; the mask is this thread's.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, libc::SIGUSR2);
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
            }
            tid_tx.send(gettid()).unwrap();
            let _ = release_rx.recv();
            // SAFETY: as above; this delivers the pending signal.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, libc::SIGUSR2);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
            }
        });
        let tid = tid_rx.recv().unwrap();
        FRAME_COUNT.store(0, Ordering::SeqCst);
        assert_eq!(capture(pid, tid, Duration::from_millis(30)), Capture::NoAnswer);
        assert_eq!(TARGET.load(Ordering::SeqCst), 0);
        release_tx.send(()).unwrap();
        blocked.join().unwrap();
        assert_eq!(FRAME_COUNT.load(Ordering::SeqCst), 0, "the late handler wrote nothing");

        // A thread that has exited.
        let gone = std::thread::spawn(gettid).join().unwrap();
        assert_eq!(capture(pid, gone, Duration::from_millis(30)), Capture::Gone);
        assert_eq!(TARGET.load(Ordering::SeqCst), 0);
    }
}
