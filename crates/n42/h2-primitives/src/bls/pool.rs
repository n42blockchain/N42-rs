// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: Apache-2.0

//! The size of blst's verification thread pool.
//!
//! blst runs its multi-signature checks (`verify_multiple_aggregate_signatures`,
//! `miller_loop_n`) on one process-wide pool it creates at first use with
//! `ThreadPool::default()`: one thread per CPU the *calling thread* may run
//! on, all spawned at once and never shrunk. It has no setting of its own.
//! [`size_verification_pool`] creates that pool first, from a helper thread
//! whose CPU mask holds only the wanted number of CPUs, then gives the pool's
//! threads the process's full mask back. Verification is unchanged: the same
//! blst code path, run on fewer workers.

/// The name of the pool's threads (they inherit the helper's).
pub const POOL_THREAD_NAME: &str = "n42-bls-pool";

/// Creates blst's verification pool with at most `threads` workers, if it
/// does not exist yet. Must run before the first blst multi-signature call,
/// or it has no effect (the pool is made once). Returns the number of
/// workers the pool was made with, or an error when the mask could not be
/// read or set (the pool is then left to blst's first caller).
#[cfg(target_os = "linux")]
pub fn size_verification_pool(threads: usize) -> std::io::Result<usize> {
    let threads = threads.max(1);
    std::thread::Builder::new()
        .name(POOL_THREAD_NAME.to_string())
        .spawn(move || -> std::io::Result<usize> {
            let full = affinity::get()?;
            let allowed: Vec<usize> = affinity::cpus(&full);
            if allowed.len() <= threads {
                // The pool would be this size anyway; make it with full masks.
                touch_pool();
                return Ok(allowed.len());
            }
            let narrow = affinity::of(&allowed[..threads]);
            affinity::set(0, &narrow)?;
            touch_pool();
            // The workers were cloned from this thread and carry its narrow
            // mask: widen every one of them (and this thread) to the full mask.
            for tid in affinity::threads_named(POOL_THREAD_NAME)? {
                // A thread that exits meanwhile is no error worth reporting.
                let _ = affinity::set(tid, &full);
            }
            Ok(threads)
        })?
        .join()
        .map_err(|_| std::io::Error::other("the blst pool helper panicked"))?
}

/// Elsewhere the pool keeps blst's own size.
#[cfg(not(target_os = "linux"))]
pub fn size_verification_pool(_threads: usize) -> std::io::Result<usize> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "only on Linux"))
}

/// One Miller loop over the generators through blst's pooled entry point:
/// the cheapest call that makes the pool.
#[cfg(target_os = "linux")]
fn touch_pool() {
    // SAFETY: the generators are static points blst owns.
    let (p, q) = unsafe { (*blst::blst_p1_affine_generator(), *blst::blst_p2_affine_generator()) };
    let _ = blst::blst_fp12::miller_loop_n(&[q, q], &[p, p]);
}

#[cfg(target_os = "linux")]
mod affinity {
    use std::io;

    pub(super) fn get() -> io::Result<libc::cpu_set_t> {
        // SAFETY: a zeroed cpu_set_t is a valid empty set; the size matches.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        // SAFETY: `set` is a valid buffer of the size passed.
        let rc = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) };
        if rc == 0 { Ok(set) } else { Err(io::Error::last_os_error()) }
    }

    pub(super) fn set(tid: libc::pid_t, set: &libc::cpu_set_t) -> io::Result<()> {
        // SAFETY: `set` is a valid cpu_set_t of the size passed.
        let rc = unsafe { libc::sched_setaffinity(tid, size_of::<libc::cpu_set_t>(), set) };
        if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    pub(super) fn cpus(set: &libc::cpu_set_t) -> Vec<usize> {
        // SAFETY: CPU_ISSET reads the set within CPU_SETSIZE.
        (0..libc::CPU_SETSIZE as usize).filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, set) }).collect()
    }

    pub(super) fn of(cpus: &[usize]) -> libc::cpu_set_t {
        // SAFETY: a zeroed cpu_set_t is a valid empty set.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in cpus {
            // SAFETY: every cpu came from `cpus`, so it is below CPU_SETSIZE.
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }
        set
    }

    /// The thread ids of this process whose name is `name`.
    pub(super) fn threads_named(name: &str) -> io::Result<Vec<libc::pid_t>> {
        let mut tids = Vec::new();
        for entry in std::fs::read_dir("/proc/self/task")? {
            let entry = entry?;
            let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse::<libc::pid_t>().ok()) else { continue };
            let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            if comm.trim_end() == name {
                tids.push(tid);
            }
        }
        Ok(tids)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn the_pool_is_sized_and_its_workers_get_the_full_mask_back() {
        let host = affinity::cpus(&affinity::get().unwrap()).len();
        let made = size_verification_pool(2).unwrap();
        assert_eq!(made, host.min(2));
        let workers = affinity::threads_named(POOL_THREAD_NAME).unwrap();
        // The helper has exited; what remains are the pool's workers (unless
        // another test in this process made the pool first).
        if workers.len() == made {
            for tid in workers {
                // SAFETY: a zeroed cpu_set_t is a valid buffer of the size passed.
                let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                let rc = unsafe { libc::sched_getaffinity(tid, size_of::<libc::cpu_set_t>(), &mut set) };
                assert_eq!(rc, 0);
                assert_eq!(affinity::cpus(&set).len(), host);
            }
        }
        // Verification still works on the small pool.
        let (a, b) = (crate::bls::BlsSecretKey::key_gen(&[3; 32]).unwrap(), crate::bls::BlsSecretKey::key_gen(&[4; 32]).unwrap());
        let (ma, mb): (&[u8], &[u8]) = (b"pool a", b"pool b");
        let (sa, sb) = (a.sign(ma), b.sign(mb));
        let (pa, pb) = (a.public_key(), b.public_key());
        assert!(crate::bls::batch_verify(&[ma, mb], &[&sa, &sb], &[&pa, &pb]).is_ok());
        assert!(crate::bls::batch_verify(&[ma, mb], &[&sb, &sa], &[&pa, &pb]).is_err());
    }
}
