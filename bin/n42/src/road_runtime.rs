// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vote road's own tokio runtime (`N42_ROAD_RUNTIME=1`), and the time a
//! road request sat in its socket before the road started (`dispatch_wait_ms`).
//!
//! The raw payload channel (`payload_serve`) and the transaction ingest
//! (`n42_tx_ingest`) used to share the execution layer's one runtime: its async
//! workers and its blocking pool. Under a flood the ingest keeps every worker
//! busy with 64 connections' read loops and per-frame RLP decodes, and keeps the
//! blocking pool busy with sender recovery -- recovery that renices its thread
//! (`N42_TX_INGEST_RECOVER_NICE`, 10 in the bench). tokio reuses idle blocking
//! threads both for later `spawn_blocking` calls and for the replacement worker
//! a `block_in_place` hands its core to, so a reniced recovery thread ends up
//! running the road's blocking work and, after the compact body's
//! `block_in_place`, the runtime's async workers too. loop240 measured the
//! validator's request waiting ~65-70 ms before the road's first timer at 64k
//! transactions in flight (6.18).
//!
//! With the switch on, the channel's accept loop and every connection it
//! serves run here instead: a small multi-thread runtime with its own blocking
//! pool, built once, whose threads never ran a recovery. The ingest stays on
//! the main runtime. A runtime that cannot be built leaves the channel where it
//! was, with a warning.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::{info, warn};

/// Whether the raw payload channel runs on its own runtime (`N42_ROAD_RUNTIME=1`,
/// off by default).
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_ROAD_RUNTIME").is_ok_and(|v| v == "1"))
}

/// Async workers of the road's runtime: `N42_ROAD_RUNTIME_WORKERS`, 4 by default,
/// clamped to 1..=16.
fn workers() -> usize {
    std::env::var("N42_ROAD_RUNTIME_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 16)
}

/// The road's runtime, built on first use; `None` when the switch is off or the
/// runtime could not be built (said once, as a warning).
///
/// Held in a static and never dropped: dropping a runtime from inside another
/// runtime's context panics, and this one lives as long as the process.
pub fn handle() -> Option<tokio::runtime::Handle> {
    static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    if !enabled() {
        return None;
    }
    RUNTIME
        .get_or_init(|| {
            let workers = workers();
            // Threads inherit the creating thread's nice value: say it, so a
            // leg whose road runtime was born on a reniced thread shows it.
            let creator_nice = current_nice();
            match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .thread_name("n42-road")
                .enable_all()
                .build()
            {
                Ok(runtime) => {
                    info!(target: "n42.payload_serve", workers, creator_nice, "vote road on its own runtime");
                    Some(runtime)
                }
                Err(err) => {
                    warn!(
                        target: "n42.payload_serve",
                        %err,
                        "N42_ROAD_RUNTIME=1 but its runtime could not be built; the road stays on the main runtime"
                    );
                    None
                }
            }
        })
        .as_ref()
        .map(|runtime| runtime.handle().clone())
}

/// The calling thread's nice value, 0 when it cannot be read.
fn current_nice() -> i32 {
    // SAFETY: gettid and getpriority on the calling thread are plain syscalls
    // with no memory effects. getpriority can legitimately return -1, so errno
    // is not consulted: the value is only reported.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::getpriority(libc::PRIO_PROCESS, tid)
    }
}

/// Whether the channel measures `dispatch_wait_ms`: under `N42_ROAD_RUNTIME=1`,
/// or on its own with `N42_ROAD_DISPATCH_WAIT=1` for the baseline leg. Off, the
/// request's first byte is read exactly as before and the field reads 0.
pub fn measure_dispatch_wait() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| enabled() || std::env::var("N42_ROAD_DISPATCH_WAIT").is_ok_and(|v| v == "1"))
}

/// Asks the kernel to stamp every segment this socket receives
/// (`SO_TIMESTAMPNS`, wall clock), read back by [`read_kind_timed`].
pub fn enable_receive_timestamps(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let on: libc::c_int = 1;
    // SAFETY: setsockopt on an open socket with a c_int option value of the
    // size given.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Reads a request's first byte, and how long it had been in the socket's
/// receive queue when it was read: from the kernel's receive timestamp to now.
/// `None` for the wait when the kernel attached no timestamp.
///
/// End of stream is `UnexpectedEof`, as `read_u8` says it.
pub async fn read_kind_timed(stream: &TcpStream) -> std::io::Result<(u8, Option<Duration>)> {
    loop {
        stream.readable().await?;
        match stream.try_io(tokio::io::Interest::READABLE, || recv_one_stamped(stream)) {
            Ok((byte, stamp)) => {
                let waited = stamp.and_then(|stamp| {
                    std::time::SystemTime::now().duration_since(stamp).ok()
                });
                return Ok((byte, waited));
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }
}

/// One byte by `recvmsg`, with the `SCM_TIMESTAMPNS` control message if any.
fn recv_one_stamped(stream: &TcpStream) -> std::io::Result<(u8, Option<std::time::SystemTime>)> {
    use std::os::fd::AsRawFd as _;
    let mut byte = 0u8;
    let mut iov = libc::iovec { iov_base: (&mut byte as *mut u8).cast(), iov_len: 1 };
    // u64 words for the cmsghdr alignment; room for a timestamp or two.
    let mut control = [0u64; 16];
    // SAFETY: an all-zero msghdr is a valid empty one; the pointers set below
    // outlive the recvmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: recvmsg on an open socket into the one-byte buffer and control
    // buffer described by `msg`.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "early eof"));
    }
    let mut stamp = None;
    // SAFETY: walking the control messages the kernel wrote into `control`,
    // bounded by `msg.msg_controllen`, with the libc macros meant for it.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPNS {
                let ts: libc::timespec = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                if ts.tv_sec >= 0 && (0..1_000_000_000).contains(&ts.tv_nsec) {
                    stamp = Some(
                        std::time::UNIX_EPOCH + Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32),
                    );
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((byte, stamp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A byte that sat in the socket for 60 ms reads as having waited about
    /// that long, and the bytes after it read as usual.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_byte_says_how_long_it_waited() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        enable_receive_timestamps(&server).unwrap();
        client.write_all(&[7, 1, 2, 3]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (kind, waited) = read_kind_timed(&server).await.unwrap();
        assert_eq!(kind, 7);
        let waited = waited.expect("the kernel stamps a loopback segment");
        assert!(waited >= Duration::from_millis(50), "waited {waited:?}");
        assert!(waited < Duration::from_secs(5), "waited {waited:?}");
        let mut rest = [0u8; 3];
        server.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, [1, 2, 3]);
        drop(client);
        let eof = read_kind_timed(&server).await.unwrap_err();
        assert_eq!(eof.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
