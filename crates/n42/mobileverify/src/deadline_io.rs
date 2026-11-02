// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-connection deadlines Go's `http.Server` keeps and hyper 1.x does not.
//!
//! hyper's `header_read_timeout` starts when the connection waits for a
//! request, so it bounds the keep-alive idle time as well: at 5 s it closes
//! a pooled connection the phone reuses a little later. [`DeadlineIo`] keeps
//! the three Go deadlines apart instead, by watching the bytes it carries:
//!
//! - **idle** (`IdleTimeout`, gov5 effectively 15 s): while no request is in
//!   progress, the next request's first byte must arrive within it;
//! - **header** (`ReadHeaderTimeout`, 5 s): from a request's first byte to
//!   the end of its header block (`\r\n\r\n`);
//! - **write** (`WriteTimeout`, 15 s): from the end of the header block, every
//!   write of the response must finish by it, so a client that never reads
//!   cannot hold a large response (and its connection) open.
//!
//! The body read stays bounded by the handler's own read timeout. Once the
//! server writes or flushes, the connection counts as idle again (a `100
//! Continue` therefore restarts the header clock for the body; the SDK does
//! not send `Expect`; pipelined requests share the first one's write
//! deadline). An expired deadline fails the IO call with
//! [`io::ErrorKind::TimedOut`], which ends the connection.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// The three deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Deadlines {
    pub(crate) idle: Duration,
    pub(crate) header: Duration,
    pub(crate) write: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    /// Between requests: the next byte must come by the deadline.
    Idle,
    /// Inside a header block; `matched` bytes of `\r\n\r\n` seen so far.
    Header { matched: u8 },
    /// Past the header block (body, or waiting on the handler).
    Body,
}

const HEADER_END: &[u8; 4] = b"\r\n\r\n";

/// A stream with Go's idle, header and write deadlines.
#[derive(Debug)]
pub(crate) struct DeadlineIo<T> {
    inner: T,
    limits: Deadlines,
    state: ReadState,
    /// The read deadline of the current state (`None` in `Body`).
    read_deadline: Option<Instant>,
    read_timer: Pin<Box<Sleep>>,
    /// The current response's write deadline, set at the end of its request's
    /// header block.
    write_deadline: Option<Instant>,
    write_timer: Pin<Box<Sleep>>,
}

impl<T> DeadlineIo<T> {
    pub(crate) fn new(inner: T, limits: Deadlines) -> Self {
        let now = Instant::now();
        let read_deadline = now + limits.idle;
        Self {
            inner,
            limits,
            state: ReadState::Idle,
            read_deadline: Some(read_deadline),
            read_timer: Box::pin(tokio::time::sleep_until(read_deadline)),
            write_deadline: None,
            write_timer: Box::pin(tokio::time::sleep_until(now)),
        }
    }

    /// Server output: the request is answered, the connection is idle again.
    fn mark_idle(&mut self) {
        if self.state != ReadState::Idle {
            self.state = ReadState::Idle;
            self.read_deadline = Some(Instant::now() + self.limits.idle);
        }
    }

    /// Advances the header scan over bytes just read.
    fn observe_read(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut matched = match self.state {
            ReadState::Body => return,
            ReadState::Idle => {
                self.read_deadline = Some(Instant::now() + self.limits.header);
                self.write_deadline = None;
                0
            }
            ReadState::Header { matched } => matched,
        };
        for &b in bytes {
            if b == HEADER_END[matched as usize] {
                matched += 1;
                if matched as usize == HEADER_END.len() {
                    self.state = ReadState::Body;
                    self.read_deadline = None;
                    self.write_deadline = Some(Instant::now() + self.limits.write);
                    return;
                }
            } else {
                matched = u8::from(b == b'\r');
            }
        }
        self.state = ReadState::Header { matched };
    }
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{what} deadline exceeded"))
}

/// Whether `deadline` has passed; otherwise arms `timer` to wake the task
/// at it.
fn expired(timer: &mut Pin<Box<Sleep>>, deadline: Instant, cx: &mut Context<'_>) -> bool {
    if timer.deadline() != deadline {
        timer.as_mut().reset(deadline);
    }
    timer.as_mut().poll(cx).is_ready()
}

impl<T: AsyncRead + Unpin> AsyncRead for DeadlineIo<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                this.observe_read(&buf.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => match this.read_deadline {
                Some(d) if expired(&mut this.read_timer, d, cx) => {
                    let what = if this.state == ReadState::Idle { "idle" } else { "header read" };
                    Poll::Ready(Err(timed_out(what)))
                }
                _ => Poll::Pending,
            },
        }
    }
}

impl<T: AsyncWrite + Unpin> DeadlineIo<T> {
    /// Runs one write under the response's write deadline; a write that
    /// moved bytes makes the connection idle again.
    fn poll_out(
        &mut self,
        cx: &mut Context<'_>,
        op: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        if self.write_deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Err(timed_out("write")));
        }
        match op(Pin::new(&mut self.inner), cx) {
            Poll::Ready(res) => {
                if res.as_ref().is_ok_and(|n| *n > 0) {
                    self.mark_idle();
                }
                Poll::Ready(res)
            }
            Poll::Pending => self.pending_write(cx),
        }
    }

    fn pending_write<R>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<R>> {
        match self.write_deadline {
            Some(d) if expired(&mut self.write_timer, d, cx) => Poll::Ready(Err(timed_out("write"))),
            _ => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DeadlineIo<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_out(cx, |io, cx| io.poll_write(cx, buf))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_out(cx, |io, cx| io.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // hyper flushes on every turn of its loop, idle or not: a flush
        // neither ends a request nor fails early, only one that stalls.
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(res) => Poll::Ready(res),
            Poll::Pending => this.pending_write(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Closing is never refused by the deadline.
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io() -> DeadlineIo<()> {
        let d = Duration::from_secs(1);
        DeadlineIo::new((), Deadlines { idle: d, header: d, write: d })
    }

    #[tokio::test]
    async fn header_scan_across_reads() {
        let mut io = io();
        io.observe_read(b"GET / HTTP/1.1\r\nHost: x\r");
        assert_eq!(io.state, ReadState::Header { matched: 1 });
        assert!(io.write_deadline.is_none());
        io.observe_read(b"\n\r");
        assert_eq!(io.state, ReadState::Header { matched: 3 });
        io.observe_read(b"\nbody\r\n\r\n");
        assert_eq!(io.state, ReadState::Body);
        assert!(io.read_deadline.is_none());
        assert!(io.write_deadline.is_some());
        io.mark_idle();
        assert_eq!(io.state, ReadState::Idle);
        // The next request's first byte drops the answered one's deadline.
        io.observe_read(b"G");
        assert!(io.write_deadline.is_none());
        io.mark_idle();
        // "\r\r\n\r\n" still ends a header block.
        io.observe_read(b"X\r\r\n\r\n");
        assert_eq!(io.state, ReadState::Body);
    }
}
