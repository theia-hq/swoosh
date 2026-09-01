//! The speed payload: a counted byte stream, iperf-shaped. The bytes carry no meaning (throughput is
//! the only signal), so both ends move a fixed zero buffer rather than generating or verifying content
//! per byte. Sending and draining are the two halves of every speed test, so they live together here as
//! [`Payload`], which owns the one chunk loop and the one reusable buffer the whole engine shares.

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// A live count of bytes a [`Payload`] has moved so far, shared with an observer for throughput-over-
/// time reporting.
///
/// The transfer loop bumps this each chunk; a reporter reads it on a timer to print periodic lines (the
/// iperf model: rate over each interval, not just the final average). Relaxed ordering is enough: this
/// is a monotonic progress gauge, never a synchronization point, and a reader that sees a slightly stale
/// count just reports a hair conservatively.
#[derive(Debug, Clone, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    /// A fresh counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes moved so far.
    pub fn bytes(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Add `n` bytes to the running count.
    fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
}

/// The transfer chunk. 64 KiB matches bifrost-mem's stream buffer and the wire's streaming chunk, so a
/// chunk crosses an in-memory stream without a partial second copy. The single source of truth for the
/// chunk size across the engine; `speed.rs` uses it as the time-bound granularity.
pub const CHUNK: u64 = 64 * 1024;

/// How much a [`Payload`] transfer moves before it stops.
#[derive(Debug, Clone, Copy)]
pub enum Bound {
    /// Move exactly this many bytes (a byte-bounded run), then stop.
    Bytes(u64),
    /// Move until this instant (a time-bounded run), checked at each chunk boundary.
    Until(Instant),
    /// Move until the peer stops (the responder-side of a time-bounded download): stream forever, and
    /// let the client's close of its read half surface as a broken-pipe write error that ends the loop.
    Peer,
}

/// A counted transfer in one direction, stopping at its [`Bound`]. One chunk loop, one reused buffer.
///
/// Optionally carries a [`Progress`] the loop bumps each chunk, so an observer can report throughput
/// over time; without one the transfer is unobserved (the responder side never reports progress).
#[derive(Debug, Clone)]
#[must_use = "a Payload does nothing until sent or drained"]
pub struct Payload {
    bound: Bound,
    progress: Option<Progress>,
}

impl Payload {
    /// A transfer of exactly `limit` bytes.
    pub fn of(limit: u64) -> Self {
        Self::from(Bound::Bytes(limit))
    }

    /// A transfer bounded by wall clock, moving chunks until `deadline`.
    pub fn until(deadline: Instant) -> Self {
        Self::from(Bound::Until(deadline))
    }

    /// A transfer that streams until the peer stops reading (the responder's unbounded source).
    pub fn until_peer_stops() -> Self {
        Self::from(Bound::Peer)
    }

    /// A transfer of `Some(n)` exact bytes, or one that runs until the peer stops (EOF when draining, a
    /// broken pipe when sending) for `None`. The bidir responder's mirror of the client's bound: an
    /// exact count for a byte-bounded run, unbounded for a time-bounded one the client's deadline ends.
    pub fn of_or_until_peer(limit: Option<u64>) -> Self {
        match limit {
            Some(bytes) => Self::of(bytes),
            None => Self::until_peer_stops(),
        }
    }

    /// Track this transfer's cumulative bytes in `progress`, so a reporter can read the rate on a timer.
    pub fn tracking(mut self, progress: Progress) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Write zero payload until the bound, returning how many bytes were written. A [`Bound::Peer`]
    /// transfer ends when the peer closes its read half (a broken-pipe write error), which is the
    /// success path for an unbounded source, so it is not surfaced as an error.
    pub async fn send<W: io::AsyncWrite + Unpin>(self, writer: &mut W) -> io::Result<u64> {
        let Self { bound, progress } = self;
        let zeros = [0u8; CHUNK as usize];
        let mut sent = 0u64;
        while let Some(want) = bound.remaining(sent) {
            let n = want.min(CHUNK) as usize;
            // A time-bounded send must not block PAST its deadline. When the peer reads slowly (or not at
            // all), the send window fills and `write_all` parks on backpressure; the between-chunk deadline
            // check in `remaining` never runs, so the run overshoots its `-t` window arbitrarily and the
            // reported rate collapses toward zero (the observed `--up`/`--bidir` hang). Race each write
            // against the deadline and stop the instant it fires: the payload is meaningless zeros, so a
            // torn final chunk on a stream that is about to be shut down costs nothing.
            let write = writer.write_all(&zeros[..n]);
            let outcome = match bound {
                Bound::Until(deadline) => {
                    match tokio::time::timeout_at(deadline.into(), write).await {
                        Ok(result) => result,
                        Err(_past_deadline) => break,
                    }
                }
                _ => write.await,
            };
            if let Err(error) = outcome {
                return match bound {
                    Bound::Peer if is_disconnect(&error) => Ok(sent),
                    _ => Err(error),
                };
            }
            sent += n as u64;
            report(&progress, n as u64);
        }
        writer.flush().await?;
        Ok(sent)
    }

    /// Drain payload until the bound or EOF, returning how many bytes arrived. A truncated transfer
    /// (EOF before the bound) is counted honestly rather than hanging.
    pub async fn drain<R: io::AsyncRead + Unpin>(self, reader: &mut R) -> io::Result<u64> {
        let Self { bound, progress } = self;
        let mut sink = [0u8; CHUNK as usize];
        let mut received = 0u64;
        while let Some(want) = bound.remaining(received) {
            let n = reader.read(&mut sink[..want.min(CHUNK) as usize]).await?;
            if n == 0 {
                break;
            }
            received += n as u64;
            report(&progress, n as u64);
        }
        Ok(received)
    }
}

impl From<Bound> for Payload {
    fn from(bound: Bound) -> Self {
        Self {
            bound,
            progress: None,
        }
    }
}

/// Bump a progress counter by `n` bytes, if the transfer is being observed.
fn report(progress: &Option<Progress>, n: u64) {
    if let Some(progress) = progress {
        progress.add(n);
    }
}

impl Bound {
    /// How many more bytes this chunk may move, or `None` once the bound is reached. A byte bound
    /// counts down to zero; a time bound yields a full chunk until the deadline passes; a peer bound
    /// never stops itself (the broken pipe does).
    fn remaining(self, moved: u64) -> Option<u64> {
        match self {
            Bound::Bytes(limit) => (moved < limit).then(|| limit - moved),
            Bound::Until(deadline) => (Instant::now() < deadline).then_some(CHUNK),
            Bound::Peer => Some(CHUNK),
        }
    }
}

/// Whether a write error means the peer closed the far end, the expected end of an unbounded source.
fn is_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}
