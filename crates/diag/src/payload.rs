//! The speed payload: a counted byte stream, iperf-shaped. The bytes carry no meaning (throughput is
//! the only signal), so both ends move a fixed zero buffer rather than generating or verifying content
//! per byte. Sending and draining are the two halves of every speed test, so they live together here as
//! [`Payload`], which owns the one chunk loop and the one reusable buffer the whole engine shares.

use std::time::Instant;

use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

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
#[derive(Debug, Clone, Copy)]
#[must_use = "a Payload does nothing until sent or drained"]
pub struct Payload {
    bound: Bound,
}

impl Payload {
    /// A transfer of exactly `limit` bytes.
    pub fn of(limit: u64) -> Self {
        Self {
            bound: Bound::Bytes(limit),
        }
    }

    /// A transfer bounded by wall clock, moving chunks until `deadline`.
    pub fn until(deadline: Instant) -> Self {
        Self {
            bound: Bound::Until(deadline),
        }
    }

    /// A transfer that streams until the peer stops reading (the responder's unbounded source).
    pub fn until_peer_stops() -> Self {
        Self { bound: Bound::Peer }
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

    /// Write zero payload until the bound, returning how many bytes were written. A [`Bound::Peer`]
    /// transfer ends when the peer closes its read half (a broken-pipe write error), which is the
    /// success path for an unbounded source, so it is not surfaced as an error.
    pub async fn send<W: io::AsyncWrite + Unpin>(self, writer: &mut W) -> io::Result<u64> {
        let Self { bound } = self;
        let zeros = [0u8; CHUNK as usize];
        let mut sent = 0u64;
        while let Some(want) = bound.remaining(sent) {
            let n = want.min(CHUNK) as usize;
            if let Err(error) = writer.write_all(&zeros[..n]).await {
                return match bound {
                    Bound::Peer if is_disconnect(&error) => Ok(sent),
                    _ => Err(error),
                };
            }
            sent += n as u64;
        }
        writer.flush().await?;
        Ok(sent)
    }

    /// Drain payload until the bound or EOF, returning how many bytes arrived. A truncated transfer
    /// (EOF before the bound) is counted honestly rather than hanging.
    pub async fn drain<R: io::AsyncRead + Unpin>(self, reader: &mut R) -> io::Result<u64> {
        let Self { bound } = self;
        let mut sink = [0u8; CHUNK as usize];
        let mut received = 0u64;
        while let Some(want) = bound.remaining(received) {
            let n = reader.read(&mut sink[..want.min(CHUNK) as usize]).await?;
            if n == 0 {
                break;
            }
            received += n as u64;
        }
        Ok(received)
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
