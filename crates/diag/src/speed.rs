//! The speed client: measure throughput to a peer over an established session, iperf-shaped but over
//! any bifrost transport. It opens one stream, asks the responder to sink (upload) or source
//! (download) a payload, moves counted bytes until a byte or time bound, and reports MiB/s.

use core::time::Duration;
use std::time::Instant;

use bifrost::Session;
use tokio::io::{self, AsyncWriteExt as _};

use crate::payload::Payload;
use crate::protocol::{ProtocolError, Request, Response};

/// Which way the payload flows in a speed test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The client sends and the peer sinks: an upload measurement.
    Up,
    /// The peer sources and the client sinks: a download measurement.
    Down,
}

/// How much to transfer before stopping.
#[derive(Debug, Clone, Copy)]
pub enum Limit {
    /// Transfer for a fixed duration, then stop at the next chunk boundary.
    ByTime(Duration),
    /// Transfer a fixed number of bytes.
    ByBytes(u64),
}

/// One transfer chunk, and the assumed rate used to size a time-bounded run's byte budget. Chunk size
/// matches the payload's; the rate estimate only caps how large the responder-sourced stream can grow,
/// the wall clock is what actually ends the run.
const CHUNK: u64 = 64 * 1024;
const ASSUMED_BYTES_PER_SEC: u64 = 1024 * 1024 * 1024;

/// A speed test against one peer: which direction, bounded by time or bytes.
#[derive(Debug, Clone, Copy)]
pub struct Speedtest {
    /// The direction to measure.
    pub direction: Direction,
    /// When to stop.
    pub limit: Limit,
}

impl Speedtest {
    /// Run the test over an established session and return the measured throughput. One-shot: consumes
    /// `self` and drives the whole transfer on a single stream.
    pub async fn run<S: Session>(self, session: &S) -> Result<SpeedReport, ProtocolError> {
        let Self { direction, limit } = self;
        let (mut writer, mut reader) = session.open_bi().await.map_err(io_from_session)?;

        let budget = limit.byte_budget();
        let started = Instant::now();
        let bytes = match direction {
            Direction::Up => {
                Request::SpeedSink {
                    limit_bytes: budget,
                }
                .write(&mut writer)
                .await?;
                let sent = send_bounded(&mut writer, limit, started).await?;
                // Signal end-of-payload so the responder stops draining and replies with its count.
                writer.shutdown().await?;
                let Response::Received { bytes } = Response::read(&mut reader).await? else {
                    return Err(ProtocolError::Mismatched);
                };
                bytes.min(sent)
            }
            Direction::Down => {
                Request::SpeedSource {
                    limit_bytes: budget,
                }
                .write(&mut writer)
                .await?;
                drain_bounded(&mut reader, limit, started).await?
            }
        };
        let elapsed = started.elapsed();
        Ok(SpeedReport {
            direction,
            bytes,
            elapsed,
        })
    }
}

impl Limit {
    /// The number of bytes to request from the responder. A byte bound is exact; a time bound requests
    /// a generous budget (the wall clock ends the run first) so the responder never runs short.
    fn byte_budget(self) -> u64 {
        match self {
            Limit::ByBytes(bytes) => bytes,
            Limit::ByTime(duration) => {
                let secs = duration.as_secs_f64();
                (secs * ASSUMED_BYTES_PER_SEC as f64) as u64
            }
        }
    }

    /// Whether the run should stop, given how much has moved and how long it has been running.
    fn reached(self, moved: u64, elapsed: Duration) -> bool {
        match self {
            Limit::ByBytes(bytes) => moved >= bytes,
            Limit::ByTime(duration) => elapsed >= duration,
        }
    }
}

/// Send zero payload one chunk at a time until the limit, returning the bytes written.
async fn send_bounded<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    limit: Limit,
    started: Instant,
) -> io::Result<u64> {
    let mut sent = 0u64;
    while !limit.reached(sent, started.elapsed()) {
        sent += Payload::of(CHUNK).send(writer).await?;
    }
    Ok(sent)
}

/// Drain payload one chunk at a time until the limit or EOF, returning the bytes read.
async fn drain_bounded<R: io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: Limit,
    started: Instant,
) -> io::Result<u64> {
    let mut received = 0u64;
    while !limit.reached(received, started.elapsed()) {
        let n = Payload::of(CHUNK).drain(reader).await?;
        if n == 0 {
            break;
        }
        received += n;
    }
    Ok(received)
}

/// A session-level failure surfaced as an i/o error so it flows through [`ProtocolError::Io`].
fn io_from_session(error: bifrost::Error) -> ProtocolError {
    ProtocolError::Io(io::Error::other(error))
}

/// The measured result of a speed test.
#[derive(Debug, Clone, Copy)]
pub struct SpeedReport {
    direction: Direction,
    bytes: u64,
    elapsed: Duration,
}

impl SpeedReport {
    /// The direction measured.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// How many payload bytes moved.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// How long the transfer took.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Throughput in mebibytes per second. Zero if no time elapsed.
    pub fn mib_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        (self.bytes as f64 / (1024.0 * 1024.0)) / secs
    }
}
