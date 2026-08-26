//! The speed client: measure throughput to a peer over an established session, iperf-shaped but over
//! any bifrost transport. It opens one stream, asks the responder to sink (upload) or source
//! (download) a payload, moves counted bytes until a byte or time bound, and reports MiB/s.

use core::time::Duration;
use std::time::Instant;

use bifrost::Session;
use tokio::io::AsyncWriteExt as _;

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

/// A speed test against one peer: which direction, bounded by time or bytes.
#[derive(Debug, Clone, Copy)]
#[must_use = "a Speedtest does nothing until run"]
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
        let (mut writer, mut reader) = session.open_bi().await?;

        // One window: bytes moved and time elapsed are both measured over this exact span.
        let started = Instant::now();
        let bytes = match direction {
            Direction::Up => {
                Request::SpeedSink {
                    // The sink cap is only a ceiling; a time-bounded upload stops at the deadline well
                    // under it, and the responder drains to the client's EOF regardless.
                    limit_bytes: limit.byte_ceiling(),
                }
                .write(&mut writer)
                .await?;
                let sent = limit.payload(started).send(&mut writer).await?;
                // Signal end-of-payload so the responder stops draining and replies with its count.
                writer.shutdown().await?;
                let Response::Received { bytes } = Response::read(&mut reader).await? else {
                    return Err(ProtocolError::Mismatched);
                };
                // Report only bytes the peer confirmed receiving. Over a reliable stream the two counts
                // match; a shortfall means loss or truncation, a real signal worth surfacing, not
                // laundering silently into a smaller (but plausible) throughput number.
                if bytes < sent {
                    tracing::warn!(
                        sent,
                        received = bytes,
                        "peer received fewer bytes than sent"
                    );
                }
                bytes.min(sent)
            }
            Direction::Down => {
                Request::SpeedSource {
                    limit_bytes: limit.source_request(),
                }
                .write(&mut writer)
                .await?;
                let received = limit.payload(started).drain(&mut reader).await?;
                // A time-bounded download sources unbounded, so the client's deadline (which just fired
                // to end the drain) is the sole terminator. Dropping the read half closes it, so the
                // responder's next flood write hits a broken pipe and it stops; shutting the write half
                // sends a clean FIN too. A byte-bounded download already ended on the exact count.
                drop(reader);
                writer.shutdown().await?;
                received
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
    /// The payload transfer this limit drives from `started`: a byte bound moves an exact count, a time
    /// bound moves chunks until its deadline.
    fn payload(self, started: Instant) -> Payload {
        match self {
            Limit::ByBytes(bytes) => Payload::of(bytes),
            Limit::ByTime(duration) => Payload::until(started + duration),
        }
    }

    /// What a `--down` client asks the responder to source: `Some(n)` for an exact byte count, `None`
    /// (unbounded) for a time bound, where the client's deadline, not a byte count, ends the run.
    fn source_request(self) -> Option<u64> {
        match self {
            Limit::ByBytes(bytes) => Some(bytes),
            Limit::ByTime(_) => None,
        }
    }

    /// The largest number of bytes a `--up` run could send, an upper bound for the sink's ceiling. A
    /// time bound has no exact count, so it uses [`u64::MAX`]; the client's EOF ends the drain first.
    fn byte_ceiling(self) -> u64 {
        match self {
            Limit::ByBytes(bytes) => bytes,
            Limit::ByTime(_) => u64::MAX,
        }
    }
}

/// The measured result of a speed test.
#[derive(Debug, Clone, Copy)]
#[must_use = "a SpeedReport is the result of the run and should be reported"]
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
