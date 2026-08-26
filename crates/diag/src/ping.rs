//! The ping client: reach a peer over an established session and measure round-trip time, the classic
//! `ping(8)` shape. It opens one bidirectional stream, sends `count` probes at `interval`, echoes each
//! back, and reports min/avg/max/mdev and loss.
//!
//! RTT is measured locally with a monotonic [`Instant`]: the wire stamp in each frame is an opaque
//! nonce, never a clock we trust. Only replies that arrive are counted; a dropped or corrupt reply is
//! loss.

use core::time::Duration;
use std::time::Instant;

use bifrost::Session;
use tokio::io::AsyncWriteExt as _;
use tokio::time;

use crate::protocol::{ProtocolError, Request, Response};

/// A ping run against one peer: how many probes, how far apart.
#[derive(Debug, Clone, Copy)]
pub struct Ping {
    /// How many probes to send.
    pub count: u32,
    /// The delay between successive probes.
    pub interval: Duration,
}

impl Ping {
    /// Run the probes over an established session and return the gathered report. One-shot: consumes
    /// `self`, opens a single stream, and drives every probe on it in sequence.
    pub async fn run<S: Session>(self, session: &S) -> Result<PingReport, ProtocolError> {
        let Self { count, interval } = self;
        let (mut writer, mut reader) = session.open_bi().await.map_err(io_from_session)?;

        let mut rtts = Vec::with_capacity(count as usize);
        for seq in 0..count {
            if seq > 0 {
                time::sleep(interval).await;
            }
            match probe(&mut writer, &mut reader, seq).await {
                Ok(rtt) => rtts.push(rtt),
                Err(error) => tracing::warn!(%error, seq, "ping probe lost"),
            }
        }
        // Close the write half so the responder sees EOF and its stream task can finish cleanly.
        writer.shutdown().await.map_err(ProtocolError::Io)?;
        Ok(PingReport { sent: count, rtts })
    }
}

/// Send one probe and await its echo, returning the locally-measured round-trip time.
async fn probe<W, R>(writer: &mut W, reader: &mut R, seq: u32) -> Result<Duration, ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    // The nonce is opaque; a monotonic instant, not this stamp, is what times the round trip.
    let sent_unix_nanos = unix_nanos();
    let started = Instant::now();
    Request::Ping {
        seq,
        sent_unix_nanos,
    }
    .write(writer)
    .await?;

    match Response::read(reader).await? {
        Response::Pong {
            seq: echoed_seq,
            sent_unix_nanos: echoed_nonce,
        } if echoed_seq == seq && echoed_nonce == sent_unix_nanos => Ok(started.elapsed()),
        _ => Err(ProtocolError::Mismatched),
    }
}

/// A wall-clock stamp used only as an echo nonce, so a stale reply from an earlier probe is detectable.
fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0)
}

/// A session-level failure surfaced as an i/o error so it flows through [`ProtocolError::Io`].
fn io_from_session(error: bifrost::Error) -> ProtocolError {
    ProtocolError::Io(tokio::io::Error::other(error))
}

/// The gathered result of a ping run: the samples plus how many probes were sent.
#[derive(Debug, Clone)]
pub struct PingReport {
    sent: u32,
    rtts: Vec<Duration>,
}

impl PingReport {
    /// How many probes were sent.
    pub fn sent(&self) -> u32 {
        self.sent
    }

    /// How many replies came back.
    pub fn received(&self) -> u32 {
        self.rtts.len() as u32
    }

    /// The fraction of probes with no reply, in `0.0..=1.0`.
    pub fn loss(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        1.0 - (self.received() as f64 / self.sent as f64)
    }

    /// The smallest round-trip time observed, if any reply came back.
    pub fn min(&self) -> Option<Duration> {
        self.rtts.iter().copied().min()
    }

    /// The largest round-trip time observed, if any reply came back.
    pub fn max(&self) -> Option<Duration> {
        self.rtts.iter().copied().max()
    }

    /// The mean round-trip time, if any reply came back.
    pub fn avg(&self) -> Option<Duration> {
        if self.rtts.is_empty() {
            return None;
        }
        let total: Duration = self.rtts.iter().sum();
        Some(total / self.received())
    }

    /// The mean absolute deviation of round-trip time, as `ping(8)` reports it.
    pub fn mdev(&self) -> Option<Duration> {
        let avg = self.avg()?.as_secs_f64();
        let mean_abs_dev = self
            .rtts
            .iter()
            .map(|rtt| (rtt.as_secs_f64() - avg).abs())
            .sum::<f64>()
            / self.received() as f64;
        Some(Duration::from_secs_f64(mean_abs_dev))
    }
}
