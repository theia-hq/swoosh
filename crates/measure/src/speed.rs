//! The speed client: measure throughput to a peer over an established session, iperf-shaped but over
//! any bifrost transport. It opens one stream and, depending on [`Mode`], asks the responder to sink
//! (upload), source (download), or mirror (bidir) a payload, moves counted bytes until a byte or time
//! bound, and reports MiB/s. Bidir moves both directions at once on the one stream, so it measures
//! upload and download simultaneously and works over a single-stream transport (quirk).

use core::time::Duration;
use std::time::Instant;

use bifrost::Session;
use tokio::io::AsyncWriteExt as _;

use crate::payload::Payload;
pub use crate::payload::Progress;
use crate::protocol::{ProtocolError, Request, Response};

/// What a speed test measures: one direction, or both at once.
///
/// An enum, not two bools: the CLI's mutually-exclusive `--up`/`--down`/`--bidir` group maps onto
/// exactly these three states, so an impossible "both up and down but not bidir" is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Measure upload only (this node sends, the peer sinks).
    Up,
    /// Measure download only (the peer sources, this node sinks).
    Down,
    /// Measure upload and download at once, full-duplex on the one stream.
    Bidir,
}

impl Mode {
    /// The short human label for this mode, for a report header. The domain names its own modes, so a
    /// reporter (the CLI) never maps variants to strings itself.
    pub fn label(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Bidir => "bidir",
        }
    }
}

/// How much to transfer before stopping.
#[derive(Debug, Clone, Copy)]
pub enum Limit {
    /// Transfer for a fixed duration, then stop at the next chunk boundary.
    ByTime(Duration),
    /// Transfer a fixed number of bytes.
    ByBytes(u64),
}

/// A speed test against one peer: which mode, bounded by time or bytes.
#[derive(Debug, Clone)]
#[must_use = "a Speedtest does nothing until run"]
pub struct Speedtest {
    /// What to measure: up, down, or both at once.
    pub mode: Mode,
    /// When to stop.
    pub limit: Limit,
    /// A live byte counter for throughput-over-time reporting, or `None` for the final number only.
    pub progress: Option<Progress>,
}

impl Speedtest {
    /// A test with no live reporting: run it and read the final throughput.
    pub fn new(mode: Mode, limit: Limit) -> Self {
        Self {
            mode,
            limit,
            progress: None,
        }
    }

    /// Report cumulative bytes into `progress` as the run proceeds, so a caller can print the rate on a
    /// timer (iperf-style periodic lines) while the final [`SpeedReport`] still carries the totals.
    pub fn tracking(mut self, progress: Progress) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Run the test over an established session and return the measured throughput. One-shot: consumes
    /// `self` and drives the whole transfer on a single stream.
    pub async fn run<S: Session>(self, session: &S) -> Result<SpeedReport, ProtocolError> {
        let Self {
            mode,
            limit,
            progress,
        } = self;
        let (mut writer, mut reader) = session.open_bi().await?;

        // One window: bytes moved and time elapsed are both measured over this exact span.
        let started = Instant::now();
        let legs = match mode {
            Mode::Up => Legs::up(upload(&mut writer, &mut reader, limit, started, progress).await?),
            Mode::Down => {
                Legs::down(download(&mut writer, &mut reader, limit, started, progress).await?)
            }
            Mode::Bidir => bidir(&mut writer, &mut reader, limit, started, progress).await?,
        };
        let elapsed = started.elapsed();
        Ok(SpeedReport { legs, elapsed })
    }
}

/// Drive the upload leg: ask the responder to sink, stream counted bytes until the bound, then read the
/// count it confirmed receiving. Reports only confirmed bytes, so a shortfall (loss or truncation)
/// surfaces rather than laundering into a plausible-but-smaller throughput.
async fn upload<W, R>(
    writer: &mut W,
    reader: &mut R,
    limit: Limit,
    started: Instant,
    progress: Option<Progress>,
) -> Result<u64, ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    Request::SpeedSink {
        // The sink cap is only a ceiling; a time-bounded upload stops at the deadline well under it,
        // and the responder drains to the client's EOF regardless.
        limit_bytes: limit.byte_ceiling(),
    }
    .write(writer)
    .await?;
    let sent = limit.payload(started, progress).send(writer).await?;
    // Signal end-of-payload so the responder stops draining and replies with its count.
    writer.shutdown().await?;
    let bytes = match Response::read(reader).await? {
        Response::Received { bytes } => bytes,
        // A node that does not serve speed refuses the sink frame with `Unsupported` before draining a
        // byte: a typed `Refused`, never a plausible-but-smaller throughput.
        Response::Unsupported { reason } => return Err(ProtocolError::Refused(reason)),
        _ => return Err(ProtocolError::Mismatched),
    };
    if bytes < sent {
        tracing::warn!(
            sent,
            received = bytes,
            "peer received fewer bytes than sent"
        );
    }
    Ok(bytes.min(sent))
}

/// Drive a download leg that owns the whole stream: ask the responder to source, then drain the count.
async fn download<W, R>(
    writer: &mut W,
    reader: &mut R,
    limit: Limit,
    started: Instant,
    progress: Option<Progress>,
) -> Result<u64, ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    Request::SpeedSource {
        limit_bytes: limit.source_request(),
    }
    .write(writer)
    .await?;
    // Read the leading go-ahead frame before draining: a node that does not serve speed refuses here
    // with `Unsupported`, which must short-circuit as a typed `Refused`, never drain as zero bytes.
    expect_sourcing(reader).await?;
    let received = limit.payload(started, progress).drain(reader).await?;
    // A time-bounded download sources unbounded, so the client's deadline (which just fired to end the
    // drain) is the sole terminator. Shutting the write half sends a clean FIN so the responder's next
    // flood write hits a broken pipe and it stops. A byte-bounded download already ended on the count.
    writer.shutdown().await?;
    Ok(received)
}

/// Drive a full-duplex bidir run over the one stream: after the single `SpeedBidir` request, send
/// counted payload while draining counted payload at once, so both directions are measured over the
/// same window. The one request opens the exchange (the responder reads exactly one), so there is no
/// per-leg framing to interleave on the shared write half, and no trailing reply to corrupt the drain.
/// Upload here is client-sent bytes (there is no `Received` confirmation frame in this mode, since a
/// reply frame appended to the source payload would corrupt the download count); a reliable stream
/// delivers what was sent, so sent bytes are the honest upload figure. Works over quirk: a single
/// bidirectional stream carries both halves.
async fn bidir<W, R>(
    writer: &mut W,
    reader: &mut R,
    limit: Limit,
    started: Instant,
    progress: Option<Progress>,
) -> Result<Legs, ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    Request::SpeedBidir {
        limit_bytes: limit.source_request(),
    }
    .write(writer)
    .await?;
    // Read the leading go-ahead frame before either leg flows: a node that does not serve speed refuses
    // here with `Unsupported`, short-circuiting as a typed `Refused` rather than a zero-byte bidir run.
    expect_sourcing(reader).await?;

    // Both legs feed the one counter, so a bidir progress line reports the aggregate the session moved;
    // the final per-leg totals still come from the returned counts.
    let (up_progress, down_progress) = (progress.clone(), progress);
    let send = async {
        let sent = limit.payload(started, up_progress).send(writer).await?;
        // FIN the write half so the responder's drain sees EOF and stops mirroring.
        writer.shutdown().await?;
        Ok::<u64, ProtocolError>(sent)
    };
    let drain = async {
        Ok::<u64, ProtocolError>(limit.payload(started, down_progress).drain(reader).await?)
    };

    let (up, down) = tokio::join!(send, drain);
    Ok(Legs {
        up: Some(up?),
        down: Some(down?),
    })
}

/// Read the leading response a download expects before the payload flows: [`Response::Sourcing`] is the
/// go-ahead, [`Response::Unsupported`] is a wrong-method refusal (a node that serves ping, not speed),
/// mapped to a typed [`ProtocolError::Refused`] so it short-circuits the run rather than draining as
/// zero bytes. Any other frame is a protocol violation.
async fn expect_sourcing<R>(reader: &mut R) -> Result<(), ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    match Response::read(reader).await? {
        Response::Sourcing => Ok(()),
        Response::Unsupported { reason } => Err(ProtocolError::Refused(reason)),
        _ => Err(ProtocolError::Mismatched),
    }
}

impl Limit {
    /// The payload transfer this limit drives from `started`: a byte bound moves an exact count, a time
    /// bound moves chunks until its deadline. Attaches `progress` when given, so the client-side leg of a
    /// tracked run bumps the shared counter each chunk.
    fn payload(self, started: Instant, progress: Option<Progress>) -> Payload {
        let payload = match self {
            Limit::ByBytes(bytes) => Payload::of(bytes),
            Limit::ByTime(duration) => Payload::until(started + duration),
        };
        match progress {
            Some(progress) => payload.tracking(progress),
            None => payload,
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

/// The measured bytes of a run, one leg per direction exercised. A one-way run fills exactly one leg; a
/// bidir run fills both, measured over the same window.
#[derive(Debug, Clone, Copy)]
struct Legs {
    up: Option<u64>,
    down: Option<u64>,
}

impl Legs {
    /// A run that measured only the upload direction.
    fn up(bytes: u64) -> Self {
        Self {
            up: Some(bytes),
            down: None,
        }
    }

    /// A run that measured only the download direction.
    fn down(bytes: u64) -> Self {
        Self {
            up: None,
            down: Some(bytes),
        }
    }
}

/// The measured result of a speed test: throughput per direction over a shared window.
#[derive(Debug, Clone, Copy)]
#[must_use = "a SpeedReport is the result of the run and should be reported"]
pub struct SpeedReport {
    legs: Legs,
    elapsed: Duration,
}

impl SpeedReport {
    /// The upload leg, if this run measured it: bytes moved and the throughput over the window.
    pub fn up(&self) -> Option<Throughput> {
        self.legs.up.map(|bytes| self.throughput(bytes))
    }

    /// The download leg, if this run measured it: bytes moved and the throughput over the window.
    pub fn down(&self) -> Option<Throughput> {
        self.legs.down.map(|bytes| self.throughput(bytes))
    }

    /// How long the transfer took, the window both legs are measured over.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    fn throughput(&self, bytes: u64) -> Throughput {
        Throughput {
            bytes,
            elapsed: self.elapsed,
        }
    }
}

/// One direction's measured throughput: bytes moved over the run's window.
#[derive(Debug, Clone, Copy)]
pub struct Throughput {
    bytes: u64,
    elapsed: Duration,
}

impl Throughput {
    /// How many payload bytes moved in this direction.
    pub fn bytes(&self) -> u64 {
        self.bytes
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
