//! The diagnostic responder bodies: what an admitted diagnostic stream does, one method at a time.
//!
//! ping and speed are TWO independent services, not one: `ping` (cheap RTT) and `speed` (bandwidth-eating
//! throughput). A node may offer one without the other, and each carries its own gate, so the served
//! method MUST match the service that admitted the stream. [`answer_ping`] and [`answer_speed`] are the
//! two narrow entry points the composing consumer wires into the route table: each refuses the other's
//! method at the wire ([`ProtocolError::WrongService`]), so a `ping` grant can never open a speed drain
//! even though both speak the same frame. [`answer_speed`] applies the [`Limits`] its route was built
//! with; [`answer`] is the union of both, unmetered, for a responder that serves both over one session.

use core::time::Duration;

use bifrost::{RefusalDetail, Session};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use tokio::{io, time};

use crate::limits::Limits;
use crate::payload::Payload;
use crate::protocol::{MethodRefusal, ProtocolError, Request, Response};

/// Answers the diagnostic services on one session's streams.
pub struct Responder;

impl Responder {
    /// Serve a session until the peer goes away: handle each inbound stream concurrently, and keep the
    /// session alive when one stream fails so a single bad probe never drops the others. The union path
    /// mirrors the client, so it enforces no responder-side bound.
    pub async fn serve<S: Session>(session: S) {
        let mut streams = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = session.accept_bi() => {
                    let Ok((writer, reader)) = accepted else {
                        // The peer closed the session (or the transport failed): stop serving it.
                        return;
                    };
                    streams.push(answer(writer, reader));
                }
                Some(result) = streams.next(), if !streams.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "diagnostic stream ended");
                    }
                }
            }
        }
    }
}

/// The responder-side bounds one speed stream enforces: the largest payload it moves per direction and the
/// longest it runs. `None` on either is unbounded (the mirror-the-client behavior), which a caller may
/// choose only through [`Limits::unmetered`](crate::Limits::unmetered) and then owns the banner caveat.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SpeedCaps {
    /// The largest payload one direction may move, or `None` for unbounded.
    pub(crate) max_bytes: Option<u64>,
    /// The longest the stream may run, or `None` for unbounded.
    pub(crate) max_duration: Option<Duration>,
}

impl SpeedCaps {
    /// Bound a requested byte count: an explicit request is clamped to the cap, and an unbounded source
    /// (`None`) becomes the cap itself, so a metered run always carries its own byte bound.
    pub(crate) fn clamp(&self, limit_bytes: Option<u64>) -> Option<u64> {
        match (self.max_bytes, limit_bytes) {
            (Some(cap), Some(requested)) => Some(requested.min(cap)),
            (Some(cap), None) => Some(cap),
            (None, requested) => requested,
        }
    }
}

/// Answer one inbound stream on the `ping` service: echo the opening ping and every probe on it
/// (the client sends its whole run over one stream). A non-ping frame is a wire-level violation, not a
/// silent widening: the outer `ping` gate admitted this stream for liveness only, so a speed frame
/// here is refused with [`ProtocolError::WrongService`].
pub async fn answer_ping<W, R>(mut writer: W, mut reader: R) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match Request::read(&mut reader).await? {
        Request::Ping {
            seq,
            sent_unix_nanos,
        } => echo_pings(&mut writer, &mut reader, seq, sent_unix_nanos).await,
        _ => {
            refuse(
                &mut writer,
                MethodRefusal::WrongMethod,
                "this node serves ping, not speed",
            )
            .await
        }
    }
}

/// Answer one inbound stream on the `speed` service: run the requested transfer (sink / source /
/// bidir), one per stream, bounded by `limits`. A ping frame is refused with
/// [`ProtocolError::WrongService`] for symmetry, so a `speed` grant serves only throughput, never a
/// liveness probe on the wrong wall.
pub async fn answer_speed<W, R>(
    mut writer: W,
    mut reader: R,
    limits: Limits,
) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let caps = limits.speed_caps();
    // One deadline for the whole stream: the request read and the transfer share the cap, so a caller
    // that stalls before naming a method is bounded too, never parked open until the client stops.
    let deadline = caps.max_duration.map(|cap| time::Instant::now() + cap);
    let request = match deadline {
        Some(deadline) => match time::timeout_at(deadline, Request::read(&mut reader)).await {
            Ok(request) => request?,
            // The cap fired before a method arrived; close cleanly, nothing was served.
            Err(_past_deadline) => return Ok(()),
        },
        None => Request::read(&mut reader).await?,
    };
    match request {
        Request::Ping { .. } => {
            refuse(
                &mut writer,
                MethodRefusal::WrongMethod,
                "this node serves speed, not ping",
            )
            .await
        }
        speed => serve_speed(&mut writer, &mut reader, speed, caps, deadline).await,
    }
}

/// Answer one inbound stream on the union of both methods, dispatching on its opening request. Used by
/// [`Responder`], which serves ping and speed over one session; the split [`answer_ping`]/[`answer_speed`]
/// are what the gated route table wires when the two are distinct services. Mirrors the client, like the
/// responder always has: no responder-side bound.
pub async fn answer<W, R>(mut writer: W, mut reader: R) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match Request::read(&mut reader).await? {
        Request::Ping {
            seq,
            sent_unix_nanos,
        } => echo_pings(&mut writer, &mut reader, seq, sent_unix_nanos).await,
        speed => serve_speed(&mut writer, &mut reader, speed, SpeedCaps::default(), None).await,
    }
}

/// Run one speed transfer for an already-read speed request: drain a sink, source a download, or mirror a
/// full-duplex run, each clamped to `caps` and stopped at `deadline` when one is set. Shared by
/// [`answer_speed`] and the union [`answer`], so the transfer engine has one home. A [`Request::Ping`] is
/// unreachable here (both callers peel it off first) and refused for completeness.
async fn serve_speed<W, R>(
    writer: &mut W,
    reader: &mut R,
    request: Request,
    caps: SpeedCaps,
    deadline: Option<time::Instant>,
) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match request {
        Request::Ping { .. } => {
            refuse(
                writer,
                MethodRefusal::WrongMethod,
                "this node serves speed, not ping",
            )
            .await
        }
        Request::SpeedSink { limit_bytes } => {
            // The sink drains the client's upload, clamped to the cap: a metered node never accepts more
            // than its configured bound, and the count it reports is the bytes it actually took. A
            // deadline stop is no exception: the drain returns its partial count and the reply carries
            // it, so a capped sink is a short count, never a dropped frame.
            let bounded = caps.clamp(Some(limit_bytes)).unwrap_or(limit_bytes);
            let bytes = drain(reader, Some(bounded), deadline).await?;
            Response::Received { bytes }
                .write(writer)
                .await
                .map_err(ProtocolError::from)
        }
        Request::SpeedSource { limit_bytes } => {
            // A leading go-ahead frame precedes the payload so the client can tell "here comes the
            // download" from a refusal on its first read; a wrong-method node writes `Unsupported`
            // instead (in `answer_ping`), so the download can never drain a refusal as zero bytes.
            Response::Sourcing.write(writer).await?;
            // A cap turns an unbounded source into a byte- or time-bounded one, so a metered run always
            // terminates on the responder's own terms; an unmetered one sources until the client stops.
            source(writer, caps.clamp(limit_bytes), deadline).await?;
            Ok(())
        }
        Request::SpeedBidir { limit_bytes } => {
            // Lead with the go-ahead frame (as the source path does) so the client's download half reads
            // "sourcing" or a refusal deterministically before any payload, then run both halves.
            Response::Sourcing.write(writer).await?;
            // Full-duplex: drain the client's upload while sourcing our download at once, both clamped to
            // the same cap and stopped at the same deadline. Run both to completion.
            let bounded = caps.clamp(limit_bytes);
            let (sourced, drained) = tokio::join!(
                source(writer, bounded, deadline),
                drain(reader, bounded, deadline),
            );
            sourced?;
            drained?;
            Ok(())
        }
    }
}

/// Write a typed refusal frame LOUDLY: a [`Response::Unsupported`] carrying `code` and a bounded detail
/// off `reason`, so the client decodes a refusal (not a silently dropped stream it would read as loss or
/// zero bytes), then return [`ProtocolError::WrongService`] so the stream task logs why it refused. This
/// is the fix for the false-success class: a refused frame is a frame on the wire, never a silent close.
///
/// Public because the splitting handlers live in the composed tree, outside this crate: a `ping` route
/// over its per-caller rate bound and a `speed` route with no free transfer slot both refuse through the
/// same frame shape the wrong-method bodies use, so every Layer 2 refusal reads identically on the wire.
pub async fn refuse<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    code: MethodRefusal,
    reason: &str,
) -> Result<(), ProtocolError> {
    Response::Unsupported {
        code,
        detail: RefusalDetail::bounded(reason),
    }
    .write(writer)
    .await?;
    Err(ProtocolError::WrongService)
}

/// Drain the client's upload to `limit_bytes` (or to EOF when `None`), stopping at `deadline` when one
/// is set and returning the count taken. A deadline stop keeps the partial count, so a capped sink
/// reports what it actually took rather than losing the count to the stop.
async fn drain<R: io::AsyncRead + Unpin>(
    reader: &mut R,
    limit_bytes: Option<u64>,
    deadline: Option<time::Instant>,
) -> Result<u64, ProtocolError> {
    Payload::of_or_until_peer(limit_bytes)
        .drain_within(reader, deadline)
        .await
        .map_err(ProtocolError::from)
}

/// Source counted download payload: an exact `Some(n)` bytes for a byte bound, or unbounded until the
/// client stops reading. Stops at `deadline` when one is set and closes the stream: a capped source is
/// a truncated close, never an unbounded run.
async fn source<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    limit_bytes: Option<u64>,
    deadline: Option<time::Instant>,
) -> io::Result<()> {
    let payload = match limit_bytes {
        Some(bytes) => Payload::of(bytes),
        None => Payload::until_peer_stops(),
    };
    match deadline {
        Some(deadline) => match time::timeout_at(deadline, payload.send(writer)).await {
            Ok(result) => result.map(|_| ()),
            // Cancelled at the cap: the stream closes behind a partial payload, so the client reads a
            // truncated stream, never a hang.
            Err(_past_deadline) => Ok(()),
        },
        None => payload.send(writer).await.map(|_| ()),
    }
}

/// Echo the opening ping, then every subsequent ping on the same stream until the client closes it.
async fn echo_pings<W, R>(
    writer: &mut W,
    reader: &mut R,
    mut seq: u32,
    mut sent_unix_nanos: u64,
) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    loop {
        Response::Pong {
            seq,
            sent_unix_nanos,
        }
        .write(writer)
        .await?;

        match Request::read(reader).await {
            Ok(Request::Ping {
                seq: next_seq,
                sent_unix_nanos: next_nonce,
            }) => {
                seq = next_seq;
                sent_unix_nanos = next_nonce;
            }
            // A clean EOF ends the probe run; any other outcome is a real stream error.
            Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Ok(_) => return Err(ProtocolError::Mismatched),
            Err(error) => return Err(error),
        }
    }
}
