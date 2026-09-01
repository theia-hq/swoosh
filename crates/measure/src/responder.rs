//! The diagnostic responder: what every "online" node runs to answer reach diagnostics. It serves an
//! accepted [`Session`]'s streams, dispatching each on its opening [`Request`]: echo a ping, drain a
//! sink, source a stream. Generic over `Session`, so the same responder answers over iroh (in
//! `swoosh serve`) and over mem (in tests).
//!
//! ping and speed are TWO independent services, not one: `ping` (cheap RTT) and `speed` (bandwidth-eating
//! throughput). A node may offer one without the other, and each carries its own gate, so the served
//! method MUST match the service that admitted the stream. [`answer_ping`] and [`answer_speed`] are the
//! two narrow entry points swoosh wires into the registry: each refuses the other's method at the wire
//! ([`ProtocolError::WrongService`]), so a `ping` grant can never open a speed drain even
//! though both speak the same frame. [`answer`] is the union of both, for a responder that serves
//! both over one session.

use bifrost::Session;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use tokio::io;

use crate::payload::Payload;
use crate::protocol::{ProtocolError, Request, Response};

/// Answers the diagnostic services on one session's streams.
pub struct Responder;

impl Responder {
    /// Serve a session until the peer goes away: handle each inbound stream concurrently, and keep the
    /// session alive when one stream fails so a single bad probe never drops the others.
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
        _ => refuse(&mut writer, "this node serves ping, not speed").await,
    }
}

/// Answer one inbound stream on the `speed` service: run the requested transfer (sink / source /
/// bidir), one per stream. A ping frame is refused with [`ProtocolError::WrongService`] for symmetry, so
/// a `speed` grant serves only throughput, never a liveness probe on the wrong wall.
pub async fn answer_speed<W, R>(mut writer: W, mut reader: R) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match Request::read(&mut reader).await? {
        Request::Ping { .. } => refuse(&mut writer, "this node serves speed, not ping").await,
        speed => serve_speed(&mut writer, &mut reader, speed).await,
    }
}

/// Answer one inbound stream on the union of both methods, dispatching on its opening
/// request. Used by [`Responder`], which serves ping and speed over one session; the split
/// [`answer_ping`]/[`answer_speed`] are what the gated registry wires when the two are distinct services.
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
        speed => serve_speed(&mut writer, &mut reader, speed).await,
    }
}

/// Run one speed transfer for an already-read speed request: drain a sink, source a download, or mirror a
/// full-duplex run. Shared by [`answer_speed`] and the union [`answer`], so the transfer engine has
/// one home. A [`Request::Ping`] is unreachable here (both callers peel it off first) and refused for
/// completeness.
async fn serve_speed<W, R>(
    writer: &mut W,
    reader: &mut R,
    request: Request,
) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match request {
        Request::Ping { .. } => refuse(writer, "this node serves speed, not ping").await,
        Request::SpeedSink { limit_bytes } => {
            let bytes = Payload::of(limit_bytes).drain(reader).await?;
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
            // A byte-bounded download sources an exact count; a time-bounded one sources until the
            // client stops reading at its deadline, so the client's wall clock is the sole terminator.
            source(writer, limit_bytes).await?;
            Ok(())
        }
        Request::SpeedBidir { limit_bytes } => {
            // Lead with the go-ahead frame (as the source path does) so the client's download half reads
            // "sourcing" or a refusal deterministically before any payload, then run both halves.
            Response::Sourcing.write(writer).await?;
            // Full-duplex: drain the client's upload to EOF while sourcing our download at once, so both
            // halves of the one stream carry counted payload simultaneously. The responder holds no
            // bound of its own; it mirrors the client. A byte bound sources an exact count and the
            // client's FIN ends the drain; a time bound sources until the client closes its read half at
            // its deadline (a broken pipe) and FINs its write half (an EOF here). Run both to completion.
            let (sourced, drained) = tokio::join!(
                source(writer, limit_bytes),
                Payload::of_or_until_peer(limit_bytes).drain(reader),
            );
            sourced?;
            drained?;
            Ok(())
        }
    }
}

/// Refuse a wrong-method frame LOUDLY: write a typed [`Response::Unsupported`] frame carrying `reason`
/// so the client decodes a refusal (not a silently dropped stream it would read as loss or zero bytes),
/// then return [`ProtocolError::WrongService`] so the stream task logs why it refused. This is the fix for
/// the false-success class: a wrong method is a frame on the wire, never a silent close.
async fn refuse<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    reason: &str,
) -> Result<(), ProtocolError> {
    Response::Unsupported {
        reason: reason.to_owned(),
    }
    .write(writer)
    .await?;
    Err(ProtocolError::WrongService)
}

/// Source counted download payload: an exact `Some(n)` bytes for a byte bound, or unbounded until the
/// client stops reading for a time bound (its deadline, not a byte count, is the terminator).
async fn source<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    limit_bytes: Option<u64>,
) -> io::Result<()> {
    let payload = match limit_bytes {
        Some(bytes) => Payload::of(bytes),
        None => Payload::until_peer_stops(),
    };
    payload.send(writer).await?;
    Ok(())
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
