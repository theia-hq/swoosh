//! The diagnostic responder: what every "online" node runs to answer reach diagnostics. It serves an
//! accepted [`Session`]'s streams, dispatching each on its opening [`Request`]: echo a ping, drain a
//! sink, source a stream. Generic over `Session`, so the same responder answers over iroh (in
//! `swoosh serve`) and over mem (in tests).

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

/// Answer one inbound diagnostic stream by dispatching on its opening request. Ping keeps the stream
/// open and echoes every probe on it (the client sends its whole run over one stream); a speed request
/// is one transfer per stream.
async fn answer<W, R>(mut writer: W, mut reader: R) -> Result<(), ProtocolError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match Request::read(&mut reader).await? {
        Request::Ping {
            seq,
            sent_unix_nanos,
        } => echo_pings(&mut writer, &mut reader, seq, sent_unix_nanos).await,
        Request::SpeedSink { limit_bytes } => {
            let bytes = Payload::of(limit_bytes).drain(&mut reader).await?;
            Response::Received { bytes }
                .write(&mut writer)
                .await
                .map_err(ProtocolError::from)
        }
        Request::SpeedSource { limit_bytes } => {
            Payload::of(limit_bytes).send(&mut writer).await?;
            Ok(())
        }
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
