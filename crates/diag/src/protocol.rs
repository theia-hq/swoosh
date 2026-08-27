//! The diag stream protocol: a small, versioned frame that opens each diagnostic stream and selects
//! what the responder should do, before the measured bytes flow. Same shape as tightbeam's
//! `protocol.rs`: a 4-byte magic guards every stream, then a typed [`Request`], then a typed reply.
//!
//! Ping round-trips a whole frame (request then echoed reply). Speed sends the framed request, then a
//! counted byte stream flows in the chosen direction, then a framed reply reports the counted total.

use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// Magic plus version prefixing every request. A foreign or mismatched-version stream is rejected, so
/// a diagnostic stream is never confused with another protocol riding the same transport.
const MAGIC: [u8; 4] = *b"DG01";

/// What a client asks a responder to do on a freshly opened stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Echo this frame back verbatim. `sent_unix_nanos` is an opaque client-chosen nonce the responder
    /// returns untouched; the client times the round trip locally with a monotonic clock and never
    /// trusts this stamp (two machines' clocks are not comparable).
    Ping {
        /// The client's sequence number for this probe.
        seq: u32,
        /// The client's send stamp, echoed back verbatim as a nonce.
        sent_unix_nanos: u64,
    },
    /// The client is about to send `limit_bytes` for the responder to drain and count (upload / sink).
    SpeedSink {
        /// How many payload bytes the client will send after this frame.
        limit_bytes: u64,
    },
    /// The responder should stream counted payload for the client to drain (download). `limit_bytes`
    /// is `Some(n)` for a byte-bounded run (send exactly `n`) or `None` for a time-bounded run, where
    /// the responder streams until the client stops reading and its wall-clock deadline is the sole
    /// terminator. Encoded with a [`UNBOUNDED`] sentinel so the wire stays a fixed-width `u64`.
    SpeedSource {
        /// How many payload bytes to send, or `None` to stream until the client closes the stream.
        limit_bytes: Option<u64>,
    },
    /// Full-duplex speed: both ends send and drain counted payload at once on this one stream, so it
    /// measures upload and download simultaneously and works over a single-stream transport (quirk).
    /// The responder mirrors the client: it drains the client's upload to EOF while sourcing its own
    /// download, `Some(n)` bytes for a byte bound or unbounded for a time bound, where the client's
    /// close of its read half ends the responder's source. Encoded with the [`UNBOUNDED`] sentinel like
    /// [`SpeedSource`](Self::SpeedSource), so the wire stays a fixed-width `u64`.
    SpeedBidir {
        /// How many payload bytes to move each direction, or `None` to run until the client stops.
        limit_bytes: Option<u64>,
    },
}

/// The wire value of an unbounded [`Request::SpeedSource`]. `u64::MAX` bytes is unreachable in any real
/// transfer, so it reads unambiguously as "stream until the client stops" rather than a byte count.
const UNBOUNDED: u64 = u64::MAX;

/// Wire tags for the [`Request`] variants, kept next to the frame they select.
mod tag {
    pub const PING: u8 = 0;
    pub const SPEED_SINK: u8 = 1;
    pub const SPEED_SOURCE: u8 = 2;
    pub const SPEED_BIDIR: u8 = 3;
}

/// Wire tags for the [`Response`] variants. A response has its own tag namespace, independent of
/// [`tag`], so a new reply variant never has to dodge a request tag to stay legible.
mod resp_tag {
    pub const PONG: u8 = 0;
    pub const RECEIVED: u8 = 1;
}

impl Request {
    /// Write the framed request: magic, tag, then the variant's fields.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&MAGIC).await?;
        match *self {
            Request::Ping {
                seq,
                sent_unix_nanos,
            } => {
                writer.write_all(&[tag::PING]).await?;
                writer.write_all(&seq.to_be_bytes()).await?;
                writer.write_all(&sent_unix_nanos.to_be_bytes()).await
            }
            Request::SpeedSink { limit_bytes } => {
                writer.write_all(&[tag::SPEED_SINK]).await?;
                writer.write_all(&limit_bytes.to_be_bytes()).await
            }
            Request::SpeedSource { limit_bytes } => {
                writer.write_all(&[tag::SPEED_SOURCE]).await?;
                writer
                    .write_all(&limit_bytes.unwrap_or(UNBOUNDED).to_be_bytes())
                    .await
            }
            Request::SpeedBidir { limit_bytes } => {
                writer.write_all(&[tag::SPEED_BIDIR]).await?;
                writer
                    .write_all(&limit_bytes.unwrap_or(UNBOUNDED).to_be_bytes())
                    .await
            }
        }
    }

    /// Read a framed request, rejecting a stream that does not open with our magic.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).await?;
        if magic != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag).await?;
        match tag[0] {
            tag::PING => Ok(Request::Ping {
                seq: read_u32(reader).await?,
                sent_unix_nanos: read_u64(reader).await?,
            }),
            tag::SPEED_SINK => Ok(Request::SpeedSink {
                limit_bytes: read_u64(reader).await?,
            }),
            tag::SPEED_SOURCE => {
                let limit_bytes = read_u64(reader).await?;
                Ok(Request::SpeedSource {
                    limit_bytes: (limit_bytes != UNBOUNDED).then_some(limit_bytes),
                })
            }
            tag::SPEED_BIDIR => {
                let limit_bytes = read_u64(reader).await?;
                Ok(Request::SpeedBidir {
                    limit_bytes: (limit_bytes != UNBOUNDED).then_some(limit_bytes),
                })
            }
            other => Err(ProtocolError::UnknownRequest(other)),
        }
    }
}

/// A responder's typed reply, sent before (source) or after (ping, sink) the payload it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// The echoed ping, carrying the request's `seq` and nonce untouched.
    Pong {
        /// The sequence number from the matching [`Request::Ping`].
        seq: u32,
        /// The nonce from the matching [`Request::Ping`], returned verbatim.
        sent_unix_nanos: u64,
    },
    /// The responder drained and counted this many bytes (reply to [`Request::SpeedSink`]).
    Received {
        /// How many payload bytes the responder read before EOF.
        bytes: u64,
    },
}

impl Response {
    /// Write the response frame (no magic: a response is only ever read on a stream we opened).
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        match *self {
            Response::Pong {
                seq,
                sent_unix_nanos,
            } => {
                writer.write_all(&[resp_tag::PONG]).await?;
                writer.write_all(&seq.to_be_bytes()).await?;
                writer.write_all(&sent_unix_nanos.to_be_bytes()).await
            }
            Response::Received { bytes } => {
                writer.write_all(&[resp_tag::RECEIVED]).await?;
                writer.write_all(&bytes.to_be_bytes()).await
            }
        }
    }

    /// Read a response frame.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag).await?;
        match tag[0] {
            resp_tag::PONG => Ok(Response::Pong {
                seq: read_u32(reader).await?,
                sent_unix_nanos: read_u64(reader).await?,
            }),
            resp_tag::RECEIVED => Ok(Response::Received {
                bytes: read_u64(reader).await?,
            }),
            other => Err(ProtocolError::UnknownResponse(other)),
        }
    }
}

async fn read_u32<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes).await?;
    Ok(u32::from_be_bytes(bytes))
}

async fn read_u64<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes).await?;
    Ok(u64::from_be_bytes(bytes))
}

/// Why a diagnostic frame could not be decoded.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The stream did not open with the diag magic (foreign or wrong-version stream).
    #[error("not a diag stream")]
    BadMagic,
    /// The request tag was not recognized.
    #[error("unknown request tag {0:#04x}")]
    UnknownRequest(u8),
    /// The response tag was not recognized.
    #[error("unknown response tag {0:#04x}")]
    UnknownResponse(u8),
    /// A well-formed reply did not match the request it answered (wrong sequence or nonce).
    #[error("reply did not match the probe")]
    Mismatched,
    /// The underlying stream failed while reading a frame.
    #[error("read frame")]
    Io(#[from] io::Error),
}

/// A session-level failure (opening a stream, connecting) surfaces as an i/o error so it flows through
/// [`ProtocolError::Io`] alongside the stream-read failures, one error type for the whole engine.
impl From<bifrost::Error> for ProtocolError {
    fn from(error: bifrost::Error) -> Self {
        ProtocolError::Io(io::Error::other(error))
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
