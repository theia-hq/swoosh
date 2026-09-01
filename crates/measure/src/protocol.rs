//! The measure stream protocol: a small, versioned frame that opens each diagnostic stream and selects
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
    pub const SOURCING: u8 = 2;
    pub const UNSUPPORTED: u8 = 3;
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

/// A responder's typed reply, sent before (source, sourcing-ack) or after (ping, sink) the payload it
/// describes. Not `Copy`: [`Unsupported`](Self::Unsupported) carries an owned reason string.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The responder accepts a download and is about to source payload (reply to
    /// [`Request::SpeedSource`] / [`Request::SpeedBidir`]). A leading go-ahead frame is what lets the
    /// download client tell "here comes the payload" from a refusal on the very first read, so a
    /// wrong-method [`Unsupported`](Self::Unsupported) can never be drained as if it were zero bytes.
    Sourcing,
    /// The gate admitted this stream, but the handler does not serve the requested method: a ping frame
    /// arrived on the `speed` service, or a speed frame on `ping`. This is the measure twin of tightbeam's
    /// `Response::Error`: a TYPED refusal on the wire, so a client can tell "refused" from "measured
    /// badly" instead of reading a silently dropped stream as loss or zero bytes. A responder writes it
    /// instead of dropping the stream; a client decodes it to [`ProtocolError::Refused`], which no report
    /// can be constructed from.
    Unsupported {
        /// Why the method was refused, for a loud client-side error naming the peer and the method.
        reason: String,
    },
}

impl Response {
    /// Write the response frame (no magic: a response is only ever read on a stream we opened).
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        match self {
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
            Response::Sourcing => writer.write_all(&[resp_tag::SOURCING]).await,
            Response::Unsupported { reason } => {
                writer.write_all(&[resp_tag::UNSUPPORTED]).await?;
                write_str(writer, reason).await
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
            resp_tag::SOURCING => Ok(Response::Sourcing),
            resp_tag::UNSUPPORTED => Ok(Response::Unsupported {
                reason: read_str(reader).await?,
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

/// The longest refusal reason we will write or read, so a hostile or corrupt frame cannot make a client
/// allocate without bound. A refusal reason is a short human phrase; a kilobyte is generous headroom.
const MAX_REASON_LEN: u32 = 1024;

/// Write a length-prefixed UTF-8 string: a `u32` byte count then the bytes. The count is capped at
/// [`MAX_REASON_LEN`] so the reader can bound its allocation.
async fn write_str<W: io::AsyncWrite + Unpin>(writer: &mut W, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    let len = (bytes.len() as u32).min(MAX_REASON_LEN);
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&bytes[..len as usize]).await
}

/// Read a length-prefixed UTF-8 string written by [`write_str`], rejecting a length over
/// [`MAX_REASON_LEN`] (a corrupt or hostile frame) rather than allocating whatever it claims.
async fn read_str<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<String, ProtocolError> {
    let len = read_u32(reader).await?;
    if len > MAX_REASON_LEN {
        return Err(ProtocolError::ReasonTooLong(len));
    }
    let mut bytes = vec![0u8; len as usize];
    reader.read_exact(&mut bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Why a diagnostic frame could not be decoded.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The stream did not open with the measure magic (foreign or wrong-version stream).
    #[error("not a measure stream")]
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
    /// This service does not serve the requested method: a ping frame arrived on the `speed`
    /// service (or a speed frame on `ping`). These are two independent services with distinct
    /// gates, so the served method must match the service the gate admitted, at the wire, not just at
    /// the gate. Refusing here is what makes a `ping` grant unable to open a speed drain. The responder
    /// answers a wrong-method frame with [`Response::Unsupported`] and returns this so the stream task
    /// logs why it refused; a client decodes that frame to [`Refused`](Self::Refused).
    #[error("this service does not serve that method")]
    WrongService,
    /// The requested method was refused: either the gate refused the whole dial (Layer 1, arriving as a
    /// `bifrost::Error::Stream("service refused: …")`), or the handler admitted the stream but does not
    /// serve this method (Layer 2, arriving as a [`Response::Unsupported`] frame). Distinct from [`Io`]
    /// and [`Mismatched`] on purpose: a refusal is NOT a measurement, so a report can never be built from
    /// it. A render site MUST surface this as a loud, distinct error, never as `0` / `100% loss` /
    /// `0.00 MiB/s`.
    ///
    /// [`Io`]: Self::Io
    #[error("refused: {0}")]
    Refused(String),
    /// A refusal-reason frame claimed a length over [`MAX_REASON_LEN`]: a corrupt or hostile stream, not
    /// a real refusal, so it is rejected rather than allocated.
    #[error("refusal reason too long ({0} bytes)")]
    ReasonTooLong(u32),
    /// The underlying stream failed while reading a frame.
    #[error("read frame")]
    Io(#[from] io::Error),
}

/// The exact prefix tightbeam's `ServiceSession` gives a Layer-1 gate refusal when it surfaces the host's
/// reason through a `bifrost::Error::Stream`. Matching it here is what keeps a typed gate refusal typed
/// instead of laundering it into an anonymous [`ProtocolError::Io`]: the render path must be able to tell
/// "the gate refused you" from "the stream had an i/o error".
const GATE_REFUSAL_PREFIX: &str = "service refused: ";

/// Map a session-level failure onto a protocol error. A gate refusal (tightbeam's `Response::Error`,
/// surfaced as a `bifrost::Error::Stream` whose SOURCE reads `"service refused: …"`) is a REFUSAL, not an
/// i/o failure, so it maps to [`ProtocolError::Refused`] with the host's reason preserved; every other
/// session failure is a genuine [`ProtocolError::Io`]. This is the seam that stops a typed refusal from
/// arriving at the render path indistinguishable from a read error. The reason lives in the boxed source,
/// not the top-level `Display` (`bifrost::Error::Stream` renders as just "stream"), so we read the source.
impl From<bifrost::Error> for ProtocolError {
    fn from(error: bifrost::Error) -> Self {
        if let Some(reason) = gate_refusal_reason(&error) {
            return ProtocolError::Refused(reason);
        }
        ProtocolError::Io(io::Error::other(error))
    }
}

/// The refusal reason if `error` is a gate refusal, else `None`. Walks the source chain because
/// tightbeam boxes the `"service refused: <reason>"` text as the stream error's source.
fn gate_refusal_reason(error: &bifrost::Error) -> Option<String> {
    let mut source: Option<&(dyn core::error::Error + 'static)> = Some(error);
    while let Some(cause) = source {
        if let Some(reason) = cause.to_string().strip_prefix(GATE_REFUSAL_PREFIX) {
            return Some(reason.to_owned());
        }
        source = cause.source();
    }
    None
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
