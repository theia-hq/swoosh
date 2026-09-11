//! The measure stream protocol: a small, versioned frame that opens each diagnostic stream and selects
//! what the responder should do, before the measured bytes flow. A 4-byte magic guards every stream, then a
//! typed [`Request`], then a typed reply.
//!
//! Ping round-trips a whole frame (request then echoed reply). Speed sends the framed request, then a
//! counted byte stream flows in the chosen direction, then a framed reply reports the counted total.

use bifrost::{RefusalDetail, RefusalDetailError};
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// Magic plus version prefixing every request. A foreign or mismatched-version stream is rejected, so
/// a diagnostic stream is never confused with another protocol riding the same transport.
const MAGIC: [u8; 4] = *b"DG02";

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

/// A refused diagnostic run. One type for both layers, so a render site has exactly one refusal arm;
/// the layer is the variant, never a string prefix.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Layer 1: the host's gate or its resource refused the stream itself, arriving as
    /// [`bifrost::Error::Refused`].
    #[error("{0}")]
    Stream(bifrost::Refusal),
    /// Layer 2: the host admitted the stream, then refused the method.
    #[error("{code}: {detail}")]
    Method {
        /// The typed method-level code.
        code: MethodRefusal,
        /// The responder's bounded detail.
        detail: RefusalDetail,
    },
}

/// The method-level refusal code: the client's branch key, distinct from the prose. A new code forces a
/// render decision at every match site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MethodRefusal {
    /// The service does not serve the requested method (a ping frame on `speed`).
    #[error("this service does not serve that method")]
    WrongMethod,
    /// The service serves the method but is at its rate limit for this caller.
    #[error("rate limited")]
    RateLimited,
    /// The service serves the method but is busy right now (a transfer slot).
    #[error("busy")]
    Busy,
}

/// Wire tags for the [`MethodRefusal`] codes, beside the frame they select. A new code forces a tag
/// here and an arm in the reader.
mod refusal_tag {
    pub const WRONG_METHOD: u8 = 0;
    pub const RATE_LIMITED: u8 = 1;
    pub const BUSY: u8 = 2;
}

impl MethodRefusal {
    /// The wire tag for this code.
    fn tag(self) -> u8 {
        match self {
            Self::WrongMethod => refusal_tag::WRONG_METHOD,
            Self::RateLimited => refusal_tag::RATE_LIMITED,
            Self::Busy => refusal_tag::BUSY,
        }
    }

    /// Decode a wire tag, rejecting an unrecognized code rather than guessing.
    fn from_tag(tag: u8) -> Result<Self, ProtocolError> {
        match tag {
            refusal_tag::WRONG_METHOD => Ok(Self::WrongMethod),
            refusal_tag::RATE_LIMITED => Ok(Self::RateLimited),
            refusal_tag::BUSY => Ok(Self::Busy),
            other => Err(ProtocolError::UnknownRefusalCode(other)),
        }
    }
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
/// describes. Not `Copy`: [`Unsupported`](Self::Unsupported) carries an owned detail.
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
    /// arrived on the `speed` service, or a speed frame on `ping`. This is a TYPED refusal on the wire, so a
    /// client can tell "refused" from "measured
    /// badly" instead of reading a silently dropped stream as loss or zero bytes. The typed
    /// [`MethodRefusal`] code is the client's branch key; the bounded [`RefusalDetail`] is the prose it
    /// renders. A responder writes it instead of dropping the stream; a client decodes it to
    /// [`ProtocolError::Refused`], which no report can be constructed from.
    Unsupported {
        /// The typed method-level code the client branches on.
        code: MethodRefusal,
        /// The responder's bounded explanation, for a loud client-side error naming the peer and method.
        detail: RefusalDetail,
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
            Response::Unsupported { code, detail } => {
                writer.write_all(&[resp_tag::UNSUPPORTED]).await?;
                writer.write_all(&[code.tag()]).await?;
                write_detail(writer, detail).await
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
                code: MethodRefusal::from_tag(read_u8(reader).await?)?,
                detail: read_detail(reader).await?,
            }),
            other => Err(ProtocolError::UnknownResponse(other)),
        }
    }
}

async fn read_u8<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte).await?;
    Ok(byte[0])
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

/// Write a length-prefixed refusal detail: a `u32` byte count then the already-bounded UTF-8 bytes. The
/// value is a [`RefusalDetail`], bounded by construction, so the writer never truncates and can never cut
/// a codepoint; the checked conversion still fails the write rather than emitting a frame our reader
/// would reject.
async fn write_detail<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    detail: &RefusalDetail,
) -> io::Result<()> {
    let bytes = detail.as_str().as_bytes();
    let len =
        u32::try_from(bytes.len()).map_err(|_| io::Error::other("refusal detail too long"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(bytes).await
}

/// Read a length-prefixed refusal detail written by [`write_detail`]. An over-cap claim is rejected
/// BEFORE the reader allocates, and the bytes must be valid UTF-8: a corrupt or hostile frame is an
/// error, never repaired or lossily decoded.
async fn read_detail<R: io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<RefusalDetail, ProtocolError> {
    let len = read_u32(reader).await?;
    if len > RefusalDetail::MAX_LEN as u32 {
        return Err(ProtocolError::BadDetail(RefusalDetailError::TooLong(len)));
    }
    let mut bytes = vec![0u8; len as usize];
    reader.read_exact(&mut bytes).await?;
    Ok(RefusalDetail::try_from(bytes)?)
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
    /// The requested method was refused, at either layer: the host's gate or resource refused the whole
    /// stream (Layer 1, arriving as [`bifrost::Error::Refused`]), or the handler admitted the stream but
    /// does not serve this method (Layer 2, arriving as a [`Response::Unsupported`] frame). Distinct from
    /// [`Io`] and [`Mismatched`] on purpose: a refusal is NOT a measurement, so a report can never be
    /// built from it. A render site MUST surface this as a loud, distinct error, never as `0` /
    /// `100% loss` / `0.00 MiB/s`.
    ///
    /// [`Io`]: Self::Io
    #[error("refused: {0}")]
    Refused(Refusal),
    /// A refusal detail could not be trusted: the frame claimed a length over [`RefusalDetail::MAX_LEN`],
    /// or its bytes were not valid UTF-8. A corrupt or hostile stream, not a real refusal, so it is
    /// rejected rather than repaired.
    #[error("bad refusal detail")]
    BadDetail(#[from] RefusalDetailError),
    /// The refusal code was not recognized: a corrupt or future stream, never guessed at.
    #[error("unknown refusal code {0:#04x}")]
    UnknownRefusalCode(u8),
    /// The underlying stream failed while reading a frame.
    #[error("read frame")]
    Io(#[from] io::Error),
}

/// Map a session-level failure onto a protocol error. A typed refusal ([`bifrost::Error::Refused`]) is a
/// REFUSAL, not an i/o failure, so it maps to [`ProtocolError::Refused`] with the dialer-class refusal
/// preserved; every other session failure is a genuine [`ProtocolError::Io`]. This is the seam that stops
/// a typed refusal from arriving at the render path indistinguishable from a read error.
impl From<bifrost::Error> for ProtocolError {
    fn from(error: bifrost::Error) -> Self {
        match error {
            bifrost::Error::Refused(refusal) => ProtocolError::Refused(Refusal::Stream(refusal)),
            other => ProtocolError::Io(io::Error::other(other)),
        }
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
