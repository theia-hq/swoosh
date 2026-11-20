//! What crosses an Open's control connection after Attached: SWC1 frames both ways.
//!
//! A unix socket carries no reset, so an end of file says nothing about whether the writer finished or
//! died. Each direction therefore says it finished: Data frames carry the bytes, and one End frame
//! closes the direction cleanly. Any other end of a direction, an end of file, a half-close or a
//! malformed frame, is a cut-off. Toward the client the resident also writes one Landed frame, once the
//! peer holds the whole upload and its end.
//!
//! | Tag | Frame | Body | Direction |
//! | --- | --- | --- | --- |
//! | 10 | Data | 1 to 8192 bytes | both |
//! | 11 | End | empty | both |
//! | 12 | Landed | empty | toward the client only |
//!
//! The tags sit above every request (1 to 6) and reply (1 to 9) tag, so a frame read in the wrong phase
//! is never taken for an operation. There is no abort frame: closing without End already says it.

use tokio::io::{
    self, AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite,
    AsyncWriteExt as _, BufReader,
};

use super::{IDENTITY, MAX_FRAME, VERSION};

/// A frame header's length: the four magic bytes, the tag and a two-byte body length.
pub(crate) const HEADER: usize = 7;

/// One frame header and the largest Data body: the one buffer each framed direction holds.
pub(crate) const FRAME_BUFFER: usize = HEADER + MAX_FRAME;

/// A reader of frames from `reader`, its buffer sized to [`FRAME_BUFFER`] so a whole frame, header and
/// body, moves through it in place. Every framed reader is built here, so none can drift from the size.
pub(crate) fn frame_reader<R: AsyncRead>(reader: R) -> BufReader<R> {
    BufReader::with_capacity(FRAME_BUFFER, reader)
}

const DATA: u8 = 10;
const END: u8 = 11;
const LANDED: u8 = 12;

/// A Data body's length, 1 to [`MAX_FRAME`], so neither an empty nor an oversized Data frame can be
/// spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataLen(u16);

impl DataLen {
    /// `len` as a Data body's length, or `None` outside 1 to [`MAX_FRAME`].
    pub(crate) fn new(len: usize) -> Option<Self> {
        if len == 0 || len > MAX_FRAME {
            return None;
        }
        u16::try_from(len).ok().map(Self)
    }

    /// The length in bytes.
    pub(crate) fn get(self) -> usize {
        usize::from(self.0)
    }
}

/// One splice-phase frame, as its header names it. A Data frame's body follows its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Frame {
    /// Bytes of the stream.
    Data(DataLen),
    /// The direction ended cleanly.
    End,
    /// Toward the client only: the peer holds the whole upload and its end.
    Landed,
}

/// Which way a frame travels, which decides whether Landed may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Toward {
    /// Written by the client, read by the resident.
    Peer,
    /// Written by the resident, read by the client.
    Client,
}

/// Why a splice-phase frame header was refused. Payload-free: a frame's bytes are the stream's, never
/// a diagnostic's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MalformedFrame {
    /// The header does not open with `SWC1`.
    #[error("splice frame magic is wrong")]
    Magic,
    /// A tag this direction does not carry.
    #[error("splice frame tag is unknown")]
    Tag,
    /// A Data frame with no body.
    #[error("splice data frame is empty")]
    Empty,
    /// A declared body over the frame ceiling, refused before a byte of it is read.
    #[error("splice frame is over the frame ceiling")]
    TooLong,
    /// An End or Landed frame that declares a body.
    #[error("splice end frame has a body")]
    Body,
}

impl From<MalformedFrame> for io::Error {
    fn from(malformed: MalformedFrame) -> Self {
        Self::new(io::ErrorKind::InvalidData, malformed)
    }
}

impl Frame {
    /// Parse a header read off the connection, travelling `toward`. The length is checked against the
    /// tag before any body byte is read.
    pub(crate) fn parse(header: [u8; HEADER], toward: Toward) -> Result<Self, MalformedFrame> {
        let [i, d, c, v, tag, high, low] = header;
        if [i, d, c] != IDENTITY || [v] != *VERSION.as_bytes() {
            return Err(MalformedFrame::Magic);
        }
        let len = usize::from(u16::from_be_bytes([high, low]));
        let empty = |frame| {
            if len == 0 {
                Ok(frame)
            } else {
                Err(MalformedFrame::Body)
            }
        };
        match (tag, toward) {
            (DATA, _) if len == 0 => Err(MalformedFrame::Empty),
            (DATA, _) => DataLen::new(len)
                .map(Self::Data)
                .ok_or(MalformedFrame::TooLong),
            (END, _) => empty(Self::End),
            (LANDED, Toward::Client) => empty(Self::Landed),
            _ => Err(MalformedFrame::Tag),
        }
    }

    /// The frame's header as it goes on the wire.
    pub(crate) fn header(self) -> [u8; HEADER] {
        let (tag, len) = match self {
            Self::Data(len) => (DATA, len.0),
            Self::End => (END, 0),
            Self::Landed => (LANDED, 0),
        };
        let [i, d, c] = IDENTITY;
        let [v] = *VERSION.as_bytes();
        let [high, low] = len.to_be_bytes();
        [i, d, c, v, tag, high, low]
    }
}

/// Read one frame header travelling `toward`. An end of file anywhere in it is an error: no direction
/// may end without its End.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    toward: Toward,
) -> io::Result<Frame> {
    let mut header = [0; HEADER];
    reader.read_exact(&mut header).await?;
    Ok(Frame::parse(header, toward)?)
}

/// How an upload, the client's direction toward the peer, ended short of its End.
#[derive(Debug)]
pub(crate) enum UploadCut {
    /// The client's direction ended without End: an end of file, a half-close, or a failed read.
    Cut(io::Error),
    /// The client wrote a frame the splice phase does not admit.
    Malformed(io::Error),
    /// A write toward the peer failed.
    Peer(io::Error),
}

impl core::fmt::Display for UploadCut {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cut(error) => write!(f, "the client's upload ended without its end: {error}"),
            Self::Malformed(error) => write!(f, "the client wrote a malformed frame: {error}"),
            Self::Peer(error) => write!(f, "a write toward the peer failed: {error}"),
        }
    }
}

/// Copy the client's Data bodies toward `to_peer` until the client's End, which is where this returns
/// `Ok`; nothing past End is read. Each body moves through the reader's own buffer in place, so the
/// declared length never sizes a buffer; a [`frame_reader`] holds a whole frame.
pub(crate) async fn upload<R, W>(from_client: &mut R, to_peer: &mut W) -> Result<(), UploadCut>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let frame = match read_frame(from_client, Toward::Peer).await {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                return Err(UploadCut::Malformed(error));
            }
            Err(error) => return Err(UploadCut::Cut(error)),
        };
        let mut left = match frame {
            Frame::Data(len) => len.get(),
            Frame::End => return Ok(()),
            // `parse` admits Landed only toward the client.
            Frame::Landed => return Err(UploadCut::Malformed(MalformedFrame::Tag.into())),
        };
        while left > 0 {
            let held = from_client.fill_buf().await.map_err(UploadCut::Cut)?;
            if held.is_empty() {
                return Err(UploadCut::Cut(io::ErrorKind::UnexpectedEof.into()));
            }
            let take = held.len().min(left);
            to_peer
                .write_all(&held[..take])
                .await
                .map_err(UploadCut::Peer)?;
            from_client.consume(take);
            left -= take;
        }
    }
}

/// The resident's writing toward the client: one buffer holding a header and a Data body, so each
/// frame goes in one write and the peer's bytes are framed by the length the resident counted.
pub(crate) struct FramedWriter<W> {
    writer: W,
    buffer: Box<[u8; FRAME_BUFFER]>,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    /// Frame what goes to `writer`.
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            buffer: Box::new([0; FRAME_BUFFER]),
        }
    }

    /// The room a Data body is read into before [`write_data`](Self::write_data) frames it: exactly
    /// [`MAX_FRAME`] bytes, so every read into it but an empty one is a [`DataLen`].
    pub(crate) fn body(&mut self) -> &mut [u8] {
        &mut self.buffer[HEADER..]
    }

    /// Write the first `len` bytes of [`body`](Self::body) as one Data frame.
    pub(crate) async fn write_data(&mut self, len: DataLen) -> io::Result<()> {
        self.buffer[..HEADER].copy_from_slice(&Frame::Data(len).header());
        self.writer
            .write_all(&self.buffer[..HEADER + len.get()])
            .await
    }

    /// Write the End frame: the download ended cleanly.
    pub(crate) async fn write_end(&mut self) -> io::Result<()> {
        self.writer.write_all(&Frame::End.header()).await
    }

    /// Write the Landed frame: the peer holds the whole upload and its end.
    pub(crate) async fn write_landed(&mut self) -> io::Result<()> {
        self.writer.write_all(&Frame::Landed.header()).await
    }

    /// Shut the writing down: the close after the last frame.
    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}

#[cfg(test)]
#[path = "splice_tests.rs"]
mod tests;
