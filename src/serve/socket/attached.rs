//! The client's two halves of an attached Open, which keep a transport stream's contract over the
//! control socket's frames.
//!
//! The write half frames what it is given as Data; its `shutdown` writes End, and dropping it any other
//! way closes the direction without End, which the resident reads as a cut-off and passes on as a reset.
//! The read half returns the peer's bytes, `Ok(0)` only after the resident's End, and an error on any
//! other end: `ConnectionReset` for an end of file before End, `InvalidData` for a malformed frame. It
//! also notes Landed, the resident's word that the peer holds the whole upload and its end.

use core::pin::Pin;
use core::task::{Context, Poll, ready};

use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use super::MAX_FRAME;
use super::splice::{DataLen, FRAME_BUFFER, Frame, HEADER, Toward};

/// What the peer's direction has said so far, past the frame being read.
#[derive(Debug, Default)]
struct Heard {
    /// The resident's End came: the download is whole.
    ended: bool,
    /// The resident's Landed came: the peer holds the upload.
    landed: bool,
}

/// The read half of an attached Open: the peer's bytes, in order, then a clean end only at End.
#[derive(Debug)]
pub struct OpenRead {
    reader: BufReader<OwnedReadHalf>,
    /// A header being gathered, and how much of it has arrived.
    header: [u8; HEADER],
    gathered: usize,
    /// What is left of the Data body being read.
    body: usize,
    heard: Heard,
}

/// A frame from the resident after its End that is not Landed, or a second End or Landed.
fn out_of_place() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "a frame out of place after attached",
    )
}

/// The resident's direction ended without End.
fn cut_off() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "the stream was cut off")
}

impl OpenRead {
    pub(crate) fn new(read: OwnedReadHalf) -> Self {
        Self {
            reader: BufReader::with_capacity(FRAME_BUFFER, read),
            header: [0; HEADER],
            gathered: 0,
            body: 0,
            heard: Heard::default(),
        }
    }

    /// Read the next frame header, `Ok(None)` at a clean end of file before any of its bytes.
    fn poll_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Frame>>> {
        while self.gathered < HEADER {
            let held = ready!(Pin::new(&mut self.reader).poll_fill_buf(cx))?;
            if held.is_empty() {
                return Poll::Ready(if self.gathered == 0 {
                    Ok(None)
                } else {
                    Err(cut_off())
                });
            }
            let take = held.len().min(HEADER - self.gathered);
            self.header[self.gathered..self.gathered + take].copy_from_slice(&held[..take]);
            Pin::new(&mut self.reader).consume(take);
            self.gathered += take;
        }
        self.gathered = 0;
        Poll::Ready(Ok(Some(Frame::parse(self.header, Toward::Client)?)))
    }

    /// Note an End or Landed, refusing a second of either.
    fn hear(&mut self, frame: Frame) -> io::Result<()> {
        let seen = match frame {
            Frame::End => &mut self.heard.ended,
            Frame::Landed => &mut self.heard.landed,
            Frame::Data(_) => return Err(out_of_place()),
        };
        if *seen {
            return Err(out_of_place());
        }
        *seen = true;
        Ok(())
    }

    /// Wait for Landed, the resident's word that the peer holds every byte of the upload and its end.
    /// Call it after the write half's `shutdown`, once the download has ended; Landed may have come
    /// already. An end of file before it is `ConnectionReset`: the upload was not confirmed.
    ///
    /// # Errors
    ///
    /// The connection ended without Landed, or the resident wrote a frame out of place.
    pub async fn landed(&mut self) -> io::Result<()> {
        core::future::poll_fn(|cx| self.poll_landed(cx)).await
    }

    fn poll_landed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.heard.landed {
            if !self.heard.ended {
                return Poll::Ready(Err(out_of_place()));
            }
            match ready!(self.poll_header(cx))? {
                None => return Poll::Ready(Err(cut_off())),
                Some(frame) => self.hear(frame)?,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for OpenRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.body > 0 {
                let held = ready!(Pin::new(&mut this.reader).poll_fill_buf(cx))?;
                if held.is_empty() {
                    return Poll::Ready(Err(cut_off()));
                }
                let take = held.len().min(this.body).min(buf.remaining());
                buf.put_slice(&held[..take]);
                Pin::new(&mut this.reader).consume(take);
                this.body -= take;
                return Poll::Ready(Ok(()));
            }
            if this.heard.ended {
                return Poll::Ready(Ok(()));
            }
            match ready!(this.poll_header(cx))? {
                None => return Poll::Ready(Err(cut_off())),
                Some(Frame::Data(len)) => this.body = len.get(),
                Some(frame) => this.hear(frame)?,
            }
        }
    }
}

/// The write half of an attached Open: what it is given goes out as Data frames, and only `shutdown`
/// writes End. Dropped any other way, it closes the direction with no End, which reaches the peer as a
/// reset.
#[derive(Debug)]
pub struct OpenWrite {
    writer: OwnedWriteHalf,
    /// The frame being written, header and body, and how much of it has gone.
    frame: Vec<u8>,
    sent: usize,
    ended: bool,
}

impl OpenWrite {
    pub(crate) fn new(write: OwnedWriteHalf) -> Self {
        Self {
            writer: write,
            frame: Vec::with_capacity(FRAME_BUFFER),
            sent: 0,
            ended: false,
        }
    }

    /// Close the direction with no End, so the peer reads a reset: the upload was cut off.
    pub fn abort(self) {
        drop(self);
    }

    /// Write out the frame being written, all of it.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.frame.len() {
            let wrote =
                ready!(Pin::new(&mut self.writer).poll_write(cx, &self.frame[self.sent..]))?;
            if wrote == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += wrote;
        }
        self.frame.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for OpenWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let take = buf.len().min(MAX_FRAME);
        let Some(len) = DataLen::new(take) else {
            return Poll::Ready(Ok(0));
        };
        this.frame.extend_from_slice(&Frame::Data(len).header());
        this.frame.extend_from_slice(&buf[..take]);
        // The bytes are taken now; the frame goes out here if it can, or on the next call.
        let _ = this.poll_drain(cx)?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.writer).poll_flush(cx)
    }

    /// Write End, then close the socket's writing: the upload ended cleanly.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if !this.ended {
            this.ended = true;
            this.frame.extend_from_slice(&Frame::End.header());
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "attached_tests.rs"]
mod tests;
