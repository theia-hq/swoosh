//! The speed payload: a counted byte stream, iperf-shaped. The bytes carry no meaning (throughput is
//! the only signal), so both ends move a fixed zero buffer rather than generating or verifying content
//! per byte. Sending and draining a fixed number of bytes are the two halves of every speed test, so
//! they live together here as [`Payload`].

use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// The transfer chunk. 64 KiB matches bifrost-mem's stream buffer and the wire's streaming chunk, so a
/// chunk crosses an in-memory stream without a partial second copy.
const CHUNK: usize = 64 * 1024;

/// A counted transfer of `limit` bytes in one direction.
#[derive(Debug, Clone, Copy)]
pub struct Payload {
    limit: u64,
}

impl Payload {
    /// A transfer of exactly `limit` bytes.
    pub fn of(limit: u64) -> Self {
        Self { limit }
    }

    /// Write `limit` bytes of zero payload, returning how many were written.
    pub async fn send<W: io::AsyncWrite + Unpin>(self, writer: &mut W) -> io::Result<u64> {
        let Self { limit } = self;
        let zeros = [0u8; CHUNK];
        let mut sent = 0u64;
        while sent < limit {
            let n = (limit - sent).min(CHUNK as u64);
            writer.write_all(&zeros[..n as usize]).await?;
            sent += n;
        }
        writer.flush().await?;
        Ok(sent)
    }

    /// Drain exactly `limit` bytes from the reader, returning how many arrived before EOF.
    pub async fn drain<R: io::AsyncRead + Unpin>(self, reader: &mut R) -> io::Result<u64> {
        let Self { limit } = self;
        let mut sink = [0u8; CHUNK];
        let mut received = 0u64;
        while received < limit {
            let want = (limit - received).min(CHUNK as u64) as usize;
            let n = reader.read(&mut sink[..want]).await?;
            if n == 0 {
                break;
            }
            received += n as u64;
        }
        Ok(received)
    }
}
