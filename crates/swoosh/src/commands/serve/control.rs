//! The SWC1 control frame codec: the mutate-free local socket protocol.
//!
//! Hand-rolled like `tightbeam::protocol` (u16 big-endian lengths, no serde): one request, one
//! response, one-shot per connection. The request enum is the mutate-free guarantee BY TYPE: it can
//! express Services, Status, and Stop, and nothing else, so a toggle/revoke RPC is unrepresentable,
//! not merely unhandled.

use core::net::SocketAddr;

use bifrost::NodeId;
use tightbeam::tunnel::ServiceCatalog;
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// The magic prefixing every control frame. A foreign magic is a loud `Error`, never a misparse.
pub const MAGIC: [u8; 4] = *b"SWC1";

/// The largest frame payload the socket admits: 8 KiB. A longer DECLARED length is refused and the
/// connection closed, before a byte of it is read.
pub const MAX_FRAME: usize = 8 * 1024;

/// The only requests a local control client can make: two reads and a stop. There is deliberately
/// NO toggle/revoke variant: enabling or disabling a service is a file-write on `<home>/disabled`,
/// never a socket RPC, so the compiler enforces the mutate-free rule at every match site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Read the served catalog (the `control.services` snapshot).
    Services,
    /// Read the node status (the public-shape reply).
    Status,
    /// Request a graceful stop (the socket twin of a SIGTERM the local user already holds).
    Stop,
}

impl Request {
    /// The one-byte tag identifying this request on the wire.
    fn tag(&self) -> u8 {
        match self {
            Self::Services => 1,
            Self::Status => 2,
            Self::Stop => 3,
        }
    }

    /// Parse a request back from its tag. An unknown tag is a protocol error, never a default.
    fn from_tag(tag: u8) -> Result<Self, ControlError> {
        match tag {
            1 => Ok(Self::Services),
            2 => Ok(Self::Status),
            3 => Ok(Self::Stop),
            other => Err(ControlError::Protocol(format!(
                "unknown request tag {other:#04x}"
            ))),
        }
    }

    /// Write one request frame: magic, tag, then the (empty) length-prefixed payload.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&MAGIC).await?;
        writer.write_all(&[self.tag()]).await?;
        writer.write_all(&0u16.to_be_bytes()).await
    }

    /// Read one request frame, enforcing the magic and the frame cap.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ControlError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .await
            .map_err(ControlError::Io)?;
        if magic != MAGIC {
            return Err(ControlError::Protocol(format!(
                "not a control stream (want SWC1, got {})",
                String::from_utf8_lossy(&magic)
            )));
        }
        let mut tag = [0u8; 1];
        reader
            .read_exact(&mut tag)
            .await
            .map_err(ControlError::Io)?;
        let request = Self::from_tag(tag[0])?;
        let mut len = [0u8; 2];
        reader
            .read_exact(&mut len)
            .await
            .map_err(ControlError::Io)?;
        let len = usize::from(u16::from_be_bytes(len));
        if len > MAX_FRAME {
            return Err(ControlError::TooLarge(len));
        }
        // Requests carry no payload today; drain exactly what was declared so a padded frame
        // cannot smuggle bytes past the read.
        let mut rest = vec![0u8; len];
        reader
            .read_exact(&mut rest)
            .await
            .map_err(ControlError::Io)?;
        if !rest.is_empty() {
            return Err(ControlError::Protocol(
                "unexpected request payload".to_owned(),
            ));
        }
        Ok(request)
    }
}

/// The node's status over the local socket: the public SHAPE only (id, pid, address, uptime, the
/// served catalog, the live disabled list). Never key material, never badge bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReply {
    /// This node's id.
    pub node_id: NodeId,
    /// The resident's pid.
    pub pid: u32,
    /// The bound address, when the transport hands one out.
    pub addr: Option<SocketAddr>,
    /// Seconds since the resident started.
    pub uptime_secs: u64,
    /// The served catalog snapshot.
    pub catalog: ServiceCatalog,
    /// The live disabled list, re-read per query.
    pub disabled: Vec<String>,
}

impl StatusReply {
    /// Encode the reply to its length-prefixed wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.node_id.key());
        out.extend_from_slice(&self.pid.to_be_bytes());
        match self.addr {
            Some(addr) => {
                out.push(1);
                let text = addr.to_string();
                let bytes = text.as_bytes();
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.uptime_secs.to_be_bytes());
        let catalog = self.catalog.encode();
        out.extend_from_slice(&(catalog.len() as u32).to_be_bytes());
        out.extend_from_slice(&catalog);
        out.extend_from_slice(&(self.disabled.len() as u32).to_be_bytes());
        for name in &self.disabled {
            let bytes = name.as_bytes();
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Decode a reply written by [`encode`](Self::encode). Bounds-checked against untrusted input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        let mut cursor = 0;
        let key: [u8; 32] = take_array(bytes, &mut cursor)?;
        let node_id = NodeId::new(bifrost::CryptoKind::Ed25519, key);
        let pid = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let has_addr = take_byte(bytes, &mut cursor)?;
        let addr = match has_addr {
            0 => None,
            1 => {
                let len = usize::from(u16::from_be_bytes(take_array(bytes, &mut cursor)?));
                if len > 256 {
                    return Err(ControlError::Protocol("status addr too long".to_owned()));
                }
                let text = core::str::from_utf8(take(bytes, &mut cursor, len)?)
                    .map_err(|_| ControlError::Protocol("status addr is not UTF-8".to_owned()))?;
                Some(
                    text.parse().map_err(|_| {
                        ControlError::Protocol("status addr does not parse".to_owned())
                    })?,
                )
            }
            other => {
                return Err(ControlError::Protocol(format!(
                    "unknown addr presence {other:#04x}"
                )));
            }
        };
        let uptime_secs = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let catalog_len = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        if catalog_len > MAX_FRAME {
            return Err(ControlError::TooLarge(catalog_len));
        }
        let catalog = ServiceCatalog::decode(take(bytes, &mut cursor, catalog_len)?)
            .map_err(ControlError::Catalog)?;
        let disabled_count = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        if disabled_count > 1024 {
            return Err(ControlError::Protocol(
                "status names too many disabled".to_owned(),
            ));
        }
        let mut disabled = Vec::with_capacity(disabled_count);
        for _ in 0..disabled_count {
            let len = usize::from(u16::from_be_bytes(take_array(bytes, &mut cursor)?));
            if len > 256 {
                return Err(ControlError::Protocol("disabled name too long".to_owned()));
            }
            let name = core::str::from_utf8(take(bytes, &mut cursor, len)?)
                .map_err(|_| ControlError::Protocol("disabled name is not UTF-8".to_owned()))?
                .to_owned();
            disabled.push(name);
        }
        if cursor != bytes.len() {
            return Err(ControlError::Protocol(
                "status has trailing bytes".to_owned(),
            ));
        }
        Ok(Self {
            node_id,
            pid,
            addr,
            uptime_secs,
            catalog,
            disabled,
        })
    }
}

/// The host's reply, sent before the connection closes: one-shot framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The served catalog (answers [`Request::Services`]).
    Catalog(ServiceCatalog),
    /// The node status (answers [`Request::Status`]).
    Status(StatusReply),
    /// The stop confirm (answers [`Request::Stop`], the socket twin of `STOP_ACK`).
    Ack,
    /// A gate/dial refusal, in the same reason vocabulary as the wire path.
    Refused(String),
    /// Version skew or a protocol error: loud, never a misparse.
    Error(String),
}

impl Response {
    /// The one-byte tag identifying this response on the wire.
    fn tag(&self) -> u8 {
        match self {
            Self::Catalog(_) => 1,
            Self::Status(_) => 2,
            Self::Ack => 3,
            Self::Refused(_) => 4,
            Self::Error(_) => 5,
        }
    }

    /// Write one response frame: magic, tag, length-prefixed payload.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let payload = match self {
            Self::Catalog(catalog) => catalog.encode(),
            Self::Status(status) => status.encode(),
            Self::Ack => Vec::new(),
            Self::Refused(reason) | Self::Error(reason) => {
                let mut out = Vec::new();
                write_str_into(&mut out, reason);
                out
            }
        };
        let len =
            u16::try_from(payload.len()).map_err(|_| io::Error::other("response too long"))?;
        writer.write_all(&MAGIC).await?;
        writer.write_all(&[self.tag()]).await?;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&payload).await
    }

    /// Read one response frame, enforcing the magic and the frame cap.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ControlError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .await
            .map_err(ControlError::Io)?;
        if magic != MAGIC {
            return Err(ControlError::Protocol(format!(
                "not a control stream (want SWC1, got {})",
                String::from_utf8_lossy(&magic)
            )));
        }
        let mut tag = [0u8; 1];
        reader
            .read_exact(&mut tag)
            .await
            .map_err(ControlError::Io)?;
        let mut len = [0u8; 2];
        reader
            .read_exact(&mut len)
            .await
            .map_err(ControlError::Io)?;
        let len = usize::from(u16::from_be_bytes(len));
        if len > MAX_FRAME {
            return Err(ControlError::TooLarge(len));
        }
        let mut payload = vec![0u8; len];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(ControlError::Io)?;
        match tag[0] {
            1 => Ok(Self::Catalog(
                ServiceCatalog::decode(&payload).map_err(ControlError::Catalog)?,
            )),
            2 => Ok(Self::Status(StatusReply::decode(&payload)?)),
            3 => {
                if payload.is_empty() {
                    Ok(Self::Ack)
                } else {
                    Err(ControlError::Protocol("unexpected ack payload".to_owned()))
                }
            }
            4 => Ok(Self::Refused(read_str_from(&payload).ok_or_else(|| {
                ControlError::Protocol("refusal is not a string".to_owned())
            })?)),
            5 => Ok(Self::Error(read_str_from(&payload).ok_or_else(|| {
                ControlError::Protocol("error is not a string".to_owned())
            })?)),
            other => Err(ControlError::Protocol(format!(
                "unknown response tag {other:#04x}"
            ))),
        }
    }
}

/// Why a control frame could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The peer closed or the read failed.
    #[error("control stream ended")]
    Io(#[source] std::io::Error),
    /// A declared length over the 8 KiB cap.
    #[error("control frame too large ({0} bytes over the cap)")]
    TooLarge(usize),
    /// Version skew, a bad tag, a bad string, trailing bytes: loud, never silent.
    #[error("control protocol error: {0}")]
    Protocol(String),
    /// The embedded catalog blob did not decode.
    #[error("control catalog error")]
    Catalog(#[source] eyre::Report),
}

/// Write a u16-prefixed string into a payload buffer.
fn write_str_into(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Read a u16-prefixed string from a whole payload (which must be exactly one string).
fn read_str_from(payload: &[u8]) -> Option<String> {
    let (len, rest) = payload.split_at_checked(2)?;
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    if rest.len() != len {
        return None;
    }
    core::str::from_utf8(rest).ok().map(str::to_owned)
}

/// Read `len` bytes at `cursor`, advancing it, or fail if the blob is too short.
fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], ControlError> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| ControlError::Protocol("length overflow".to_owned()))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| ControlError::Protocol("status is truncated".to_owned()))?;
    *cursor = end;
    Ok(slice)
}

/// Read a fixed-size array at `cursor`, advancing it.
fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], ControlError> {
    let slice = take(bytes, cursor, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}

/// Read one byte at `cursor`, advancing it.
fn take_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, ControlError> {
    Ok(take_array::<1>(bytes, cursor)?[0])
}
