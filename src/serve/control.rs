//! The SWC1 control frame codec: the mutate-free local socket protocol.
//!
//! Hand-rolled like `tightbeam::protocol` (u16 big-endian lengths, no serde): one request, one
//! response, one-shot per connection. The request enum is the mutate-free guarantee BY TYPE: it can
//! express Services, Status, and Stop, and nothing else, so a toggle/revoke RPC is unrepresentable,
//! not merely unhandled.

use core::net::SocketAddr;
use std::path::PathBuf;

use bifrost::NodeId;
use tightbeam::tunnel::ServiceCatalog;
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// The control wire's identity: the bytes every control frame opens with, at every version, forever.
/// A frame that does not open with these is not a control frame, and that is the only thing an
/// identity mismatch is allowed to mean.
const IDENTITY: [u8; 3] = *b"SWC";

/// The frame grammar THIS build speaks, written after [`IDENTITY`] and parsed (never compared whole)
/// on read: together they are the four magic bytes `SWC1`.
const VERSION: WireVersion = WireVersion(*b"1");

/// The magic splits by RULE, not by a remembered offset: the identity is the leading run of capitals,
/// the version is the digits after it, four bytes in all. Held at build time so a magic that breaks the
/// rule fails to compile rather than splitting somewhere the next reader would not look. A digit is
/// never a capital, so "all capitals, then all digits" is exactly "the maximal leading capital run".
const _: () = assert!(
    all_between(&IDENTITY, b'A', b'Z')
        && all_between(VERSION.as_bytes(), b'0', b'9')
        && IDENTITY.len() + VERSION.as_bytes().len() == 4,
    "the magic must be four bytes: a run of capitals (the identity) then digits (the version)"
);

/// Whether `bytes` is non-empty and every byte falls in `lo..=hi`. `const` because its one caller is a
/// build-time claim about the magic.
const fn all_between(bytes: &[u8], lo: u8, hi: u8) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] < lo || bytes[at] > hi {
            return false;
        }
        at += 1;
    }
    !bytes.is_empty()
}

/// The version half of a control frame's magic: the byte after [`IDENTITY`], naming which frame
/// grammar the peer that wrote it speaks.
///
/// Parsed as a value rather than folded into one four-byte comparison, because the two halves of the
/// magic answer different questions. An IDENTITY mismatch says the connection is not a control
/// stream, and there is nothing true we could say to whatever is on the other end. A VERSION mismatch
/// says a swoosh control peer on another build, which is a fact both ends can act on, so the resident
/// answers it ([`ControlError::Version`] reaches the client as a `Response::Error`) instead of
/// dropping the connection on a peer that cannot see why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireVersion([u8; 1]);

impl WireVersion {
    /// Read the version half, after the identity. The width of the field lives here, in the type that
    /// owns it, so the reader and the writer cannot drift apart.
    async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ControlError> {
        let mut bytes = [0u8; 1];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(ControlError::Io)?;
        Ok(Self(bytes))
    }

    /// The bytes as they go on the wire.
    const fn as_bytes(&self) -> &[u8; 1] {
        &self.0
    }
}

impl core::fmt::Display for WireVersion {
    /// Renders the WHOLE four-byte tag (`SWC1`), because that is the form the source and the changelog
    /// use, so a peer handed one in an error can match it against what it reads. A peer's version byte
    /// is arbitrary and need not be printable, so it is escaped rather than trusted: this string
    /// reaches a terminal.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{}", IDENTITY.escape_ascii(), self.0.escape_ascii())
    }
}

/// Write the four magic bytes that open every control frame, as [`IDENTITY`] then [`VERSION`]. The
/// two writers and the two readers share one pair of helpers so a request and a response can never
/// disagree about what opens a frame.
async fn write_magic<W: io::AsyncWrite + Unpin>(writer: &mut W) -> io::Result<()> {
    writer.write_all(&IDENTITY).await?;
    writer.write_all(VERSION.as_bytes()).await
}

/// Read the four magic bytes and check them, parsed as [`IDENTITY`] plus a [`WireVersion`] and never
/// compared as four bytes, so that "not a control stream" and "a control stream from another build"
/// stay two facts instead of one. Only the second is something the peer can act on.
async fn read_magic<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<(), ControlError> {
    let mut identity = [0u8; IDENTITY.len()];
    reader
        .read_exact(&mut identity)
        .await
        .map_err(ControlError::Io)?;
    if identity != IDENTITY {
        return Err(ControlError::Foreign);
    }
    let version = WireVersion::read(reader).await?;
    if version != VERSION {
        return Err(ControlError::Version { peer: version });
    }
    Ok(())
}

/// The largest frame payload the socket admits: 8 KiB. A longer DECLARED length is refused and the
/// connection closed, before a byte of it is read.
pub const MAX_FRAME: usize = 8 * 1024;

/// The longest string one status reply carries: a disabled name, an explicit-unknown reason, or the
/// bound address text. Both the encoder and the decoder enforce it, so an encode can never produce a
/// status frame its own decode refuses.
pub const MAX_STATUS_STRING: usize = 256;

/// The most disabled names one service menu carries. The encoder refuses a longer list and the
/// decoder refuses a longer declared count, so the two ends cannot disagree about the cap.
pub const MAX_DISABLED_NAMES: usize = 1024;

/// The most warm-peer entries a status reply carries. 64 entries at 40 bytes each keep the whole
/// reply under [`MAX_FRAME`]; the encoder and the decoder both enforce it, so a warm list can never
/// produce a frame the client refuses.
pub const MAX_WARM_ENTRIES: usize = 64;

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
        write_magic(writer).await?;
        writer.write_all(&[self.tag()]).await?;
        writer.write_all(&0u16.to_be_bytes()).await
    }

    /// Read one request frame, enforcing the magic and the frame cap.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ControlError> {
        read_magic(reader).await?;
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

/// The live disabled list in a status reply: the names, or an explicit unknown when the file could
/// not be read. An enum, not an empty vector, so a read failure never renders as "nothing disabled"
/// while the gate still refuses the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisabledList {
    /// The names currently disabled. An empty list means the file is absent or empty: nothing is
    /// disabled, and the gate agrees.
    Known(Vec<String>),
    /// The file exists but could not be read or exceeded the bounded read: the gate still refuses
    /// whatever it honors, so the oracle reports an explicit unknown instead of a false empty.
    Unknown(String),
}

/// The live service menu: the served catalog snapshot plus the live disabled list. The one payload
/// both a [`Response::Catalog`] read and a [`StatusReply`] carry, so the two replies share one codec
/// path and a change to the disabled section lands once.
///
/// The wire form (all ints big-endian), self-delimiting so a reader needs no out-of-band length:
///
/// ```text
///   catalog_len  u32
///   catalog      [u8; catalog_len]   ServiceCatalog::encode (its own layout)
///   disabled     u8 tag: 0 known, 1 unknown
///     known:     count u32, then per name: len u16, name [u8; len] UTF-8
///                names sorted, at most MAX_DISABLED_NAMES (1024), each at most
///                MAX_STATUS_STRING (256) bytes
///     unknown:   len u16, reason [u8; len] UTF-8, at most MAX_STATUS_STRING bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMenu {
    /// The served catalog snapshot.
    pub catalog: ServiceCatalog,
    /// The live disabled list, re-read per query.
    pub disabled: DisabledList,
}

impl ServiceMenu {
    /// Encode the menu to its self-delimiting wire form.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Write the menu into `out` at its current end: the nested writer [`StatusReply::encode`] uses
    /// so the menu sits inline with the fields that follow it.
    fn encode_into(&self, out: &mut Vec<u8>) -> io::Result<()> {
        // The catalog carries its OWN wire bound (the one the remote `control.services` read holds); this
        // local socket's frame cap is a second, tighter one. Both apply, and each reports itself: a catalog
        // past its own bound says which service is at fault, which "over the frame cap" cannot.
        let catalog = self.catalog.encode().map_err(io::Error::other)?;
        if catalog.len() > MAX_FRAME {
            return Err(io::Error::other("catalog over the frame cap"));
        }
        out.extend_from_slice(&(catalog.len() as u32).to_be_bytes());
        out.extend_from_slice(&catalog);
        encode_disabled(out, &self.disabled)
    }

    /// Decode a whole payload as one menu, enforcing the whole-payload-consumed rule.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        let mut cursor = 0;
        let menu = Self::decode_at(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(ControlError::Protocol("menu has trailing bytes".to_owned()));
        }
        Ok(menu)
    }

    /// Decode a menu at `cursor`, advancing it: the nested decoder [`StatusReply::decode`] uses so
    /// the menu is inline with the fields that follow it.
    fn decode_at(bytes: &[u8], cursor: &mut usize) -> Result<Self, ControlError> {
        let catalog_len = u32::from_be_bytes(take_array(bytes, cursor)?) as usize;
        if catalog_len > MAX_FRAME {
            return Err(ControlError::TooLarge(catalog_len));
        }
        let catalog = ServiceCatalog::decode(take(bytes, cursor, catalog_len)?)
            .map_err(ControlError::Catalog)?;
        let disabled = decode_disabled(bytes, cursor)?;
        Ok(Self { catalog, disabled })
    }
}

/// One warm peer in a status reply: its node id and how many seconds since the cached connection
/// was last used. The cache itself is a later pass; the field rides the wire now (empty until then)
/// so the reply shape does not churn when it lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// The warm peer's node id.
    pub peer: NodeId,
    /// Seconds since the cached connection to this peer was last used.
    pub idle_secs: u64,
}

/// The node's status over the local socket: the public SHAPE only (id, pid, address, uptime, the
/// live menu, the warm peers). Never key material, never badge bytes.
///
/// The wire form (all ints big-endian), self-delimiting so a reader needs no out-of-band length:
///
/// ```text
///   node_id       32 bytes        ed25519 public key (CryptoKind implicit Ed25519 in SWC1)
///   pid           u32
///   addr_present  u8              (0 or 1)
///   addr_len      u16             present iff addr_present == 1
///   addr          [u8; addr_len]  UTF-8 SocketAddr, at most MAX_STATUS_STRING (256) bytes
///   uptime_secs   u64
///   menu          ServiceMenu layout (catalog + disabled, above)
///   warm_count    u32             at most MAX_WARM_ENTRIES
///   per warm entry, ascending by peer key:
///     peer        32 bytes
///     idle_secs   u64
/// ```
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
    /// The live menu: the served catalog snapshot plus the live disabled list.
    pub menu: ServiceMenu,
    /// The cached warm peers, ascending by key. Empty until the warm cache lands.
    pub warm: Vec<PeerEntry>,
}

impl StatusReply {
    /// Encode the reply to its length-prefixed wire form. Fallible when a disabled-unknown reason or
    /// a warm list cannot fit the reply caps, never silently truncated.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.warm.len() > MAX_WARM_ENTRIES {
            return Err(io::Error::other("status carries too many warm peers"));
        }
        let mut out = Vec::new();
        out.extend_from_slice(self.node_id.key());
        out.extend_from_slice(&self.pid.to_be_bytes());
        match self.addr {
            Some(addr) => {
                out.push(1);
                let text = addr.to_string();
                let bytes = text.as_bytes();
                if bytes.len() > MAX_STATUS_STRING {
                    return Err(io::Error::other("status addr too long"));
                }
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.uptime_secs.to_be_bytes());
        self.menu.encode_into(&mut out)?;
        out.extend_from_slice(&(self.warm.len() as u32).to_be_bytes());
        for entry in &self.warm {
            out.extend_from_slice(entry.peer.key());
            out.extend_from_slice(&entry.idle_secs.to_be_bytes());
        }
        Ok(out)
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
                if len > MAX_STATUS_STRING {
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
        let menu = ServiceMenu::decode_at(bytes, &mut cursor)?;
        let warm_count = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        if warm_count > MAX_WARM_ENTRIES {
            return Err(ControlError::Protocol(
                "status carries too many warm peers".to_owned(),
            ));
        }
        let mut warm = Vec::with_capacity(warm_count);
        for _ in 0..warm_count {
            let key: [u8; 32] = take_array(bytes, &mut cursor)?;
            let peer = NodeId::new(bifrost::CryptoKind::Ed25519, key);
            let idle_secs = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
            warm.push(PeerEntry { peer, idle_secs });
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
            menu,
            warm,
        })
    }
}

/// The host's reply, sent before the connection closes: one-shot framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The live service menu (answers [`Request::Services`]).
    Catalog(ServiceMenu),
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
            Self::Catalog(menu) => menu.encode()?,
            Self::Status(status) => status.encode()?,
            Self::Ack => Vec::new(),
            Self::Refused(reason) | Self::Error(reason) => {
                let mut out = Vec::new();
                write_str_into(&mut out, reason)?;
                out
            }
        };
        // The whole payload must fit the frame cap both ends enforce; a server that would emit more
        // is refused here rather than writing a frame its own decoder rejects.
        if payload.len() > MAX_FRAME {
            return Err(io::Error::other("response over the frame cap"));
        }
        let len =
            u16::try_from(payload.len()).map_err(|_| io::Error::other("response too long"))?;
        write_magic(writer).await?;
        writer.write_all(&[self.tag()]).await?;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&payload).await
    }

    /// Read one response frame, enforcing the magic and the frame cap.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ControlError> {
        read_magic(reader).await?;
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
            1 => Ok(Self::Catalog(ServiceMenu::decode(&payload)?)),
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

/// Why a control frame could not be read or written, or a control operation could not be attempted.
/// One typed error the codec, the socket client, and the resident all map into, so a caller can
/// match `NoResident`/`Untrusted`/`Refused` instead of stringifying a cause it cannot inspect.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// No resident node is addressable under this home: either no socket exists, or the runtime root
    /// cannot be resolved. The bare control verbs teach from this rather than dialing cold.
    #[error("no resident node under this home; start one with `swoosh serve --resident`")]
    NoResident,
    /// A path exists but is not this user's 0700 runtime dir/socket: never trusted enough to connect.
    #[error("refusing to trust the control path {path}: not this user's 0700 runtime dir/socket")]
    Untrusted {
        /// The path that failed the ownership, mode, or socket check.
        path: PathBuf,
    },
    /// The resident did not answer an exchange phase within its bound.
    #[error("the resident did not answer the control {phase} within the bound")]
    Timeout {
        /// Which phase hit its deadline: `"connect"`, `"request write"`, or `"response read"`.
        phase: &'static str,
    },
    /// The peer closed or the read failed.
    #[error("control stream ended")]
    Io(#[source] std::io::Error),
    /// A declared length over the 8 KiB cap.
    #[error("control frame too large ({0} bytes over the cap)")]
    TooLarge(usize),
    /// The connection did not open with [`IDENTITY`], so it is not a control stream. The wording is
    /// now exactly true: it used to cover a control peer on another version as well, which it never
    /// was.
    #[error("not a control stream")]
    Foreign,
    /// A control frame from a build that speaks a different frame grammar.
    ///
    /// This message goes ON THE WIRE (the resident answers an unreadable request with a
    /// `Response::Error` carrying it), so it is FIXED text plus the two version tags and nothing
    /// else. Never interpolate host state here. The socket is uid-gated, so the peer is already this
    /// user and there is nobody to fingerprint, but the rule holds anyway: an answer written for a
    /// peer on another build is not the place to spend facts.
    #[error(
        "control wire version mismatch: the frame is {peer}, this build speaks {VERSION}; run one \
         swoosh build at both ends"
    )]
    Version {
        /// The version the peer's frame named.
        peer: WireVersion,
    },
    /// A bad tag, a bad string, trailing bytes: loud, never silent.
    #[error("control protocol error: {0}")]
    Protocol(String),
    /// The embedded catalog blob did not decode.
    #[error("control catalog error")]
    Catalog(#[source] eyre::Report),
    /// The resident refused the request, in the wire refusal vocabulary.
    #[error("the resident refused: {0}")]
    Refused(String),
}

/// Write the disabled section into a payload buffer: a presence tag, then either the known names or
/// the explicit unknown reason. The one encoder both [`ServiceMenu`] and [`StatusReply`] use.
fn encode_disabled(out: &mut Vec<u8>, disabled: &DisabledList) -> io::Result<()> {
    match disabled {
        DisabledList::Known(names) => {
            if names.len() > MAX_DISABLED_NAMES {
                return Err(io::Error::other("too many disabled names"));
            }
            out.push(0);
            out.extend_from_slice(&(names.len() as u32).to_be_bytes());
            for name in names {
                if name.len() > MAX_STATUS_STRING {
                    return Err(io::Error::other("disabled name too long"));
                }
                let bytes = name.as_bytes();
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }
        DisabledList::Unknown(reason) => {
            if reason.len() > MAX_STATUS_STRING {
                return Err(io::Error::other("disabled unknown reason too long"));
            }
            out.push(1);
            write_str_into(out, reason)?;
        }
    }
    Ok(())
}

/// Read the disabled section written by [`encode_disabled`], advancing `cursor`. Bounds-checked
/// against untrusted input: too many names, an over-long name or reason, or an unknown tag refuses.
fn decode_disabled(bytes: &[u8], cursor: &mut usize) -> Result<DisabledList, ControlError> {
    match take_byte(bytes, cursor)? {
        0 => {
            let count = u32::from_be_bytes(take_array(bytes, cursor)?) as usize;
            if count > MAX_DISABLED_NAMES {
                return Err(ControlError::Protocol(
                    "status names too many disabled".to_owned(),
                ));
            }
            let mut names = Vec::with_capacity(count);
            for _ in 0..count {
                let len = usize::from(u16::from_be_bytes(take_array(bytes, cursor)?));
                if len > MAX_STATUS_STRING {
                    return Err(ControlError::Protocol("disabled name too long".to_owned()));
                }
                let name = core::str::from_utf8(take(bytes, cursor, len)?)
                    .map_err(|_| ControlError::Protocol("disabled name is not UTF-8".to_owned()))?
                    .to_owned();
                names.push(name);
            }
            Ok(DisabledList::Known(names))
        }
        1 => {
            let len = usize::from(u16::from_be_bytes(take_array(bytes, cursor)?));
            if len > MAX_STATUS_STRING {
                return Err(ControlError::Protocol(
                    "disabled unknown reason too long".to_owned(),
                ));
            }
            let reason = core::str::from_utf8(take(bytes, cursor, len)?)
                .map_err(|_| {
                    ControlError::Protocol("disabled unknown reason is not UTF-8".to_owned())
                })?
                .to_owned();
            Ok(DisabledList::Unknown(reason))
        }
        other => Err(ControlError::Protocol(format!(
            "unknown disabled presence {other:#04x}"
        ))),
    }
}

/// Write a u16-prefixed string into a payload buffer.
fn write_str_into(out: &mut Vec<u8>, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    let len =
        u16::try_from(bytes.len()).map_err(|_| io::Error::other("response string too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
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
