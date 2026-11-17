//! The Open request body and its two replies, Attached and OpenRefusal.
//!
//! Open asks the resident for one admitted stream to a peer. Its body is the only request body that
//! may exceed the frame ceiling, because a slip is a whole link. Every bound below is a structural
//! byte count checked before a byte is turned into a typed value, so a hostile body costs a bounded
//! scan and owns nothing until the whole grammar holds.

use core::fmt::{self, Write as _};
use core::net::SocketAddr;
use core::time::Duration;

use bifrost::{ConnInfo, NodeId, Path, Refusal, RefusalDetail, Relay};
use nauthy::{Link, Service};
use tokio::io;

use super::{ControlError, MAX_FRAME, local_detail};

/// The largest body request 4 (Open) may declare. Every other request and every reply keeps
/// [`MAX_FRAME`]. Declaring more than the grammar can use buys nothing: the decoder requires exact
/// consumption, so the extra room is never padding.
pub const MAX_OPEN_REQUEST: usize = 16 * 1024;

/// At most this many dial hints ride one Open.
const MAX_HINTS: usize = 16;
/// A hint's text length. The longest `SocketAddr` text (a scoped IPv6 address with a port) is 58 bytes.
const MAX_HINT_LEN: usize = 64;
/// A service name's length, the same bound the service grammar holds.
const MAX_SERVICE_LEN: usize = 128;
/// A slip's text length: a whole link, whose token can run past 13,000 characters.
const MAX_SLIP_LEN: usize = 14_336;

/// The observation byte this build writes and the only one it reads. Observing an Open's path needs a
/// reference the resident does not yet hand out, so a request asking for one is malformed rather than
/// silently attached unobserved.
const UNOBSERVED: u8 = 0;

/// The smallest Open body: a peer, no hints, a one-byte service, a lane, no slip, the observation byte.
const MIN_OPEN_BODY: usize = 32 + 1 + (1 + 1) + 1 + 1 + 1;
/// The largest Open body the grammar can spell, every field at its bound.
const MAX_OPEN_BODY: usize = 32
    + 1
    + MAX_HINTS * (1 + MAX_HINT_LEN)
    + (1 + MAX_SERVICE_LEN)
    + 1
    + 1
    + (2 + MAX_SLIP_LEN)
    + 1;

// The declared cap must hold the whole grammar, and the arithmetic is pinned to the published sizes so
// a moved bound is a compile error here rather than a silently wider body.
const _: () = assert!(MIN_OPEN_BODY == 38 && MAX_OPEN_BODY == 15_543);
const _: () = assert!(MAX_OPEN_BODY <= MAX_OPEN_REQUEST && MAX_FRAME < MAX_OPEN_REQUEST);

/// A relay URL's length inside a path report.
const MAX_RELAY_URL: usize = 1024;
/// A remote address's text length inside a path report.
const MAX_REMOTE: usize = 256;
/// The largest path report: class, the longest relay URL, a round trip, the longest remote address.
const MAX_CONN_INFO: usize = 1 + (2 + MAX_RELAY_URL) + (1 + 8) + (1 + 2 + MAX_REMOTE);
/// The largest Attached body a peer may declare: reference presence, a path reference, a path report.
/// This build reads only reference-free bodies, but the declaration ceiling is the grammar's.
pub(super) const MAX_ATTACHED: usize = 1 + 24 + MAX_CONN_INFO;
/// The largest OpenRefusal body: an outer class, a nested peer class, and the longest detail.
pub(super) const MAX_OPEN_REFUSAL: usize = 1 + 1 + 2 + RefusalDetail::MAX_LEN;
/// The largest Error body an Open reader accepts: a length and at most 256 reason bytes.
pub(super) const MAX_OPEN_ERROR: usize = 2 + 256;

const _: () = assert!(MAX_CONN_INFO == 1295 && MAX_ATTACHED == 1320 && MAX_OPEN_REFUSAL == 1028);
const _: () = assert!(MAX_ATTACHED <= MAX_FRAME && MAX_OPEN_REFUSAL <= MAX_FRAME);

/// The lane an Open rides at the resident, as the wire names it.
///
/// A wire form of its own rather than [`crate::peers::Lane`]: the wire carries Isolated, which is a
/// connection and never a held lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenLane {
    /// The peer's held session for ordinary service use.
    Main,
    /// The peer's held fan-out session.
    Bulk,
    /// A connection of its own, never held.
    Isolated,
}

impl OpenLane {
    const fn byte(self) -> u8 {
        match self {
            Self::Main => 0,
            Self::Bulk => 1,
            Self::Isolated => 2,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Main),
            1 => Some(Self::Bulk),
            2 => Some(Self::Isolated),
            _ => None,
        }
    }
}

/// Why an Open body was refused: which field broke the grammar, and never its bytes.
///
/// Payload-free on purpose: the body carries hints and a slip, and no diagnostic may echo either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MalformedOpen {
    /// The body ended inside a field.
    #[error("open request is truncated")]
    Truncated,
    /// The peer bytes are not a key bifrost can dial.
    #[error("open request peer is not a valid key")]
    Peer,
    /// More than 16 hints.
    #[error("open request has too many hints")]
    HintCount,
    /// A hint's length is zero or over 64 bytes.
    #[error("open request hint length is out of bounds")]
    HintLength,
    /// A hint is not a socket address.
    #[error("open request hint is not a socket address")]
    Hint,
    /// The service's length is zero or over 128 bytes.
    #[error("open request service length is out of bounds")]
    ServiceLength,
    /// The service is not a service name.
    #[error("open request service is not a service name")]
    Service,
    /// The lane byte names no lane.
    #[error("open request lane is unknown")]
    Lane,
    /// The slip presence byte is neither 0 nor 1.
    #[error("open request slip presence is invalid")]
    SlipPresence,
    /// A present slip's length is zero or over 14336 bytes.
    #[error("open request slip length is out of bounds")]
    SlipLength,
    /// The slip is not a link.
    #[error("open request slip is not a link")]
    Slip,
    /// The observation byte is not the one this build reads.
    #[error("open request observation mode is unsupported")]
    Observation,
    /// Bytes follow the observation byte.
    #[error("open request has trailing bytes")]
    Trailing,
}

/// An Open request body: reach `peer`'s `service` on `lane`, presenting `slip` when there is one.
///
/// Built only through [`new`](Self::new) or [`decode`](Self::decode), so a value always encodes.
/// Hints keep their order and duplicates; they are addresses, never names to resolve. Not `Clone`:
/// one request owns its slip, and a copy would be a second credential body to account for.
pub struct OpenRequest {
    peer: NodeId,
    hints: Vec<SocketAddr>,
    service: Service,
    lane: OpenLane,
    slip: Option<Link>,
}

impl OpenRequest {
    /// An Open for `service` at `peer`.
    ///
    /// # Errors
    ///
    /// [`MalformedOpen::HintCount`] past 16 hints, so a request the resident would refuse is never
    /// built. A slip needs no check: a parsed link's token is held to 13,200 bytes, so its text
    /// always fits the slip field.
    pub fn new(
        peer: NodeId,
        hints: Vec<SocketAddr>,
        service: Service,
        lane: OpenLane,
        slip: Option<Link>,
    ) -> Result<Self, MalformedOpen> {
        if hints.len() > MAX_HINTS {
            return Err(MalformedOpen::HintCount);
        }
        Ok(Self {
            peer,
            hints,
            service,
            lane,
            slip,
        })
    }

    /// The peer to reach.
    pub fn peer(&self) -> NodeId {
        self.peer
    }

    /// The dial hints, in the order the caller gave them.
    pub fn hints(&self) -> &[SocketAddr] {
        &self.hints
    }

    /// The service to open.
    pub fn service(&self) -> &Service {
        &self.service
    }

    /// The lane to ride.
    pub fn lane(&self) -> OpenLane {
        self.lane
    }

    /// The link presented for this stream only, when the caller typed the peer as one.
    pub fn slip(&self) -> Option<&Link> {
        self.slip.as_ref()
    }

    /// The body as it goes on the wire. The observation byte is always the unobserved value.
    ///
    /// # Errors
    ///
    /// [`MalformedOpen::HintLength`] if a hint renders past 64 bytes, which no socket address does.
    pub fn encode(&self) -> Result<Vec<u8>, MalformedOpen> {
        let mut out = Vec::with_capacity(MIN_OPEN_BODY);
        out.extend_from_slice(self.peer.key());
        // Both counts are held under 256 by construction: `new` bounds the hints, `Service` its length.
        out.push(u8::try_from(self.hints.len()).map_err(|_| MalformedOpen::HintCount)?);
        for hint in &self.hints {
            let mut text = AddrText::default();
            write!(text, "{hint}").map_err(|_| MalformedOpen::HintLength)?;
            out.push(u8::try_from(text.len).map_err(|_| MalformedOpen::HintLength)?);
            out.extend_from_slice(text.as_bytes());
        }
        let service = self.service.as_str().as_bytes();
        out.push(u8::try_from(service.len()).map_err(|_| MalformedOpen::ServiceLength)?);
        out.extend_from_slice(service);
        out.push(self.lane.byte());
        match &self.slip {
            None => out.push(0),
            Some(slip) => {
                let slip = slip.as_str().as_bytes();
                let len = u16::try_from(slip.len()).map_err(|_| MalformedOpen::SlipLength)?;
                out.push(1);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(slip);
            }
        }
        out.push(UNOBSERVED);
        Ok(out)
    }

    /// Parse a whole Open body.
    ///
    /// Every length, the observation byte and exact consumption are checked over borrowed bytes
    /// first; only a body whose whole grammar holds is turned into owned, typed fields.
    ///
    /// # Errors
    ///
    /// The [`MalformedOpen`] field that failed, never its bytes.
    pub fn decode(body: &[u8]) -> Result<Self, MalformedOpen> {
        let raw = RawOpen::scan(body)?;
        let peer = NodeId::try_new(bifrost::CryptoKind::Ed25519, raw.peer)
            .map_err(|_| MalformedOpen::Peer)?;
        let mut hints = Vec::with_capacity(raw.hint_count);
        for hint in &raw.hints[..raw.hint_count] {
            let hint = core::str::from_utf8(hint)
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or(MalformedOpen::Hint)?;
            hints.push(hint);
        }
        let service = core::str::from_utf8(raw.service)
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or(MalformedOpen::Service)?;
        let slip = match raw.slip {
            None => None,
            Some(slip) => Some(
                core::str::from_utf8(slip)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .ok_or(MalformedOpen::Slip)?,
            ),
        };
        Ok(Self {
            peer,
            hints,
            service,
            lane: raw.lane,
            slip,
        })
    }
}

impl fmt::Debug for OpenRequest {
    /// Names the peer, the service and the lane, and only counts what could identify the caller's
    /// reach: no hint address and no slip text is printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenRequest")
            .field("peer", &self.peer)
            .field("hints", &self.hints.len())
            .field("service", &self.service)
            .field("lane", &self.lane)
            .field("slip", &self.slip.as_ref().map(|_| Redacted))
            .finish()
    }
}

/// Stands in for a slip in [`OpenRequest`]'s `Debug`.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// An Open body whose structure holds, still borrowing the bytes it was read from.
struct RawOpen<'a> {
    peer: [u8; 32],
    hints: [&'a [u8]; MAX_HINTS],
    hint_count: usize,
    service: &'a [u8],
    lane: OpenLane,
    slip: Option<&'a [u8]>,
}

impl<'a> RawOpen<'a> {
    fn scan(body: &'a [u8]) -> Result<Self, MalformedOpen> {
        let mut cursor = Cursor(body);
        let peer = cursor.array().ok_or(MalformedOpen::Truncated)?;
        let hint_count = usize::from(cursor.byte().ok_or(MalformedOpen::Truncated)?);
        if hint_count > MAX_HINTS {
            return Err(MalformedOpen::HintCount);
        }
        let mut hints = [&[][..]; MAX_HINTS];
        for hint in &mut hints[..hint_count] {
            let len = usize::from(cursor.byte().ok_or(MalformedOpen::Truncated)?);
            if !(1..=MAX_HINT_LEN).contains(&len) {
                return Err(MalformedOpen::HintLength);
            }
            *hint = cursor.take(len).ok_or(MalformedOpen::Truncated)?;
        }
        let len = usize::from(cursor.byte().ok_or(MalformedOpen::Truncated)?);
        if !(1..=MAX_SERVICE_LEN).contains(&len) {
            return Err(MalformedOpen::ServiceLength);
        }
        let service = cursor.take(len).ok_or(MalformedOpen::Truncated)?;
        let lane = OpenLane::from_byte(cursor.byte().ok_or(MalformedOpen::Truncated)?)
            .ok_or(MalformedOpen::Lane)?;
        let slip = match cursor.byte().ok_or(MalformedOpen::Truncated)? {
            0 => None,
            1 => {
                let len = usize::from(cursor.u16().ok_or(MalformedOpen::Truncated)?);
                if !(1..=MAX_SLIP_LEN).contains(&len) {
                    return Err(MalformedOpen::SlipLength);
                }
                Some(cursor.take(len).ok_or(MalformedOpen::Truncated)?)
            }
            _ => return Err(MalformedOpen::SlipPresence),
        };
        if cursor.byte().ok_or(MalformedOpen::Truncated)? != UNOBSERVED {
            return Err(MalformedOpen::Observation);
        }
        if !cursor.0.is_empty() {
            return Err(MalformedOpen::Trailing);
        }
        Ok(Self {
            peer,
            hints,
            hint_count,
            service,
            lane,
            slip,
        })
    }
}

/// A socket address's rendered text, held inline: rendering a hint or a remote address for the wire
/// allocates nothing and cannot grow past the hint bound, the tighter of the two address fields.
struct AddrText {
    bytes: [u8; MAX_HINT_LEN],
    len: usize,
}

impl Default for AddrText {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_HINT_LEN],
            len: 0,
        }
    }
}

impl AddrText {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Write for AddrText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self
            .len
            .checked_add(text.len())
            .filter(|&end| end <= MAX_HINT_LEN)
            .ok_or(fmt::Error)?;
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Why the resident did not attach an Open, as the wire carries it.
///
/// [`Peer`](Self::Peer) is the far end's own decision; every other class is this machine's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenRefusal {
    /// The peer refused the stream.
    Peer(PeerRefusal),
    /// The peer answered with a refusal this build cannot read.
    PeerUnreadable(RefusalDetail),
    /// The peer could not be dialed.
    Unreachable(RefusalDetail),
    /// The dial or the stream open ran out of time.
    Timeout,
    /// The session broke while the stream was opening.
    Broken(RefusalDetail),
    /// The resident or the peer's lane is at its cap.
    Busy,
    /// This home's standing has ended and could not be renewed.
    StandingEnded,
    /// The Open names this machine, or presents a link anyone may hold.
    NotHere,
}

/// A peer's refusal class, closed over the classes the wire names.
///
/// Its own type rather than [`Refusal`], which is non-exhaustive: an encoder over it needs no arm
/// for a class the wire cannot carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRefusal {
    /// The peer's gate did not admit this dial.
    NotAdmitted,
    /// The peer rejected the request shape.
    BadRequest(RefusalDetail),
    /// The peer could not serve the dial for a reason of its own.
    Unavailable(RefusalDetail),
}

impl From<PeerRefusal> for Refusal {
    /// The refusal the peer's own transport would have raised, so a caller through the resident
    /// matches the same [`bifrost::Error::Refused`] a direct dial gets.
    fn from(refusal: PeerRefusal) -> Self {
        match refusal {
            PeerRefusal::NotAdmitted => Self::NotAdmitted,
            PeerRefusal::BadRequest(detail) => Self::BadRequest { detail },
            PeerRefusal::Unavailable(detail) => Self::Unavailable { detail },
        }
    }
}

impl OpenRefusal {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_OPEN_REFUSAL);
        match self {
            Self::Peer(refusal) => {
                out.push(0);
                match refusal {
                    PeerRefusal::NotAdmitted => out.push(0),
                    PeerRefusal::BadRequest(detail) => {
                        out.push(1);
                        push_detail(&mut out, detail);
                    }
                    PeerRefusal::Unavailable(detail) => {
                        out.push(2);
                        push_detail(&mut out, detail);
                    }
                }
            }
            Self::PeerUnreadable(detail) => {
                out.push(1);
                push_detail(&mut out, detail);
            }
            Self::Unreachable(detail) => {
                out.push(2);
                push_detail(&mut out, detail);
            }
            Self::Timeout => out.push(3),
            Self::Broken(detail) => {
                out.push(4);
                push_detail(&mut out, detail);
            }
            Self::Busy => out.push(5),
            Self::StandingEnded => out.push(6),
            Self::NotHere => out.push(7),
        }
        out
    }

    pub(super) fn decode(body: &[u8]) -> Result<Self, ControlError> {
        let mut cursor = Cursor(body);
        let class = cursor.byte().ok_or_else(truncated)?;
        let refusal = match class {
            0 => Self::Peer(match cursor.byte().ok_or_else(truncated)? {
                0 => PeerRefusal::NotAdmitted,
                1 => PeerRefusal::BadRequest(take_detail(&mut cursor)?),
                2 => PeerRefusal::Unavailable(take_detail(&mut cursor)?),
                _ => return Err(local_detail::protocol("unknown peer refusal class")),
            }),
            1 => Self::PeerUnreadable(take_detail(&mut cursor)?),
            2 => Self::Unreachable(take_detail(&mut cursor)?),
            3 => Self::Timeout,
            4 => Self::Broken(take_detail(&mut cursor)?),
            5 => Self::Busy,
            6 => Self::StandingEnded,
            7 => Self::NotHere,
            _ => return Err(local_detail::protocol("unknown open refusal class")),
        };
        finish(&cursor)?;
        Ok(refusal)
    }
}

// A detail is already held to `RefusalDetail::MAX_LEN`, so its length always fits the u16 field.
fn push_detail(out: &mut Vec<u8>, detail: &RefusalDetail) {
    let text = detail.as_str().as_bytes();
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text);
}

fn take_detail(cursor: &mut Cursor<'_>) -> Result<RefusalDetail, ControlError> {
    let len = usize::from(cursor.u16().ok_or_else(truncated)?);
    if len > RefusalDetail::MAX_LEN {
        return Err(local_detail::protocol(
            "open refusal detail exceeds 1024 bytes",
        ));
    }
    core::str::from_utf8(cursor.take(len).ok_or_else(truncated)?)
        .ok()
        .and_then(|text| RefusalDetail::try_from(text).ok())
        .ok_or_else(|| local_detail::protocol("open refusal detail is not UTF-8"))
}

/// Encode an Attached body: no path reference, then the path report. Every bound and conversion is
/// checked here, before the caller writes a header.
pub(super) fn encode_attached(info: &ConnInfo) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 3);
    out.push(0);
    match &info.path {
        Path::Unknown => out.push(0),
        Path::Direct => out.push(1),
        Path::Relayed(relay) => {
            let url = relay.url().as_str().as_bytes();
            if url.is_empty() || url.len() > MAX_RELAY_URL {
                return Err(io::Error::other("relay url out of bounds"));
            }
            out.push(2);
            out.extend_from_slice(&(url.len() as u16).to_be_bytes());
            out.extend_from_slice(url);
        }
    }
    match info.rtt {
        None => out.push(0),
        Some(rtt) => {
            // Floor to whole microseconds; a round trip past u64 microseconds is refused, never
            // wrapped or saturated into a plausible number.
            let micros = u64::try_from(rtt.as_micros())
                .map_err(|_| io::Error::other("round trip out of range"))?;
            out.push(1);
            out.extend_from_slice(&micros.to_be_bytes());
        }
    }
    match info.remote {
        None => out.push(0),
        Some(remote) => {
            let mut text = AddrText::default();
            write!(text, "{remote}").map_err(|_| io::Error::other("remote address too long"))?;
            out.push(1);
            out.extend_from_slice(&(text.len as u16).to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
    }
    Ok(out)
}

/// Decode an Attached body. A path reference is a protocol error: this build never asks for one, so
/// a reply carrying one answered some other request.
pub(super) fn decode_attached(body: &[u8]) -> Result<ConnInfo, ControlError> {
    let mut cursor = Cursor(body);
    match cursor.byte().ok_or_else(truncated)? {
        0 => {}
        1 => {
            return Err(local_detail::protocol(
                "attached carries an unrequested path reference",
            ));
        }
        _ => {
            return Err(local_detail::protocol(
                "attached reference presence is invalid",
            ));
        }
    }
    let path = match cursor.byte().ok_or_else(truncated)? {
        0 => Path::Unknown,
        1 => Path::Direct,
        2 => {
            let len = usize::from(cursor.u16().ok_or_else(truncated)?);
            if !(1..=MAX_RELAY_URL).contains(&len) {
                return Err(local_detail::protocol(
                    "attached relay url length is out of bounds",
                ));
            }
            let url = core::str::from_utf8(cursor.take(len).ok_or_else(truncated)?)
                .ok()
                .and_then(|text| url::Url::parse(text).ok())
                .ok_or_else(|| local_detail::protocol("attached relay url is invalid"))?;
            Path::Relayed(Relay::from(url))
        }
        _ => return Err(local_detail::protocol("attached path class is unknown")),
    };
    let rtt = match cursor.byte().ok_or_else(truncated)? {
        0 => None,
        1 => Some(Duration::from_micros(u64::from_be_bytes(
            cursor.array().ok_or_else(truncated)?,
        ))),
        _ => {
            return Err(local_detail::protocol(
                "attached round trip presence is invalid",
            ));
        }
    };
    let remote = match cursor.byte().ok_or_else(truncated)? {
        0 => None,
        1 => {
            let len = usize::from(cursor.u16().ok_or_else(truncated)?);
            if !(1..=MAX_REMOTE).contains(&len) {
                return Err(local_detail::protocol(
                    "attached remote length is out of bounds",
                ));
            }
            Some(
                core::str::from_utf8(cursor.take(len).ok_or_else(truncated)?)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(|| local_detail::protocol("attached remote is invalid"))?,
            )
        }
        _ => {
            return Err(local_detail::protocol(
                "attached remote presence is invalid",
            ));
        }
    };
    finish(&cursor)?;
    Ok(ConnInfo { path, rtt, remote })
}

fn truncated() -> ControlError {
    local_detail::protocol("open reply is truncated")
}

fn finish(cursor: &Cursor<'_>) -> Result<(), ControlError> {
    if !cursor.0.is_empty() {
        return Err(local_detail::protocol("open reply has trailing bytes"));
    }
    Ok(())
}

/// Reads fields off the front of a body. Every read is `None` past the end, and the caller names the
/// failure, so one cursor serves the request's typed errors and the replies' protocol errors.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (part, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(part)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn byte(&mut self) -> Option<u8> {
        let [byte] = self.array()?;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }
}

#[cfg(test)]
#[path = "open_tests.rs"]
mod tests;
