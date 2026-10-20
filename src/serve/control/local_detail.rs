use core::fmt;

use tokio::io::{self, AsyncWriteExt as _};

use super::{ControlError, MAX_FRAME};

/// The optional local-detail limit that prevented a complete snapshot.
///
/// These limits do not restrict startup configuration or status reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDetailLimit {
    /// More than 256 bound service pairs.
    BoundCount,
    /// A bound service name exceeds 63 bytes.
    NameBytes,
    /// A startup target exceeds 4096 bytes.
    TargetBytes,
    /// The complete success payload exceeds 8192 bytes.
    PayloadBytes,
}

impl fmt::Display for LocalDetailLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BoundCount => "256 bound services",
            Self::NameBytes => "63 bytes per service name",
            Self::TargetBytes => "4096 bytes per target",
            Self::PayloadBytes => "8192 payload bytes",
        })
    }
}

/// Why local service detail could not produce a complete snapshot.
#[derive(Debug, thiserror::Error)]
pub enum LocalDetailError {
    /// The answering resident has no installed startup service state.
    #[error("the resident has no startup service snapshot")]
    MissingStartup,
    /// The complete snapshot exceeds an optional detail limit; no partial snapshot is returned.
    #[error("local service detail exceeds the limit of {0}")]
    LimitExceeded(LocalDetailLimit),
    /// The answering resident cannot represent its state as a valid snapshot.
    #[error("the resident's local service state is inconsistent")]
    InconsistentState,
    /// Memory allocation failed or reserved capacity exceeded a local service-detail storage limit.
    #[error("local service detail resources are unavailable")]
    ResourceUnavailable,
    /// The peer returned a bounded Error reason.
    ///
    /// The reason is retained as data, not parsed into another error kind or included in Display.
    #[error("the resident could not provide local service detail")]
    PeerError(String),
}

/// A resident capture failure representable in a local-detail response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocalDetailCaptureError {
    /// No startup service state is installed.
    #[error("the resident has no startup service snapshot")]
    MissingStartup,
    /// The complete snapshot exceeds an optional detail limit.
    #[error("local service detail exceeds the limit of {0}")]
    LimitExceeded(LocalDetailLimit),
    /// Resident state cannot produce a valid snapshot.
    #[error("the resident's local service state is inconsistent")]
    InconsistentState,
}

impl From<LocalDetailCaptureError> for LocalDetailError {
    fn from(error: LocalDetailCaptureError) -> Self {
        match error {
            LocalDetailCaptureError::MissingStartup => Self::MissingStartup,
            LocalDetailCaptureError::LimitExceeded(limit) => Self::LimitExceeded(limit),
            LocalDetailCaptureError::InconsistentState => Self::InconsistentState,
        }
    }
}

/// Validated startup service pairs and refusal bits from one local resident observation.
///
/// Targets retain their startup spelling. This is neither a backend health check nor the configuration saved for the next start. Escape target text before terminal output.
#[derive(PartialEq, Eq)]
pub struct LocalServiceSnapshot {
    payload: Vec<u8>,
    count: u16,
}

impl LocalServiceSnapshot {
    /// Return the number of bound startup pairs.
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Return whether the resident bound no startup services.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate all pairs in ascending UTF-8 name-byte order without allocating.
    pub fn pairs(&self) -> LocalServicePairs<'_> {
        LocalServicePairs {
            bytes: &self.payload[3..],
        }
    }

    /// Find a pair by exact stored-name bytes without allocating.
    ///
    /// A noncanonical search name finds nothing; names are not folded or repaired.
    pub fn get(&self, name: &str) -> Option<LocalServicePair<'_>> {
        self.pairs().find(|pair| pair.name().as_str() == name)
    }

    /// Test exact stored-name membership without allocating or normalizing the name.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

// Existing unexpected-response diagnostics use Debug, so it must not disclose startup targets.
impl fmt::Debug for LocalServiceSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalServiceSnapshot")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// A borrowed startup name, exact target and refusal bit from a validated snapshot.
#[derive(Clone, Copy)]
pub struct LocalServicePair<'a> {
    name: LocalServiceName<'a>,
    target: LocalServiceTarget<'a>,
    refused: bool,
}

impl<'a> LocalServicePair<'a> {
    /// Return the canonical startup service name.
    pub fn name(&self) -> LocalServiceName<'a> {
        self.name
    }
    /// Return the exact startup target; it may require terminal escaping.
    pub fn target(&self) -> LocalServiceTarget<'a> {
        self.target
    }
    /// Return whether the resident refused this bound name at capture.
    ///
    /// Removal can also set this bit. It does not report whether the current saved configuration disables the service or whether the backend is healthy.
    pub fn refused(&self) -> bool {
        self.refused
    }
}

/// A validated, borrowed canonical service name.
#[derive(Clone, Copy)]
pub struct LocalServiceName<'a>(&'a str);

impl<'a> LocalServiceName<'a> {
    /// Borrow the exact canonical name.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

/// A borrowed, nonempty UTF-8 startup target, without address or path normalization.
#[derive(Clone, Copy)]
pub struct LocalServiceTarget<'a>(&'a str);

impl<'a> LocalServiceTarget<'a> {
    /// Borrow the exact startup target; escape it before terminal output.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

/// An allocation-free iterator over every validated startup pair in wire order.
pub struct LocalServicePairs<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for LocalServicePairs<'a> {
    type Item = LocalServicePair<'a>;

    /// Return the next validated pair; successful snapshot validation makes iteration infallible.
    fn next(&mut self) -> Option<Self::Item> {
        // The immutable body was fully validated before ownership entered the snapshot.
        let name = borrowed_string(&mut self.bytes)?;
        let target = borrowed_string(&mut self.bytes)?;
        let (&refused, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(LocalServicePair {
            name: LocalServiceName(name),
            target: LocalServiceTarget(target),
            refused: refused == 1,
        })
    }
}

pub(super) async fn write<W: io::AsyncWrite + Unpin>(
    reply: &Result<LocalServiceSnapshot, LocalDetailCaptureError>,
    writer: &mut W,
) -> io::Result<()> {
    let outcome;
    let payload = match reply {
        Ok(snapshot) => snapshot.payload.as_slice(),
        Err(error) => {
            outcome = match error {
                LocalDetailCaptureError::MissingStartup => [1, 0],
                LocalDetailCaptureError::LimitExceeded(limit) => [
                    2,
                    match limit {
                        LocalDetailLimit::BoundCount => 1,
                        LocalDetailLimit::NameBytes => 2,
                        LocalDetailLimit::TargetBytes => 3,
                        LocalDetailLimit::PayloadBytes => 4,
                    },
                ],
                LocalDetailCaptureError::InconsistentState => [3, 0],
            };
            &outcome[..if outcome[0] == 2 { 2 } else { 1 }]
        }
    };
    // Only validated, bounded storage reaches this writer; it borrows rather than re-encodes it.
    let len = u16::try_from(payload.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    super::write_magic(writer).await?;
    writer.write_all(&[9]).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await
}

pub(super) fn decode(
    payload: Vec<u8>,
) -> Result<Result<LocalServiceSnapshot, LocalDetailCaptureError>, ControlError> {
    let mut cursor = 0;
    let outcome = take(&payload, &mut cursor, 1)?[0];
    let error = match outcome {
        0 => {
            let count = u16::from_be_bytes(take_u16(&payload, &mut cursor)?);
            if count > 256 {
                return Err(protocol("local service detail has too many bound services"));
            }
            let mut previous = &[][..];
            for _ in 0..count {
                let name = field(
                    &payload,
                    &mut cursor,
                    63,
                    "local service name exceeds 63 bytes",
                )?;
                if !canonical_name(name) {
                    return Err(protocol("invalid local service name"));
                }
                if name <= previous {
                    return Err(protocol("local service names are not strictly ordered"));
                }
                previous = name;
                let target = field(
                    &payload,
                    &mut cursor,
                    4096,
                    "local service target exceeds 4096 bytes",
                )?;
                if target.is_empty() || core::str::from_utf8(target).is_err() {
                    return Err(protocol("invalid local service target"));
                }
                if take(&payload, &mut cursor, 1)?[0] > 1 {
                    return Err(protocol("invalid local service refusal byte"));
                }
            }
            finish(&payload, cursor)?;
            return Ok(Ok(LocalServiceSnapshot { payload, count }));
        }
        1 => LocalDetailCaptureError::MissingStartup,
        2 => LocalDetailCaptureError::LimitExceeded(match take(&payload, &mut cursor, 1)?[0] {
            1 => LocalDetailLimit::BoundCount,
            2 => LocalDetailLimit::NameBytes,
            3 => LocalDetailLimit::TargetBytes,
            4 => LocalDetailLimit::PayloadBytes,
            _ => return Err(protocol("unknown local service detail limit")),
        }),
        3 => LocalDetailCaptureError::InconsistentState,
        _ => return Err(protocol("unknown local service detail outcome")),
    };
    finish(&payload, cursor)?;
    Ok(Err(error))
}

// One fallible payload allocation, with capacity checked before reading untrusted bytes.
pub(super) fn storage(len: usize) -> Result<Vec<u8>, ControlError> {
    if len > MAX_FRAME {
        return Err(ControlError::TooLarge(len));
    }
    let mut payload = Vec::new();
    payload.try_reserve_exact(len).map_err(|_| unavailable())?;
    if payload.capacity() > MAX_FRAME {
        return Err(unavailable());
    }
    payload.resize(len, 0);
    Ok(payload)
}

fn unavailable() -> ControlError {
    ControlError::LocalDetail(LocalDetailError::ResourceUnavailable)
}

// Fixed diagnostics are fallible too; no peer text or target ever enters this allocation.
fn protocol(reason: &'static str) -> ControlError {
    let mut owned = String::new();
    if owned.try_reserve_exact(reason.len()).is_err() || owned.capacity() > 256 {
        return unavailable();
    }
    owned.push_str(reason);
    ControlError::Protocol(owned)
}

fn checked_end(start: usize, len: usize) -> Result<usize, ControlError> {
    start
        .checked_add(len)
        .ok_or_else(|| protocol("invalid local service detail length"))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], ControlError> {
    let end = checked_end(*cursor, len)?;
    let part = bytes
        .get(*cursor..end)
        .ok_or_else(|| protocol("local service detail is truncated"))?;
    *cursor = end;
    Ok(part)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 2], ControlError> {
    let part = take(bytes, cursor, 2)?;
    Ok([part[0], part[1]])
}

fn field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    cap: usize,
    diagnostic: &'static str,
) -> Result<&'a [u8], ControlError> {
    let len = usize::from(u16::from_be_bytes(take_u16(bytes, cursor)?));
    if len > cap {
        return Err(protocol(diagnostic));
    }
    take(bytes, cursor, len)
}

fn finish(bytes: &[u8], cursor: usize) -> Result<(), ControlError> {
    if cursor != bytes.len() {
        return Err(protocol("unexpected trailing local service detail bytes"));
    }
    Ok(())
}

fn canonical_name(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && ![b"control".as_slice(), b"lookup".as_slice()].contains(&bytes)
}

fn borrowed_string<'a>(bytes: &mut &'a [u8]) -> Option<&'a str> {
    let (prefix, rest) = bytes.split_at_checked(2)?;
    let len = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let (text, rest) = rest.split_at_checked(len)?;
    *bytes = rest;
    core::str::from_utf8(text).ok()
}

#[cfg(test)]
#[path = "local_detail_tests.rs"]
mod tests;
