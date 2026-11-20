//! Path: sample the connection one observed Open attached to, by the reference its Attached carried.
//!
//! A reference names one Open, never a peer or a lane, so two callers on one peer, a replaced cache
//! entry or a restarted resident can never answer for each other. It is public attribution, not a
//! capability: a process of this user that learns one can sample it or finish it, and neither touches the
//! stream it names.

use core::num::NonZeroU64;

use bifrost::ConnInfo;
use rand::RngCore;
use tokio::io::{self, AsyncReadExt as _};

use super::open::{Cursor, MAX_CONN_INFO, decode_conn_info, encode_conn_info};
use super::{ControlError, local_detail};

/// A Path request's body: a reference and an action, exactly.
pub(super) const PATH_REQUEST: usize = PathRef::LEN + 1;

/// The largest Path reply body: the sample outcome and the longest path report.
pub(super) const MAX_PATH_REPLY: usize = 1 + MAX_CONN_INFO;

const _: () = assert!(PATH_REQUEST == 25 && MAX_PATH_REPLY == 1296);

/// The diagnostic every malformed Path request is answered with. Fixed words, so a reference's bytes
/// never reach a reply.
pub(super) const INVALID_PATH: &str = "invalid path request";

/// Whether an Open asks for a reference to its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// No reference: the resident keeps nothing past the stream.
    Unobserved,
    /// A reference in Attached, and the connection kept for Path until it is finished or expires.
    Observed,
}

impl Observation {
    pub(super) const fn byte(self) -> u8 {
        match self {
            Self::Unobserved => 0,
            Self::Observed => 1,
        }
    }

    pub(super) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Unobserved),
            1 => Some(Self::Observed),
            _ => None,
        }
    }
}

/// One resident run's namespace for its references: sixteen random bytes, never all zero, drawn once
/// when the run starts. A reference from an earlier run names another epoch, so it can never resolve to
/// a connection of this one. Public, like the reference it heads: it guards against reuse, not guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch([u8; 16]);

impl Epoch {
    /// Draw an epoch from `random`. A source that fails, or a draw of all zeros, is an error: no
    /// fallback value and no second draw, so a broken source can never hand two runs one namespace.
    ///
    /// # Errors
    ///
    /// [`EpochError`] when the source fails or draws zero.
    pub fn draw(random: &mut impl RngCore) -> Result<Self, EpochError> {
        let mut bytes = [0; 16];
        random
            .try_fill_bytes(&mut bytes)
            .map_err(EpochError::Random)?;
        Self::from_bytes(bytes).ok_or(EpochError::Zero)
    }

    /// The epoch these bytes spell, or `None` for zero, which no run draws.
    const fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        if u128::from_be_bytes(bytes) == 0 {
            None
        } else {
            Some(Self(bytes))
        }
    }
}

/// Why a run could not draw its epoch.
#[derive(Debug, thiserror::Error)]
pub enum EpochError {
    /// The operating system's random source failed.
    #[error("the random source failed while starting path observation")]
    Random(#[source] rand::Error),
    /// The draw was all zeros, which no reference may carry.
    #[error("the random source returned only zeros while starting path observation")]
    Zero,
}

/// One observed Open's number within its run: from 1, in order, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(NonZeroU64);

impl Ticket {
    /// The first ticket a run hands out.
    pub(crate) const FIRST: Self = Self(NonZeroU64::MIN);

    /// The ticket after this one, or `None` past `u64::MAX`: a run that hands that one out has no more.
    pub(crate) fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    #[cfg(test)]
    pub(crate) fn at(number: NonZeroU64) -> Self {
        Self(number)
    }
}

/// A reference to one observed Open's connection: `epoch[16] | ticket:u64be`, both nonzero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRef {
    epoch: Epoch,
    ticket: Ticket,
}

impl PathRef {
    /// A reference's length on the wire.
    pub(super) const LEN: usize = 24;

    /// The reference to `ticket` in `epoch`.
    pub(crate) fn new(epoch: Epoch, ticket: Ticket) -> Self {
        Self { epoch, ticket }
    }

    /// The run it names.
    pub(crate) fn epoch(self) -> Epoch {
        self.epoch
    }

    /// The Open it names within that run.
    pub(crate) fn ticket(self) -> Ticket {
        self.ticket
    }

    pub(super) fn encode_into(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.epoch.0);
        out.extend_from_slice(&self.ticket.0.get().to_be_bytes());
    }

    /// Read a reference. The caller names the failure, since a short body and a zero field mean
    /// different things in a request and in a reply.
    pub(super) fn decode(cursor: &mut Cursor<'_>) -> Result<Self, BadRef> {
        let epoch = cursor.array().ok_or(BadRef::Truncated)?;
        let ticket = u64::from_be_bytes(cursor.array().ok_or(BadRef::Truncated)?);
        let epoch = Epoch::from_bytes(epoch).ok_or(BadRef::Zero)?;
        let ticket = NonZeroU64::new(ticket).ok_or(BadRef::Zero)?;
        Ok(Self {
            epoch,
            ticket: Ticket(ticket),
        })
    }
}

/// Why a reference did not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BadRef {
    /// The body ended inside it.
    Truncated,
    /// Its epoch or ticket is zero, which no run hands out.
    Zero,
}

/// What a Path request asks of the reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAction {
    /// Sample the connection; the reference stays.
    Sample,
    /// Sample the connection once more and retire the reference.
    Finish,
}

/// Request 5: one action on one reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRequest {
    /// The Open whose connection to sample.
    pub reference: PathRef,
    /// Whether the reference stays.
    pub action: PathAction,
}

impl PathRequest {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PATH_REQUEST);
        self.reference.encode_into(&mut out);
        out.push(match self.action {
            PathAction::Sample => 0,
            PathAction::Finish => 1,
        });
        out
    }

    /// Read a Path body of `len` declared bytes. Only 25 is a Path, so any other length is refused
    /// before a byte of the body is read, and the body is held inline, never allocated.
    pub(super) async fn read<R: io::AsyncRead + Unpin>(
        reader: &mut R,
        len: usize,
    ) -> Result<Self, ControlError> {
        if len != PATH_REQUEST {
            return Err(local_detail::protocol(INVALID_PATH));
        }
        let mut body = [0; PATH_REQUEST];
        reader
            .read_exact(&mut body)
            .await
            .map_err(ControlError::Io)?;
        Self::decode(&body)
    }

    // The body is exactly 25 bytes, so every failure here is the one fixed diagnostic: a zero field and
    // an unknown action alike, and nothing of the reference is echoed.
    fn decode(body: &[u8; PATH_REQUEST]) -> Result<Self, ControlError> {
        let mut cursor = Cursor(body);
        let reference = PathRef::decode(&mut cursor);
        let action = match cursor.byte() {
            Some(0) => Some(PathAction::Sample),
            Some(1) => Some(PathAction::Finish),
            _ => None,
        };
        match (reference, action) {
            (Ok(reference), Some(action)) => Ok(Self { reference, action }),
            _ => Err(local_detail::protocol(INVALID_PATH)),
        }
    }
}

/// Reply 8: the connection's path report, or that the reference names nothing this run can sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathReply {
    /// The referenced connection, sampled as the request was taken. `Unknown` is a sample too: the
    /// connection could not tell its path.
    Sample(ConnInfo),
    /// Another run's reference, one never handed out, one finished, or one past its retention: all
    /// read alike.
    Unavailable,
}

impl PathReply {
    /// The reply body. Every bound is checked here, before a header is written.
    pub(super) fn encode(&self) -> io::Result<Vec<u8>> {
        match self {
            Self::Sample(info) => {
                let mut out = Vec::with_capacity(1 + 3);
                out.push(0);
                encode_conn_info(&mut out, info)?;
                Ok(out)
            }
            Self::Unavailable => Ok(vec![1]),
        }
    }

    pub(super) fn decode(body: &[u8]) -> Result<Self, ControlError> {
        let mut cursor = Cursor(body);
        let outcome = cursor
            .byte()
            .ok_or_else(|| local_detail::protocol("path reply is truncated"))?;
        let reply = match outcome {
            0 => Self::Sample(decode_conn_info(&mut cursor)?),
            1 => Self::Unavailable,
            _ => return Err(local_detail::protocol("path reply outcome is unknown")),
        };
        if !cursor.0.is_empty() {
            return Err(local_detail::protocol("path reply has trailing bytes"));
        }
        Ok(reply)
    }
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
