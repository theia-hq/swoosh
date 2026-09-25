//! The update: the root's signed list of its live devices and its revocations, and its canonical encoding.
//!
//! Any device may serve an update, but only the root signs one, so a courier that relays the blob cannot
//! forge it. This module is the payload, its bounds and its codec; the signing is nauthy's generic
//! [`sign_document`](nauthy::Identity::sign_document) and [`Signed`](nauthy::Signed). Each live device
//! carries its name, the end and length of its standing, the ids of its live standings, and its newest
//! standing (bare), so a device can pick up its own renewal from any peer. No last-seen is carried.

use nauthy::{Link, SignError, Signed, VerifyKey};

pub use crate::codec::{
    FormatError, Id, MAX_BADGE, MAX_IDS, MAX_MEMBERS, MAX_REVOCATION_ID, MAX_REVOKED,
    MAX_REVOKED_KEYS,
};
use crate::codec::{Put as _, Reader, bound, canonicalize, check_device, check_ids, unique_labels};
use crate::contacts::DeviceLabel;

mod artifact;

pub use artifact::{Artifact, ArtifactError};

/// The magic the update's payload opens with: `swoosh-` and the file it heads. A payload this key signs
/// under another magic is never read as an update.
pub(crate) const MAGIC: &[u8] = b"swoosh-roster";

/// The layout version, after [`MAGIC`].
const VERSION: u8 = 1;

/// The fixed header: [`MAGIC`], [`VERSION`], the `u64` epoch and the `u32` member count.
const HEADER_LEN: usize = MAGIC.len() + 1 + 8 + 4;

/// One id on the wire: its `u64` expiry, `u16` length and bytes, at the bound.
pub(crate) const MAX_ID_LEN: usize = 8 + 2 + MAX_REVOCATION_ID;

/// One member on the wire at every bound: node key, name, `until`, `duration`, its ids, and its standing.
pub(crate) const MAX_MEMBER_LEN: usize =
    VerifyKey::LEN + 2 + DeviceLabel::MAX_LEN + 8 + 8 + 1 + MAX_IDS * MAX_ID_LEN + 2 + MAX_BADGE;

/// The detached ed25519 signature in the envelope [`cut`] writes.
const SIGNATURE_LEN: usize = 64;

/// nauthy's signed envelope: the signer key and the signature ahead of the payload ([`Signed::encode`]).
/// Restated because nauthy keeps its signature length private; the exactness test cuts a maximal update
/// and holds this to the byte.
pub(crate) const ENVELOPE_LEN: usize = VerifyKey::LEN + SIGNATURE_LEN;

/// The largest update blob a reader admits, in bytes: the envelope around the biggest payload
/// [`RosterDoc::parse_canonical`] accepts. A fold reads no more. Computed from the bounds, never chosen:
///
/// ```text
///     ENVELOPE_LEN                               signer key + signature
///   + HEADER_LEN                                 MAGIC + VERSION + epoch + member count
///   + MAX_MEMBERS * MAX_MEMBER_LEN               every member at every bound
///   + 4 + MAX_REVOKED * MAX_ID_LEN               the revoked ids
///   + 4 + MAX_REVOKED_KEYS * 32                  the revoked keys
///   = 96 + 26 + 4096 * 1436 + 4 + 16384 * 74 + 4 + 4096 * 32
///   = 7_225_474 bytes
/// ```
pub const MAX_ROSTER_BLOB: u64 = (ENVELOPE_LEN
    + HEADER_LEN
    + MAX_MEMBERS * MAX_MEMBER_LEN
    + 4
    + MAX_REVOKED * MAX_ID_LEN
    + 4
    + MAX_REVOKED_KEYS * VerifyKey::LEN) as u64;

/// A monotonically-increasing version of an operator's roster, carrying the cutter's own
/// [`RosterVersion`](crate::contacts::RosterVersion) onto the wire: it advances when the MEMBER SET
/// changes, not when a doc is re-cut or re-served. It orders two snapshots a device might see from two
/// courier nodes: the higher epoch is newer. It is NOT a timestamp (no wall clock, so no pattern-of-life
/// leak) and NOT a per-member field (no last-seen): it versions the WHOLE doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The reserved zero: no update cut yet. It parses like any other epoch and is refused at the fold,
    /// so "not versioned" stays a distinct condition from "not newer".
    pub const UNVERSIONED: Self = Self(0);
}

/// One live device in an update.
#[derive(Debug, Clone)]
pub struct Member {
    /// The device's key: the key it is dialed at and its standing is bound to.
    pub node: VerifyKey,
    /// The device's name. A suggestion, not authority: a puller keeps its own names.
    pub label: DeviceLabel,
    /// When the device's standing ends, in unix seconds.
    pub until: u64,
    /// How long each renewal runs, in seconds; 0 means never renewed on its own.
    pub duration: u64,
    /// The ids of its live standings, at most [`MAX_IDS`], each carried only until it expires.
    pub ids: Vec<Id>,
    /// Its newest standing, bare.
    pub standing: Link,
}

impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        self.node == other.node
            && self.label == other.label
            && self.until == other.until
            && self.duration == other.duration
            && self.ids == other.ids
            && self.standing.as_str() == other.standing.as_str()
    }
}

impl Eq for Member {}

/// The update: the live devices, the revoked ids and the revoked keys at one epoch. Canonical at
/// construction (every list sorted, every bound held), so its bytes are a pure function of its content
/// and every doc that builds also parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterDoc {
    epoch: Epoch,
    // invariant: every list sorted and unique, every bound held (upheld by `with_revocations`).
    members: Vec<Member>,
    revoked: Vec<Id>,
    revoked_keys: Vec<VerifyKey>,
}

impl RosterDoc {
    /// An update listing `members` and no revocations.
    pub fn new(epoch: Epoch, members: Vec<Member>) -> Result<Self, FormatError> {
        Self::with_revocations(epoch, members, Vec::new(), Vec::new())
    }

    /// An update listing `members`, the revoked ids and the revoked keys. Sorts every list, and refuses a
    /// repeated key, name or id and anything over its bound.
    pub fn with_revocations(
        epoch: Epoch,
        mut members: Vec<Member>,
        mut revoked: Vec<Id>,
        mut revoked_keys: Vec<VerifyKey>,
    ) -> Result<Self, FormatError> {
        bound(members.len(), MAX_MEMBERS, "members")?;
        bound(revoked.len(), MAX_REVOKED, "revoked ids")?;
        bound(revoked_keys.len(), MAX_REVOKED_KEYS, "revoked keys")?;
        for member in &mut members {
            check_device(&mut member.ids, &member.standing)?;
        }
        members.sort_by(|a, b| a.node.bytes().cmp(b.node.bytes()));
        if let Some(pair) = members.windows(2).find(|pair| pair[0].node == pair[1].node) {
            return Err(FormatError::DuplicateNode(pair[0].node));
        }
        unique_labels(members.iter().map(|member| &member.label))?;
        check_ids(&mut revoked)?;
        canonicalize(&mut revoked_keys, |key| *key.bytes())?;
        Ok(Self {
            epoch,
            members,
            revoked,
            revoked_keys,
        })
    }

    /// The roster's epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The members, in canonical (node-sorted) order.
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The revoked ids, sorted.
    pub fn revoked(&self) -> &[Id] {
        &self.revoked
    }

    /// The revoked device keys, sorted.
    pub fn revoked_keys(&self) -> &[VerifyKey] {
        &self.revoked_keys
    }

    /// The exact bytes that get signed and verified, a pure function of the doc's content:
    ///
    /// ```text
    /// all ints big-endian
    ///   MAGIC            b"swoosh-roster"
    ///   VERSION          u8 (1)
    ///   epoch            u64
    ///   member_count     u32                     (<= MAX_MEMBERS)
    ///   per member, ascending by node:
    ///     node           [u8; 32]
    ///     label          u16 length, bytes       (<= DeviceLabel::MAX_LEN)
    ///     until          u64
    ///     duration       u64
    ///     id_count       u8                      (<= MAX_IDS)
    ///     per id, ascending by id:
    ///       expires      u64
    ///       id           u16 length, bytes       (<= MAX_REVOCATION_ID)
    ///     standing       u16 length, bare link   (<= MAX_BADGE)
    ///   revoked_count    u32                     (<= MAX_REVOKED), then each id as above
    ///   revoked_key_count u32                    (<= MAX_REVOKED_KEYS), then each key, 32 bytes
    /// ```
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(MAGIC);
        out.put_u8(VERSION);
        out.put_u64(self.epoch.0);
        out.put_u32(self.members.len());
        for member in &self.members {
            out.extend_from_slice(member.node.bytes());
            out.put_bytes16(member.label.as_str().as_bytes());
            out.put_u64(member.until);
            out.put_u64(member.duration);
            out.put_u8(member.ids.len() as u8);
            for id in &member.ids {
                out.put_id(id);
            }
            out.put_bytes16(member.standing.as_str().as_bytes());
        }
        out.put_ids32(&self.revoked);
        out.put_keys32(&self.revoked_keys);
        out
    }

    /// Parse canonical bytes back into a doc: the inverse of [`canonical_bytes`](Self::canonical_bytes),
    /// bounds-checked before every allocation. Every list must already be strictly ascending (a permuted
    /// or repeated list is refused, not re-sorted) and every byte consumed, so the wire is one byte-string
    /// per doc.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut reader = Reader::open(bytes, MAGIC, VERSION)?;
        let epoch = Epoch(reader.u64()?);
        let count = reader.count32(MAX_MEMBERS, "members")?;
        let mut members: Vec<Member> = Vec::with_capacity(count);
        for _ in 0..count {
            let node = reader.key()?;
            if members
                .last()
                .is_some_and(|previous| node.bytes() <= previous.node.bytes())
            {
                return Err(FormatError::NonCanonicalOrder);
            }
            members.push(Member {
                node,
                label: reader.label()?,
                until: reader.u64()?,
                duration: reader.u64()?,
                ids: reader.device_ids()?,
                standing: reader.standing()?,
            });
        }
        unique_labels(members.iter().map(|member| &member.label))?;
        let revoked = reader.revoked()?;
        let revoked_keys = reader.revoked_keys()?;
        reader.finish()?;
        Ok(Self {
            epoch,
            members,
            revoked,
            revoked_keys,
        })
    }
}

/// Cut a fresh signed roster: canonicalize `doc` and sign it with the signet `identity`, yielding the wire
/// blob a `roster:` handler serves. The single CUT seam, so the canonicalize-then-sign pair is one call and
/// a caller cannot sign bytes that are not this doc's canonical form.
///
/// DESIGN LOCK, the one-writer rule: the SIGNET is the sole cutter. Only the signet SECRET can
/// produce a signature the signet verifies, so cutting a roster requires the secret (this `identity`), and
/// there is exactly ONE writer. SERVE (relaying an already-signed blob) needs only the bytes, so any member
/// node may courier a roster, but none may cut one. Multi-writer is rejected by rule: two signet-holding
/// devices cutting concurrently is not supported, which is what makes reconciliation trivial (highest epoch
/// wins, a total order, because one writer never reuses an epoch). Any feature that would need a second
/// writer (co-owned fleets, delegated cutting) is a new design, not a roster change.
pub fn cut(identity: &nauthy::Identity, doc: &RosterDoc) -> Vec<u8> {
    identity.sign_document(&doc.canonical_bytes()).encode()
}

/// Verify a wire blob against `signet` and parse the enclosed roster. The single VERIFY seam, so
/// verify-then-parse is one call and no caller can verify one blob but parse a different one: a forged or
/// foreign roster is refused HERE (`SignError`), before any member is read. Freshness (rejecting a stale
/// replay) is the caller's job on top of this, via the persisted epoch floor in
/// [`Contacts::hydrate`](crate::contacts::Contacts::hydrate).
pub fn verify(bytes: &[u8], signet: VerifyKey) -> Result<RosterDoc, RosterVerifyError> {
    // An empty read is its OWN condition, checked before the envelope decoder turns it into a signature
    // failure. A node that has cut nothing yet serves nothing, and telling its operator that their own
    // coordination node is serving an unverifiable blob sends them hunting a forgery that is not there.
    if bytes.is_empty() {
        return Err(RosterVerifyError::Empty);
    }
    let signed = Signed::decode(bytes)?;
    let payload = signed.verify(signet)?;
    Ok(RosterDoc::parse_canonical(payload)?)
}

/// Why a served roster blob could not be trusted: it failed the SIGNATURE seam (forged, foreign, or
/// truncated at the envelope) or the PAYLOAD parse (not a roster, or a malformed member list).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterVerifyError {
    /// The node served NO bytes: it has cut no roster yet. Distinct from a signature failure, because
    /// the fix is on the serving side (make one membership edit) and nothing is wrong with the key.
    #[error("the node served no roster")]
    Empty,
    /// The signed envelope did not verify: foreign signer, bad signature, or a truncated envelope.
    #[error("roster signature did not verify")]
    Signature(#[from] SignError),
    /// The verified payload was not a well-formed roster.
    #[error("roster payload is malformed")]
    Payload(#[from] FormatError),
}

#[cfg(test)]
#[path = "roster_tests.rs"]
mod roster_tests;
