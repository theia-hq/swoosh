//! The membership snapshot an operator's signet vouches for: the payload of a signed roster.
//!
//! B1 (deliberation 28, D1) is bootstrap roster-sync: one member node serves the operator's fleet
//! membership to a fresh device, SIGNED by the signet so a courier that merely relays the blob cannot forge
//! it. This module is the payload and its canonical encoding; the SIGNING is nauthy's generic
//! [`sign_document`](nauthy::Identity::sign_document) / [`Signed`](nauthy::Signed) primitive, which roots a
//! blob at the same ed25519 key the signet mints caps with. The payload schema lives HERE, in swoosh, next
//! to the [`Contacts`](crate::contacts::Contacts) it is cut from and hydrated into: the whole roster story
//! (build a doc from contacts, canonicalize, sign, serve, verify, parse, fold) reads in one crate, and
//! nauthy carries only the generic verb, no fleet-directory concept.
//!
//! A member entry is (who, what the operator calls it) and NOTHING else: no last-seen (a pattern-of-life
//! oracle, delib-28 fix 1) and no capability (a roster that grants is a coordinator, delib-28 fix 2). Both
//! are TYPE properties here, unrepresentable rather than merely omitted. A member's label is a
//! [`DeviceLabel`], the SAME type local contacts use: one label type, no lossy seam to cross.

use nauthy::{SignError, Signed, VerifyKey};

use crate::contacts::DeviceLabel;

/// The domain-separating prefix over the signed bytes: a `MAGIC`-prefixed message this key signs can never
/// be confused with a cap or anything else it signs.
const MAGIC: &[u8] = b"theia-roster";

/// The canonical-encoding version, appended after [`MAGIC`]. Bump to force an old verifier to refuse
/// ([`RosterError::BadMagic`]) rather than misread a layout it does not know.
const VERSION: u8 = 1;

/// The maximum number of members [`RosterDoc::parse_canonical`] will parse from an untrusted blob. A DoS
/// bound: a personal fleet is tiny, and a hostile courier must not make a puller allocate for a huge count
/// before the signature is even checked.
const MAX_MEMBERS: usize = 4096;

/// Take `n` bytes from `bytes` at `*cur`, advancing the cursor, or [`RosterError::Truncated`] if the input
/// runs out. Bounds-checked so untrusted input is a clean error, never a panic. The fixed-width readers
/// ([`take_u64`], [`take_u32`], [`take_u16`], [`take_array`]) build on it.
fn take<'a>(bytes: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8], RosterError> {
    let end = cur.checked_add(n).ok_or(RosterError::Truncated)?;
    let slice = bytes.get(*cur..end).ok_or(RosterError::Truncated)?;
    *cur = end;
    Ok(slice)
}

/// Read a big-endian `u64` off the cursor. `take` already returns exactly 8 bytes, so the `try_into` is
/// infallible; it stays a clean error rather than an `expect`.
fn take_u64(bytes: &[u8], cur: &mut usize) -> Result<u64, RosterError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cur)?))
}

/// Read a big-endian `u32` off the cursor.
fn take_u32(bytes: &[u8], cur: &mut usize) -> Result<u32, RosterError> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, cur)?))
}

/// Read a big-endian `u16` off the cursor.
fn take_u16(bytes: &[u8], cur: &mut usize) -> Result<u16, RosterError> {
    Ok(u16::from_be_bytes(take_array::<2>(bytes, cur)?))
}

/// Read a fixed `N`-byte array off the cursor.
fn take_array<const N: usize>(bytes: &[u8], cur: &mut usize) -> Result<[u8; N], RosterError> {
    take(bytes, cur, N)?
        .try_into()
        .map_err(|_| RosterError::Truncated)
}

/// A monotonically-increasing version of an operator's roster, bumped each time the snapshot is re-cut (a
/// member added or removed). It orders two snapshots a device might see from two courier nodes: the higher
/// epoch is newer. It is NOT a timestamp (no wall clock, so no pattern-of-life leak) and NOT a per-member
/// field (no last-seen): it versions the WHOLE doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u64);

/// One member advertisement: a fleet node's identity and the operator's own label for it, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member node's identity: the key it is dialed at and its badge is bound to.
    pub node: VerifyKey,
    /// The operator's device label for this member (`ci-runner`, `desk`). A display/suggestion string, not
    /// authority: the puller keeps its OWN petnames (names are local). The same [`DeviceLabel`] local
    /// contacts use, so hydrating a member into contacts needs no re-parse.
    pub label: DeviceLabel,
}

/// The membership snapshot an operator's signet vouches for: a set of members at an epoch. This is the
/// payload that gets signed. Sorted and de-duplicated at construction so its canonical bytes are a pure
/// function of its logical content (two docs with the same members in any input order sign identically).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterDoc {
    epoch: Epoch,
    // invariant: sorted by node bytes, unique by node (upheld by `new`).
    members: Vec<Member>,
}

impl RosterDoc {
    /// Build a doc from an epoch and members. Sorts by `node` bytes and rejects a duplicate node (two labels
    /// for one key is operator error, not a merge case), so the stored order is canonical and
    /// [`canonical_bytes`](Self::canonical_bytes) is deterministic regardless of caller insertion order.
    pub fn new(epoch: Epoch, mut members: Vec<Member>) -> Result<Self, RosterError> {
        members.sort_by(|a, b| a.node.bytes().cmp(b.node.bytes()));
        if let Some(pair) = members.windows(2).find(|pair| pair[0].node == pair[1].node) {
            return Err(RosterError::DuplicateNode(pair[0].node));
        }
        Ok(Self { epoch, members })
    }

    /// The roster's epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The members, in canonical (node-sorted) order.
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The exact bytes that get signed and verified: a pure function of the doc's content, so the same
    /// logical doc yields the same bytes yields the same signature. Fixed field order, fixed-width keys,
    /// sorted members, and a length prefix on the only variable field (the label) mean no delimiter can be
    /// spoofed and no insertion order can change the signature. The wire LAYOUT (shared by the parser):
    ///
    /// ```text
    /// wire layout (all ints big-endian), a pure function of doc content:
    ///   MAGIC          b"theia-roster"
    ///   VERSION        u8
    ///   epoch          u64
    ///   count          u32                (<= MAX_MEMBERS on parse)
    ///   per member x count, ascending by node:
    ///     node         [u8; 32]
    ///     label_len    u16                (<= DeviceLabel::MAX_LEN)
    ///     label        [u8; label_len]    (UTF-8, no slash/whitespace/control)
    /// ```
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAGIC.len() + 13 + self.members.len() * 40);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        // A fleet is small; the count never approaches u32::MAX, and the cast is deterministic.
        out.extend_from_slice(&(self.members.len() as u32).to_be_bytes());
        for member in &self.members {
            out.extend_from_slice(member.node.bytes());
            let label = member.label.as_str().as_bytes();
            // DeviceLabel bounds the length to MAX_LEN (< u16::MAX), so this cast never truncates.
            out.extend_from_slice(&(label.len() as u16).to_be_bytes());
            out.extend_from_slice(label);
        }
        out
    }

    /// Parse canonical bytes back into a doc. The inverse of [`canonical_bytes`](Self::canonical_bytes) over
    /// the layout table documented there, bounds-checked so untrusted input is a clean error. The whole blob
    /// must be consumed (no trailing bytes) and the member list must already be strictly-ascending-by-node:
    /// a non-canonical or duplicate order is REJECTED, not silently re-sorted, so the wire is non-malleable
    /// (one byte-string per doc).
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, RosterError> {
        let mut cur = 0;
        if take(bytes, &mut cur, MAGIC.len())? != MAGIC
            || take_array::<1>(bytes, &mut cur)?[0] != VERSION
        {
            return Err(RosterError::BadMagic);
        }
        let epoch = Epoch(take_u64(bytes, &mut cur)?);
        let count = take_u32(bytes, &mut cur)? as usize;
        if count > MAX_MEMBERS {
            return Err(RosterError::TooManyMembers);
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let node = VerifyKey::new(take_array::<{ VerifyKey::LEN }>(bytes, &mut cur)?);
            let label_len = usize::from(take_u16(bytes, &mut cur)?);
            let text = core::str::from_utf8(take(bytes, &mut cur, label_len)?)
                .map_err(|_| RosterError::BadLabel("not valid UTF-8"))?;
            let label = text.parse::<DeviceLabel>().map_err(|_| {
                RosterError::BadLabel("empty, too long, or held a slash/whitespace/control byte")
            })?;
            // Reject rather than re-sort: the members must arrive strictly-ascending-by-node, so a permuted
            // or duplicated wire (which would decode to the same logical doc under a re-sort) is refused and
            // the wire stays canonical, one byte-string per doc. `new`'s sort is the CUT-side canonicalizer;
            // the parse side proves the bytes were already canonical.
            if members
                .last()
                .is_some_and(|previous: &Member| node.bytes() <= previous.node.bytes())
            {
                return Err(RosterError::NonCanonicalOrder);
            }
            members.push(Member { node, label });
        }
        if cur != bytes.len() {
            return Err(RosterError::Truncated);
        }
        // The strict-ascending check above already proved sort + uniqueness, so `new` re-derives the same
        // (canonical) doc without a second reordering.
        Self::new(epoch, members)
    }
}

/// Cut a fresh signed roster: canonicalize `doc` and sign it with the signet `identity`, yielding the wire
/// blob a `roster:` handler serves. The single CUT seam, so the canonicalize-then-sign pair is one call and
/// a caller cannot sign bytes that are not this doc's canonical form.
///
/// DESIGN LOCK (delib-28, the one-writer rule): the SIGNET is the sole cutter. Only the signet SECRET can
/// produce a signature the signet verifies, so cutting a roster requires the secret (this `identity`), and
/// there is exactly ONE writer. SERVE (relaying an already-signed blob) needs only the bytes, so any member
/// node may courier a roster, but none may cut one. Multi-writer is rejected by rule: two signet-holding
/// devices cutting concurrently is not supported, which is what makes reconciliation trivial (highest epoch
/// wins, a total order, because one writer never reuses an epoch). Any feature that would need a second
/// writer (co-owned fleets, delegated cutting) is a new deliberation, not a roster change.
pub fn cut(identity: &nauthy::Identity, doc: &RosterDoc) -> Vec<u8> {
    identity.sign_document(&doc.canonical_bytes()).encode()
}

/// Verify a wire blob against `signet` and parse the enclosed roster. The single VERIFY seam, so
/// verify-then-parse is one call and no caller can verify one blob but parse a different one: a forged or
/// foreign roster is refused HERE (`SignError`), before any member is read. Freshness (rejecting a stale
/// replay) is the caller's job on top of this, via the persisted epoch floor in
/// [`Contacts::hydrate`](crate::contacts::Contacts::hydrate).
pub fn verify(bytes: &[u8], signet: VerifyKey) -> Result<RosterDoc, RosterVerifyError> {
    let signed = Signed::decode(bytes)?;
    let payload = signed.verify(signet)?;
    Ok(RosterDoc::parse_canonical(payload)?)
}

/// Why a served roster blob could not be trusted: it failed the SIGNATURE seam (forged, foreign, or
/// truncated at the envelope) or the PAYLOAD parse (not a roster, or a malformed member list).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterVerifyError {
    /// The signed envelope did not verify: foreign signer, bad signature, or a truncated envelope.
    #[error("roster signature did not verify")]
    Signature(#[from] SignError),
    /// The verified payload was not a well-formed roster.
    #[error("roster payload is malformed")]
    Payload(#[from] RosterError),
}

/// Why a roster could not be built or parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterError {
    /// A member label was not a valid device label (empty, too long, or held a slash/whitespace/control
    /// byte, or was not valid UTF-8). One variant carrying the reason: a caller never branches on WHICH
    /// label rule failed, only that one did.
    #[error("invalid roster label: {0}")]
    BadLabel(&'static str),
    /// Two members shared one node identity.
    #[error("roster lists node {0} twice")]
    DuplicateNode(VerifyKey),
    /// The members were not strictly ascending by node on the wire (a non-canonical or duplicate order).
    #[error("roster members are not in canonical order")]
    NonCanonicalOrder,
    /// The blob's leading magic or version did not match: not a roster, or a version this build does not
    /// know.
    #[error("not a roster (bad magic or version)")]
    BadMagic,
    /// The blob ended before a field was complete, or carried trailing bytes.
    #[error("roster blob is truncated or malformed")]
    Truncated,
    /// The blob claimed more members than the parse bound allows.
    #[error("roster lists too many members")]
    TooManyMembers,
}

#[cfg(test)]
#[path = "roster_tests.rs"]
mod roster_tests;
