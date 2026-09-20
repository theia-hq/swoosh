//! Unit tests for the roster payload + its canonical encoding + the cut/verify seams. Determinism (the
//! signature depends only on logical content, never input order), a non-malleable wire (a non-canonical
//! member order is rejected, not re-sorted), and the parse-don't-validate label guard are the load-bearing
//! properties: a signature over ambiguous bytes is a forgeable signature.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::str::FromStr as _;

use nauthy::{Identity, SignError, VerifyKey};

use super::{
    Epoch, MAX_MEMBERS, MAX_ROSTER_BLOB, Member, RosterDoc, RosterError, RosterVerifyError,
};
use crate::contacts::DeviceLabel;

/// A deterministic signing identity for the sign/verify tests.
fn identity(seed: u8) -> Identity {
    Identity::from_secret(&[seed; 32]).unwrap()
}

fn sample_doc() -> RosterDoc {
    RosterDoc::new(Epoch(9), vec![member(1, "desk"), member(2, "ci-runner")]).unwrap()
}

fn key(n: u8) -> VerifyKey {
    VerifyKey::new([n; 32])
}

fn member(node: u8, label: &str) -> Member {
    Member {
        node: key(node),
        label: DeviceLabel::from_str(label).unwrap(),
    }
}

#[test]
fn canonical_bytes_are_order_independent() {
    // The same members handed in opposite orders must sign identically: `new` sorts by node bytes, so the
    // canonical encoding is a pure function of the SET, not the caller's insertion order.
    let forward = RosterDoc::new(Epoch(7), vec![member(1, "desk"), member(2, "phone")]).unwrap();
    let reversed = RosterDoc::new(Epoch(7), vec![member(2, "phone"), member(1, "desk")]).unwrap();
    assert_eq!(forward.canonical_bytes(), reversed.canonical_bytes());
    assert_eq!(forward, reversed);
}

#[test]
fn canonical_bytes_change_with_every_field() {
    let base = RosterDoc::new(Epoch(1), vec![member(1, "desk")]).unwrap();
    let other_epoch = RosterDoc::new(Epoch(2), vec![member(1, "desk")]).unwrap();
    let other_node = RosterDoc::new(Epoch(1), vec![member(9, "desk")]).unwrap();
    let other_label = RosterDoc::new(Epoch(1), vec![member(1, "phone")]).unwrap();
    let extra_member =
        RosterDoc::new(Epoch(1), vec![member(1, "desk"), member(2, "phone")]).unwrap();

    let bytes = base.canonical_bytes();
    assert_ne!(bytes, other_epoch.canonical_bytes());
    assert_ne!(bytes, other_node.canonical_bytes());
    assert_ne!(bytes, other_label.canonical_bytes());
    assert_ne!(bytes, extra_member.canonical_bytes());
}

#[test]
fn canonical_bytes_are_domain_separated() {
    // The signed bytes lead with the roster magic, so this key's roster signature can never be replayed as
    // a signature over anything else it signs.
    let doc = RosterDoc::new(Epoch(1), vec![member(1, "desk")]).unwrap();
    assert!(doc.canonical_bytes().starts_with(b"theia-roster\x01"));
}

#[test]
fn parse_rejects_a_bad_label_byte_on_the_wire() {
    // A wire label carrying a control byte (which DeviceLabel forbids) is refused as a BadLabel, so a
    // smuggled newline can never reframe a later field in the signed bytes.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"theia-roster\x01");
    bytes.extend_from_slice(&7u64.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&[1u8; 32]);
    let label = b"de\nsk";
    bytes.extend_from_slice(&(label.len() as u16).to_be_bytes());
    bytes.extend_from_slice(label);
    assert!(matches!(
        RosterDoc::parse_canonical(&bytes),
        Err(RosterError::BadLabel(_))
    ));
}

#[test]
fn new_rejects_a_duplicate_node() {
    let err = RosterDoc::new(Epoch(1), vec![member(3, "a"), member(3, "b")]).unwrap_err();
    assert_eq!(err, RosterError::DuplicateNode(key(3)));
}

#[test]
fn new_sorts_members_by_node() {
    let doc = RosterDoc::new(
        Epoch(1),
        vec![member(5, "e"), member(1, "a"), member(3, "c")],
    )
    .unwrap();
    let nodes: Vec<_> = doc.members().iter().map(|m| *m.node.bytes()).collect();
    assert_eq!(nodes, vec![[1u8; 32], [3u8; 32], [5u8; 32]]);
}

#[test]
fn a_cut_roster_verifies_against_its_signet() {
    // `cut` signs the doc's canonical bytes; `verify` against the same signet returns an equal doc, and only
    // through that verify path (a caller cannot get a trusted doc any other way).
    let id = identity(7);
    let doc = sample_doc();
    let blob = super::cut(&id, &doc);
    assert_eq!(super::verify(&blob, id.verifying_key()), Ok(doc));
}

#[test]
fn verify_rejects_a_foreign_signet() {
    let blob = super::cut(&identity(7), &sample_doc());
    let stranger = identity(8).verifying_key();
    assert_eq!(
        super::verify(&blob, stranger),
        Err(RosterVerifyError::Signature(SignError::ForeignSigner))
    );
}

#[test]
fn verify_rejects_a_tampered_payload() {
    // Flip a payload byte after signing: the envelope still decodes, but the signature no longer covers
    // these bytes, so verify fails at the signature seam before any parse.
    let id = identity(7);
    let mut blob = super::cut(&id, &sample_doc());
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    assert_eq!(
        super::verify(&blob, id.verifying_key()),
        Err(RosterVerifyError::Signature(SignError::BadSignature))
    );
}

#[test]
fn parse_round_trips_canonical_bytes() {
    let doc = sample_doc();
    let parsed = RosterDoc::parse_canonical(&doc.canonical_bytes()).unwrap();
    assert_eq!(parsed, doc);
}

#[test]
fn parse_rejects_bad_magic_and_trailing_bytes() {
    assert_eq!(
        RosterDoc::parse_canonical(b"not-a-roster-blob-here"),
        Err(RosterError::BadMagic)
    );
    let mut trailing = sample_doc().canonical_bytes();
    trailing.push(0);
    assert_eq!(
        RosterDoc::parse_canonical(&trailing),
        Err(RosterError::Truncated)
    );
    let bytes = sample_doc().canonical_bytes();
    assert_eq!(
        RosterDoc::parse_canonical(&bytes[..bytes.len() - 1]),
        Err(RosterError::Truncated)
    );
}

#[test]
fn parse_rejects_a_non_canonical_member_order() {
    // F2: a blob whose members are not strictly-ascending-by-node is REJECTED, not silently re-sorted, so
    // the wire is non-malleable. Hand-build a two-member payload with the nodes in descending order.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"theia-roster\x01");
    bytes.extend_from_slice(&7u64.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    for (node, label) in [(2u8, "phone"), (1u8, "desk")] {
        bytes.extend_from_slice(&[node; 32]);
        bytes.extend_from_slice(&(label.len() as u16).to_be_bytes());
        bytes.extend_from_slice(label.as_bytes());
    }
    assert_eq!(
        RosterDoc::parse_canonical(&bytes),
        Err(RosterError::NonCanonicalOrder)
    );
}

#[test]
fn parse_rejects_a_duplicate_node_on_the_wire() {
    // A repeated node is also non-ascending (equal is not strictly greater), so it is refused the same way.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"theia-roster\x01");
    bytes.extend_from_slice(&7u64.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    for label in ["a", "b"] {
        bytes.extend_from_slice(&[3u8; 32]);
        bytes.extend_from_slice(&(label.len() as u16).to_be_bytes());
        bytes.extend_from_slice(label.as_bytes());
    }
    assert_eq!(
        RosterDoc::parse_canonical(&bytes),
        Err(RosterError::NonCanonicalOrder)
    );
}

#[test]
fn parse_rejects_too_many_members() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"theia-roster\x01");
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&(u32::MAX).to_be_bytes());
    assert_eq!(
        RosterDoc::parse_canonical(&bytes),
        Err(RosterError::TooManyMembers)
    );
}

/// The largest roster the parser accepts, cut for real: [`MAX_MEMBERS`] members, each label at
/// [`DeviceLabel::MAX_LEN`], signed into the envelope a courier serves.
fn maximal_blob(id: &Identity) -> Vec<u8> {
    let members = (0..MAX_MEMBERS)
        .map(|nth| Member {
            // Distinct and non-colliding: the first two bytes carry the index, which MAX_MEMBERS fits.
            node: VerifyKey::new({
                let mut bytes = [0u8; VerifyKey::LEN];
                bytes[..2].copy_from_slice(&(nth as u16).to_be_bytes());
                bytes
            }),
            label: DeviceLabel::from_str(&"n".repeat(DeviceLabel::MAX_LEN)).unwrap(),
        })
        .collect();
    super::cut(id, &RosterDoc::new(Epoch(u64::MAX), members).unwrap())
}

#[test]
fn the_largest_roster_the_parser_accepts_is_exactly_the_blob_bound() {
    // The blob bound is DERIVED, so this pins the derivation to the wire it describes: a roster at every
    // field bound the parser enforces, in the envelope `cut` writes, is EXACTLY MAX_ROSTER_BLOB bytes. A
    // framing change the expression does not follow fails here rather than as a reader's cap that quietly
    // admits less, or more, than the parser does. It also holds the one term the derivation cannot name,
    // nauthy's private signature length: an envelope change over there lands on this assertion.
    let id = identity(7);
    let blob = maximal_blob(&id);
    assert_eq!(
        blob.len() as u64,
        MAX_ROSTER_BLOB,
        "a reader's cap derived from these bounds must be attainable to the byte"
    );
    // And the blob at the ceiling is one the whole seam takes: a cap that admits bytes the verifier
    // refuses would be a bound on nothing.
    assert!(
        super::verify(&blob, id.verifying_key()).is_ok(),
        "the largest blob a reader will accept is one that verifies and parses"
    );
}
