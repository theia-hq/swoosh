//! Unit tests for the update payload, its canonical encoding, its bounds and the cut/verify seams.
//! Determinism (the signature depends only on logical content, never input order), a non-malleable wire
//! (a non-canonical order is rejected, not re-sorted), and the bounds are the load-bearing properties: a
//! signature over ambiguous bytes is a forgeable signature.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::str::FromStr as _;

use nauthy::{Link, RevocationId, SignError, VerifyKey};

use super::{
    ENVELOPE_LEN, Epoch, FormatError, HEADER_LEN, Id, MAX_BADGE, MAX_IDS, MAX_MEMBER_LEN,
    MAX_MEMBERS, MAX_REVOCATION_ID, MAX_REVOKED, MAX_REVOKED_KEYS, MAX_ROSTER_BLOB, Member,
    RosterDoc, RosterVerifyError,
};
use crate::contacts::DeviceLabel;
use crate::testkit::{TestNode, TestRoot};

/// The root every fixture here signs with.
const ROOT: u8 = 7;

/// A deterministic signing identity for the sign/verify tests.
fn identity(seed: u8) -> TestRoot {
    TestRoot::seeded(seed)
}

fn sample_doc() -> RosterDoc {
    RosterDoc::new(Epoch(9), vec![member(1, "desk"), member(2, "ci-runner")]).unwrap()
}

fn key(n: u8) -> VerifyKey {
    VerifyKey::new([n; 32])
}

fn member(node: u8, label: &str) -> Member {
    identity(ROOT)
        .member(key(node), DeviceLabel::from_str(label).unwrap())
        .unwrap()
}

fn id(byte: u8, len: usize) -> Id {
    Id {
        expires: u64::from(byte),
        id: RevocationId::from_bytes(vec![byte; len]),
    }
}

/// The offset of the first member's label length in a doc's canonical bytes.
const FIRST_LABEL: usize = HEADER_LEN + VerifyKey::LEN;

#[test]
fn canonical_bytes_are_order_independent() {
    // The same members handed in opposite orders must sign identically: `new` sorts by node bytes, so the
    // canonical encoding is a pure function of the SET, not the caller's insertion order.
    let (desk, phone) = (member(1, "desk"), member(2, "phone"));
    let forward = RosterDoc::new(Epoch(7), vec![desk.clone(), phone.clone()]).unwrap();
    let reversed = RosterDoc::new(Epoch(7), vec![phone, desk]).unwrap();
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
    let with = |edit: fn(&mut Member)| {
        let mut changed = member(1, "desk");
        edit(&mut changed);
        RosterDoc::new(Epoch(1), vec![changed]).unwrap()
    };
    let other_until = with(|m| m.until += 1);
    let other_duration = with(|m| m.duration += 1);
    let other_ids = with(|m| m.ids.push(id(1, 64)));
    let other_standing = with(|m| m.standing = identity(ROOT).standing(key(2)).unwrap());
    let revoked =
        RosterDoc::with_revocations(Epoch(1), vec![member(1, "desk")], vec![id(2, 64)], vec![])
            .unwrap();
    let revoked_key =
        RosterDoc::with_revocations(Epoch(1), vec![member(1, "desk")], vec![], vec![key(3)])
            .unwrap();

    let bytes = base.canonical_bytes();
    for other in [
        other_epoch,
        other_node,
        other_label,
        extra_member,
        other_until,
        other_duration,
        other_ids,
        other_standing,
        revoked,
        revoked_key,
    ] {
        assert_ne!(bytes, other.canonical_bytes());
    }
}

#[test]
fn canonical_bytes_are_domain_separated() {
    // The signed bytes lead with the roster magic, so this key's roster signature can never be replayed as
    // a signature over anything else it signs.
    let doc = RosterDoc::new(Epoch(1), vec![member(1, "desk")]).unwrap();
    assert!(doc.canonical_bytes().starts_with(b"swoosh-roster\x01"));
}

#[test]
fn parse_rejects_a_bad_label_byte_on_the_wire() {
    // A wire label carrying a control byte (which DeviceLabel forbids) is refused as a BadLabel, so a
    // smuggled newline can never reframe a later field in the signed bytes.
    let mut bytes = RosterDoc::new(Epoch(7), vec![member(1, "desk")])
        .unwrap()
        .canonical_bytes();
    bytes[FIRST_LABEL + 2 + 2] = b'\n';
    assert!(matches!(
        RosterDoc::parse_canonical(&bytes),
        Err(FormatError::BadLabel(_))
    ));
}

#[test]
fn new_rejects_a_duplicate_node() {
    let err = RosterDoc::new(Epoch(1), vec![member(3, "a"), member(3, "b")]).unwrap_err();
    assert_eq!(err, FormatError::DuplicateNode(key(3)));
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
    let blob = super::cut(id.identity(), &doc);
    assert_eq!(super::verify(&blob, id.verify_key()), Ok(doc));
}

#[test]
fn verify_rejects_a_foreign_signet() {
    let blob = super::cut(identity(7).identity(), &sample_doc());
    let stranger = identity(8).verify_key();
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
    let mut blob = super::cut(id.identity(), &sample_doc());
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    assert_eq!(
        super::verify(&blob, id.verify_key()),
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
        Err(FormatError::BadMagic)
    );
    let mut trailing = sample_doc().canonical_bytes();
    trailing.push(0);
    assert_eq!(
        RosterDoc::parse_canonical(&trailing),
        Err(FormatError::Truncated)
    );
    let bytes = sample_doc().canonical_bytes();
    assert_eq!(
        RosterDoc::parse_canonical(&bytes[..bytes.len() - 1]),
        Err(FormatError::Truncated)
    );
}

/// Two members' encodings, concatenated under a header that counts two: the wire a hostile courier could
/// build with any order it likes.
fn two_members_on_the_wire(first: &Member, second: &Member) -> Vec<u8> {
    let encode = |m: &Member| {
        let bytes = RosterDoc::new(Epoch(7), vec![m.clone()])
            .unwrap()
            .canonical_bytes();
        // The member alone: past the header, before the two empty revocation counts.
        bytes[HEADER_LEN..bytes.len() - 8].to_vec()
    };
    let mut bytes = RosterDoc::new(Epoch(7), vec![]).unwrap().canonical_bytes();
    bytes.truncate(HEADER_LEN);
    bytes[HEADER_LEN - 4..].copy_from_slice(&2u32.to_be_bytes());
    bytes.extend(encode(first));
    bytes.extend(encode(second));
    bytes.extend_from_slice(&[0; 8]);
    bytes
}

#[test]
fn parse_rejects_a_non_canonical_member_order() {
    // A blob whose members are not strictly-ascending-by-node is REJECTED, not silently re-sorted, so the
    // wire is non-malleable.
    let bytes = two_members_on_the_wire(&member(2, "phone"), &member(1, "desk"));
    assert_eq!(
        RosterDoc::parse_canonical(&bytes),
        Err(FormatError::NonCanonicalOrder)
    );
    let ascending = two_members_on_the_wire(&member(1, "desk"), &member(2, "phone"));
    assert!(RosterDoc::parse_canonical(&ascending).is_ok());
}

#[test]
fn parse_rejects_a_duplicate_node_on_the_wire() {
    // A repeated node is also non-ascending (equal is not strictly greater), so it is refused the same way.
    let bytes = two_members_on_the_wire(&member(3, "a"), &member(3, "b"));
    assert_eq!(
        RosterDoc::parse_canonical(&bytes),
        Err(FormatError::NonCanonicalOrder)
    );
}

#[test]
fn parse_rejects_a_non_canonical_id_order() {
    // Ids are a list like the members: one order on the wire, the ascending one.
    let doc =
        RosterDoc::with_revocations(Epoch(7), vec![], vec![id(1, 4), id(2, 4)], vec![]).unwrap();
    let mut bytes = doc.canonical_bytes();
    let first = HEADER_LEN + 4;
    let (a, b) = (first..first + 14, first + 14..first + 28);
    let swapped: Vec<u8> = [&bytes[b.clone()], &bytes[a.clone()]].concat();
    bytes[a.start..b.end].copy_from_slice(&swapped);
    assert_eq!(
        RosterDoc::parse_canonical(&bytes),
        Err(FormatError::NonCanonicalOrder)
    );
}

/// A signed label is read as stored: `Laptop` refuses rather than folding to `laptop`, so two byte-strings
/// can never decode to one doc and the signed wire stays one byte-string per doc.
#[test]
fn parse_rejects_a_capital_label() {
    let bytes = RosterDoc::new(Epoch(7), vec![member(1, "laptop")])
        .unwrap()
        .canonical_bytes();
    let parsed = RosterDoc::parse_canonical(&bytes).expect("the folded label parses");
    assert_eq!(parsed.canonical_bytes(), bytes, "one byte-string per doc");
    let mut capital = bytes;
    capital[FIRST_LABEL + 2] = b'L';
    assert!(
        matches!(
            RosterDoc::parse_canonical(&capital),
            Err(FormatError::BadLabel(_))
        ),
        "a capital label refuses on the wire"
    );
}

#[test]
fn parse_rejects_every_count_over_its_bound() {
    // Each count is refused before anything is allocated for it: a hostile courier cannot make a puller
    // reserve memory for a list it never sends.
    let empty = RosterDoc::new(Epoch(0), vec![]).unwrap().canonical_bytes();
    let over = |at: usize, count: usize| {
        let mut bytes = empty.clone();
        bytes[at..at + 4].copy_from_slice(&(count as u32).to_be_bytes());
        RosterDoc::parse_canonical(&bytes)
    };
    assert_eq!(
        over(HEADER_LEN - 4, MAX_MEMBERS + 1),
        Err(FormatError::TooLarge("members"))
    );
    assert_eq!(
        over(HEADER_LEN, MAX_REVOKED + 1),
        Err(FormatError::TooLarge("revoked ids"))
    );
    assert_eq!(
        over(HEADER_LEN + 4, MAX_REVOKED_KEYS + 1),
        Err(FormatError::TooLarge("revoked keys"))
    );
}

#[test]
fn a_member_over_a_field_bound_neither_builds_nor_parses() {
    let mut five_ids = member(1, "desk");
    five_ids.ids = (0..=MAX_IDS as u8).map(|n| id(n, 8)).collect();
    assert_eq!(
        RosterDoc::new(Epoch(1), vec![five_ids]).err(),
        Some(FormatError::TooLarge("ids"))
    );
    let mut long_id = member(1, "desk");
    long_id.ids = vec![id(1, MAX_REVOCATION_ID + 1)];
    assert_eq!(
        RosterDoc::new(Epoch(1), vec![long_id]).err(),
        Some(FormatError::TooLarge("revocation id"))
    );

    // On the wire: the id count byte of a one-member doc, raised past the bound.
    let mut bytes = RosterDoc::new(Epoch(1), vec![member(1, "desk")])
        .unwrap()
        .canonical_bytes();
    let id_count = FIRST_LABEL + 2 + "desk".len() + 16;
    bytes[id_count] = MAX_IDS as u8 + 1;
    assert_eq!(
        RosterDoc::parse_canonical(&bytes),
        Err(FormatError::TooLarge("ids"))
    );
}

#[test]
fn a_standing_that_is_not_a_bare_link_refuses() {
    // The standing's text is parsed as a link: a prefixed or damaged one never reaches a fold.
    let bytes = RosterDoc::new(Epoch(1), vec![member(1, "desk")])
        .unwrap()
        .canonical_bytes();
    let standing = FIRST_LABEL + 2 + "desk".len() + 16 + 1;
    let mut damaged = bytes.clone();
    let last = damaged.len() - 9;
    damaged[last] ^= 0x01;
    assert_eq!(
        RosterDoc::parse_canonical(&damaged),
        Err(FormatError::BadStanding)
    );
    let text = &bytes[standing + 2..bytes.len() - 8];
    let prefixed = [b"swoosh:".as_slice(), text].concat();
    let mut wire = bytes[..standing].to_vec();
    wire.extend_from_slice(&(prefixed.len() as u16).to_be_bytes());
    wire.extend_from_slice(&prefixed);
    wire.extend_from_slice(&[0; 8]);
    assert_eq!(
        RosterDoc::parse_canonical(&wire),
        Err(FormatError::BadStanding)
    );
}

/// A real sealed standing, from the same mint a root act uses for a device.
fn real_standing() -> Link {
    identity(ROOT)
        .device_badge(TestNode::seeded(1).node_id(), std::time::SystemTime::now())
        .unwrap()
}

#[test]
fn a_real_standing_fits_max_badge() {
    // Measured: a sealed standing is 664 bytes, 830 with 25% headroom, under MAX_BADGE (1024).
    let standing = real_standing();
    let len = standing.as_str().len();
    assert!(
        len * 5 / 4 <= MAX_BADGE,
        "a real standing of {len} bytes needs {} with headroom, over MAX_BADGE {MAX_BADGE}",
        len * 5 / 4
    );
}

#[test]
fn max_roster_blob_is_computed_from_the_bounds() {
    // The formula over the bounds, spelled out field by field.
    let id = 8 + 2 + MAX_REVOCATION_ID;
    let member = 32 + (2 + DeviceLabel::MAX_LEN) + 8 + 8 + 1 + MAX_IDS * id + (2 + MAX_BADGE);
    let payload = (b"swoosh-roster".len() + 1 + 8 + 4)
        + MAX_MEMBERS * member
        + (4 + MAX_REVOKED * id)
        + (4 + MAX_REVOKED_KEYS * 32);
    assert_eq!(MAX_ROSTER_BLOB, (32 + 64 + payload) as u64);
    assert_eq!(MAX_MEMBER_LEN, member);
}

/// The largest update the parser accepts but for its standings, which are real ones: [`MAX_MEMBERS`]
/// members, each name at [`DeviceLabel::MAX_LEN`] and [`MAX_IDS`] ids at [`MAX_REVOCATION_ID`], then
/// [`MAX_REVOKED`] ids and [`MAX_REVOKED_KEYS`] keys, signed into the envelope a courier serves.
fn maximal_blob(id: &TestRoot, standing: &Link) -> Vec<u8> {
    let index_key = |nth: usize| {
        let mut bytes = [0u8; VerifyKey::LEN];
        bytes[..4].copy_from_slice(&(nth as u32).to_be_bytes());
        bytes
    };
    let full_id = |nth: usize| {
        let mut bytes = vec![0xff; MAX_REVOCATION_ID];
        bytes[..4].copy_from_slice(&(nth as u32).to_be_bytes());
        Id {
            expires: u64::MAX,
            id: RevocationId::from_bytes(bytes),
        }
    };
    let members = (0..MAX_MEMBERS)
        .map(|nth| Member {
            node: VerifyKey::new(index_key(nth)),
            label: DeviceLabel::from_str(&"n".repeat(DeviceLabel::MAX_LEN)).unwrap(),
            until: u64::MAX,
            duration: u64::MAX,
            ids: (0..MAX_IDS).map(full_id).collect(),
            standing: standing.clone(),
        })
        .collect();
    let revoked = (0..MAX_REVOKED).map(full_id).collect();
    let keys = (0..MAX_REVOKED_KEYS)
        .map(|nth| VerifyKey::new(index_key(nth)))
        .collect();
    super::cut(
        id.identity(),
        &RosterDoc::with_revocations(Epoch(u64::MAX), members, revoked, keys).unwrap(),
    )
}

#[test]
fn the_largest_update_the_parser_accepts_is_exactly_the_blob_bound() {
    // The bound is computed, so this pins the computation to the wire it describes: an update at every
    // bound, in the envelope `cut` writes, is MAX_ROSTER_BLOB bytes less only what its real standings fall
    // short of MAX_BADGE. It also holds ENVELOPE_LEN, the one term nauthy keeps private.
    let id = identity(ROOT);
    let standing = real_standing();
    let blob = maximal_blob(&id, &standing);
    let short = MAX_MEMBERS * (MAX_BADGE - standing.as_str().len());
    assert_eq!(blob.len() + short, MAX_ROSTER_BLOB as usize);
    assert_eq!(ENVELOPE_LEN, 96);
    assert!(
        super::verify(&blob, id.verify_key()).is_ok(),
        "the largest update a reader accepts verifies and parses"
    );
}
