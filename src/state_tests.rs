//! Unit tests for `state`: its codec, its magic against the update's, and the atomic write.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::str::FromStr as _;
use std::path::{Path, PathBuf};

use nauthy::{RevocationId, VerifyKey};

use super::{FILE, MAX_ROWS, Row, State, StateError, load, verify, write};
use crate::codec::{FormatError, Id};
use crate::contacts::DeviceLabel;
use crate::roster::{self, Epoch, RosterDoc};
use crate::testkit::{TestNode, TestRoot};

const ROOT: u8 = 7;

fn root() -> TestRoot {
    TestRoot::seeded(ROOT)
}

fn key(n: u8) -> VerifyKey {
    TestNode::seeded(n).verify_key()
}

fn row(n: u8, label: &str) -> Row {
    Row {
        key: key(n),
        label: DeviceLabel::from_str(label).unwrap(),
        until: 100,
        duration: 90 * 86_400,
        seeded: true,
        invite_until: 50,
        revoked_on: 0,
        ids: vec![Id {
            expires: 100,
            id: RevocationId::from_bytes(vec![n; 64]),
        }],
        standing: root().standing(key(n)).unwrap(),
    }
}

fn sample(last_update: u64) -> State {
    let mut gone = row(3, "desk");
    gone.revoked_on = 40;
    State::new(
        Epoch(last_update),
        vec![row(1, "desk"), row(2, "laptop"), gone],
        vec![Id {
            expires: 90,
            id: RevocationId::from_bytes(vec![9; 64]),
        }],
        vec![key(3)],
    )
    .unwrap()
}

/// A fresh directory for one test.
fn dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("swoosh-state-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_state_round_trips_through_its_signature_and_verify() {
    let state = sample(4);
    let signed = root().sign_state(&state);
    assert_eq!(verify(&signed, root().verify_key()), Ok(state));
}

#[test]
fn state_rows_are_unique_by_key_and_by_live_name() {
    assert_eq!(
        State::new(
            Epoch(1),
            vec![row(1, "desk"), row(1, "laptop")],
            vec![],
            vec![]
        )
        .err(),
        Some(FormatError::DuplicateNode(key(1)))
    );
    let desk = DeviceLabel::from_str("desk").unwrap();
    assert_eq!(
        State::new(
            Epoch(1),
            vec![row(1, "desk"), row(2, "desk")],
            vec![],
            vec![]
        )
        .err(),
        Some(FormatError::DuplicateLabel(desk.clone()))
    );
    // On the wire too: the second row's name rewritten to the first's.
    let bytes = State::new(
        Epoch(1),
        vec![row(1, "desk"), row(2, "dusk")],
        vec![],
        vec![],
    )
    .unwrap()
    .canonical_bytes();
    let dusk = bytes
        .windows(4)
        .position(|window| window == b"dusk")
        .expect("the second name is on the wire");
    let mut twice = bytes.clone();
    twice[dusk..dusk + 4].copy_from_slice(b"desk");
    assert_eq!(
        State::parse_canonical(&twice),
        Err(FormatError::DuplicateLabel(desk))
    );
}

#[test]
fn state_refuses_rows_over_its_bound() {
    let mut bytes = State::new(Epoch(1), vec![], vec![], vec![])
        .unwrap()
        .canonical_bytes();
    let count = super::MAGIC.len() + 1 + 8;
    bytes[count..count + 4].copy_from_slice(&(MAX_ROWS as u32 + 1).to_be_bytes());
    assert_eq!(
        State::parse_canonical(&bytes),
        Err(FormatError::TooLarge("rows"))
    );
}

#[test]
fn a_seeded_flag_other_than_zero_or_one_refuses() {
    let bytes = State::new(Epoch(1), vec![row(1, "desk")], vec![], vec![])
        .unwrap()
        .canonical_bytes();
    let seeded = super::MAGIC.len() + 1 + 8 + 4 + 32 + 2 + "desk".len() + 16;
    assert_eq!(bytes[seeded], 1);
    let mut two = bytes;
    two[seeded] = 2;
    assert_eq!(State::parse_canonical(&two), Err(FormatError::BadFlag));
}

#[test]
fn root_documents_never_parse_as_each_other() {
    // An update and a `state`, signed by one root, each fail the other's parser: empty ones included,
    // whose layouts after the magic are the same bytes.
    let root = root();
    for (update, state) in [
        (
            RosterDoc::new(Epoch(0), vec![]).unwrap(),
            State::new(Epoch(0), vec![], vec![], vec![]),
        ),
        (
            RosterDoc::new(
                Epoch(3),
                vec![
                    root.member(key(1), DeviceLabel::from_str("desk").unwrap())
                        .unwrap(),
                ],
            )
            .unwrap(),
            Ok(sample(3)),
        ),
    ] {
        let update = root.sign_update(&update);
        let state = root.sign_state(&state.unwrap());
        assert!(matches!(
            verify(&update, root.verify_key()),
            Err(super::StateVerifyError::Payload(FormatError::BadMagic))
        ));
        assert!(matches!(
            roster::verify(&state, root.verify_key()),
            Err(roster::RosterVerifyError::Payload(FormatError::BadMagic))
        ));
    }
}

#[test]
fn a_magic_is_compared_by_its_own_length() {
    // Both magics are shorter than any fixed width, and neither is a prefix of the other.
    assert!(!roster::MAGIC.starts_with(super::MAGIC) && !super::MAGIC.starts_with(roster::MAGIC));
    let update = RosterDoc::new(Epoch(1), vec![]).unwrap().canonical_bytes();
    let state = sample(1).canonical_bytes();
    assert!(RosterDoc::parse_canonical(&update).is_ok());
    assert!(State::parse_canonical(&state).is_ok());
    for at in 0..roster::MAGIC.len() {
        let mut changed = update.clone();
        changed[at] ^= 0x20;
        assert_eq!(
            RosterDoc::parse_canonical(&changed),
            Err(FormatError::BadMagic),
            "byte {at} of the update's magic"
        );
    }
    for at in 0..super::MAGIC.len() {
        let mut changed = state.clone();
        changed[at] ^= 0x20;
        assert_eq!(
            State::parse_canonical(&changed),
            Err(FormatError::BadMagic),
            "byte {at} of the state's magic"
        );
    }
}

#[test]
fn no_valid_state_refuses_as_changed_outside_swoosh() {
    let root = root();
    let dir = dir("damaged");
    std::fs::write(dir.join(FILE), b"torn").unwrap();
    let error = load(&dir, root.verify_key()).unwrap_err();
    assert!(matches!(error, StateError::Damaged { .. }));
    // Signed by another root: it verifies under nothing this home trusts.
    std::fs::write(dir.join(FILE), TestRoot::seeded(8).sign_state(&sample(1))).unwrap();
    let error = load(&dir, root.verify_key()).unwrap_err();
    assert!(matches!(error, StateError::Damaged { .. }));
    assert!(error.to_string().contains("changed outside swoosh"));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `sample`'s bytes with the revoked row's `revoked_on` (set to a marker) zeroed: a live row whose key is
/// still a revoked key.
fn revived(mut state_rows: Vec<Row>, revoked_keys: Vec<VerifyKey>) -> Vec<u8> {
    const MARKER: u64 = 0x5eed_0f0f_f1ce_0000;
    for row in &mut state_rows {
        if row.is_revoked() {
            row.revoked_on = MARKER;
        }
    }
    let mut bytes = State::new(Epoch(1), state_rows, vec![], revoked_keys)
        .unwrap()
        .canonical_bytes();
    let at = bytes
        .windows(8)
        .position(|window| window == MARKER.to_be_bytes())
        .unwrap();
    bytes[at..at + 8].fill(0);
    bytes
}

#[test]
fn a_row_is_revoked_exactly_when_its_key_is() {
    let mut gone = row(3, "desk");
    gone.revoked_on = 40;
    // A revoked row whose key is not a revoked key.
    assert_eq!(
        State::new(Epoch(1), vec![row(1, "desk"), gone.clone()], vec![], vec![]).err(),
        Some(FormatError::RevokedMismatch(key(3)))
    );
    // A live row whose key is a revoked key.
    assert_eq!(
        State::new(Epoch(1), vec![row(1, "desk")], vec![], vec![key(1)]).err(),
        Some(FormatError::RevokedMismatch(key(1)))
    );
    // A revoked key with no row is kept.
    assert!(State::new(Epoch(1), vec![row(1, "desk")], vec![], vec![key(9)]).is_ok());
    // On the wire: the revoked row made live again.
    assert_eq!(
        State::parse_canonical(&revived(vec![row(1, "laptop"), gone], vec![key(3)])),
        Err(FormatError::RevokedMismatch(key(3)))
    );
}

#[test]
fn state_holds_at_most_max_members_live_rows() {
    let standing = row(1, "desk").standing;
    let live = |n: usize| Row {
        key: TestNode::from_seed(core::array::from_fn(|at| (n >> (8 * (at % 2))) as u8))
            .verify_key(),
        label: DeviceLabel::from_str(&format!("d{n}")).unwrap(),
        ids: vec![],
        standing: standing.clone(),
        ..row(1, "desk")
    };
    let rows: Vec<Row> = (0..=crate::codec::MAX_MEMBERS).map(live).collect();
    assert_eq!(
        State::new(Epoch(1), rows.clone(), vec![], vec![]).err(),
        Some(FormatError::TooLarge("live rows"))
    );
    // On the wire: MAX_MEMBERS live rows and one revoked, made live again.
    let mut rows = rows;
    let last = rows.last_mut().unwrap();
    last.revoked_on = 1;
    let revoked = vec![last.key];
    assert_eq!(
        State::parse_canonical(&revived(rows, revoked)),
        Err(FormatError::TooLarge("live rows"))
    );
}

#[cfg(unix)]
#[test]
fn state_is_written_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = root();
    let state = sample(1);
    let signed = root.sign_state(&state);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

    let dir = dir("owner-only");
    write(&crate::testkit::lock(), &dir, &signed).unwrap();
    assert_eq!(mode(&dir.join(FILE)), 0o600);

    assert_eq!(
        verify(&std::fs::read(dir.join(FILE)).unwrap(), root.verify_key()),
        Ok(state)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
