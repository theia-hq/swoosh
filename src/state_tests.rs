//! Unit tests for `state`: its codec, its magic against the update's, and the atomic write.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::str::FromStr as _;
use std::io;
use std::path::{Path, PathBuf};

use nauthy::{RevocationId, VerifyKey};

use super::{
    Disk, FILE, MAX_ROWS, RealDisk, Row, STAGED, State, StateError, read, read_with, sign, verify,
    write, write_with,
};
use crate::codec::{FormatError, Id};
use crate::contacts::DeviceLabel;
use crate::roster::{self, Epoch, RosterDoc};
use crate::testkit::TestRoot;

const ROOT: u8 = 7;

fn root() -> TestRoot {
    TestRoot::seeded(ROOT)
}

fn key(n: u8) -> VerifyKey {
    VerifyKey::new([n; 32])
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
fn a_state_round_trips_through_sign_and_verify() {
    let state = sample(4);
    let signed = sign(root().identity(), &state);
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
    let header = super::MAGIC.len() + 1 + 8 + 4;
    let first_row = State::new(Epoch(1), vec![row(1, "desk")], vec![], vec![])
        .unwrap()
        .canonical_bytes()
        .len()
        - header
        - 8;
    let dusk = header + first_row + 32 + 2;
    assert_eq!(&bytes[dusk..dusk + 4], b"dusk");
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
        let update = roster::cut(root.identity(), &update);
        let state = sign(root.identity(), &state.unwrap());
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

/// A disk that fails its `fail_at`th call, and tears a write it fails: half the bytes land.
struct Faulty {
    calls: usize,
    fail_at: usize,
}

impl Disk for Faulty {
    fn write(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        if self.fault() {
            std::fs::write(path, &bytes[..bytes.len() / 2])?;
            return Err(io::Error::other("fault"));
        }
        RealDisk.write(path, bytes)
    }

    fn sync(&mut self, path: &Path) -> io::Result<()> {
        if self.fault() {
            return Err(io::Error::other("fault"));
        }
        RealDisk.sync(path)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        if self.fault() {
            return Err(io::Error::other("fault"));
        }
        RealDisk.rename(from, to)
    }
}

impl Faulty {
    fn fault(&mut self) -> bool {
        let now = self.calls;
        self.calls += 1;
        now == self.fail_at
    }
}

#[test]
fn a_torn_write_leaves_one_consistent_state() {
    // Replace one valid `state` with another, failing each call of the write in turn. Whatever call
    // fails, the next read finds the old records or the new ones, and then `state` alone holds them.
    let root = root();
    let old = sample(1);
    let new = sample(2);
    let signed = sign(root.identity(), &new);
    for fail_at in 0.. {
        let dir = dir(&format!("torn-{fail_at}"));
        write(&dir, &sign(root.identity(), &old)).unwrap();
        let mut disk = Faulty { calls: 0, fail_at };
        let done = write_with(&mut disk, &dir, &signed).is_ok();
        let read_back = read(&dir, root.verify_key()).expect("one valid state survives");
        assert!(
            read_back == old || read_back == new,
            "a fault at call {fail_at} left neither"
        );
        let on_disk = std::fs::read(dir.join(FILE)).unwrap();
        assert_eq!(verify(&on_disk, root.verify_key()), Ok(read_back));
        std::fs::remove_dir_all(&dir).unwrap();
        if done {
            // write, sync, rename, sync the directory: each failed once before this clean run.
            assert_eq!(fail_at, 4, "every call of the write was failed once");
            break;
        }
    }
}

#[test]
fn a_valid_staged_state_is_promoted_when_state_is_not() {
    let root = root();
    let dir = dir("promote");
    let staged = sample(5);
    std::fs::write(dir.join(STAGED), sign(root.identity(), &staged)).unwrap();
    std::fs::write(dir.join(FILE), b"torn").unwrap();
    assert_eq!(read(&dir, root.verify_key()).unwrap(), staged);
    assert!(
        !dir.join(STAGED).exists(),
        "state.new was renamed over state"
    );
    assert_eq!(read(&dir, root.verify_key()).unwrap(), staged);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_valid_state_wins_over_a_staged_one() {
    let root = root();
    let dir = dir("wins");
    let current = sample(1);
    write(&dir, &sign(root.identity(), &current)).unwrap();
    std::fs::write(dir.join(STAGED), sign(root.identity(), &sample(2))).unwrap();
    assert_eq!(read(&dir, root.verify_key()).unwrap(), current);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn no_valid_state_refuses_as_damaged_naming_restore() {
    let root = root();
    let dir = dir("damaged");
    std::fs::write(dir.join(FILE), b"torn").unwrap();
    // Signed by another root: it verifies under nothing this home trusts.
    std::fs::write(
        dir.join(STAGED),
        sign(TestRoot::seeded(8).identity(), &sample(1)),
    )
    .unwrap();
    let error = read_with(&mut RealDisk, &dir, root.verify_key()).unwrap_err();
    assert!(matches!(error, StateError::Damaged { .. }));
    assert!(error.to_string().contains("swoosh restore"));
    std::fs::remove_dir_all(&dir).unwrap();
}
