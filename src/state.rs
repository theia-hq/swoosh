//! `state`: the root's own signed records, kept beside its key.
//!
//! One file of [`nauthy::Signed`] bytes from [`sign_document`](nauthy::Identity::sign_document), whose
//! payload opens with [`MAGIC`] and a version byte. It holds every device row the root has signed, revoked
//! ones included, and what only the root needs (`seeded`, `invite_until`, `revoked_on`), so it is never
//! served. A payload under another magic (an update the same root signed) is refused.
//!
//! [`write`] replaces the file atomically through an owner-only `state.new`. [`load`] takes a valid
//! `state`, else a valid `state.new`, else refuses as damaged, and renames nothing; [`recover`] does the
//! same and promotes the `state.new` it took, so only a holder of the root's lock calls it.

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use nauthy::{Link, SignError, Signed, VerifyKey};

use crate::codec::{
    FormatError, Id, MAX_MEMBERS, MAX_REVOKED, MAX_REVOKED_KEYS, Put as _, Reader, bound,
    canonicalize, check_device, check_ids, unique_labels,
};
use crate::contacts::DeviceLabel;
use crate::roster::{ENVELOPE_LEN, Epoch, MAX_ID_LEN, MAX_MEMBER_LEN};

/// The magic the payload opens with: `swoosh-` and the file it heads.
pub(crate) const MAGIC: &[u8] = b"swoosh-state";

/// The layout version, after [`MAGIC`].
const VERSION: u8 = 1;

/// The file name.
pub const FILE: &str = "state";

/// The staged file a write goes through.
pub const STAGED: &str = "state.new";

/// The most rows `state` holds: every live device and every revoked one, whose keys are kept for good.
pub const MAX_ROWS: usize = MAX_MEMBERS + MAX_REVOKED_KEYS;

/// One row at every bound: a member's fields, then `seeded`, `invite_until` and `revoked_on`.
const MAX_ROW_LEN: usize = MAX_MEMBER_LEN + 1 + 8 + 8;

/// The largest signed `state` a read admits, in bytes: the envelope around the biggest payload
/// [`State::parse_canonical`] accepts, computed from the bounds like
/// [`MAX_ROSTER_BLOB`](crate::roster::MAX_ROSTER_BLOB). A longer file is not read.
pub const MAX_STATE_BLOB: u64 = (ENVELOPE_LEN
    + MAGIC.len()
    + 1
    + 8
    + 4
    + MAX_ROWS * MAX_ROW_LEN
    + 4
    + MAX_REVOKED * MAX_ID_LEN
    + 4
    + MAX_REVOKED_KEYS * VerifyKey::LEN) as u64;

/// One device the root has signed for.
#[derive(Debug, Clone)]
pub struct Row {
    /// The device's key.
    pub key: VerifyKey,
    /// Its name, stored without `me/`.
    pub label: DeviceLabel,
    /// When its standing ends, in unix seconds.
    pub until: u64,
    /// How long each renewal runs, in seconds; 0 means never renewed on its own.
    pub duration: u64,
    /// Whether the root handed this device its key (an invite that carries one).
    pub seeded: bool,
    /// The end of the standing in the last invite that carried a key for this row, 0 if none.
    pub invite_until: u64,
    /// When it was revoked, in unix seconds; 0 means not revoked.
    pub revoked_on: u64,
    /// The ids of its live standings, at most [`MAX_IDS`](crate::codec::MAX_IDS).
    pub ids: Vec<Id>,
    /// The newest standing signed for it, bare.
    pub standing: Link,
}

impl Row {
    /// Whether this row is revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_on != 0
    }
}

impl PartialEq for Row {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
            && self.label == other.label
            && self.until == other.until
            && self.duration == other.duration
            && self.seeded == other.seeded
            && self.invite_until == other.invite_until
            && self.revoked_on == other.revoked_on
            && self.ids == other.ids
            && self.standing.as_str() == other.standing.as_str()
    }
}

impl Eq for Row {}

/// The root's records. Canonical at construction: rows sorted and unique by key, at most
/// [`MAX_MEMBERS`] rows that are not revoked and at most one per name, a row revoked exactly when its key
/// is a revoked key, every list sorted and every bound held, so every `State` that builds also parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    last_update: Epoch,
    // invariant: every list sorted and unique, every bound held (upheld by `new`).
    rows: Vec<Row>,
    revoked: Vec<Id>,
    revoked_keys: Vec<VerifyKey>,
}

impl State {
    /// The records: the last update cut (`Epoch(0)` for none), the rows, the revoked ids and the revoked
    /// keys. Sorts every list, and refuses a repeated key, a name two live rows share, a row revoked in
    /// one list and not the other, and anything over its bound.
    pub fn new(
        last_update: Epoch,
        mut rows: Vec<Row>,
        mut revoked: Vec<Id>,
        mut revoked_keys: Vec<VerifyKey>,
    ) -> Result<Self, FormatError> {
        bound(rows.len(), MAX_ROWS, "rows")?;
        bound(revoked.len(), MAX_REVOKED, "revoked ids")?;
        bound(revoked_keys.len(), MAX_REVOKED_KEYS, "revoked keys")?;
        for row in &mut rows {
            check_device(&mut row.ids, &row.standing)?;
        }
        rows.sort_by(|a, b| a.key.bytes().cmp(b.key.bytes()));
        if let Some(pair) = rows.windows(2).find(|pair| pair[0].key == pair[1].key) {
            return Err(FormatError::DuplicateNode(pair[0].key));
        }
        check_ids(&mut revoked)?;
        canonicalize(&mut revoked_keys, |key| *key.bytes())?;
        check_rows(&rows, &revoked_keys)?;
        Ok(Self {
            last_update,
            rows,
            revoked,
            revoked_keys,
        })
    }

    /// The last update cut from these records; `Epoch(0)` means none yet.
    pub fn last_update(&self) -> Epoch {
        self.last_update
    }

    /// Every row, sorted by key.
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The revoked ids, sorted.
    pub fn revoked(&self) -> &[Id] {
        &self.revoked
    }

    /// The revoked device keys, sorted.
    pub fn revoked_keys(&self) -> &[VerifyKey] {
        &self.revoked_keys
    }

    /// The bytes that get signed:
    ///
    /// ```text
    /// all ints big-endian
    ///   MAGIC              b"swoosh-state"
    ///   VERSION            u8 (1)
    ///   last_update        u64
    ///   device_count       u32                     (<= MAX_ROWS)
    ///   per row, ascending by key:
    ///     key              [u8; 32]
    ///     label            u16 length, bytes
    ///     until            u64
    ///     duration         u64
    ///     seeded           u8 (0 or 1)
    ///     invite_until     u64
    ///     revoked_on       u64
    ///     id_count         u8                      (<= MAX_IDS), then each id: expires u64, u16 length, bytes
    ///     standing         u16 length, bare link   (<= MAX_BADGE)
    ///   revoked_count      u32                     (<= MAX_REVOKED), then each id
    ///   revoked_key_count  u32                     (<= MAX_REVOKED_KEYS), then each key, 32 bytes
    /// ```
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.put_u8(VERSION);
        out.put_u64(self.last_update.0);
        out.put_u32(self.rows.len());
        for row in &self.rows {
            out.extend_from_slice(row.key.bytes());
            out.put_bytes16(row.label.as_str().as_bytes());
            out.put_u64(row.until);
            out.put_u64(row.duration);
            out.put_u8(u8::from(row.seeded));
            out.put_u64(row.invite_until);
            out.put_u64(row.revoked_on);
            out.put_u8(row.ids.len() as u8);
            for id in &row.ids {
                out.put_id(id);
            }
            out.put_bytes16(row.standing.as_str().as_bytes());
        }
        out.put_ids32(&self.revoked);
        out.put_keys32(&self.revoked_keys);
        out
    }

    /// Parse the bytes [`canonical_bytes`](Self::canonical_bytes) writes, and nothing else: every list
    /// strictly ascending, every bound held, every byte consumed.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut reader = Reader::open(bytes, MAGIC, VERSION)?;
        let last_update = Epoch(reader.u64()?);
        let count = reader.count32(MAX_ROWS, "rows")?;
        let mut rows: Vec<Row> = Vec::with_capacity(count);
        for _ in 0..count {
            let key = reader.key()?;
            if rows
                .last()
                .is_some_and(|previous| key.bytes() <= previous.key.bytes())
            {
                return Err(FormatError::NonCanonicalOrder);
            }
            rows.push(Row {
                key,
                label: reader.label()?,
                until: reader.u64()?,
                duration: reader.u64()?,
                seeded: reader.flag()?,
                invite_until: reader.u64()?,
                revoked_on: reader.u64()?,
                ids: reader.device_ids()?,
                standing: reader.standing()?,
            });
        }
        let revoked = reader.revoked()?;
        let revoked_keys = reader.revoked_keys()?;
        reader.finish()?;
        check_rows(&rows, &revoked_keys)?;
        Ok(Self {
            last_update,
            rows,
            revoked,
            revoked_keys,
        })
    }
}

/// Refuse more than [`MAX_MEMBERS`] live rows, two live rows under one name, and a row revoked in one
/// list and not the other (`revoked_keys` sorted). A revoked key may have no row.
fn check_rows(rows: &[Row], revoked_keys: &[VerifyKey]) -> Result<(), FormatError> {
    let live = || rows.iter().filter(|row| !row.is_revoked());
    bound(live().count(), MAX_MEMBERS, "live rows")?;
    for row in rows {
        let key_revoked = revoked_keys
            .binary_search_by(|key| key.bytes().cmp(row.key.bytes()))
            .is_ok();
        if key_revoked != row.is_revoked() {
            return Err(FormatError::RevokedMismatch(row.key));
        }
    }
    unique_labels(live().map(|row| &row.label))
}

/// Verify signed bytes against `root` and parse the `state` inside.
pub fn verify(bytes: &[u8], root: VerifyKey) -> Result<State, StateVerifyError> {
    let signed = Signed::decode(bytes)?;
    Ok(State::parse_canonical(signed.verify(root)?)?)
}

/// Why signed bytes are not a `state` of this root.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateVerifyError {
    /// The signature did not verify under the root.
    #[error("the root's records are not signed by this root")]
    Signature(#[from] SignError),
    /// The payload is not a well-formed `state`.
    #[error("the root's records are malformed")]
    Payload(#[from] FormatError),
}

/// Why `state` could not be read.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Neither `state` nor `state.new` holds valid records of this root.
    #[error(
        "this root's records were changed outside swoosh ({}): refusing to sign with them. Use another copy.",
        dir.display()
    )]
    Damaged {
        /// The root's directory.
        dir: PathBuf,
    },
    /// A file could not be read, or the promotion of `state.new` could not be written.
    #[error("reading the root's records in {}", dir.display())]
    Io {
        /// The root's directory.
        dir: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },
}

/// Store `signed` (the root's signature over [`State::canonical_bytes`]) as `dir/state`: write `state.new` and fsync it, rename it over `state`,
/// then fsync `dir`. A crash at any point leaves the old `state` or the new one, and [`load`] finds it.
pub fn write(dir: &Path, signed: &[u8]) -> io::Result<()> {
    write_with(&mut RealDisk, dir, signed)
}

/// Read `dir/state` and verify it against `root`: a valid `state`, else a valid `state.new`, else the
/// records are damaged. Renames nothing, so it needs no lock.
pub fn load(dir: &Path, root: VerifyKey) -> Result<State, StateError> {
    let io = io_error(dir);
    if let Some(state) = load_file(&dir.join(FILE), root).map_err(&io)? {
        return Ok(state);
    }
    match load_file(&dir.join(STAGED), root).map_err(&io)? {
        Some(state) => Ok(state),
        None => Err(StateError::Damaged {
            dir: dir.to_path_buf(),
        }),
    }
}

/// [`load`], and when the records came from `state.new`, rename it over `state`. Only a holder of the
/// root's lock calls it: a writer may be rewriting `state.new` under anyone else.
pub fn recover(dir: &Path, root: VerifyKey) -> Result<State, StateError> {
    recover_with(&mut RealDisk, dir, root)
}

/// Name `dir` on a failed read or promotion.
fn io_error(dir: &Path) -> impl Fn(io::Error) -> StateError + use<> {
    let dir = dir.to_path_buf();
    move |source| StateError::Io {
        dir: dir.clone(),
        source,
    }
}

/// The filesystem calls a write and a promotion make, one method per call, so a test can fail each one.
pub(crate) trait Disk {
    fn write(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    fn sync(&mut self, path: &Path) -> io::Result<()>;
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
}

/// The real filesystem.
pub(crate) struct RealDisk;

impl Disk for RealDisk {
    /// A fresh owner-only file: whatever sat at `path` is removed first, and `create_new` never follows a
    /// link there.
    fn write(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        match fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(path)?.write_all(bytes)
    }

    fn sync(&mut self, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
}

pub(crate) fn write_with(disk: &mut impl Disk, dir: &Path, signed: &[u8]) -> io::Result<()> {
    let staged = dir.join(STAGED);
    disk.write(&staged, signed)?;
    disk.sync(&staged)?;
    disk.rename(&staged, &dir.join(FILE))?;
    disk.sync(dir)
}

pub(crate) fn recover_with(
    disk: &mut impl Disk,
    dir: &Path,
    root: VerifyKey,
) -> Result<State, StateError> {
    let io = io_error(dir);
    if let Some(state) = load_file(&dir.join(FILE), root).map_err(&io)? {
        return Ok(state);
    }
    let staged = dir.join(STAGED);
    let Some(state) = load_file(&staged, root).map_err(&io)? else {
        return Err(StateError::Damaged {
            dir: dir.to_path_buf(),
        });
    };
    disk.rename(&staged, &dir.join(FILE)).map_err(&io)?;
    disk.sync(dir).map_err(&io)?;
    Ok(state)
}

/// The verified records at `path`, or `None` when the file is missing, longer than [`MAX_STATE_BLOB`], or
/// does not verify.
fn load_file(path: &Path, root: VerifyKey) -> io::Result<Option<State>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BLOB + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BLOB {
        return Ok(None);
    }
    Ok(verify(&bytes, root).ok())
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod state_tests;
