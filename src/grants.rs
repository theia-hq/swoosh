//! The ledger: one record per link this machine has signed with its own key.
//!
//! It is an admission input. `serve`'s gate admits a link rooted at this machine's own key only when the
//! link's root revocation id is recorded here ([`IssuedLedger`]), so a copy of the key cannot mint access
//! to this machine: every mint yields a fresh id, and a mint made elsewhere never lands in this file. A
//! ledger that cannot be read admits no such link.
//!
//! It is also the issuer's index from holder to that root id, which is what revoking a link by naming its
//! holder, and `status`, read. It is a who-can-reach-what record, so it is written `0600`, and it lives
//! in the node home beside the identity so one home moves the whole identity and trust unit together.
//!
//! Every writer takes the exclusive flock on `<home>/links.lock`. An [`append`](Grants::append) is one
//! `O_APPEND` line and a `sync_data`, so a link is on disk before it is printed; a rewrite (the prune an
//! append runs once enough rows have expired) writes `links.new`, syncs it and renames it over `links`.

use core::num::ParseIntError;
use core::str::FromStr;
use core::time::Duration;
use std::collections::HashSet;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nauthy::{FileStamp, IssuedIds, RevocationId, STAT_DEBOUNCE, Service, ServiceParseError};

/// How many expired rows an [`append`](Grants::append) lets gather before it prunes them. A prune rewrites
/// the whole file, so it waits until the rewrite removes enough to be worth it.
pub const PRUNE_AT: usize = 64;

/// The persisted ledger backing a node home. Owns the load / append / prune logic over its path; the
/// location is the caller's to choose (see [`Home::links`](crate::home::Home::links)), and the lock and
/// the rewrite's temp are its siblings, `<path>.lock` and `<path>.new`.
pub struct Grants {
    path: PathBuf,
    /// Prune once this many rows have expired. [`PRUNE_AT`] outside tests.
    prune_at: usize,
}

impl Grants {
    /// A ledger backed by `path`. No file is touched until the first [`append`](Self::append); an absent file
    /// reads as no grants.
    pub fn at(path: PathBuf) -> Self {
        Self {
            path,
            prune_at: PRUNE_AT,
        }
    }

    /// This ledger, pruning once `rows` rows have expired rather than [`PRUNE_AT`], so a test can force a
    /// prune on every append.
    #[cfg(test)]
    pub(crate) fn pruning_at(mut self, rows: usize) -> Self {
        self.prune_at = rows;
        self
    }

    /// The file backing this ledger.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record one issued grant, creating the file (and its parent dir) on first use, under the ledger's
    /// exclusive lock. Returns once the row is on disk (`sync_data`), so a caller that prints the link
    /// after this never prints a link whose row a crash could lose.
    ///
    /// When at least [`PRUNE_AT`] rows have expired, the append first rewrites the file without them. The
    /// lock is what makes that safe: a rewrite reads, writes `links.new` and renames it over `links`, and
    /// a concurrent append to the old file would be lost in between.
    ///
    /// The private posture is reasserted every append: the config dir is `0700` and the ledger `0600`,
    /// because this index of who can reach what is as sensitive as the grants it tracks.
    pub async fn append(&self, record: &GrantRecord) -> Result<(), LedgerError> {
        let path = self.path.clone();
        let line = format!("{}\n", record.to_line());
        let prune_at = self.prune_at;
        tokio::task::spawn_blocking(move || append_locked(&path, &line, prune_at))
            .await
            .map_err(|error| LedgerError::Io(std::io::Error::other(error)))?
    }

    /// Every grant this node has issued, in append order. An absent file is no grants (nothing issued yet).
    ///
    /// A single corrupt line must NOT wedge the whole ledger, or one bad byte would blind every `status`
    /// and `grant revoke <holder>`: the good rows still matter for revocation. So parsing is per-line, good
    /// rows are kept, and each bad line is reported to stderr (named by file and line number) for the issuer
    /// to fix, never swallowed silently. An unreadable FILE (not a bad line) is still a hard error.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    pub async fn load(&self) -> Result<Vec<GrantRecord>, LedgerError> {
        let text = match tokio::fs::read_to_string(&self.path).await {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(LedgerError::Io(error)),
        };
        let mut records = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match GrantRecord::from_line(line) {
                Ok(record) => records.push(record),
                Err(error) => eprintln!(
                    "warning: skipping malformed grant ledger line {} in {}: {error}",
                    index + 1,
                    self.path.display()
                ),
            }
        }
        Ok(records)
    }
}

/// `path` with `suffix` appended to its file name: the ledger's lock and its rewrite's temp.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// The body of [`Grants::append`], synchronous so the flock and the file work never hold an executor
/// thread across an await. The lock is held until this returns.
fn append_locked(path: &Path, line: &str, prune_at: usize) -> Result<(), LedgerError> {
    if let Some(parent) = path.parent() {
        // swoosh's config dir holds the identity key, the denylist, and this index, so create it owner-only
        // (`0700`). Create-with-mode tightens only dirs WE make; it is a no-op on an existing dir, so we
        // never chmod (and fight ownership of) a dir another verb or the user already made.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(LedgerError::Io)?;
    }
    let _lock = LedgerLock::take(&sibling(path, ".lock")).map_err(LedgerError::Io)?;
    prune_expired(path, prune_at).map_err(LedgerError::Io)?;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(LedgerError::Io)?;
    // Reassert 0600 even on a pre-existing ledger (create's mode fired only on first creation).
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(LedgerError::Io)?;
    file.write_all(line.as_bytes()).map_err(LedgerError::Io)?;
    file.sync_data().map_err(LedgerError::Io)
}

/// Rewrite the ledger without its expired rows, when at least `prune_at` have expired. Called with the
/// ledger's lock held. A line that does not parse is kept as it is: a prune removes only rows it read as
/// expired, never one it could not read.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn prune_expired(path: &Path, prune_at: usize) -> std::io::Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let now = SystemTime::now();
    let expired =
        |line: &str| GrantRecord::from_line(line.trim()).is_ok_and(|record| record.expiry <= now);
    if text.lines().filter(|line| expired(line)).count() < prune_at {
        return Ok(());
    }
    let mut kept = String::with_capacity(text.len());
    for line in text
        .lines()
        .filter(|line| !line.trim().is_empty() && !expired(line))
    {
        kept.push_str(line);
        kept.push('\n');
    }
    let new = sibling(path, ".new");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&new)?;
    file.write_all(kept.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&new, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// The ledger's exclusive flock, held while this value lives. On its own file, a stable inode, because a
/// prune replaces the ledger itself by rename.
struct LedgerLock {
    /// Held, never read: the lock lives exactly as long as this open file does.
    _held: std::fs::File,
}

impl LedgerLock {
    /// Take the lock at `path`, creating the file, and wait for any other writer to finish.
    fn take(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        // SAFETY: `file` owns a valid fd for the whole call, and `flock` only attaches an advisory lock to
        // it. Without `LOCK_NB` it waits for a writer that holds the lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { _held: file })
    }
}

/// The ledger as the gate reads it: the root revocation ids of every link this machine signed, so an
/// anchored gate admits a link rooted at this machine's own key only when this machine recorded issuing
/// it.
///
/// Live: it re-stats the file at most once per [`STAT_DEBOUNCE`] and re-reads it when its [`FileStamp`]
/// changed, so a `grant issue` run while `serve` runs is admitted with no restart.
///
/// It fails closed. A file that cannot be opened or read admits no self-anchored link until it can be
/// read again, and each change between readable and unreadable is logged with the path. A missing file is
/// readable and holds no links. One malformed line fails only that row.
pub struct IssuedLedger {
    path: PathBuf,
    state: Mutex<LedgerState>,
}

/// What an [`IssuedLedger`] read last.
struct LedgerState {
    /// The ids the last successful read found; empty while the file is unreadable.
    ids: HashSet<RevocationId>,
    /// The stamp of the file the ids came from, `None` before a read or after a failed one.
    stamp: Option<FileStamp>,
    /// When the file was last statted, to debounce the next stat.
    last_stat: Option<Instant>,
    /// Whether the last look at the file could read it, `None` before the first look.
    readable: Option<bool>,
}

impl IssuedLedger {
    /// The ledger at `<home>/links`, read once now so `serve` logs an unreadable ledger at start.
    pub fn open(home: &crate::home::Home) -> Self {
        let ledger = Self {
            path: home.links(),
            state: Mutex::new(LedgerState {
                ids: HashSet::new(),
                stamp: None,
                last_stat: None,
                readable: None,
            }),
        };
        ledger.refresh(&mut ledger.state.lock().unwrap_or_else(PoisonError::into_inner));
        ledger
    }

    /// Re-read the file when its stamp changed, at most once per [`STAT_DEBOUNCE`].
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn refresh(&self, state: &mut LedgerState) {
        if state
            .last_stat
            .is_some_and(|last| last.elapsed() < STAT_DEBOUNCE)
        {
            return;
        }
        state.last_stat = Some(Instant::now());
        let read = match std::fs::metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
            Ok(meta) => {
                let stamp = FileStamp::of(&meta);
                if FileStamp::unchanged(state.stamp, stamp) {
                    return;
                }
                std::fs::read_to_string(&self.path).map(|text| Some((text, stamp)))
            }
        };
        let readable = match read {
            Ok(None) => {
                state.ids.clear();
                state.stamp = None;
                true
            }
            Ok(Some((text, stamp))) => {
                state.ids = self.parse(&text);
                state.stamp = stamp;
                true
            }
            Err(error) => {
                state.ids.clear();
                state.stamp = None;
                if state.readable != Some(false) {
                    tracing::error!(
                        path = %self.path.display(),
                        %error,
                        "the grants ledger cannot be read; no link this machine signed is admitted until it can"
                    );
                }
                false
            }
        };
        if readable && state.readable == Some(false) {
            tracing::warn!(path = %self.path.display(), "the grants ledger can be read again");
        }
        state.readable = Some(readable);
    }

    /// The root ids in `text`, skipping and naming each line that does not parse.
    fn parse(&self, text: &str) -> HashSet<RevocationId> {
        let mut ids = HashSet::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match GrantRecord::from_line(line) {
                Ok(record) => {
                    ids.insert(record.root_id);
                }
                Err(error) => tracing::warn!(
                    path = %self.path.display(),
                    line = index + 1,
                    %error,
                    "skipping a malformed grants ledger line"
                ),
            }
        }
        ids
    }
}

impl IssuedIds for IssuedLedger {
    fn is_issued(&self, id: &RevocationId) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        state.ids.contains(id)
    }
}

/// One issued grant, as the ledger records it: enough to display what was granted and to revoke it by its
/// root, never the usable link itself (only the opaque root revocation id, so the ledger holds no presentable
/// capability).
#[derive(Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// What the grant reaches: one named service (e.g. `ssh`), or family membership itself. An enum, not
    /// a service name, so a service can never be named `membership` and a membership line can never read
    /// as a service.
    pub target: GrantTarget,
    /// How the grant is bound: device, fleet, or bearer.
    pub kind: GrantKind,
    /// Whether the holder may narrow and re-share it: a bound grant is always [`Sealed`](Delegation::Sealed);
    /// a bearer slip is [`Delegable`](Delegation::Delegable) only when issued so.
    pub delegation: Delegation,
    /// Who it was issued to. For a bound grant this is the RESOLVED device node id (canonical), so revoke-by-
    /// holder matches whether the issuer typed a petname or the raw key. [`ANYONE`] (`-`) for a bearer slip,
    /// which names no one.
    pub holder: String,
    /// The cap's ROOT revocation id: recording it in the denylist revokes the grant and everything delegated
    /// from it. An opaque handle, not a usable token.
    pub root_id: RevocationId,
    /// When the grant expires.
    pub expiry: SystemTime,
}

impl GrantRecord {
    /// The one-word caveat the `ls` view shows for this grant: its theft/re-share posture. A bound grant is
    /// tied to its device or fleet; a bearer slip is `delegable` or `non-delegable` by how it was issued.
    pub fn caveat(&self) -> &'static str {
        match (self.kind, self.delegation) {
            (GrantKind::Device, _) => "device-bound",
            (GrantKind::Fleet, _) => "fleet-bound",
            (GrantKind::Bearer, Delegation::Delegable) => "delegable",
            (GrantKind::Bearer, Delegation::Sealed) => "non-delegable",
        }
    }
}

/// The placeholder a bearer grant records for its holder: a bearer slip names no one (anyone holding it may
/// present it), so there is no grantee to record.
pub const ANYONE: &str = "-";

/// The tab that separates a record's fields on disk. A record's fields are a validated service name, a
/// grant-kind word, a holder (a node id or petname, both whitespace-free by construction), a decimal expiry,
/// and a hex id, none of which can contain a tab, so it delimits unambiguously.
const FIELD: char = '\t';

impl GrantRecord {
    /// Serialize to one tab-separated line: kind, delegation, service, holder, expiry (unix seconds), root id
    /// (hex).
    fn to_line(&self) -> String {
        format!(
            "{kind}{FIELD}{delegation}{FIELD}{target}{FIELD}{holder}{FIELD}{expiry}{FIELD}{root}",
            kind = self.kind.as_str(),
            delegation = self.delegation.as_str(),
            target = self.target.as_str(),
            holder = self.holder,
            expiry = unix_secs(self.expiry),
            root = self.root_id.to_hex(),
        )
    }

    /// Parse one line back into a record; a wrong field count, an unknown kind or delegation, a bad service,
    /// expiry, or id is a typed error, never a silent default.
    fn from_line(line: &str) -> Result<Self, LedgerError> {
        let mut fields = line.split(FIELD);
        let mut next = || fields.next().ok_or(LedgerError::Malformed);
        let kind = next()?.parse::<GrantKind>()?;
        let delegation = next()?.parse::<Delegation>()?;
        let target = next()?.parse::<GrantTarget>()?;
        let holder = next()?.to_owned();
        let expiry = from_unix_secs(next()?.parse::<u64>().map_err(LedgerError::Expiry)?);
        let root_id = RevocationId::from_hex(next()?).map_err(|_| LedgerError::RootId)?;
        // Trailing fields mean a format we did not write; refuse rather than ignore the tail.
        if fields.next().is_some() {
            return Err(LedgerError::Malformed);
        }
        Ok(Self {
            target,
            kind,
            delegation,
            holder,
            root_id,
            expiry,
        })
    }
}

/// What a grant reaches: one named service, or family membership itself.
///
/// The line word is the service name verbatim, or `membership`. A service named `membership` is
/// unrepresentable: the word is rejected as a service at this boundary and at `grant issue`, so no
/// service line can contain it and no membership line contains a service name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantTarget {
    /// One named service (e.g. `ssh`).
    Service(Service),
    /// Family membership: the whole family gate, not one service.
    Membership,
}

impl GrantTarget {
    /// The ledger word for membership.
    pub const MEMBERSHIP_WORD: &str = "membership";

    /// The word this target is stored and displayed as: the service name verbatim, or `membership`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Service(service) => service.as_str(),
            Self::Membership => Self::MEMBERSHIP_WORD,
        }
    }

    /// Whether `service` names a service that may be issued. The membership word is reserved out of the
    /// service namespace: a service named `membership` would collide with the real membership line.
    pub fn is_issuable_service_name(text: &str) -> bool {
        text != Self::MEMBERSHIP_WORD
    }
}

impl FromStr for GrantTarget {
    type Err = LedgerError;

    /// The word alone decides: `membership` is Membership, and anything else is parsed as a service name.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == Self::MEMBERSHIP_WORD {
            return Ok(Self::Membership);
        }
        let service = text.parse::<Service>().map_err(LedgerError::Service)?;
        Ok(Self::Service(service))
    }
}

/// How a grant is bound, which fixes its theft-resistance and delegability. An enum, not a stored word, so a
/// future grant kind forces a decision at every match site rather than reading as one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    /// Bound to ONE device: theft-resistant, non-delegable, standing access for that device alone.
    Device,
    /// Bound to a whole fleet (a person's signet): every device that person adopts.
    Fleet,
    /// An unbound bearer slip: delegable, short-lived, presentable by anyone holding it.
    Bearer,
}

impl GrantKind {
    /// The word this kind is stored and displayed as.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Fleet => "fleet",
            Self::Bearer => "bearer",
        }
    }
}

impl FromStr for GrantKind {
    type Err = LedgerError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "device" => Ok(Self::Device),
            "fleet" => Ok(Self::Fleet),
            "bearer" => Ok(Self::Bearer),
            other => Err(LedgerError::Kind(other.to_owned())),
        }
    }
}

/// Whether a grant's holder may narrow and re-share it. The law: bound grants are never delegable (binding is
/// the point), so device/fleet grants are always [`Sealed`](Self::Sealed); a bearer slip is
/// [`Delegable`](Self::Delegable) only when issued with the delegable option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delegation {
    /// The holder may narrow the grant and hand a tighter copy onward.
    Delegable,
    /// The grant cannot be re-shared: bound by construction, or a bearer slip issued sealed.
    Sealed,
}

impl Delegation {
    /// The word this delegability is stored as.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delegable => "delegable",
            Self::Sealed => "sealed",
        }
    }
}

impl FromStr for Delegation {
    type Err = LedgerError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "delegable" => Ok(Self::Delegable),
            "sealed" => Ok(Self::Sealed),
            other => Err(LedgerError::Delegation(other.to_owned())),
        }
    }
}

/// A duration as its largest whole unit, `<n>d`/`<n>h`/`<n>m`/`<n>s`. Coarse on purpose: a grant lifetime is
/// a rough "how much longer", not a stopwatch. Shared by `grant issue` (framing the fresh lifetime) and
/// `invite ls` (a row's remaining lifetime).
pub fn humanize(span: Duration) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    let secs = span.as_secs();
    if secs >= DAY {
        format!("{}d", secs / DAY)
    } else if secs >= HOUR {
        format!("{}h", secs / HOUR)
    } else if secs >= MINUTE {
        format!("{}m", secs / MINUTE)
    } else {
        format!("{secs}s")
    }
}

/// A [`SystemTime`] as whole seconds since the unix epoch. A grant expiry is always after the epoch; a clock
/// somehow before it records `0` rather than failing a mint-log write.
fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// The inverse of [`unix_secs`]: whole seconds since the unix epoch back to a [`SystemTime`].
fn from_unix_secs(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Why reading or writing the grants ledger failed.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The ledger file could not be read or written.
    #[error("access the grants ledger")]
    Io(#[source] std::io::Error),
    /// A line did not have the expected number of tab-separated fields.
    #[error("grants ledger has a malformed line")]
    Malformed,
    /// A line named a grant kind that is not `device`, `fleet`, or `bearer`.
    #[error("grants ledger has an unknown grant kind {0:?}")]
    Kind(String),
    /// A line named a delegation that is not `delegable` or `sealed`.
    #[error("grants ledger has an unknown delegation {0:?}")]
    Delegation(String),
    /// A line's service field was not a valid service name.
    #[error("grants ledger has an invalid service name")]
    Service(#[source] ServiceParseError),
    /// A line's expiry field was not a decimal number of seconds.
    #[error("grants ledger has an invalid expiry")]
    Expiry(#[source] ParseIntError),
    /// A line's root-id field was not valid hex.
    #[error("grants ledger has an invalid root id")]
    RootId,
}

#[cfg(test)]
#[path = "grants_tests.rs"]
mod grants_tests;
