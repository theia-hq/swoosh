//! The issuer-side mint log: one record per grant this node has issued, so a grant can be revoked by the
//! holder it was issued to, and audited, after the link has left this machine.
//!
//! A minted link is gone the moment it is handed off: the holder carries it and this node keeps no copy. But
//! revoking a grant by NAMING its holder (rather than pasting the exact link back) needs an issuer-side index
//! from grantee to the cap's ROOT revocation id, the id that, once recorded in the denylist, kills the grant
//! and everything delegated from it. This ledger IS that index. It is a who-can-reach-what record, so it is
//! written `0600` and the gate NEVER reads it: it is issuer-side audit and revoke only, never an admission
//! input. It lives beside the identity, dir-derived from `--key` like the denylist and the contacts file, so
//! one `--key` moves the whole identity+trust unit as a unit.

use core::num::ParseIntError;
use core::str::FromStr;
use core::time::Duration;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nauthy::{RevocationId, Service, ServiceParseError};
use tokio::io::AsyncWriteExt as _;

/// The persisted mint-log ledger backing a `--key` dir. Owns the load / append / read logic over its path;
/// the location is the caller's to choose (see [`config::grants_path`](crate::config::grants_path)).
pub struct Grants {
    path: PathBuf,
}

impl Grants {
    /// A ledger backed by `path`. No file is touched until the first [`append`](Self::append); an absent file
    /// reads as no grants.
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// The file backing this ledger.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record one issued grant, creating the file (and its parent dir) on first use. Appends a single line,
    /// so a concurrent read of the ledger sees whole records only. The private-posture is reasserted every
    /// append: the config dir is `0700` and the ledger `0600`, because this index of who can reach what is as
    /// sensitive as the grants it tracks. `create`'s mode applies only on first creation, so the file mode is
    /// reasserted (an fchmod on the open fd) to tighten a ledger that was somehow loosened after creation.
    pub async fn append(&self, record: &GrantRecord) -> Result<(), LedgerError> {
        if let Some(parent) = self.path.parent() {
            // swoosh's config dir holds the identity key, the denylist, and this index, so create it owner-only
            // (`0700`). Create-with-mode tightens only dirs WE make; it is a no-op on an existing dir, so we
            // never chmod (and fight ownership of) a dir another verb or the user already made.
            #[cfg(unix)]
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(LedgerError::Io)?;
            #[cfg(not(unix))]
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(LedgerError::Io)?;
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&self.path).await.map_err(LedgerError::Io)?;
        // Reassert 0600 even on a pre-existing ledger (create's mode fired only on first creation).
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(LedgerError::Io)?;
        file.write_all(format!("{}\n", record.to_line()).as_bytes())
            .await
            .map_err(LedgerError::Io)?;
        file.flush().await.map_err(LedgerError::Io)?;
        Ok(())
    }

    /// Every grant this node has issued, in append order. An absent file is no grants (nothing issued yet).
    ///
    /// A single corrupt line must NOT wedge the whole ledger, or one bad byte would blind every `grant ls`
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

/// One issued grant, as the ledger records it: enough to display what was granted and to revoke it by its
/// root, never the usable link itself (only the opaque root revocation id, so the ledger holds no presentable
/// capability).
#[derive(Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// The service the grant reaches (e.g. `ssh`), the key `ls` groups by.
    pub service: Service,
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
            "{kind}{FIELD}{delegation}{FIELD}{service}{FIELD}{holder}{FIELD}{expiry}{FIELD}{root}",
            kind = self.kind.as_str(),
            delegation = self.delegation.as_str(),
            service = self.service.as_str(),
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
        let service = next()?.parse::<Service>().map_err(LedgerError::Service)?;
        let holder = next()?.to_owned();
        let expiry = from_unix_secs(next()?.parse::<u64>().map_err(LedgerError::Expiry)?);
        let root_id = RevocationId::from_hex(next()?).map_err(|_| LedgerError::RootId)?;
        // Trailing fields mean a format we did not write; refuse rather than ignore the tail.
        if fields.next().is_some() {
            return Err(LedgerError::Malformed);
        }
        Ok(Self {
            service,
            kind,
            delegation,
            holder,
            root_id,
            expiry,
        })
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
/// `grant ls` (a row's remaining lifetime).
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
