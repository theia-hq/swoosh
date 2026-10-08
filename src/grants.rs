//! The ledger: one record per link this machine has signed with its own key.
//!
//! It is an admission input. `serve`'s gate admits a link rooted at this machine's own key only when the
//! link's root revocation id is recorded here ([`IssuedLedger`]), so a copy of the key cannot mint access
//! to this machine: every mint yields a fresh id, and a mint made elsewhere never lands in this file. A
//! ledger that cannot be read admits no such link.
//!
//! It is also the issuer's index from holder to that root id, which is what revoking a link by naming its
//! holder, and `status`, read. Each row records what its service's name served when the link was made, so
//! `serve` reads it at start too ([`LinksForAnother`]), and binds no shell under a name whose live links were
//! made for something else. It is a who-can-reach-what record, so it is written `0600`, and it lives
//! in the node home beside the identity so one home moves the whole identity and trust unit together.
//!
//! Every writer holds `home.lock`. An [`append`](Grants::append) is one `O_APPEND` line and a `sync_data`,
//! so a link is on disk before it is printed, and the directory is synced when the file is first made; a
//! rewrite (the prune an append runs once enough rows have expired) goes through the home's one write
//! routine.

use core::fmt;
use core::num::ParseIntError;
use core::str::FromStr;
use core::time::Duration;
use std::collections::HashSet;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nauthy::{FileStamp, IssuedIds, RevocationId, STAT_DEBOUNCE, Service, ServiceParseError};

use crate::escape::EscapedPath;
use crate::home::HomeWrite;

/// How many expired rows an [`append`](Grants::append) lets gather before it prunes them. A prune rewrites
/// the whole file, so it waits until the rewrite removes enough to be worth it.
pub const PRUNE_AT: usize = 64;

/// The persisted ledger backing a node home. Owns the load / append / prune logic over its path; the
/// location is the caller's to choose (see [`Home::links`](crate::home::Home::links)).
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

    /// Record one issued grant under `home.lock`, creating the file (and its parent dir) on first use.
    /// Returns once the row is on disk (`sync_data`), so a caller that prints the link after this never
    /// prints a link whose row a crash could lose.
    ///
    /// When at least [`PRUNE_AT`] rows have expired, the append first rewrites the file without them.
    /// `home.lock` is what makes that safe: a rewrite reads the file and replaces it, and a concurrent
    /// append to the old file would be lost in between.
    ///
    /// The private posture is reasserted every append: the config dir is `0700` and the ledger `0600`,
    /// because this index of who can reach what is as sensitive as the grants it tracks.
    ///
    /// # Errors
    ///
    /// The file could not be pruned, opened, written or synced.
    pub fn append(&self, home_lock: &HomeWrite, record: &GrantRecord) -> Result<(), LedgerError> {
        let line = format!("{}\n", record.to_line());
        append_locked(home_lock, &self.path, &line, self.prune_at)
    }

    /// Every grant this node has issued, in append order. An absent file is no grants (nothing issued yet).
    ///
    /// A single corrupt line must NOT wedge the whole ledger, or one bad byte would blind every `status`
    /// and `revoke <holder>`: the good rows still matter for revocation. So parsing is per-line, good
    /// rows are kept, and each bad line is reported to stderr (named by file and line number) for the issuer
    /// to fix, never swallowed silently. An unreadable FILE (not a bad line) is still a hard error.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    pub async fn load(&self) -> Result<Vec<GrantRecord>, LedgerError> {
        let text = match crate::home::read_trust_file_async(&self.path).await {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(LedgerError::Io(error)),
        };
        Ok(self.records(&text))
    }

    /// [`load`](Self::load), read on the calling thread, for a check made where nothing can be awaited.
    ///
    /// # Errors
    ///
    /// The file exists and could not be read.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    pub fn read(&self) -> Result<Vec<GrantRecord>, LedgerError> {
        let text = match crate::home::read_trust_file(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(LedgerError::Io(error)),
        };
        Ok(self.records(&text))
    }

    /// The rows in `text`, each line that does not parse skipped and named on stderr.
    fn records(&self, text: &str) -> Vec<GrantRecord> {
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
                    EscapedPath(&self.path)
                ),
            }
        }
        records
    }
}

/// The body of [`Grants::append`], under `home.lock`.
fn append_locked(
    home_lock: &HomeWrite,
    path: &Path,
    line: &str,
    prune_at: usize,
) -> Result<(), LedgerError> {
    if let Some(parent) = path.parent() {
        // swoosh's config dir holds the identity key, the denylist, and this index, so create it owner-only
        // (`0700`). Create-with-mode tightens only dirs WE make; it is a no-op on an existing dir, so we
        // never chmod (and fight ownership of) a dir another verb or the user already made.
        crate::config::create_store_dir(parent).map_err(LedgerError::Io)?;
    }
    prune_expired(home_lock, path, prune_at).map_err(LedgerError::Io)?;
    let made = !path.exists();
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
    file.sync_data().map_err(LedgerError::Io)?;
    // A file this append made is durable only once the directory that names it is.
    if made && let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(LedgerError::Io)?;
    }
    Ok(())
}

/// Rewrite the ledger without its expired rows, when at least `prune_at` have expired, through the home's
/// one write routine under `home.lock`. A line that does not parse is kept as it is: a prune removes only
/// rows it read as expired, never one it could not read.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn prune_expired(home_lock: &HomeWrite, path: &Path, prune_at: usize) -> std::io::Result<()> {
    let text = match crate::home::read_trust_file(path) {
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
    crate::config::write_private_atomic(home_lock, path, kept.as_bytes())
}

/// The ledger as the gate reads it: the root revocation ids of every link this machine signed, so an
/// anchored gate admits a link rooted at this machine's own key only when this machine recorded issuing
/// it.
///
/// Live: it re-stats the file at most once per [`STAT_DEBOUNCE`] and re-reads it when its [`FileStamp`]
/// changed, so a `share` run while `serve` runs is admitted with no restart.
///
/// It fails closed. A file that cannot be opened or read, or that another user owns or others can write
/// (checked on the handle each read comes from), admits no self-anchored link until it can be read again,
/// and each change between readable and unreadable is logged with the path. A missing file is readable and
/// holds no links. One malformed line fails only that row.
pub struct IssuedLedger {
    path: PathBuf,
    state: Mutex<LedgerState>,
}

/// What an [`IssuedLedger`] read last.
struct LedgerState {
    /// The ids the last successful read found; empty while the file is unreadable.
    ids: HashSet<RevocationId>,
    /// Which of `ids` are one-use links ([`GrantKind::Once`]).
    once: HashSet<RevocationId>,
    /// The one-use links this run has admitted once already. Kept across re-reads, since a link stays
    /// used whatever the file does, and trimmed to the one-use ids the file still holds, so it never
    /// outgrows the ledger. Held in memory only: a restarted `serve` starts with none.
    used: HashSet<RevocationId>,
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
                once: HashSet::new(),
                used: HashSet::new(),
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
                crate::home::read_trust_file(&self.path).map(|text| Some((text, stamp)))
            }
        };
        let readable = match read {
            Ok(None) => {
                state.ids.clear();
                state.once.clear();
                state.stamp = None;
                true
            }
            Ok(Some((text, stamp))) => {
                (state.ids, state.once) = self.parse(&text);
                let once = &state.once;
                state.used.retain(|id| once.contains(id));
                state.stamp = stamp;
                true
            }
            Err(error) => {
                state.ids.clear();
                state.once.clear();
                state.stamp = None;
                if state.readable != Some(false) {
                    tracing::error!(
                        path = %EscapedPath(&self.path),
                        %error,
                        "the grants ledger cannot be read; no link this machine signed is admitted until it can"
                    );
                }
                false
            }
        };
        if readable && state.readable == Some(false) {
            tracing::warn!(
                path = %EscapedPath(&self.path),
                "the grants ledger can be read again"
            );
        }
        state.readable = Some(readable);
    }

    /// The root ids in `text`, and which of them are one-use links, skipping and naming each line that
    /// does not parse.
    fn parse(&self, text: &str) -> (HashSet<RevocationId>, HashSet<RevocationId>) {
        let mut ids = HashSet::new();
        let mut once = HashSet::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match GrantRecord::from_line(line) {
                Ok(record) => {
                    if record.kind == GrantKind::Once {
                        once.insert(record.root_id.clone());
                    }
                    ids.insert(record.root_id);
                }
                Err(error) => tracing::warn!(
                    path = %EscapedPath(&self.path),
                    line = index + 1,
                    %error,
                    "skipping a malformed grants ledger line"
                ),
            }
        }
        (ids, once)
    }
}

impl IssuedIds for IssuedLedger {
    /// Whether this machine recorded issuing the link `id` roots, and, for a one-use link, whether this is
    /// its first admission. nauthy asks this last, once every other check on the link has passed, so the
    /// first `true` for a one-use id is its one admission: the id is marked used then, and every later ask
    /// is `false`, the refusal any unrecorded link gets. The unit is the admission, so each stream that
    /// presents the link spends it, not each session.
    fn is_issued(&self, id: &RevocationId) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        if !state.ids.contains(id) {
            return false;
        }
        if !state.once.contains(id) {
            return true;
        }
        state.used.insert(id.clone())
    }
}

/// One issued grant, as the ledger records it: enough to display what was granted and to revoke it by its
/// root, never the usable link itself (only the opaque root revocation id, so the ledger holds no presentable
/// capability).
#[derive(Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// The one service the grant reaches (e.g. `ssh`).
    pub target: Service,
    /// What that service's name served when the grant was made, `None` when it served nothing. `serve`
    /// reads it, so a name later bound to a shell never inherits a link made for something else.
    pub serves: Option<ServedTarget>,
    /// How the grant is bound: device, fleet, bearer, or once.
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
            (GrantKind::Once, _) => "one-use",
            (GrantKind::Bearer, Delegation::Delegable) => "delegable",
            (GrantKind::Bearer, Delegation::Sealed) => "non-delegable",
        }
    }
}

/// The placeholder a bearer grant records for its holder: a bearer slip names no one (anyone holding it may
/// present it), so there is no grantee to record.
pub const ANYONE: &str = "-";

/// The tab that separates a record's fields on disk. A record's fields are a validated service name, a
/// served target (which holds no control character, by [`ServedTarget`]), a grant-kind word, a holder (a
/// node id or petname, both whitespace-free by construction), a decimal expiry, and a hex id, none of which
/// can contain a tab, so it delimits unambiguously.
const FIELD: char = '\t';

/// What the served-target field holds when the name served nothing. Never a target, which always holds a
/// `:`.
const SERVED_NOTHING: &str = "-";

impl GrantRecord {
    /// Serialize to one tab-separated line: kind, delegation, service, served target (or `-`), holder,
    /// expiry (unix seconds), root id (hex).
    fn to_line(&self) -> String {
        format!(
            "{kind}{FIELD}{delegation}{FIELD}{target}{FIELD}{serves}{FIELD}{holder}{FIELD}{expiry}{FIELD}{root}",
            kind = self.kind.as_str(),
            delegation = self.delegation.as_str(),
            target = self.target.as_str(),
            serves = self
                .serves
                .as_ref()
                .map_or(SERVED_NOTHING, ServedTarget::as_str),
            holder = self.holder,
            expiry = unix_secs(self.expiry),
            root = self.root_id.to_hex(),
        )
    }

    /// Parse one line back into a record; a wrong field count, an unknown kind or delegation, a bad service,
    /// served target, expiry, or id is a typed error, never a silent default. A one-use link that reads as
    /// delegable is malformed: one use cannot be passed on.
    fn from_line(line: &str) -> Result<Self, LedgerError> {
        let mut fields = line.split(FIELD);
        let mut next = || fields.next().ok_or(LedgerError::Malformed);
        let kind = next()?.parse::<GrantKind>()?;
        let delegation = next()?.parse::<Delegation>()?;
        if kind == GrantKind::Once && delegation == Delegation::Delegable {
            return Err(LedgerError::Malformed);
        }
        let target = next()?.parse::<Service>().map_err(LedgerError::Service)?;
        let serves = match next()? {
            SERVED_NOTHING => None,
            served => Some(served.parse::<ServedTarget>()?),
        };
        let holder = next()?.to_owned();
        let expiry = from_unix_secs(next()?.parse::<u64>().map_err(LedgerError::Expiry)?);
        let root_id = RevocationId::from_hex(next()?).map_err(|_| LedgerError::RootId)?;
        // Trailing fields mean a format we did not write; refuse rather than ignore the tail.
        if fields.next().is_some() {
            return Err(LedgerError::Malformed);
        }
        Ok(Self {
            target,
            serves,
            kind,
            delegation,
            holder,
            root_id,
            expiry,
        })
    }
}

/// What a service's name served when a link to it was made: the target of its `serve` entry, `sshd:` or
/// `tcp:localhost:22`. Parsed, so it always names a scheme (it holds a `:`) and holds no control character,
/// which keeps it one field of one ledger line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedTarget(String);

impl ServedTarget {
    /// The target as its `serve` entry spells it.
    pub fn as_str(&self) -> &str {
        let Self(text) = self;
        text
    }
}

impl FromStr for ServedTarget {
    type Err = LedgerError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if !text.contains(':') || text.chars().any(char::is_control) {
            return Err(LedgerError::Served(text.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for ServedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name `serve` will not bind a code-running engine under: live links were shared for it while it
/// served something else (or nothing), and a shell under the name would admit them. Its display is the
/// refusal line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinksForAnother {
    /// The service name.
    name: String,
    /// What the name served when each of those links was made, `None` for nothing; distinct, in order.
    targets: Vec<Option<String>>,
    /// Who each of them was shared with, as the ledger records them; distinct, in order.
    holders: Vec<String>,
}

impl LinksForAnother {
    /// The first of `entries` (`name=target`, as `serve` binds them) that binds a code-running engine under a
    /// name with a live link in `records` made for another target, or `None` when none does. Live: not past
    /// its expiry at `now`, and not in `revoked`.
    pub fn first<'a>(
        entries: impl IntoIterator<Item = &'a str>,
        records: &[GrantRecord],
        revoked: &nauthy::Denylist,
        now: std::time::SystemTime,
    ) -> Option<Self> {
        entries.into_iter().find_map(|entry| {
            let (name, target) = entry.split_once('=')?;
            if !crate::serve::runs_code(target) {
                return None;
            }
            let mut found: Option<Self> = None;
            for record in records.iter().filter(|record| {
                record.target.as_str() == name
                    && record.expiry > now
                    && !revoked.is_revoked_any([&record.root_id])
                    && record
                        .serves
                        .as_ref()
                        .is_none_or(|served| served.as_str() != target)
            }) {
                let found = found.get_or_insert_with(|| Self {
                    name: name.to_owned(),
                    targets: Vec::new(),
                    holders: Vec::new(),
                });
                let served = record.serves.as_ref().map(ToString::to_string);
                if !found.targets.contains(&served) {
                    found.targets.push(served);
                }
                let holder = match record.holder.as_str() {
                    ANYONE => "anyone".to_owned(),
                    key => key.to_owned(),
                };
                if !found.holders.contains(&holder) {
                    found.holders.push(holder);
                }
            }
            found
        })
    }

    /// [`first`](Self::first) over `home`'s ledger and revocations as they stand now. Only an entry that
    /// binds a code-running engine is checked, so a `serve` that binds none reads neither file and starts as
    /// it did, whatever state they are in.
    ///
    /// # Errors
    ///
    /// The ledger or the revocations could not be read while an entry binds a code-running engine: the
    /// check fails closed, so nothing binds.
    pub fn in_home<'a>(
        home: &crate::home::Home,
        entries: impl IntoIterator<Item = &'a str>,
    ) -> eyre::Result<Option<Self>> {
        let entries: Vec<&str> = entries
            .into_iter()
            .filter(|entry| {
                entry
                    .split_once('=')
                    .is_some_and(|(_, target)| crate::serve::runs_code(target))
            })
            .collect();
        if entries.is_empty() {
            return Ok(None);
        }
        let records = Grants::at(home.links()).read()?;
        let revoked = crate::revoked::open(home)?;
        Ok(Self::first(
            entries,
            &records,
            &revoked,
            std::time::SystemTime::now(),
        ))
    }

    /// The same check over services added to `held` (a `serve.toml` read while `serve` runs) under the names
    /// `added`. An added service is never bound before the next start, so the running set stays either way;
    /// this is what that start would refuse, for the run's log.
    ///
    /// # Errors
    ///
    /// As [`in_home`](Self::in_home); a `held` that lists something that is not a service adds nothing.
    pub fn among_added(
        home: &crate::home::Home,
        held: &crate::serve_toml::ServeToml,
        added: &[String],
    ) -> eyre::Result<Option<Self>> {
        let Ok(started) = crate::serve::Started::bare(held, &home.serve_toml()) else {
            return Ok(None);
        };
        let entries = started.entries();
        Self::in_home(
            home,
            entries.iter().map(String::as_str).filter(|entry| {
                entry
                    .split_once('=')
                    .is_some_and(|(name, _)| added.iter().any(|added| added == name))
            }),
        )
    }
}

impl core::fmt::Display for LinksForAnother {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let targets: Vec<&str> = self
            .targets
            .iter()
            .map(|target| target.as_deref().unwrap_or("not served"))
            .collect();
        write!(
            f,
            "links shared for {name} were made when it was {targets}, and a shell under that name would reach \
             them: revoke them first (swoosh revoke <holder>, for {holders}), or serve the shell under another \
             name.",
            name = self.name,
            targets = targets.join(" or "),
            holders = self.holders.join(", "),
        )
    }
}

impl core::error::Error for LinksForAnother {}

/// How a grant is bound, which fixes its theft-resistance and delegability. An enum, not a stored word, so a
/// future grant kind forces a decision at every match site rather than reading as one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    /// Bound to ONE device: theft-resistant, non-delegable, standing access for that device alone.
    Device,
    /// Bound to a whole fleet (a person's signet): every device of that person.
    Fleet,
    /// An unbound bearer slip: delegable, short-lived, presentable by anyone holding it.
    Bearer,
    /// An unbound slip that admits once: sealed, so it cannot be passed on, and refused by the serving
    /// node after its first admission.
    Once,
}

impl GrantKind {
    /// The word this kind is stored and displayed as.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Fleet => "fleet",
            Self::Bearer => "bearer",
            Self::Once => "once",
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
            "once" => Ok(Self::Once),
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
/// a rough "how much longer", not a stopwatch. `invite` frames a device's life with it; `share` prints the
/// span as typed instead, since a rounded span misstates what a link gives.
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
    /// A line named a grant kind that is not `device`, `fleet`, `bearer`, or `once`.
    #[error("grants ledger has an unknown grant kind {0:?}")]
    Kind(String),
    /// A line named a delegation that is not `delegable` or `sealed`.
    #[error("grants ledger has an unknown delegation {0:?}")]
    Delegation(String),
    /// A line's service field was not a valid service name.
    #[error("grants ledger has an invalid service name")]
    Service(#[source] ServiceParseError),
    /// A line's served-target field was not a target: no `:`, or a control character.
    #[error("grants ledger has an invalid served target {0:?}")]
    Served(String),
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
