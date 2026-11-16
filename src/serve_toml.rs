//! `<home>/serve.toml`: what `serve` runs. One file holds the services a bare `serve` resumes, the
//! services turned off, the relay this machine is reached through and the resolver it publishes to.
//!
//! Every writer holds home.lock and preserves fields it does not set. service add|rm edits saved
//! membership; service on|off edits off names. Launch may retain reach settings, never service membership
//! or off names.
//!
//! One LiveServeToml reads saved policy throughout the run. Bare startup uses its saved/default services;
//! explicit startup uses captured constructors. Off policy remains live in both modes.
//! A failed live policy read retains accepted configuration and refuses new admissions to bound user
//! services until a valid read. Initial absence still permits defaults. Internal routes remain available;
//! existing streams are not terminated by this policy change.
//!
//! Saved removal refuses new streams only for a configuration-following run. Saved additions and target
//! edits do not construct routes. Invocation-selected membership and targets stay fixed. Off policy and
//! failed-policy refusal remain live in both modes; existing streams are not promised to end.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use nauthy::{FileStamp, STAT_DEBOUNCE, Service};
use tightbeam::enabled::EnabledServices;

use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::serve::Started;
use crate::transport::{RelayUrl, ResolverUrl};

/// The most bytes `serve.toml` may hold: far above any list of services, and a bound on what one read of a
/// running `serve` allocates.
pub const MAX_SERVE_TOML: u64 = 64 * 1024;

/// How often a running `serve` checks the file for what waits for its next start, with no stream asking.
pub const CHECK_EVERY: Duration = Duration::from_secs(1);

/// The services key: the list a bare `serve` resumes.
const SERVICES: &str = "services";
/// The off key: the services turned off.
const OFF: &str = "off";
/// The relay key.
const RELAY: &str = "relay";
/// The resolver key.
const RESOLVER: &str = "resolver";

/// What `<home>/serve.toml` holds. An absent file holds nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeToml {
    /// The saved list used by a bare start; an explicitly empty list selects no user services.
    pub services: Option<Vec<String>>,
    /// The services turned off.
    pub off: BTreeSet<String>,
    /// The relay this machine is reached through, as `serve --relay` gave it.
    pub relay: Option<RelayUrl>,
    /// The resolver this machine publishes to and looks devices up through, as `serve --resolver` gave it.
    pub resolver: Option<ResolverUrl>,
}

/// Why `<home>/serve.toml` could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum ServeTomlError {
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    #[error(transparent)]
    Definition(#[from] crate::serve::ServingError),
    /// The file exists and could not be read or written, or another user owns it, or others can write it.
    #[error("could not use {}", EscapedPath(path))]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// The file is not one swoosh wrote: it is not TOML, a field has the wrong type, a key is unknown, a
    /// service turned off is not a service name, or it is larger than [`MAX_SERVE_TOML`].
    #[error("{} was changed outside swoosh: refusing to use it", EscapedPath(path))]
    Damaged {
        /// The file.
        path: PathBuf,
    },
    /// The relay or the resolver the file keeps is not a URL swoosh can use. Swoosh's own line, never the
    /// parser's text, and it names no command: which server to use is the person's call, and swoosh
    /// never falls back to the default one.
    #[error(
        "the {what} in {path} is not a usable {what}, and swoosh will not fall back to the default one",
        path = EscapedPath(path)
    )]
    Unusable {
        /// The file.
        path: PathBuf,
        /// `relay` or `resolver`.
        what: &'static str,
    },
}

/// Why `serve.toml`'s text is not a file swoosh wrote.
enum Undecodable {
    /// It is damaged.
    Damaged,
    /// The field `what` is not a usable URL.
    Unusable(&'static str),
}

impl ServeToml {
    /// Read `<home>/serve.toml`; an absent file holds nothing.
    ///
    /// # Errors
    ///
    /// [`ServeTomlError`] when the file cannot be read, is loose, or is damaged.
    pub fn read(home: &Home) -> Result<Self, ServeTomlError> {
        Ok(read_stamped(&home.serve_toml())?
            .map(|(file, _)| file)
            .unwrap_or_default())
    }

    /// Re-read `<home>/serve.toml`, let `change` set what it sets, and write the file back when anything
    /// changed, under `home.lock`, which the caller holds. Every field `change` leaves alone keeps what the
    /// file held.
    ///
    /// # Errors
    ///
    /// [`ServeTomlError`] when the file cannot be read or written.
    pub fn update(
        home_lock: &HomeWrite,
        home: &Home,
        change: impl FnOnce(&mut Self),
    ) -> Result<(), ServeTomlError> {
        Self::try_update(home_lock, home, |file| {
            change(file);
            Ok::<_, core::convert::Infallible>(())
        })
        .map(|_| ())
    }

    /// [`update`](Self::update) for a `change` that may refuse: the file is written only when it returns
    /// `Ok`, so a refusal leaves it as it was whatever `change` set before refusing. All or nothing holds by
    /// this, never by the order a change mutates in. The outer result is the file's; the inner one is what
    /// `change` returned.
    ///
    /// # Errors
    ///
    /// [`ServeTomlError`] when the file cannot be read or written.
    pub fn try_update<T, E>(
        home_lock: &HomeWrite,
        home: &Home,
        change: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Result<T, E>, ServeTomlError> {
        let path = home.serve_toml();
        let held = Self::read(home)?;
        let mut next = held.clone();
        let changed = match change(&mut next) {
            Ok(changed) => changed,
            Err(refused) => return Ok(Err(refused)),
        };
        if next != held {
            crate::config::write_private_atomic(home_lock, &path, next.encode().as_bytes())
                .map_err(|source| ServeTomlError::Io { path, source })?;
        }
        Ok(Ok(changed))
    }

    /// The file's text: each field that holds something, and nothing else.
    fn encode(&self) -> String {
        let mut table = toml::Table::new();
        let list = |items: &mut dyn Iterator<Item = &String>| {
            toml::Value::Array(items.cloned().map(toml::Value::String).collect())
        };
        if let Some(services) = &self.services {
            table.insert(SERVICES.to_owned(), list(&mut services.iter()));
        }
        if !self.off.is_empty() {
            table.insert(OFF.to_owned(), list(&mut self.off.iter()));
        }
        if let Some(relay) = &self.relay {
            table.insert(RELAY.to_owned(), toml::Value::String(relay.to_string()));
        }
        if let Some(resolver) = &self.resolver {
            table.insert(
                RESOLVER.to_owned(),
                toml::Value::String(resolver.to_string()),
            );
        }
        table.to_string()
    }

    /// Decode the file's `text`, every field parsed here: a service turned off that is not a name as swoosh
    /// stores one (folded, so it can match the service served) is damage, and so is a relay or a resolver
    /// that is not a usable URL, named by its key.
    fn decode(text: &str) -> Result<Self, Undecodable> {
        let damaged = |_| Undecodable::Damaged;
        let table: toml::Table = text.parse().map_err(damaged)?;
        let mut read = Self::default();
        for (key, value) in table {
            match key.as_str() {
                SERVICES => read.services = Some(strings(value).ok_or(Undecodable::Damaged)?),
                OFF => {
                    let off = strings(value).ok_or(Undecodable::Damaged)?;
                    if off
                        .iter()
                        .any(|name| crate::names::Name::stored(name).is_err())
                    {
                        return Err(Undecodable::Damaged);
                    }
                    read.off = off.into_iter().collect();
                }
                RELAY => read.relay = Some(url(&value, RELAY)?),
                RESOLVER => read.resolver = Some(url(&value, RESOLVER)?),
                _ => return Err(Undecodable::Damaged),
            }
        }
        Ok(read)
    }
}

/// The URL `value` holds for the key `what`. A value that is not a string is damage; a string that is not
/// a usable URL is named by its key.
fn url<T: core::str::FromStr>(value: &toml::Value, what: &'static str) -> Result<T, Undecodable> {
    value
        .as_str()
        .ok_or(Undecodable::Damaged)?
        .parse()
        .map_err(|_| Undecodable::Unusable(what))
}

/// The strings of an array `value`, or `None` when it is not an array of strings.
fn strings(value: toml::Value) -> Option<Vec<String>> {
    let toml::Value::Array(items) = value else {
        return None;
    };
    items
        .into_iter()
        .map(|item| match item {
            toml::Value::String(text) => Some(text),
            _ => None,
        })
        .collect()
}

/// Read and decode the file at `path` and its stamp from one open handle, checked as a trust file.
/// Only absence returns `None`; a successful read need not have a stamp.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn read_stamped(path: &Path) -> Result<Option<(ServeToml, Option<FileStamp>)>, ServeTomlError> {
    let io = |source| ServeTomlError::Io {
        path: path.to_owned(),
        source,
    };
    let mut file = match crate::home::open_trust_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(io(error)),
    };
    let stamp = file.metadata().ok().and_then(|meta| FileStamp::of(&meta));
    let mut text = String::new();
    (&mut file)
        .take(MAX_SERVE_TOML + 1)
        .read_to_string(&mut text)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::InvalidData => ServeTomlError::Damaged {
                path: path.to_owned(),
            },
            _ => io(error),
        })?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_SERVE_TOML {
        return Err(ServeTomlError::Damaged {
            path: path.to_owned(),
        });
    }
    let read = ServeToml::decode(&text).map_err(|why| match why {
        Undecodable::Damaged => ServeTomlError::Damaged {
            path: path.to_owned(),
        },
        Undecodable::Unusable(what) => ServeTomlError::Unusable {
            path: path.to_owned(),
            what,
        },
    })?;
    Ok(Some((read, stamp)))
}

/// `<home>/serve.toml`, read live: the one watcher a running `serve` reads the file through. It holds the
/// whole file. The gate asks it on every stream which services are off (it is the [`EnabledServices`]
/// the exposer consults), the status reports the same set, and the run's start takes its services, relay
/// and resolver from its first read. Cloning shares one instance, so no two readers ever disagree about a
/// file they each read at a different moment.
///
/// It re-stats the file at most once per [`STAT_DEBOUNCE`] and re-reads it when its [`FileStamp`] (mtime,
/// length, inode and ctime) changed, so a same-length rewrite renamed into place is seen.
/// A failed live policy read retains accepted configuration and refuses new admissions to bound user
/// services until a valid read. Initial absence still permits defaults. Internal routes remain available;
/// existing streams are not terminated by this policy change.
#[derive(Clone)]
pub struct LiveServeToml {
    shared: Arc<Watched>,
}

/// What a running `serve` serves, fixed when its routes bound: what a later read is held against.
struct Serving {
    /// The names its services are bound under, each with its target. Only these are refused for leaving
    /// `services`: the node's own routes are bound by no entry.
    bound: BTreeMap<String, String>,
    /// Where its services came from, which decides whether leaving `services` refuses them.
    selection: Selection,
    /// The relay the file held once the run saved what it was told, which is the one it bound.
    relay: Option<RelayUrl>,
    /// The resolver, likewise.
    resolver: Option<ResolverUrl>,
}

/// Where a run's services came from.
#[derive(Clone, Copy)]
enum Selection {
    /// Named on the command line: fixed for the run, whatever `services` later holds.
    Invocation,
    /// The saved list or the defaults: a service that leaves `services` is refused.
    Saved,
}

/// Saved services or reach settings that differ from this run's captured startup configuration.
/// Saved service changes are a basis for a later bare start, not a promise about repeating explicit constructors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Waiting {
    /// The relay changed.
    pub relay: bool,
    /// The resolver changed.
    pub resolver: bool,
    /// The services added, sorted.
    pub added: Vec<String>,
    /// The services the run serves that the file gives another target, sorted.
    pub changed: Vec<String>,
}

impl Waiting {
    /// Whether nothing waits.
    pub fn is_empty(&self) -> bool {
        !self.relay && !self.resolver && self.added.is_empty() && self.changed.is_empty()
    }

    /// What waits now that did not wait in `said`: each fact is named when it starts to wait, never again
    /// while it goes on waiting.
    fn since(&self, said: &Self) -> Self {
        let new = |now: &[String], said: &[String]| {
            now.iter()
                .filter(|name| !said.contains(name))
                .cloned()
                .collect()
        };
        Self {
            relay: self.relay && !said.relay,
            resolver: self.resolver && !said.resolver,
            added: new(&self.added, &said.added),
            changed: new(&self.changed, &said.changed),
        }
    }
}

impl core::fmt::Display for Waiting {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut lines = Vec::new();
        if self.relay {
            lines.push("the changed relay in serve.toml takes effect at the next start".to_owned());
        }
        if self.resolver {
            lines.push(
                "the changed resolver in serve.toml takes effect at the next start".to_owned(),
            );
        }
        for name in self.added.iter().chain(&self.changed) {
            lines.push(format!(
                "saved service {name} applies to the next bare or --with/--without serve"
            ));
        }
        f.write_str(&lines.join("\n"))
    }
}

// Use the captured cwd for every snapshot, without consulting the current process directory.
fn running(file: &ServeToml, cwd: &Path) -> Option<BTreeMap<String, String>> {
    Started::bare_at(file, cwd)
        .ok()
        .map(|started| targets(&started))
}

/// The names `started` binds, each with its target; an entry with no name binds none.
fn targets(started: &Started) -> BTreeMap<String, String> {
    started
        .entries()
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(name, target)| (name.to_owned(), target.to_owned()))
        })
        .collect()
}

/// The file a [`LiveServeToml`] reads, what it read first, and what it read last.
struct Watched {
    path: PathBuf,
    first: ServeToml,
    state: Mutex<Held>,
}

/// What a [`LiveServeToml`] read last.
struct Held {
    // Every snapshot uses the startup basis, never the watcher's ambient working directory.
    cwd: PathBuf,
    /// The file, as the last good read found it.
    file: ServeToml,
    /// The last accepted saved/default service targets, not the invocation-selected targets. A load
    /// refuses an invalid list and a failed read keeps the last accepted one, so there is always one.
    running: BTreeMap<String, String>,
    /// Captured startup targets and selection origin, absent until routes bind.
    serving: Option<Serving>,
    /// Admission follows read health, never a fabricated change to the accepted file.
    policy: LivePolicy,
    /// The stamp of the file that read came from; `None` re-reads at the next stat.
    stamp: Option<FileStamp>,
    /// When the file was last statted, to debounce the next stat.
    last_stat: Option<Instant>,
}

/// The reason a status carries while the file cannot be read. Fixed and pathless, so it always fits the
/// reply's string cap and a long home path can never fail the whole status.
const UNREADABLE: &str = "serve.toml cannot be read";
const _: () = assert!(UNREADABLE.len() <= crate::serve::control_codec::MAX_STATUS_STRING);

/// Only initial absence permits defaults without a file. Once a file was observed or a read failed,
/// absence cannot establish a valid policy again; recovery requires a successful read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LivePolicy {
    Absent,
    Accepted,
    Failed,
}

impl LiveServeToml {
    /// Read `home`'s `serve.toml` now.
    ///
    /// # Errors
    ///
    /// [`ServeTomlError`] when the file cannot be read, is loose, or is damaged: a `serve` does not start
    /// on a file it cannot read.
    pub fn load(home: &Home) -> Result<Self, ServeTomlError> {
        let cwd = std::env::current_dir().map_err(|source| ServeTomlError::Io {
            path: home.serve_toml(),
            source,
        })?;
        Self::load_at(home, &cwd)
    }

    /// Read `home`'s `serve.toml` now.
    ///
    /// # Errors
    ///
    /// Returns an error if the saved file cannot be read or accepted, or a saved service definition is invalid.
    pub fn load_at(home: &Home, cwd: &Path) -> Result<Self, ServeTomlError> {
        let path = home.serve_toml();
        let read = read_stamped(&path)?;
        Self::from_read(path, read, cwd)
    }

    // Complete syntax establishes health; a stamp only controls when to read again.
    fn from_read(
        path: PathBuf,
        read: Option<(ServeToml, Option<FileStamp>)>,
        cwd: &Path,
    ) -> Result<Self, ServeTomlError> {
        let (file, stamp, policy) = match read {
            Some((file, stamp)) => (file, stamp, LivePolicy::Accepted),
            None => (ServeToml::default(), None, LivePolicy::Absent),
        };
        let started = Started::bare_at(&file, cwd)?;
        let running = targets(&started);
        Ok(Self {
            shared: Arc::new(Watched {
                first: file.clone(),
                state: Mutex::new(Held {
                    cwd: cwd.to_owned(),
                    file,
                    running,
                    serving: None,
                    policy,
                    stamp,
                    last_stat: Some(Instant::now()),
                }),
                path,
            }),
        })
    }

    /// The first file read supplies saved/default services for a bare start, plus relay and resolver
    /// settings; explicit constructors supply invocation-selected services.
    pub fn first_read(&self) -> &ServeToml {
        &self.shared.first
    }

    /// The file as held now, re-read first when it changed.
    pub fn held(&self) -> ServeToml {
        self.refreshed().file.clone()
    }

    /// The last accepted saved/default service targets, not the invocation-selected targets.
    /// None when no valid service list is available; explicit launch never repairs it.
    pub fn saved_services(&self) -> Option<Started> {
        let held = self.refreshed();
        if held.policy == LivePolicy::Failed {
            return None;
        }
        Started::bare_at(&held.file, &held.cwd).ok()
    }

    /// The services off now, sorted.
    pub fn off(&self) -> Vec<String> {
        self.refreshed().file.off.iter().cloned().collect()
    }

    /// The refused service names, sorted: saved off names, removed bound services, and all bound user
    /// services while live policy is unreadable. Retained configuration and saved off marks are unchanged.
    pub fn refused(&self) -> Vec<String> {
        self.refreshed().refused()
    }

    /// What the status reports as off: [`refused`](Self::refused), or unknown while the file cannot be
    /// read. Then the gate refuses every service this run bound, and naming them all as off would send
    /// the user to turn on a service the gate goes on refusing. Decided under one refreshed hold, so the
    /// report and the gate never straddle a read.
    pub fn disabled(&self) -> crate::serve::control_codec::DisabledList {
        use crate::serve::control_codec::DisabledList;

        let held = self.refreshed();
        match held.policy {
            LivePolicy::Failed => DisabledList::Unknown(UNREADABLE.to_owned()),
            LivePolicy::Absent | LivePolicy::Accepted => DisabledList::Known(held.refused()),
        }
    }

    /// Capture started's bound targets and selection origin once routes bind, before the first stream.
    /// Refresh saved policy without saving or replacing service entries.
    pub fn serving(&self, started: &Started) {
        let mut held = self.lock();
        held.stamp = None;
        held.last_stat = None;
        self.refresh(&mut held);
        held.serving = Some(Serving {
            bound: targets(started),
            selection: match started {
                Started::Named(_) | Started::Adjusted(_) => Selection::Invocation,
                Started::Resumed(_) | Started::Default => Selection::Saved,
            },
            relay: held.file.relay.clone(),
            resolver: held.file.resolver.clone(),
        });
    }

    // Startup pairs and refusal bits are serialized while this single refreshed guard is held.
    pub(crate) fn local_service_snapshot(
        &self,
    ) -> Result<
        crate::serve::control_codec::LocalServiceSnapshot,
        crate::serve::control_codec::LocalDetailError,
    > {
        use crate::serve::control_codec::{LocalDetailError, LocalServiceSnapshot};

        let held = self.refreshed();
        let serving = held
            .serving
            .as_ref()
            .ok_or(LocalDetailError::MissingStartup)?;
        LocalServiceSnapshot::capture(
            serving
                .bound
                .iter()
                .map(|(name, target)| (name.as_str(), target.as_str(), held.refuses(name))),
        )
    }

    /// Saved services or reach settings that differ from this run's captured startup configuration.
    /// Saved service changes are a basis for a later bare start, not a promise about repeating explicit constructors.
    pub fn waiting(&self) -> Waiting {
        let held = self.refreshed();
        let Some(serving) = &held.serving else {
            return Waiting::default();
        };
        Waiting {
            relay: held.file.relay != serving.relay,
            resolver: held.file.resolver != serving.resolver,
            added: held
                .running
                .iter()
                .filter(|(name, _)| !serving.bound.contains_key(*name))
                .map(|(name, _)| name.clone())
                .collect(),
            changed: held
                .running
                .iter()
                .filter(|(name, target)| {
                    serving
                        .bound
                        .get(*name)
                        .is_some_and(|bound| bound != *target)
                })
                .map(|(name, _)| name.clone())
                .collect(),
        }
    }

    /// Check the file every [`CHECK_EVERY`], for as long as the run lasts, and hand `say` only what newly
    /// waits each time, so a change the run cannot apply is named once, when it is made.
    pub async fn watch(&self, mut say: impl FnMut(&Waiting)) {
        // What already differs at the start is the selection the banner shows, never a change: an explicit
        // start differs from the saved list, or the defaults, from its first moment.
        let mut said = self.waiting();
        loop {
            tokio::time::sleep(CHECK_EVERY).await;
            let waiting = self.waiting();
            let news = waiting.since(&said);
            if !news.is_empty() {
                say(&news);
            }
            said = waiting;
        }
    }

    /// The held state, re-read first when the file changed.
    fn refreshed(&self) -> MutexGuard<'_, Held> {
        let mut state = self.lock();
        self.refresh(&mut state);
        state
    }

    /// The held state, as it is.
    fn lock(&self) -> MutexGuard<'_, Held> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Re-read the file when its stamp changed, at most once per [`STAT_DEBOUNCE`]. Failures keep
    /// accepted data but deny new bound user admissions until a valid read, not merely a successful stat.
    // `core::io::ErrorKind` is still unstable, as in `read_stamped`.
    #[allow(clippy::std_instead_of_core)]
    fn refresh(&self, state: &mut Held) {
        if state
            .last_stat
            .is_some_and(|last| last.elapsed() < STAT_DEBOUNCE)
        {
            return;
        }
        state.last_stat = Some(Instant::now());
        let path = &self.shared.path;
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound
                    || state.policy != LivePolicy::Absent
                {
                    // A recovered stat may have the same stamp. Only a new read restores admission.
                    let error = ServeTomlError::Io {
                        path: path.clone(),
                        source: error,
                    };
                    state.fail(path, &error, None);
                }
                return;
            }
        };
        let statted = FileStamp::of(&meta);
        if FileStamp::unchanged(state.stamp, statted) {
            return;
        }
        state.take(path, read_stamped(path), statted);
    }
}

impl Held {
    /// Only a valid read of an existing file replaces accepted data and restores admission. A file
    /// removed after stat is a failure too, never a request to restore defaults. Rejected contents are
    /// marked as read until they change; other failures retry at the next stat.
    fn take(
        &mut self,
        path: &Path,
        read: Result<Option<(ServeToml, Option<FileStamp>)>, ServeTomlError>,
        statted: Option<FileStamp>,
    ) {
        let read = read.and_then(|read| {
            read.map(|(file, stamp)| match running(&file, &self.cwd) {
                Some(running) => Ok((file, running, stamp)),
                None => Err(ServeTomlError::Damaged {
                    path: path.to_owned(),
                }),
            })
            .transpose()
        });
        match read {
            Ok(Some((file, running, stamp))) => {
                self.file = file;
                self.running = running;
                self.stamp = stamp;
                if self.policy == LivePolicy::Failed {
                    tracing::warn!(path = %EscapedPath(path), "serve.toml can be read again");
                }
                self.policy = LivePolicy::Accepted;
            }
            Ok(None) => {
                let error = ServeTomlError::Io {
                    path: path.to_owned(),
                    source: io::ErrorKind::NotFound.into(),
                };
                self.fail(path, &error, None);
            }
            Err(error) => {
                let stamp = if matches!(
                    error,
                    ServeTomlError::Damaged { .. } | ServeTomlError::Unusable { .. }
                ) {
                    statted
                } else {
                    None
                };
                self.fail(path, &error, stamp);
            }
        }
    }

    /// Keep what was held and refuse every service this run bound until a read succeeds. `stamp` marks
    /// the file as read, or `None` reads it again at the next stat. Said once, when reads start failing:
    /// a failure that retries at every stat would otherwise log every [`STAT_DEBOUNCE`], and a different
    /// failure while still failing changes nothing the gate does.
    fn fail(&mut self, path: &Path, error: &ServeTomlError, stamp: Option<FileStamp>) {
        self.stamp = stamp;
        if self.policy != LivePolicy::Failed {
            tracing::warn!(
                path = %EscapedPath(path),
                %error,
                "serve.toml cannot be read; new connections to the services this serve bound are refused until it can"
            );
        }
        self.policy = LivePolicy::Failed;
    }

    /// The names the gate refuses, sorted: those off, and those it refuses of the ones this run bound.
    fn refused(&self) -> Vec<String> {
        let mut refused = self.file.off.clone();
        refused.extend(
            self.serving
                .iter()
                .flat_map(|serving| serving.bound.keys())
                .filter(|name| self.refuses(name))
                .cloned(),
        );
        refused.into_iter().collect()
    }
}

impl Held {
    /// Off policy and failed live policy refuse new user-service admissions in both modes.
    /// Saved membership removal additionally refuses configuration-following routes, never invocation-selected membership.
    /// No saved edit constructs a route; internal control routes remain separate.
    fn refuses(&self, name: &str) -> bool {
        self.file.off.contains(name)
            || self.serving.as_ref().is_some_and(|serving| {
                serving.bound.contains_key(name)
                    && (self.policy == LivePolicy::Failed
                        || matches!(serving.selection, Selection::Saved)
                            && !self.running.contains_key(name))
            })
    }
}

impl EnabledServices for LiveServeToml {
    /// Refuse a service turned off, and every service the run serves while the file cannot be read. A run
    /// that follows the saved file also refuses one `services` no longer runs; a run that named its
    /// services does not. Never opens one: a service added to the file has no route until the next `serve`.
    fn is_enabled(&self, service: &Service) -> bool {
        !self.refreshed().refuses(service.as_str())
    }
}

#[cfg(test)]
#[path = "serve_toml_tests.rs"]
mod serve_toml_tests;
