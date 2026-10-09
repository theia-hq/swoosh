//! `<home>/serve.toml`: what `serve` runs. One file holds the services a bare `serve` resumes, the
//! services turned off, the relay this machine is reached through and the resolver it publishes to.
//!
//! Every writer changes it under `home.lock`, re-reading it first and keeping the fields it does not set:
//! a `serve` that names its services (once its routes bind), `service add|rm`, `service on|off`, and `serve
//! --relay` or `--resolver`. A person is not meant to open it.
//!
//! A running `serve` reads the file through one [`LiveServeToml`], from its start to its end: the services
//! it starts with, the relay and the resolver it binds over, and the services off all come from that one
//! watcher's first read, and every later read is that watcher's too, so no two parts of a `serve` ever
//! hold the file as read at two different moments. Its gate refuses a service turned off and serves one
//! turned back on, with no restart, and its status reports the same set the gate refuses. A file that
//! goes missing or cannot be read keeps everything read last, so deleting the file never turns a service
//! back on.
//!
//! A running `serve` takes service away live and gives it only when it starts, where its routes are
//! proven and its banner says what it serves. So a service dropped from `services` is refused on its next
//! stream, as one turned off is, while a service added or retargeted there, and a changed relay or
//! resolver, wait for the next `serve`; the watcher names what waits ([`Waiting`]) so the run can say so
//! once.

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
    /// The services a bare `serve` starts, paths made absolute, in order: as the last `serve` that named its
    /// services gave them, edited since by `service add` and `service rm`. `None` on a home that never
    /// named any, which serves the default; `Some` and empty once `service rm` took the last one, which
    /// serves nothing, so the default never returns on its own.
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
        Ok(read_stamped(&home.serve_toml())?.0)
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

/// Read and decode the file at `path` and its stamp from one open handle, checked as a trust file. An
/// absent file holds nothing and has no stamp.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn read_stamped(path: &Path) -> Result<(ServeToml, Option<FileStamp>), ServeTomlError> {
    let io = |source| ServeTomlError::Io {
        path: path.to_owned(),
        source,
    };
    let mut file = match crate::home::open_trust_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((ServeToml::default(), None));
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
    Ok((read, stamp))
}

/// `<home>/serve.toml`, read live: the one watcher a running `serve` reads the file through. It holds the
/// whole file. The gate asks it on every stream which services are off (it is the [`EnabledServices`]
/// the exposer consults), the status reports the same set, and the run's start takes its services, relay
/// and resolver from its first read. Cloning shares one instance, so no two readers ever disagree about a
/// file they each read at a different moment.
///
/// It re-stats the file at most once per [`STAT_DEBOUNCE`] and re-reads it when its [`FileStamp`] (mtime,
/// length, inode and ctime) changed, so a same-length rewrite renamed into place is seen. A file that goes
/// missing, cannot be read, or is damaged keeps everything read last.
#[derive(Clone)]
pub struct LiveServeToml {
    shared: Arc<Watched>,
}

/// What a running `serve` serves, fixed when its routes bound: what a later read is held against.
struct Serving {
    /// The names its services are bound under, each with its target. Only these are refused for leaving
    /// `services`: the node's own routes are bound by no entry.
    bound: BTreeMap<String, String>,
    /// The relay the file held once the run saved what it was told, which is the one it bound.
    relay: Option<RelayUrl>,
    /// The resolver, likewise.
    resolver: Option<ResolverUrl>,
}

/// What `serve.toml` holds that a running `serve` applies only when it next starts: a relay or a resolver
/// other than the one it bound, the services it lists that the run does not serve, and the ones it serves
/// under another target. Empty when the file holds nothing the run is not doing.
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
}

impl core::fmt::Display for Waiting {
    /// One line naming each change that waits: "the changed relay and the added service drop in serve.toml
    /// take effect the next time serve starts" (printed after `warning: `).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut items = Vec::new();
        if self.relay {
            items.push("the changed relay".to_owned());
        }
        if self.resolver {
            items.push("the changed resolver".to_owned());
        }
        // Each name passed the service-name parser, so it holds nothing a terminal would act on.
        match self.added.as_slice() {
            [] => {}
            [one] => items.push(format!("the added service {one}")),
            many => items.push(format!("the added services {}", and_list(many))),
        }
        match self.changed.as_slice() {
            [] => {}
            [one] => items.push(format!("the changed service {one}")),
            many => items.push(format!("the changed services {}", and_list(many))),
        }
        let verb = if items.len() == 1 && self.added.len() < 2 && self.changed.len() < 2 {
            "takes"
        } else {
            "take"
        };
        write!(
            f,
            "{} in serve.toml {verb} effect the next time serve starts",
            and_list(&items)
        )
    }
}

/// `items` as a list a sentence reads: "a", "a and b", "a, b and c".
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

/// The names `file`'s services run, each with its target, as a bare `serve` started over the file at `path`
/// would bind them; `None` when it lists a service that is not one.
fn running(file: &ServeToml, path: &Path) -> Option<BTreeMap<String, String>> {
    Started::bare(file, path)
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
    /// The file, as the last good read found it.
    file: ServeToml,
    /// The names `file`'s services run, each with its target, as a bare `serve` would start them (the
    /// default when it never recorded a list). `None` only while the first read lists a service that is not one: a
    /// `serve` that named its services started over such a file, and its own write replaces it.
    running: Option<BTreeMap<String, String>>,
    /// What the run serves, once its routes bound; `None` before, when nothing is refused for leaving
    /// `services` and nothing waits.
    serving: Option<Serving>,
    /// The stamp of the file that read came from; `None` re-reads at the next stat.
    stamp: Option<FileStamp>,
    /// When the file was last statted, to debounce the next stat.
    last_stat: Option<Instant>,
}

impl LiveServeToml {
    /// Read `home`'s `serve.toml` now.
    ///
    /// # Errors
    ///
    /// [`ServeTomlError`] when the file cannot be read, is loose, or is damaged: a `serve` does not start
    /// on a file it cannot read.
    pub fn load(home: &Home) -> Result<Self, ServeTomlError> {
        let path = home.serve_toml();
        let (file, stamp) = read_stamped(&path)?;
        let running = running(&file, &path);
        Ok(Self {
            shared: Arc::new(Watched {
                first: file.clone(),
                state: Mutex::new(Held {
                    file,
                    running,
                    serving: None,
                    stamp,
                    last_stat: Some(Instant::now()),
                }),
                path,
            }),
        })
    }

    /// The file as [`load`](Self::load) read it: what a run starts with and binds over, so the services
    /// it starts and the relay and resolver it binds come from one read, however long its start takes.
    pub fn first_read(&self) -> &ServeToml {
        &self.shared.first
    }

    /// The file as held now, re-read first when it changed.
    pub fn held(&self) -> ServeToml {
        self.refreshed().file.clone()
    }

    /// The services off now, sorted.
    pub fn off(&self) -> Vec<String> {
        self.refreshed().file.off.iter().cloned().collect()
    }

    /// The services the gate refuses now, sorted: those off, and those the run serves that `services` no
    /// longer runs. What the status reports as off, so it and the gate never disagree.
    pub fn refused(&self) -> Vec<String> {
        let held = self.refreshed();
        let mut refused = held.file.off.clone();
        refused.extend(held.removed());
        refused.into_iter().collect()
    }

    /// Hold the file this run just wrote, at once rather than at the next stat, and fix what the run
    /// serves: the names `started` bound with their targets, and the relay and resolver the file now holds. Called once its
    /// routes bound and it saved what it was told, before the first stream, so its own write never reads
    /// as a service removed.
    pub fn serving(&self, started: &Started) {
        let mut held = self.lock();
        held.stamp = None;
        held.last_stat = None;
        self.refresh(&mut held);
        held.serving = Some(Serving {
            bound: targets(started),
            relay: held.file.relay.clone(),
            resolver: held.file.resolver.clone(),
        });
    }

    /// What the file holds now that the run applies only when it next starts.
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
                .flatten()
                .filter(|(name, _)| !serving.bound.contains_key(*name))
                .map(|(name, _)| name.clone())
                .collect(),
            changed: held
                .running
                .iter()
                .flatten()
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

    /// Check the file every [`CHECK_EVERY`], for as long as the run lasts, and hand `say` what waits each
    /// time that changes, so a change the run cannot apply is named once, when it is made.
    pub async fn watch(&self, mut say: impl FnMut(&Waiting)) {
        let mut said = Waiting::default();
        loop {
            tokio::time::sleep(CHECK_EVERY).await;
            let waiting = self.waiting();
            if waiting != said {
                if !waiting.is_empty() {
                    say(&waiting);
                }
                said = waiting;
            }
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

    /// Re-read the file when its stamp changed, at most once per [`STAT_DEBOUNCE`]. Every failure keeps
    /// what was held: a missing file, a failed stat or read, and a damaged file.
    fn refresh(&self, state: &mut Held) {
        if state
            .last_stat
            .is_some_and(|last| last.elapsed() < STAT_DEBOUNCE)
        {
            return;
        }
        state.last_stat = Some(Instant::now());
        let path = &self.shared.path;
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let statted = FileStamp::of(&meta);
        if FileStamp::unchanged(state.stamp, statted) {
            return;
        }
        state.take(path, read_stamped(path), statted);
    }
}

impl Held {
    /// Take one read of the file at `path`, whose stat just gave `statted`. Only a read of a file that is
    /// there replaces what is held: a file removed between the stat and the read reads as absent, and
    /// keeps it, so deleting the file never turns a service back on. A failed read keeps it too, and so
    /// does one whose `services` lists a service that is not one, which a running `serve` treats as damage
    /// rather than as every service removed. A file whose contents are refused is marked as read, so it is
    /// not read again until it changes; any other failure is tried again at the next stat.
    fn take(
        &mut self,
        path: &Path,
        read: Result<(ServeToml, Option<FileStamp>), ServeTomlError>,
        statted: Option<FileStamp>,
    ) {
        let read = read.and_then(|(file, stamp)| match running(&file, path) {
            Some(running) => Ok((file, running, stamp)),
            None => Err(ServeTomlError::Damaged {
                path: path.to_owned(),
            }),
        });
        match read {
            Ok((file, running, Some(stamp))) => {
                self.file = file;
                self.running = Some(running);
                self.stamp = Some(stamp);
            }
            Ok((_, _, None)) => {}
            Err(error) => {
                if matches!(
                    error,
                    ServeTomlError::Damaged { .. } | ServeTomlError::Unusable { .. }
                ) {
                    self.stamp = statted;
                }
                tracing::warn!(
                    path = %EscapedPath(path),
                    %error,
                    "keeping what serve.toml held when it was last read"
                );
            }
        }
    }
}

impl Held {
    /// The names the run serves that the held `services` no longer runs. A name bound by no entry (the
    /// node's own routes) is never among them, and an emptied list runs nothing, so every name it bound is.
    fn removed(&self) -> impl Iterator<Item = String> + '_ {
        self.serving
            .iter()
            .zip(&self.running)
            .flat_map(|(serving, running)| {
                serving
                    .bound
                    .keys()
                    .filter(|name| !running.contains_key(*name))
                    .cloned()
            })
    }

    /// Whether the gate refuses `name`: it is off, or it left `services`.
    fn refuses(&self, name: &str) -> bool {
        self.file.off.contains(name) || self.removed().any(|removed| removed == name)
    }
}

impl EnabledServices for LiveServeToml {
    /// Refuse a service turned off, and one the run serves that `services` no longer runs. Never opens
    /// one: a service added to the file has no route until the next `serve`.
    fn is_enabled(&self, service: &Service) -> bool {
        !self.refreshed().refuses(service.as_str())
    }
}

#[cfg(test)]
#[path = "serve_toml_tests.rs"]
mod serve_toml_tests;
