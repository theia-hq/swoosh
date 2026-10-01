//! `<home>/serve.toml`: what `serve` runs. One file holds the services a bare `serve` resumes, the
//! services turned off, the relay this machine offers and the resolver it publishes to.
//!
//! Every writer changes it under `home.lock`, re-reading it first and keeping the fields it does not set:
//! a `serve` that names its services (once its routes bind), `service on|off`, and `serve --relay` or
//! `--resolver`. A person is not meant to open it.
//!
//! A running `serve` reads which services are off through one [`ServicesOff`], live: its gate refuses a
//! service turned off and serves one turned back on, with no restart, and its status reports the same set
//! the gate refuses. A file that goes missing or cannot be read keeps the set read last, so deleting the
//! file never turns a service back on.

use std::collections::BTreeSet;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use nauthy::{FileStamp, STAT_DEBOUNCE, Service};
use tightbeam::enabled::EnabledServices;

use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::transport::{RelayUrl, ResolverUrl};

/// The most bytes `serve.toml` may hold: far above any list of services, and a bound on what one read of a
/// running `serve` allocates.
pub const MAX_SERVE_TOML: u64 = 64 * 1024;

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
    /// The services the last `serve` that named its services gave, paths made absolute, in its order;
    /// empty when no `serve` named any.
    pub services: Vec<String>,
    /// The services turned off.
    pub off: BTreeSet<String>,
    /// The relay this machine offers, as `serve --relay` gave it.
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
    #[error("{} is damaged", EscapedPath(path))]
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
        let path = home.serve_toml();
        let held = Self::read(home)?;
        let mut next = held.clone();
        change(&mut next);
        if next == held {
            return Ok(());
        }
        crate::config::write_private_atomic(home_lock, &path, next.encode().as_bytes())
            .map_err(|source| ServeTomlError::Io { path, source })
    }

    /// The file's text: each field that holds something, and nothing else.
    fn encode(&self) -> String {
        let mut table = toml::Table::new();
        let list = |items: &mut dyn Iterator<Item = &String>| {
            toml::Value::Array(items.cloned().map(toml::Value::String).collect())
        };
        if !self.services.is_empty() {
            table.insert(SERVICES.to_owned(), list(&mut self.services.iter()));
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

    /// Decode the file's `text`, every field parsed here: a service turned off that is not a service name
    /// is damage, and so is a relay or a resolver that is not a usable URL, named by its key.
    fn decode(text: &str) -> Result<Self, Undecodable> {
        let damaged = |_| Undecodable::Damaged;
        let table: toml::Table = text.parse().map_err(damaged)?;
        let mut read = Self::default();
        for (key, value) in table {
            match key.as_str() {
                SERVICES => read.services = strings(value).ok_or(Undecodable::Damaged)?,
                OFF => {
                    let off = strings(value).ok_or(Undecodable::Damaged)?;
                    if off.iter().any(|name| name.parse::<Service>().is_err()) {
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

/// The services turned off in `<home>/serve.toml`, read live: the [`EnabledServices`] a running `serve`'s
/// gate asks on every stream, and the set its status reports. Cloning shares one instance, so the gate and
/// the status never disagree about a file they each read at a different moment.
///
/// It re-stats the file at most once per [`STAT_DEBOUNCE`] and re-reads it when its [`FileStamp`] (mtime,
/// length, inode and ctime) changed, so a same-length rewrite renamed into place is seen. A file that goes
/// missing, cannot be read, or is damaged keeps the set read last.
#[derive(Clone)]
pub struct ServicesOff {
    shared: Arc<Watched>,
}

/// The file a [`ServicesOff`] reads, and what it read last.
struct Watched {
    path: PathBuf,
    state: Mutex<OffState>,
}

/// What a [`ServicesOff`] read last.
struct OffState {
    /// The services off, as the last good read found them.
    off: BTreeSet<String>,
    /// The stamp of the file that read came from; `None` re-reads at the next stat.
    stamp: Option<FileStamp>,
    /// When the file was last statted, to debounce the next stat.
    last_stat: Option<Instant>,
}

impl ServicesOff {
    /// Read the services off in `home`'s `serve.toml` now.
    ///
    /// # Errors
    ///
    /// [`ServeTomlError`] when the file cannot be read, is loose, or is damaged: a `serve` does not start
    /// on a set it cannot read.
    pub fn load(home: &Home) -> Result<Self, ServeTomlError> {
        let path = home.serve_toml();
        let (read, stamp) = read_stamped(&path)?;
        Ok(Self {
            shared: Arc::new(Watched {
                path,
                state: Mutex::new(OffState {
                    off: read.off,
                    stamp,
                    last_stat: Some(Instant::now()),
                }),
            }),
        })
    }

    /// The services off now, sorted.
    pub fn names(&self) -> Vec<String> {
        self.refreshed().off.iter().cloned().collect()
    }

    /// The held state, re-read first when the file changed.
    fn refreshed(&self) -> MutexGuard<'_, OffState> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        state
    }

    /// Re-read the file when its stamp changed, at most once per [`STAT_DEBOUNCE`]. Every failure keeps the
    /// set: a missing file, a failed stat or read, and a damaged file.
    fn refresh(&self, state: &mut OffState) {
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
        if FileStamp::unchanged(state.stamp, FileStamp::of(&meta)) {
            return;
        }
        match read_stamped(path) {
            Ok((read, stamp)) => {
                state.off = read.off;
                state.stamp = stamp;
            }
            Err(error) => tracing::warn!(
                path = %EscapedPath(path),
                %error,
                "keeping the services off already read"
            ),
        }
    }
}

impl EnabledServices for ServicesOff {
    fn is_enabled(&self, service: &Service) -> bool {
        !self.refreshed().off.contains(service.as_str())
    }
}

#[cfg(test)]
#[path = "serve_toml_tests.rs"]
mod serve_toml_tests;
