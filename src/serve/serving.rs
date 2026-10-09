//! What a `serve` serves when it starts: the services it was given, the list this home last served, or
//! the default.
//!
//! The list is the `services` of `<home>/serve.toml`, one service form per entry. Only the services are
//! kept: `--public`, `--public-unsafe`, `--admit` and `--expires` apply to the run that types them, so a
//! restart never opens a service to anyone the person did not open it to again. Each entry is read by the
//! service-entry parser, never by the flag parser, so an entry cannot become a flag.
//!
//! A named `serve` replaces the whole list; `service add` and `service rm` edit one entry of it. The list is
//! keyed by name: every writer refuses a list that names one service twice, so what is recorded, what the
//! router binds and what a link is checked against ([`BoundTargets`](super::BoundTargets)) are one map.
//! The default (`ping`, `speed`) is what a home that never named a list serves; a list emptied by
//! `service rm` stays empty, so the default never comes back on its own.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::{DEFAULT_SERVICES, service_entry};
use crate::escape::{Escaped, EscapedPath};
use crate::home::Home;
use crate::serve_toml::ServeToml;

/// The targets whose argument is a path on this machine: stored absolute, because a service manager
/// starts `serve` in a different directory than the shell that named them.
const PATH_SCHEMES: [&str; 4] = ["recv", "unix", "file", "fifo"];

/// Why the services a `serve` starts with could not be settled.
#[derive(Debug, thiserror::Error)]
pub enum ServingError {
    /// An entry of the services `<home>/serve.toml` keeps is not a service form, a flag above all: it is
    /// refused, never spliced into the command line. Only a hand edit puts it there, and `service rm` would
    /// refuse the same file, so the line points at the file and names no command.
    #[error(
        "{} lists {}, which is not a service\n  Edit that file to fix or remove the entry.",
        EscapedPath(path),
        line.escape_debug()
    )]
    NotAService {
        /// The file the entry was read from.
        path: PathBuf,
        /// The entry, as it is in the file.
        line: String,
    },
    /// A named service that one entry of `<home>/serve.toml` cannot hold as it is: a control character or
    /// a space at either end would not read back as it was typed, and a path that is not UTF-8 would be
    /// saved as a different path. It is refused, and nothing is saved.
    #[error(
        "{} cannot be saved in {}: it has a control character, a space at either end, or a path that is \
         not UTF-8",
        entry.escape_debug(),
        EscapedPath(path)
    )]
    CannotSave {
        /// The file the list is saved in.
        path: PathBuf,
        /// The service, paths made absolute.
        entry: String,
    },
    /// The list `<home>/serve.toml` keeps names a service twice. No writer saves such a list, so the file
    /// was changed by hand: the router would refuse the second and a link check would keep only one of
    /// them, and which one was meant is the person's call, so nothing starts or is saved until they make it.
    #[error(
        "{name} is named twice in {}\n  Each service needs its own name; swoosh will not guess which one to \
         keep.",
        EscapedPath(path)
    )]
    Twice {
        /// The name given twice.
        name: String,
        /// The file that names it twice.
        path: PathBuf,
    },
    /// The services typed on this command line cannot be one list.
    #[error(transparent)]
    Mistyped(#[from] Mistyped),
}

/// Why the services typed on one command line cannot be one list: a usage error, found before anything is
/// read, written or bound.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Mistyped {
    /// One name typed twice: the list is keyed by name, and keeping either would drop the other unseen.
    #[error("{} is named twice; each service needs its own name", Escaped(.0))]
    Twice(String),
    /// An entry with no name, which the list cannot be keyed by: a target with none (`tcp:localhost:3000`),
    /// or a word that is no service swoosh knows (`db`) and so needs a target. The example fills the
    /// missing half, so the line serves `serve` and `service add` alike and names neither.
    #[error("{}", unnamed(.0))]
    Unnamed(String),
}

impl Mistyped {
    /// Refuse typed `entries` (each through the service-entry parser) that hold an entry with no name, or
    /// name one service twice.
    ///
    /// # Errors
    ///
    /// [`Mistyped::Unnamed`] for the first entry with no name, else [`Mistyped::Twice`] for the first name
    /// typed twice.
    pub fn check(entries: &[String]) -> Result<(), Self> {
        if let Some(entry) = entries.iter().find(|entry| !entry.contains('=')) {
            return Err(Self::Unnamed(entry.clone()));
        }
        Self::check_names(names(entries))
    }

    /// Refuse typed `names` that hold one name twice.
    ///
    /// # Errors
    ///
    /// [`Mistyped::Twice`] for the first name typed twice.
    pub fn check_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<(), Self> {
        match twice(names) {
            Some(name) => Err(Self::Twice(name.to_owned())),
            None => Ok(()),
        }
    }
}

/// The line for an entry with no name: one holding a `:` is a target missing its name, any other a name
/// missing its target. The entry was typed, so it prints through the escaper.
pub fn unnamed(entry: &str) -> String {
    let shown = Escaped(entry);
    if entry.contains(':') {
        format!("{shown} needs a name, like web={shown}")
    } else {
        format!("{shown} needs a target, like {shown}=tcp:<address>:<port>")
    }
}

/// Why `service add` or `service rm` changed nothing.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// The list could not be read or the new list could not be saved.
    #[error(transparent)]
    Serving(#[from] ServingError),
    /// `add` was given a new target under a name already listed. A name is never pointed elsewhere by an
    /// add: a link made for the old target would follow it, so the move is a `rm` then an `add`.
    #[error("{name} already serves {held} here")]
    Retarget {
        /// The listed name.
        name: String,
        /// The target it serves now.
        held: String,
        /// The entry `add` was given.
        asked: String,
    },
    /// `rm` was given a name the list does not hold.
    #[error("{0} is not listed here")]
    NotListed(String),
}

/// What `service add` found for one entry it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    /// Not listed before: it is now.
    New(String),
    /// Listed already, with this very target: nothing changed.
    Listed(String),
    /// Listed already, with this very target, and turned off: an add changes the list, never whether a
    /// listed service answers, so it stays off.
    ListedOff(String),
}

/// What a named `serve` changed in the list it replaced: the entries it no longer serves, and the names it
/// kept with another target. Empty when the home recorded no list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Replaced {
    /// The recorded entries the new list drops, as a bare start reads them.
    pub dropped: Vec<String>,
    /// Each kept name whose target changed: the name, the new target, the old one.
    pub retargeted: Vec<(String, String, String)>,
}

/// The services a `serve` starts with, and where they came from: the banner says which, and only a named
/// list is recorded for the next bare `serve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// Named on this run's command line, paths made absolute.
    Named(Vec<String>),
    /// Nothing named: the list this home records, as the last named `serve`, `service add` or `service rm`
    /// left it. It may be empty: a list emptied by `service rm` serves nothing, never the default.
    Resumed(Vec<String>),
    /// Nothing named and no list recorded: the default, `ping` and `speed`.
    Default,
}

impl Started {
    /// Settle what a `serve` under `home` starts with: `named` (already through the service-entry parser)
    /// with its paths made absolute against `cwd`, else the list `kept` (the home's `serve.toml`, as the
    /// run's one watcher read it) records, else the default.
    ///
    /// # Errors
    ///
    /// [`ServingError::Mistyped`] when the named services hold one with no name or name one twice,
    /// [`ServingError::CannotSave`] when one cannot be saved as typed, and the errors of
    /// [`bare`](Self::bare) when nothing is named.
    pub fn of(
        named: &[String],
        kept: &ServeToml,
        home: &Home,
        cwd: &Path,
    ) -> Result<Self, ServingError> {
        let path = home.serve_toml();
        if !named.is_empty() {
            Mistyped::check(named)?;
            let named = named
                .iter()
                .map(|entry| saved(entry, cwd, &path))
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Self::Named(named));
        }
        Self::bare(kept, &path)
    }

    /// What a bare `serve` starts with from `kept`, the `serve.toml` at `path`: the list it records, else
    /// the default. A running `serve` asks this of each later read too, for the services that file runs,
    /// and `share` asks it for what a name serves.
    ///
    /// # Errors
    ///
    /// [`ServingError::NotAService`] when `kept` lists something that is not a service form (a flag, or an
    /// entry with no name or no target), and [`ServingError::Twice`] when it names one service twice: no writer saves such a list, so a file
    /// that holds one was changed by hand, and a start refuses it rather than guess which one was meant.
    pub fn bare(kept: &ServeToml, path: &Path) -> Result<Self, ServingError> {
        let Some(listed) = &kept.services else {
            return Ok(Self::Default);
        };
        let mut entries = Vec::new();
        for line in listed {
            let not_a_service = || ServingError::NotAService {
                path: path.to_owned(),
                line: line.clone(),
            };
            if line.starts_with('-') {
                return Err(not_a_service());
            }
            let entry = service_entry(line).map_err(|_| not_a_service())?;
            // The parser passes a nameless form through for a typed line to teach (`db`, `tcp:…`); in the
            // file nothing was typed, so it is the file's fault, never a usage error.
            if !entry.contains('=') {
                return Err(not_a_service());
            }
            entries.push(entry);
        }
        once(&entries, path)?;
        Ok(Self::Resumed(entries))
    }

    /// The service forms this run binds.
    pub fn entries(&self) -> Vec<String> {
        match self {
            Self::Named(entries) | Self::Resumed(entries) => entries.clone(),
            Self::Default => DEFAULT_SERVICES
                .iter()
                .map(|&entry| entry.to_owned())
                .collect(),
        }
    }

    /// The names this run's services are bound under, in their order; an entry with no name binds none.
    pub fn names(&self) -> Vec<String> {
        self.entries()
            .iter()
            .filter_map(|entry| entry.split_once('=').map(|(name, _)| name.to_owned()))
            .collect()
    }

    /// What this start changes in the list `kept` records: the entries a named list drops, and the names it
    /// keeps under another target. A resumed or default start changes nothing, and neither does a named one
    /// on a home that recorded no list.
    ///
    /// "Listed" means two things in this module, on purpose. Here it is only what was recorded: these lines
    /// report undoing something the person named, and on a home that never named a list nothing was, so a
    /// first `serve ssh` says nothing about the default it replaces. [`record`](Self::record),
    /// [`ServeToml::add`] and [`ServeToml::remove`] count the default as listed instead (the list as
    /// [`bare`](Self::bare) reads it): a start must fail closed on an `off` row, and an add must never
    /// remove.
    ///
    /// The recorded list is read as [`bare`](Self::bare) reads `kept`, the `serve.toml` at `path`, so a
    /// hand-written `ping` a named start drops is reported like any other entry. A list `bare` refuses
    /// holds nothing that can be read, so nothing is reported from it.
    pub fn replaces(&self, kept: &ServeToml, path: &Path) -> Replaced {
        let (Self::Named(entries), Ok(Self::Resumed(recorded))) = (self, Self::bare(kept, path))
        else {
            return Replaced::default();
        };
        let mut replaced = Replaced::default();
        for old in &recorded {
            // Every entry `bare` keeps has its name.
            let Some((name, was)) = old.split_once('=') else {
                continue;
            };
            match entries.iter().find_map(|entry| target(entry, name)) {
                None => replaced.dropped.push(old.clone()),
                Some(now) if now != was => {
                    replaced
                        .retargeted
                        .push((name.to_owned(), now.to_owned(), was.to_owned()));
                }
                Some(_) => {}
            }
        }
        replaced
    }

    /// Record a named list in `file` as what the next bare `serve` resumes, replacing the list it held, and
    /// turn back on only the names it adds. A start never clears `off` for a name the list already held: a
    /// service manager restarts `serve` on any exit, and any of your devices may stop it, so clearing every
    /// name a start carries would let a stop, or a reboot, undo an off typed at this machine. A restart
    /// never widens what this machine serves past its last explicit act. A resumed or default start changes
    /// neither. Applied inside the one [`ServeToml::update`] a start makes once its routes bound, so a start
    /// that fails writes nothing.
    ///
    /// What the list held is read as [`bare`](Self::bare) reads `file`, the `serve.toml` at `path`, so a
    /// hand-written `ping` holds `ping` here as it does for a bare start and every `service` edit. A list
    /// `bare` refuses holds nothing that can be read, so every `off` row stays: the start fails closed.
    pub fn record(&self, file: &mut ServeToml, path: &Path) {
        let Self::Named(entries) = self else {
            return;
        };
        if let Ok(held) = Self::bare(file, path).map(|held| held.names()) {
            let held: BTreeSet<String> = held.into_iter().collect();
            for name in names(entries) {
                if !held.contains(name) {
                    file.off.remove(name);
                }
            }
        }
        file.services = Some(entries.clone());
    }
}

impl ServeToml {
    /// `service add`: add `entries` (each through the service-entry parser, paths made absolute against
    /// `cwd`) to the list, which is the `serve.toml` at `path`, and say what each one found. All or nothing:
    /// one entry refused changes nothing. It starts from the list as a bare `serve` would start it
    /// ([`Started::bare`]): the default on a home that never recorded one, so what a bare `serve` served
    /// stays served, and a list a start would refuse is refused here too, never written on top of. A name
    /// already listed is never pointed elsewhere, and an add never turns a listed service back on.
    ///
    /// # Errors
    ///
    /// [`EditError`] when an entry has no name, cannot be saved as typed, is given twice, or names a listed
    /// service with another target, or when the list holds an entry that is not a service or names one
    /// service twice.
    pub fn add(
        &mut self,
        entries: &[String],
        cwd: &Path,
        path: &Path,
    ) -> Result<Vec<Added>, EditError> {
        Mistyped::check(entries).map_err(ServingError::from)?;
        let mut list = Started::bare(self, path)?.entries();
        let mut found = Vec::new();
        let mut fresh = Vec::new();
        for entry in entries {
            let entry = saved(entry, cwd, path)?;
            // Checked above: every typed entry has its name.
            let Some((name, asked)) = entry.split_once('=') else {
                continue;
            };
            match list.iter().find_map(|held| target(held, name)) {
                Some(held) if held == asked => found.push(if self.off.contains(name) {
                    Added::ListedOff(name.to_owned())
                } else {
                    Added::Listed(name.to_owned())
                }),
                Some(held) => {
                    return Err(EditError::Retarget {
                        name: name.to_owned(),
                        held: held.to_owned(),
                        asked: entry.clone(),
                    });
                }
                None => {
                    found.push(Added::New(name.to_owned()));
                    fresh.push(entry.clone());
                }
            }
        }
        // No name repeats: each fresh one is typed once and is not on the list.
        list.extend(fresh);
        if found.iter().any(|added| matches!(added, Added::New(_))) {
            self.services = Some(list);
        }
        Ok(found)
    }

    /// `service rm`: take `names` off the list, and with each its `off` row, which would otherwise outlive
    /// the service it was for. All or nothing: a name the list does not hold changes nothing. It starts from
    /// the list as a bare `serve` would start it, as [`add`](Self::add) does: the default on a home that never
    /// recorded one. An emptied list stays empty.
    ///
    /// # Errors
    ///
    /// [`EditError::NotListed`] when a name is not on the list, and [`ServingError`] when a name is typed
    /// twice or the list at `path` holds an entry that is not a service or names one service twice.
    pub fn remove(&mut self, names: &[nauthy::Service], path: &Path) -> Result<(), EditError> {
        Mistyped::check_names(names.iter().map(nauthy::Service::as_str))
            .map_err(ServingError::from)?;
        let mut list = Started::bare(self, path)?.entries();
        for name in names {
            let name = name.as_str();
            let before = list.len();
            list.retain(|entry| target(entry, name).is_none());
            if list.len() == before {
                return Err(EditError::NotListed(name.to_owned()));
            }
        }
        for name in names {
            self.off.remove(name.as_str());
        }
        self.services = Some(list);
        Ok(())
    }
}

/// `entry` as the list saves it: its path made absolute against `cwd`, refused when it would not read back
/// as typed from the `serve.toml` at `path`.
fn saved(entry: &str, cwd: &Path, path: &Path) -> Result<String, ServingError> {
    let cannot_save = |entry: String| ServingError::CannotSave {
        path: path.to_owned(),
        entry,
    };
    let saved = absolute(entry, cwd).map_err(|()| cannot_save(entry.to_owned()))?;
    if saved.chars().any(char::is_control) || saved.trim() != saved {
        return Err(cannot_save(saved));
    }
    Ok(saved)
}

/// The target `entry` serves under `name`, or `None` when it serves another name or none.
fn target<'a>(entry: &'a str, name: &str) -> Option<&'a str> {
    entry
        .split_once('=')
        .and_then(|(held, target)| (held == name).then_some(target))
}

/// The names `entries` are bound under, in their order; an entry with no name binds none.
fn names(entries: &[String]) -> impl Iterator<Item = &str> {
    entries
        .iter()
        .filter_map(|entry| entry.split_once('=').map(|(name, _)| name))
}

/// Refuse the list the `serve.toml` at `path` keeps when it names one service twice, before the router or
/// the link check sees it: the router refuses the second, and the link check would keep only the last, so
/// the two would disagree.
fn once(entries: &[String], path: &Path) -> Result<(), ServingError> {
    match twice(names(entries)) {
        Some(name) => Err(ServingError::Twice {
            name: name.to_owned(),
            path: path.to_owned(),
        }),
        None => Ok(()),
    }
}

/// The first name `names` holds a second time.
fn twice<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let mut seen = BTreeSet::new();
    names.into_iter().find(|name| !seen.insert(*name))
}

/// `entry` with a path argument made absolute against `cwd`: `drop=recv:.` becomes `drop=recv:<cwd>/.` and
/// `logs=file:app.log` becomes `logs=file:<cwd>/app.log`. A `~/…` path is relative like any other, since
/// nothing expands it when the service binds. `inbox=recv:` is kept as typed: it saves into the inbox, never
/// the cwd. Raw `stdin:` and every non-path target are kept as typed.
/// `Err` when the joined path is not UTF-8, so it cannot be saved as the path it names.
fn absolute(entry: &str, cwd: &Path) -> Result<String, ()> {
    let Some((name, target)) = entry.split_once('=') else {
        return Ok(entry.to_owned());
    };
    let Some((scheme, rest)) = target.split_once(':') else {
        return Ok(entry.to_owned());
    };
    if !PATH_SCHEMES.contains(&scheme)
        || Path::new(rest).is_absolute()
        || (scheme == super::RECV_SCHEME && rest.is_empty())
    {
        return Ok(entry.to_owned());
    }
    let path = if rest.is_empty() {
        cwd.to_owned()
    } else {
        cwd.join(rest)
    };
    let path = path.to_str().ok_or(())?;
    Ok(format!("{name}={scheme}:{path}"))
}

#[cfg(test)]
#[path = "serve_serving_tests.rs"]
mod serving_tests;
