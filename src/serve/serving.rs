//! What a `serve` serves when it starts: the services it was given, the list this home last served, or
//! the default.
//!
//! The list is the `services` of `<home>/serve.toml`, one service form per entry. Only the services are
//! kept: `--public`, `--public-unsafe`, `--admit` and `--expires` apply to the run that types them, so a
//! restart never opens a service to anyone the person did not open it to again. Each entry is read by the
//! service-entry parser, never by the flag parser, so an entry cannot become a flag.

use std::path::{Path, PathBuf};

use super::{DEFAULT_SERVICES, service_entry};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::serve_toml::{ServeToml, ServeTomlError};

/// The targets whose argument is a path on this machine: stored absolute, because a service manager
/// starts `serve` in a different directory than the shell that named them.
const PATH_SCHEMES: [&str; 4] = ["recv", "unix", "file", "fifo"];

/// Why the services a `serve` starts with could not be settled.
#[derive(Debug, thiserror::Error)]
pub enum ServingError {
    /// An entry of the services `<home>/serve.toml` keeps is not a service form, a flag above all: it is
    /// refused, never spliced into the command line.
    #[error(
        "{} has a line that is not a service: {line}. Name the services: swoosh serve ssh ping …",
        EscapedPath(path)
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
         not UTF-8.",
        entry.escape_debug(),
        EscapedPath(path)
    )]
    CannotSave {
        /// The file the list is saved in.
        path: PathBuf,
        /// The service, paths made absolute.
        entry: String,
    },
    /// `<home>/serve.toml` could not be read or written.
    #[error(transparent)]
    File(#[from] ServeTomlError),
}

/// The services a `serve` starts with, and where they came from: the banner says which, and only a named
/// list is recorded for the next bare `serve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// Named on this run's command line, paths made absolute.
    Named(Vec<String>),
    /// Nothing named: the list this home last started with.
    Resumed(Vec<String>),
    /// Nothing named and nothing recorded: the default, `ping` and `speed`.
    Default,
}

impl Started {
    /// Settle what a `serve` under `home` starts with: `named` (already through the service-entry parser)
    /// with its paths made absolute against `cwd`, else the recorded list, else the default.
    pub fn of(named: &[String], home: &Home, cwd: &Path) -> Result<Self, ServingError> {
        let path = home.serve_toml();
        if !named.is_empty() {
            let cannot_save = |entry: String| ServingError::CannotSave {
                path: path.clone(),
                entry,
            };
            return named
                .iter()
                .map(|entry| {
                    let kept = absolute(entry, cwd).map_err(|()| cannot_save(entry.clone()))?;
                    if kept.chars().any(char::is_control) || kept.trim() != kept {
                        return Err(cannot_save(kept));
                    }
                    Ok(kept)
                })
                .collect::<Result<_, _>>()
                .map(Self::Named);
        }
        let mut entries = Vec::new();
        for line in ServeToml::read(home)?.services {
            let not_a_service = || ServingError::NotAService {
                path: path.clone(),
                line: line.clone(),
            };
            if line.starts_with('-') {
                return Err(not_a_service());
            }
            entries.push(service_entry(&line).map_err(|_| not_a_service())?);
        }
        if entries.is_empty() {
            return Ok(Self::Default);
        }
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

    /// Whether this run serves what the home last served, for the banner's "(as last time)".
    pub fn is_resumed(&self) -> bool {
        matches!(self, Self::Resumed(_))
    }

    /// Record a named list as what the next bare `serve` under `home` resumes. Called only after the
    /// routes bound, so a start that fails leaves the record as it was; a resumed or default start
    /// writes nothing. Under `home.lock`, which the caller holds.
    ///
    /// # Errors
    ///
    /// [`ServingError::File`] when the list could not be written.
    pub fn record(&self, home_lock: &HomeWrite, home: &Home) -> Result<(), ServingError> {
        let Self::Named(entries) = self else {
            return Ok(());
        };
        ServeToml::update(home_lock, home, |file| file.services.clone_from(entries))?;
        Ok(())
    }
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
