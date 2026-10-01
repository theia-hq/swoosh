//! What a `serve` serves when it starts: the services it was given, the list this home last served, or
//! the default.
//!
//! The list is `<home>/serving`, one service form per line. Only the services are kept: `--public`,
//! `--public-unsafe`, `--admit` and `--expires` apply to the run that types them, so a restart never opens
//! a service to anyone the person did not open it to again. Each line is read by the service-entry parser,
//! never by the flag parser, so a line cannot become a flag.

use std::io;
use std::path::{Path, PathBuf};

use super::{DEFAULT_SERVICES, service_entry};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};

/// The targets whose argument is a path on this machine: stored absolute, because a service manager
/// starts `serve` in a different directory than the shell that named them.
const PATH_SCHEMES: [&str; 4] = ["recv", "unix", "file", "fifo"];

/// Why the services a `serve` starts with could not be settled.
#[derive(Debug, thiserror::Error)]
pub enum ServingError {
    /// A line of `<home>/serving` is not a service form, a flag above all: it is refused, never spliced
    /// into the command line.
    #[error(
        "{} has a line that is not a service: {line}. Name the services: swoosh serve ssh ping …",
        EscapedPath(path)
    )]
    NotAService {
        /// The file the line was read from.
        path: PathBuf,
        /// The line, as it is in the file.
        line: String,
    },
    /// A named service that one line of `<home>/serving` cannot hold as it is: a line break would read back
    /// as more services, a space at either end is trimmed on the way back, and a path that is not UTF-8
    /// would be saved as a different path. It is refused, and nothing is saved.
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
    /// `<home>/serving` exists and could not be read or written.
    #[error("could not use {}", EscapedPath(path))]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
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
        let path = home.serving();
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
        let text = match crate::home::read_trust_file(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::Default),
            Err(source) => return Err(ServingError::Io { path, source }),
        };
        let mut entries = Vec::new();
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let not_a_service = || ServingError::NotAService {
                path: path.clone(),
                line: line.to_owned(),
            };
            if line.starts_with('-') {
                return Err(not_a_service());
            }
            entries.push(service_entry(line).map_err(|_| not_a_service())?);
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
    /// [`ServingError::Io`] when the list could not be written.
    pub fn record(&self, home_lock: &HomeWrite, home: &Home) -> Result<(), ServingError> {
        let Self::Named(entries) = self else {
            return Ok(());
        };
        let path = home.serving();
        let mut body = entries.join("\n");
        body.push('\n');
        crate::config::write_private_atomic(home_lock, &path, body.as_bytes())
            .map_err(|source| ServingError::Io { path, source })
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
