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
use crate::home::Home;

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
        path.display()
    )]
    NotAService {
        /// The file the line was read from.
        path: PathBuf,
        /// The line, as it is in the file.
        line: String,
    },
    /// `<home>/serving` exists and could not be read or written.
    #[error("could not use {}", path.display())]
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
        if !named.is_empty() {
            return Ok(Self::Named(
                named.iter().map(|entry| absolute(entry, cwd)).collect(),
            ));
        }
        let path = home.serving();
        let text = match std::fs::read_to_string(&path) {
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
    /// writes nothing.
    pub fn record(&self, home: &Home) -> Result<(), ServingError> {
        let Self::Named(entries) = self else {
            return Ok(());
        };
        let path = home.serving();
        let mut body = entries.join("\n");
        body.push('\n');
        write_atomic(&path, &body).map_err(|source| ServingError::Io { path, source })
    }
}

/// `entry` with a path argument made absolute against `cwd`: `inbox=recv:` becomes `inbox=recv:<cwd>` and
/// `logs=file:app.log` becomes `logs=file:<cwd>/app.log`. A home-relative `~/…` path, raw `stdin:` and
/// every non-path target are kept as typed.
fn absolute(entry: &str, cwd: &Path) -> String {
    let Some((name, target)) = entry.split_once('=') else {
        return entry.to_owned();
    };
    let Some((scheme, rest)) = target.split_once(':') else {
        return entry.to_owned();
    };
    if !PATH_SCHEMES.contains(&scheme) || rest.starts_with('~') || Path::new(rest).is_absolute() {
        return entry.to_owned();
    }
    let path = if rest.is_empty() {
        cwd.to_owned()
    } else {
        cwd.join(rest)
    };
    format!("{name}={scheme}:{}", path.display())
}

/// Write `body` to `path` through a temp sibling and a rename, owner-only, so a reader sees the old list
/// or the new one and never a torn one.
fn write_atomic(path: &Path, body: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
#[path = "serve_serving_tests.rs"]
mod serving_tests;
