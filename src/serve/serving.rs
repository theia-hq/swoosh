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
use crate::home::Home;
use crate::serve_toml::ServeToml;

/// The targets whose argument is a path on this machine: stored absolute, because a service manager
/// starts `serve` in a different directory than the shell that named them.
const PATH_SCHEMES: [&str; 4] = ["recv", "unix", "file", "fifo"];

/// Why the services a `serve` starts with could not be settled.
#[derive(Debug, thiserror::Error)]
pub enum ServingError {
    /// An entry of the services `<home>/serve.toml` keeps is not a service form, a flag above all: it is
    /// refused, never spliced into the command line. Which services to serve instead is the person's call,
    /// so the line names no command.
    #[error(
        "{} lists {} as a service, and it is not one, so serve will not start unless you name its services",
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
    /// with its paths made absolute against `cwd`, else the list `kept` (the home's `serve.toml`, as the
    /// run's one watcher read it) records, else the default.
    pub fn of(
        named: &[String],
        kept: &ServeToml,
        home: &Home,
        cwd: &Path,
    ) -> Result<Self, ServingError> {
        let path = home.serve_toml();
        if !named.is_empty() {
            let cannot_save = |entry: String| ServingError::CannotSave {
                path: path.clone(),
                entry,
            };
            return named
                .iter()
                .map(|entry| {
                    let saved = absolute(entry, cwd).map_err(|()| cannot_save(entry.clone()))?;
                    if saved.chars().any(char::is_control) || saved.trim() != saved {
                        return Err(cannot_save(saved));
                    }
                    Ok(saved)
                })
                .collect::<Result<_, _>>()
                .map(Self::Named);
        }
        Self::bare(kept, &path)
    }

    /// What a bare `serve` starts with from `kept`, the `serve.toml` at `path`: the list it records, else
    /// the default. A running `serve` asks this of each later read too, for the services that file runs,
    /// and `share` asks it for what a name serves.
    ///
    /// # Errors
    ///
    /// [`ServingError::NotAService`] when `kept` lists something that is not a service form.
    pub fn bare(kept: &ServeToml, path: &Path) -> Result<Self, ServingError> {
        let mut entries = Vec::new();
        for line in &kept.services {
            let not_a_service = || ServingError::NotAService {
                path: path.to_owned(),
                line: line.clone(),
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

    /// The names this run's services are bound under, in their order; an entry with no name binds none.
    pub fn names(&self) -> Vec<String> {
        self.entries()
            .iter()
            .filter_map(|entry| entry.split_once('=').map(|(name, _)| name.to_owned()))
            .collect()
    }

    /// Whether this run serves what the home last served, for the banner's "(as last time)".
    pub fn is_resumed(&self) -> bool {
        matches!(self, Self::Resumed(_))
    }

    /// Record a named list in `file` as what the next bare `serve` resumes, and turn its services back on:
    /// a `serve` that names a service serves it, so one turned off yesterday is not refused by today's
    /// `serve ssh`. A resumed or default start changes neither. Applied inside the one
    /// [`ServeToml::update`] a start makes once its routes bound, so a start that fails writes nothing.
    pub fn record(&self, file: &mut ServeToml) {
        let Self::Named(entries) = self else {
            return;
        };
        file.services.clone_from(entries);
        for entry in entries {
            if let Some((name, _)) = entry.split_once('=') {
                file.off.remove(name);
            }
        }
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
