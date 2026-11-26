use core::fmt;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fetch::OriginAllowlist;
use nauthy::Service;
use tightbeam::tunnel::{TargetSpec, TargetSyntaxError};

use crate::names::{NameError, Reserved, ReservedService};

/// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefinitionError {
    /// The input list containing the invalid definition.
    pub operand: Operand,
    /// The definition's one-based position within that input list.
    pub index: usize,
    /// The finite syntax refusal.
    pub cause: DefinitionCause,
}

impl DefinitionError {
    /// The reserved word this definition named, when that is why it was refused.
    pub fn reserved(&self) -> Option<Reserved> {
        match self.cause {
            DefinitionCause::Reserved(reserved) => Some(reserved),
            _ => None,
        }
    }
}

impl fmt::Display for DefinitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            operand,
            index,
            cause,
        } = self;
        // A reserved word is the one refusal that names what was typed: the word is one of five fixed ones,
        // so it holds nothing of the input, and its line is the same in every service slot.
        if let Some(reserved) = self.reserved() {
            return ReservedService(reserved).fmt(f);
        }
        write!(
            f,
            "invalid {operand}service definition at index {index}: {cause}"
        )
    }
}

impl core::error::Error for DefinitionError {}

/// The input list containing the invalid definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// Positional input.
    Positional,
    /// Base input.
    Base,
    /// Addition input.
    Addition,
    /// Saved input.
    Saved,
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            // Only the saved list is named: the others are what was just typed.
            Self::Positional | Self::Base | Self::Addition => "",
            Self::Saved => "saved ",
        })
    }
}

/// A finite syntax refusal that never retains input or parser reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DefinitionCause {
    /// Invalid service name.
    #[error("invalid service name")]
    Name,
    /// A reserved word where the name goes.
    #[error("{}", ReservedService(*.0))]
    Reserved(Reserved),
    /// Unsupported target scheme.
    #[error("unsupported target scheme")]
    Scheme,
    /// Invalid target form.
    #[error("invalid target form")]
    Arity,
    /// Unsupported target suffix.
    #[error("unsupported target suffix")]
    Suffix,
    /// Invalid endpoint.
    #[error("invalid endpoint")]
    Endpoint,
    /// Empty path.
    #[error("empty path")]
    EmptyPath,
    /// Path is not valid UTF-8.
    #[error("path is not valid UTF-8")]
    Encoding,
    /// Invalid proxy origin.
    #[error("invalid proxy origin")]
    Origin,
    /// Service name already used.
    #[error("service name already used")]
    Collision,
}

impl From<TargetSyntaxError> for DefinitionCause {
    fn from(error: TargetSyntaxError) -> Self {
        match error {
            TargetSyntaxError::MissingScheme | TargetSyntaxError::UnexpectedArgument => Self::Arity,
            TargetSyntaxError::UnknownScheme => Self::Scheme,
            TargetSyntaxError::MissingPath => Self::EmptyPath,
            TargetSyntaxError::InvalidEndpoint => Self::Endpoint,
            TargetSyntaxError::UnsupportedLossy => Self::Suffix,
            TargetSyntaxError::PathEncoding => Self::Encoding,
            TargetSyntaxError::RelativeWorkingDirectory
            | TargetSyntaxError::UnsupportedPathAnchoring => Self::Arity,
        }
    }
}

/// A service name and target that passed complete syntax validation. This does not establish backend availability.
#[derive(Clone)]
pub(super) struct ValidatedDefinition {
    pub(super) name: Service,
    pub(super) target: Target,
}

/// What a validated definition serves, parsed once so binding never reads the target text again.
#[derive(Clone)]
pub(super) enum Target {
    /// A tightbeam primitive target, bound by the router.
    Primitive(TargetSpec),
    /// The `ping:` engine.
    Ping,
    /// The `speed:` engine.
    Speed,
    /// The `sshd:` shell, only in a build with the `ssh` feature.
    #[cfg(feature = "ssh")]
    Sshd,
    /// A `recv:` receiver and where it saves.
    Receive(Receive),
    /// A `proxy:` scoped to one HTTP(S) origin.
    Proxy {
        /// The origin as given, which the entry renders back.
        text: String,
        /// The parsed origin, the only one the proxy reaches.
        allow: OriginAllowlist,
    },
}

/// Where a `recv:` receiver saves.
#[derive(Clone)]
pub(super) enum Receive {
    /// `recv:` alone: the inbox, found only when the service is prepared, never at validation.
    Inbox,
    /// `recv:<dir>`: the directory given, made absolute against the cwd when anchored.
    Path(PathBuf),
}

impl ValidatedDefinition {
    pub(super) fn parse(entry: &str) -> Result<Self, DefinitionCause> {
        clean(entry)?;
        // The self-naming proxy must be recognized before splitting '=' in its URL.
        let (name, target) = if entry.starts_with("proxy:") {
            ("proxy", entry)
        } else if let Some((name, target)) = entry.split_once('=') {
            (name, target)
        } else {
            match entry {
                _ if entry.starts_with("recv:") => ("recv", entry),
                _ if entry.contains(':') => return Err(DefinitionCause::Arity),
                _ => {
                    let name = service_name(entry)?;
                    if name.as_str() == "proxy" {
                        return Err(DefinitionCause::Origin);
                    }
                    let Some(&(_, target)) = super::BUILT_IN
                        .iter()
                        .find(|&&(built_in, _)| built_in == name.as_str())
                    else {
                        return Err(DefinitionCause::Arity);
                    };
                    return Self::named(name, target);
                }
            }
        };
        let name = service_name(name)?;
        Self::named(name, target)
    }

    fn named(name: Service, text: &str) -> Result<Self, DefinitionCause> {
        clean(text)?;
        let (scheme, rest) = text.split_once(':').ok_or(DefinitionCause::Arity)?;
        let target = match scheme {
            "ping" | "speed" | "sshd" => {
                if !rest.is_empty() {
                    return Err(if text.ends_with("+lossy") {
                        DefinitionCause::Suffix
                    } else {
                        DefinitionCause::Arity
                    });
                }
                match scheme {
                    "ping" => Target::Ping,
                    "speed" => Target::Speed,
                    #[cfg(feature = "ssh")]
                    "sshd" => Target::Sshd,
                    _ => return Err(DefinitionCause::Scheme),
                }
            }
            "recv" => Target::Receive(if rest.is_empty() {
                Receive::Inbox
            } else {
                Receive::Path(PathBuf::from(rest))
            }),
            "proxy" => {
                let parsed = url::Url::parse(rest).map_err(|_| DefinitionCause::Origin)?;
                if !matches!(parsed.scheme(), "http" | "https")
                    || !matches!(parsed.path(), "" | "/")
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                {
                    return Err(DefinitionCause::Origin);
                }
                let allow = OriginAllowlist::parse([rest]).map_err(|_| DefinitionCause::Origin)?;
                Target::Proxy {
                    text: rest.to_owned(),
                    allow,
                }
            }
            _ => Target::Primitive(text.parse::<TargetSpec>().map_err(DefinitionCause::from)?),
        };
        Ok(Self { name, target })
    }

    pub(super) fn anchored(mut self, cwd: &Path) -> Result<Self, DefinitionCause> {
        if !cwd.is_absolute() {
            return Err(DefinitionCause::Arity);
        }
        self.target = match self.target {
            Target::Primitive(spec) => {
                Target::Primitive(spec.anchored(cwd).map_err(DefinitionCause::from)?)
            }
            Target::Receive(Receive::Path(path)) => {
                Target::Receive(Receive::Path(anchor_receive(&path, cwd)?))
            }
            other => other,
        };
        clean(&self.entry())?;
        Ok(self)
    }

    /// Whether the target holds a relative path, which means a directory only once a cwd anchors it.
    pub(super) fn is_relative(&self) -> bool {
        match &self.target {
            // Anchoring changes only a relative path tail and keeps every other target byte-identical,
            // so a change under a fixed root is the grammar's own answer. A refusal to anchor also means
            // a path tail that needed a directory.
            Target::Primitive(spec) => !spec
                .anchored(Path::new(ANY_ROOT))
                .is_ok_and(|anchored| anchored == *spec),
            Target::Receive(Receive::Path(path)) => !path.is_absolute(),
            _ => false,
        }
    }

    pub(super) fn entry(&self) -> String {
        let target = match &self.target {
            Target::Primitive(spec) => spec.as_str().to_owned(),
            Target::Ping => "ping:".to_owned(),
            Target::Speed => "speed:".to_owned(),
            #[cfg(feature = "ssh")]
            Target::Sshd => "sshd:".to_owned(),
            Target::Receive(Receive::Inbox) => "recv:".to_owned(),
            Target::Receive(Receive::Path(path)) => format!("recv:{}", path.to_string_lossy()),
            Target::Proxy { text, .. } => format!("proxy:{text}"),
        };
        format!("{}={target}", self.name)
    }

    pub(super) fn list(
        entries: &[String],
        operand: Operand,
        cwd: Option<&Path>,
    ) -> Result<Vec<Self>, DefinitionError> {
        let mut seen = BTreeSet::new();
        entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let error = |cause| DefinitionError {
                    operand,
                    index: index + 1,
                    cause,
                };
                let definition = Self::parse(entry)
                    .and_then(|definition| match cwd {
                        Some(cwd) => definition.anchored(cwd),
                        None => Ok(definition),
                    })
                    .map_err(error)?;
                if !seen.insert(definition.name.to_string()) {
                    return Err(error(DefinitionCause::Collision));
                }
                Ok(definition)
            })
            .collect()
    }
}

/// An absolute directory to anchor at when only whether a path is relative matters, never where it points.
#[cfg(windows)]
const ANY_ROOT: &str = r"C:\";
#[cfg(not(windows))]
const ANY_ROOT: &str = "/";

fn anchor_receive(path: &Path, cwd: &Path) -> Result<PathBuf, DefinitionCause> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    let text = path.to_str().ok_or(DefinitionCause::Encoding)?;
    #[cfg(windows)]
    if path.has_root()
        || matches!(text.as_bytes(), [drive, b':', ..] if drive.is_ascii_alphabetic())
    {
        return Err(DefinitionCause::Arity);
    }
    let cwd = cwd.to_str().ok_or(DefinitionCause::Encoding)?;
    // Concatenation preserves lexical dots even under a Windows verbatim cwd. Receive has no suffix
    // grammar, so '+lossy' is always path text here rather than a primitive delivery option.
    #[cfg(windows)]
    let separated = cwd.ends_with('\\') || (!cwd.starts_with(r"\\?\") && cwd.ends_with('/'));
    #[cfg(not(windows))]
    let separated = cwd.ends_with(std::path::MAIN_SEPARATOR);
    let separator = if separated {
        ""
    } else {
        std::path::MAIN_SEPARATOR_STR
    };
    Ok(PathBuf::from(format!("{cwd}{separator}{text}")))
}

/// The service a definition names, through the one name rule; a reserved word keeps which one it was.
pub(super) fn service_name(text: &str) -> Result<Service, DefinitionCause> {
    crate::names::service(text).map_err(|error| match error {
        NameError::ReservedService(ReservedService(reserved)) => {
            DefinitionCause::Reserved(reserved)
        }
        NameError::NotAName(_) | NameError::Reserved(_) => DefinitionCause::Name,
    })
}

fn clean(text: &str) -> Result<(), DefinitionCause> {
    if text.chars().any(char::is_control) || text.trim() != text {
        return Err(DefinitionCause::Arity);
    }
    Ok(())
}

#[cfg(test)]
#[path = "definition_tests.rs"]
mod tests;
