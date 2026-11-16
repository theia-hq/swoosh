use core::fmt;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fetch::OriginAllowlist;
use nauthy::Service;
use tightbeam::tunnel::{TargetSpec, TargetSyntaxError};

/// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid {operand} service definition at index {index}: {cause}")]
pub struct DefinitionError {
    /// The input list containing the invalid definition.
    pub operand: Operand,
    /// The definition's one-based position within that input list.
    pub index: usize,
    /// The finite syntax refusal.
    pub cause: DefinitionCause,
}

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
            Self::Positional => "positional",
            Self::Base => "base",
            Self::Addition => "addition",
            Self::Saved => "saved",
        })
    }
}

/// A finite syntax refusal that never retains input or parser reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DefinitionCause {
    /// Invalid service name.
    #[error("invalid service name")]
    Name,
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

#[derive(Clone)]
pub(super) enum Target {
    Primitive(TargetSpec),
    Ping,
    Speed,
    #[cfg(feature = "ssh")]
    Sshd,
    Receive(Receive),
    Proxy {
        text: String,
        allow: OriginAllowlist,
    },
}

#[derive(Clone)]
pub(super) enum Receive {
    Inbox,
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
                    let name = crate::names::service(entry).map_err(|_| DefinitionCause::Name)?;
                    let target = match name.as_str() {
                        "ping" => "ping:",
                        "speed" => "speed:",
                        "ssh" => "sshd:",
                        "proxy" => return Err(DefinitionCause::Origin),
                        _ => return Err(DefinitionCause::Arity),
                    };
                    return Self::named(name, target);
                }
            }
        };
        let name = crate::names::service(name).map_err(|_| DefinitionCause::Name)?;
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

fn clean(text: &str) -> Result<(), DefinitionCause> {
    if text.chars().any(char::is_control) || text.trim() != text {
        return Err(DefinitionCause::Arity);
    }
    Ok(())
}

#[cfg(test)]
#[path = "definition_tests.rs"]
mod tests;
