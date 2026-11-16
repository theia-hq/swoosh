//! Select the user services a `serve` starts with.
//!
//! Explicit service constructors select only this invocation; they do not change saved services or
//! clear `off` names. Bare `serve` uses the saved list, or `ping` and `speed` when no list is saved.
//! An explicitly empty saved list stays empty. `service add` and `service rm` edit the saved list.

use std::collections::BTreeSet;
use std::path::Path;

use super::DEFAULT_SERVICES;
use super::definition::{DefinitionCause, DefinitionError, Operand, ValidatedDefinition};
use crate::serve_toml::ServeToml;

/// Why the services a `serve` starts with could not be settled.
#[derive(Debug, thiserror::Error)]
pub enum ServingError {
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    #[error(transparent)]
    Definition(#[from] DefinitionError),
    /// The services typed on this command line cannot be one list.
    #[error(transparent)]
    Mistyped(#[from] Mistyped),
}

/// Why the services typed on one command line cannot be one list: a usage error, found before anything is read, written or bound.
#[derive(Debug, Clone, thiserror::Error)]
#[error(transparent)]
pub struct Mistyped(pub DefinitionError);

impl Mistyped {
    /// Validate complete service definitions and reject duplicate names.
    ///
    /// # Errors
    ///
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    pub fn check(entries: &[String]) -> Result<(), Self> {
        ValidatedDefinition::list(entries, Operand::Positional, None)
            .map(|_| ())
            .map_err(Self)
    }

    /// Refuse typed names that hold one name twice.
    ///
    /// # Errors
    ///
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    pub fn check_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<(), Self> {
        let mut seen = BTreeSet::new();
        for (index, name) in names.into_iter().enumerate() {
            let name = crate::names::service(name).map_err(|_| {
                Self(DefinitionError {
                    operand: Operand::Positional,
                    index: index + 1,
                    cause: DefinitionCause::Name,
                })
            })?;
            if !seen.insert(name.to_string()) {
                return Err(Self(DefinitionError {
                    operand: Operand::Positional,
                    index: index + 1,
                    cause: DefinitionCause::Collision,
                }));
            }
        }
        Ok(())
    }
}

/// Why `service add` or `service rm` changed nothing.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// The list could not be read or the new list could not be saved.
    #[error(transparent)]
    Serving(#[from] ServingError),
    /// `add` was given a new target under a name already listed.
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
    /// Listed already, with this very target, and turned off.
    ListedOff(String),
}

/// The user services selected at startup and whether selection came from this invocation or saved policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// Explicit constructors for this invocation, with paths made absolute; never saved by launch.
    Named(Vec<String>),
    /// The saved list used by a bare start; an explicitly empty list selects no user services.
    Resumed(Vec<String>),
    /// Nothing named and no list recorded: the default, `ping` and `speed`.
    Default,
}

impl Started {
    /// Settle what a `serve` under `home` starts with.
    ///
    /// # Errors
    ///
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    pub fn of(named: &[String], kept: &ServeToml, cwd: &Path) -> Result<Self, ServingError> {
        if !named.is_empty() {
            return Self::positional(named, cwd);
        }
        Self::bare_at(kept, cwd)
    }

    /// Explicit constructors for this invocation, with paths made absolute; never saved by launch.
    ///
    /// # Errors
    ///
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    pub fn positional(entries: &[String], cwd: &Path) -> Result<Self, ServingError> {
        Ok(Self::Named(normalized(
            entries,
            Operand::Positional,
            Some(cwd),
        )?))
    }

    /// The services a bare `serve` would start from the saved list, or the default when no list is saved.
    ///
    /// # Errors
    ///
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    pub fn bare(kept: &ServeToml) -> Result<Self, ServingError> {
        match &kept.services {
            Some(listed) => Ok(Self::Resumed(normalized(listed, Operand::Saved, None)?)),
            None => Ok(Self::Default),
        }
    }

    /// The services a bare `serve` would start from the saved list, with paths made absolute.
    ///
    /// # Errors
    ///
    /// Identifies an invalid definition by operand, one-based index, and finite cause. Contains no definition text or underlying parser error.
    pub fn bare_at(kept: &ServeToml, cwd: &Path) -> Result<Self, ServingError> {
        match &kept.services {
            Some(listed) => Ok(Self::Resumed(normalized(
                listed,
                Operand::Saved,
                Some(cwd),
            )?)),
            None => Ok(Self::Default),
        }
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

    /// The names this run's services are bound under, in their order.
    pub fn names(&self) -> Vec<String> {
        self.entries()
            .iter()
            .filter_map(|entry| entry.split_once('=').map(|(name, _)| name.to_owned()))
            .collect()
    }
}

impl ServeToml {
    /// `service add`: add entries to the saved list, all or nothing, without retargeting or changing off names.
    ///
    /// # Errors
    ///
    /// An entry or the saved list is invalid, or a listed name has another target.
    pub fn add(&mut self, entries: &[String], cwd: &Path) -> Result<Vec<Added>, EditError> {
        let additions = normalized(entries, Operand::Positional, Some(cwd))?;
        // Held entries are compared in the form this edit's cwd gives them, as the additions are, but
        // written back as saved: an edit rewrites no entry it was not given.
        let held = Started::bare_at(self, cwd)?.entries();
        let mut list = self.services.clone().unwrap_or_else(|| held.clone());
        let mut found = Vec::new();
        let mut fresh = Vec::new();
        for entry in additions {
            let Some((name, asked)) = entry.split_once('=') else {
                continue;
            };
            match held.iter().find_map(|held| target(held, name)) {
                Some(held) if held == asked => found.push(if self.off.contains(name) {
                    Added::ListedOff(name.to_owned())
                } else {
                    Added::Listed(name.to_owned())
                }),
                Some(held) => {
                    return Err(EditError::Retarget {
                        name: name.to_owned(),
                        held: held.to_owned(),
                        asked: entry,
                    });
                }
                None => {
                    found.push(Added::New(name.to_owned()));
                    fresh.push(entry);
                }
            }
        }
        list.extend(fresh);
        if found.iter().any(|added| matches!(added, Added::New(_))) {
            self.services = Some(list);
        }
        Ok(found)
    }

    /// Remove names from the saved service list, retaining all off names. The edit is all or nothing.
    ///
    /// # Errors
    ///
    /// A name is not listed, is given twice, or the saved list is invalid.
    pub fn remove(&mut self, names: &[nauthy::Service]) -> Result<(), EditError> {
        Mistyped::check_names(names.iter().map(nauthy::Service::as_str))
            .map_err(ServingError::from)?;
        // Each kept entry is written back as saved; its validated form only finds its name.
        let forms = Started::bare(self)?.entries();
        let saved = self.services.clone().unwrap_or_else(|| forms.clone());
        let mut list: Vec<(String, String)> = forms.into_iter().zip(saved).collect();
        for name in names {
            let name = name.as_str();
            let before = list.len();
            list.retain(|(form, _)| target(form, name).is_none());
            if list.len() == before {
                return Err(EditError::NotListed(name.to_owned()));
            }
        }
        self.services = Some(list.into_iter().map(|(_, saved)| saved).collect());
        Ok(())
    }
}

fn normalized(
    entries: &[String],
    operand: Operand,
    cwd: Option<&Path>,
) -> Result<Vec<String>, ServingError> {
    Ok(ValidatedDefinition::list(entries, operand, cwd)?
        .iter()
        .map(ValidatedDefinition::entry)
        .collect())
}

fn target<'a>(entry: &'a str, name: &str) -> Option<&'a str> {
    entry
        .split_once('=')
        .and_then(|(held, target)| (held == name).then_some(target))
}

#[cfg(test)]
#[path = "serve_serving_tests.rs"]
mod serving_tests;
