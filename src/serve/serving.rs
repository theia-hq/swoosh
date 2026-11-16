//! Select the user services a `serve` starts with.
//!
//! Explicit service constructors select only this invocation; they do not change saved services or
//! clear `off` names. Bare `serve` uses the saved list, or `ping` and `speed` when no list is saved.
//! An explicitly empty saved list stays empty. `service add` and `service rm` edit the saved list.
//!
//! `--with DEF` and `--without NAME` add to or omit from the saved services (or ping and speed) for this run.
//! Later saved service additions, removals and target changes do not change this process's selection.
//! Off changes affect new admissions; existing streams may continue. Each restart, including a
//! supervisor restart, captures the then-current saved/default selection again. Launch changes neither
//! saved services nor off settings.

use std::collections::{BTreeMap, BTreeSet};
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
    /// An exclusion name is invalid.
    #[error("--without #{index} is not a valid service name")]
    InvalidExclusion {
        /// The operand's one-based position.
        index: usize,
    },
    /// An exclusion is absent from the captured base.
    #[error("--without #{index} is not in the saved/default selection")]
    MissingExclusion {
        /// The operand's one-based position.
        index: usize,
    },
    /// An exclusion repeats a normalized name.
    #[error("--without #{index} repeats an earlier --without")]
    DuplicateExclusion {
        /// The operand's one-based position.
        index: usize,
    },
    /// An addition is also excluded.
    #[error("--with #{index} is also named by --without")]
    ExcludedAddition {
        /// The operand's one-based position.
        index: usize,
    },
    /// An addition conflicts with a captured base target.
    #[error("--with #{index} has a different target than the saved/default one")]
    ConflictingAddition {
        /// The operand's one-based position.
        index: usize,
    },
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
    /// Not listed before, and its relative path was made absolute against this edit's cwd: it is now,
    /// with `target` as stored.
    NewAnchored {
        /// The service name.
        name: String,
        /// The target as stored, its path absolute.
        target: String,
    },
    /// Listed already, with this very target: nothing changed.
    Listed(String),
    /// Listed already, with this very target, and turned off.
    ListedOff(String),
}

/// The user services selected at startup and whether selection came from this invocation or saved policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// Invocation-selected services with anchored paths; launch does not save them.
    Named(Vec<String>),
    /// The saved/default services with `--with` and `--without` applied, captured once for this
    /// invocation with anchored paths; launch does not save them.
    Adjusted(Vec<String>),
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

    /// Validate the complete saved/default base and operands against the supplied absolute cwd, then select a fixed service list for this invocation without preparing services or changing saved policy.
    ///
    /// # Errors
    ///
    /// Returns a categorical operand/index error for invalid definitions, exclusions or name conflicts.
    pub fn relative(
        kept: &ServeToml,
        additions: &[String],
        exclusions: &[String],
        cwd: &Path,
    ) -> Result<Self, ServingError> {
        let defaults;
        let base = match &kept.services {
            Some(entries) => entries,
            None => {
                defaults = DEFAULT_SERVICES
                    .iter()
                    .map(|entry| (*entry).to_owned())
                    .collect();
                &defaults
            }
        };
        // Both lists pass the same complete, pure grammar before any membership is removed. In
        // particular, exclusion cannot hide malformed saved syntax or prepare an excluded backend.
        let base = ValidatedDefinition::list(base, Operand::Base, Some(cwd))?;
        let additions = ValidatedDefinition::list(additions, Operand::Addition, Some(cwd))?;
        // Keyed by name text, as the neighbouring lists are: a service name has no order of its own.
        let base_targets: BTreeMap<String, String> = base
            .iter()
            .map(|definition| (definition.name.to_string(), definition.entry()))
            .collect();
        let mut excluded = BTreeSet::new();
        for (index, name) in exclusions.iter().enumerate() {
            let index = index + 1;
            let name = crate::names::service(name)
                .map_err(|_| ServingError::InvalidExclusion { index })?;
            if !excluded.insert(name.to_string()) {
                return Err(ServingError::DuplicateExclusion { index });
            }
            if !base_targets.contains_key(name.as_str()) {
                return Err(ServingError::MissingExclusion { index });
            }
        }
        let mut fresh = BTreeMap::new();
        for (index, definition) in additions.into_iter().enumerate() {
            let index = index + 1;
            if excluded.contains(definition.name.as_str()) {
                return Err(ServingError::ExcludedAddition { index });
            }
            let entry = definition.entry();
            match base_targets.get(definition.name.as_str()) {
                Some(held) if *held != entry => {
                    return Err(ServingError::ConflictingAddition { index });
                }
                Some(_) => {}
                None => {
                    fresh.insert(definition.name.to_string(), entry);
                }
            }
        }
        let mut selected: Vec<_> = base
            .into_iter()
            .filter(|definition| !excluded.contains(definition.name.as_str()))
            .map(|definition| definition.entry())
            .collect();
        // Base order is retained; new names have a stable order independent of flag placement.
        selected.extend(fresh.into_values());
        Ok(Self::Adjusted(selected))
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
            Self::Named(entries) | Self::Adjusted(entries) | Self::Resumed(entries) => {
                entries.clone()
            }
            Self::Default => DEFAULT_SERVICES
                .iter()
                .map(|&entry| entry.to_owned())
                .collect(),
        }
    }

    /// Whether `name`'s target holds a relative path. Unanchored, as a bare start reads saved text, such a
    /// path has no directory until a `serve` starts and anchors it at its own cwd. An entry that does not
    /// parse counts as relative, so a caller that refuses relative targets refuses it too.
    pub fn is_relative(&self, name: &str) -> bool {
        self.entries()
            .iter()
            .filter(|entry| target(entry, name).is_some())
            .any(|entry| {
                !ValidatedDefinition::parse(entry).is_ok_and(|parsed| !parsed.is_relative())
            })
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
        // The same entries as typed, to tell which of them anchoring changed.
        let typed = normalized(entries, Operand::Positional, None)?;
        // Held entries are compared in the form this edit's cwd gives them, as the additions are, but
        // written back as saved: an edit rewrites no entry it was not given.
        let held = Started::bare_at(self, cwd)?.entries();
        let mut list = self.services.clone().unwrap_or_else(|| held.clone());
        let mut found = Vec::new();
        let mut fresh = Vec::new();
        for (entry, typed) in additions.into_iter().zip(typed) {
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
                    found.push(if entry == typed {
                        Added::New(name.to_owned())
                    } else {
                        Added::NewAnchored {
                            name: name.to_owned(),
                            target: asked.to_owned(),
                        }
                    });
                    fresh.push(entry);
                }
            }
        }
        list.extend(fresh);
        if found
            .iter()
            .any(|added| matches!(added, Added::New(_) | Added::NewAnchored { .. }))
        {
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
#[path = "relative_tests.rs"]
mod relative_tests;
#[cfg(test)]
#[path = "serve_serving_tests.rs"]
mod serving_tests;
