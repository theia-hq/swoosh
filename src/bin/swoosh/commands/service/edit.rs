//! `swoosh service add <service>…` / `swoosh service rm <service>…`: change this machine's list, the one a
//! bare `serve` serves.
//!
//! Both are LOCAL FILE WRITES on the `services` of `<home>/serve.toml`, under `home.lock`, and all or
//! nothing: one entry refused changes nothing and prints only its refusal (with `Nothing was added.` or
//! `Nothing was removed.` under it when more than one was typed, so no one reads the entries before the bad
//! one as landed). Otherwise one line per service, in the order typed.
//!
//! `add` takes `serve`'s forms, and on a home that never named a list starts from what a bare `serve`
//! served, so an add never removes. A running `serve` binds only at its start, so what it adds is served
//! from its next start. `add` reads the running `serve`'s socket for one line only: a name already listed
//! that the running one did not bind says it is served from the next start too. Whether the write happens
//! never depends on that read. `rm` takes a name's `off` row with it.
//!
//! A name typed twice is a usage error, exit 2, before the home is read.

use clap::Args;
use nauthy::Service;
use swoosh::home::{Home, HomeWrite};
use swoosh::serve::{Added, EditError, Mistyped, ServingError, as_typed};
use swoosh::serve_toml::ServeToml;

use super::{Running, Usage};

/// Add services to what this machine serves
#[derive(Debug, Args)]
pub struct ServiceAddCmd {
    /// A built-in (ssh, ping, speed, proxy:<url>) or name=target
    #[arg(
        value_name = "service",
        required = true,
        value_parser = swoosh::serve::service_entry
    )]
    pub entries: Vec<String>,
}

/// Remove services from what this machine serves
#[derive(Debug, Args)]
pub struct ServiceRmCmd {
    /// A name on this machine's list
    #[arg(value_name = "service", required = true, value_parser = swoosh::names::service)]
    pub names: Vec<Service>,
}

impl ServiceAddCmd {
    /// Add the entries to `<home>/serve.toml`'s list under `home.lock`, all or nothing, and say what each
    /// one found on stderr.
    ///
    /// # Errors
    ///
    /// [`Usage`] when an entry has no name or one is typed twice; an entry the list refuses; the file
    /// cannot be read or written; the current directory cannot be read.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        Mistyped::check(&self.entries).map_err(Usage::from)?;
        let cwd = std::env::current_dir()?;
        let path = home.serve_toml();
        let home_lock = HomeWrite::take(home).await?;
        let added = ServeToml::try_update(&home_lock, home, |file| {
            file.add(&self.entries, &cwd, &path)
        })?;
        drop(home_lock);
        let added = added.map_err(|error| refused(&error, self.entries.len(), "added"))?;
        // Asked only when a line needs it, after the write: the write never waits on a running node.
        let running = if added.iter().any(|found| matches!(found, Added::Listed(_))) {
            Running::ask(home).await
        } else {
            None
        };
        for found in &added {
            eprintln!("{}", added_line(found, running.as_ref()));
        }
        Ok(())
    }
}

impl ServiceRmCmd {
    /// Take the names off `<home>/serve.toml`'s list under `home.lock`, all or nothing, and say so on stderr.
    ///
    /// # Errors
    ///
    /// [`Usage`] when a name is typed twice; a name the list does not hold; the file cannot be read or
    /// written.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        Mistyped::check_names(self.names.iter().map(Service::as_str)).map_err(Usage::from)?;
        let path = home.serve_toml();
        let home_lock = HomeWrite::take(home).await?;
        let removed =
            ServeToml::try_update(&home_lock, home, |file| file.remove(&self.names, &path))?;
        drop(home_lock);
        removed.map_err(|error| refused(&error, self.names.len(), "removed"))?;
        for name in &self.names {
            eprintln!("Removed {name}.");
        }
        Ok(())
    }
}

/// The line for one entry `add` was given. A name already listed that the `serve` running here did not bind
/// says when it is served; with no `serve` answering, there is nothing to say past that it is listed.
fn added_line(found: &Added, running: Option<&Running>) -> String {
    match found {
        Added::New(name) => format!("Added {name}; it is served when swoosh serve next starts."),
        Added::Listed(name) if running.is_some_and(|running| !running.serves(name)) => {
            format!("{name} is already listed; it is served when swoosh serve next starts.")
        }
        Added::Listed(name) => format!("{name} is already listed."),
        Added::ListedOff(name) => {
            format!("{name} is already listed and off.\nTo turn it on:\n  swoosh service on {name}")
        }
    }
}

/// The refusal for an edit that changed nothing, with `Nothing was <done>.` as its first detail line when
/// more than one entry was typed: the head stays the one clause, the rest of its detail stays under it.
fn refused(error: &EditError, typed: usize, done: &str) -> eyre::Report {
    if let EditError::Serving(ServingError::Mistyped(mistyped)) = error {
        // Checked before the home was read; kept a usage error should the list refuse it after all.
        return eyre::Report::new(Usage::from(mistyped.clone()));
    }
    let text = match error {
        EditError::Retarget { name, held, asked } => format!(
            "{name} already serves {held} here\n  To point it elsewhere, remove it, then add it:\n    swoosh \
             service rm {name}\n    swoosh service add {}",
            as_typed(asked)
        ),
        other => other.to_string(),
    };
    if typed < 2 {
        return eyre::eyre!("{text}");
    }
    let (head, detail) = text.split_once('\n').unwrap_or((&text, ""));
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!("\n{detail}")
    };
    eyre::eyre!("{head}\n  Nothing was {done}.{detail}")
}

#[cfg(test)]
#[path = "edit_tests.rs"]
mod edit_tests;
