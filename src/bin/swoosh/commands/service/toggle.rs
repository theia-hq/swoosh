//! `swoosh service on <service>` / `swoosh service off <service>`: turn one listed service on or off here,
//! live, without stopping `serve`.
//!
//! Both are LOCAL FILE WRITES on the `off` list of `<home>/serve.toml`, never a socket call: the running
//! `serve` is never asked anything. Its gate reads the file live (the
//! [`LiveServeToml`](swoosh::serve_toml::LiveServeToml) it consults per stream), so an `off` refuses the
//! service on the next stream and an `on` restores it, with no restart; with no `serve` running, the next
//! start reads the same file. So one line fits both: the setting is written either way. An `off` PERSISTS
//! (fail-closed): a restart keeps it off, and no start clears it for a name already listed.
//!
//! Each acts on a name the list holds ([`ServeToml::listed`]), the default included on a home that never
//! named a list. `on` of a name not listed refuses and names the `service add` that would list it; `off` of
//! one refuses with no fix, since a name not listed already does not answer. Neither opens a new service:
//! `on` only takes a name off the `off` list.
//!
//! A machine typed after the service (`[me/<name>]`), or alone in its slot, is parsed so it can be refused
//! with exit 2, and hidden from usage: these act on this machine only until they can reach another of your
//! devices.
//!
//! Two racing toggles cannot lose an edit: the read-modify-write runs under `home.lock`, and the rewrite goes
//! through the home's one write routine, so a crash mid-write can never leave a torn list.

use clap::Args;
use nauthy::Service;
use swoosh::escape::Escaped;
use swoosh::home::{Home, HomeWrite};
use swoosh::names::NameError;
use swoosh::serve_toml::ServeToml;

/// Turn a service on or off; the leaf carries the service, and the subcommand says which way.
#[derive(Debug, Args)]
pub struct ServiceToggleCmd {
    // A name this machine's list holds. No help line: the metavar says it, and the leaf's row says the rest.
    #[arg(value_name = "service", value_parser = slot)]
    pub service: Slot,
    // One of your devices: refused until this can act there, so usage does not show it.
    #[arg(value_name = "me/<name>", hide = true)]
    pub machine: Option<String>,
}

/// What was typed in the service slot, sorted by shape: a service name, or a machine typed where the service
/// goes. A machine is never a service name (no name holds a `/`), so the two cannot be mistaken.
#[derive(Debug, Clone)]
pub enum Slot {
    /// A service name, through the one name rule.
    Service(Service),
    /// Text shaped like a machine (`me/nas`), kept so its refusal can name it.
    Machine(String),
}

/// The value parser: a `/` makes a machine, anything else meets the service name rule, so a dotted internal
/// route (`control.stop`) is still refused at parse.
fn slot(text: &str) -> Result<Slot, NameError> {
    if text.contains('/') {
        return Ok(Slot::Machine(text.to_owned()));
    }
    swoosh::names::service(text).map(Slot::Service)
}

/// Which way a toggle turns its service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    /// `service on`: take the name off the `off` list.
    On,
    /// `service off`: put the name on it.
    Off,
}

impl Way {
    /// The subcommand, as typed.
    pub fn verb(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// A usage error found once the line is parsed: exit 2, as clap's own are, before anything is read.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

/// What a toggle found: it turned the service, or the service was already that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Toggled {
    /// The setting changed.
    Turned,
    /// It already was; nothing was written.
    Already,
}

impl ServiceToggleCmd {
    /// The service to turn, here: refused as a usage error when a machine was typed, in the service slot or
    /// after it, naming the command to run there. The service as typed is in that command, or the literal
    /// `<service>` when only a machine was typed.
    ///
    /// # Errors
    ///
    /// [`Usage`] when a machine was typed.
    pub fn here(&self, way: Way) -> Result<&Service, Usage> {
        let machine = match (&self.service, &self.machine) {
            (Slot::Service(service), None) => return Ok(service),
            (Slot::Machine(machine), _) | (Slot::Service(_), Some(machine)) => machine,
        };
        let service = match &self.service {
            Slot::Service(service) => service.as_str(),
            Slot::Machine(_) => "<service>",
        };
        let verb = way.verb();
        let name = machine.strip_prefix("me/").unwrap_or(machine);
        Err(Usage(format!(
            "swoosh service {verb} acts only on this machine\n  To run it on {}:\n    swoosh ssh {} -- \
             swoosh service {verb} {service}",
            Escaped(name),
            Escaped(machine)
        )))
    }

    /// Turn the service `way` here, in `<home>/serve.toml` under `home.lock`, and say so on stderr. The
    /// running `serve` is not asked: its gate reads the file live, and a stopped one reads it at start.
    ///
    /// # Errors
    ///
    /// [`Usage`] when a machine was typed; the name is not listed here; the file cannot be read or
    /// written.
    pub async fn run(self, home: &Home, way: Way) -> eyre::Result<()> {
        let service = self.here(way)?;
        let name = service.as_str();
        let home_lock = HomeWrite::take(home).await?;
        let mut toggled = None;
        ServeToml::update(&home_lock, home, |file| {
            toggled = Some(toggle(file, name, way));
        })?;
        drop(home_lock);
        let Some(toggled) = toggled else {
            eyre::bail!("internal: serve.toml was updated without its change running");
        };
        let line = match (toggled, way) {
            (None, Way::On) => eyre::bail!(
                "{name} is not listed here; add it: swoosh service add {}",
                swoosh::serve::entry_for(name)
            ),
            (None, Way::Off) => eyre::bail!("{name} is not listed here"),
            (Some(Toggled::Turned), _) => format!("Turned {name} {} here.", way.verb()),
            (Some(Toggled::Already), _) => format!("{name} is already {}.", way.verb()),
        };
        eprintln!("{line}");
        Ok(())
    }
}

/// Turn `name` `way` in `file`, which holds the list it must be on; `None`, and nothing changed, when the
/// list does not hold it.
fn toggle(file: &mut ServeToml, name: &str, way: Way) -> Option<Toggled> {
    let listed = file
        .listed()
        .iter()
        .any(|entry| entry.split_once('=').is_some_and(|(held, _)| held == name));
    if !listed {
        return None;
    }
    let changed = match way {
        Way::On => file.off.remove(name),
        Way::Off => file.off.insert(name.to_owned()),
    };
    Some(if changed {
        Toggled::Turned
    } else {
        Toggled::Already
    })
}

#[cfg(test)]
#[path = "toggle_tests.rs"]
mod toggle_tests;
