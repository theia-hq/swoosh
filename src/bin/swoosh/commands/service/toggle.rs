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
//! Each acts on a name the list holds, read as a bare `serve` reads it ([`Started::bare`]), the default
//! included on a home that never named a list; a list that read refuses is refused here too, naming the
//! file. `on` of a name not listed refuses and names the `service add` that would list it; `off` of
//! one refuses with no fix, since a name not listed already does not answer. Neither opens a new service:
//! `on` only takes a name off the `off` list.
//!
//! A machine typed after the service (`[me/<name>]`), or alone in its slot, is parsed so it can be refused
//! with exit 2, and hidden from usage: these act on this machine only until they can reach another of your
//! devices. A second service after the first is refused with exit 2 too: each takes one.
//!
//! Two racing toggles cannot lose an edit: the read-modify-write runs under `home.lock`, and the rewrite goes
//! through the home's one write routine, so a crash mid-write can never leave a torn list.

use std::path::Path;

use clap::Args;
use nauthy::Service;
use swoosh::escape::Escaped;
use swoosh::home::{Home, HomeWrite};
use swoosh::names::{Name, NameError};
use swoosh::serve::{ServingError, Started};
use swoosh::serve_toml::ServeToml;

use super::Usage;

/// Turn a service on or off; the leaf carries the service, and the subcommand says which way.
#[derive(Debug, Args)]
pub struct ServiceToggleCmd {
    /// A name on this machine's list
    #[arg(value_name = "service", value_parser = slot)]
    pub service: Slot,
    // One of your devices: refused until this can act there, so usage does not show it. Any text parses, so
    // a second service reaches its own refusal rather than clap's.
    #[arg(value_name = "me/<name>", hide = true, value_parser = after)]
    pub machine: Option<After>,
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

/// The value parser: a `/` or a root's `root:` makes a machine, anything else meets the service name rule,
/// so a dotted internal route (`control.stop`) is still refused at parse.
fn slot(text: &str) -> Result<Slot, NameError> {
    if is_machine(text) {
        return Ok(Slot::Machine(text.to_owned()));
    }
    swoosh::names::service(text).map(Slot::Service)
}

/// What was typed after the service: a machine (`me/nas`), or a second word, which `on` and `off` never
/// take. Sorted by the same `/` as [`Slot`], since no name holds one.
#[derive(Debug, Clone)]
pub enum After {
    /// Text shaped like a machine, kept so its refusal can name it.
    Machine(String),
    /// Anything else: most likely a second service, as `add` and `rm` take several.
    Word,
}

/// The value parser for the machine slot: total, so every text there reaches [`ServiceToggleCmd::here`].
fn after(text: &str) -> Result<After, core::convert::Infallible> {
    Ok(if is_machine(text) {
        After::Machine(text.to_owned())
    } else {
        After::Word
    })
}

/// Whether `text` is shaped like a machine: it holds a `/`, or it is a root's key (`root:ed01…`), which these
/// refuse as any machine is refused, by the head alone, so the key is never printed back.
fn is_machine(text: &str) -> bool {
    text.contains('/') || swoosh::root_key::is_prefixed(text)
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

/// What a toggle found: it turned the service, or the service was already that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Toggled {
    /// The setting changed.
    Turned,
    /// It already was; nothing was written.
    Already,
}

impl ServiceToggleCmd {
    /// The service to turn, here: refused as a usage error when a second word or a machine was typed. A
    /// second word is a second service, which these never take. A machine, in the service slot or after it,
    /// acts only here; when it is one of your devices (`me/<name>`) the refusal names the command to run
    /// there, with the service as typed or the literal `<service>` when only a machine was typed. Any other
    /// machine (a contact's `bob/nas`, a bare `me/`) gets no command: an `ssh` there would reach a machine
    /// that is not yours.
    ///
    /// # Errors
    ///
    /// [`Usage`] when a second word or a machine was typed.
    pub fn here(&self, way: Way) -> Result<&Service, Usage> {
        let verb = way.verb();
        let machine = match (&self.service, &self.machine) {
            (Slot::Service(service), None) => return Ok(service),
            (Slot::Service(_), Some(After::Word)) => {
                return Err(Usage(format!("swoosh service {verb} takes one service")));
            }
            (Slot::Machine(machine), _) | (Slot::Service(_), Some(After::Machine(machine))) => {
                machine
            }
        };
        let head = format!("swoosh service {verb} acts only on this machine");
        let Some(name) = machine
            .strip_prefix("me/")
            .and_then(|name| name.parse::<Name>().ok())
        else {
            return Err(Usage(head));
        };
        let service = match &self.service {
            Slot::Service(service) => service.as_str(),
            Slot::Machine(_) => "<service>",
        };
        Err(Usage(format!(
            "{head}\n  To run it on {name}:\n    swoosh ssh {} -- swoosh service {verb} {service}",
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
        let path = home.serve_toml();
        let toggled =
            ServeToml::try_update(&home_lock, home, |file| toggle(file, name, way, &path))?;
        drop(home_lock);
        let line = match (toggled, way) {
            (Err(Refused::NotListed), Way::On) => eyre::bail!(
                "{name} is not listed here; add it: swoosh service add {}",
                swoosh::serve::entry_for(name)
            ),
            (Err(Refused::NotListed), Way::Off) => eyre::bail!("{name} is not listed here"),
            (Err(Refused::List(error)), _) => return Err(error.into()),
            (Ok(Toggled::Turned), _) => format!("Turned {name} {} here.", way.verb()),
            (Ok(Toggled::Already), _) => format!("{name} is already {}.", way.verb()),
        };
        eprintln!("{line}");
        Ok(())
    }
}

/// Why a toggle changed nothing.
#[derive(Debug)]
enum Refused {
    /// The list does not hold the name the toggle was given.
    NotListed,
    /// The list is one a bare `serve` refuses to start from, so no name on it can be trusted as listed.
    List(ServingError),
}

/// Turn `name` `way` in `file`, the `serve.toml` at `path`, which holds the list it must be on. The list
/// is read as a bare `serve` reads it, so a hand-written `ping` is listed here as it is served there.
fn toggle(file: &mut ServeToml, name: &str, way: Way, path: &Path) -> Result<Toggled, Refused> {
    let listed = Started::bare(file, path)
        .map_err(Refused::List)?
        .names()
        .iter()
        .any(|held| held == name);
    if !listed {
        return Err(Refused::NotListed);
    }
    let changed = match way {
        Way::On => file.off.remove(name),
        Way::Off => file.off.insert(name.to_owned()),
    };
    Ok(if changed {
        Toggled::Turned
    } else {
        Toggled::Already
    })
}

#[cfg(test)]
#[path = "toggle_tests.rs"]
mod toggle_tests;
