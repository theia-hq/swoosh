//! `swoosh service enable <svc>` / `swoosh service disable <svc>`: turn one of YOUR node's services off or
//! back on, live, without stopping it.
//!
//! Both are LOCAL FILE WRITES on `<home>/disabled` (a newline list of disabled service names), never a
//! socket call and never a remote op: you toggle your OWN node, so there is no `--at`. A running `serve`
//! honors the edit within the mtime-watch window (the [`FileDisabledList`](tightbeam::enabled::FileDisabledList)
//! oracle its gate consults per stream), so a `disable` refuses the service on the next stream and an `enable`
//! restores it, both with NO restart. A `disable` PERSISTS (fail-closed): a restart keeps a turned-off service
//! off, so a node never silently re-exposes something the operator disabled. An `enable` only REMOVES a name
//! from the list, so it can only return a declared service to its declared baseline, never open a new one or
//! raise posture (validation is serve-side; a name this node does not serve is simply a no-op there).
//!
//! Two racing toggles cannot lose an edit: the read-modify-write runs under `home.lock`, and the rewrite goes
//! through the home's one write routine, so a crash mid-write can never leave a torn list.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use clap::Args;
use nauthy::Service;
use swoosh::home::{Home, HomeWrite};

/// Turn a service off (`disable`) or back on (`enable`); the leaf carries only the service name, the verb
/// (which way to toggle) is the subcommand.
#[derive(Debug, Args)]
pub struct ServiceToggleCmd {
    /// the service to toggle (a name this node serves, e.g. `speed`)
    #[arg(value_name = "service", value_parser = swoosh::names::service)]
    pub service: Service,
}

impl ServiceToggleCmd {
    /// `service disable <svc>`: add the name to `<home>/disabled` so a running `serve` refuses it live and a
    /// restart keeps it off. Idempotent: disabling an already-disabled service just reports the state.
    pub async fn run_disable(self, home: &Home) -> eyre::Result<()> {
        let home_lock = HomeWrite::take(home).await?;
        edit(&home_lock, home, |disabled| {
            disabled.insert(self.service.to_string());
        })?;
        println!("{}: disabled (persisted)", self.service);
        Ok(())
    }

    /// `service enable <svc>`: remove the name from `<home>/disabled` so a running `serve` serves it again
    /// live. Idempotent: enabling a service that was not disabled just reports the state. Only ever removes a
    /// name, so it returns a declared service to its baseline and never opens a new one.
    pub async fn run_enable(self, home: &Home) -> eyre::Result<()> {
        let home_lock = HomeWrite::take(home).await?;
        edit(&home_lock, home, |disabled| {
            disabled.remove(self.service.as_str());
        })?;
        println!("{}: enabled", self.service);
        Ok(())
    }
}

/// Turn back on every one of `names` that `<home>/disabled` holds: a `serve` that names a service at
/// start serves it, so a service turned off yesterday is not refused by today's `serve ssh`. Writes nothing
/// when none of them is off. Under `home.lock`, which the caller holds.
pub(crate) fn turn_on<'a>(
    home_lock: &HomeWrite,
    home: &Home,
    names: impl IntoIterator<Item = &'a str>,
) -> eyre::Result<()> {
    let off = disabled(home)?;
    let names: Vec<&str> = names
        .into_iter()
        .filter(|name| off.contains(*name))
        .collect();
    if names.is_empty() {
        return Ok(());
    }
    edit(home_lock, home, |disabled| {
        for name in names {
            disabled.remove(name);
        }
    })
}

/// The service names `<home>/disabled` holds; none when there is no file.
pub(crate) fn disabled(home: &Home) -> eyre::Result<BTreeSet<String>> {
    read(&home.disabled())
}

/// Read `<home>/disabled`, apply `mutate`, and write it back atomically, all under `home.lock` so two
/// concurrent toggles serialize (neither loses the other's edit). The disabled set is a [`BTreeSet`] so the
/// rewritten file is name-sorted and stable (a clean diff, and the same shape the denylist writes). An
/// EMPTY set still writes an (empty) file rather than deleting it, so the oracle reads "nothing disabled"
/// from a present file and the mtime-watch tracks the change cleanly.
fn edit(
    home_lock: &HomeWrite,
    home: &Home,
    mutate: impl FnOnce(&mut BTreeSet<String>),
) -> eyre::Result<()> {
    let mut disabled = read(&home.disabled())?;
    mutate(&mut disabled);
    let mut body = disabled.iter().cloned().collect::<Vec<_>>().join("\n");
    body.push('\n');
    swoosh::config::write_private_atomic(home_lock, &home.disabled(), body.as_bytes())?;
    Ok(())
}

/// Parse `<home>/disabled` into its set of names: one trimmed, non-empty name per line. An absent file is an
/// empty set (nothing disabled), the first-run case, not an error.
fn read(path: &Path) -> eyre::Result<BTreeSet<String>> {
    match swoosh::home::read_trust_file(path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[path = "toggle_tests.rs"]
mod toggle_tests;
