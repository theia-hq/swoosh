//! `swoosh service enable <svc>` / `swoosh service disable <svc>`: turn one of YOUR node's services off or
//! back on, live, without stopping it.
//!
//! Both are LOCAL FILE WRITES on the `off` list of `<home>/serve.toml`, never a socket call and never a
//! remote op: you toggle your OWN node, so there is no `--at`. A running `serve` honors the edit within the
//! watch window (the [`LiveServeToml`](swoosh::serve_toml::LiveServeToml) its gate consults per stream), so a
//! `disable` refuses the service on the next stream and an `enable` restores it, both with NO restart. A
//! `disable` PERSISTS (fail-closed): a restart keeps a turned-off service off, so a node never silently
//! re-exposes something the operator disabled. An `enable` only REMOVES a name from the list, so it can only
//! return a declared service to its declared baseline, never open a new one or raise posture (validation is
//! serve-side; a name this node does not serve is simply a no-op there).
//!
//! Two racing toggles cannot lose an edit: the read-modify-write runs under `home.lock`, and the rewrite goes
//! through the home's one write routine, so a crash mid-write can never leave a torn list.

use std::collections::BTreeSet;

use clap::Args;
use nauthy::Service;
use swoosh::home::{Home, HomeWrite};
use swoosh::serve_toml::ServeToml;

/// Turn a service off (`disable`) or back on (`enable`); the leaf carries only the service name, the verb
/// (which way to toggle) is the subcommand.
#[derive(Debug, Args)]
pub struct ServiceToggleCmd {
    /// the service to toggle (a name this node serves, e.g. `speed`)
    #[arg(value_name = "service", value_parser = swoosh::names::service)]
    pub service: Service,
}

impl ServiceToggleCmd {
    /// `service disable <svc>`: add the name to the services off in `<home>/serve.toml` so a running `serve` refuses it live and a
    /// restart keeps it off. Idempotent: disabling an already-disabled service just reports the state.
    pub async fn run_disable(self, home: &Home) -> eyre::Result<()> {
        let home_lock = HomeWrite::take(home).await?;
        edit(&home_lock, home, |disabled| {
            disabled.insert(self.service.to_string());
        })?;
        println!("{}: disabled (persisted)", self.service);
        Ok(())
    }

    /// `service enable <svc>`: remove the name from the services off in `<home>/serve.toml` so a running `serve` serves it again
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

/// Change the services off in `<home>/serve.toml` by `mutate`, under `home.lock`, which the caller holds,
/// so two concurrent toggles serialize (neither loses the other's edit). The other fields keep what the
/// file held.
fn edit(
    home_lock: &HomeWrite,
    home: &Home,
    mutate: impl FnOnce(&mut BTreeSet<String>),
) -> eyre::Result<()> {
    ServeToml::update(home_lock, home, |file| mutate(&mut file.off))?;
    Ok(())
}

#[cfg(test)]
#[path = "toggle_tests.rs"]
mod toggle_tests;
