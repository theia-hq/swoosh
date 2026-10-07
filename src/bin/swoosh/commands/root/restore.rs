//! `swoosh root restore <dir>`: put your root on this machine from a copy.
//!
//! Two steps, like `join`: every check, the passphrase and the writes run here, before any transport is
//! bound ([`RestoreCmd::run_local`]), so a refusal binds nothing; then [`RestoreSync`] binds one to exchange
//! with your devices, which brings the restored root up to date, and prints what happened.

use std::io::{self, Write};
use std::path::PathBuf;

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use swoosh::home::Home;
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::root::Restored;
use swoosh::sync::{Dial, NodeDial};
use swoosh::transport::ReachArgs;

/// put your root on this machine from a copy
#[derive(Debug, Args)]
pub struct RestoreCmd {
    /// the copy's own directory, which root backup made
    #[arg(value_name = "dir")]
    pub(crate) dir: PathBuf,
    #[command(flatten)]
    pub(crate) reach: ReachArgs,
}

impl RestoreCmd {
    /// Check, ask and write, at the terminal: the exchange to run next, or the refusal.
    pub async fn run_local(self, home: &Home) -> eyre::Result<RestoreSync> {
        self.restore(home, &mut Terminal).await
    }

    pub(crate) async fn restore(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
    ) -> eyre::Result<RestoreSync> {
        let restored = swoosh::root::restore(home, &self.dir, prompt).await?;
        Ok(RestoreSync {
            restored,
            reach: self.reach,
        })
    }
}

/// The exchange after a restore, with your devices: it binds a transport.
#[derive(Debug)]
pub struct RestoreSync {
    restored: Restored,
    reach: ReachArgs,
}

impl RestoreSync {
    /// Exchange through `dial`, then say what was restored and from where.
    pub(crate) async fn finish(
        self,
        home: &Home,
        dial: &impl Dial,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let (root, was_device) = (self.restored.root, self.restored.was_device);
        let synced = self.restored.sync(home, dial).await?;
        let short = swoosh::credential::short(&root);
        match synced.from.filter(|_| !synced.waiting) {
            _ if synced.waiting => writeln!(
                err,
                "restored root:{short}, your root, on this machine. Your other devices learn of this machine \
                 the next time you use your root."
            )?,
            Some(from) => writeln!(
                err,
                "restored root:{short}, your root, on this machine; brought up to date from {from}."
            )?,
            None => writeln!(
                err,
                "restored root:{short}, your root, on this machine. No device answered: your other devices \
                 learn of this machine the next time you use your root."
            )?,
        }
        if !was_device {
            writeln!(
                err,
                "a copy of your root, locked with its passphrase, is wherever the lost copy is. A strong \
                 passphrase holds; a weak or seen one does not: then replace your root: swoosh revoke --help"
            )?;
        }
        Ok(())
    }
}

impl swoosh::reaching::Reaching for RestoreSync {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// The exchange dials your devices itself.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        None
    }

    /// `root restore` takes no `--present` and no peer, so there is nothing to conflict.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        Ok(())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, as this machine: each device's gate admits it by the standing the restore just wrote.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: None,
        })
    }

    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.finish(ctx.home, &NodeDial::new(node, ctx.home), &mut io::stderr())
            .await
    }
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod restore_tests;
