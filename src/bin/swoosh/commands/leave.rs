//! `swoosh leave [--new-key]`: stop being one of your devices, and with `--new-key` also give this machine
//! a new key.
//!
//! `leave` removes this machine's standing, its copy of your devices' list, and the pin, the pin last
//! ([`swoosh::joining::leave`]). It keeps every revocation this machine learned, and refuses where your
//! root is kept. `--new-key` replaces the key too, keeping the old key and its links aside; it refuses while
//! `serve` runs, since a running `serve` is this machine's old key. On a machine that is no root's device
//! it only replaces the key.

use std::io::{self, Write};
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use swoosh::escape::EscapedPath;
use swoosh::home::{Home, HomeWrite, ServeLock};
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::root::Date;
use swoosh::standing::{Standing, StandingError};

/// Stop being one of your devices. `--new-key` also gives this machine a new key.
#[derive(Debug, Args)]
#[command(
    after_long_help = "A server you reach only through swoosh needs its console after `leave --new-key`, unless it \
                       first issued you a link (swoosh share ssh <your key>)."
)]
pub struct LeaveCmd {
    /// Make a new key: inside the invite, or for this machine.
    #[arg(long = "new-key")]
    pub new_key: bool,
}

/// What this machine was before it left.
enum Was {
    /// A device of `root` until `until`.
    Device { root: NodeId, until: u64 },
    /// A home whose records disagreed, trusting `root` if its pin could be read.
    Damaged { root: Option<NodeId> },
    /// No root's device.
    Unpinned,
}

impl LeaveCmd {
    /// Leave, on the real terminal and clock, printing the new key on stdout.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.leave(
            home,
            &mut Terminal,
            SystemTime::now(),
            &mut io::stdout(),
            &mut io::stderr(),
        )
        .await
    }

    pub(crate) async fn leave(
        &self,
        home: &Home,
        prompt: &mut impl Prompt,
        now: SystemTime,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let was = match Standing::read(home).await {
            Ok(standing) => match standing {
                Standing::Device { pin, until } => Was::Device {
                    root: pin,
                    until: unix(until),
                },
                Standing::Unpinned if self.new_key => Was::Unpinned,
                Standing::Unpinned => eyre::bail!("this machine is not one of your devices."),
                Standing::HoldsRoot { .. } => eyre::bail!("{}", swoosh::root::KEPT_HERE),
                Standing::InterruptedMint { .. } => {
                    eyre::bail!(swoosh::standing::UNFINISHED_MINT)
                }
            },
            Err(StandingError::Damaged(_)) => Was::Damaged {
                root: swoosh::config::load_signet(home).await.ok().flatten(),
            },
            Err(other) => return Err(other.into()),
        };

        // Taken once the standing is read, so a refusal of the standing leaves no lock file behind. Taken
        // without waiting and held to the end, `serve.lock` rules out a running `serve`. The new key is
        // staged before anything is left, so a passphrase that is not chosen leaves the home as it was.
        let (_serve_lock, new_key) = if self.new_key {
            let serve_lock = {
                let home_lock = HomeWrite::take(home).await?;
                ServeLock::take(&home_lock, home)?
            };
            (
                Some(serve_lock),
                Some(swoosh::identity::NewKey::stage(home, prompt)?),
            )
        } else {
            (None, None)
        };
        let serving = !self.new_key && swoosh::home::serve_running(home).await;
        let home_lock = HomeWrite::take(home).await?;
        still(&home_lock, home, &was).await?;
        let name = match was {
            Was::Device { .. } => own_name(home).await,
            Was::Damaged { .. } | Was::Unpinned => None,
        };
        if !matches!(was, Was::Unpinned) {
            swoosh::joining::leave(&home_lock, home)?;
        }
        let left = match was {
            Was::Device { root, .. } | Was::Damaged { root: Some(root) } => Some(root),
            Was::Damaged { root: None } | Was::Unpinned => None,
        };
        if let Some(root) = left {
            let listed = match (&was, name) {
                (Was::Device { until, .. }, Some(name)) => format!(
                    " Your root still lists it as me/{name} until {}: revoke it there with swoosh revoke \
                     me/{name}.",
                    Date(*until)
                ),
                _ => String::new(),
            };
            writeln!(
                err,
                "this machine no longer trusts root root:{root}.{listed}"
            )?;
            if serving {
                writeln!(err, "{}", super::join::sessions_end(root))?;
            }
        }

        if let Some(new_key) = new_key {
            let replaced = new_key.put(&home_lock, home, &Date(unix(now)).to_string())?;
            writeln!(out, "{}", replaced.key)?;
            out.flush()?;
            if let Some(kept) = &replaced.kept {
                writeln!(err, "kept the old key at {}", EscapedPath(kept))?;
            }
            writeln!(
                err,
                "links this machine made under its old key stop working."
            )?;
            if matches!(was, Was::Device { .. }) {
                writeln!(
                    err,
                    "Give the new key to the machine that keeps your root to invite it again."
                )?;
            }
        }
        Ok(())
    }
}

/// Refuse, under `home.lock`, when this machine's standing is no longer `was`, the one read before the
/// lock: a `join`, a mint or another `leave` ran meanwhile, during the new key's prompt or before it.
async fn still(_home_lock: &HomeWrite, home: &Home, was: &Was) -> eyre::Result<()> {
    let holds = match Standing::read(home).await {
        Ok(standing) => match (was, standing) {
            (Was::Device { root, .. }, Standing::Device { pin, .. }) => *root == pin,
            (Was::Unpinned, Standing::Unpinned) => true,
            _ => false,
        },
        Err(StandingError::Damaged(_)) => matches!(was, Was::Damaged { .. }),
        Err(other) => return Err(other.into()),
    };
    if !holds {
        eyre::bail!("{}", swoosh::standing::CHANGED);
    }
    Ok(())
}

/// This machine's name among your devices, when it has one.
async fn own_name(home: &Home) -> Option<String> {
    swoosh::renewal::own_label(home)
        .await
        .map(|label| label.to_string())
}

/// `when` in unix seconds.
fn unix(when: SystemTime) -> u64 {
    when.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
#[path = "leave_tests.rs"]
mod leave_tests;
