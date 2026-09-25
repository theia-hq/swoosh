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
use swoosh::contacts::{ContactsStore, ME, Petname};
use swoosh::home::Home;
use swoosh::identity::HomeLock;
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
            Ok(read) => {
                for line in &read.finished {
                    writeln!(err, "{line}")?;
                }
                match read.standing {
                    Standing::Device { pin, until } => Was::Device {
                        root: pin,
                        until: unix(until),
                    },
                    Standing::Unpinned if self.new_key => Was::Unpinned,
                    Standing::Unpinned => eyre::bail!("this machine is not one of your devices."),
                    Standing::HoldsRoot { .. } => eyre::bail!(
                        "your root is kept on this machine, and a machine that keeps a root is that root's \
                         device. To move your root off it: swoosh move-root <dir>"
                    ),
                    Standing::InterruptedMint { root_key } => {
                        eyre::bail!("{}", swoosh::standing::unfinished_line(root_key))
                    }
                }
            }
            Err(StandingError::Damaged(_)) => Was::Damaged {
                root: swoosh::config::load_signet(home).await.ok().flatten(),
            },
            Err(other) => return Err(other.into()),
        };

        // Taken once the standing is read, so a refusal of the standing leaves no lock file behind.
        let _lock = if self.new_key {
            Some(HomeLock::new_key(home)?)
        } else {
            None
        };
        let serving = HomeLock::is_held(home);
        let name = match was {
            Was::Device { .. } => own_name(home).await,
            Was::Damaged { .. } | Was::Unpinned => None,
        };
        if !matches!(was, Was::Unpinned) {
            swoosh::joining::leave(home).await?;
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

        if self.new_key {
            let replaced = swoosh::identity::replace(home, prompt, &Date(unix(now)).to_string())?;
            writeln!(out, "{}", replaced.key)?;
            out.flush()?;
            if let Some(kept) = &replaced.kept {
                writeln!(err, "kept the old key at {}", kept.display())?;
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

/// This machine's name among your devices, from `me`, when it has one there.
async fn own_name(home: &Home) -> Option<String> {
    let own = swoosh::identity::inspect(home).ok()?.stored().node_id();
    let store = ContactsStore::open(home.contacts()).await.ok()?;
    let me = Petname::stored(ME).ok()?;
    let devices = store.contacts().devices(&me)?;
    devices
        .into_iter()
        .find(|(_, key)| **key == own)
        .map(|(label, _)| label.to_string())
}

/// `when` in unix seconds.
fn unix(when: SystemTime) -> u64 {
    when.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
#[path = "leave_tests.rs"]
mod leave_tests;
