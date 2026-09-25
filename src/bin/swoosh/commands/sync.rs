//! `swoosh sync`: bring your device list up to date with your other devices, both ways.
//!
//! It exchanges with every live device of your root ([`swoosh::sync`]), each within 5 s and all within
//! 20 s, and asks every one: it takes a newer list from any that has one and gives the newest to any
//! that lacks it. It prints one report on stdout. It takes no argument, and runs only on a device of a
//! root, one that holds it or not.

use core::time::Duration;

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use swoosh::home::Home;
use swoosh::standing::{Standing, StandingError};
use swoosh::sync::{Answer, NodeDial, Until};
use swoosh::transport::ReachArgs;

/// How long `sync` spends on all your devices together.
const TOTAL: Duration = Duration::from_secs(20);

/// The refusal on a machine that is not a device of any root.
const NOT_A_DEVICE: &str =
    "this machine is not one of your devices yet: nothing to sync. To join yours: swoosh join";

/// Bring your device list up to date with your other devices, both ways.
#[derive(Debug, Args)]
pub struct SyncCmd {
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for SyncCmd {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// `sync` dials every device itself, and each dial is an exchange already.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        None
    }

    /// `sync` takes no `--present` and no peer, so there is nothing to conflict.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        Ok(())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, as this machine: each device's gate admits it by the standing it presents, which is
    /// bound to this home's key.
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
        refuse_unless_device(ctx.home).await?;
        let devices = swoosh::sync::devices(ctx.home, []).await?;
        let dial = NodeDial::new(node, ctx.home);
        let answers = swoosh::sync::round(&dial, &devices, Until::Every, TOTAL).await;
        let rows: Vec<(String, Row)> = answers
            .into_iter()
            .map(|(device, answer)| (device.name, Row::of(answer)))
            .collect();
        print!("{}", report(&rows));
        Ok(())
    }
}

/// Refuse on every standing but a device's, with `status`'s line for it.
pub(crate) async fn refuse_unless_device(home: &Home) -> eyre::Result<()> {
    let read = match Standing::read(home).await {
        Ok(read) => read,
        Err(StandingError::Damaged(what)) => {
            eyre::bail!("{}", swoosh::standing::damaged_line(&what))
        }
        Err(other) => return Err(other.into()),
    };
    for line in &read.finished {
        eprintln!("{line}");
    }
    match read.standing {
        Standing::Device { .. } | Standing::HoldsRoot { .. } => Ok(()),
        Standing::Unpinned | Standing::PinOnly { .. } => eyre::bail!(NOT_A_DEVICE),
        Standing::InterruptedMint { root_key } => {
            eyre::bail!("{}", swoosh::standing::unfinished_line(root_key))
        }
    }
}

/// What `sync` counts one device as, from its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Row {
    /// It held the same list.
    InSync,
    /// It held a newer list, and this machine took it.
    Took,
    /// It lacked the newest list, and took it from this machine.
    Gave,
    /// It holds another list at the same number: two copies of your root both signed one.
    Fork,
    /// It refused, or did not answer in time.
    NoAnswer,
}

impl Row {
    /// The row one answer reads as; `None` is a device that did not answer.
    pub(crate) fn of(answer: Option<Answer>) -> Self {
        match answer {
            Some(Answer::Same) => Self::InSync,
            Some(Answer::Took) => Self::Took,
            Some(Answer::Gave) => Self::Gave,
            Some(Answer::Forked | Answer::ForkRecorded { .. }) => Self::Fork,
            Some(Answer::Refused) | None => Self::NoAnswer,
        }
    }
}

/// The report, one line per outcome: a fork line for each device that holds another list, then the one
/// line that says what moved, with the devices that did not answer in brackets.
pub(crate) fn report(rows: &[(String, Row)]) -> String {
    let names = |row: Row| -> Vec<&str> {
        rows.iter()
            .filter(|(_, got)| *got == row)
            .map(|(name, _)| name.as_str())
            .collect()
    };
    if rows.iter().all(|(_, row)| *row == Row::NoAnswer) {
        return "no device answered; your devices get it at their next sync.\n".to_owned();
    }
    let mut out = String::new();
    for name in names(Row::Fork) {
        out.push_str(&format!(
            "{name} holds a different list of your devices. Kept every revoked key from both; your next \
             swoosh invite or swoosh revoke settles it.\n"
        ));
    }
    let missed = names(Row::NoAnswer);
    let missed = if missed.is_empty() {
        String::new()
    } else {
        format!(" ({} did not answer)", missed.join(", "))
    };
    let (took, gave, same) = (names(Row::Took), names(Row::Gave), names(Row::InSync));
    let line = if !took.is_empty() {
        let gave = if gave.is_empty() {
            String::new()
        } else {
            format!("; gave it to {}", gave.join(", "))
        };
        format!(
            "took the newest list of your devices from {}{gave}",
            took.join(", ")
        )
    } else if !gave.is_empty() {
        format!(
            "gave the newest list of your devices to {}",
            gave.join(", ")
        )
    } else if !same.is_empty() {
        format!("in sync with {}", same.join(", "))
    } else {
        return out;
    };
    out.push_str(&format!("{line}{missed}.\n"));
    out
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod sync_tests;
