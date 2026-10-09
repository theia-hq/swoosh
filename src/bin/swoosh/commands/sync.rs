//! `swoosh sync`: bring your device list up to date with your other devices, both ways.
//!
//! It exchanges with every live device of your root ([`swoosh::sync`]), one at a time, each within 5 s
//! and all within 20 s, and asks every one: it takes a newer list from any that has one and gives the
//! newest to any that lacks it, asking again any device it had asked before a take. It prints one report on stdout. It takes no argument, and runs only on a device of a
//! root, one that holds it or not. When your devices refuse this machine because its standing has ended
//! or was revoked here, it picks up its renewal from one of them ([`swoosh::renewal`]), says so, and
//! exchanges again. Then it asks each saved machine of a person with no root saved which root vouches for
//! it, and offers that root once per person ([`swoosh::learn`]).

use core::time::Duration;

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use swoosh::contacts::DeviceLabel;
use swoosh::home::Home;
use swoosh::renewal::{NodeFetch, PickUp, Renewed};
use swoosh::standing::{Standing, StandingError};
use swoosh::sync::{Answer, NodeDial, Reply, Until};
use swoosh::transport::ReachArgs;

use crate::commands::learning;

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
        let mut replies = swoosh::sync::round(&dial, &devices, Until::Every, TOTAL).await;
        // Refused for a standing that needs a renewal: pick it up from one of your devices, then exchange
        // again with it.
        match swoosh::renewal::after_round(ctx.home, &NodeFetch::new(node), &replies).await {
            PickUp::Skipped => {}
            PickUp::Took(renewed) => {
                println!("{}", took(&renewed));
                replies = swoosh::sync::round(&dial, &devices, Until::Every, TOTAL).await;
            }
            PickUp::Missed => {
                let label = swoosh::renewal::own_label(ctx.home).await;
                println!("{}", missed(label.as_ref()));
                learn_roots(node, ctx.home).await;
                return Ok(());
            }
        }
        let rows: Vec<(String, Row)> = replies
            .into_iter()
            .map(|(device, reply)| (device.name, Row::of(reply)))
            .collect();
        print!("{}", report(&rows));
        learn_roots(node, ctx.home).await;
        Ok(())
    }
}

/// After `sync`'s own lines: ask each saved machine of a person with no root saved which root vouches for
/// it ([`swoosh::learn::sweep`]), and tell the person once per person, in name order. Silent for a machine
/// that does not answer; never a failure of `sync`.
async fn learn_roots<T: Transport, D: Discovery>(node: &Node<T, D>, home: &Home) {
    let machines = match swoosh::contacts::ContactsStore::open(home).await {
        Ok(store) => swoosh::learn::unrooted(store.contacts()),
        Err(error) => {
            tracing::debug!(%error, "the book could not be read to ask for roots");
            return;
        }
    };
    let shown = swoosh::learn::sweep(node, machines).await;
    learning::tell_each(
        home,
        &shown,
        learning::Asking::here(),
        &mut swoosh::passphrase::Terminal,
        &mut std::io::stderr(),
    )
    .await;
}

/// The line `sync` prints when it took this machine's renewal from one of your devices.
pub(crate) fn took(renewed: &Renewed) -> String {
    format!(
        "took your renewal from {}: this machine is {} until {}.",
        renewed.from,
        renewed.name,
        renewed.ends()
    )
}

/// The line `sync` prints when none of your devices had a renewal for this machine, naming the renewal
/// to make where your root is kept.
pub(crate) fn missed(label: Option<&DeviceLabel>) -> String {
    let name = label.map_or_else(|| "<name>".to_owned(), ToString::to_string);
    format!(
        "none of your devices had a renewal for this machine. Where your root is kept: swoosh invite \
         {name}."
    )
}

/// Refuse on every standing but a device's, with `status`'s line for it.
pub(crate) async fn refuse_unless_device(home: &Home) -> eyre::Result<()> {
    let standing = match Standing::read(home).await {
        Ok(standing) => standing,
        Err(StandingError::Damaged(what)) => {
            eyre::bail!("{}", swoosh::standing::damaged_line(&what))
        }
        Err(other) => return Err(other.into()),
    };
    match standing {
        Standing::Device { .. } | Standing::HoldsRoot { .. } => Ok(()),
        Standing::Unpinned => eyre::bail!(NOT_A_DEVICE),
        Standing::InterruptedMint { .. } => eyre::bail!(swoosh::standing::UNFINISHED_MINT),
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
    /// The row one reply reads as; a device that refused this machine, or did not answer, is one that did
    /// not answer.
    pub(crate) fn of(reply: Reply) -> Self {
        match reply {
            Reply::Answered(Answer::Same) => Self::InSync,
            Reply::Answered(Answer::Took) => Self::Took,
            Reply::Answered(Answer::Gave) => Self::Gave,
            Reply::Answered(Answer::Forked | Answer::ForkRecorded { .. }) => Self::Fork,
            Reply::Answered(Answer::Refused) | Reply::NotAdmitted | Reply::Silent => Self::NoAnswer,
        }
    }
}

/// The report, one line per outcome: a fork line for each device that holds another list, then the one
/// line that says what moved, with the devices that did not answer in brackets; when only forks answered,
/// the devices that did not answer on a line of their own.
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
    let missed = names(Row::NoAnswer).join(", ");
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
        // Only forks answered: the devices that did not answer get their own line.
        if !missed.is_empty() {
            out.push_str(&format!("{missed} did not answer.\n"));
        }
        return out;
    };
    let missed = if missed.is_empty() {
        String::new()
    } else {
        format!(" ({missed} did not answer)")
    };
    out.push_str(&format!("{line}{missed}.\n"));
    out
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod sync_tests;
