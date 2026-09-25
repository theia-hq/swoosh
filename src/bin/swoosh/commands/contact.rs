//! `swoosh contact`: manage the local address book (petnames for peer identities).
//!
//! A local verb group: unlike the reach verbs it binds no transport and dials nobody, it just edits the
//! contacts file beside the identity. `main` dispatches this before composing any transport, since there
//! is nothing to reach. Each leaf owns an `async fn run(self, ..)` that consumes it and persists.
//!
//! `me/` is not edited here: it lists this person's own devices, and their root decides it. `add` and
//! `rm` refuse it and write nothing.

use clap::Subcommand;
use swoosh::contacts::{ContactRef, ContactsStore, Petname};
use swoosh::names::NameError;

pub mod add;
pub mod ls;
pub mod rm;
pub mod signet;

/// Manage local petnames: save a peer's key under a name, list saved contacts, remove one.
#[derive(Debug, Subcommand)]
pub enum ContactCmd {
    /// Save a peer's key under a petname (`alice` or `alice/macbook` for a device).
    Add(add::AddCmd),
    /// Record a person's signet root, so `--for fleet:<petname>` binds their fleet.
    Signet(signet::SignetCmd),
    /// List saved contacts, or one contact's devices.
    Ls(ls::LsCmd),
    /// Remove a contact, or one of its devices (`alice` or `alice/macbook`).
    Rm(rm::RmCmd),
}

impl ContactCmd {
    /// Run the selected contact verb against the loaded store.
    pub async fn run(self, store: ContactsStore) -> eyre::Result<()> {
        match self {
            Self::Add(cmd) => cmd.run(store).await,
            Self::Signet(cmd) => cmd.run(store).await,
            Self::Ls(cmd) => cmd.run(store).await,
            Self::Rm(cmd) => cmd.run(store).await,
        }
    }
}

/// The guidance for a typed name under `me/`: this person's own devices are listed by their root, never
/// typed into the address book.
const ME_IS_YOUR_ROOTS: &str = "`me/` lists your devices, and your root decides it. Add one with `swoosh \
                                invite <name> <key>`; remove one with `swoosh revoke me/<name>`.";

/// Refuse a name under `me/`, before anything is written.
fn refuse_me(name: &ContactRef) -> eyre::Result<()> {
    if name.petname().as_str() == "me" {
        eyre::bail!(ME_IS_YOUR_ROOTS);
    }
    Ok(())
}

/// Parse the name `contact add` saves, at the clap boundary (exit 2): a contact address whose person is not
/// reserved. `me` gets its own guidance; `root` and `anyone` name nobody.
fn new_contact(text: &str) -> Result<ContactRef, String> {
    let name: ContactRef = text.parse().map_err(|error: NameError| error.to_string())?;
    if name.petname().as_str() == "me" {
        return Err(ME_IS_YOUR_ROOTS.to_owned());
    }
    name.petname()
        .clone()
        .unreserved()
        .map_err(|error| error.to_string())?;
    Ok(name)
}

/// Parse the person `contact signet` records, at the clap boundary (exit 2): a petname that is not
/// reserved.
fn new_person(text: &str) -> Result<Petname, NameError> {
    text.parse::<Petname>()?.unreserved()
}
