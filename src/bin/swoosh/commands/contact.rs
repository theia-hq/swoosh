//! `swoosh contact`: save or remove another person's key under a name.
//!
//! A local verb group: it binds no transport and dials nobody, it just edits the contacts file beside the
//! identity. `main` dispatches this before composing any transport, since there is nothing to reach. Each
//! leaf owns an `async fn run(self, ..)` that consumes it and persists. Each takes `home.lock` before it
//! opens the book and holds it to the save, so a fold that lands meanwhile never loses the edit.
//!
//! The shape of the name decides what is saved: `alice` is a person, saved with the key of their root, and
//! `alice/laptop` is one machine of theirs, saved with its own key.
//!
//! `me/` is not edited here: it lists this person's own devices, and their root decides it. `add` and
//! `rm` refuse it and write nothing.

use std::io::Write;

use clap::Subcommand;
use swoosh::contacts::ContactRef;
use swoosh::home::Home;
use swoosh::names::NameError;
use swoosh::passphrase::Prompt;

pub mod add;
pub mod rm;

/// Save or remove another person's key under a name.
#[derive(Debug, Subcommand)]
pub enum ContactCmd {
    /// Save a person's root, or one machine of theirs
    Add(add::AddCmd),
    /// Remove a saved person, or one machine of theirs
    Rm(rm::RmCmd),
}

impl ContactCmd {
    /// Run the selected contact verb against `home`'s book. Replacing a person's root asks at `prompt`, and
    /// its lines go to `err`.
    pub async fn run(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        match self {
            Self::Add(cmd) => cmd.run(home, prompt, err).await,
            Self::Rm(cmd) => cmd.run(home).await,
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
