//! `swoosh contact add <person> <root key>` and `swoosh contact add <person>/<name> <key>`: save another
//! person's root, or one machine of theirs, under a local name.
//!
//! The name's shape decides which: a bare person is saved with their root's key, which `share <svc>
//! <person>` binds a link to, so every machine that root vouches for can use it; `<person>/<name>` is one
//! machine, which `share <svc> <person>/<name>` binds a link to alone, and which a dial can reach. A root key
//! may be typed `root:ed01…`, the form `status` and `revoke`'s recipe print it in; a machine takes no `root:`.
//!
//! A saved key is never replaced unasked. A name that holds another key refuses, naming both keys and the
//! way out: the links given to the key it holds are found by that name, so `revoke` and `contact rm` must
//! run before the name can point elsewhere. A key saved under another name refuses too, so one key has one
//! name here. (U22c turns the root's refusal into a typed confirmation that also ends the old root's links;
//! a machine's stays a refusal.)

use bifrost::NodeId;
use clap::Args;
use swoosh::contacts::{ContactRef, ContactsStore, Saved, Taken};
use swoosh::home::{Home, HomeWrite};

/// Save a person's root, or one machine of theirs
#[derive(Debug, Args)]
pub struct AddCmd {
    /// `alice` for a person, or `alice/laptop` for one machine of theirs
    #[arg(value_name = "name", value_parser = super::new_contact)]
    pub name: ContactRef,
    /// the person's root key, or that machine's key
    #[arg(value_name = "key", value_parser = typed_key)]
    pub key: TypedKey,
}

/// The key `contact add` was given, with whether it was typed as a root (`root:ed01…`).
#[derive(Debug, Clone, Copy)]
pub struct TypedKey {
    /// The key itself, with any `root:` taken off.
    pub key: NodeId,
    /// Typed with `root:` before it.
    pub root: bool,
}

/// The prefix that types a root, ASCII case aside.
const ROOT_PREFIX: &str = "root:";

/// Parse the key, taking off a `root:` before it (in any case) and remembering it was there.
fn typed_key(text: &str) -> Result<TypedKey, String> {
    let rest = text
        .get(..ROOT_PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(ROOT_PREFIX))
        .and_then(|_| text.get(ROOT_PREFIX.len()..));
    let key = swoosh::peer::parse_key(rest.unwrap_or(text)).map_err(|error| error.to_string())?;
    Ok(TypedKey {
        key,
        root: rest.is_some(),
    })
}

/// A usage error found once the command runs (a root key given for a machine): exit 2, as clap's own are.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

impl AddCmd {
    /// Save the key and persist, or refuse and write nothing. Re-adding the same key says so. A reserved
    /// person (`me`, `root`, `anyone`) never reaches here: [`new_contact`](super::new_contact) refuses it at
    /// parse.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        let name = &self.name;
        let key = self.key.key;
        if self.key.root && name.device().is_some() {
            let person = name.petname();
            return Err(Usage(format!(
                "root:{key} is a root key, which vouches for all of {person}'s machines: swoosh contact add \
                 {person} root:{key}"
            ))
            .into());
        }
        let home_lock = HomeWrite::take(home).await?;
        let mut store = ContactsStore::open(home).await?;
        let saved = match store.contacts_mut().save(name, key) {
            Ok(saved) => saved,
            Err(Taken::Name { held }) => eyre::bail!("{}", replaced(name, held, key)),
            Err(Taken::Key { at }) => eyre::bail!("{}", second_name(&at, key)),
        };
        if saved == Saved::Created {
            store.save(&home_lock)?;
        }
        let short = swoosh::credential::short(&key);
        let person = name.petname();
        match (name.device(), saved) {
            (None, Saved::Created) => eprintln!("saved root:{short} as {person}'s root."),
            (None, Saved::Unchanged) => eprintln!("root:{short} is already {person}'s root."),
            (Some(_), Saved::Created) => println!("added {name} -> {short}"),
            (Some(_), Saved::Unchanged) => println!("{name} already -> {short} (unchanged)"),
        }
        Ok(())
    }
}

/// The refusal for a name that holds another key: both keys whole, so a person can compare them, and the
/// two commands that free the name. `revoke` first, since `contact rm` refuses while links to it are live.
fn replaced(name: &ContactRef, held: NodeId, typed: NodeId) -> String {
    let (held, typed, what) = match name.device() {
        None => (format!("root:{held}"), format!("root:{typed}"), "root"),
        Some(_) => (held.to_string(), typed.to_string(), "key"),
    };
    let saved = match name.device() {
        None => format!("{name}'s root"),
        Some(_) => name.to_string(),
    };
    format!(
        "{saved} here is {held}, not {typed}\n  A saved {what} is never replaced. To save the new one, end the \
         links you gave {name}, then remove {name}:\n    swoosh revoke {name}\n    swoosh contact rm {name}"
    )
}

/// The refusal for a key saved under another name, naming where it is.
fn second_name(at: &ContactRef, key: NodeId) -> String {
    match at.device() {
        None => format!(
            "root:{key} is saved here already, as {}'s root",
            at.petname()
        ),
        Some(_) => format!("{key} is saved here already, as {at}"),
    }
}

#[cfg(test)]
#[path = "add_tests.rs"]
mod add_tests;
