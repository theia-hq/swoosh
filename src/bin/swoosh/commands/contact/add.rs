//! `swoosh contact add <person> root:<key>` and `swoosh contact add <person>/<name> <key>`: save another
//! person's root, or one machine of theirs, under a local name.
//!
//! The name's shape decides which, and the key's shape must agree: a bare person is saved with their root's
//! key, typed `root:ed01…`, which `share <svc> <person>` binds a link to, so every machine that root vouches
//! for can use it; `<person>/<name>` is one machine, typed `ed01…`, which `share <svc> <person>/<name>` binds
//! a link to alone, and which a dial can reach. Either kind of key where the other is wanted is a usage
//! error naming the form that saves it.
//!
//! A saved machine key is never replaced unasked: a name that holds another key refuses, naming both keys
//! and the way out. A person's root can change (they made a new one), so a different root over a saved one
//! replaces it, but only at a terminal, after both roots and the links it ends are shown and the new root's
//! token is typed; then the links this machine gave the old root are revoked, since only the old root's
//! holder could use them. A key saved under another name refuses, so one key has one name here.

use std::io::Write;
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use nauthy::Revocation;
use swoosh::contacts::{ContactRef, ContactsStore, Petname, Saved, Taken};
use swoosh::grants::{GrantKind, GrantRecord, Grants};
use swoosh::home::{Home, HomeWrite};
use swoosh::passphrase::Prompt;
use swoosh::root_key::{RootKey, RootKeyError};

use crate::commands::token;

/// Save a person's root, or one machine of theirs
#[derive(Debug, Args)]
pub struct AddCmd {
    /// A person, or one machine of theirs
    #[arg(value_name = "person | person/name", value_parser = super::new_contact)]
    pub name: ContactRef,
    /// A person's root key, or that one machine's key
    #[arg(value_name = "key | root key", value_parser = typed_key)]
    pub key: TypedKey,
}

/// The key `contact add` was given, in the kind its shape says: a machine's (`ed01…`) or a root's
/// (`root:ed01…`).
#[derive(Debug, Clone, Copy)]
pub enum TypedKey {
    /// A bare key: one machine's.
    Machine(NodeId),
    /// A key typed `root:ed01…`: a person's root.
    Root(RootKey),
}

/// Parse the key, keeping the kind its shape says.
fn typed_key(text: &str) -> Result<TypedKey, String> {
    if swoosh::root_key::is_prefixed(text) {
        return text
            .parse::<RootKey>()
            .map(TypedKey::Root)
            .map_err(|error: RootKeyError| error.to_string());
    }
    swoosh::peer::parse_key(text)
        .map(TypedKey::Machine)
        .map_err(|error| error.to_string())
}

/// A usage error found once the command runs (a key of the wrong kind for the name): exit 2, as clap's own
/// are.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

impl AddCmd {
    /// Save the key and persist, or refuse and write nothing. Re-adding the same key says so. A reserved
    /// person (`me`, `root`, `anyone`, `control`, `lookup`) never reaches here: [`new_contact`](super::new_contact)
    /// refuses it at parse. A root over a different saved one asks at `prompt` first; every line about a
    /// root goes to `err`.
    pub async fn run(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let name = &self.name;
        match (self.key, name.device()) {
            (TypedKey::Root(root), Some(_)) => {
                let person = name.petname();
                Err(Usage(format!(
                    "that is a root key, not a machine's key\n  To save it as {person}'s root:\n    swoosh \
                     contact add {person} {root}"
                ))
                .into())
            }
            (TypedKey::Machine(key), None) => {
                let person = name.petname();
                Err(Usage(format!(
                    "saving {person} takes a root key, not a machine's key\n  {person}'s swoosh status shows \
                     it as the key under \"your root\".\n  To save {person}:\n    swoosh contact add {person} \
                     root:<key>\n  To save this key as one of {person}'s machines instead:\n    swoosh contact \
                     add {person}/<name> {key}"
                ))
                .into())
            }
            (TypedKey::Machine(key), Some(_)) => add_machine(home, name, key).await,
            (TypedKey::Root(root), None) => add_root(home, name.petname(), root, prompt, err).await,
        }
    }
}

/// Save one machine's key under `<person>/<name>`. A name holding another key, or a key under another name,
/// refuses.
async fn add_machine(home: &Home, name: &ContactRef, key: NodeId) -> eyre::Result<()> {
    let home_lock = HomeWrite::take(home).await?;
    let mut store = ContactsStore::open(home).await?;
    let saved = match store.contacts_mut().save(name, key) {
        Ok(saved) => saved,
        Err(Taken::Name { held }) => {
            // The same count `contact rm` refuses on, so `revoke` is named exactly when `rm` needs it.
            let live =
                super::rm::live_links(home, &super::rm::holders(store.contacts(), name)).await?;
            let way_out = if live > 0 {
                WayOut::Revoke
            } else {
                WayOut::Remove
            };
            eyre::bail!("{}", replaced(name, held, key, way_out))
        }
        Err(Taken::Key { at }) => eyre::bail!("{}", second_name(&at, key)),
    };
    if saved == Saved::Created {
        store.save(&home_lock)?;
    }
    let short = swoosh::credential::short(&key);
    match saved {
        Saved::Created => println!("added {name} -> {short}"),
        Saved::Unchanged | Saved::Unlearned => println!("{name} already -> {short} (unchanged)"),
    }
    Ok(())
}

/// Save `root` as `person`'s. Into an empty slot it saves; over the same root it says so, and an explicit
/// save clears a learned mark; over a different root it is a replace, which asks first.
async fn add_root(
    home: &Home,
    person: &Petname,
    root: RootKey,
    prompt: &mut impl Prompt,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let held = ContactsStore::open(home)
        .await?
        .contacts()
        .signet(person)
        .map(|saved| saved.node);
    if let Some(old) = held
        && old != root.key()
    {
        return replace(home, person, RootKey::from(old), root, prompt, err).await;
    }
    let at = ContactRef::person(Petname::clone(person));
    let home_lock = HomeWrite::take(home).await?;
    let mut store = ContactsStore::open(home).await?;
    let saved = match store.contacts_mut().save(&at, root.key()) {
        Ok(saved) => saved,
        // Saved meanwhile under this name, as another root: run again to replace it.
        Err(Taken::Name { .. }) => eyre::bail!("{}", swoosh::standing::CHANGED),
        Err(Taken::Key { at }) => eyre::bail!("{}", second_name(&at, root.key())),
    };
    match saved {
        Saved::Created => {
            store.save(&home_lock)?;
            writeln!(err, "saved {} as {person}'s root.", root.short())?;
        }
        Saved::Unlearned => {
            store.save(&home_lock)?;
            writeln!(err, "Saved {person}'s root.")?;
        }
        Saved::Unchanged => writeln!(err, "{person}'s root is already saved.")?,
    }
    Ok(())
}

/// Replace `person`'s saved root `old` with `new`: only at a terminal, once both roots and the links it ends
/// are shown and `new`'s token is typed. Then, under `home.lock`, this machine's live links bound to `old`
/// are revoked and `new` is saved; a crash between the two leaves the old root saved with its links already
/// ended, never the new root saved with the old root's links still open. Nothing is written on a refusal.
async fn replace(
    home: &Home,
    person: &Petname,
    old: RootKey,
    new: RootKey,
    prompt: &mut impl Prompt,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let store = ContactsStore::open(home).await?;
    if let Some(at) = store.contacts().saved_at(&new.key()) {
        eyre::bail!("{}", second_name(&at, new.key()));
    }
    if !prompt.terminal() {
        eyre::bail!("{}", needs_terminal(person, new));
    }
    let ending = live_links(home, old.key()).await?;
    for line in [
        format!("{person}'s root here:"),
        format!("  {old}"),
        "The new root:".to_owned(),
        format!("  {new}"),
    ] {
        prompt.say(&line);
    }
    if !ending.is_empty() {
        prompt.say(&format!(
            "Replacing it will end these links you gave {person}:"
        ));
        for link in &ending {
            prompt.say(&row(link));
        }
    }
    let answer = token::ask(prompt, new, &format!("replace {person}'s root"))
        // A terminal gone since the check is the missing terminal.
        .map_err(|_| eyre::eyre!("{}", needs_terminal(person, new)))?;
    if answer == token::Typed::Other {
        eyre::bail!("that did not match; nothing was changed");
    }

    let home_lock = HomeWrite::take(home).await?;
    let mut store = ContactsStore::open(home).await?;
    // What the person read may have moved while they typed: the root replaced or removed meanwhile.
    if store.contacts().signet(person).map(|saved| saved.node) != Some(old.key()) {
        eyre::bail!("{}", swoosh::standing::CHANGED);
    }
    let ended = live_links(home, old.key()).await?;
    swoosh::revoked::add(
        &home_lock,
        home,
        ended
            .iter()
            .map(|link| Revocation::Id(link.root_id.clone())),
    )?;
    match store.contacts_mut().replace_root(person, new.key()) {
        Ok(_) => {}
        Err(Taken::Key { at }) => eyre::bail!("{}", second_name(&at, new.key())),
        Err(Taken::Name { .. }) => eyre::bail!("{}", swoosh::standing::CHANGED),
    }
    store.save(&home_lock)?;
    drop(home_lock);

    writeln!(err, "Replaced {person}'s root.")?;
    if ended.is_empty() {
        return Ok(());
    }
    writeln!(err, "\nlinks ended")?;
    for link in &ended {
        writeln!(err, "{}", row(link))?;
    }
    writeln!(err, "\nTo share again:")?;
    let mut services: Vec<&str> = Vec::new();
    for link in &ended {
        if !services.contains(&link.target.as_str()) {
            services.push(link.target.as_str());
        }
    }
    for service in services {
        writeln!(err, "  swoosh share {service} {person}")?;
    }
    Ok(())
}

/// The refusal for a replace with no terminal to ask at, naming the command to run at one.
fn needs_terminal(person: &Petname, new: RootKey) -> String {
    format!(
        "replacing {person}'s root needs a terminal\n  Run this at a terminal:\n    swoosh contact add {person} \
         {new}"
    )
}

/// One link's row in the replace's lists: its service, then the first 8 hex characters of its id, the id
/// `status` lists it by.
fn row(link: &GrantRecord) -> String {
    let id: String = link.root_id.to_hex().chars().take(8).collect();
    format!("  {:<16} {id}", link.target.as_str())
}

/// The links this machine gave `root` that still admit: bound to that root, not ended, not revoked. A
/// link bound to one of the person's machines is bound to that machine's key, so it is never among them.
async fn live_links(home: &Home, root: NodeId) -> eyre::Result<Vec<GrantRecord>> {
    let holder = root.to_string();
    let now = SystemTime::now();
    let revoked = swoosh::revoked::open(home)?;
    Ok(Grants::at(home.links())
        .load()
        .await?
        .into_iter()
        .filter(|record| record.kind == GrantKind::Fleet && record.holder == holder)
        .filter(|record| record.expiry > now)
        .filter(|record| !revoked.is_revoked_any([&record.root_id]))
        .collect())
}

/// What frees a name that holds another key: `contact rm` refuses while links given to it are live, so
/// then `revoke` runs first; with none live, `contact rm` alone, since a `revoke` would end nothing and fail.
#[derive(Debug, Clone, Copy)]
enum WayOut {
    /// Links given to the name are live: `revoke`, then `contact rm`.
    Revoke,
    /// No live link: `contact rm` alone.
    Remove,
}

/// The refusal for a machine's name that holds another key: both keys whole, so a person can compare them,
/// and the commands that free the name, each alone on its line.
fn replaced(name: &ContactRef, held: NodeId, typed: NodeId, way_out: WayOut) -> String {
    let head = format!("{name} is saved here as {held}, not {typed}");
    match way_out {
        WayOut::Revoke => format!(
            "{head}\n  a saved key is never replaced; to save the new one, end the links you gave {name}, \
             then remove {name}:\n    swoosh revoke {name}\n    swoosh contact rm {name}"
        ),
        WayOut::Remove => format!(
            "{head}\n  a saved key is never replaced; to save the new one, remove {name}:\n    swoosh \
             contact rm {name}"
        ),
    }
}

/// The refusal for a key saved under another name, naming where it is.
fn second_name(at: &ContactRef, key: NodeId) -> String {
    match at.device() {
        None => format!("that root is already saved as {}", at.petname()),
        Some(_) => format!("{key} is saved here already, as {at}"),
    }
}

#[cfg(test)]
#[path = "add_tests.rs"]
mod add_tests;
