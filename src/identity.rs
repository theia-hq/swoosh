//! The node identity: the ed25519 secret every swoosh verb binds under.
//!
//! Identity is chosen by intent, and exactly one intent CREATES a key. A verb that must be *reachable at
//! a stable address* (`serve`) persists its secret at `<home>/machine/key`: it loads that key and writes
//! one on first use, so restarting the node keeps its address. A verb that only *reaches outward* (`ping`,
//! `speed`, `reach`, including the `reach` behind `swoosh ssh`) LOADS that key when it already exists,
//! because the membership badge it presents must root at the key the dial binds under, and mints a
//! throwaway in-memory key when it does not. It never writes one: a dial does not provision a node, and
//! the file it would write is the very key a later `serve` roots its fleet at.
//!
//! An explicit home (`--home <dir>` or `SWOOSH_HOME`) chooses WHERE that key lives, never WHETHER one is
//! created. The verb's intent alone decides that, so a home named for one outward dial is left exactly as
//! it was found.
//!
//! Nothing here ever writes OVER a key that is already there. The file is a [`keystore`] key file, and
//! that crate enforces the rule for every write: a key is minted only into the absence of one, a file
//! that is not a key this build reads is refused rather than minted over, and [`write`] (the `join`
//! path) refuses a home that already holds a different identity. The key is the one file in the store
//! with no issuer and no second copy: a signet roots every badge its owner ever signed, and there is
//! nobody to cut another. So it is replaced only when the operator asks for it by name, by a restore ([`restore`]),
//! which checks the identity it replaces, or by `leave --new-key` ([`replace`]), never as a side effect
//! of another verb.
//!
//! How the file protects the key is a property of the FILE, read from its own bytes: `plain` by default,
//! or sealed under a passphrase, `touch-id`, or both once its owner asks for that with [`lock`], which adds a
//! lock beside the others and takes one off only on `--remove`. A sealed key opens only with a person at the
//! terminal: a touch at this Mac ([`crate::touch`]), or a passphrase typed there ([`crate::passphrase`]). A
//! failed unlock is an error, never a fresh identity.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes its bytes on drop so the
//! key does not linger in freed memory, and it lends them out only at the boundaries that need them raw.
//!
//! The key lives at `<home>/machine/key`, mode 0600, in a directory system backups leave out
//! ([`make_machine_dir`]): a copy of the key acts as this machine.

use bifrost::NodeId;
use keystore::{KeyFile, Protection, Stored, Unlock};
use tightbeam::identity::AsNodeId as _;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::escape::EscapedPath;
use crate::home::Home;
use crate::passphrase::{Asked, Prompt, Terminal};
use crate::touch::{self, Touch, TouchAct, TouchHere};

mod replace;

pub use replace::{CHOOSE_NEEDS_TERMINAL, NewKey, Replaced};

/// The ed25519 secret key a verb binds under: a [`keystore::Secret`], which wipes itself on drop and never
/// hands its bytes out by value.
pub struct Secret(keystore::Secret);

/// The inner secret wipes itself on drop, so this one does.
impl ZeroizeOnDrop for Secret {}

impl Secret {
    /// A fresh random secret, kept only in memory. The identity of a reach-outward run. The stack copy
    /// is wiped as it is taken in.
    pub fn ephemeral() -> Self {
        let mut seed: [u8; 32] = rand::random();
        Self(keystore::Secret::take(&mut seed))
    }

    /// Lend the raw seed to `lend` for the length of the call: for the transport bind, which borrows
    /// the seed and returns a future that no longer does, so no copy of it leaves this wrapper.
    pub fn with_bytes<R>(&self, lend: impl FnOnce(&[u8; 32]) -> R) -> R {
        self.0.with_bytes(lend)
    }

    /// The node id this secret binds under: the identity a peer reaches when it dials this key. Derived
    /// offline (no transport stood up), so `swoosh status` can print it without serving.
    pub fn node_id(&self) -> NodeId {
        self.0.with_bytes(NodeId::from_ed25519_secret)
    }

    /// A stable seed for this node's ssh host key, so a swoosh node exposing `ssh=sshd:` under its persisted
    /// key presents the SAME host key a client pins. Delegates to [`sshh::host_seed`], which owns the
    /// domain-separated derivation, so it lives in exactly one place; the raw secret never leaves the
    /// wrapper, only the seed. Gated on the `ssh` feature, like the rest of the shell surface: a lean client
    /// built without `ssh` neither serves a shell nor needs a host key.
    #[cfg(feature = "ssh")]
    pub fn ssh_host_seed(&self) -> [u8; 32] {
        self.0.with_bytes(sshh::host_seed)
    }
}

/// How a verb wants its identity: pinned to a stable address, or freshly minted for one run.
///
/// The distinction that drives the whole module: `serve` must be reachable at the same address across
/// runs, so it is [`Persisted`](Self::Persisted); a reach-outward verb addresses a peer and never needs
/// to be found again, so it is [`PersistedIfPresent`](Self::PersistedIfPresent), binding the home's key
/// where one exists (its badge roots there) and a throwaway where none does. The home says where the key
/// lives; only the intent says whether one is written (see [`resolve`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// Persist the secret to disk and reuse it every run, so this node keeps one stable address.
    Persisted,
    /// Mint a fresh random secret in memory for this run only; nothing is written or read.
    Ephemeral,
    /// Dial under the persisted identity WHEN one already exists, else mint a fresh ephemeral key. Every
    /// reach-outward verb wants this: a membership badge only admits at a family-gated node when it roots
    /// at the SAME key the dial binds under, so a provisioned operator reaches their own gated node by
    /// loading the persisted identity, while a fresh install still dials out with nothing on disk. Never
    /// CREATES the persisted file, under any home: an outward dial must not mint a lasting identity where
    /// one was not asked for, least of all the key a later `serve` would gate its whole fleet on.
    PersistedIfPresent,
}

/// Resolve the secret a verb binds under from its home: the key is always `<home>/machine/key`, and the
/// verb's [`Identity`] ALONE decides whether one is written.
///
/// The home names the directory, default or explicit alike. A `--home`/`SWOOSH_HOME` run does not turn an
/// outward dial into a provisioning step: the home the caller named for one `swoosh reach` must be left
/// as it was found, because the key that would appear there is the root a later `serve` gates its fleet
/// on, and nothing asked for a fleet. A sealed key is unlocked at the terminal.
pub async fn resolve(intent: Identity, home: &Home) -> eyre::Result<Secret> {
    resolve_with(intent, home, &mut Terminal)
}

/// [`resolve`], asking `prompt` for the passphrase of a sealed key.
///
/// The key file store is synchronous: it runs once per verb, before any transport is bound.
pub fn resolve_with(
    intent: Identity,
    home: &Home,
    prompt: &mut impl Prompt,
) -> eyre::Result<Secret> {
    let file = key_file(home);
    match intent {
        Identity::Persisted => match open(&file, prompt)? {
            Some(secret) => Ok(secret),
            None => mint(home, &file),
        },
        Identity::Ephemeral => Ok(Secret::ephemeral()),
        // Load the persisted key only if it already exists; never create it. So a provisioned operator's
        // outward dial roots at their own key (their badge admits at their gated node) while a fresh
        // install dials out ephemerally, with nothing written to disk.
        Identity::PersistedIfPresent => Ok(open(&file, prompt)?.unwrap_or_else(Secret::ephemeral)),
    }
}

/// Load the persisted secret at `<home>/machine/key` if the file exists and holds a key, else `None`,
/// WITHOUT creating one. A bound invite carries no seed, so `join` uses this to require the key the
/// badge was signed for; a home with no identity gets a teaching error, never a fresh key minted over
/// the invite's binding.
pub async fn load(home: &Home) -> eyre::Result<Option<Secret>> {
    open(&key_file(home), &mut Terminal)
}

/// Which key the home's key file is, WITHOUT unlocking it, minting a plain key first when the home has none.
///
/// `join` and `invite` read the key this way before they use it. For a sealed file the key is what its header
/// claims, checked as a key at tightbeam's bridge ([`key_of`]); nothing here asks for a passphrase, so reading
/// a key never blocks on a prompt.
pub fn inspect(home: &Home) -> eyre::Result<Inspected> {
    let file = key_file(home);
    match file.load()? {
        Some(stored) => Ok(Inspected::Found(key_of(&file, &stored)?)),
        None => mint(home, &file).map(|secret| Inspected::Made(secret.node_id())),
    }
}

/// Which key the home's key file is, WITHOUT unlocking it and WITHOUT minting one: `None` only when the
/// home has no key file. For a check that asks whether a key is this machine's, where a key made by the
/// check would be a lasting identity nobody asked for, and a passphrase asked would stop on a prompt.
///
/// # Errors
///
/// The key file could not be read, or is a sealed file whose header names no key ([`UnusableKey`]).
pub fn peek(home: &Home) -> eyre::Result<Option<NodeId>> {
    let file = key_file(home);
    match file.load()? {
        Some(stored) => Ok(Some(key_of(&file, &stored)?)),
        None => Ok(None),
    }
}

/// What this machine's key is locked with, read from its key file's header: `None` only where the home has no
/// key file. Touch ID's health is asked of `prompt`, which is borrowed shared, so the read can ask for no
/// passphrase and no touch; it shows no dialog, takes no `home.lock`, and writes nothing, so a person can
/// look before they change anything.
///
/// # Errors
///
/// The key file could not be read.
pub fn locks(home: &Home, prompt: &impl Prompt) -> Result<Option<Locks>, keystore::Error> {
    Ok(key_file(home)
        .load()?
        .map(|stored| Locks::of(&stored, prompt)))
}

/// The home's key as [`inspect`] read it: already there, or made by this read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inspected {
    /// The key was already in the home.
    Found(NodeId),
    /// The home had no key, and this read made one, plain.
    Made(NodeId),
}

impl Inspected {
    /// The key, whichever way it came.
    pub fn key(self) -> NodeId {
        match self {
            Self::Found(key) | Self::Made(key) => key,
        }
    }
}

/// The key `stored`, read from `file`, is for. A plain file's key is computed from the seed it holds, a fact.
/// A sealed file's is its header's claim, which anyone who can write the file can set to any bytes, so it is
/// checked as a key at tightbeam's bridge, and a header no key could be refuses naming the file.
///
/// # Errors
///
/// A sealed file's header names bytes that are not a key anyone can hold.
pub fn key_of(file: &KeyFile, stored: &Stored) -> Result<NodeId, UnusableKey> {
    match stored {
        Stored::Plain(secret) => Ok(secret.with_bytes(NodeId::from_ed25519_secret)),
        Stored::Locked(locked) => locked.public_key().node_id().map_err(|_| UnusableKey {
            path: file.path().to_path_buf(),
            whose: Whose::of(file),
        }),
    }
}

/// The line for an [`UnusableKey`]. This machine's key is set aside by `leave --new-key`, which never needs
/// its identity, but which never runs where a root is kept, so beside one the line names no command; which
/// copy of a root to trust is the person's call, so the root's line names none either.
fn unusable_line(unusable: &UnusableKey) -> String {
    match unusable.whose {
        Whose::Machine => format!(
            "this machine's key file at {} is damaged and holds no usable key; start this machine over with a \
             new key: swoosh leave --new-key",
            EscapedPath(&unusable.path)
        ),
        Whose::MachineKeepingRoot => format!(
            "this machine's key file at {} is damaged and holds no usable key.",
            EscapedPath(&unusable.path)
        ),
        Whose::Root => format!(
            "the root key file at {} is damaged and holds no usable key.",
            EscapedPath(&unusable.path)
        ),
    }
}

/// A sealed key file whose header names a key nobody can hold: the file was changed outside swoosh.
#[derive(Debug, thiserror::Error)]
#[error("{}", unusable_line(self))]
pub struct UnusableKey {
    /// The key file.
    pub path: std::path::PathBuf,
    /// Whose key the file is for.
    pub whose: Whose,
}

/// Whose key a damaged key file was for, as its line needs to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whose {
    /// This machine's, in a home that keeps no root: `leave --new-key` sets it aside.
    Machine,
    /// This machine's, beside a root kept in its home, which `leave` never leaves.
    MachineKeepingRoot,
    /// A root's.
    Root,
}

impl Whose {
    /// Whose key `file` is for. This machine's key is `<home>/machine/key` and a root kept in that home is
    /// `<home>/root.key`, looked for where `leave` looks, so the line never names the command that refusal
    /// turns away. A root that cannot be ruled out counts as kept: the line then names no command.
    pub fn of(file: &KeyFile) -> Self {
        match file.kind() {
            keystore::Kind::Strict => Self::Root,
            keystore::Kind::Standard => {
                let absent = file
                    .path()
                    .parent()
                    .and_then(std::path::Path::parent)
                    .is_some_and(|home| matches!(crate::home::keeps_root_in(home), Ok(false)));
                if absent {
                    Self::Machine
                } else {
                    Self::MachineKeepingRoot
                }
            }
        }
    }
}

/// What [`lock`] did to this machine's key: one variant per outcome, so two different acts never share a
/// result. Every lock set in it is read back from the file's header after the write, under `home.lock`, and
/// never taken from what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locked {
    /// The home had no key, and this made one, sealed from its first write.
    Made {
        /// The key made.
        key: NodeId,
        /// What it opens with.
        now: Methods,
        /// The failure the key store answered after the file was in place (its directory not synced, say), as
        /// its chain reads: the file read back holds the key, so it is made, and the failure is said beside it.
        failed: Option<String>,
    },
    /// Locks were put on the key beside the ones it had: its first, on a plain key.
    Added {
        /// The locks put on: both, where a plain key beside a kept root gets a passphrase and Touch ID.
        method: Methods,
        /// What the key opens with now.
        now: Now,
        /// Whether a root is kept on this machine, read under `home.lock`.
        root: Root,
        /// As [`Locked::Made`]'s: a failure after the write was in place, said beside the result.
        failed: Option<String>,
    },
    /// The key's lock of `method` was replaced by a new one: a new passphrase, or Touch ID set again.
    Changed {
        /// The lock replaced.
        method: keystore::Method,
        /// What the key opens with now.
        now: Now,
        /// As [`Locked::Made`]'s.
        failed: Option<String>,
    },
    /// The key's lock of `method` was taken off.
    Removed {
        /// The lock taken off.
        method: keystore::Method,
        /// What the key opens with now.
        now: Now,
        /// As [`Locked::Made`]'s.
        failed: Option<String>,
    },
    /// Nothing was changed.
    Unchanged(Why),
}

/// What the key opens with after a write that landed: read back from the file, or not, where the read failed.
/// The write stands either way, so a failed read is said beside the result, never as the act's failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Now {
    /// The locks read back.
    Read(Locks),
    /// The file could not be read back.
    Unread(Unread),
}

impl Now {
    /// What `file` holds now, read back under `home.lock` after a write that landed.
    fn after(file: &KeyFile, prompt: &impl Prompt) -> Self {
        match Locks::after(file, prompt) {
            Ok(locks) => Self::Read(locks),
            Err(error) => Self::Unread(Unread {
                path: file.path().to_string_lossy().into_owned(),
                read: crate::escape::causes(&error),
            }),
        }
    }
}

/// A key file that could not be read back, as a line names it: its path's text and the read's own cause
/// chain, each printed through the escaper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    /// The key file's path, as text.
    pub path: String,
    /// Why it could not be read.
    pub read: String,
}

/// The refusal when the key file read back cannot be confirmed as what this command wrote: it cannot be read,
/// or holds this run's key without the lock this run wrote, or no lock set this act leaves. It claims neither a
/// key made nor none, and keeps the read's own error where there is one.
#[derive(Debug, thiserror::Error)]
#[error("this command could not confirm the key file")]
pub struct Unconfirmed {
    /// The key file.
    pub path: std::path::PathBuf,
    /// The read's error, where a read failed.
    #[source]
    pub read: Option<keystore::Error>,
}

/// The refusal when the key file this command wrote under `home.lock` is gone when read back: something that
/// takes no `home.lock` removed it.
#[derive(Debug, thiserror::Error)]
#[error("the key file this command wrote is gone")]
pub struct Gone {
    /// The key file.
    pub path: std::path::PathBuf,
}

/// The refusal when a first key beside a root was made under the chosen passphrase but a step after its write
/// failed, so Touch ID, which the command was asked for, was not added. The key is made: the screen says so,
/// with the failure, and how to add Touch ID; the run still fails, since what was asked did not happen.
#[derive(Debug, thiserror::Error)]
#[error("Touch ID was not added")]
pub struct TouchIdNotAdded {
    /// The key made.
    pub key: NodeId,
    /// The failure after the write, as its chain reads.
    pub failed: String,
}

/// One lock method or both: the locks a key was made with or given, never none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Methods {
    /// A passphrase.
    Passphrase,
    /// Touch ID.
    TouchId,
    /// A passphrase and Touch ID, either of which opens the key.
    Both,
}

impl Methods {
    /// The methods `locked`'s header lists, of the ones this build knows.
    fn of(locked: &keystore::Locked) -> Option<Self> {
        match (touch::holds_passphrase(locked), holds_touch_id(locked)) {
            (true, false) => Some(Self::Passphrase),
            (false, true) => Some(Self::TouchId),
            (true, true) => Some(Self::Both),
            (false, false) => None,
        }
    }

    /// Whether `method` is one of these.
    pub fn has(self, method: keystore::Method) -> bool {
        match (self, method) {
            (Self::Both, _)
            | (Self::Passphrase, keystore::Method::Passphrase)
            | (Self::TouchId, keystore::Method::TouchId) => true,
            (Self::Passphrase, keystore::Method::TouchId)
            | (Self::TouchId, keystore::Method::Passphrase) => false,
        }
    }
}

/// What this machine's key opens with, read from its header with no dialog. A Touch ID lock carries its
/// health as this Mac reads it, so a line never says the key opens with a lock that reads dead here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locks {
    /// No lock: the key file is plain, and a copy of it opens anywhere.
    None,
    /// A passphrase alone.
    Passphrase,
    /// Touch ID alone, with its health here.
    TouchId(Option<keystore::Health>),
    /// Touch ID or a passphrase, with Touch ID's health here.
    Both(Option<keystore::Health>),
}

impl Locks {
    /// The locks of `stored`, Touch ID's health read by `prompt` with no dialog.
    pub fn of(stored: &Stored, prompt: &impl Prompt) -> Self {
        let Stored::Locked(locked) = stored else {
            return Self::None;
        };
        // A sealed file the key store read holds at least one lock it knows, and this build knows each of
        // them, so `None` cannot be read here; it falls to the passphrase rather than to no lock, which a
        // result would print as a key a copy opens anywhere.
        match Methods::of(locked) {
            Some(Methods::Passphrase) | None => Self::Passphrase,
            Some(Methods::TouchId) => Self::TouchId(prompt.health(locked)),
            Some(Methods::Both) => Self::Both(prompt.health(locked)),
        }
    }

    /// The locks `file` holds, read back under `home.lock` after a write that left it there.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or is gone: something outside swoosh, which takes no `home.lock`, removed it.
    fn after(file: &KeyFile, prompt: &impl Prompt) -> Result<Self, keystore::Error> {
        match file.load()? {
            Some(stored) => Ok(Self::of(&stored, prompt)),
            None => Err(keystore::Error::Absent {
                path: file.path().to_path_buf(),
            }),
        }
    }

    /// The methods, or `None` for a plain key.
    pub fn methods(self) -> Option<Methods> {
        match self {
            Self::None => None,
            Self::Passphrase => Some(Methods::Passphrase),
            Self::TouchId(_) => Some(Methods::TouchId),
            Self::Both(_) => Some(Methods::Both),
        }
    }

    /// Whether the key has a lock of `method`.
    pub fn has(self, method: keystore::Method) -> bool {
        self.methods().is_some_and(|methods| methods.has(method))
    }

    /// What the key opens with, as a line after an act names it: `None` for a plain key, which opens with
    /// nothing, and for a Touch ID lock that reads dead here, which no line says the key opens with.
    pub fn opens_with(self) -> Option<&'static str> {
        match self {
            Self::None
            | Self::TouchId(Some(keystore::Health::Dead))
            | Self::Both(Some(keystore::Health::Dead)) => None,
            Self::Passphrase => Some("the passphrase"),
            Self::TouchId(_) => Some("Touch ID, on this Mac only"),
            Self::Both(_) => Some("Touch ID or the passphrase"),
        }
    }
}

/// Whether a root is kept on this machine, where the passphrase beside Touch ID never comes off, so no result
/// offers the step that would take it off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    /// A root is kept here.
    Kept,
    /// None is.
    NotKept,
}

impl Root {
    /// Whether `home` keeps a root.
    fn of(home: &Home) -> eyre::Result<Self> {
        Ok(if home.keeps_root()? {
            Self::Kept
        } else {
            Self::NotKept
        })
    }
}

/// Why [`lock`] changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The home has no key: a removal makes none.
    NoKey,
    /// The key is plain: it has no lock to take off.
    NoLock,
    /// The key has no lock of this method to take off.
    NoSuchLock(keystore::Method),
    /// `touch-id` on a key under Touch ID alone where no root is kept, which opens here: it has the one lock
    /// asked for.
    TouchIdAlone,
    /// The same beside a kept root, where the key still needs the passphrase `lock passphrase` adds beside it.
    NeedsPassphrase,
}

/// The result of putting `method` on a key whose locks were `before` and are `now`, each read under
/// `home.lock`: a lock of that method already there was replaced, else `method` was added. `failed` is a
/// failure the key store answered after the write was in place.
fn added(method: Methods, before: Locks, now: Now, root: Root, failed: Option<String>) -> Locked {
    let replaced = match method {
        Methods::Passphrase => Some(keystore::Method::Passphrase),
        Methods::TouchId => Some(keystore::Method::TouchId),
        Methods::Both => None,
    };
    match replaced {
        Some(method) if before.has(method) => Locked::Changed {
            method,
            now,
            failed,
        },
        _ => Locked::Added {
            method,
            now,
            root,
            failed,
        },
    }
}

/// Set, change or remove the lock of `method` on this machine's key. The key never changes, so it runs beside
/// a `serve`, which holds its key in memory. Every prompt comes first, the current lock before the new one,
/// and `home.lock` is taken for the write alone; a touch that proves a new `touch-id` lock is part of the
/// write, so it is asked under the lock, bounded.
///
/// `lock` adds the lock of `method` beside the ones the key has, or replaces the one of that method, and never
/// takes a lock off: only a removal does, and only the lock it names. Where a root is kept on this machine
/// ([`Home::keeps_root`]), a key that comes to open with `touch-id` gets a passphrase beside it, as the root
/// has, and keeps it, because no verb gives this machine a new key there. A home with no key gets its first
/// one sealed under the lock chosen, so a key meant to be sealed never touches the disk in the clear. A
/// removal of a lock the key does not have changes nothing. Before an add asks for anything, it says what the
/// key will open with, once nothing is left that refuses without asking.
///
/// # Errors
///
/// A lock was not given or did not open the key, a touch could not be asked for here, or the rewrite failed.
/// A make whose touch did not land says whether this command made a key, from the file read back.
pub async fn lock(
    home: &Home,
    method: keystore::Method,
    remove: bool,
    prompt: &mut impl Prompt,
) -> eyre::Result<Locked> {
    match (method, remove) {
        (keystore::Method::Passphrase, false) => set_passphrase(home, prompt).await,
        (keystore::Method::Passphrase, true) => remove_passphrase(home, prompt).await,
        (keystore::Method::TouchId, false) => set_touch_id(home, prompt).await,
        (keystore::Method::TouchId, true) => remove_touch_id(home, prompt).await,
    }
}

/// Set or change the passphrase on this machine's key.
async fn set_passphrase(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Locked> {
    let file = key_file(home);
    let locked = match file.load()? {
        None => {
            let new = choose_after(prompt, touch::MAKES_UNDER_PASSPHRASE)?;
            let secret = keystore::Secret::generate()?;
            let drawn = Drawn::of(&secret);
            let _home_lock = crate::home::HomeWrite::take(home).await?;
            make_machine_dir(home)?;
            let wrote = file.write(&secret, Protection::Passphrase(&new));
            return drawn.made(&file, wrote.err());
        }
        Some(Stored::Plain(_)) => {
            let new = choose_after(prompt, touch::SEALS_UNDER_PASSPHRASE)?;
            let _home_lock = crate::home::HomeWrite::take(home).await?;
            let before = Locks::after(&file, prompt)?;
            let root = Root::of(home)?;
            let failed = written(file.add_lock(None, keystore::NewLock::Passphrase(&new)))?;
            let now = Now::after(&file, prompt);
            return Ok(added(Methods::Passphrase, before, now, root, failed));
        }
        Some(Stored::Locked(locked)) => locked,
    };
    if !prompt.terminal() {
        eyre::bail!(crate::passphrase::CHANGE_FOR_KEY_NEEDS_TERMINAL);
    }
    if !touch::holds_passphrase(&locked) {
        // Under `touch-id` alone: the touch is routed first, so a key that cannot be touched here is refused
        // before anything is said or a new passphrase typed; then the line says the passphrase goes beside it,
        // it is chosen, and one touch opens the key to add it.
        let by_touch = ByTouch::route(prompt, &file, &locked)?;
        prompt.warn(touch::BESIDE_TOUCH_ID);
        prompt.warn("");
        let new = crate::passphrase::choose(prompt, Asked::MachineKey)?;
        let act = TouchAct::AddPassphrase { new };
        let home_lock = crate::home::HomeWrite::take(home).await?;
        // Added or changed, and whether a root is kept, by what is there under `home.lock`, not what was read
        // before the prompts.
        let before = Locks::after(&file, prompt)?;
        let root = Root::of(home)?;
        let failed = by_touch.change(prompt, &home_lock, act)?;
        let now = Now::after(&file, prompt);
        drop(home_lock);
        // A blank line, so the result stands apart from the wait.
        prompt.warn("");
        return Ok(added(Methods::Passphrase, before, now, root, failed));
    }
    let current = prove_passphrase(prompt, &locked)?;
    let new = crate::passphrase::choose(prompt, Asked::MachineKey)?;
    let _home_lock = crate::home::HomeWrite::take(home).await?;
    let before = Locks::after(&file, prompt)?;
    let root = Root::of(home)?;
    let failed = written(file.add_lock(
        Some(Unlock::Passphrase(&current)),
        keystore::NewLock::Passphrase(&new),
    ))?;
    let now = Now::after(&file, prompt);
    Ok(added(Methods::Passphrase, before, now, root, failed))
}

/// Take the passphrase off this machine's key. Never where a root is kept and `touch-id` would be left alone.
async fn remove_passphrase(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Locked> {
    let file = key_file(home);
    let locked = match file.load()? {
        None => return Ok(Locked::Unchanged(Why::NoKey)),
        Some(Stored::Plain(_)) => return Ok(Locked::Unchanged(Why::NoLock)),
        Some(Stored::Locked(locked)) => locked,
    };
    if !touch::holds_passphrase(&locked) {
        return Ok(Locked::Unchanged(Why::NoSuchLock(
            keystore::Method::Passphrase,
        )));
    }
    if holds_touch_id(&locked) && home.keeps_root()? {
        eyre::bail!(KEEPS_PASSPHRASE);
    }
    if !prompt.terminal() {
        eyre::bail!(crate::passphrase::CHANGE_FOR_KEY_NEEDS_TERMINAL);
    }
    // Touch ID left alone must open here, or the key store refuses the removal: a lock that does not, or
    // cannot be checked, is refused now, before a line says it will open the key and a passphrase is typed.
    if holds_touch_id(&locked) {
        let lines = touch::Lines::of(Asked::MachineKey, &file, true);
        match prompt.health(&locked) {
            Some(keystore::Health::Live) => {}
            Some(keystore::Health::Unchecked) => eyre::bail!("{}", lines.unchecked()),
            // A build with no enclave reads no health, and Touch ID opens nothing here.
            None if prompt.touch_here() == TouchHere::NoEnclave => {
                eyre::bail!(touch::PASSPHRASE_STAYS_OFF_THE_MAC)
            }
            Some(keystore::Health::Dead) | None => eyre::bail!("{}", lines.dead()),
        }
    }
    prompt.warn(if holds_touch_id(&locked) {
        touch::TAKES_PASSPHRASE_OFF
    } else {
        touch::TAKES_LAST_LOCK_OFF
    });
    prompt.warn("");
    let current = prove_passphrase(prompt, &locked)?;
    let _home_lock = crate::home::HomeWrite::take(home).await?;
    let failed =
        written(file.remove_lock(Unlock::Passphrase(&current), keystore::Method::Passphrase))?;
    Ok(Locked::Removed {
        method: keystore::Method::Passphrase,
        now: Now::after(&file, prompt),
        failed,
    })
}

/// The refusal of `lock passphrase --remove` on a key that keeps its passphrase beside `touch-id` where a root
/// is kept, with the removal that is allowed there.
pub const KEEPS_PASSPHRASE: &str = "this machine's key keeps its passphrase while your root is here\n  \
     To take Touch ID off instead:\n    \
     swoosh lock touch-id --remove";

/// Put a `touch-id` lock on this machine's key beside its passphrase, or set it again where it has a passphrase
/// to open it by. Asked only at this Mac's own screen; says what the key will open with, and what a new
/// fingerprint does to it, before anything is asked or written. A key under `touch-id` alone already has the
/// lock this asks for, so nothing is asked and nothing changes, and since a lock that reads live was made
/// under the fingers enrolled now, nothing needs to; beside a kept root it still needs its passphrase, which
/// is `lock passphrase`'s to add. It is answered at this Mac's own screen only, by the lock's health: one that
/// does not open here, or cannot be checked now, is refused with the line that says why, never called done.
async fn set_touch_id(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Locked> {
    let here = prompt.touch_here();
    if here != TouchHere::Here {
        eyre::bail!("{}", touch::set_elsewhere(here, "swoosh lock touch-id"));
    }
    let keeps_root = home.keeps_root()?;
    let file = key_file(home);
    let stored = file.load()?;
    if let Some(Stored::Locked(locked)) = &stored
        && holds_touch_id(locked)
        && !touch::holds_passphrase(locked)
    {
        // The route reads the health with no dialog: live goes on to a touch, which is not asked, since
        // the lock is already the one asked for. Beside a root the passphrase it lacks is the passphrase
        // command's to add, so this one changes nothing there either.
        ByTouch::route(prompt, &file, locked)?;
        return Ok(Locked::Unchanged(if keeps_root {
            Why::NeedsPassphrase
        } else {
            Why::TouchIdAlone
        }));
    }
    // What the key will open with after, said before the first prompt. A key with a passphrase keeps it, so
    // its line names both locks; a key with no lock yet gets a passphrase only where a root is kept, and is
    // told what a new fingerprint does only where Touch ID will be its one lock. On a lock that does not
    // open here, who opens the new one is said with the warning that comes with it, so the fingerprint line
    // is not said twice.
    let dead = matches!(
        &stored,
        Some(Stored::Locked(locked)) if prompt.health(locked) == Some(keystore::Health::Dead)
    );
    match &stored {
        Some(Stored::Locked(locked)) if holds_touch_id(locked) => {
            prompt.warn(touch::CHANGES_TOUCH_ID);
            if !dead {
                prompt.warn(touch::EVERY_FINGERPRINT);
            }
        }
        Some(Stored::Locked(_)) => prompt.warn(touch::TOUCH_ID_BESIDE),
        None if keeps_root => prompt.warn(touch::MAKES_BESIDE_ROOT),
        None => prompt.warn(touch::MAKES_UNDER_TOUCH_ID),
        Some(Stored::Plain(_)) if keeps_root => prompt.warn(touch::SEALS_BESIDE_ROOT),
        Some(Stored::Plain(_)) => prompt.warn(touch::SEALS_UNDER_TOUCH_ID),
    }
    if keeps_root && root_opens_by_touch(home) {
        prompt.warn(touch::SHARED_FINGER);
    }
    let lines = touch::Lines::of(Asked::MachineKey, &file, keeps_root);
    let act = match stored {
        // A first key beside a root is written under a chosen passphrase before the touch, so it is made
        // whether or not the touch lands.
        None if keeps_root => {
            // A blank line, so the prompts stand apart from what was said before them.
            prompt.warn("");
            let current = choose_new(prompt)?;
            let secret = keystore::Secret::generate()?;
            let drawn = Drawn::of(&secret);
            let home_lock = crate::home::HomeWrite::take(home).await?;
            make_machine_dir(home)?;
            // A failure after the write was in place stops short of the touch: the key is made, under the
            // passphrase alone, and the person is told Touch ID was not added.
            if let Some(failed) = written(file.write(&secret, Protection::Passphrase(&current)))? {
                return Err(drawn.touch_id_not_added(&file, failed));
            }
            let act = TouchAct::BesidePassphrase { current };
            let touched = set_by_touch(prompt, &lines, &home_lock, &file, act);
            return drawn
                .sealed_first(touched, &file)
                .inspect(|_| prompt.warn(""));
        }
        // A first key under Touch ID alone is written by the touch itself, so a touch that does not land
        // made nothing, which the file read back says.
        None => {
            let secret = keystore::Secret::generate()?;
            let drawn = Drawn::of(&secret);
            let home_lock = crate::home::HomeWrite::take(home).await?;
            make_machine_dir(home)?;
            let act = TouchAct::Write(secret);
            let touched = set_by_touch(prompt, &lines, &home_lock, &file, act);
            return drawn.by_touch(touched, &file).inspect(|_| prompt.warn(""));
        }
        // A plain key beside a root is sealed under a chosen passphrase before the touch, so it keeps that
        // lock whether or not the touch lands.
        Some(Stored::Plain(_)) if keeps_root => {
            prompt.warn("");
            let current = choose_new(prompt)?;
            let home_lock = crate::home::HomeWrite::take(home).await?;
            let root = Root::of(home)?;
            // A failure after the seal was in place still leaves the passphrase on, so the touch is asked,
            // and the failure is said beside the result.
            let sealed = written(file.add_lock(None, keystore::NewLock::Passphrase(&current)))?;
            let act = TouchAct::BesidePassphrase { current };
            let touched = set_by_touch(prompt, &lines, &home_lock, &file, act);
            return sealed_then_touched(touched, sealed, &file, prompt, root)
                .inspect(|_| prompt.warn(""));
        }
        Some(Stored::Plain(_)) => TouchAct::SealPlain,
        // Under `touch-id` alone, the key returned above, so a sealed key here holds a passphrase. Opened with
        // it, never the touch: setting `touch-id` again is how a lock that stopped opening is mended, so the
        // old one is not asked for. One that does not open says first to check for a fingerprint nobody
        // added, since the new lock opens under every finger enrolled now.
        Some(Stored::Locked(locked)) => {
            if dead {
                prompt.warn(&touch::Lines::of(Asked::MachineKey, &file, true).before_set_again());
            }
            // A blank line, so the prompts stand apart from what was said before them.
            prompt.warn("");
            let current = prove_passphrase(prompt, &locked)?;
            TouchAct::BesidePassphrase { current }
        }
    };
    let home_lock = crate::home::HomeWrite::take(home).await?;
    // Added or set again, and whether a root is kept, by what is there under `home.lock`, not what was read
    // before the prompts: a lock taken off meanwhile makes this an add, and a root that arrived meanwhile
    // keeps the passphrase, so no step offers to take it off.
    let before = Locks::after(&file, prompt)?;
    let root = Root::of(home)?;
    let failed = touch::landed(set_by_touch(prompt, &lines, &home_lock, &file, act), &lines)?;
    let now = Now::after(&file, prompt);
    drop(home_lock);
    // A blank line, so the result stands apart from the wait.
    prompt.warn("");
    Ok(added(Methods::TouchId, before, now, root, failed))
}

/// Take the `touch-id` lock off this machine's key: opened with the passphrase where it has one, else with
/// the touch itself.
async fn remove_touch_id(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Locked> {
    let file = key_file(home);
    let locked = match file.load()? {
        None => return Ok(Locked::Unchanged(Why::NoKey)),
        Some(Stored::Plain(_)) => return Ok(Locked::Unchanged(Why::NoLock)),
        Some(Stored::Locked(locked)) => locked,
    };
    if !holds_touch_id(&locked) {
        return Ok(Locked::Unchanged(Why::NoSuchLock(
            keystore::Method::TouchId,
        )));
    }
    let removed = |now, failed| Locked::Removed {
        method: keystore::Method::TouchId,
        now,
        failed,
    };
    if !touch::holds_passphrase(&locked) {
        let by_touch = ByTouch::route(prompt, &file, &locked)?;
        prompt.warn(touch::TAKES_LAST_LOCK_OFF);
        let home_lock = crate::home::HomeWrite::take(home).await?;
        let failed = by_touch.change(prompt, &home_lock, TouchAct::RemoveTouchId)?;
        let now = Now::after(&file, prompt);
        prompt.warn("");
        return Ok(removed(now, failed));
    }
    if !prompt.terminal() {
        eyre::bail!(crate::passphrase::CHANGE_FOR_KEY_NEEDS_TERMINAL);
    }
    prompt.warn(touch::TAKES_TOUCH_ID_OFF);
    prompt.warn("");
    let current = prove_passphrase(prompt, &locked)?;
    let _home_lock = crate::home::HomeWrite::take(home).await?;
    let failed =
        written(file.remove_lock(Unlock::Passphrase(&current), keystore::Method::TouchId))?;
    Ok(removed(Now::after(&file, prompt), failed))
}

/// Prove the passphrase on this machine's key, asking up to three times, and hand it back for the change.
fn prove_passphrase(
    prompt: &mut impl Prompt,
    locked: &keystore::Locked,
) -> eyre::Result<keystore::Passphrase> {
    // Proven before anything new is asked, so a mistyped one fails at once.
    let ((), current) = crate::passphrase::unlock(prompt, Asked::MachineKey, |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase)).map(drop)
    })?;
    Ok(current)
}

/// Whether `locked` holds a `touch-id` lock.
fn holds_touch_id(locked: &keystore::Locked) -> bool {
    locked
        .methods()
        .any(|method| method == keystore::Method::TouchId)
}

/// Whether this machine's key opens with `touch-id` alone while a root is kept here, read from its header
/// with no dialog: the one state the two-lock rule ([`lock`]) does not allow, which a root arriving beside
/// such a key (made or restored) leaves until `lock passphrase` adds the passphrase.
pub fn touch_id_alone_beside_root(home: &Home) -> bool {
    matches!(home.keeps_root(), Ok(true))
        && matches!(
            key_file(home).load(),
            Ok(Some(Stored::Locked(key))) if holds_touch_id(&key) && !touch::holds_passphrase(&key)
        )
}

/// What is said where [`touch_id_alone_beside_root`] holds: after a root is made or restored here, and in
/// `status`.
pub const TOUCH_ID_ALONE_BESIDE_ROOT: &str = "this machine's key needs a passphrase beside Touch ID while your \
     root is here:\n  \
     swoosh lock passphrase";

/// Whether the root kept in `home` has a `touch-id` lock, read from its header. A root that cannot be read
/// says nothing here; every use of it says why.
fn root_opens_by_touch(home: &Home) -> bool {
    matches!(
        KeyFile::strict(home.root_key()).load(),
        Ok(Some(Stored::Locked(root))) if holds_touch_id(&root)
    )
}

/// This machine's key under `touch-id` alone, routed to a touch: one that can be asked for here and reads
/// live. Only [`route`](Self::route) makes one, so a change by touch never runs on a key that would refuse
/// it, and the refusal comes before anything else is asked.
struct ByTouch<'a> {
    file: &'a KeyFile,
}

impl<'a> ByTouch<'a> {
    /// Route `locked`, read from `file`, to its touch, or refuse with the line that says why.
    fn route(
        prompt: &impl Prompt,
        file: &'a KeyFile,
        locked: &keystore::Locked,
    ) -> eyre::Result<Self> {
        match touch::route(prompt, file, locked, Asked::MachineKey) {
            touch::Route::Touch => Ok(Self { file }),
            touch::Route::Refuse(line) => eyre::bail!("{line}"),
            touch::Route::Passphrase(Some(aside)) => eyre::bail!("{}", aside.into_line()),
            touch::Route::Passphrase(None) => eyre::bail!("{}", touch::TOUCH_ID_GONE),
        }
    }

    /// Change the key's locks through `act`, which the touch opens it for, under `home.lock` (`_home_lock`).
    /// The waiting line and the dialog both name the act, so the person sees the change they asked for. The
    /// caller holds the lock, so what it reads before and after is read under it too. Hands back a failure the
    /// key store answered after the write was in place.
    fn change(
        self,
        prompt: &mut impl Prompt,
        _home_lock: &crate::home::HomeWrite,
        act: TouchAct,
    ) -> eyre::Result<Option<String>> {
        let lines = touch::Lines::of(Asked::MachineKey, self.file, false);
        prompt.say(&lines.waiting(act.act()));
        let touch = Touch::on_machine_key(self.file.clone(), act);
        touch::landed(prompt.touch(touch), &lines)
    }
}

/// Ask for the touch that proves a new `touch-id` lock on this machine's key through `act`, under `home.lock`
/// (`_home_lock`), and hand back how it ended, for the caller to say what the key was left with.
fn set_by_touch(
    prompt: &mut impl Prompt,
    lines: &touch::Lines<'_>,
    _home_lock: &crate::home::HomeWrite,
    file: &KeyFile,
    act: TouchAct,
) -> touch::Touched {
    prompt.say(&lines.waiting(act.act()));
    prompt.touch(Touch::on_machine_key(file.clone(), act))
}

/// A key this run drew for a home with none: what the file read back after its write must claim, to be the
/// one this run made.
struct Drawn {
    key: NodeId,
    public: keystore::PublicKey,
}

/// What the key file held, read back under `home.lock` after this run wrote into the absence of one.
enum Found {
    /// This run's key, under these locks.
    Mine(Methods),
    /// Nothing.
    Absent,
    /// A key that is not this run's, read whole: another writer's, as a first `serve` mints with no
    /// `home.lock`.
    Theirs,
    /// A file that cannot be read, with the read's error, or this run's key under no lock this build knows.
    Unconfirmed(Option<keystore::Error>),
}

impl Drawn {
    /// The key `secret` is, before it is written.
    fn of(secret: &keystore::Secret) -> Self {
        Self {
            key: secret.with_bytes(NodeId::from_ed25519_secret),
            public: secret.public_key(),
        }
    }

    /// What `file` holds now. `home.lock` keeps out every swoosh writer that takes it, but a first `serve`,
    /// `invite` or `join` mints a plain key with none, so a file there may be another's. A header is a claim
    /// anyone who can write the file can set, but it cannot claim the key this run just drew, so only a match
    /// counts as this run's. A file that cannot be read is neither.
    fn found(&self, file: &KeyFile) -> Found {
        match file.load() {
            Ok(None) => Found::Absent,
            Ok(Some(Stored::Locked(locked))) if locked.public_key() == self.public => {
                Methods::of(&locked).map_or(Found::Unconfirmed(None), Found::Mine)
            }
            Ok(Some(_)) => Found::Theirs,
            Err(error) => Found::Unconfirmed(Some(error)),
        }
    }

    /// The key written under a passphrase, with no touch, the write answering `wrote`: made where the file read
    /// back is this run's, a failure that came after it said beside it; over no file, the write's own failure.
    fn made(&self, file: &KeyFile, wrote: Option<keystore::Error>) -> eyre::Result<Locked> {
        match (self.found(file), wrote) {
            (Found::Mine(now), wrote) => Ok(Locked::Made {
                key: self.key,
                now,
                failed: wrote.map(|error| crate::escape::causes(&error)),
            }),
            (Found::Absent, Some(error)) => Err(error.into()),
            (Found::Absent, None) => Err(gone(file)),
            (Found::Theirs, _) => eyre::bail!(KEY_ALREADY_THERE),
            (Found::Unconfirmed(read), _) => Err(unconfirmed(file, read)),
        }
    }

    /// The refusal for a first key beside a root whose write under the chosen passphrase landed, the key store
    /// answering `failed` after it, so the touch that adds Touch ID was not asked: made, where the file read
    /// back is this run's under the passphrase alone; any other read cannot be confirmed.
    fn touch_id_not_added(&self, file: &KeyFile, failed: String) -> eyre::Report {
        match self.found(file) {
            Found::Mine(Methods::Passphrase) => TouchIdNotAdded {
                key: self.key,
                failed,
            }
            .into(),
            Found::Unconfirmed(read) => unconfirmed(file, read),
            Found::Mine(_) | Found::Absent | Found::Theirs => unconfirmed(file, None),
        }
    }

    /// The key the touch itself writes, under Touch ID alone: made only where the file read back is this
    /// run's key with Touch ID on it. A touch that did not land, over no file, made nothing; over another's
    /// key, it did not make that one either. A failure can come after the file is in place (its directory
    /// not synced), so the file, not the answer, says whether a key was made.
    fn by_touch(&self, touched: touch::Touched, file: &KeyFile) -> eyre::Result<Locked> {
        match self.found(file) {
            Found::Mine(now) if now.has(keystore::Method::TouchId) => Ok(Locked::Made {
                key: self.key,
                now,
                failed: failure(&touched),
            }),
            Found::Mine(_) => Err(unconfirmed(file, None)),
            Found::Absent => Err(missed(touched, MADE_NO_KEY).unwrap_or_else(|| gone(file))),
            Found::Theirs => eyre::bail!(KEY_ALREADY_THERE),
            Found::Unconfirmed(read) => Err(unconfirmed(file, read)),
        }
    }

    /// The key written under a chosen passphrase before the touch that adds Touch ID beside it: made either
    /// way, so a touch that did not land says so, then that the key was made under the passphrase alone.
    fn sealed_first(&self, touched: touch::Touched, file: &KeyFile) -> eyre::Result<Locked> {
        let now = match self.found(file) {
            Found::Mine(now) => now,
            Found::Absent => return Err(gone(file)),
            Found::Theirs => eyre::bail!(KEY_ALREADY_THERE),
            Found::Unconfirmed(read) => return Err(unconfirmed(file, read)),
        };
        if now.has(keystore::Method::TouchId) {
            return Ok(Locked::Made {
                key: self.key,
                now,
                failed: failure(&touched),
            });
        }
        let detail = format!(
            "Made this machine's key, locked with the passphrase you chose:\n    {}",
            self.key
        );
        match missed(touched, &detail) {
            Some(refused) => Err(refused),
            None => Ok(Locked::Made {
                key: self.key,
                now,
                failed: None,
            }),
        }
    }
}

/// A plain key beside a kept root, sealed under a chosen passphrase before the touch that adds Touch ID
/// beside it: the passphrase was added either way, so a touch that did not land says so, then what the key
/// opens with, read back. A file read back with neither Touch ID nor the passphrase alone, or not at all, is
/// not called anything. `sealed` is a failure the key store answered after the seal was in place; the
/// result says it, or the touch's own failure after its lock was in place.
fn sealed_then_touched(
    touched: touch::Touched,
    sealed: Option<String>,
    file: &KeyFile,
    prompt: &impl Prompt,
    root: Root,
) -> eyre::Result<Locked> {
    let now = match Locks::after(file, prompt) {
        Ok(now) => now,
        Err(keystore::Error::Absent { .. }) => return Err(gone(file)),
        Err(error) => return Err(unconfirmed(file, Some(error))),
    };
    if now.has(keystore::Method::TouchId) {
        // The lock landed, whatever the answer; a failure after it is said beside the result.
        return Ok(Locked::Added {
            method: Methods::Both,
            now: Now::Read(now),
            root,
            failed: failure(&touched).or(sealed),
        });
    }
    let Locks::Passphrase = now else {
        return Err(unconfirmed(file, None));
    };
    let detail = "Added a passphrase to this machine's key, which now opens with the passphrase.";
    match missed(touched, detail) {
        Some(refused) => Err(refused),
        None => Ok(Locked::Added {
            method: Methods::Passphrase,
            now: Now::Read(now),
            root,
            failed: sealed,
        }),
    }
}

/// A write's answer, as a result takes it: done, or done with the failure the key store answered after the
/// file was in place (its directory not synced), as its chain reads, to be said beside the result.
///
/// # Errors
///
/// Any other failure: the write did not land.
fn written(answer: Result<(), keystore::Error>) -> Result<Option<String>, keystore::Error> {
    match answer {
        Ok(()) => Ok(None),
        Err(error @ keystore::Error::Unsynced { .. }) => Ok(Some(crate::escape::causes(&error))),
        Err(error) => Err(error),
    }
}

/// The failure a touch answered, as its chain reads, for a result whose file shows the act landed anyway.
fn failure(touched: &touch::Touched) -> Option<String> {
    match touched {
        touch::Touched::Failed(why) => Some(format!("{why:#}")),
        touch::Touched::Opened(_)
        | touch::Touched::Declined
        | touch::Touched::NotHere
        | touch::Touched::TimedOut => None,
    }
}

/// The refusal for a touch that did not land on a make: its cause as the head, then `detail`, the fact of
/// what the key was left with, and after a failure its own chain, on a line of its own. `None` for a touch
/// that landed.
fn missed(touched: touch::Touched, detail: &str) -> Option<eyre::Report> {
    let head = match touched {
        touch::Touched::Opened(_) => return None,
        touch::Touched::Declined => "Touch ID was cancelled",
        touch::Touched::NotHere => "Touch ID did not open the new lock on this Mac",
        touch::Touched::TimedOut => touch::TIMED_OUT,
        // The failure's chain on its own line after the fact, as the person reads the fact first.
        touch::Touched::Failed(why) => {
            return Some(eyre::eyre!("Touch ID failed\n  {detail}\n  {why:#}"));
        }
    };
    Some(eyre::eyre!("{head}\n  {detail}"))
}

/// [`Gone`], for `file`.
fn gone(file: &KeyFile) -> eyre::Report {
    Gone {
        path: file.path().to_path_buf(),
    }
    .into()
}

/// [`Unconfirmed`], for `file`, with the read's error where one failed.
fn unconfirmed(file: &KeyFile, read: Option<keystore::Error>) -> eyre::Report {
    Unconfirmed {
        path: file.path().to_path_buf(),
        read,
    }
    .into()
}

/// The fact under a make whose touch did not land, over no file: scoped to this command, since a first `serve`
/// can make a key here a moment later without `home.lock`.
pub const MADE_NO_KEY: &str = "This command made no key.";

/// The refusal when a make finds another's key, read whole, where it wrote: it is not this command's, so it is
/// not called made, and `status` says what it is.
pub const KEY_ALREADY_THERE: &str =
    "a key was already there\n  This command did not make it; swoosh status shows it.";

/// A first passphrase for this machine's key, chosen at the terminal after `notice`, which says what the key
/// will open with, and a blank line: said only once a terminal is there, so a refusal for want of one is the
/// first thing heard.
fn choose_after(prompt: &mut impl Prompt, notice: &str) -> eyre::Result<keystore::Passphrase> {
    if !prompt.terminal() {
        eyre::bail!(CHOOSE_FOR_KEY_NEEDS_TERMINAL);
    }
    prompt.warn(notice);
    prompt.warn("");
    choose_new(prompt)
}

/// A first passphrase for this machine's key, chosen at the terminal.
fn choose_new(prompt: &mut impl Prompt) -> eyre::Result<keystore::Passphrase> {
    if !prompt.terminal() {
        eyre::bail!(CHOOSE_FOR_KEY_NEEDS_TERMINAL);
    }
    crate::passphrase::choose(prompt, Asked::MachineKey)
}

/// The refusal when a passphrase for this machine's key is to be chosen and nobody is at a terminal.
pub const CHOOSE_FOR_KEY_NEEDS_TERMINAL: &str =
    "setting a passphrase on this machine's key needs a terminal: over swoosh ssh, add -t after --";

/// The home's key file.
fn key_file(home: &Home) -> KeyFile {
    KeyFile::new(home.key())
}

/// The key the file holds, unlocked, or `None` only when nothing is at the path.
///
/// A file that is present but refuses (corrupt, foreign, readable by others, a wrong passphrase) is an
/// error naming the file, never a fall-through to a fresh ephemeral identity.
fn open(file: &KeyFile, prompt: &mut impl Prompt) -> eyre::Result<Option<Secret>> {
    Ok(match file.load()? {
        None => None,
        Some(Stored::Plain(secret)) => Some(Secret(secret)),
        Some(Stored::Locked(locked)) => Some(Secret(touch::open(
            prompt,
            file,
            &locked,
            Asked::MachineKey,
            touch::Reason::to_use(touch::USE_MACHINE_KEY),
        )?)),
    })
}

/// Mint a fresh key into the empty key file, plain: the default a home is created with. A home that
/// cannot be written is named with the system's reason, the one thing a person can act on.
fn mint(home: &Home, file: &KeyFile) -> eyre::Result<Secret> {
    let secret = keystore::Secret::generate()?;
    let dir = file.path().parent().unwrap_or(file.path());
    let cannot = |reason: &dyn core::fmt::Display| {
        eyre::eyre!(
            "cannot make this machine's key in {}: {reason}",
            EscapedPath(dir)
        )
    };
    make_machine_dir(home)?;
    file.write(&secret, Protection::Plain)
        .map_err(|error| match &error {
            keystore::Error::Io { source, .. } => cannot(source),
            _ => eyre::Report::new(error),
        })?;
    Ok(Secret(secret))
}

/// Make `<home>/machine/`, owner-only like the home above it, and mark it for system backups to leave out,
/// before any key is written into it: on macOS the Time Machine exclusion `tmutil addexclusion` sets, on
/// other platforms a `CACHEDIR.TAG` holding the standard signature. Only this directory is marked, never the
/// home: a copy of the key acts as this machine, while a copy of the root is a backup. The mark sits on the
/// directory because a file's is lost when the file is replaced by a rename, and every key write is one.
/// Safe to run again: a directory already made and marked is left as it is.
///
/// # Errors
///
/// The directory could not be made, or marked: the same line as a first key that cannot be made, naming
/// the directory and the system's reason.
pub fn make_machine_dir(home: &Home) -> eyre::Result<()> {
    let dir = home.machine();
    crate::config::create_store_dir(&dir)
        .and_then(|()| mark_for_no_backup(&dir))
        .map_err(|reason| {
            eyre::eyre!(
                "cannot make this machine's key in {}: {reason}",
                EscapedPath(&dir)
            )
        })
}

/// The extended attribute Time Machine reads to leave an item out, as `tmutil addexclusion` sets it.
#[cfg(target_os = "macos")]
pub const TIME_MACHINE_EXCLUSION: &str = "com.apple.metadata:com_apple_backup_excludeItem";

/// The value `tmutil addexclusion` writes under [`TIME_MACHINE_EXCLUSION`]: the binary property list of the
/// string `com.apple.backupd`.
#[cfg(target_os = "macos")]
pub const TIME_MACHINE_EXCLUDED: &[u8] = b"bplist00_\x10\x11com.apple.backupd\x08\0\0\0\0\0\0\x01\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1c";

/// Exclude `dir` from Time Machine, the way `tmutil addexclusion <dir>` does: the exclusion travels with
/// the directory, so a key renamed into it later is left out too.
#[cfg(target_os = "macos")]
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn mark_for_no_backup(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let name = std::ffi::CString::new(TIME_MACHINE_EXCLUSION)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `path` and `name` are live NUL-terminated strings, and `TIME_MACHINE_EXCLUDED` is a live
    // static of the length passed; `setxattr` only reads them for the length of the call.
    let set = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            TIME_MACHINE_EXCLUDED.as_ptr().cast(),
            TIME_MACHINE_EXCLUDED.len(),
            0,
            0,
        )
    };
    if set != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The name of the tag backup tools read to leave a directory out.
#[cfg(not(target_os = "macos"))]
pub const CACHEDIR_TAG: &str = "CACHEDIR.TAG";

/// The first line every `CACHEDIR.TAG` starts with, which is what makes it one.
#[cfg(not(target_os = "macos"))]
pub const CACHEDIR_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

/// Leave a `CACHEDIR.TAG` in `dir` (owner-only, as every file in the home), which restic, borg, tar
/// `--exclude-caches` and other backup tools read to skip it. One already there is kept.
#[cfg(not(target_os = "macos"))]
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn mark_for_no_backup(dir: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(CACHEDIR_TAG));
    let mut tag = match opened {
        Ok(tag) => tag,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error),
    };
    tag.write_all(
        format!(
            "{CACHEDIR_SIGNATURE}\n\
             # See https://bford.info/cachedir/\n"
        )
        .as_bytes(),
    )?;
    tag.sync_all()
}

/// Write `seed` as the persisted identity at `<home>/machine/key`, plain, mode 0600, creating the store
/// dir, REFUSING a home that already holds a different one.
///
/// This is how `join` provisions the device identity a later `serve` binds from an invite that carries a
/// key: it MUST land in the same store [`resolve`] reads, so the node comes up AS the invited device.
///
/// The refusal is here, in the module that owns the file, and not at the one call site, because it is
/// the FILE's rule: the key is the one file nobody can issue again. Writing the key ALREADY on disk is
/// not a replacement, so joining the same invite again stays the silent no-op it should be; if its owner
/// locked that key, opening it by its own lock (a touch or the passphrase) proves it is the same one.
pub async fn write(seed: &[u8; 32], home: &Home) -> eyre::Result<()> {
    write_with(seed, home, &mut Terminal)
}

/// [`write`], asking `prompt` to open a sealed key that claims to be this same one.
fn write_with(seed: &[u8; 32], home: &Home, prompt: &mut impl Prompt) -> eyre::Result<()> {
    let file = key_file(home);
    let mut copy = Zeroizing::new(*seed);
    let secret = keystore::Secret::take(&mut copy);
    let incoming = secret.with_bytes(NodeId::from_ed25519_secret);
    // A sealed file's header only CLAIMS its node; opening it, by the route every open of this key takes,
    // is what proves it holds this key. Once open it is proven, so nothing is written: adopting it again
    // under a touch would ask a second dialog, with no bound.
    if let Some(Stored::Locked(locked)) = file.load()?
        && locked.public_key() == secret.public_key()
    {
        touch::open(
            prompt,
            &file,
            &locked,
            Asked::MachineKey,
            touch::Reason::to_use(touch::USE_MACHINE_KEY),
        )?;
        return Ok(());
    }
    make_machine_dir(home)?;
    match file.adopt(&secret, Protection::Plain) {
        Ok(()) => Ok(()),
        Err(keystore::Error::Different { path, existing, .. }) => {
            // The key store names no key, so the existing one is spelled here, through the bridge: a sealed
            // file's header is only a claim, and one no key could be is refused naming the file.
            let existing = existing.node_id().map_err(|_| UnusableKey {
                path: path.clone(),
                whose: Whose::of(&file),
            })?;
            eyre::bail!(
                "this machine is already {existing}; joining this would replace it with {incoming}. {} \
             holds the only copy of that key: nobody can issue another. To replace it: swoosh leave \
             --new-key",
                EscapedPath(&path),
            )
        }
        Err(error) => Err(error.into()),
    }
}

/// Write `seed` over `made`, the key [`inspect`] made earlier in this same run and nothing has used yet:
/// bare `join` printed that key, and the invite pasted after it carries its own. Any other key at
/// `<home>/machine/key` is refused. The caller holds `serve.lock` (`_serve_lock`), so no `serve` runs as
/// `made` while it is replaced, and `home.lock` (`_home_lock`) for the write.
pub fn replace_made(
    _serve_lock: &crate::home::ServeLock,
    _home_lock: &crate::home::HomeWrite,
    seed: &[u8; 32],
    made: NodeId,
    home: &Home,
) -> eyre::Result<()> {
    let file = key_file(home);
    match file.load()? {
        Some(Stored::Plain(stored)) if stored.with_bytes(NodeId::from_ed25519_secret) == made => {}
        _ => eyre::bail!(
            "{} changed while this waited for the invite; nothing was written",
            EscapedPath(file.path())
        ),
    }
    let mut copy = Zeroizing::new(*seed);
    let secret = keystore::Secret::take(&mut copy);
    let staged = KeyFile::new(home.machine().join("key.new"));
    replace::remove(staged.path())?;
    staged.write(&secret, Protection::Plain)?;
    std::fs::rename(staged.path(), file.path())?;
    std::fs::File::open(home.machine())?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
