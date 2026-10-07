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
//! or sealed under a passphrase or `touch-id` once its owner asks for that with [`lock`]. A sealed key opens
//! only with a person at the terminal: a touch at this Mac ([`crate::touch`]), or a passphrase typed there
//! ([`crate::passphrase`]). A failed unlock is an error, never a fresh identity.
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
use crate::touch::{self, Then, Touch, TouchAct, TouchHere};

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
            keystore::Kind::Root => Self::Root,
            keystore::Kind::Device => {
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

/// What [`lock`] did to this machine's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locked {
    /// The key now has a passphrase. `first` when it had none before, made here, plain until now, or under
    /// `touch-id` alone.
    Set {
        /// Whether this is the first passphrase the key has had.
        first: bool,
    },
    /// The key's passphrase was taken off: it is plain now, or opens with `touch-id` alone.
    Removed {
        /// Whether the key is plain now.
        plain: bool,
    },
    /// `--remove` on a key with no passphrase: nothing to do.
    NoPassphrase,
    /// The key opens with `touch-id` now.
    TouchId {
        /// Whether its passphrase stays beside it: where a root is kept on this machine.
        passphrase: bool,
    },
    /// The key's `touch-id` lock was taken off: it is plain now, or opens with its passphrase alone.
    TouchIdRemoved {
        /// Whether the key is plain now.
        plain: bool,
    },
    /// `touch-id --remove` on a key with no `touch-id` lock: nothing to do.
    NoTouchId,
}

/// Set, change or remove the lock of `method` on this machine's key. The key never changes, so it runs beside
/// a `serve`, which holds its key in memory. Every prompt comes first, the current lock before the new one,
/// and `home.lock` is taken for the write alone; a touch that proves a new `touch-id` lock is part of the
/// write, so it is asked under the lock, bounded.
///
/// How many locks the key keeps follows one rule: where a root is kept on this machine
/// ([`Home::keeps_root`]), the key keeps a passphrase beside `touch-id`, as the root does, because no verb
/// gives this machine a new key there; elsewhere `touch-id` and a passphrase each replace the other, and the
/// key has one lock. A home with no key gets its first one sealed under the lock chosen, so a key meant to be
/// sealed never touches the disk in the clear. A removal of a lock the key does not have changes nothing.
///
/// # Errors
///
/// A lock was not given or did not open the key, a touch could not be asked for here, or the rewrite failed.
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
            let new = choose_new(prompt)?;
            let secret = keystore::Secret::generate()?;
            let _home_lock = crate::home::HomeWrite::take(home).await?;
            make_machine_dir(home)?;
            file.write(&secret, Protection::Passphrase(&new))?;
            return Ok(Locked::Set { first: true });
        }
        Some(Stored::Plain(_)) => {
            let new = choose_new(prompt)?;
            let _home_lock = crate::home::HomeWrite::take(home).await?;
            file.add_lock(None, keystore::NewLock::Passphrase(&new))?;
            return Ok(Locked::Set { first: true });
        }
        Some(Stored::Locked(locked)) => locked,
    };
    if !prompt.terminal() {
        eyre::bail!(crate::passphrase::CHANGE_FOR_KEY_NEEDS_TERMINAL);
    }
    if !touch::holds_passphrase(&locked) {
        // Under `touch-id` alone: the new passphrase is chosen first, then one touch opens the key to add it.
        let new = crate::passphrase::choose(prompt, Asked::MachineKey)?;
        let then = if home.keeps_root()? {
            Then::Keep
        } else {
            Then::Drop
        };
        let act = TouchAct::AddPassphrase { new, then };
        change_by_touch(home, prompt, &file, &locked, act).await?;
        return Ok(Locked::Set { first: true });
    }
    let current = prove_passphrase(prompt, &locked)?;
    let new = crate::passphrase::choose(prompt, Asked::MachineKey)?;
    let _home_lock = crate::home::HomeWrite::take(home).await?;
    file.add_lock(
        Some(Unlock::Passphrase(&current)),
        keystore::NewLock::Passphrase(&new),
    )?;
    Ok(Locked::Set { first: false })
}

/// Take the passphrase off this machine's key. Never where a root is kept and `touch-id` would be left alone.
async fn remove_passphrase(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Locked> {
    let file = key_file(home);
    let Some(Stored::Locked(locked)) = file.load()? else {
        return Ok(Locked::NoPassphrase);
    };
    if !touch::holds_passphrase(&locked) {
        return Ok(Locked::NoPassphrase);
    }
    let touch_id = holds_touch_id(&locked);
    if touch_id && home.keeps_root()? {
        eyre::bail!(KEEPS_PASSPHRASE);
    }
    if !prompt.terminal() {
        eyre::bail!(crate::passphrase::CHANGE_FOR_KEY_NEEDS_TERMINAL);
    }
    let current = prove_passphrase(prompt, &locked)?;
    let _home_lock = crate::home::HomeWrite::take(home).await?;
    file.remove_lock(Unlock::Passphrase(&current), keystore::Method::Passphrase)?;
    Ok(Locked::Removed { plain: !touch_id })
}

/// The refusal of `lock --remove` on a key that keeps its passphrase beside `touch-id` where a root is kept.
pub const KEEPS_PASSPHRASE: &str = "this machine's key keeps its passphrase beside touch-id while your root is \
     on this machine; to remove touch-id: swoosh lock touch-id --remove";

/// Put a `touch-id` lock on this machine's key, or set it again. Asked only at this Mac's own screen; says what
/// a new fingerprint does to it before anything is asked or written.
async fn set_touch_id(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Locked> {
    let here = prompt.touch_here();
    if here != TouchHere::Here {
        eyre::bail!("{}", touch::set_elsewhere(here, "swoosh lock touch-id"));
    }
    let keeps_root = home.keeps_root()?;
    let file = key_file(home);
    let stored = file.load()?;
    prompt.say(if keeps_root {
        touch::BESIDE_PASSPHRASE
    } else {
        touch::ONE_LOCK
    });
    if keeps_root && root_opens_by_touch(home) {
        prompt.say(touch::SHARED_FINGER);
    }
    let lines = touch::Lines::of(Asked::MachineKey, &file, keeps_root);
    let act = match stored {
        None if keeps_root => {
            let current = choose_new(prompt)?;
            let secret = keystore::Secret::generate()?;
            let home_lock = crate::home::HomeWrite::take(home).await?;
            make_machine_dir(home)?;
            file.write(&secret, Protection::Passphrase(&current))?;
            let act = TouchAct::BesidePassphrase {
                current,
                then: Then::Keep,
            };
            set_by_touch(prompt, &lines, &home_lock, &file, act, Before::Sealed)?;
            return Ok(Locked::TouchId { passphrase: true });
        }
        None => {
            let secret = keystore::Secret::generate()?;
            let home_lock = crate::home::HomeWrite::take(home).await?;
            make_machine_dir(home)?;
            let act = TouchAct::Write(secret);
            set_by_touch(prompt, &lines, &home_lock, &file, act, Before::Untouched)?;
            return Ok(Locked::TouchId { passphrase: false });
        }
        Some(Stored::Plain(_)) if keeps_root => {
            let current = choose_new(prompt)?;
            let home_lock = crate::home::HomeWrite::take(home).await?;
            file.add_lock(None, keystore::NewLock::Passphrase(&current))?;
            let act = TouchAct::BesidePassphrase {
                current,
                then: Then::Keep,
            };
            set_by_touch(prompt, &lines, &home_lock, &file, act, Before::Sealed)?;
            return Ok(Locked::TouchId { passphrase: true });
        }
        Some(Stored::Plain(_)) => TouchAct::SealPlain,
        Some(Stored::Locked(locked)) if touch::holds_passphrase(&locked) => {
            // Opened with the passphrase, never the touch: setting `touch-id` again is how a lock that stopped
            // opening is mended, so the old one is not asked for.
            let current = prove_passphrase(prompt, &locked)?;
            let then = if keeps_root { Then::Keep } else { Then::Drop };
            TouchAct::BesidePassphrase { current, then }
        }
        Some(Stored::Locked(locked)) => {
            // Under `touch-id` alone, the lock that opens it is the touch.
            let act = if keeps_root {
                let new = crate::passphrase::choose(prompt, Asked::MachineKey)?;
                TouchAct::AddPassphrase {
                    new,
                    then: Then::Keep,
                }
            } else {
                TouchAct::Again
            };
            change_by_touch(home, prompt, &file, &locked, act).await?;
            return Ok(Locked::TouchId {
                passphrase: keeps_root,
            });
        }
    };
    let home_lock = crate::home::HomeWrite::take(home).await?;
    set_by_touch(prompt, &lines, &home_lock, &file, act, Before::Untouched)?;
    Ok(Locked::TouchId {
        passphrase: keeps_root,
    })
}

/// Take the `touch-id` lock off this machine's key: opened with the passphrase where it has one, else with
/// the touch itself.
async fn remove_touch_id(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Locked> {
    let file = key_file(home);
    let Some(Stored::Locked(locked)) = file.load()? else {
        return Ok(Locked::NoTouchId);
    };
    if !holds_touch_id(&locked) {
        return Ok(Locked::NoTouchId);
    }
    if !touch::holds_passphrase(&locked) {
        change_by_touch(home, prompt, &file, &locked, TouchAct::RemoveTouchId).await?;
        return Ok(Locked::TouchIdRemoved { plain: true });
    }
    if !prompt.terminal() {
        eyre::bail!(crate::passphrase::CHANGE_FOR_KEY_NEEDS_TERMINAL);
    }
    let current = prove_passphrase(prompt, &locked)?;
    let _home_lock = crate::home::HomeWrite::take(home).await?;
    file.remove_lock(Unlock::Passphrase(&current), keystore::Method::TouchId)?;
    Ok(Locked::TouchIdRemoved { plain: false })
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

/// Whether the root kept in `home` has a `touch-id` lock, read from its header. A root that cannot be read
/// says nothing here; every use of it says why.
fn root_opens_by_touch(home: &Home) -> bool {
    matches!(
        KeyFile::root(home.root_key()).load(),
        Ok(Some(Stored::Locked(root))) if holds_touch_id(&root)
    )
}

/// Change the locks on this machine's key under `touch-id` alone: the touch opens it, so it must be one that
/// can be asked for here and reads live, or the change is refused with the line that says why.
async fn change_by_touch(
    home: &Home,
    prompt: &mut impl Prompt,
    file: &KeyFile,
    locked: &keystore::Locked,
    act: TouchAct,
) -> eyre::Result<()> {
    let lines = touch::Lines::of(Asked::MachineKey, file, false);
    match touch::route(prompt, file, locked, Asked::MachineKey) {
        touch::Route::Touch => {}
        touch::Route::Refuse(line) | touch::Route::Passphrase(Some(line)) => eyre::bail!("{line}"),
        touch::Route::Passphrase(None) => eyre::bail!("{}", touch::TOUCH_ID_GONE),
    }
    let home_lock = crate::home::HomeWrite::take(home).await?;
    prompt.say(&lines.waiting());
    let touch = Touch {
        file: file.clone(),
        reason: touch::CHANGE_MACHINE_KEY,
        act,
    };
    touch::changed(prompt.touch(touch), &lines)?;
    drop(home_lock);
    Ok(())
}

/// What a `touch-id` lock change wrote before its touch, which is what a touch that does not open can say
/// of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Before {
    /// Nothing: a touch that does not open changes nothing.
    Untouched,
    /// The key was sealed under a chosen passphrase first, so it stays sealed under it.
    Sealed,
}

/// Put a new `touch-id` lock on this machine's key through `act`, which proves it with a touch, under
/// `home.lock`.
fn set_by_touch(
    prompt: &mut impl Prompt,
    lines: &touch::Lines<'_>,
    _home_lock: &crate::home::HomeWrite,
    file: &KeyFile,
    act: TouchAct,
    before: Before,
) -> eyre::Result<()> {
    prompt.say(&lines.checking());
    let touch = Touch {
        file: file.clone(),
        reason: touch::CHECK_MACHINE_KEY,
        act,
    };
    match (before, prompt.touch(touch)) {
        (Before::Sealed, touch::Touched::Declined | touch::Touched::NotHere) => {
            eyre::bail!(SEALED_NOT_TOUCHED)
        }
        (_, touched) => touch::changed(touched, lines),
    }
}

/// The refusal when the touch that proves a new `touch-id` lock does not open, after the key was sealed
/// under a passphrase chosen for it: the passphrase lock stays.
pub const SEALED_NOT_TOUCHED: &str = "touch-id did not open this machine's key, so it was not added; the key is \
     locked with the passphrase you chose";

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
    KeyFile::device(home.key())
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
            touch::USE_MACHINE_KEY,
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
/// locked that key, the passphrase proves it is the same one.
pub async fn write(seed: &[u8; 32], home: &Home) -> eyre::Result<()> {
    write_with(seed, home, &mut Terminal)
}

/// [`write`], asking `prompt` for the passphrase of a sealed key that claims to be this same one.
fn write_with(seed: &[u8; 32], home: &Home, prompt: &mut impl Prompt) -> eyre::Result<()> {
    let file = key_file(home);
    let mut copy = Zeroizing::new(*seed);
    let secret = keystore::Secret::take(&mut copy);
    let incoming = secret.with_bytes(NodeId::from_ed25519_secret);
    // A sealed file's header only CLAIMS its node; the unlock is what proves it holds this key.
    let passphrase = match file.load()? {
        Some(Stored::Locked(locked)) if locked.public_key() == secret.public_key() => {
            let (_, passphrase) =
                crate::passphrase::unlock(prompt, Asked::MachineKey, |passphrase| {
                    locked.unlock(Unlock::Passphrase(passphrase))
                })?;
            Some(passphrase)
        }
        _ => None,
    };
    let protection = match &passphrase {
        Some(passphrase) => Protection::Passphrase(passphrase),
        None => Protection::Plain,
    };
    make_machine_dir(home)?;
    match file.adopt(&secret, protection) {
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
    let staged = KeyFile::device(home.machine().join("key.new"));
    replace::remove(staged.path())?;
    staged.write(&secret, Protection::Plain)?;
    std::fs::rename(staged.path(), file.path())?;
    std::fs::File::open(home.machine())?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
