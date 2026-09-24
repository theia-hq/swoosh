//! The node identity: the ed25519 secret every swoosh verb binds under.
//!
//! Identity is chosen by intent, and exactly one intent CREATES a key. A verb that must be *reachable at
//! a stable address* (`serve`) persists its secret at `<home>/identity.key`: it loads that key and writes
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
//! that is not a key this build reads is refused rather than minted over, and [`write`] (the `adopt`
//! path) refuses a home that already holds a different identity. The key is the one file in the store
//! with no issuer and no second copy: a signet roots every badge its owner ever signed, and there is
//! nobody to cut another. So it is replaced only by a restore the operator asks for by name
//! ([`restore`]), which checks the identity it replaces, never as a side effect of another verb.
//!
//! How the file protects the key is a property of the FILE, read from its own bytes: `plain` by default,
//! or sealed under a passphrase once its owner asks for that with [`protect`]. A sealed key opens only
//! under a passphrase typed at the terminal ([`crate::passphrase`]); a failed unlock is an error, never a
//! fresh identity.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes its bytes on drop so the
//! key does not linger in freed memory, and it lends them out only at the boundaries that need them raw.
//!
//! The persisted default lives at `~/.config/swoosh/identity.key`, mode 0600.

use bifrost::NodeId;
use keystore::{KeyFile, Protection, Stored};
use nauthy::Link;
use tightbeam::identity::AsVerifyKey as _;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::home::Home;
use crate::passphrase::{Prompt, Terminal};

mod backup;
mod lock;
mod protect;
mod stage;

pub use backup::{Existing, Restored, export, restore};
pub use lock::HomeLock;
pub use protect::{Protected, protect};

/// The DEFAULT lifetime a signet-signed, STORED device membership badge stands before it must be
/// re-minted, applied by `swoosh invite add` only when the operator passes no `--expires`. A default, not a
/// hardcoded law: the CLI threads an explicit window straight into [`sign_device_badge`], and falls back
/// to this value when none is given.
///
/// A stored badge is a longer-lived bearer credential than the 5-minute self-sign a signet holder mints
/// per dial, so it must carry a FINITE lifetime, not "forever" -- a lost, un-denylisted device then ages
/// out on its own even absent an explicit revoke. Offline there is no control plane to split the invite's
/// leak-window from the badge lifetime, so this value IS the worst-case leak window for a mint that is
/// never revoked. 90 days is the chosen default: a real re-mint cadence (about quarterly) a homelab owner
/// can absorb, and a 90-day backstop instead of a year, matching the invite default operators expect. A
/// longer window (up to a year via `swoosh invite add --expires 365d`, for a controlled reused-secret case such
/// as qat) stays reachable, but is now a conscious opt-in rather than the silent, only value. Revocation
/// stays the primary, immediate control (the `FileDenylist`, offline + live); the TTL is the backstop for
/// a leak never noticed.
pub const DEVICE_BADGE_TTL: core::time::Duration =
    core::time::Duration::from_secs(90 * 24 * 60 * 60);

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
    /// offline (no transport stood up), so `swoosh identity` can print it without serving.
    pub fn node_id(&self) -> NodeId {
        self.0.node_id()
    }

    /// The cap-signing identity rooted at this secret: the same key, read as a nauthy [`Identity`] that
    /// can mint and verify capabilities. Borrows, so the secret stays owned here and zeroizes on drop.
    ///
    /// This is what lets the signet holder SELF-SIGN a membership badge when it dials a family-gated node
    /// (`invite add` signs a device's badge; `swoosh ssh` self-signs its own): the badge roots at this key, the
    /// same key the dial binds under, so the gate's device-binding matches. Mirrors tightbeam's
    /// `Secret::cap_identity`, the exposer side of the same seam.
    pub fn cap_identity(&self) -> eyre::Result<nauthy::Identity> {
        Ok(self.0.with_bytes(nauthy::Identity::from_secret)?)
    }

    /// Self-sign a membership badge for THIS identity: a short-lived cap carrying a `member(true)` fact in
    /// its authority block, rooted at this key and bound to this key's own node id. The `member(true)` fact
    /// is what a family gate reads as membership; because biscuit trusts only authority-block facts, it
    /// cannot be forged by attenuation. The signet holder is the one party always entitled to a badge
    /// (it holds the root), so when it dials a family-gated node it mints one in-process rather than
    /// carrying a stored one. Short-lived because it is re-minted per dial; the binding makes it useless if
    /// intercepted off another key. Returns the `sheer:` link to present.
    pub fn member_badge(&self) -> eyre::Result<Link> {
        use core::time::Duration;

        // Minted fresh each dial, so a few minutes is ample and bounds a leaked in-flight badge.
        let ttl = Duration::from_secs(5 * 60);
        Ok(self
            .cap_identity()?
            .mint_member(
                self.node_id().verify_key(),
                nauthy::Request::expires_in(ttl),
            )?
            .seal()?
            .link()?)
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

    /// Sign a membership badge FOR a device, rooted at THIS key (the signet) and bound to `device`.
    ///
    /// This is the mint-time counterpart to [`member_badge`](Self::member_badge): where the signet holder
    /// self-signs its OWN badge per dial (root == dialer), here the signet signs a badge for a DIFFERENT
    /// key (the device's derived node id), so the device can present a signet-rooted proof it could never
    /// mint itself. The gate trusts the signet root, so this badge admits; a device's own self-sign roots
    /// at its child key and is (correctly) refused. `bound_device` = `device`, so an intercepted badge
    /// replayed from another key fails the binding.
    ///
    /// FINITE lifetime: unlike the 5-minute self-sign (re-minted per dial), this badge is STORED on the
    /// device and stands until it expires or is denylisted, so it carries a generous-but-finite `ttl`
    /// rather than "forever" -- a lost, un-denylisted device eventually ages out. The caller owns the
    /// window: `swoosh invite add` passes an explicit `--expires`, or falls back to [`DEVICE_BADGE_TTL`], so
    /// the lifetime is a default the CLI applies, not a constant buried in this signer. The signet secret
    /// stays in this wrapper: only the signed public badge (a `sheer:` link) leaves.
    pub fn sign_device_badge(
        &self,
        device: NodeId,
        ttl: core::time::Duration,
    ) -> eyre::Result<Link> {
        Ok(self
            .cap_identity()?
            .mint_member(device.verify_key(), nauthy::Request::expires_in(ttl))?
            .seal()?
            .link()?)
    }

    /// The seed for a device identity derived from this key (the signet) under `label`: the secret a
    /// machine ADOPTS to become that device, and the payload of a derived invite. Borrows, so this root
    /// stays owned here and zeroizes on drop; the raw root never leaves the wrapper, only the derived
    /// child does. Hardened (only the holder of this root can compute a child), so a leaked device seed
    /// cannot recover the root or a sibling. The child is secret too, so it arrives in a wiping owner.
    pub fn derive_child_seed(&self, label: &str) -> Zeroizing<[u8; 32]> {
        self.0
            .with_bytes(|root| bifrost_core::derive_ed25519_child_secret(root, label))
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

/// Resolve the secret a verb binds under from its home: the key is always `<home>/identity.key`, and the
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
            None => mint(&file),
        },
        Identity::Ephemeral => Ok(Secret::ephemeral()),
        // Load the persisted key only if it already exists; never create it. So a provisioned operator's
        // outward dial roots at their own key (their badge admits at their gated node) while a fresh
        // install dials out ephemerally, with nothing written to disk.
        Identity::PersistedIfPresent => Ok(open(&file, prompt)?.unwrap_or_else(Secret::ephemeral)),
    }
}

/// Load the persisted secret at `<home>/identity.key` if the file exists and holds a key, else `None`,
/// WITHOUT creating one. A bound invite carries no seed, so `adopt` uses this to require the key the
/// badge was signed for; a home with no identity gets a teaching error, never a fresh key minted over
/// the invite's binding.
pub async fn load(home: &Home) -> eyre::Result<Option<Secret>> {
    open(&key_file(home), &mut Terminal)
}

/// What the home's key file is, WITHOUT unlocking it, minting a plain key first when the home has none.
///
/// This is the offline look `swoosh identity` prints: which node the file is for and how it is protected.
/// For a sealed file the node is what its header claims (see [`keystore::Locked::node_id`]); nothing here
/// asks for a passphrase, so printing an identity never blocks on a prompt.
pub fn inspect(home: &Home) -> eyre::Result<Stored> {
    let file = key_file(home);
    match file.load()? {
        Some(stored) => Ok(stored),
        None => mint(&file).map(|secret| Stored::Plain(secret.0)),
    }
}

/// The home's key file.
fn key_file(home: &Home) -> KeyFile {
    KeyFile::device(home.identity_key())
}

/// The key the file holds, unlocked, or `None` only when nothing is at the path.
///
/// A file that is present but refuses (corrupt, foreign, readable by others, a wrong passphrase) is an
/// error naming the file, never a fall-through to a fresh ephemeral identity.
fn open(file: &KeyFile, prompt: &mut impl Prompt) -> eyre::Result<Option<Secret>> {
    Ok(match file.load()? {
        None => None,
        Some(Stored::Plain(secret)) => Some(Secret(secret)),
        Some(Stored::Locked(locked)) => {
            let passphrase = prompt.unlock(file.path())?;
            Some(Secret(locked.unlock(&passphrase)?))
        }
    })
}

/// Mint a fresh key into the empty key file, plain: the default a home is created with.
fn mint(file: &KeyFile) -> eyre::Result<Secret> {
    let secret = keystore::Secret::generate()?;
    create_dir(file)?;
    file.write(&secret, Protection::Plain)?;
    Ok(Secret(secret))
}

/// Create the directory the key file lives in, owner-only, as every store file's directory is.
fn create_dir(file: &KeyFile) -> eyre::Result<()> {
    if let Some(dir) = file.path().parent() {
        crate::config::create_store_dir(dir)?;
    }
    Ok(())
}

/// Write `seed` as the persisted identity at `<home>/identity.key`, plain, mode 0600, creating the store
/// dir, REFUSING a home that already holds a different one.
///
/// This is how `adopt` provisions the device identity a later `serve` binds: it MUST land in the same
/// store [`resolve`] reads, so the node comes up AS the adopted device. (Writing tightbeam's separate
/// store instead was the qat identity-mismatch bug: `serve` bound swoosh's own key, never the adopted
/// one, so the exposed node had a different id than the contact pointed at.)
///
/// The refusal is here, in the module that owns the file, and not at the one call site, because it is
/// the FILE's rule. What is at stake is not recoverable. Its siblings in `adopt`'s transaction (the
/// trusted signet, the stored badge) are both `--force`-gated and both re-obtainable from the owner, so
/// the flag that waves those through deliberately does not reach this one. Writing the key ALREADY on
/// disk is not a replacement, so re-adopting the same invite stays the silent no-op it should be; if its
/// owner sealed that key, the passphrase proves it is the same one.
pub async fn write(seed: &[u8; 32], home: &Home) -> eyre::Result<()> {
    write_with(seed, home, &mut Terminal)
}

/// [`write`], asking `prompt` for the passphrase of a sealed key that claims to be this same one.
fn write_with(seed: &[u8; 32], home: &Home, prompt: &mut impl Prompt) -> eyre::Result<()> {
    let file = key_file(home);
    let mut copy = Zeroizing::new(*seed);
    let secret = keystore::Secret::take(&mut copy);
    let incoming = secret.node_id();
    // A sealed file's header only CLAIMS its node; the unlock is what proves it holds this key.
    let passphrase = match file.load()? {
        Some(Stored::Locked(locked)) if locked.node_id() == incoming => {
            Some(prompt.unlock(file.path())?)
        }
        _ => None,
    };
    let protection = match &passphrase {
        Some(passphrase) => Protection::Passphrase(passphrase),
        None => Protection::Plain,
    };
    create_dir(&file)?;
    match file.adopt(&secret, protection) {
        Ok(()) => Ok(()),
        Err(keystore::Error::Different {
            path,
            existing,
            incoming,
        }) => eyre::bail!(
            "this machine is already {existing}; adopting this would replace it with {incoming}. {} \
             holds the only copy of that key: nobody can issue another, and if it is the signet your \
             fleet roots at, every device you enrolled roots there too. --force will not do it either, \
             because what it waves through is a credential the owner can re-issue. copy the file \
             somewhere safe and move it aside, if becoming a different device is what you meant",
            path.display(),
        ),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
