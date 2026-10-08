//! Retiring the root kept on this machine, for good: `revoke root:<key>` where that root is kept.
//!
//! The root is presented as [`RootVerb::RevokeRoot`]: every check, then its passphrase, before anything is
//! written. It never cuts, so it dials none of your devices and folds nothing. A root whose making or restore
//! stopped after its `root.key` is retired the same way: it is a root, and its passphrase proves it is yours.
//! Under `home.lock` the root's key is latched into `revoked` first, and from that write on every read takes
//! the files it vouched for as absent: a revoked `root.key` is no root, never one to finish or mint from, and a
//! revoked pin is no pin. Then this machine's device files go, then the pin, and `root.key` last, so a crash
//! at any point after the latch leaves the revoked `root.key` on disk, which names the root still to finish.
//!
//! There is no staging directory. A crash after the latch leaves a revoked root on this machine, which
//! `status` names, and running the revoke again finishes it ([`finish`]); the root is already revoked by
//! then, so the finish asks for no passphrase. A `join` made meanwhile pins another root, whose files the
//! finish never touches: it takes `root.key` alone.

use bifrost::NodeId;
use nauthy::Revocation;
use tightbeam::identity::AsVerifyKey as _;

use super::{Root, RootError, RootPlace, RootVerb, Seam};
use crate::home::{Home, HomeWrite};
use crate::passphrase::Prompt;
use crate::standing::Standing;
use crate::sync::Dial;

/// Retire `key`, the root kept on this machine: present it, which asks its passphrase, then under
/// `home.lock` latch it and take it and this machine's device files off. Prints what the present prints on
/// `out`.
///
/// `dial` is never dialed, since the act cuts nothing; it is taken so a test can show that.
///
/// # Errors
///
/// The present's refusals, among them a wrong passphrase; the root kept here is not `key`, or this
/// machine's standing moved before the lock; or a write failed.
pub async fn retire(
    home: &Home,
    key: NodeId,
    prompt: &mut impl Prompt,
    dial: &impl Dial,
    out: &mut impl std::io::Write,
) -> Result<(), RootError> {
    let root = Root::present_to(
        home,
        RootPlace::Home,
        RootVerb::RevokeRoot,
        prompt,
        dial,
        out,
    )
    .await?;
    // The person typed the root to end; the one unlocked must be it, whatever changed since it was read.
    if root.key() != key {
        return Err(RootError::StandingChanged);
    }
    let home_lock = HomeWrite::take(home).await?;
    match Standing::read(home).await? {
        // A half-made root an `invite` finished meanwhile is the same root, still the one to end.
        Standing::HoldsRoot { pin, .. } | Standing::InterruptedMint { root_key: pin }
            if pin == key => {}
        _ => return Err(RootError::StandingChanged),
    }
    crate::revoked::add(&home_lock, home, [Revocation::Key(key.verify_key()?)])
        .map_err(|error| RootError::Write(error.into()))?;
    // The unlocked key is wiped now, before the files go: nothing after the latch signs.
    drop(root);
    super::seam(Seam::Latched)?;
    strip(&home_lock, home, key).await
}

/// Finish retiring `root`, a revoked root still on this machine: a retire that stopped after its latch.
/// Under `home.lock`, as [`retire`] writes.
///
/// # Errors
///
/// `root` is no longer the revoked root on this machine, the pin cannot be read, or a file could not be
/// removed.
pub async fn finish(home: &Home, root: NodeId) -> Result<(), RootError> {
    let home_lock = HomeWrite::take(home).await?;
    if Standing::revoked_root(home).await? != Some(root) {
        return Err(RootError::StandingChanged);
    }
    strip(&home_lock, home, root).await
}

/// Take off what the revoked `root` left here, `root.key` last. Where the pin names `root`, or there is no
/// pin, this machine's device files go first, then the pin ([`crate::joining::leave`]). A pin naming another
/// root is a `join` made since the latch, and every file but `root.key` is that root's, so they stay.
async fn strip(home_lock: &HomeWrite, home: &Home, root: NodeId) -> Result<(), RootError> {
    if crate::standing::read_pin(home)
        .await?
        .is_none_or(|pin| pin == root)
    {
        // By name: `leave` keeps the list while a `root.key` is here, and this one goes only last.
        for path in [home.devices(), home.devices_conflict()] {
            super::remove_file(&path)?;
        }
        super::seam(Seam::Delisted)?;
        crate::joining::leave(home_lock, home).map_err(super::io_at(home.dir()))?;
    }
    super::seam(Seam::Left)?;
    super::remove_file(&home.root_key())
}
