//! Retiring the root kept on this machine, for good: `revoke root:<key>` where that root is kept.
//!
//! The root is presented as [`RootVerb::RevokeRoot`]: every check, then its passphrase, before anything is
//! written. It never cuts, so it dials none of your devices and folds nothing. Under `home.lock` the root's
//! key is latched into `revoked` first, and from that write on every read takes the files it vouched for as
//! absent: a revoked `root.key` is no root, never one to finish or mint from, and a revoked pin is no pin.
//! Then `root.key` goes, then this machine's device files, and `root.pub` last.
//!
//! There is no staging directory. A crash after the latch leaves a revoked root on this machine, which
//! `status` names, and running the revoke again finishes it ([`finish`]); the root is already revoked by
//! then, so the finish asks for no passphrase.

use bifrost::NodeId;
use nauthy::Revocation;
use tightbeam::identity::AsVerifyKey as _;

use super::{Root, RootError, RootPlace, RootVerb};
use crate::home::{Home, HomeWrite};
use crate::passphrase::Prompt;
use crate::standing::Standing;
use crate::sync::Dial;

/// Retire the root kept on this machine: present it, which asks its passphrase, then under `home.lock`
/// latch it and take it and this machine's device files off. Prints what the present prints on `out`.
/// Returns the root retired.
///
/// `dial` is never dialed, since the act cuts nothing; it is taken so a test can show that.
///
/// # Errors
///
/// The present's refusals, among them a wrong passphrase; this machine's standing moved before the lock;
/// or a write failed.
pub async fn retire(
    home: &Home,
    prompt: &mut impl Prompt,
    dial: &impl Dial,
    out: &mut impl std::io::Write,
) -> Result<NodeId, RootError> {
    let root = Root::present_to(
        home,
        RootPlace::Home,
        RootVerb::RevokeRoot,
        prompt,
        dial,
        out,
    )
    .await?;
    let key = root.key();
    let home_lock = HomeWrite::take(home).await?;
    match Standing::read(home).await? {
        Standing::HoldsRoot { pin, .. } if pin == key => {}
        _ => return Err(RootError::StandingChanged),
    }
    crate::revoked::add(&home_lock, home, [Revocation::Key(key.verify_key()?)])
        .map_err(|error| RootError::Write(error.into()))?;
    // The unlocked key is wiped now, before the files go: nothing after the latch signs.
    drop(root);
    strip(&home_lock, home)?;
    Ok(key)
}

/// Finish retiring `root`, a revoked root still on this machine: a retire that stopped after its latch.
/// Under `home.lock`, as [`retire`] writes.
///
/// # Errors
///
/// `root` is no longer the revoked root on this machine, or a file could not be removed.
pub async fn finish(home: &Home, root: NodeId) -> Result<(), RootError> {
    let home_lock = HomeWrite::take(home).await?;
    if Standing::revoked_root(home).await? != Some(root) {
        return Err(RootError::StandingChanged);
    }
    strip(&home_lock, home)
}

/// `root.key` first, then this machine's device files, the pin last ([`crate::joining::leave`]), which
/// removes the list of your devices too once no root is kept here.
fn strip(home_lock: &HomeWrite, home: &Home) -> Result<(), RootError> {
    super::remove_file(&home.root_key())?;
    crate::joining::leave(home_lock, home).map_err(super::io_at(home.dir()))
}
