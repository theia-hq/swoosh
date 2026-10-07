//! Joining a root and leaving it: the writes, in the order that keeps a crash readable. Each runs under
//! `home.lock`, which its caller holds.
//!
//! The pin is written last on a join and removed last on a leave. It is what makes the other files mean
//! anything, so a crash part way leaves a home [`Standing::read`](crate::standing::Standing::read) reads as
//! an act that did not finish, naming the verb that finishes it, never as a standing.

use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

use bifrost::NodeId;
use nauthy::{Link, Revocations as _};
use tightbeam::identity::AsVerifyKey as _;

use crate::contacts::DeviceLabel;
use crate::home::{Home, HomeWrite};
use crate::standing::Standing;

/// What a join writes: this machine's standing from the root, and the machine that made the invite with
/// the name it gave this one.
#[derive(Debug)]
pub struct Join<'a> {
    /// The root the standing is from: the pin.
    pub root: NodeId,
    /// This machine's standing, signed by the root.
    pub standing: &'a Link,
    /// The machine that made the invite: the first device a sync asks.
    pub from: NodeId,
    /// The name the invite gives this machine: what it is called until a list of your devices lands.
    pub name: &'a DeviceLabel,
    /// Whether the pin changes: a first join, or a switch to another root.
    pub pin_changes: bool,
}

/// Write a join, under `home.lock`: on a pin change, the old root's lists go and `invited-by` is written;
/// then the standing; then, on a pin change, the pin. A join to the root already pinned is the same-root
/// write, and leaves the pin as it is.
///
/// # Errors
///
/// A file could not be removed or written.
pub fn join(home_lock: &HomeWrite, home: &Home, join: Join<'_>) -> io::Result<()> {
    if join.pin_changes {
        for path in [home.devices(), home.synced(), home.devices_conflict()] {
            remove(path)?;
        }
        crate::config::write_private_atomic(
            home_lock,
            &home.invited_by(),
            format!("{}\n{}\n", join.from, join.name).as_bytes(),
        )?;
    }
    same_root_write(home_lock, home, join.standing)?;
    if join.pin_changes {
        crate::config::write_signet(home_lock, home, join.root)?;
    }
    Ok(())
}

/// What `invited-by` holds: the machine whose invite this machine joined, and the name that invite gave
/// this machine. Both are the invite's unsigned hints; a list of your devices replaces them once it lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitedBy {
    /// The machine that made the invite.
    pub from: NodeId,
    /// The name the invite gave this machine, when the file holds a usable one.
    pub name: Option<DeviceLabel>,
}

impl InvitedBy {
    /// Read `invited-by`. `None` when it is absent, or its first line is not a key.
    pub fn read(home: &Home) -> Option<Self> {
        let text = std::fs::read_to_string(home.invited_by()).ok()?;
        let mut lines = text.lines();
        let from = lines.next()?.trim().parse::<NodeId>().ok()?;
        let name = lines.next().and_then(|name| name.trim().parse().ok());
        Some(Self { from, name })
    }
}

/// Take a renewed standing that one of your devices handed this machine, under `home.lock`, through the
/// same-root write a join makes: only one bound to this machine's key, rooted at the pin, ending after the
/// one held, and neither its id nor this key revoked here. When it ends, if it was taken.
///
/// It never writes the pin, so a standing fetched from the network can renew this machine and never move
/// it to another root.
pub async fn take_renewal(
    home_lock: &HomeWrite,
    home: &Home,
    standing: &Link,
) -> eyre::Result<Option<SystemTime>> {
    let (pin, held) = match Standing::read(home).await? {
        Standing::Device { pin, until } | Standing::HoldsRoot { pin, until } => (pin, until),
        Standing::Unpinned | Standing::InterruptedMint { .. } => return Ok(None),
    };
    let file = keystore::KeyFile::device(home.key());
    let Some(own) = file
        .load()?
        .map(|stored| crate::identity::key_of(&file, &stored))
        .transpose()?
    else {
        return Ok(None);
    };
    let cap = standing.cap();
    let Ok(Some(until)) = cap.expiry() else {
        return Ok(None);
    };
    let (own, pin) = (own.verify_key()?, pin.verify_key()?);
    let bound = cap
        .verify_member_at_root_without_revocation(SystemTime::now(), own, pin)
        .is_ok();
    let revocations = crate::revoked::open(home)?;
    let blocked = revocations.is_revoked(cap) || revocations.is_revoked_peer(&own);
    if !bound || until <= held || blocked {
        return Ok(None);
    }
    same_root_write(home_lock, home, standing)?;
    Ok(Some(until))
}

/// The write a standing from the root already pinned takes: the standing, atomically. The pin already
/// names that root, so it is not touched.
fn same_root_write(home_lock: &HomeWrite, home: &Home, standing: &Link) -> io::Result<()> {
    crate::config::write_badge(home_lock, home, standing)
}

/// Leave the root this machine trusts, under `home.lock`: the standing and the lists go, and with them
/// the devices under `me`, then the pin, last. The revocations this machine learned stay, and so does a
/// root kept here: while `root.key` is on this machine, `devices` and `devices.conflict` are its list and
/// what its next number is read from, so they stay with it.
///
/// # Errors
///
/// A file could not be removed, or whether a root is kept here could not be told.
pub fn leave(_home_lock: &HomeWrite, home: &Home) -> io::Result<()> {
    let mut gone = vec![home.key_cert(), home.synced(), home.invited_by()];
    if !home.keeps_root()? {
        gone.extend([home.devices(), home.devices_conflict()]);
    }
    for path in gone {
        remove(path)?;
    }
    remove(home.root_pub())?;
    Ok(())
}

/// Remove a file. Already gone is done.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn remove(path: PathBuf) -> io::Result<()> {
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}
