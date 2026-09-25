//! What this machine's own key signs: slips for the services it serves, and nothing else.
//!
//! A slip signed here roots at this machine's key, so the only gate that admits it is this machine's own.
//! Whoever steals the key can already reach everything such a slip reaches. That is why a machine may
//! sign one with no one's leave, and why it may sign nothing wider: no membership badge, no device
//! standing, no fleet document.
//!
//! A slip is minted only through [`NodeSigner::mint_slip`]. The helper here that reads a [`Secret`] as a
//! signing `nauthy::Identity`, `cap_identity`, is private to this module.
//!
//! That is not yet a guarantee that the key cannot be read as a signer elsewhere: [`Secret::with_bytes`]
//! is public, so `secret.with_bytes(nauthy::Identity::from_secret)` still compiles anywhere until the
//! `disallowed-methods` ban on `from_secret` lands (U22). Its one interim caller is
//! [`Secret::sign_device_badge`] (U17).
//!
//! ```
//! use swoosh::grants::Delegation;
//! use swoosh::identity::Secret;
//! use swoosh::node_signer::{Bind, NodeSigner};
//!
//! let secret = Secret::ephemeral();
//! let ssh: nauthy::Service = "ssh".parse()?;
//! let link = NodeSigner::from(&secret).mint_slip(
//!     &ssh,
//!     Bind::Anyone,
//!     core::time::Duration::from_secs(3600),
//!     Delegation::Sealed,
//! )?;
//! assert!(link.as_str().starts_with("ed01"));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! The helper is not callable from outside:
//!
//! ```compile_fail,E0624
//! let secret = swoosh::identity::Secret::ephemeral();
//! let _ = secret.cap_identity();
//! ```

use core::time::Duration;

use nauthy::{CapError, Identity, Link, Service, VerifyKey};

use crate::grants::Delegation;
use crate::identity::Secret;

/// This machine's own key, lent for signing slips.
///
/// Built from the machine's [`Secret`], which it borrows, so the key stays in the wrapper that wipes it.
/// It prints nothing: there is no `Debug`, since the only field is the key.
pub struct NodeSigner<'a> {
    secret: &'a Secret,
}

impl<'a> From<&'a Secret> for NodeSigner<'a> {
    fn from(secret: &'a Secret) -> Self {
        Self { secret }
    }
}

/// Who a slip grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    /// Anyone holding the link: a bearer slip.
    Anyone,
    /// One device, which must prove this key when it dials.
    Device(VerifyKey),
    /// Every device the root with this key vouches for.
    Fleet(VerifyKey),
}

/// Why a slip was not signed.
#[derive(Debug, thiserror::Error)]
pub enum SlipError {
    /// A slip bound to a device or a fleet is useless to anyone else, so passing it on is never what the
    /// binding meant. It is always sealed.
    #[error("a slip bound to a device or a fleet cannot be delegable")]
    BoundIsSealed,
    /// The signing itself failed.
    #[error("could not sign the slip")]
    Cap(#[from] CapError),
}

impl NodeSigner<'_> {
    /// Sign a slip granting `service` to `bind`, valid for `lifetime` from now, rooted at this machine's
    /// key.
    ///
    /// A bearer slip is left open for its holder to narrow and pass on only when `delegation` is
    /// [`Delegable`](Delegation::Delegable). A bound slip is always sealed, and asking for a delegable one
    /// is refused rather than quietly sealed.
    pub fn mint_slip(
        &self,
        service: &Service,
        bind: Bind,
        lifetime: Duration,
        delegation: Delegation,
    ) -> Result<Link, SlipError> {
        let identity = self.secret.cap_identity()?;
        match (bind, delegation) {
            (Bind::Anyone, Delegation::Delegable) => Ok(Link::mint(&identity, service, lifetime)?),
            (Bind::Anyone, Delegation::Sealed) => {
                Ok(Link::mint(&identity, service, lifetime)?.seal()?)
            }
            (Bind::Device(_) | Bind::Fleet(_), Delegation::Delegable) => {
                Err(SlipError::BoundIsSealed)
            }
            (Bind::Device(device), Delegation::Sealed) => {
                Ok(Link::mint_bound(&identity, service, device, lifetime)?)
            }
            (Bind::Fleet(root), Delegation::Sealed) => Ok(Link::mint_authority_bound(
                &identity, service, root, lifetime,
            )?),
        }
    }
}

impl Secret {
    /// This secret, read as a nauthy [`Identity`] that can sign. Private to this module, so what a
    /// [`NodeSigner`] may sign is the list of its methods.
    fn cap_identity(&self) -> Result<Identity, CapError> {
        self.with_bytes(Identity::from_secret)
    }
}

#[cfg(test)]
#[path = "node_signer_tests.rs"]
mod node_signer_tests;
