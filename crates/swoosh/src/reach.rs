//! Resolve a [`Target`] to a live session: turn a petname or key into a connected peer.
//!
//! The reach-outward verbs (`ping`, `speed`, `status`) share one need: take the peer slot the user
//! typed, resolve it against the contact store, and dial. A raw key dials once; a person (`alice`) dials
//! each of their devices in order until one connects, the v1 "first reachable device wins" of weak
//! device-grouping. This module owns that dial-in-order so no verb repeats it.

use bifrost::{Discovery, Node, NodeId, Transport};

use crate::contacts::{Contacts, Target};

/// A dialed peer: the session plus the identity that actually answered.
///
/// The identity is returned because a person target can resolve to several devices and this reports
/// WHICH one connected, so a verb prints the device it reached, not the name it was asked for.
pub struct Reached<S> {
    /// The live session to the peer.
    pub session: S,
    /// The identity that answered (the specific device, for a multi-device person).
    pub peer: NodeId,
}

/// Resolve `target` against `contacts` and connect to the first identity that answers.
///
/// Candidates are tried in resolution order; the first successful [`connect`](Node::connect) wins and
/// its error, if all fail, is the last one seen. An unknown petname surfaces the resolver's clean error
/// before any dial. A raw key resolves to a single candidate, so this is a plain dial for the common
/// case and only fans out for a multi-device person.
pub async fn dial<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    contacts: &Contacts,
    target: &Target,
) -> eyre::Result<Reached<T::Session>> {
    let candidates = target.resolve(contacts)?;

    let mut last_error = None;
    for peer in candidates {
        match node.connect(peer).await {
            Ok(session) => return Ok(Reached { session, peer }),
            Err(error) => {
                tracing::debug!(%peer, %error, "device unreachable; trying the next");
                last_error = Some(error);
            }
        }
    }

    // Every candidate failed. `resolve` guarantees at least one candidate, so `last_error` is set; carry
    // its source rather than inventing a message, and note the target for the reader.
    Err(match last_error {
        Some(error) => eyre::Report::new(error).wrap_err(format!("could not reach {target}")),
        None => eyre::eyre!("could not reach {target}: no known device"),
    })
}
