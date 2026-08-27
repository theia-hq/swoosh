//! Resolve a [`Target`] to a live session: turn a petname or key into a connected peer.
//!
//! The reach-outward verbs (`ping`, `speed`, `status`) share one need: take the peer slot the user
//! typed, resolve it against the contact store, and dial. A raw key dials once; a person (`alice`) dials
//! each of their devices in order until one connects, the v1 "first reachable device wins" of weak
//! device-grouping. This module owns that dial-in-order so no verb repeats it.

use core::time::Duration;

use bifrost::{Discovery, Node, NodeId, Transport};

use crate::contacts::{Contacts, Target};
use crate::transport;

/// How long to wait for one candidate device to connect before moving on to the next.
///
/// Weak device-grouping dials a person's devices in order and takes the first that answers, so a single
/// wedged device (a black hole that neither connects nor refuses) must not strand the reachable devices
/// behind it. This bounds each `connect` attempt: a candidate that has not answered within the budget is
/// treated as unreachable and the next is tried, keeping first-reachable actually reachable. Ten seconds
/// is generous for a real handshake (including iroh hole-punching) yet short enough that a dead device
/// does not feel like a hang.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

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
/// Candidates are tried in resolution order under a per-candidate [`DIAL_TIMEOUT`]; the first successful
/// [`connect`](Node::connect) wins and its error, if all fail, is the last one seen. An unknown petname
/// surfaces the resolver's clean error before any dial. A raw key resolves to a single candidate, so this
/// is a plain dial for the common case and only fans out for a multi-device person. `transport` names the
/// bound backend so the final error can point the user at the fix its transport needs.
pub async fn dial<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    contacts: &Contacts,
    target: &Target,
    transport: transport::Transport,
) -> eyre::Result<Reached<T::Session>> {
    let candidates = target.resolve(contacts)?;

    let mut last_error = None;
    for peer in candidates {
        // Bound each attempt so a wedged device does not strand the reachable ones behind it: a timeout
        // is just this candidate being unreachable, so it stashes an error and falls through to the next,
        // exactly like a refused connection.
        match tokio::time::timeout(DIAL_TIMEOUT, node.connect(peer)).await {
            Ok(Ok(session)) => return Ok(Reached { session, peer }),
            Ok(Err(error)) => {
                tracing::debug!(%peer, %error, "device unreachable; trying the next");
                last_error = Some(eyre::Report::new(error));
            }
            Err(_elapsed) => {
                tracing::debug!(%peer, timeout = ?DIAL_TIMEOUT, "device did not answer in time; trying the next");
                last_error = Some(eyre::eyre!(
                    "timed out after {DIAL_TIMEOUT:?} with no response"
                ));
            }
        }
    }

    // Every candidate failed. `resolve` guarantees at least one candidate, so `last_error` is set; carry
    // its source rather than inventing a message, note the target, and append the fix this transport
    // needs so the user is told what to do next, not just what went wrong.
    let reached = match last_error {
        Some(error) => error.wrap_err(format!("could not reach {target}")),
        None => eyre::eyre!("could not reach {target}: no known device"),
    };
    Err(match transport {
        // quirk is direct-only with no discovery, so an unreachable peer is almost always a missing or
        // wrong address hint. Name the exact flag (mirroring the exemplary unknown-contact error) and the
        // one-flag escape to a self-discovering transport.
        transport::Transport::Quirk => reached.wrap_err(
            "quirk is direct-only: pass --peer <key>=<addr> (the line the peer's `swoosh serve` printed), or use --transport iroh",
        ),
        transport::Transport::Iroh => reached,
    })
}
