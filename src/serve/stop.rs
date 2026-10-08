use core::time::Duration;
use std::sync::Arc;

use nauthy::VerifyKey;
use tightbeam::identity::AsNodeId as _;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, CancellationToken, Handler, ServeError, Served};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::contacts::Contacts;
use crate::peer::OwnDevice;
use crate::serve::{StopKind, StopSource};

/// The `control.stop` handler swoosh injects: the remote node-lifecycle stop. It holds a CLONE of the
/// node's teardown token as the node-control CAPABILITY (never a node handle), so when an admitted caller
/// reaches it, it REQUESTS the graceful teardown by cancelling that token; the exposer (the one owner of
/// teardown) sees the cancel and stops the node.
///
/// MEMBER-only: the `control.stop` route is declared member-only where `serve` assembles it, and
/// tightbeam's dispatch checks that floor after the gate admits and before any `Response::Ok`, so only a
/// caller the gate admitted as a whole-node member (this node's own devices, the fleet) can stop it. A
/// delegate holding a `control.stop` slip is refused with the same uniform refusal a gate miss gives, and
/// this handler never runs; an open gate over the route is refused at
/// [`Router::expose`](tightbeam::tunnel::Router::expose).
///
/// The handler does not re-check the witness: the floor is enforced once in tightbeam's dispatch path.
/// The HARDENED lifecycle (an arm->confirm nonce + a single-use device-bound DESTROY-CAP, ideally
/// OWNER-only so another fleet device cannot casually shut the node down) is the FOLLOW, and needs an
/// Adversary gating-review before `control.stop` is trusted on a multi-device fleet; the open question
/// there is whether the `Admitted` witness can distinguish an owner device from another fleet device.
///
/// Any of your devices may stop any other, so the stopped node says who did, on its own stderr: the
/// one trail a stop leaves. The handler notes the key the connection proved ([`Served::peer`]) as the
/// stop's source, and `serve` names it at teardown from this node's own book ([`stopped_by`]). The
/// record holds only that key, so nothing on the line can come from the caller's request, and a caller
/// cannot claim to be another device.
///
/// On admission the handler writes ONE ack byte and finishes its side, so the client can confirm the stop
/// was actioned (not merely that the dial was admitted): a positive, explicit confirmation, the honest
/// counterpart to the loud typed refusal a non-admitted caller gets at the gate. Only once the caller
/// closes its side (or [`ACK_GRACE`] passes) does it note the stop and cancel the token. The order is the
/// point: the teardown drops the connection at once, and a QUIC close may discard bytes still in flight,
/// so a node that cancelled first could stop for real while its ack never arrived. The side that receives
/// last is the only one that knows the data landed, so the caller closes first and the node stops after.
/// A handler dropped during that wait, once the ack has left, still notes the stop and cancels the token.
///
/// Public so the `gated_stop` proof drives the SAME handler `serve` injects, not a hand-rolled near-copy,
/// exactly as the `gated_measure` proof reuses `diagnostics`.
pub struct Stop {
    cancel: CancellationToken,
    /// Where the node records how it was asked to stop, shared with the run that reads it at teardown.
    source: Arc<StopSource>,
}

impl Stop {
    /// Build the `control.stop` handler holding a CLONE of the node's teardown token as the node-control
    /// capability (never a node handle): an admitted caller REQUESTS the graceful teardown by cancelling it,
    /// and the key it came from is noted in `source`.
    pub fn new(cancel: CancellationToken, source: Arc<StopSource>) -> Self {
        Self { cancel, source }
    }
}

impl Handler for Stop {
    // The route is member-only (declared in `serve`) and has no safe public form: the marker keeps an
    // open-gate pairing from ever being built, and the member floor refuses every non-member pre-Ok.
    type Exposure = Never;

    async fn serve(
        &self,
        served: Served<Self>,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        // The ack byte, then the end of this side, so the caller holds both before anything tears down.
        // Kept as a value, never `?`-ed: an admitted stop must happen whatever the stream did.
        let written = writer.write_all(&[STOP_ACK]).await;
        // Armed once the byte has left this handler, since from then the caller may hold the ack and
        // print `Stopped`. Something can still drop this future in the wait below (a live cut ending the
        // session), and the guard turns that drop into the stop the caller was told happened. Before the
        // write nothing is armed: a handler dropped there sent no ack, so its caller claims nothing.
        let stopping = StopOnDrop {
            stop: self,
            peer: served.peer(),
        };
        let acked = match written {
            Ok(()) => writer.shutdown().await,
            Err(error) => Err(error),
        };
        // Wait for the caller's side to end: its close after reading the ack, a broken stream, or the
        // bound, whichever is first. Read only to see it end; nothing read is kept, since the key is the
        // connection's. The cap bounds what a caller can make the node read on its way down.
        let mut ignored = (&mut reader).take(CALLER_BYTES);
        let _ = tokio::time::timeout(
            ACK_GRACE,
            tokio::io::copy(&mut ignored, &mut tokio::io::sink()),
        )
        .await;
        // The normal path stops through the guard too, so the note and cancel live in one place.
        drop(stopping);
        acked.map_err(Into::into)
    }
}

/// The stop an acked `control.stop` owes, fired when dropped: on the handler's own return, or when the
/// handler's future is dropped mid-wait. Either way the caller's `Stopped` stays true.
struct StopOnDrop<'a> {
    stop: &'a Stop,
    /// The key the connection proved, noted as the stop's source.
    peer: VerifyKey,
}

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        // Noted before the cancel, as the socket stop does, so the run reads a wire stop and its key. On a
        // drop racing Ctrl-C this can note the wire stop first, which is true too: both asked.
        self.stop.source.note(StopKind::Wire(self.peer));
        self.stop.cancel.cancel();
    }
}

/// The line a node stopped over `control.stop` prints: the name this node holds for the key that stopped it
/// and its short key, or the whole key when it holds no name for it. One of your devices is named as yours
/// first, whatever else the book saved the key under.
pub fn stopped_by(contacts: &Contacts, peer: VerifyKey) -> String {
    // An admitted peer's key is one the transport proved, so it is always a usable key; the arm keeps the
    // whole key for one that somehow is not.
    let Ok(node) = peer.node_id() else {
        return format!("Stopped by {peer}.");
    };
    let mine = contacts
        .mine()
        .find(|(_, key)| **key == node)
        .map(|(label, _)| OwnDevice::from(label.clone()).to_string());
    match mine.or_else(|| contacts.saved_at(&node).map(|name| name.to_string())) {
        Some(name) => format!("Stopped by {name} ({}).", crate::credential::short(&node)),
        None => format!("Stopped by {node}."),
    }
}

/// How long the stopped node waits for the caller to close its side after the ack, before it stops anyway.
/// The caller closes the moment it reads the ack, so on a live path this is one round trip; the bound is
/// for a caller that never closes, which can then delay the stop by this much and no more. A member may
/// stop the node outright, so the delay gives it nothing it did not already hold.
pub const ACK_GRACE: Duration = Duration::from_secs(2);

/// The most the stopped node reads from the caller while it waits for the close. The caller sends nothing
/// after its request, so any cap works; one that does send more than this ends the wait early, which can
/// cost only that caller its ack.
const CALLER_BYTES: u64 = 64;

/// The single byte `control.stop` writes to confirm the stop was actioned. Any value works (the client only
/// needs to read one byte on an admitted stream); a printable `.` keeps a raw wire dump legible.
pub const STOP_ACK: u8 = b'.';
