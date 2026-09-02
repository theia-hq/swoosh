use nauthy::Admitted;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, CancellationToken, Handler};
use tokio::io::AsyncWriteExt as _;

/// The `control.stop` handler swoosh injects: the remote node-lifecycle stop. It holds a CLONE of the
/// node's teardown token as the node-control CAPABILITY (never a node handle), so when an admitted caller
/// reaches it, it REQUESTS the graceful teardown by cancelling that token; the exposer (the one owner of
/// teardown) sees the cancel and stops the node. GATED, because stopping the node is a mutation with no
/// safe public form: the family gate is its authentication, so only an admitted member (this node's own
/// devices, for a single-owner node) can stop it. An open gate over it is refused at
/// [`Exposer::new`](tightbeam::tunnel::Exposer::new).
///
/// SAFE FIRST SLICE (delib-18): this ships the FAMILY-GATED stop, correct for a single-owner qat node.
/// The HARDENED lifecycle (an arm->confirm nonce + a single-use device-bound DESTROY-CAP, ideally
/// OWNER-only so a delegate cannot casually shut the node down) is the FOLLOW, and needs an Adversary
/// gating-review before `control.stop` is trusted on a multi-delegate node; the open question there is
/// whether the `Admitted` witness can distinguish an owner device from a delegate.
///
/// On admission the handler cancels the token, then writes ONE ack byte so the client can confirm the stop
/// was actioned (not merely that the dial was admitted): a positive, explicit confirmation, the honest
/// counterpart to the loud typed refusal a non-admitted caller gets at the gate.
///
/// Public so the `gated_stop` proof drives the SAME handler `serve` injects, not a hand-rolled near-copy,
/// exactly as the `gated_measure` proof reuses `registry`.
pub struct Stop {
    cancel: CancellationToken,
}

impl Stop {
    /// Build the `control.stop` handler holding a CLONE of the node's teardown token as the node-control
    /// capability (never a node handle): an admitted caller REQUESTS the graceful teardown by cancelling it.
    pub fn new(cancel: CancellationToken) -> Self {
        Self { cancel }
    }
}

impl Handler for Stop {
    // GATED: stopping the node is a mutation with no safe public form; the family gate is its authentication.
    type Public = Never;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> eyre::Result<()> {
        self.cancel.cancel();
        // The ack byte: proof to the client that the stop landed. Written after the cancel so a client
        // reading it knows the teardown was requested, then flushed since the node is about to close.
        writer.write_all(&[STOP_ACK]).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// The single byte `control.stop` writes to confirm the stop was actioned. Any value works (the client only
/// needs to read one byte on an admitted stream); a printable `.` keeps a raw wire dump legible.
pub const STOP_ACK: u8 = b'.';
