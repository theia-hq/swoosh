use nauthy::Admitted;
use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler};

/// The `ping:` handler swoosh injects: the cheap RTT half of reach diagnostics, behind the node's
/// gate. It answers one ping run over the admitted stream and REFUSES a speed frame at the wire, so a grant
/// for `ping` can never open the speed drain. GATED for now (an open gate over it, `--public
/// ping:`, is a deliberate opt-out a node makes to advertise as a public ping responder); a member is
/// admitted whole-node.
pub(super) struct Ping;

impl Handler for Ping {
    // OPT-IN: an open gate over it (`--public ping:`) is a deliberate opt-out a node makes to advertise as a
    // public ping responder; a member is otherwise admitted whole-node.
    type Public = OptIn;

    // AMPLIFIER: `ping` answers any caller with no responder-side rate limit yet, so a PUBLIC one lets an
    // anonymous stranger drain this node's uplink. Declared here so the readiness banner narrates the caveat
    // where the danger is, rather than swoosh hardcoding a `ping`/`speed` name list (delib-40/41).
    const AMPLIFIER: bool = true;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> eyre::Result<()> {
        measure::answer_ping(&mut writer, &mut reader).await?;
        Ok(())
    }
}
